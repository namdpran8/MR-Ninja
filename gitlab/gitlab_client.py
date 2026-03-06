"""
gitlab/gitlab_client.py

GitLab API connector for Mr Ninja.

Provides a clean async-capable client for interacting with GitLab's REST API.
Handles MR diffs, file content retrieval, note posting, and pagination.

All API calls include automatic retry with backoff for rate limiting.
"""


# MR-Ninja
# Copyright (c) 2026 Pranshu Namdeo and Chukwunonso Richard Iwenor
# Licensed under Apache License 2.0


from __future__ import annotations

import json
import logging
import time
import urllib.parse
import urllib.request
from typing import Any, Optional

logger = logging.getLogger("mr_ninja.gitlab_client")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_GITLAB_URL = "https://gitlab.com"
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 2
RETRY_DELAY_SECONDS = 2
PER_PAGE = 100


class GitLabClientError(Exception):
    """Raised when a GitLab API call fails."""
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


class GitLabClient:
    """Minimal, dependency-free GitLab REST API client.

    Uses only stdlib (urllib) to avoid requiring `requests` as a dependency.
    Supports all operations needed by the Mr Ninja pipeline:
    - Fetching MR metadata and diffs
    - Reading file contents
    - Listing repository files
    - Posting MR notes/comments

    Args:
        gitlab_url: Base URL of the GitLab instance.
        token: Private access token with `api` scope.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        gitlab_url: str = DEFAULT_GITLAB_URL,
        token: str = "",
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.base_url = gitlab_url.rstrip("/") + "/api/v4"
        self.token = token
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
    ) -> Any:
        """Execute an HTTP request against the GitLab API.

        Includes automatic retry on 429 (rate limit) responses.

        Args:
            method: HTTP method (GET, POST, PUT).
            path: API path (appended to base_url).
            params: Query parameters.
            data: JSON body data.

        Returns:
            Parsed JSON response (dict or list).

        Raises:
            GitLabClientError: On non-retryable API failures.
        """
        url = f"{self.base_url}{path}"
        if params:
            # Filter out None values
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                url += "?" + urllib.parse.urlencode(filtered)

        body = json.dumps(data).encode() if data else None
        headers = {
            "PRIVATE-TOKEN": self.token,
            "Content-Type": "application/json",
        }

        for attempt in range(MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(
                    url, data=body, headers=headers, method=method
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    response_body = resp.read()
                    if not response_body:
                        return {}
                    return json.loads(response_body)

            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < MAX_RETRIES:
                    # Rate limited — wait and retry
                    logger.warning(
                        f"Rate limited on {method} {path}, "
                        f"retrying in {RETRY_DELAY_SECONDS}s "
                        f"(attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    time.sleep(RETRY_DELAY_SECONDS)
                    continue
                logger.error(f"GitLab API error: {method} {path} -> {e.code}")
                raise GitLabClientError(
                    f"API {method} {path} failed: HTTP {e.code}",
                    status_code=e.code,
                )

            except Exception as e:
                if attempt < MAX_RETRIES:
                    logger.warning(f"Request failed ({e}), retrying...")
                    time.sleep(RETRY_DELAY_SECONDS)
                    continue
                logger.error(f"GitLab API error: {method} {path} -> {e}")
                raise GitLabClientError(f"API {method} {path} failed: {e}")

        return {}

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        """Convenience GET request."""
        return self._request("GET", path, params=params)

    def _post(self, path: str, data: dict) -> Any:
        """Convenience POST request."""
        return self._request("POST", path, data=data)

    def _put(self, path: str, data: dict) -> Any:
        """Convenience PUT request."""
        return self._request("PUT", path, data=data)

    @staticmethod
    def _encode_project_id(project_id: str) -> str:
        """URL-encode a project ID (handles 'group/project' paths)."""
        return urllib.parse.quote(project_id, safe="")

    # ------------------------------------------------------------------
    # Merge Request operations
    # ------------------------------------------------------------------

    def get_merge_request(self, project_id: str, mr_iid: int) -> dict:
        """Fetch merge request metadata.

        Args:
            project_id: Project ID or URL-encoded path.
            mr_iid: Merge request internal ID.

        Returns:
            MR metadata dict.
        """
        pid = self._encode_project_id(project_id)
        return self._get(f"/projects/{pid}/merge_requests/{mr_iid}")

    def get_merge_request_diffs(
        self,
        project_id: str,
        mr_iid: int,
        page: int = 1,
        per_page: int = PER_PAGE,
    ) -> list[dict]:
        """Fetch MR diff entries (one page).

        Each entry contains: old_path, new_path, diff, new_file, etc.
        """
        pid = self._encode_project_id(project_id)
        result = self._get(
            f"/projects/{pid}/merge_requests/{mr_iid}/diffs",
            {"page": page, "per_page": per_page},
        )
        return result if isinstance(result, list) else []

    def get_all_merge_request_diffs(
        self,
        project_id: str,
        mr_iid: int,
    ) -> list[dict]:
        """Fetch ALL MR diffs, handling pagination automatically.

        Iterates through pages until no more results are returned.
        """
        all_diffs: list[dict] = []
        page = 1

        while True:
            batch = self.get_merge_request_diffs(
                project_id, mr_iid, page=page
            )
            if not batch:
                break
            all_diffs.extend(batch)
            if len(batch) < PER_PAGE:
                break
            page += 1

        logger.info(f"Fetched {len(all_diffs)} diff entries for MR !{mr_iid}")
        return all_diffs

    def get_merge_request_changes(
        self,
        project_id: str,
        mr_iid: int,
    ) -> dict:
        """Fetch MR with full changes (alternative endpoint)."""
        pid = self._encode_project_id(project_id)
        return self._get(f"/projects/{pid}/merge_requests/{mr_iid}/changes")

    # ------------------------------------------------------------------
    # MR notes (comments)
    # ------------------------------------------------------------------

    def create_merge_request_note(
        self,
        project_id: str,
        mr_iid: int,
        body: str,
    ) -> dict:
        """Post a comment on a merge request.

        Args:
            project_id: Project ID or path.
            mr_iid: MR internal ID.
            body: Markdown comment body.

        Returns:
            Created note dict.
        """
        pid = self._encode_project_id(project_id)
        return self._post(
            f"/projects/{pid}/merge_requests/{mr_iid}/notes",
            {"body": body},
        )

    # ------------------------------------------------------------------
    # Repository file operations
    # ------------------------------------------------------------------

    def get_file_content(
        self,
        project_id: str,
        file_path: str,
        ref: str = "main",
    ) -> str:
        """Fetch raw file content from the repository.

        Args:
            project_id: Project ID or path.
            file_path: Path to file in the repo.
            ref: Branch, tag, or commit SHA.

        Returns:
            Decoded file content as string.
        """
        pid = self._encode_project_id(project_id)
        fp = urllib.parse.quote(file_path, safe="")
        data = self._get(f"/projects/{pid}/repository/files/{fp}", {"ref": ref})

        if isinstance(data, dict) and "content" in data:
            import base64
            return base64.b64decode(data["content"]).decode(
                "utf-8", errors="replace"
            )
        return ""

    def list_files(
        self,
        project_id: str,
        path: str = "",
        ref: str = "main",
        recursive: bool = False,
    ) -> list[dict]:
        """List files in a repository directory.

        Args:
            project_id: Project ID or path.
            path: Directory path within the repo.
            ref: Branch or commit reference.
            recursive: If True, list files recursively.

        Returns:
            List of file/directory entry dicts.
        """
        pid = self._encode_project_id(project_id)
        params = {
            "path": path or None,
            "ref": ref,
            "per_page": PER_PAGE,
            "recursive": "true" if recursive else None,
        }
        result = self._get(f"/projects/{pid}/repository/tree", params)
        return result if isinstance(result, list) else []

    # ------------------------------------------------------------------
    # Project operations
    # ------------------------------------------------------------------

    def get_project(self, project_id: str) -> dict:
        """Fetch project metadata."""
        pid = self._encode_project_id(project_id)
        return self._get(f"/projects/{pid}")

    # ------------------------------------------------------------------
    # Utility: parse MR URL
    # ------------------------------------------------------------------

    @staticmethod
    def parse_mr_url(url: str) -> tuple[str, str, int]:
        """Parse a GitLab MR URL into components.

        Args:
            url: Full MR URL like
                 https://gitlab.com/group/project/-/merge_requests/42

        Returns:
            Tuple of (gitlab_base_url, project_path, mr_iid).

        Raises:
            ValueError: If URL format is not recognized.
        """
        import re
        match = re.match(
            r"(https?://[^/]+)/(.+)/-/merge_requests/(\d+)",
            url,
        )
        if not match:
            raise ValueError(f"Cannot parse MR URL: {url}")

        return match.group(1), match.group(2), int(match.group(3))
