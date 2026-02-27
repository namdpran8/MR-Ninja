"""
pipeline/contextual_scaffolding.py

Automated "Contextual Scaffolding" — GitLab Webhook handler that fires on
branch creation and automatically injects up-to-date Architecture Decision
Records (ADRs), API docs, and security policies into the repo's /docs folder.

This eliminates the 10-15 minutes developers spend manually assembling
context before invoking GitLab Duo.

Deploy as:
  - A GitLab Serverless function  (recommended)
  - A simple Python web server behind a GitLab Webhook
  - A GitLab CI job triggered by push events

Webhook setup:
  Settings > Webhooks > Add new webhook
  URL: https://your-runner/scaffold
  Trigger: Push events (branch creation only)
  Secret: $SCAFFOLD_WEBHOOK_SECRET

Environment variables required:
  GITLAB_TOKEN            - PAT with api + write_repository scopes
  SCAFFOLD_WEBHOOK_SECRET - webhook secret for signature verification
  GITLAB_URL              - e.g. https://gitlab.com
  ADR_SOURCE_PROJECT      - project ID containing your canonical ADRs
  API_DOCS_SOURCE_PROJECT - project ID containing your API specs
  POLICY_SOURCE_PROJECT   - project ID containing security policies
"""

import os
import json
import hmac
import hashlib
import logging
import urllib.request
import urllib.parse
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scaffold")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

GITLAB_URL    = os.getenv("GITLAB_URL", "https://gitlab.com")
GITLAB_TOKEN  = os.getenv("GITLAB_TOKEN", "")
WEBHOOK_SECRET= os.getenv("SCAFFOLD_WEBHOOK_SECRET", "")

# Source project IDs for living documentation
SOURCE_PROJECTS = {
    "adrs":     os.getenv("ADR_SOURCE_PROJECT", ""),
    "api_docs": os.getenv("API_DOCS_SOURCE_PROJECT", ""),
    "policies": os.getenv("POLICY_SOURCE_PROJECT", ""),
}

# Where in the target repo to place injected context
SCAFFOLD_DIR  = ".pipeline/context"
SCAFFOLD_FILE = f"{SCAFFOLD_DIR}/DUO_CONTEXT.md"

# Only scaffold when a branch name starts with these prefixes
BRANCH_PREFIXES = ("feature/", "fix/", "bugfix/", "hotfix/", "chore/", "sec/")


# ---------------------------------------------------------------------------
# GitLab API helpers
# ---------------------------------------------------------------------------

class GitLabAPI:
    def __init__(self, url: str, token: str):
        self.base = url.rstrip("/") + "/api/v4"
        self.token = token

    def _request(self, method: str, path: str, data: dict = None) -> dict | list:
        url = f"{self.base}{path}"
        body = json.dumps(data).encode() if data else None
        headers = {
            "PRIVATE-TOKEN": self.token,
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as e:
            log.error(f"GitLab API {method} {path} failed: {e}")
            return {}

    def get(self, path: str) -> dict | list:
        return self._request("GET", path)

    def post(self, path: str, data: dict) -> dict:
        return self._request("POST", path, data)

    def list_files(self, project_id: str, path: str = "", ref: str = "main") -> list[dict]:
        pid = urllib.parse.quote(project_id, safe="")
        result = self.get(f"/projects/{pid}/repository/tree?path={path}&ref={ref}&per_page=100")
        return result if isinstance(result, list) else []

    def get_file(self, project_id: str, file_path: str, ref: str = "main") -> str:
        pid = urllib.parse.quote(project_id, safe="")
        fp  = urllib.parse.quote(file_path, safe="")
        data = self.get(f"/projects/{pid}/repository/files/{fp}?ref={ref}")
        if "content" in data:
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return ""

    def create_or_update_file(
        self,
        project_id: str,
        file_path: str,
        content: str,
        branch: str,
        commit_message: str,
    ) -> dict:
        pid = urllib.parse.quote(project_id, safe="")
        fp  = urllib.parse.quote(file_path, safe="")
        # Try create first, fall back to update
        for action in ("POST", "PUT"):
            result = self._request(action, f"/projects/{pid}/repository/files/{fp}", {
                "branch": branch,
                "content": content,
                "commit_message": commit_message,
                "encoding": "text",
            })
            if result:
                return result
        return {}

    def get_project(self, project_id: str) -> dict:
        pid = urllib.parse.quote(project_id, safe="")
        return self.get(f"/projects/{pid}")


# ---------------------------------------------------------------------------
# Document fetchers
# ---------------------------------------------------------------------------

def fetch_adrs(api: GitLabAPI, project_id: str) -> str:
    """Fetch all Architecture Decision Records from the source project."""
    if not project_id:
        return ""

    files = api.list_files(project_id, path="docs/adr")
    if not files:
        files = api.list_files(project_id, path="adr")
    if not files:
        files = api.list_files(project_id, path="docs/decisions")

    md_files = [f for f in files if f.get("name", "").endswith(".md")]
    if not md_files:
        return ""

    sections = ["## 📐 Architecture Decision Records\n"]
    # Include the 5 most recent ADRs (by filename — ADRs are usually numbered)
    for f in sorted(md_files, key=lambda x: x["name"], reverse=True)[:5]:
        content = api.get_file(project_id, f["path"])
        if content:
            # Extract just the title + status + context (not full ADR — keep tokens low)
            lines = content.splitlines()
            header = "\n".join(lines[:30])  # first 30 lines
            sections.append(f"### {f['name']}\n```\n{header}\n...\n```\n")

    return "\n".join(sections)


def fetch_api_docs(api: GitLabAPI, project_id: str) -> str:
    """Fetch OpenAPI spec summary or API documentation."""
    if not project_id:
        return ""

    # Look for OpenAPI/Swagger files
    candidates = [
        "openapi.yaml", "openapi.json", "swagger.yaml", "swagger.json",
        "docs/api/openapi.yaml", "api/openapi.yaml",
    ]
    for path in candidates:
        content = api.get_file(project_id, path)
        if content:
            # Trim to first 200 lines — enough for endpoints list
            preview = "\n".join(content.splitlines()[:200])
            return f"## 🌐 API Specification (preview)\n```yaml\n{preview}\n...\n```\n"

    return ""


def fetch_security_policies(api: GitLabAPI, project_id: str) -> str:
    """Fetch security policies and compliance rules."""
    if not project_id:
        return ""

    candidates = [
        "SECURITY.md", "docs/SECURITY.md",
        "docs/security-policy.md", "policies/security.md",
        ".gitlab/security-policy.md",
    ]
    for path in candidates:
        content = api.get_file(project_id, path)
        if content:
            preview = "\n".join(content.splitlines()[:100])
            return f"## 🔒 Security Policies\n{preview}\n"

    return ""


# ---------------------------------------------------------------------------
# Scaffolding builder
# ---------------------------------------------------------------------------

def build_context_document(
    api: GitLabAPI,
    target_project: dict,
    branch: str,
) -> str:
    """Assemble the full DUO_CONTEXT.md to inject into the branch."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    project_name = target_project.get("name", "Unknown")
    project_desc = target_project.get("description", "")

    sections = [
        f"# 🤖 Pipeline — Duo Context Scaffold",
        f"> Auto-generated {now} for branch `{branch}` in **{project_name}**",
        f"> Do not edit manually — this file is refreshed on every branch creation.",
        f"",
        f"## Project Overview",
        f"**Name:** {project_name}",
        f"**Description:** {project_desc or 'No description provided.'}",
        f"",
        "---",
        "",
    ]

    adrs     = fetch_adrs(api, SOURCE_PROJECTS["adrs"])
    api_docs = fetch_api_docs(api, SOURCE_PROJECTS["api_docs"])
    policies = fetch_security_policies(api, SOURCE_PROJECTS["policies"])

    if adrs:     sections.append(adrs)
    if api_docs: sections.append(api_docs)
    if policies: sections.append(policies)

    if not any([adrs, api_docs, policies]):
        sections.append(
            "## ℹ️ No external context sources configured\n"
            "Set `ADR_SOURCE_PROJECT`, `API_DOCS_SOURCE_PROJECT`, and "
            "`POLICY_SOURCE_PROJECT` environment variables to enable auto-injection.\n"
        )

    sections += [
        "---",
        "## 💡 How to Use This File with GitLab Duo",
        "",
        "When prompting Duo, reference this file for context:",
        "```",
        f'@duo Please review my changes in the context of the ADRs and security policies',
        f'documented in {SCAFFOLD_FILE}. Focus on compliance with our API design rules.',
        "```",
        "",
        f"*Generated by [Pipeline](https://gitlab.com) — Large Context Orchestrator*",
    ]

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Core scaffolding action
# ---------------------------------------------------------------------------

def scaffold_branch(project_id: str, branch: str, user: str) -> dict:
    """
    Main action: fetch docs from source projects, build context doc,
    commit it to the new branch.
    """
    api = GitLabAPI(GITLAB_URL, GITLAB_TOKEN)

    log.info(f"Scaffolding branch '{branch}' in project {project_id} (triggered by {user})")

    project = api.get_project(project_id)
    if not project:
        return {"status": "error", "reason": "Could not fetch project info"}

    doc = build_context_document(api, project, branch)

    result = api.create_or_update_file(
        project_id=project_id,
        file_path=SCAFFOLD_FILE,
        content=doc,
        branch=branch,
        commit_message=(
            f"🤖 pipeline: inject Duo context scaffold for `{branch}`\n\n"
            f"Auto-generated by Pipeline scaffolding service.\n"
            f"Contains: ADRs, API specs, security policies.\n"
            f"Triggered by: {user}"
        ),
    )

    if result:
        log.info(f"✅ Context scaffold committed to {branch}:{SCAFFOLD_FILE}")
        return {"status": "ok", "branch": branch, "file": SCAFFOLD_FILE}
    else:
        log.error(f"❌ Failed to commit scaffold to {branch}")
        return {"status": "error", "reason": "Commit failed"}


# ---------------------------------------------------------------------------
# Webhook server
# ---------------------------------------------------------------------------

def verify_signature(body: bytes, signature: str, secret: str) -> bool:
    """Verify GitLab webhook HMAC-SHA256 signature."""
    if not secret:
        return True  # skip verification if no secret configured
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


class WebhookHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        log.info(f"HTTP {args[1]} {args[0]}")

    def do_POST(self):
        if self.path != "/scaffold":
            self.send_response(404)
            self.end_headers()
            return

        length  = int(self.headers.get("Content-Length", 0))
        body    = self.rfile.read(length)
        sig     = self.headers.get("X-Gitlab-Token", "")

        if WEBHOOK_SECRET and sig != WEBHOOK_SECRET:
            log.warning("Webhook signature mismatch — rejecting")
            self.send_response(401)
            self.end_headers()
            return

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        event = self.headers.get("X-Gitlab-Event", "")

        # Only handle branch/tag push events (branch creation = before sha is all zeros)
        if event != "Push Hook":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"skipped","reason":"not a push event"}')
            return

        before  = payload.get("before", "")
        ref     = payload.get("ref", "")           # refs/heads/feature/my-branch
        user    = payload.get("user_name", "unknown")
        pid     = str(payload.get("project_id", ""))

        # Only on branch creation (before is all zeros)
        is_creation = before == "0" * 40
        branch = ref.replace("refs/heads/", "")

        if not is_creation:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"skipped","reason":"not a branch creation"}')
            return

        if not any(branch.startswith(p) for p in BRANCH_PREFIXES):
            log.info(f"Branch '{branch}' doesn't match prefixes — skipping scaffold")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"skipped","reason":"branch prefix not matched"}')
            return

        result = scaffold_branch(pid, branch, user)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())


def run_server(port: int = 8080):
    server = HTTPServer(("0.0.0.0", port), WebhookHandler)
    log.info(f"Pipeline Scaffolding Service listening on port {port}")
    log.info(f"Configure GitLab webhook: POST /scaffold")
    server.serve_forever()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Pipeline Contextual Scaffolding Service")
    subparsers = parser.add_subparsers(dest="cmd")

    serve_parser = subparsers.add_parser("serve", help="Run webhook server")
    serve_parser.add_argument("--port", type=int, default=8080)

    test_parser = subparsers.add_parser("test", help="Test scaffold a branch manually")
    test_parser.add_argument("--project-id", required=True)
    test_parser.add_argument("--branch",     required=True)
    test_parser.add_argument("--user",       default="cli-test")

    args = parser.parse_args()

    if args.cmd == "serve":
        run_server(args.port)
    elif args.cmd == "test":
        result = scaffold_branch(args.project_id, args.branch, args.user)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()
