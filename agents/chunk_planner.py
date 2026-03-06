"""
agents/chunk_planner.py

Chunk Planner Agent for Mr Ninja.

Responsible for:
1. Fetching MR diff information from GitLab
2. Converting raw diffs into FileEntry objects with token estimates
3. Delegating to the ChunkingEngine for priority classification and bin-packing
4. Producing a ChunkPlan that the orchestrator uses to dispatch work

This agent is the first step in the pipeline — it determines HOW the MR
will be analyzed before any actual analysis begins.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

from core.chunking_engine import ChunkingEngine
from core.models import ChunkPlan, FileEntry, FilePriority
from core.token_estimator import TokenEstimator
from gitlab.gitlab_client import GitLabClient

logger = logging.getLogger("mr_ninja.chunk_planner")


class ChunkPlanner:
    """Plans how to split a large MR into analyzable chunks.

    The planner fetches MR diffs from GitLab, estimates token usage,
    classifies files by priority, and delegates bin-packing to the
    ChunkingEngine.

    Args:
        gitlab_client: Authenticated GitLab API client.
        chunking_engine: Engine for file classification and bin-packing.
        token_estimator: Token estimation utility.
    """

    def __init__(
        self,
        gitlab_client: Optional[GitLabClient] = None,
        chunking_engine: Optional[ChunkingEngine] = None,
        token_estimator: Optional[TokenEstimator] = None,
    ):
        self.gitlab = gitlab_client or GitLabClient()
        self.engine = chunking_engine or ChunkingEngine()
        self.estimator = token_estimator or TokenEstimator()

    def plan_from_mr(
        self,
        project_id: str,
        mr_iid: int,
    ) -> ChunkPlan:
        """Build a chunk plan from a live GitLab merge request.

        Fetches all diffs, converts them to FileEntry objects,
        and runs the chunking engine.

        Args:
            project_id: GitLab project ID or URL-encoded path.
            mr_iid: Merge request internal ID.

        Returns:
            Complete ChunkPlan ready for the orchestrator.
        """
        start = time.time()
        logger.info(f"Planning chunks for {project_id} MR !{mr_iid}")

        # Fetch MR metadata
        mr = self.gitlab.get_merge_request(project_id, mr_iid)
        mr_title = mr.get("title", f"MR !{mr_iid}")
        mr_url = mr.get("web_url", "")

        # Fetch all diffs (paginated)
        raw_diffs = self.gitlab.get_all_merge_request_diffs(project_id, mr_iid)
        logger.info(f"Fetched {len(raw_diffs)} file diffs")

        # Convert to FileEntry objects
        files = self._diffs_to_file_entries(raw_diffs)

        # Run the chunking engine
        plan = self.engine.create_plan(
            files=files,
            mr_id=str(mr_iid),
            mr_title=mr_title,
            mr_url=mr_url,
            project_id=project_id,
        )

        elapsed = time.time() - start
        logger.info(
            f"Chunk plan ready in {elapsed:.2f}s: "
            f"{plan.chunk_count} chunk(s), "
            f"{plan.total_estimated_tokens:,} tokens"
        )

        return plan

    def plan_from_files(
        self,
        files: list[FileEntry],
        mr_id: str = "local",
        mr_title: str = "Local Analysis",
    ) -> ChunkPlan:
        """Build a chunk plan from a pre-built list of FileEntry objects.

        Useful for demo mode and testing — doesn't need a GitLab connection.

        Args:
            files: List of FileEntry objects with token estimates.
            mr_id: Identifier for the analysis run.
            mr_title: Human-readable title.

        Returns:
            Complete ChunkPlan.
        """
        return self.engine.create_plan(
            files=files,
            mr_id=mr_id,
            mr_title=mr_title,
        )

    def _diffs_to_file_entries(self, diffs: list[dict]) -> list[FileEntry]:
        """Convert raw GitLab diff dicts into typed FileEntry objects.

        Parses addition/deletion counts from diff text and estimates
        token usage for each file.
        """
        entries: list[FileEntry] = []

        for d in diffs:
            path = d.get("new_path") or d.get("old_path", "unknown")
            diff_text = d.get("diff", "")

            # Count added/deleted lines from diff markers
            add_lines = sum(
                1 for line in diff_text.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            )
            del_lines = sum(
                1 for line in diff_text.splitlines()
                if line.startswith("-") and not line.startswith("---")
            )

            # Estimate tokens from the diff content
            est_tokens = self.estimator.estimate_diff(diff_text)

            entries.append(FileEntry(
                path=path,
                additions=add_lines,
                deletions=del_lines,
                estimated_tokens=est_tokens,
                diff_content=diff_text[:2000],  # keep first 2k chars for preview
                language=self._detect_language(path),
            ))

        logger.info(f"Converted {len(entries)} diffs to FileEntry objects")
        return entries

    @staticmethod
    def _detect_language(path: str) -> str:
        """Detect programming language from file extension."""
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "javascript", ".tsx": "typescript", ".rb": "ruby",
            ".go": "go", ".java": "java", ".rs": "rust", ".cpp": "cpp",
            ".c": "c", ".cs": "csharp", ".php": "php",
            ".tf": "terraform", ".yaml": "yaml", ".yml": "yaml",
            ".json": "json", ".sh": "shell",
        }
        for ext, lang in ext_map.items():
            if path.lower().endswith(ext):
                return lang
        return "unknown"

    def print_plan(self, plan: ChunkPlan) -> None:
        """Print a human-readable chunk plan to the console."""
        sep = "=" * 60
        print(f"\n{sep}")
        print("MR NINJA CHUNK PLAN")
        print(sep)
        print(f"MR:             {plan.mr_title} (#{plan.mr_id})")
        print(f"Total files:    {plan.total_files}")
        print(f"Est. tokens:    {plan.total_estimated_tokens:,}")
        mode = "CHUNKED" if plan.chunking_required else "SINGLE-PASS"
        print(f"Mode:           {mode}")

        if plan.skipped_files:
            print(f"Skipped:        {len(plan.skipped_files)} generated/lock files")

        print()
        for chunk in plan.chunks:
            print(f"  {chunk.summary_line()}")
            for f in chunk.files:
                print(
                    f"    [P{f.priority.value}] {f.path}  "
                    f"(+{f.additions}/-{f.deletions})"
                )
        print(f"{sep}\n")
