"""
core/chunking_engine.py

Intelligent file chunking engine for Mr Ninja.

Given a list of FileEntry objects, this engine:
1. Classifies files by priority (security-critical first, tests last)
2. Sorts by priority + path for deterministic ordering
3. Bin-packs files into chunks using a greedy first-fit algorithm
4. Assigns each chunk a recommended specialist agent

The chunking strategy ensures:
- Security-critical files are analyzed first
- No single chunk exceeds the token ceiling
- Oversized files get their own chunk
- Files are never duplicated across chunks
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from core.models import (
    AgentType,
    Chunk,
    ChunkPlan,
    FileEntry,

    FilePriority,
)
from core.token_estimator import (
    CHUNK_MAX_TOKENS,
    CHUNK_TARGET_TOKENS,
    CHUNKING_TRIGGER_TOKENS,
    TokenEstimator,
)

logger = logging.getLogger("mr_ninja.chunking_engine")

# ---------------------------------------------------------------------------
# File priority classification patterns
# ---------------------------------------------------------------------------

# Checked in order. First match wins. P6 is checked first to exclude
# generated files from accidentally matching P1 security patterns.
PRIORITY_RULES: list[tuple[FilePriority, list[str]]] = [
    # P6 — Generated / lock files (exclude early)
    (FilePriority.GENERATED, [
        r"package-lock\.json$",
        r"yarn\.lock$",
        r"Gemfile\.lock$",
        r"poetry\.lock$",
        r"go\.sum$",
        r"\.generated\.",
        r"(^|/)dist/",
        r"\.min\.js$",
        r"\.min\.css$",
        r"\.map$",
        r"(^|/)node_modules/",
        r"(^|/)vendor/",
        r"__pycache__/",
        r"\.pyc$",
    ]),
    # P1 — Security-critical files
    (FilePriority.SECURITY_CRITICAL, [
        r"(^|/)\.env$",
        r"(^|/)\.env\.",
        r"(^|/)secrets?\.",
        r"(^|/)tokens?\.",
        r"(^|/)auth\.",
        r"(^|/)auth/",
        r"(^|/)authentication",
        r"(^|/)authorization",
        r"(^|/)credentials?\.",
        r"(^|/)password",
        r"(^|/)passwd",
        r"(^|/)Dockerfile",
        r"\.tf$",
        r"(^|/)\.github/workflows/",
        r"(^|/)\.gitlab-ci\.yml$",
        r"requirements.*\.txt$",
        r"(^|/)package\.json$",
        r"(^|/)Gemfile$",
        r"pyproject\.toml$",
        r"setup\.cfg$",
        r"(^|/)permissions?\.",
        r"(^|/)policies?\.",
        r"\.pem$",
        r"\.key$",
        r"\.crt$",
        r"(^|/)csp\.",
        r"(^|/)cors\.",
    ]),
    # P2 — Entry points / routes / API surface
    (FilePriority.ENTRY_POINT, [
        r"(^|/)main\.",
        r"(^|/)app\.",
        r"(^|/)index\.",
        r"(^|/)server\.",
        r"(^|/)routes?/",
        r"(^|/)api/",
        r"(^|/)views?\.",
        r"(^|/)controllers?/",
        r"(^|/)handlers?/",
    ]),
    # P5 — Tests (process late)
    (FilePriority.TEST_FILE, [
        r"(^|/)tests?/",
        r"(^|/)specs?/",
        r"_test\.",
        r"_spec\.",
        r"\.test\.",
        r"\.spec\.",
        r"(^|/)fixtures?/",
        r"(^|/)mocks?/",
        r"conftest\.py$",
    ]),
]


class ChunkingEngine:
    """Splits a list of files into LLM-sized chunks for phased processing.

    The engine uses a priority-sorted greedy bin-packing algorithm:
    1. Classify each file into a priority tier
    2. Sort files by (priority, path) for deterministic ordering
    3. Pack files into chunks, starting a new chunk when the target is exceeded
    4. Assign a recommended agent type per chunk based on file composition

    Args:
        target_tokens: Ideal token budget per chunk (default: 70k).
        max_tokens: Hard ceiling per chunk (default: 100k).
        trigger_tokens: Total token threshold to enable chunking (default: 150k).
        skip_generated: If True, P6 files are excluded from analysis.
    """

    def __init__(
        self,
        target_tokens: int = CHUNK_TARGET_TOKENS,
        max_tokens: int = CHUNK_MAX_TOKENS,
        trigger_tokens: int = CHUNKING_TRIGGER_TOKENS,
        skip_generated: bool = True,
    ):
        self.target_tokens = target_tokens
        self.max_tokens = max_tokens
        self.trigger_tokens = trigger_tokens
        self.skip_generated = skip_generated
        self.estimator = TokenEstimator()

    def classify_file(self, path: str) -> FilePriority:
        """Determine the processing priority for a file path.

        Checks against PRIORITY_RULES in order. First regex match wins.
        Unmatched files default to P3 (CHANGED_FILE).
        """
        for priority, patterns in PRIORITY_RULES:
            for pat in patterns:
                if re.search(pat, path, re.IGNORECASE):
                    return priority
        return FilePriority.CHANGED_FILE

    def classify_files(
        self,
        files: list[FileEntry],
    ) -> tuple[list[FileEntry], list[str]]:
        """Classify and filter a list of files.

        Sets each file's priority based on its path. If skip_generated
        is True, P6 files are moved to the skipped list.

        Returns:
            Tuple of (processable files sorted by priority, skipped file paths).
        """
        processable: list[FileEntry] = []
        skipped: list[str] = []

        for f in files:
            f.priority = self.classify_file(f.path)

            if self.skip_generated and f.priority == FilePriority.GENERATED:
                skipped.append(f.path)
                logger.debug(f"Skipping generated file: {f.path}")
                continue

            # Ensure minimum token estimate
            if f.estimated_tokens < self.estimator.min_file_tokens:
                f.estimated_tokens = self.estimator.min_file_tokens

            processable.append(f)

        # Sort by priority (ascending = highest priority first), then path
        processable.sort(key=lambda f: (f.priority.value, f.path))
        return processable, skipped

    def build_chunks(self, files: list[FileEntry]) -> list[Chunk]:
        """Pack files into chunks using greedy first-fit bin packing.

        Files must already be sorted by priority. The algorithm:
        - Iterates files in priority order
        - Adds each file to the current chunk until target_tokens is reached
        - Oversized files (> target_tokens) get their own chunk
        - Each chunk is assigned a recommended agent based on its files

        Args:
            files: Priority-sorted list of FileEntry objects.

        Returns:
            List of Chunk objects.
        """
        if not files:
            return []

        chunks: list[Chunk] = []
        current_files: list[FileEntry] = []
        current_tokens = 0
        chunk_id = 1

        for f in files:
            # Oversized file — gets its own chunk
            if f.estimated_tokens > self.target_tokens:
                # Flush current chunk first
                if current_files:
                    chunks.append(self._make_chunk(chunk_id, current_files))
                    chunk_id += 1
                    current_files = []
                    current_tokens = 0

                logger.info(
                    f"Oversized file {f.path} "
                    f"({f.estimated_tokens:,} tokens) gets its own chunk"
                )
                chunks.append(self._make_chunk(chunk_id, [f]))
                chunk_id += 1
                continue

            # Would adding this file exceed target? Start a new chunk.
            if (current_tokens + f.estimated_tokens > self.target_tokens
                    and current_files):
                chunks.append(self._make_chunk(chunk_id, current_files))
                chunk_id += 1
                current_files = []
                current_tokens = 0

            current_files.append(f)
            current_tokens += f.estimated_tokens

        # Flush remaining files
        if current_files:
            chunks.append(self._make_chunk(chunk_id, current_files))

        logger.info(
            f"Created {len(chunks)} chunk(s) from {len(files)} files"
        )
        return chunks

    def create_plan(
        self,
        files: list[FileEntry],
        mr_id: str = "",
        mr_title: str = "",
        mr_url: str = "",
        project_id: str = "",
    ) -> ChunkPlan:
        """Build a complete chunk plan from raw file entries.

        This is the main entry point. It:
        1. Classifies files by priority
        2. Estimates total tokens
        3. Decides whether chunking is needed
        4. Packs files into chunks (or a single chunk if under threshold)

        Args:
            files: Raw list of FileEntry objects (priorities will be set).
            mr_id: Merge request identifier.
            mr_title: MR title.
            mr_url: Full MR URL.
            project_id: GitLab project ID.

        Returns:
            A ChunkPlan with all chunks and metadata.
        """
        # Classify and filter
        processable, skipped = self.classify_files(files)

        total_tokens = sum(f.estimated_tokens for f in processable)
        chunking_required = total_tokens > self.trigger_tokens

        if chunking_required:
            chunks = self.build_chunks(processable)
        else:
            # Everything fits in one context window
            chunks = [self._make_chunk(1, processable)] if processable else []

        plan = ChunkPlan(
            mr_id=mr_id,
            mr_title=mr_title,
            mr_url=mr_url,
            project_id=project_id,
            total_files=len(files),
            total_estimated_tokens=total_tokens,
            chunking_required=chunking_required,
            chunks=chunks,
            skipped_files=skipped,
        )

        logger.info(
            f"Chunk plan: {plan.total_files} files, "
            f"{plan.total_estimated_tokens:,} tokens, "
            f"{plan.chunk_count} chunk(s), "
            f"{'CHUNKED' if chunking_required else 'SINGLE-PASS'}"
        )

        return plan

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_chunk(self, chunk_id: int, files: list[FileEntry]) -> Chunk:
        """Create a Chunk from a list of files, auto-detecting the agent type."""
        return Chunk(
            chunk_id=chunk_id,
            files=files,
            estimated_tokens=sum(f.estimated_tokens for f in files),
            recommended_agent=self._detect_agent_type(files),
        )

    def _detect_agent_type(self, files: list[FileEntry]) -> AgentType:
        """Determine which specialist agent should handle this chunk.

        Rules:
        - If chunk contains P1 (security) files → security agent
        - If chunk contains only P5 (test) files → code_review agent
        - If mix of security + logic files → mixed agent
        - Otherwise → code_review agent
        """
        priorities = {f.priority for f in files}

        has_security = FilePriority.SECURITY_CRITICAL in priorities
        has_logic = any(
            p in priorities
            for p in (FilePriority.ENTRY_POINT, FilePriority.CHANGED_FILE,
                      FilePriority.SHARED_MODULE)
        )

        if has_security and has_logic:
            return AgentType.MIXED
        if has_security:
            return AgentType.SECURITY
        return AgentType.CODE_REVIEW

    def _detect_language(self, path: str) -> str:
        """Detect programming language from file extension."""
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "javascript", ".tsx": "typescript", ".rb": "ruby",
            ".go": "go", ".java": "java", ".rs": "rust", ".cpp": "cpp",
            ".c": "c", ".cs": "csharp", ".php": "php", ".swift": "swift",
            ".kt": "kotlin", ".scala": "scala", ".tf": "terraform",
            ".yaml": "yaml", ".yml": "yaml", ".json": "json",
            ".md": "markdown", ".sh": "shell", ".bash": "shell",
        }
        for ext, lang in ext_map.items():
            if path.lower().endswith(ext):
                return lang
        return "unknown"
