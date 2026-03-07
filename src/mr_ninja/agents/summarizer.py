"""
agents/summarizer.py

Context Summarizer Agent for Mr Ninja.

Maintains cross-chunk context by compressing chunk results into
compact summaries that are prepended to subsequent chunk calls.

This ensures that downstream chunks can see:
- What files have already been analyzed
- What findings were discovered
- What exports/symbols are available
- What open questions remain

The summarizer keeps summaries compact (< 2000 tokens) to leave
maximum room for the next chunk's actual content.
"""

from __future__ import annotations

import logging

from mr_ninja.core.models import ChunkSummary, Finding, Severity

logger = logging.getLogger("mr_ninja.summarizer")

# Maximum tokens to spend on cross-chunk context
MAX_CONTEXT_TOKENS = 2000
# Approximate chars-per-token for context strings
CHARS_PER_TOKEN = 4
MAX_CONTEXT_CHARS = MAX_CONTEXT_TOKENS * CHARS_PER_TOKEN


class ContextSummarizer:
    """Builds and manages cross-chunk context summaries.

    After each chunk is processed, the summarizer:
    1. Takes the ChunkSummary
    2. Merges it with accumulated context from previous chunks
    3. Produces a compact context header for the next chunk

    The context is incrementally compressed — only the most important
    information survives across chunks:
    - CRITICAL/HIGH findings (always kept)
    - MEDIUM findings (kept if space allows)
    - LOW/INFO findings (dropped after 2 chunks)
    - Open questions (always kept until resolved)
    """

    def __init__(self, max_context_chars: int = MAX_CONTEXT_CHARS):
        self.max_context_chars = max_context_chars
        self._accumulated_summaries: list[ChunkSummary] = []
        self._accumulated_findings: list[Finding] = []
        self._all_processed_files: list[str] = []
        self._all_exports: list[str] = []
        self._open_questions: list[str] = []
        self._resolved_questions: list[str] = []

    def ingest_chunk_summary(self, summary: ChunkSummary) -> None:
        """Add a chunk summary to the accumulated context.

        Args:
            summary: The ChunkSummary from a just-processed chunk.
        """
        self._accumulated_summaries.append(summary)
        self._accumulated_findings.extend(summary.findings)
        self._all_processed_files.extend(summary.files_processed)
        self._all_exports.extend(summary.imports_exported)

        # Merge open questions
        for q in summary.open_questions:
            if q not in self._open_questions:
                self._open_questions.append(q)

        logger.info(
            f"Ingested chunk {summary.chunk_id} summary: "
            f"{len(summary.findings)} findings, "
            f"{len(summary.open_questions)} open questions"
        )

    def resolve_question(self, question: str) -> None:
        """Mark an open question as resolved."""
        if question in self._open_questions:
            self._open_questions.remove(question)
            self._resolved_questions.append(f"RESOLVED: {question}")

    def get_context_for_next_chunk(self) -> str:
        """Build compact context string for the next chunk's agent call.

        Prioritizes information by importance:
        1. Critical/High findings (always included)
        2. Open questions (always included)
        3. Key exports (truncated if needed)
        4. Processing stats

        Returns:
            Compact context string under max_context_chars.
        """
        if not self._accumulated_summaries:
            return ""

        last_summary = self._accumulated_summaries[-1]
        chunks_done = last_summary.chunk_id
        total_chunks = last_summary.total_chunks

        lines: list[str] = [
            "=== CROSS-CHUNK CONTEXT (read-only) ===",
            f"Chunks completed: {chunks_done}/{total_chunks}",
            f"Files analyzed: {len(self._all_processed_files)}",
        ]

        # Critical/High findings — always include
        critical_high = [
            f for f in self._accumulated_findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if critical_high:
            lines.append(
                f"Critical/High findings: {len(critical_high)}"
            )
            for f in critical_high[:10]:
                lines.append(
                    f"  [{f.severity.value}] {f.file}:{f.line or '?'} "
                    f"— {f.title}"
                )

        # Open questions
        if self._open_questions:
            lines.append("Open questions:")
            for q in self._open_questions[:5]:
                lines.append(f"  - {q}")

        # Key exports (compact)
        if self._all_exports:
            exports_preview = ", ".join(self._all_exports[:15])
            lines.append(f"Key exports: {exports_preview}")

        lines.append("=== END CONTEXT ===")

        context = "\n".join(lines)

        # Truncate if over budget
        if len(context) > self.max_context_chars:
            context = context[:self.max_context_chars - 20] + "\n... (truncated)"

        return context

    def get_all_findings(self) -> list[Finding]:
        """Return all accumulated findings across all chunks."""
        return list(self._accumulated_findings)

    def get_open_questions(self) -> list[str]:
        """Return unresolved open questions."""
        return list(self._open_questions)

    def get_summary_stats(self) -> dict:
        """Return summary statistics for logging/reporting."""
        severity_counts: dict[str, int] = {}
        for f in self._accumulated_findings:
            severity_counts[f.severity.value] = (
                severity_counts.get(f.severity.value, 0) + 1
            )

        return {
            "chunks_processed": len(self._accumulated_summaries),
            "total_files": len(self._all_processed_files),
            "total_findings": len(self._accumulated_findings),
            "severity_counts": severity_counts,
            "open_questions": len(self._open_questions),
            "resolved_questions": len(self._resolved_questions),
            "exports_tracked": len(self._all_exports),
        }
