"""
agents/aggregator.py

Result Aggregator Agent for Mr Ninja.

Combines findings from all chunk summaries into a single unified
analysis report. Responsible for:
- Deduplicating findings (same file + same issue type → keep highest severity)
- Severity ranking
- Risk score calculation
- Generating the final Markdown report posted to the MR
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from core.models import (
    AnalysisReport,
    ChunkPlan,
    ChunkSummary,
    Finding,
    Severity,
)

logger = logging.getLogger("mr_ninja.aggregator")

# Severity weights for risk score calculation
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class ResultAggregator:
    """Aggregates chunk results into a unified analysis report.

    The aggregator:
    1. Collects all findings from all chunk summaries
    2. Deduplicates by (file, finding type) — keeping highest severity
    3. Sorts by severity (CRITICAL first)
    4. Calculates an overall risk score
    5. Renders a Markdown report suitable for MR comments
    """

    def __init__(self):
        self._findings_map: dict[tuple[str, str], Finding] = {}
        self._open_questions: list[str] = []
        self._chunk_summaries: list[ChunkSummary] = []

    def ingest_summary(self, summary: ChunkSummary) -> None:
        """Add a chunk summary's findings to the aggregation pool.

        Deduplicates on-the-fly: if a finding for the same file and
        issue type already exists, keeps the one with higher severity.
        """
        self._chunk_summaries.append(summary)

        for finding in summary.findings:
            key = (finding.file, finding.title)
            existing = self._findings_map.get(key)

            if existing is None:
                self._findings_map[key] = finding
            elif finding.severity.rank < existing.severity.rank:
                # New finding is more severe — replace
                self._findings_map[key] = finding

        # Collect open questions
        for q in summary.open_questions:
            if q not in self._open_questions:
                self._open_questions.append(q)

    def get_deduplicated_findings(self) -> list[Finding]:
        """Return all findings, sorted by severity (most critical first)."""
        findings = list(self._findings_map.values())
        findings.sort(key=lambda f: f.severity.rank)
        return findings

    def calculate_risk_score(self) -> float:
        """Calculate a numerical risk score (0-100).

        Formula: weighted sum of findings, capped at 100.
        Score 0 = no issues, Score 100 = critical risk.
        """
        findings = self.get_deduplicated_findings()
        if not findings:
            return 0.0

        raw_score = sum(
            SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings
        )
        # Normalize: cap at 100
        return min(100.0, raw_score)

    def determine_overall_risk(self) -> Severity:
        """Determine the overall risk level from aggregated findings."""
        findings = self.get_deduplicated_findings()
        if not findings:
            return Severity.INFO

        # Overall risk = severity of the worst finding
        return findings[0].severity

    def build_report(
        self,
        plan: ChunkPlan,
        processing_time: float = 0.0,
    ) -> AnalysisReport:
        """Build the final AnalysisReport from aggregated data.

        Args:
            plan: The ChunkPlan that was executed.
            processing_time: Total wall-clock processing time.

        Returns:
            Complete AnalysisReport.
        """
        findings = self.get_deduplicated_findings()
        unresolved = [
            q for q in self._open_questions
            if not q.startswith("RESOLVED:")
        ]

        report = AnalysisReport(
            mr_id=plan.mr_id,
            mr_title=plan.mr_title,
            mr_url=plan.mr_url,
            project_id=plan.project_id,
            total_files_scanned=plan.total_files,
            total_estimated_tokens=plan.total_estimated_tokens,
            chunks_processed=plan.chunk_count,
            findings=findings,
            unresolved_questions=unresolved,
            chunk_summaries=self._chunk_summaries,
            overall_risk=self.determine_overall_risk(),
            processing_time_seconds=processing_time,
        )

        logger.info(
            f"Report built: {len(findings)} findings, "
            f"risk={report.overall_risk.value}, "
            f"score={self.calculate_risk_score():.0f}/100"
        )

        return report

    def render_markdown(
        self,
        plan: ChunkPlan,
        processing_time: float = 0.0,
    ) -> str:
        """Render the final Markdown report for MR posting.

        Produces a complete Markdown document with:
        - Executive summary with risk level
        - Findings table sorted by severity
        - Unresolved cross-chunk questions
        - Recommendations
        - Per-chunk processing details (collapsible)
        """
        findings = self.get_deduplicated_findings()
        risk = self.determine_overall_risk()
        risk_score = self.calculate_risk_score()

        # Severity counts
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        # Risk badge
        risk_badges = {
            Severity.CRITICAL: "CRITICAL",
            Severity.HIGH: "HIGH",
            Severity.MEDIUM: "MEDIUM",
            Severity.LOW: "LOW",
            Severity.INFO: "CLEAN",
        }
        risk_badge = risk_badges.get(risk, "UNKNOWN")

        # Build findings table
        if findings:
            table_header = (
                "| # | Severity | File | Issue | Recommendation | Line |\n"
                "|---|----------|------|-------|----------------|------|\n"
            )
            table_rows = "\n".join(
                f"| {i+1} | **{f.severity.value}** | `{f.file}` | "
                f"{f.title} | {f.recommendation[:60]}{'...' if len(f.recommendation) > 60 else ''} | "
                f"{f.line or '-'} |"
                for i, f in enumerate(findings)
            )
            findings_section = table_header + table_rows
        else:
            findings_section = "_No findings detected. Code looks clean._"

        # Build unresolved questions section
        unresolved = [
            q for q in self._open_questions
            if not q.startswith("RESOLVED:")
        ]
        if unresolved:
            oq_section = "\n".join(f"- {q}" for q in unresolved)
        else:
            oq_section = "_All cross-chunk concerns resolved._"

        # Build recommendations
        recommendations = self._build_recommendations(findings, sev_counts)

        # Build per-chunk details (collapsible)
        chunk_details = self._build_chunk_details()

        # Category breakdown
        categories: dict[str, int] = {}
        for f in findings:
            categories[f.category] = categories.get(f.category, 0) + 1
        category_line = ", ".join(
            f"{count} {cat}" for cat, count in sorted(categories.items())
        )

        return f"""# Mr Ninja Analysis Report

**MR:** {plan.mr_title} (#{plan.mr_id})
**Risk Level:** {risk_badge} (Score: {risk_score:.0f}/100)
**Scanned:** {plan.total_files} files | ~{plan.total_estimated_tokens:,} tokens | {plan.chunk_count} chunk(s)
**Processing Time:** {processing_time:.1f}s

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Files scanned | {plan.total_files} |
| Critical vulnerabilities | {sev_counts.get('CRITICAL', 0)} |
| High vulnerabilities | {sev_counts.get('HIGH', 0)} |
| Medium issues | {sev_counts.get('MEDIUM', 0)} |
| Low issues | {sev_counts.get('LOW', 0)} |
| Info | {sev_counts.get('INFO', 0)} |
| Categories | {category_line or 'none'} |

---

## Findings

{findings_section}

---

## Unresolved Cross-Chunk Questions

{oq_section}

---

## Recommendations

{recommendations}

---

## Processing Details

<details>
<summary>Chunk-by-chunk breakdown ({len(self._chunk_summaries)} chunks)</summary>

{chunk_details}

</details>

---

*Generated by **Mr Ninja** — Large Context Orchestrator for GitLab Duo*
*GitLab AI Hackathon 2026*
"""

    def _build_recommendations(
        self,
        findings: list[Finding],
        sev_counts: dict[str, int],
    ) -> str:
        """Generate actionable recommendations based on findings."""
        lines: list[str] = []

        if sev_counts.get("CRITICAL", 0) > 0:
            lines.append(
                "1. **BLOCK MERGE** — Resolve all CRITICAL findings before merging. "
                "These represent active security vulnerabilities."
            )
        if sev_counts.get("HIGH", 0) > 0:
            lines.append(
                "2. **High Priority** — Address HIGH findings in this MR or create "
                "follow-up issues with a committed timeline."
            )
        if sev_counts.get("MEDIUM", 0) > 0:
            lines.append(
                "3. **Review** — MEDIUM findings should be addressed but may not block merge. "
                "Use team judgment."
            )

        # Specific recommendations by category
        security_findings = [f for f in findings if f.category == "security"]
        if security_findings:
            lines.append(
                "4. **Security** — Run a dedicated SAST scan (Semgrep, GitLab SAST) "
                "on the flagged files for deeper analysis."
            )

        dep_findings = [f for f in findings if f.category == "dependency"]
        if dep_findings:
            lines.append(
                "5. **Dependencies** — Run `npm audit` / `pip audit` / `bundle audit` "
                "and update flagged packages."
            )

        if not lines:
            lines.append("No blocking issues found. Standard review applies.")

        return "\n".join(lines)

    def _build_chunk_details(self) -> str:
        """Build collapsible per-chunk details section."""
        if not self._chunk_summaries:
            return "_No chunks processed._"

        sections: list[str] = []
        for cs in self._chunk_summaries:
            finding_count = len(cs.findings)
            critical = len([
                f for f in cs.findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ])

            section = f"### Chunk {cs.chunk_id}/{cs.total_chunks}\n"
            section += f"- **Files:** {len(cs.files_processed)}\n"
            section += f"- **Findings:** {finding_count}"
            if critical:
                section += f" ({critical} critical/high)"
            section += "\n"
            section += f"- **Time:** {cs.processing_time_seconds:.2f}s\n"

            if cs.files_processed:
                section += "- **Files processed:**\n"
                for fp in cs.files_processed:
                    section += f"  - `{fp}`\n"

            sections.append(section)

        return "\n".join(sections)
