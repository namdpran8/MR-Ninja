"""
tests/test_aggregation.py

Tests for the result aggregator and context summarizer.
"""

import pytest
from mr_ninja.agents.aggregator import ResultAggregator
from mr_ninja.agents.summarizer import ContextSummarizer
from mr_ninja.core.models import (
    ChunkPlan,
    ChunkSummary,
    Finding,
    Severity,
    FileEntry,
    Chunk,
    AgentType,
)


class TestResultAggregator:
    """Test the result aggregation logic."""

    def setup_method(self):
        self.aggregator = ResultAggregator()

    def _make_finding(
        self,
        file: str,
        severity: Severity,
        title: str = "Test finding",
        category: str = "security",
    ) -> Finding:
        return Finding(
            file=file,
            severity=severity,
            title=title,
            category=category,
            description="Test description",
            recommendation="Fix it",
        )

    def _make_summary(
        self,
        chunk_id: int,
        findings: list[Finding],
        open_questions: list[str] = None,
    ) -> ChunkSummary:
        return ChunkSummary(
            chunk_id=chunk_id,
            total_chunks=3,
            files_processed=[f"file_{chunk_id}.py"],
            findings=findings,
            open_questions=open_questions or [],
        )

    def _make_plan(self) -> ChunkPlan:
        return ChunkPlan(
            mr_id="42",
            mr_title="Test MR",
            total_files=10,
            total_estimated_tokens=50_000,
            chunks=[
                Chunk(
                    chunk_id=1,
                    files=[],
                    estimated_tokens=25_000,
                    recommended_agent=AgentType.SECURITY,
                ),
            ],
        )

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def test_deduplicate_same_finding(self):
        """Duplicate findings should be deduplicated."""
        f1 = self._make_finding("app.py", Severity.HIGH, "SQL Injection")
        f2 = self._make_finding("app.py", Severity.MEDIUM, "SQL Injection")

        summary1 = self._make_summary(1, [f1])
        summary2 = self._make_summary(2, [f2])

        self.aggregator.ingest_summary(summary1)
        self.aggregator.ingest_summary(summary2)

        findings = self.aggregator.get_deduplicated_findings()
        assert len(findings) == 1
        # Should keep the highest severity
        assert findings[0].severity == Severity.HIGH

    def test_different_findings_not_deduplicated(self):
        """Different findings should not be deduplicated."""
        f1 = self._make_finding("app.py", Severity.HIGH, "SQL Injection")
        f2 = self._make_finding("app.py", Severity.MEDIUM, "XSS")

        summary = self._make_summary(1, [f1, f2])
        self.aggregator.ingest_summary(summary)

        findings = self.aggregator.get_deduplicated_findings()
        assert len(findings) == 2

    def test_different_files_not_deduplicated(self):
        """Same issue in different files should not be deduplicated."""
        f1 = self._make_finding("app.py", Severity.HIGH, "SQL Injection")
        f2 = self._make_finding("auth.py", Severity.HIGH, "SQL Injection")

        summary = self._make_summary(1, [f1, f2])
        self.aggregator.ingest_summary(summary)

        findings = self.aggregator.get_deduplicated_findings()
        assert len(findings) == 2

    # ------------------------------------------------------------------
    # Severity sorting
    # ------------------------------------------------------------------

    def test_findings_sorted_by_severity(self):
        """Findings should be sorted with CRITICAL first."""
        findings = [
            self._make_finding("a.py", Severity.LOW, "Low issue"),
            self._make_finding("b.py", Severity.CRITICAL, "Critical issue"),
            self._make_finding("c.py", Severity.MEDIUM, "Medium issue"),
        ]
        summary = self._make_summary(1, findings)
        self.aggregator.ingest_summary(summary)

        sorted_findings = self.aggregator.get_deduplicated_findings()
        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[1].severity == Severity.MEDIUM
        assert sorted_findings[2].severity == Severity.LOW

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def test_risk_score_no_findings(self):
        """No findings should give risk score 0."""
        assert self.aggregator.calculate_risk_score() == 0.0

    def test_risk_score_critical(self):
        """CRITICAL finding should give high score."""
        f = self._make_finding("a.py", Severity.CRITICAL, "Big problem")
        self.aggregator.ingest_summary(self._make_summary(1, [f]))
        assert self.aggregator.calculate_risk_score() >= 10

    def test_risk_score_cap_at_100(self):
        """Risk score should cap at 100."""
        findings = [
            self._make_finding(f"file{i}.py", Severity.CRITICAL, f"Issue {i}")
            for i in range(20)
        ]
        self.aggregator.ingest_summary(self._make_summary(1, findings))
        assert self.aggregator.calculate_risk_score() == 100.0

    # ------------------------------------------------------------------
    # Overall risk
    # ------------------------------------------------------------------

    def test_overall_risk_no_findings(self):
        """No findings should give INFO risk."""
        assert self.aggregator.determine_overall_risk() == Severity.INFO

    def test_overall_risk_critical(self):
        """Critical finding should give CRITICAL overall risk."""
        f = self._make_finding("a.py", Severity.CRITICAL, "Bad")
        self.aggregator.ingest_summary(self._make_summary(1, [f]))
        assert self.aggregator.determine_overall_risk() == Severity.CRITICAL

    # ------------------------------------------------------------------
    # Open questions
    # ------------------------------------------------------------------

    def test_open_questions_collected(self):
        """Open questions should be collected from all summaries."""
        s1 = self._make_summary(1, [], ["Question 1"])
        s2 = self._make_summary(2, [], ["Question 2"])

        self.aggregator.ingest_summary(s1)
        self.aggregator.ingest_summary(s2)

        assert len(self.aggregator._open_questions) == 2

    def test_open_questions_deduplication(self):
        """Duplicate questions should not be duplicated."""
        s1 = self._make_summary(1, [], ["Same question"])
        s2 = self._make_summary(2, [], ["Same question"])

        self.aggregator.ingest_summary(s1)
        self.aggregator.ingest_summary(s2)

        assert len(self.aggregator._open_questions) == 1

    # ------------------------------------------------------------------
    # Report building
    # ------------------------------------------------------------------

    def test_build_report(self):
        """Should build a complete AnalysisReport."""
        f = self._make_finding("app.py", Severity.HIGH, "XSS")
        self.aggregator.ingest_summary(self._make_summary(1, [f]))

        plan = self._make_plan()
        report = self.aggregator.build_report(plan, processing_time=1.5)

        assert report.mr_id == "42"
        assert len(report.findings) == 1
        assert report.overall_risk == Severity.HIGH
        assert report.processing_time_seconds == 1.5

    # ------------------------------------------------------------------
    # Markdown rendering
    # ------------------------------------------------------------------

    def test_render_markdown_has_title(self):
        """Markdown report should contain the title."""
        plan = self._make_plan()
        md = self.aggregator.render_markdown(plan)
        assert "Mr Ninja Analysis Report" in md

    def test_render_markdown_has_findings(self):
        """Markdown report should include findings table."""
        f = self._make_finding("app.py", Severity.CRITICAL, "SQL Injection")
        self.aggregator.ingest_summary(self._make_summary(1, [f]))

        plan = self._make_plan()
        md = self.aggregator.render_markdown(plan)

        assert "SQL Injection" in md
        assert "CRITICAL" in md
        assert "app.py" in md

    def test_render_markdown_no_findings(self):
        """Markdown report should show clean message when no findings."""
        plan = self._make_plan()
        md = self.aggregator.render_markdown(plan)
        assert "No findings detected" in md


class TestContextSummarizer:
    """Test the cross-chunk context summarizer."""

    def setup_method(self):
        self.summarizer = ContextSummarizer()

    def _make_summary(
        self,
        chunk_id: int = 1,
        total_chunks: int = 3,
        findings: list[Finding] = None,
        exports: list[str] = None,
        questions: list[str] = None,
    ) -> ChunkSummary:
        return ChunkSummary(
            chunk_id=chunk_id,
            total_chunks=total_chunks,
            files_processed=[f"file_{chunk_id}.py"],
            findings=findings or [],
            imports_exported=exports or [],
            open_questions=questions or [],
        )

    def test_empty_context(self):
        """No summaries should produce empty context."""
        assert self.summarizer.get_context_for_next_chunk() == ""

    def test_context_after_one_chunk(self):
        """After one chunk, context should include chunk info."""
        summary = self._make_summary(1, 3)
        self.summarizer.ingest_chunk_summary(summary)

        context = self.summarizer.get_context_for_next_chunk()
        assert "Chunks completed: 1/3" in context
        assert "CROSS-CHUNK CONTEXT" in context

    def test_context_includes_critical_findings(self):
        """Context should always include critical findings."""
        finding = Finding(
            file="auth.py",
            severity=Severity.CRITICAL,
            title="Hardcoded secret",
            description="Found API key",
            category="security",
        )
        summary = self._make_summary(1, 3, findings=[finding])
        self.summarizer.ingest_chunk_summary(summary)

        context = self.summarizer.get_context_for_next_chunk()
        assert "CRITICAL" in context
        assert "auth.py" in context

    def test_context_includes_open_questions(self):
        """Context should include open questions."""
        summary = self._make_summary(
            1, 3, questions=["Check auth module for related issues"]
        )
        self.summarizer.ingest_chunk_summary(summary)

        context = self.summarizer.get_context_for_next_chunk()
        assert "Check auth module" in context

    def test_context_includes_exports(self):
        """Context should include exported symbols."""
        summary = self._make_summary(
            1, 3, exports=["auth.py:AuthService", "utils.py:validate"]
        )
        self.summarizer.ingest_chunk_summary(summary)

        context = self.summarizer.get_context_for_next_chunk()
        assert "auth.py:AuthService" in context

    def test_accumulation(self):
        """Multiple summaries should accumulate."""
        self.summarizer.ingest_chunk_summary(self._make_summary(1, 3))
        self.summarizer.ingest_chunk_summary(self._make_summary(2, 3))

        stats = self.summarizer.get_summary_stats()
        assert stats["chunks_processed"] == 2
        assert stats["total_files"] == 2

    def test_resolve_question(self):
        """Resolving a question should remove it from open questions."""
        summary = self._make_summary(1, 3, questions=["Check auth"])
        self.summarizer.ingest_chunk_summary(summary)

        assert len(self.summarizer.get_open_questions()) == 1

        self.summarizer.resolve_question("Check auth")
        assert len(self.summarizer.get_open_questions()) == 0

    def test_context_truncation(self):
        """Context should be truncated if too long."""
        summarizer = ContextSummarizer(max_context_chars=200)

        # Create a summary with many findings to force truncation
        findings = [
            Finding(
                file=f"file_{i}.py",
                severity=Severity.HIGH,
                title=f"Issue {i} with a really long title that takes up space",
                description="desc",
                category="security",
            )
            for i in range(50)
        ]
        summary = self._make_summary(1, 3, findings=findings)
        summarizer.ingest_chunk_summary(summary)

        context = summarizer.get_context_for_next_chunk()
        assert len(context) <= 200
