"""
tests/test_orchestrator.py

Integration tests for the orchestrator agent.
Tests the full pipeline using synthetic data (no GitLab API needed).
"""

import pytest
from mr_ninja.agents.orchestrator import Orchestrator
from mr_ninja.agents.chunk_planner import ChunkPlanner
from mr_ninja.agents.chunk_processor import ChunkProcessor
from mr_ninja.agents.summarizer import ContextSummarizer
from mr_ninja.agents.aggregator import ResultAggregator
from mr_ninja.core.models import (
    AnalysisReport,
    FileEntry,
    FilePriority,
    Severity,
)


class TestOrchestratorDemoMode:
    """Test the orchestrator in demo/offline mode (no GitLab API calls)."""

    def setup_method(self):
        self.orchestrator = Orchestrator(
            post_comments=False,
            use_duo_agents=False,
        )

    def _make_files(self, count: int = 10) -> list[FileEntry]:
        """Create a list of synthetic FileEntry objects."""
        files = []
        for i in range(count):
            files.append(FileEntry(
                path=f"src/module_{i}.py",
                additions=20,
                deletions=5,
                estimated_tokens=500,
                diff_content=f"""@@ -1,5 +1,20 @@
+import os
+import json
+
+class Module{i}:
+    def process(self, data):
+        return {{"ok": True}}
""",
                language="python",
            ))
        return files

    def _make_vulnerable_files(self) -> list[FileEntry]:
        """Create files with intentional vulnerabilities."""
        return [
            FileEntry(
                path="auth/handler.py",
                additions=10,
                deletions=0,
                estimated_tokens=300,
                diff_content="""@@ -0,0 +1,10 @@
+API_KEY = "sk-live-abcdef123456"
+password = "admin123!"
+
+def login(user, pwd):
+    query = "SELECT * FROM users WHERE name='" + user + "'"
+    return eval(query)
""",
                language="python",
            ),
            FileEntry(
                path=".env",
                additions=5,
                deletions=0,
                estimated_tokens=200,
                diff_content="""@@ -0,0 +1,5 @@
+DATABASE_URL=postgresql://admin:password123@db:5432/app
+SECRET_KEY=super-secret
+API_TOKEN=tok_live_abc123
""",
            ),
            FileEntry(
                path="src/server.py",
                additions=8,
                deletions=0,
                estimated_tokens=250,
                diff_content="""@@ -0,0 +1,8 @@
+import subprocess
+
+def run_cmd(user_input):
+    subprocess.call(user_input, shell=True)
+
+def process(data):
+    return eval(data)
""",
                language="python",
            ),
        ]

    # ------------------------------------------------------------------
    # Basic pipeline tests
    # ------------------------------------------------------------------

    def test_analyze_empty_files(self):
        """Analyzing empty file list should succeed."""
        report = self.orchestrator.analyze_files(
            files=[], mr_id="test-0", mr_title="Empty MR"
        )
        assert isinstance(report, AnalysisReport)
        assert report.mr_id == "test-0"
        assert len(report.findings) == 0

    def test_analyze_clean_files(self):
        """Analyzing clean files should produce few/no findings."""
        files = self._make_files(5)
        report = self.orchestrator.analyze_files(
            files=files, mr_id="test-clean", mr_title="Clean MR"
        )

        assert isinstance(report, AnalysisReport)
        assert report.total_files_scanned == 5
        assert report.chunks_processed >= 1

    def test_analyze_vulnerable_files(self):
        """Analyzing vulnerable files should detect issues."""
        files = self._make_vulnerable_files()
        report = self.orchestrator.analyze_files(
            files=files, mr_id="test-vuln", mr_title="Vulnerable MR"
        )

        assert isinstance(report, AnalysisReport)
        assert len(report.findings) > 0

        # Should find at least some critical/high issues
        severities = {f.severity for f in report.findings}
        assert Severity.CRITICAL in severities or Severity.HIGH in severities

    def test_analyze_large_file_set(self):
        """Analyzing many files should trigger chunking and succeed."""
        # Create enough files to trigger chunking
        files = self._make_files(50)
        # Set high token counts to trigger chunking
        for f in files:
            f.estimated_tokens = 5000

        report = self.orchestrator.analyze_files(
            files=files, mr_id="test-large", mr_title="Large MR"
        )

        assert isinstance(report, AnalysisReport)
        assert report.chunks_processed >= 1
        assert report.processing_time_seconds > 0

    # ------------------------------------------------------------------
    # Report content tests
    # ------------------------------------------------------------------

    def test_report_has_correct_metadata(self):
        """Report should preserve MR metadata."""
        files = self._make_files(3)
        report = self.orchestrator.analyze_files(
            files=files, mr_id="42", mr_title="Feature: auth"
        )

        assert report.mr_id == "42"
        assert report.mr_title == "Feature: auth"

    def test_report_severity_counts(self):
        """Report severity_counts should match findings."""
        files = self._make_vulnerable_files()
        report = self.orchestrator.analyze_files(
            files=files, mr_id="test", mr_title="Test"
        )

        # Verify severity_counts is consistent with findings
        manual_counts: dict[str, int] = {}
        for f in report.findings:
            manual_counts[f.severity.value] = manual_counts.get(f.severity.value, 0) + 1

        assert report.severity_counts == manual_counts

    def test_report_processing_time(self):
        """Report should have a positive processing time."""
        files = self._make_files(5)
        report = self.orchestrator.analyze_files(
            files=files, mr_id="test", mr_title="Test"
        )
        assert report.processing_time_seconds > 0


class TestChunkProcessor:
    """Test the chunk processor's pattern-matching analysis."""

    def setup_method(self):
        self.processor = ChunkProcessor(use_duo_agents=False)

    def test_detect_hardcoded_secret(self):
        """Should detect hardcoded secrets."""
        from mr_ninja.core.models import Chunk, AgentType

        chunk = Chunk(
            chunk_id=1,
            files=[FileEntry(
                path="config.py",
                estimated_tokens=100,
                diff_content='password = "admin123!"',
            )],
            estimated_tokens=100,
            recommended_agent=AgentType.SECURITY,
        )

        summary = self.processor.process_chunk(chunk)
        security_findings = [
            f for f in summary.findings if f.category == "security"
        ]
        assert len(security_findings) > 0

    def test_detect_eval(self):
        """Should detect unsafe eval() usage."""
        from mr_ninja.core.models import Chunk, AgentType

        chunk = Chunk(
            chunk_id=1,
            files=[FileEntry(
                path="handler.py",
                estimated_tokens=100,
                diff_content='result = eval(user_input)',
            )],
            estimated_tokens=100,
            recommended_agent=AgentType.SECURITY,
        )

        summary = self.processor.process_chunk(chunk)
        eval_findings = [
            f for f in summary.findings if "eval" in f.title.lower()
        ]
        assert len(eval_findings) > 0

    def test_detect_sql_injection(self):
        """Should detect potential SQL injection."""
        from mr_ninja.core.models import Chunk, AgentType

        chunk = Chunk(
            chunk_id=1,
            files=[FileEntry(
                path="db.py",
                estimated_tokens=100,
                diff_content="query = \"SELECT * FROM users WHERE id=\" + request.args['id']",
            )],
            estimated_tokens=100,
            recommended_agent=AgentType.SECURITY,
        )

        summary = self.processor.process_chunk(chunk)
        sql_findings = [
            f for f in summary.findings if "sql" in f.title.lower()
        ]
        assert len(sql_findings) > 0

    def test_code_review_detects_debug_print(self):
        """Should detect debug print statements."""
        from mr_ninja.core.models import Chunk, AgentType

        chunk = Chunk(
            chunk_id=1,
            files=[FileEntry(
                path="handler.py",
                estimated_tokens=100,
                diff_content='print("debugging this value")',
            )],
            estimated_tokens=100,
            recommended_agent=AgentType.CODE_REVIEW,
        )

        summary = self.processor.process_chunk(chunk)
        print_findings = [
            f for f in summary.findings if "print" in f.title.lower() or "debug" in f.title.lower()
        ]
        assert len(print_findings) > 0

    def test_chunk_summary_has_correct_metadata(self):
        """Chunk summary should have correct metadata."""
        from mr_ninja.core.models import Chunk, AgentType

        chunk = Chunk(
            chunk_id=3,
            files=[FileEntry(
                path="app.py",
                estimated_tokens=100,
                diff_content="pass",
            )],
            estimated_tokens=100,
            recommended_agent=AgentType.CODE_REVIEW,
        )

        summary = self.processor.process_chunk(chunk, total_chunks=5)
        assert summary.chunk_id == 3
        assert summary.total_chunks == 5
        assert "app.py" in summary.files_processed
