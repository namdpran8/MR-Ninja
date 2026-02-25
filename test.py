"""
tests/test_mr_chunker.py

Run with: python -m pytest tests/ -v
"""

import pytest
from mr_ninja import (
    MRChunker, FileEntry, ChunkSummary, FindingsAggregator,
    TOKEN_TRIGGER, TOKEN_CHUNK_TARGET, parse_mr_url,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_file(path: str, tokens: int = 5000, priority: int = 3) -> FileEntry:
    return FileEntry(
        path=path,
        additions=100,
        deletions=20,
        estimated_tokens=tokens,
        priority=priority,
    )


def fake_diffs(count: int, tokens_each: int = 5000) -> list[dict]:
    return [
        {
            "new_path": f"src/module_{i}.py",
            "old_path": f"src/module_{i}.py",
            "diff": "+" * (tokens_each * 4),   # 4 chars/token heuristic
            "a_mode": "100644",
        }
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Priority classification
# ---------------------------------------------------------------------------

class TestPriorityClassification:
    def setup_method(self):
        self.chunker = MRChunker(token="fake")

    def test_security_files_get_priority_1(self):
        security_files = [
            "config/.env", "src/auth/token.py", "k8s/secrets.yaml",
            "Dockerfile", "terraform/main.tf", "requirements.txt",
        ]
        for path in security_files:
            entry = FileEntry(path=path, additions=10, deletions=0, estimated_tokens=500, priority=0)
            p = self.chunker._get_priority(path)
            assert p == 1, f"Expected P1 for {path}, got {p}"

    def test_entry_points_get_priority_2(self):
        for path in ["src/main.py", "app.js", "server/index.ts", "api/routes/v1.py"]:
            p = self.chunker._get_priority(path)
            assert p == 2, f"Expected P2 for {path}, got {p}"

    def test_tests_get_priority_5(self):
        for path in ["tests/test_auth.py", "spec/models/user_spec.rb", "src/auth.test.ts"]:
            p = self.chunker._get_priority(path)
            assert p == 5, f"Expected P5 for {path}, got {p}"

    def test_generated_files_get_priority_6(self):
        for path in ["package-lock.json", "yarn.lock", "go.sum", "dist/bundle.min.js"]:
            p = self.chunker._get_priority(path)
            assert p == 6, f"Expected P6 for {path}, got {p}"

    def test_regular_files_get_default_priority(self):
        from pipeline.mr_chunker import DEFAULT_PRIORITY
        p = self.chunker._get_priority("src/utils/helpers.py")
        assert p == DEFAULT_PRIORITY


# ---------------------------------------------------------------------------
# Token estimation
# ---------------------------------------------------------------------------

class TestTokenEstimation:
    def setup_method(self):
        self.chunker = MRChunker(token="fake")

    def test_empty_string(self):
        assert self.chunker.estimate_tokens("") == 1  # floor

    def test_4_chars_equals_1_token(self):
        assert self.chunker.estimate_tokens("a" * 400) == 100

    def test_large_text(self):
        text = "x" * 400_000
        assert self.chunker.estimate_tokens(text) == 100_000


# ---------------------------------------------------------------------------
# Chunk packing
# ---------------------------------------------------------------------------

class TestChunkPacking:
    def setup_method(self):
        self.chunker = MRChunker(token="fake", max_chunk_tokens=70_000)

    def test_single_pass_when_small(self):
        files = [make_file(f"src/f{i}.py", tokens=5_000) for i in range(5)]
        chunks = self.chunker._make_single_chunk(files)
        assert chunks.chunk_id == 1
        assert len(chunks.files) == 5

    def test_splits_into_multiple_chunks(self):
        # 10 files × 20k tokens = 200k total → should produce 3+ chunks with 70k limit
        files = [make_file(f"src/f{i}.py", tokens=20_000) for i in range(10)]
        chunks = self.chunker._pack_chunks(files)
        assert len(chunks) >= 3
        for chunk in chunks:
            assert chunk.estimated_tokens <= 70_000 + 20_000  # max 1 file overflow

    def test_oversized_single_file_gets_own_chunk(self):
        files = [
            make_file("small.py", tokens=10_000),
            make_file("giant.py", tokens=95_000),   # exceeds max
            make_file("other.py", tokens=10_000),
        ]
        chunks = self.chunker._pack_chunks(files)
        giant_chunks = [c for c in chunks if any(f.path == "giant.py" for f in c.files)]
        assert len(giant_chunks) == 1
        assert len(giant_chunks[0].files) == 1

    def test_priority_order_preserved(self):
        files = [
            make_file("tests/test_auth.py", tokens=5_000, priority=5),
            make_file("src/main.py", tokens=5_000, priority=2),
            make_file(".env", tokens=1_000, priority=1),
        ]
        # After sort, .env (P1) → main.py (P2) → test (P5)
        files.sort(key=lambda f: f.priority)
        assert files[0].path == ".env"
        assert files[1].path == "src/main.py"
        assert files[2].path == "tests/test_auth.py"


# ---------------------------------------------------------------------------
# Agent recommendation
# ---------------------------------------------------------------------------

class TestAgentRecommendation:
    def setup_method(self):
        self.chunker = MRChunker(token="fake")

    def test_security_only(self):
        files = [make_file(".env", priority=1), make_file("secrets.yaml", priority=1)]
        assert self.chunker._recommended_agent(files) == "security"

    def test_code_review_only(self):
        files = [make_file("src/utils.py", priority=3), make_file("lib/parser.py", priority=3)]
        assert self.chunker._recommended_agent(files) == "code_review"

    def test_mixed_chunk(self):
        files = [make_file(".env", priority=1), make_file("src/utils.py", priority=3)]
        assert self.chunker._recommended_agent(files) == "mixed"


# ---------------------------------------------------------------------------
# Cross-chunk context header
# ---------------------------------------------------------------------------

class TestCrossChunkContext:
    def test_empty_summary_header(self):
        cs = ChunkSummary.empty(1, 5)
        header = cs.to_context_header()
        assert "=== CROSS-CHUNK CONTEXT" in header
        assert "=== END CONTEXT ===" in header

    def test_header_includes_open_questions(self):
        cs = ChunkSummary(
            chunk_id=2,
            total_chunks=4,
            files_processed=["auth.py"],
            findings=[],
            imports_exported=["verify_token"],
            open_questions=["Is verify_token called with proper scopes in later modules?"],
        )
        header = cs.to_context_header()
        assert "verify_token" in header
        assert "Is verify_token called" in header

    def test_header_includes_critical_findings(self):
        cs = ChunkSummary(
            chunk_id=1,
            total_chunks=3,
            files_processed=["secrets.yaml"],
            findings=[{"file": "secrets.yaml", "severity": "CRITICAL", "summary": "Hardcoded API key", "line": 12}],
            imports_exported=[],
            open_questions=[],
        )
        header = cs.to_context_header()
        assert "CRITICAL" in header
        assert "Hardcoded API key" in header


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

class TestFindingsAggregator:
    def make_summary(self, chunk_id: int, findings: list[dict], questions: list[str] = None) -> ChunkSummary:
        return ChunkSummary(
            chunk_id=chunk_id,
            total_chunks=3,
            files_processed=[f"file{chunk_id}.py"],
            findings=findings,
            imports_exported=[],
            open_questions=questions or [],
        )

    def test_deduplicates_same_file_same_type(self):
        agg = FindingsAggregator()
        s1 = self.make_summary(1, [{"file": "auth.py", "type": "sqli", "severity": "MEDIUM", "summary": "SQL injection risk"}])
        s2 = self.make_summary(2, [{"file": "auth.py", "type": "sqli", "severity": "HIGH", "summary": "SQL injection confirmed"}])
        agg.ingest_chunk_summary(s1)
        agg.ingest_chunk_summary(s2)
        findings = agg.get_sorted_findings()
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"  # higher severity wins

    def test_keeps_different_types_from_same_file(self):
        agg = FindingsAggregator()
        s1 = self.make_summary(1, [
            {"file": "auth.py", "type": "sqli",  "severity": "HIGH",   "summary": "SQL injection"},
            {"file": "auth.py", "type": "xss",   "severity": "MEDIUM", "summary": "XSS risk"},
        ])
        agg.ingest_chunk_summary(s1)
        assert len(agg.get_sorted_findings()) == 2

    def test_sorted_by_severity(self):
        agg = FindingsAggregator()
        s = self.make_summary(1, [
            {"file": "a.py", "type": "a", "severity": "LOW",      "summary": "low"},
            {"file": "b.py", "type": "b", "severity": "CRITICAL", "summary": "crit"},
            {"file": "c.py", "type": "c", "severity": "MEDIUM",   "summary": "med"},
        ])
        agg.ingest_chunk_summary(s)
        findings = agg.get_sorted_findings()
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[1]["severity"] == "MEDIUM"
        assert findings[2]["severity"] == "LOW"


# ---------------------------------------------------------------------------
# URL parser
# ---------------------------------------------------------------------------

class TestParseMrUrl:
    def test_standard_gitlab_com_url(self):
        pid, iid = parse_mr_url("https://gitlab.com/mygroup/myproject/-/merge_requests/42")
        assert pid == "mygroup/myproject"
        assert iid == 42

    def test_nested_group_url(self):
        pid, iid = parse_mr_url("https://gitlab.com/a/b/c/-/merge_requests/7")
        assert pid == "a/b/c"
        assert iid == 7

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            parse_mr_url("https://github.com/org/repo/pull/42")
