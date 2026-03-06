"""
tests/test_chunking.py

Tests for the chunking engine — file classification, bin-packing, and plan generation.
"""

import pytest
from mr_ninja.core.chunking_engine import ChunkingEngine
from mr_ninja.core.models import (
    AgentType,
    Chunk,
    ChunkPlan,
    FileEntry,
    FilePriority,
)


class TestFileClassification:
    """Test file priority classification."""

    def setup_method(self):
        self.engine = ChunkingEngine()

    # Security-critical files (P1)
    def test_classify_env_file(self):
        assert self.engine.classify_file(".env") == FilePriority.SECURITY_CRITICAL

    def test_classify_dockerfile(self):
        assert self.engine.classify_file("Dockerfile") == FilePriority.SECURITY_CRITICAL

    def test_classify_terraform(self):
        assert self.engine.classify_file("infra/main.tf") == FilePriority.SECURITY_CRITICAL

    def test_classify_requirements(self):
        assert self.engine.classify_file("requirements.txt") == FilePriority.SECURITY_CRITICAL

    def test_classify_package_json(self):
        assert self.engine.classify_file("package.json") == FilePriority.SECURITY_CRITICAL

    def test_classify_auth_module(self):
        assert self.engine.classify_file("auth/handler.py") == FilePriority.SECURITY_CRITICAL

    def test_classify_gitlab_ci(self):
        assert self.engine.classify_file(".gitlab-ci.yml") == FilePriority.SECURITY_CRITICAL

    def test_classify_pem_file(self):
        assert self.engine.classify_file("certs/server.pem") == FilePriority.SECURITY_CRITICAL

    # Entry points (P2)
    def test_classify_main_py(self):
        assert self.engine.classify_file("main.py") == FilePriority.ENTRY_POINT

    def test_classify_app_js(self):
        assert self.engine.classify_file("app.js") == FilePriority.ENTRY_POINT

    def test_classify_index_ts(self):
        assert self.engine.classify_file("src/index.ts") == FilePriority.ENTRY_POINT

    def test_classify_routes_dir(self):
        assert self.engine.classify_file("routes/user.py") == FilePriority.ENTRY_POINT

    def test_classify_api_dir(self):
        assert self.engine.classify_file("api/v1/endpoint.py") == FilePriority.ENTRY_POINT

    # Changed files (P3 — default)
    def test_classify_regular_file(self):
        assert self.engine.classify_file("src/utils/helpers.py") == FilePriority.CHANGED_FILE

    def test_classify_unknown_extension(self):
        assert self.engine.classify_file("data/report.csv") == FilePriority.CHANGED_FILE

    # Test files (P5)
    def test_classify_test_dir(self):
        assert self.engine.classify_file("tests/test_main.py") == FilePriority.TEST_FILE

    def test_classify_spec_file(self):
        assert self.engine.classify_file("utils.spec.js") == FilePriority.TEST_FILE

    def test_classify_test_suffix(self):
        assert self.engine.classify_file("user_test.go") == FilePriority.TEST_FILE

    def test_classify_conftest(self):
        assert self.engine.classify_file("tests/conftest.py") == FilePriority.TEST_FILE

    # Generated files (P6)
    def test_classify_package_lock(self):
        assert self.engine.classify_file("package-lock.json") == FilePriority.GENERATED

    def test_classify_yarn_lock(self):
        assert self.engine.classify_file("yarn.lock") == FilePriority.GENERATED

    def test_classify_minified_js(self):
        assert self.engine.classify_file("dist/bundle.min.js") == FilePriority.GENERATED

    def test_classify_source_map(self):
        assert self.engine.classify_file("app.js.map") == FilePriority.GENERATED

    def test_classify_node_modules(self):
        assert self.engine.classify_file("node_modules/lodash/index.js") == FilePriority.GENERATED


class TestFileSorting:
    """Test that files are sorted by priority."""

    def setup_method(self):
        self.engine = ChunkingEngine()

    def test_classify_files_sorts_by_priority(self):
        """Files should be sorted with P1 first, P5 last."""
        files = [
            FileEntry(path="tests/test_main.py", estimated_tokens=100, diff_content="test"),
            FileEntry(path="src/handler.py", estimated_tokens=100, diff_content="code"),
            FileEntry(path=".env", estimated_tokens=100, diff_content="secret"),
            FileEntry(path="main.py", estimated_tokens=100, diff_content="entry"),
        ]
        processed, skipped = self.engine.classify_files(files)

        assert len(processed) == 4
        assert processed[0].path == ".env"  # P1
        assert processed[1].path == "main.py"  # P2
        assert processed[2].path == "src/handler.py"  # P3
        assert processed[3].path == "tests/test_main.py"  # P5

    def test_skip_generated_files(self):
        """Generated files should be skipped when skip_generated=True."""
        files = [
            FileEntry(path="src/app.py", estimated_tokens=100, diff_content="code"),
            FileEntry(path="package-lock.json", estimated_tokens=5000, diff_content="lock"),
            FileEntry(path="yarn.lock", estimated_tokens=3000, diff_content="lock"),
        ]
        processed, skipped = self.engine.classify_files(files)

        assert len(processed) == 1
        assert len(skipped) == 2
        assert "package-lock.json" in skipped

    def test_keep_generated_files(self):
        """Generated files should be kept when skip_generated=False."""
        engine = ChunkingEngine(skip_generated=False)
        files = [
            FileEntry(path="package-lock.json", estimated_tokens=5000, diff_content="lock"),
        ]
        processed, skipped = engine.classify_files(files)

        assert len(processed) == 1
        assert len(skipped) == 0


class TestBinPacking:
    """Test the greedy bin-packing algorithm."""

    def setup_method(self):
        self.engine = ChunkingEngine(target_tokens=1000, max_tokens=2000)

    def _make_file(self, path: str, tokens: int) -> FileEntry:
        return FileEntry(
            path=path,
            estimated_tokens=tokens,
            priority=FilePriority.CHANGED_FILE,
            diff_content="x" * (tokens * 4),
        )

    def test_single_chunk_small_input(self):
        """Files fitting in one chunk should produce one chunk."""
        files = [self._make_file(f"file{i}.py", 200) for i in range(4)]
        chunks = self.engine.build_chunks(files)

        assert len(chunks) == 1
        assert chunks[0].file_count == 4

    def test_multiple_chunks(self):
        """Files exceeding target should split into multiple chunks."""
        files = [self._make_file(f"file{i}.py", 400) for i in range(10)]
        chunks = self.engine.build_chunks(files)

        assert len(chunks) >= 3
        for chunk in chunks:
            assert chunk.estimated_tokens <= self.engine.target_tokens + 400

    def test_oversized_file_own_chunk(self):
        """A file larger than target_tokens gets its own chunk."""
        files = [
            self._make_file("small.py", 200),
            self._make_file("huge.py", 1500),  # > 1000 target
            self._make_file("another.py", 200),
        ]
        chunks = self.engine.build_chunks(files)

        # huge.py should be in its own chunk
        huge_chunks = [c for c in chunks if "huge.py" in c.file_paths]
        assert len(huge_chunks) == 1
        assert huge_chunks[0].file_count == 1

    def test_empty_input(self):
        """Empty file list should produce no chunks."""
        chunks = self.engine.build_chunks([])
        assert len(chunks) == 0

    def test_chunk_ids_sequential(self):
        """Chunk IDs should be sequential starting at 1."""
        files = [self._make_file(f"file{i}.py", 400) for i in range(8)]
        chunks = self.engine.build_chunks(files)

        for i, chunk in enumerate(chunks):
            assert chunk.chunk_id == i + 1


class TestAgentTypeDetection:
    """Test that chunks get the correct recommended agent."""

    def setup_method(self):
        self.engine = ChunkingEngine(target_tokens=100_000)

    def test_security_files_get_security_agent(self):
        """Chunks with only security files should use security agent."""
        files = [
            FileEntry(
                path=".env",
                estimated_tokens=100,
                priority=FilePriority.SECURITY_CRITICAL,
                diff_content="SECRET=xxx",
            ),
        ]
        processed, _ = self.engine.classify_files(files)
        chunks = self.engine.build_chunks(processed)

        assert chunks[0].recommended_agent == AgentType.SECURITY

    def test_code_files_get_code_review_agent(self):
        """Chunks with only code files should use code_review agent."""
        files = [
            FileEntry(
                path="src/utils.py",
                estimated_tokens=100,
                priority=FilePriority.CHANGED_FILE,
                diff_content="def foo(): pass",
            ),
        ]
        processed, _ = self.engine.classify_files(files)
        chunks = self.engine.build_chunks(processed)

        assert chunks[0].recommended_agent == AgentType.CODE_REVIEW

    def test_mixed_files_get_mixed_agent(self):
        """Chunks with both security and code files should use mixed agent."""
        files = [
            FileEntry(
                path=".env",
                estimated_tokens=100,
                priority=FilePriority.SECURITY_CRITICAL,
                diff_content="SECRET=xxx",
            ),
            FileEntry(
                path="src/handler.py",
                estimated_tokens=100,
                priority=FilePriority.CHANGED_FILE,
                diff_content="def handler(): pass",
            ),
        ]
        processed, _ = self.engine.classify_files(files)
        chunks = self.engine.build_chunks(processed)

        assert chunks[0].recommended_agent == AgentType.MIXED


class TestChunkPlanCreation:
    """Test full plan creation."""

    def setup_method(self):
        self.engine = ChunkingEngine(target_tokens=500, trigger_tokens=1000)

    def _make_file(self, path: str, tokens: int) -> FileEntry:
        return FileEntry(
            path=path,
            estimated_tokens=tokens,
            diff_content="x" * (tokens * 4),
        )

    def test_plan_below_threshold(self):
        """Below trigger threshold should produce a non-chunked plan."""
        files = [self._make_file(f"file{i}.py", 100) for i in range(5)]
        # 5 * 100 = 500 tokens, below trigger_tokens=1000
        plan = self.engine.create_plan(files, mr_id="1", mr_title="Test MR")

        assert plan.chunking_required is False
        assert plan.chunk_count == 1
        assert plan.total_files == 5

    def test_plan_above_threshold(self):
        """Above trigger threshold should produce a chunked plan."""
        files = [self._make_file(f"file{i}.py", 300) for i in range(10)]
        # 10 * 300 = 3000 tokens, above trigger_tokens=1000
        plan = self.engine.create_plan(files, mr_id="2", mr_title="Big MR")

        assert plan.chunking_required is True
        assert plan.chunk_count > 1

    def test_plan_preserves_metadata(self):
        """Plan should preserve MR metadata."""
        files = [self._make_file("test.py", 100)]
        plan = self.engine.create_plan(
            files,
            mr_id="42",
            mr_title="Feature: big change",
            mr_url="https://gitlab.com/group/project/-/merge_requests/42",
            project_id="group/project",
        )

        assert plan.mr_id == "42"
        assert plan.mr_title == "Feature: big change"
        assert plan.project_id == "group/project"

    def test_plan_skipped_files(self):
        """Plan should report skipped generated files."""
        files = [
            self._make_file("src/app.py", 100),
            self._make_file("package-lock.json", 5000),
        ]
        plan = self.engine.create_plan(files)

        assert "package-lock.json" in plan.skipped_files
        assert plan.total_files == 2  # original count
