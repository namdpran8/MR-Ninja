"""
tests/test_token_estimator.py

Tests for the token estimation engine.
"""

import pytest
from mr_ninja.core.token_estimator import (
    TokenEstimator,
    estimate_tokens,
    estimate_file_tokens,
    needs_chunking,
    CHUNKING_TRIGGER_TOKENS,
    CHUNK_TARGET_TOKENS,
    CHARS_PER_TOKEN,
)


class TestTokenEstimator:
    """Test suite for TokenEstimator."""

    def setup_method(self):
        self.estimator = TokenEstimator()

    # ------------------------------------------------------------------
    # Basic estimation
    # ------------------------------------------------------------------

    def test_estimate_empty_string(self):
        """Empty string should return 0 tokens."""
        assert self.estimator.estimate("") == 0

    def test_estimate_short_string(self):
        """Short string estimation."""
        # 8 chars / 4 chars_per_token = 2 tokens
        assert self.estimator.estimate("12345678") == 2

    def test_estimate_minimum_one(self):
        """Even a single character should return at least 1 token."""
        assert self.estimator.estimate("a") == 1

    def test_estimate_known_length(self):
        """Test with a string of known length."""
        text = "a" * 400  # 400 chars / 4 = 100 tokens
        assert self.estimator.estimate(text) == 100

    def test_estimate_code_content(self):
        """Estimate tokens for realistic code content."""
        code = 'def hello():\n    print("Hello, world!")\n'
        result = self.estimator.estimate(code)
        assert result > 0
        assert result == len(code) // CHARS_PER_TOKEN

    # ------------------------------------------------------------------
    # File estimation
    # ------------------------------------------------------------------

    def test_estimate_file_empty(self):
        """Empty file should return min_file_tokens."""
        result = self.estimator.estimate_file("", "test.py")
        assert result == self.estimator.min_file_tokens

    def test_estimate_file_python(self):
        """Python file estimation (multiplier = 1.0)."""
        content = "x" * 400  # 100 tokens base
        result = self.estimator.estimate_file(content, "main.py")
        assert result == 100  # 1.0 multiplier

    def test_estimate_file_json_multiplier(self):
        """JSON files should have a higher token estimate."""
        content = "x" * 400  # 100 tokens base
        result = self.estimator.estimate_file(content, "data.json")
        # 100 base * 1.15 = 115.0 (may be 114 due to float precision)
        assert result >= 114
        assert result <= 115

    def test_estimate_file_yaml_multiplier(self):
        """YAML files should have a higher token estimate."""
        content = "x" * 400
        result = self.estimator.estimate_file(content, "config.yaml")
        assert result >= 114
        assert result <= 115

    def test_estimate_file_markdown_multiplier(self):
        """Markdown files should have a lower token estimate."""
        content = "x" * 400
        result = self.estimator.estimate_file(content, "README.md")
        # 100 base * 0.9 = 90.0 — but min_file_tokens floor is 100
        assert result >= 90
        assert result <= 100

    def test_estimate_file_minified_multiplier(self):
        """Minified files should have a higher token estimate."""
        content = "x" * 400
        result = self.estimator.estimate_file(content, "bundle.min.js")
        assert result == 130  # 1.3 multiplier

    def test_estimate_file_min_floor(self):
        """Small files should return at least min_file_tokens."""
        result = self.estimator.estimate_file("x", "tiny.py")
        assert result == self.estimator.min_file_tokens

    # ------------------------------------------------------------------
    # Diff estimation
    # ------------------------------------------------------------------

    def test_estimate_diff_overhead(self):
        """Diff estimation should include 10% overhead."""
        diff = "+" * 440  # 110 tokens base, * 1.1 = 121
        result = self.estimator.estimate_diff(diff)
        assert result == 121

    def test_estimate_diff_empty(self):
        """Empty diff should return min_file_tokens."""
        result = self.estimator.estimate_diff("")
        assert result == self.estimator.min_file_tokens

    # ------------------------------------------------------------------
    # Chunking decisions
    # ------------------------------------------------------------------

    def test_needs_chunking_below_threshold(self):
        """Below threshold should not need chunking."""
        assert self.estimator.needs_chunking(100_000) is False

    def test_needs_chunking_above_threshold(self):
        """Above threshold should need chunking."""
        assert self.estimator.needs_chunking(200_000) is True

    def test_needs_chunking_at_threshold(self):
        """At exactly the threshold should not need chunking."""
        assert self.estimator.needs_chunking(CHUNKING_TRIGGER_TOKENS) is False

    def test_needs_chunking_just_above(self):
        """One token above threshold should need chunking."""
        assert self.estimator.needs_chunking(CHUNKING_TRIGGER_TOKENS + 1) is True

    # ------------------------------------------------------------------
    # Chunk count calculation
    # ------------------------------------------------------------------

    def test_calculate_chunk_count_small(self):
        """Small input should need just 1 chunk."""
        assert self.estimator.calculate_chunk_count(50_000) == 1

    def test_calculate_chunk_count_two_chunks(self):
        """Input slightly over target should need 2 chunks."""
        assert self.estimator.calculate_chunk_count(80_000) == 2

    def test_calculate_chunk_count_many_chunks(self):
        """Large input should need multiple chunks."""
        result = self.estimator.calculate_chunk_count(500_000)
        assert result >= 7  # 500k / 70k ≈ 7.14

    def test_calculate_chunk_count_zero(self):
        """Zero tokens should still return 1 chunk."""
        assert self.estimator.calculate_chunk_count(0) == 1

    # ------------------------------------------------------------------
    # Format tokens
    # ------------------------------------------------------------------

    def test_format_tokens_small(self):
        assert TokenEstimator.format_tokens(500) == "500"

    def test_format_tokens_thousands(self):
        assert TokenEstimator.format_tokens(70_000) == "70.0k"

    def test_format_tokens_millions(self):
        assert TokenEstimator.format_tokens(1_500_000) == "1.5M"

    # ------------------------------------------------------------------
    # Module-level convenience functions
    # ------------------------------------------------------------------

    def test_module_estimate_tokens(self):
        """Test module-level estimate_tokens function."""
        assert estimate_tokens("a" * 100) == 25

    def test_module_estimate_file_tokens(self):
        """Test module-level estimate_file_tokens function."""
        result = estimate_file_tokens("a" * 400, "test.py")
        assert result == 100

    def test_module_needs_chunking(self):
        """Test module-level needs_chunking function."""
        assert needs_chunking(200_000) is True
        assert needs_chunking(100_000) is False
