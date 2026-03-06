"""
core/token_estimator.py

Token estimation engine for Mr Ninja.

Uses a character-based heuristic (1 token ~ 4 characters) to estimate
how many tokens a file or diff will consume in an LLM context window.

This avoids the overhead of running a real tokenizer while staying
within ~10% accuracy for code content — plenty accurate for chunking decisions.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger("mr_ninja.token_estimator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Base heuristic: 1 token ≈ 4 characters for English/code
CHARS_PER_TOKEN = 4

# Trigger threshold — if total tokens exceed this, chunking is mandatory
CHUNKING_TRIGGER_TOKENS = 150_000

# Chunk size targets
CHUNK_TARGET_TOKENS = 70_000    # aim for this per chunk
CHUNK_MAX_TOKENS = 100_000      # hard ceiling per chunk
CHUNK_MIN_TOKENS = 5_000        # minimum useful chunk size

# Floor: even tiny files get at least this many estimated tokens
# (accounts for file metadata overhead in context)
MIN_FILE_TOKENS = 100


class TokenEstimator:
    """Estimates token counts for text content.

    Uses a character-based heuristic that is fast and dependency-free.
    Different content types have slightly different ratios:
    - Code: ~4 chars/token (lots of symbols, short identifiers)
    - Prose: ~4.5 chars/token (longer words)
    - JSON/YAML: ~3.5 chars/token (lots of punctuation)
    """

    def __init__(
        self,
        chars_per_token: int = CHARS_PER_TOKEN,
        min_file_tokens: int = MIN_FILE_TOKENS,
    ):
        self.chars_per_token = chars_per_token
        self.min_file_tokens = min_file_tokens

    def estimate(self, text: str) -> int:
        """Estimate token count for a string.

        Args:
            text: Raw text content to estimate.

        Returns:
            Estimated token count (minimum: 1).
        """
        if not text:
            return 0
        return max(1, len(text) // self.chars_per_token)

    def estimate_file(self, content: str, path: str = "") -> int:
        """Estimate tokens for a file, with content-type adjustment.

        Applies a small multiplier based on file extension to improve accuracy.
        Also enforces the minimum file token floor.

        Args:
            content: File content or diff text.
            path: File path (used for content-type detection).

        Returns:
            Estimated token count (minimum: min_file_tokens).
        """
        if not content:
            return self.min_file_tokens

        base = self.estimate(content)

        # Apply content-type multiplier
        multiplier = self._get_content_multiplier(path)
        adjusted = int(base * multiplier)

        return max(adjusted, self.min_file_tokens)

    def estimate_diff(self, diff_text: str) -> int:
        """Estimate tokens specifically for a diff.

        Diffs have extra overhead from +/- markers, @@ headers, etc.
        Apply a small overhead factor to account for this.
        """
        if not diff_text:
            return self.min_file_tokens

        base = self.estimate(diff_text)
        # Diff headers and markers add ~10% overhead
        return max(int(base * 1.1), self.min_file_tokens)

    def needs_chunking(self, total_tokens: int) -> bool:
        """Check if total token count exceeds the chunking trigger threshold."""
        return total_tokens > CHUNKING_TRIGGER_TOKENS

    def calculate_chunk_count(self, total_tokens: int) -> int:
        """Calculate how many chunks are needed for a given token count.

        Returns minimum 1 chunk even if under threshold.
        """
        if total_tokens <= CHUNK_TARGET_TOKENS:
            return 1
        # Round up to ensure all content fits
        count = (total_tokens + CHUNK_TARGET_TOKENS - 1) // CHUNK_TARGET_TOKENS
        return max(1, count)

    def _get_content_multiplier(self, path: str) -> float:
        """Get a token estimation multiplier based on file type.

        JSON/YAML use more tokens per character (lots of punctuation).
        Prose uses fewer (longer words).
        """
        if not path:
            return 1.0

        path_lower = path.lower()

        # JSON and YAML are token-heavy (lots of braces, quotes, colons)
        if path_lower.endswith((".json", ".yaml", ".yml")):
            return 1.15

        # Minified files are very token-dense
        if path_lower.endswith((".min.js", ".min.css")):
            return 1.3

        # Markdown / docs are more token-efficient
        if path_lower.endswith((".md", ".rst", ".txt")):
            return 0.9

        # Lock files are highly repetitive but still token-heavy
        if any(lock in path_lower for lock in
               ("package-lock", "yarn.lock", "gemfile.lock", "poetry.lock")):
            return 1.2

        return 1.0

    @staticmethod
    def format_tokens(count: int) -> str:
        """Human-readable token count string."""
        if count >= 1_000_000:
            return f"{count / 1_000_000:.1f}M"
        if count >= 1_000:
            return f"{count / 1_000:.1f}k"
        return str(count)


# Module-level convenience instance
_default_estimator = TokenEstimator()


def estimate_tokens(text: str) -> int:
    """Module-level convenience function for token estimation."""
    return _default_estimator.estimate(text)


def estimate_file_tokens(content: str, path: str = "") -> int:
    """Module-level convenience function for file token estimation."""
    return _default_estimator.estimate_file(content, path)


def needs_chunking(total_tokens: int) -> bool:
    """Module-level convenience: check if chunking is needed."""
    return _default_estimator.needs_chunking(total_tokens)
