"""
agents/chunk_processor.py

Chunk Processor Agent for Mr Ninja.

Processes a single chunk through specialist analysis agents:
- Security Analyst: scans for vulnerabilities, hardcoded secrets, unsafe patterns
- Code Reviewer: evaluates code quality, patterns, complexity
- Dependency Analyzer: checks dependency risks

In production, these would invoke GitLab Duo sub-agents. In demo mode,
they use pattern-matching heuristics to simulate realistic findings.
"""

from __future__ import annotations

import logging
import re
import time

from mr_ninja.core.models import (
    AgentType,
    Chunk,
    ChunkSummary,
    Finding,
    Severity,
)

logger = logging.getLogger("mr_ninja.chunk_processor")


# ---------------------------------------------------------------------------
# Security scanning patterns (heuristic-based for demo/offline mode)
# ---------------------------------------------------------------------------

SECURITY_PATTERNS: list[tuple[str, Severity, str, str]] = [
    # (regex pattern, severity, title, recommendation)
    (
        r"""(?:password|passwd|secret|api_key|apikey|token|credential)"""
        r"""\s*[=:]\s*["'][^"']{4,}["']""",
        Severity.CRITICAL,
        "Hardcoded secret or credential",
        "Move to environment variables or a secrets manager (e.g., GitLab CI/CD variables)",
    ),
    (
        r"\beval\s*\(",
        Severity.HIGH,
        "Unsafe eval() usage",
        "Replace eval() with a safe parser. eval() enables arbitrary code execution",
    ),
    (
        r"\bexec\s*\(",
        Severity.HIGH,
        "Unsafe exec() usage",
        "Avoid exec() — use structured alternatives to prevent code injection",
    ),
    (
        r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True",
        Severity.HIGH,
        "Shell injection risk via subprocess",
        "Use shell=False and pass arguments as a list",
    ),
    (
        r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*(?:request|user|input|params)",
        Severity.CRITICAL,
        "Potential SQL injection",
        "Use parameterized queries or an ORM instead of string concatenation",
    ),
    (
        r"innerHTML\s*=",
        Severity.HIGH,
        "XSS risk via innerHTML",
        "Use textContent or a sanitization library instead of innerHTML",
    ),
    (
        r"dangerouslySetInnerHTML",
        Severity.HIGH,
        "XSS risk via dangerouslySetInnerHTML",
        "Sanitize input with DOMPurify before using dangerouslySetInnerHTML",
    ),
    (
        r"(?:http|ftp)://(?!localhost|127\.0\.0\.1)",
        Severity.MEDIUM,
        "Non-HTTPS URL detected",
        "Use HTTPS for all external connections to prevent MITM attacks",
    ),
    (
        r"(?:PRIVATE.KEY|BEGIN RSA|BEGIN DSA|BEGIN EC)",
        Severity.CRITICAL,
        "Private key found in source code",
        "Remove immediately. Store private keys in a secure vault, never in source",
    ),
    (
        r"(?:TODO|FIXME|HACK|XXX).*(?:security|auth|cred|password|token)",
        Severity.MEDIUM,
        "Security-related TODO/FIXME",
        "Address security TODOs before merging to production",
    ),
    (
        r"verify\s*=\s*False",
        Severity.HIGH,
        "SSL verification disabled",
        "Enable SSL verification. Disabling it allows MITM attacks",
    ),
    (
        r"(?:chmod|os\.chmod)\s*\(\s*[^,]+,\s*0o?777",
        Severity.HIGH,
        "World-writable file permissions",
        "Use least-privilege permissions (e.g., 0o644 or 0o600)",
    ),
    (
        r"pickle\.loads?\(",
        Severity.HIGH,
        "Unsafe deserialization with pickle",
        "Use json or a safer serialization format. Pickle can execute arbitrary code",
    ),
]


# ---------------------------------------------------------------------------
# Code quality patterns
# ---------------------------------------------------------------------------

QUALITY_PATTERNS: list[tuple[str, Severity, str, str]] = [
    (
        r"(?:except|catch)\s*(?:\(\s*\)|\s*:)",
        Severity.MEDIUM,
        "Bare except/catch clause",
        "Catch specific exception types instead of using bare except",
    ),
    (
        r"(?:print|console\.log|System\.out\.print)\s*\(",
        Severity.LOW,
        "Debug print statement left in code",
        "Remove debug print statements before merging",
    ),
    (
        r"#\s*(?:TODO|FIXME|HACK|XXX)",
        Severity.INFO,
        "TODO/FIXME comment",
        "Track TODOs as issues rather than code comments",
    ),
    (
        r"\.{3}pass\b",
        Severity.LOW,
        "Empty function body (pass statement)",
        "Implement the function or add a NotImplementedError",
    ),
    (
        r"(?:time\.sleep|Thread\.sleep|sleep)\s*\(\s*\d{2,}",
        Severity.MEDIUM,
        "Long sleep/delay in code",
        "Use async patterns or event-based waits instead of long sleeps",
    ),
    (
        r"(?:global|nonlocal)\s+\w+",
        Severity.LOW,
        "Global/nonlocal variable usage",
        "Consider refactoring to avoid global state",
    ),
]


# ---------------------------------------------------------------------------
# Dependency risk patterns
# ---------------------------------------------------------------------------

DEPENDENCY_PATTERNS: list[tuple[str, Severity, str, str]] = [
    (
        r'(?:lodash|underscore|moment|request|left-pad)["\']\s*:',
        Severity.MEDIUM,
        "Potentially deprecated/risky dependency",
        "Check for CVEs and consider modern alternatives",
    ),
    (
        r'["\']\*["\']\s*$',
        Severity.HIGH,
        "Wildcard version specifier",
        "Pin to a specific version range to prevent supply chain attacks",
    ),
    (
        r">=\s*0\.",
        Severity.MEDIUM,
        "Overly broad version range",
        "Use a tighter version constraint to avoid breaking changes",
    ),
]


class ChunkProcessor:
    """Processes a single chunk through specialist analysis agents.

    In demo/offline mode, uses pattern-matching heuristics to simulate
    realistic security and code quality findings. In production mode,
    would delegate to GitLab Duo sub-agents.

    The processor runs the appropriate specialist(s) based on the chunk's
    recommended_agent field:
    - SECURITY: runs security analysis
    - CODE_REVIEW: runs code quality analysis
    - DEPENDENCY: runs dependency risk analysis
    - MIXED: runs security + code quality
    """

    def __init__(self, use_duo_agents: bool = False):
        """Initialize the chunk processor.

        Args:
            use_duo_agents: If True, invoke real GitLab Duo agents.
                           If False, use pattern-matching heuristics (demo mode).
        """
        self.use_duo_agents = use_duo_agents

    def process_chunk(
        self,
        chunk: Chunk,
        prior_context: str = "",
        total_chunks: int = 1,
    ) -> ChunkSummary:
        """Process a single chunk through the appropriate specialist agents.

        Args:
            chunk: The chunk to analyze.
            prior_context: Cross-chunk context from previously processed chunks.
            total_chunks: Total number of chunks in the plan.

        Returns:
            ChunkSummary with findings and context for the next chunk.
        """
        start = time.time()
        logger.info(
            f"Processing chunk {chunk.chunk_id}/{total_chunks} "
            f"({chunk.file_count} files, ~{chunk.estimated_tokens:,} tokens, "
            f"agent={chunk.recommended_agent.value})"
        )

        all_findings: list[Finding] = []
        imports_exported: list[str] = []
        open_questions: list[str] = []

        # Run the appropriate specialist(s)
        if chunk.recommended_agent in (AgentType.SECURITY, AgentType.MIXED):
            findings = self._run_security_analysis(chunk)
            all_findings.extend(findings)
            logger.info(f"  Security analysis: {len(findings)} findings")

        if chunk.recommended_agent in (AgentType.CODE_REVIEW, AgentType.MIXED):
            findings = self._run_code_review(chunk)
            all_findings.extend(findings)
            logger.info(f"  Code review: {len(findings)} findings")

        if chunk.recommended_agent == AgentType.DEPENDENCY:
            findings = self._run_dependency_analysis(chunk)
            all_findings.extend(findings)
            logger.info(f"  Dependency analysis: {len(findings)} findings")

        # Always run dependency check on package files
        dep_files = [
            f for f in chunk.files
            if any(pkg in f.path.lower() for pkg in
                   ("package.json", "requirements", "gemfile",
                    "pyproject.toml", "go.mod", "cargo.toml"))
        ]
        if dep_files and chunk.recommended_agent != AgentType.DEPENDENCY:
            findings = self._run_dependency_analysis(
                Chunk(
                    chunk_id=chunk.chunk_id,
                    files=dep_files,
                    estimated_tokens=sum(f.estimated_tokens for f in dep_files),
                    recommended_agent=AgentType.DEPENDENCY,
                )
            )
            all_findings.extend(findings)

        # Extract exports and open questions
        imports_exported = self._extract_exports(chunk)
        open_questions = self._identify_open_questions(chunk, all_findings)

        elapsed = time.time() - start

        summary = ChunkSummary(
            chunk_id=chunk.chunk_id,
            total_chunks=total_chunks,
            files_processed=[f.path for f in chunk.files],
            findings=all_findings,
            imports_exported=imports_exported,
            open_questions=open_questions,
            processing_time_seconds=round(elapsed, 2),
        )

        logger.info(
            f"Chunk {chunk.chunk_id} complete: "
            f"{len(all_findings)} findings, {elapsed:.2f}s"
        )

        return summary

    # ------------------------------------------------------------------
    # Specialist analysis methods
    # ------------------------------------------------------------------

    def _run_security_analysis(self, chunk: Chunk) -> list[Finding]:
        """Scan chunk files for security vulnerabilities."""
        findings: list[Finding] = []

        for file_entry in chunk.files:
            content = file_entry.diff_content
            if not content:
                continue

            for pattern, severity, title, recommendation in SECURITY_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # Estimate line number from match position
                    line_no = content[:match.start()].count("\n") + 1

                    findings.append(Finding(
                        file=file_entry.path,
                        line=line_no,
                        severity=severity,
                        category="security",
                        title=title,
                        description=f"Found: {match.group()[:80]}",
                        recommendation=recommendation,
                        rule_id=f"SEC-{title[:20].upper().replace(' ', '-')}",
                        chunk_id=chunk.chunk_id,
                    ))

        return findings

    def _run_code_review(self, chunk: Chunk) -> list[Finding]:
        """Analyze chunk files for code quality issues."""
        findings: list[Finding] = []

        for file_entry in chunk.files:
            content = file_entry.diff_content
            if not content:
                continue

            for pattern, severity, title, recommendation in QUALITY_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_no = content[:match.start()].count("\n") + 1

                    findings.append(Finding(
                        file=file_entry.path,
                        line=line_no,
                        severity=severity,
                        category="quality",
                        title=title,
                        description=f"Found: {match.group()[:80]}",
                        recommendation=recommendation,
                        rule_id=f"QUA-{title[:20].upper().replace(' ', '-')}",
                        chunk_id=chunk.chunk_id,
                    ))

        return findings

    def _run_dependency_analysis(self, chunk: Chunk) -> list[Finding]:
        """Analyze chunk files for dependency risks."""
        findings: list[Finding] = []

        for file_entry in chunk.files:
            content = file_entry.diff_content
            if not content:
                continue

            for pattern, severity, title, recommendation in DEPENDENCY_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_no = content[:match.start()].count("\n") + 1

                    findings.append(Finding(
                        file=file_entry.path,
                        line=line_no,
                        severity=severity,
                        category="dependency",
                        title=title,
                        description=f"Found: {match.group()[:80]}",
                        recommendation=recommendation,
                        rule_id=f"DEP-{title[:20].upper().replace(' ', '-')}",
                        chunk_id=chunk.chunk_id,
                    ))

        return findings

    # ------------------------------------------------------------------
    # Context extraction helpers
    # ------------------------------------------------------------------

    def _extract_exports(self, chunk: Chunk) -> list[str]:
        """Extract exported symbols/modules from chunk files.

        These are passed in the cross-chunk context so downstream
        chunks know what's available from upstream.
        """
        exports: list[str] = []

        for file_entry in chunk.files:
            content = file_entry.diff_content
            if not content:
                continue

            # Python: class and function definitions
            for match in re.finditer(
                r"(?:^|\n)\+\s*(?:class|def)\s+(\w+)", content
            ):
                exports.append(f"{file_entry.path}:{match.group(1)}")

            # JavaScript/TypeScript: export statements
            for match in re.finditer(
                r"(?:^|\n)\+\s*export\s+(?:default\s+)?(?:class|function|const|let|var)\s+(\w+)",
                content,
            ):
                exports.append(f"{file_entry.path}:{match.group(1)}")

        return exports[:30]  # Cap at 30 to keep context compact

    def _identify_open_questions(
        self,
        chunk: Chunk,
        findings: list[Finding],
    ) -> list[str]:
        """Identify cross-file concerns that later chunks should investigate.

        For example, if a chunk imports a module that hasn't been seen yet,
        that's an open question for a future chunk.
        """
        questions: list[str] = []

        # Check for imports that reference paths not in this chunk
        chunk_paths = {f.path for f in chunk.files}

        for file_entry in chunk.files:
            content = file_entry.diff_content
            if not content:
                continue

            # Python imports
            for match in re.finditer(
                r"(?:^|\n)\+\s*(?:from|import)\s+(\S+)", content
            ):
                imported = match.group(1)
                # Check if it looks like a local import not in this chunk
                if (not imported.startswith(("os", "sys", "re", "json",
                                            "typing", "datetime", "pathlib"))
                        and "." in imported
                        and imported not in chunk_paths):
                    questions.append(
                        f"Verify import '{imported}' in {file_entry.path} "
                        f"— not found in this chunk"
                    )

        # If there are critical findings, flag for cross-chunk verification
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        if critical:
            questions.append(
                f"CRITICAL: {len(critical)} critical finding(s) in chunk "
                f"{chunk.chunk_id} — verify no related issues in other chunks"
            )

        return questions[:10]  # Cap to keep context manageable
