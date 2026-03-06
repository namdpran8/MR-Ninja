"""
core/models.py

Pydantic data models used across the Mr Ninja pipeline.

These models define the contract between all system components:
orchestrator, chunk planner, processors, summarizer, and aggregator.
"""

# MR-Ninja
# Copyright (c) 2026 Pranshu Namdeo
# Licensed under Apache License 2.0

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, computed_field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, enum.Enum):
    """Finding severity levels, ordered from most to least critical."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Lower rank = higher severity."""
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank


class AgentType(str, enum.Enum):
    """Types of specialist agents that can analyze a chunk."""
    SECURITY = "security"
    CODE_REVIEW = "code_review"
    DEPENDENCY = "dependency"
    MIXED = "mixed"


class FilePriority(int, enum.Enum):
    """File processing priority. Lower number = processed first."""
    SECURITY_CRITICAL = 1
    ENTRY_POINT = 2
    CHANGED_FILE = 3
    SHARED_MODULE = 4
    TEST_FILE = 5
    GENERATED = 6


# ---------------------------------------------------------------------------
# File-level models
# ---------------------------------------------------------------------------

class FileEntry(BaseModel):
    """Represents a single file from an MR diff with metadata."""
    path: str = Field(..., description="File path relative to repo root")
    additions: int = Field(0, ge=0, description="Lines added")
    deletions: int = Field(0, ge=0, description="Lines deleted")
    estimated_tokens: int = Field(0, ge=0, description="Estimated token count")
    priority: FilePriority = Field(
        FilePriority.CHANGED_FILE,
        description="Processing priority (1=highest)",
    )
    diff_content: str = Field("", description="Diff text content")
    language: str = Field("", description="Detected programming language")

    @computed_field
    @property
    def churn(self) -> int:
        """Total lines changed (additions + deletions)."""
        return self.additions + self.deletions


# ---------------------------------------------------------------------------
# Chunk-level models
# ---------------------------------------------------------------------------

class Chunk(BaseModel):
    """A group of files that fits within a single agent context window."""
    chunk_id: int = Field(..., ge=1, description="Sequential chunk identifier")
    files: list[FileEntry] = Field(default_factory=list)
    estimated_tokens: int = Field(0, ge=0, description="Total tokens in chunk")
    recommended_agent: AgentType = Field(
        AgentType.CODE_REVIEW,
        description="Which specialist agent should process this chunk",
    )

    @computed_field
    @property
    def file_count(self) -> int:
        return len(self.files)

    @computed_field
    @property
    def file_paths(self) -> list[str]:
        return [f.path for f in self.files]

    def summary_line(self) -> str:
        """Human-readable one-line summary."""
        agent_labels = {
            AgentType.SECURITY: "Security Analyst",
            AgentType.CODE_REVIEW: "Code Review",
            AgentType.DEPENDENCY: "Dependency Analyzer",
            AgentType.MIXED: "Security + Code Review",
        }
        label = agent_labels.get(self.recommended_agent, str(self.recommended_agent))
        return (
            f"Chunk {self.chunk_id} "
            f"(~{self.estimated_tokens:,} tokens | {self.file_count} files) "
            f"-> {label}"
        )


# ---------------------------------------------------------------------------
# Analysis plan
# ---------------------------------------------------------------------------

class ChunkPlan(BaseModel):
    """Complete analysis plan produced by the chunk planner."""
    mr_id: str = Field(..., description="Merge request IID")
    mr_title: str = Field("", description="MR title")
    mr_url: str = Field("", description="Full MR URL")
    project_id: str = Field("", description="GitLab project identifier")
    total_files: int = Field(0, ge=0)
    total_estimated_tokens: int = Field(0, ge=0)
    chunking_required: bool = Field(False)
    chunks: list[Chunk] = Field(default_factory=list)
    skipped_files: list[str] = Field(
        default_factory=list,
        description="Files skipped (generated/lock files)",
    )

    @computed_field
    @property
    def chunk_count(self) -> int:
        return len(self.chunks)


# ---------------------------------------------------------------------------
# Findings & chunk summary
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A single security, quality, or dependency finding."""
    file: str = Field(..., description="File path where issue was found")
    line: Optional[int] = Field(None, description="Line number (if applicable)")
    severity: Severity = Field(Severity.INFO)
    category: str = Field("general", description="Finding category (security/quality/dependency)")
    title: str = Field("", description="Short finding title")
    description: str = Field("", description="Detailed description")
    recommendation: str = Field("", description="Suggested fix")
    rule_id: str = Field("", description="Rule or check identifier")
    chunk_id: Optional[int] = Field(None, description="Which chunk found this")


class ChunkSummary(BaseModel):
    """Summary produced after processing a single chunk.

    This is the cross-chunk context carrier — it gets compressed and
    prepended to the next chunk's agent call so downstream chunks
    can see what upstream chunks discovered.
    """
    chunk_id: int = Field(..., ge=1)
    total_chunks: int = Field(..., ge=1)
    files_processed: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    imports_exported: list[str] = Field(
        default_factory=list,
        description="Symbols/modules exported that downstream chunks may need",
    )
    open_questions: list[str] = Field(
        default_factory=list,
        description="Cross-file concerns requiring later chunks to resolve",
    )
    processing_time_seconds: float = Field(0.0, ge=0)

    def to_context_header(self) -> str:
        """Compact text to prepend to the next chunk's agent call."""
        lines = [
            "=== CROSS-CHUNK CONTEXT (read-only) ===",
            f"Chunks completed: {self.chunk_id}/{self.total_chunks}",
            f"Files analyzed so far: {len(self.files_processed)}",
        ]
        if self.imports_exported:
            lines.append(f"Key exports seen: {', '.join(self.imports_exported[:20])}")
        if self.open_questions:
            lines.append("Open questions from prior chunks:")
            for q in self.open_questions:
                lines.append(f"  - {q}")
        critical_high = [
            f for f in self.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if critical_high:
            lines.append(f"Critical/High findings so far: {len(critical_high)}")
            for f in critical_high[:5]:
                lines.append(
                    f"  [{f.severity.value}] {f.file}: {f.title or f.description[:80]}"
                )
        lines.append("=== END CONTEXT ===\n")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Final aggregated report
# ---------------------------------------------------------------------------

class AnalysisReport(BaseModel):
    """Final aggregated report combining all chunk results."""
    mr_id: str
    mr_title: str = ""
    mr_url: str = ""
    project_id: str = ""
    total_files_scanned: int = 0
    total_estimated_tokens: int = 0
    chunks_processed: int = 0
    findings: list[Finding] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    chunk_summaries: list[ChunkSummary] = Field(default_factory=list)
    overall_risk: Severity = Field(Severity.INFO)
    processing_time_seconds: float = Field(0.0)
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @computed_field
    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @computed_field
    @property
    def critical_count(self) -> int:
        return self.severity_counts.get("CRITICAL", 0)

    @computed_field
    @property
    def high_count(self) -> int:
        return self.severity_counts.get("HIGH", 0)

    @computed_field
    @property
    def medium_count(self) -> int:
        return self.severity_counts.get("MEDIUM", 0)

    @computed_field
    @property
    def low_count(self) -> int:
        return self.severity_counts.get("LOW", 0)


# ---------------------------------------------------------------------------
# API request/response models (for FastAPI)
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Incoming request to analyze an MR."""
    mr_url: str = Field("", description="Full GitLab MR URL")
    project_id: str = Field("", description="GitLab project ID or path")
    mr_iid: int = Field(0, ge=0, description="MR internal ID")
    gitlab_url: str = Field("https://gitlab.com", description="GitLab instance URL")
    gitlab_token: str = Field("", description="GitLab private token")
    max_chunk_tokens: int = Field(70_000, ge=10_000)
    post_comment: bool = Field(True, description="Post results as MR comment")


class AnalyzeResponse(BaseModel):
    """Response from the analysis endpoint."""
    status: str = Field("ok")
    mr_id: str = ""
    chunks_processed: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    overall_risk: str = ""
    report_markdown: str = ""
    processing_time_seconds: float = 0.0
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "1.0.0"
    service: str = "mr-ninja"
