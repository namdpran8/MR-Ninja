"""
pipeline/mr_ninja.py

Core chunking utility for the Pipeline Large Context Orchestrator.
Can be called standalone (CLI) or imported as a module.

Usage (CLI):
    python mr_ninja.py --mr-url https://gitlab.com/group/project/-/merge_requests/42 \
                         --token $GITLAB_TOKEN \
                         --max-chunk-tokens 70000

Usage (module):
    from mr_chunker import MRChunker
    chunker = MRChunker(gitlab_url, token)
    plan = chunker.build_chunk_plan(project_id, mr_iid)
"""

import os
import re
import json
import argparse
from dataclasses import dataclass, field, asdict
from typing import Optional
import urllib.request
import urllib.parse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOKEN_TRIGGER      = 150_000   # start chunking above this
TOKEN_CHUNK_TARGET = 70_000    # aim for this per chunk
TOKEN_CHUNK_MAX    = 100_000   # hard ceiling per chunk
CHARS_PER_TOKEN    = 4         # heuristic: 1 token ≈ 4 chars

# File priority groups (checked in order, first match wins)
PRIORITY_PATTERNS = [
    # P6 — Generated / lock files (check FIRST to exclude from security P1 matches)
    (6, [
        r"package-lock\.json$", r"yarn\.lock$", r"Gemfile\.lock$",
        r"poetry\.lock$", r"go\.sum$", r"\.generated\.", r"(^|/)dist/",
        r"\.min\.js$", r"\.map$",
    ]),
    # P1 — Security-critical (checked after P6 to avoid false positives)
    (1, [
        r"(^|/)\.env$", r"(^|/)\.env\.",            # .env files only
        r"(^|/)secrets?\.",                          # secret.yaml, secrets.json etc.
        r"(^|/)tokens?\.",                           # token.py, tokens.json etc.
        r"(^|/)auth\.",r"(^|/)auth/", r"(^|/)authentication", r"(^|/)authorization",
        r"(^|/)credentials?\.",
        r"(^|/)password", r"(^|/)passwd",
        r"(^|/)Dockerfile",
        r"\.tf$",                                    # Terraform
        r"(^|/)\.github/workflows/",                 # CI config
        r"requirements.*\.txt$",
        r"(^|/)package\.json$",                      # not lock files (caught by P6)
        r"(^|/)Gemfile$",
        r"pyproject\.toml$", r"setup\.cfg$",
        r"(^|/)permissions?\.", r"(^|/)policies?\.",
        r"\.pem$", r"\.key$", r"\.crt$",
    ]),
    # P2 — Entry points / routes
    (2, [
        r"(^|/)main\.", r"(^|/)app\.", r"(^|/)index\.", r"(^|/)server\.",
        r"(^|/)routes?/", r"(^|/)api/",
    ]),
    # P5 — Tests (process late)
    (5, [
        r"(^|/)tests?/", r"(^|/)specs?/", r"_test\.", r"_spec\.",
        r"\.test\.", r"\.spec\.", r"(^|/)fixtures?/",
    ]),
]


DEFAULT_PRIORITY = 3   # directly changed files not matched above


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FileEntry:
    path: str
    additions: int
    deletions: int
    estimated_tokens: int
    priority: int
    diff_snippet: str = ""   # first 500 chars of diff for quick preview


@dataclass
class Chunk:
    chunk_id: int
    files: list[FileEntry]
    estimated_tokens: int
    recommended_agent: str  # "security" | "code_review" | "mixed"
    priority_min: int        # lowest (highest-priority) P-number in this chunk

    def file_paths(self) -> list[str]:
        return [f.path for f in self.files]

    def summary_line(self) -> str:
        agent_label = {
            "security":    "🔐 Security Analyst",
            "code_review": "🔎 Code Review",
            "mixed":       "🔐+🔎 Security + Code Review",
        }.get(self.recommended_agent, self.recommended_agent)
        return (
            f"Chunk {self.chunk_id} (~{self.estimated_tokens:,} tokens | "
            f"{len(self.files)} files) → {agent_label}"
        )


@dataclass
class ChunkPlan:
    mr_id: str
    mr_title: str
    total_files: int
    total_estimated_tokens: int
    chunked: bool
    chunks: list[Chunk]
    skipped_files: list[str] = field(default_factory=list)

    def print_plan(self):
        print(f"\n{'='*60}")
        print(f"PIPELINE CHUNK PLAN")
        print(f"{'='*60}")
        print(f"MR:             {self.mr_title} (#{self.mr_id})")
        print(f"Total files:    {self.total_files}")
        print(f"Est. tokens:    {self.total_estimated_tokens:,}")
        print(f"Mode:           {'CHUNKED' if self.chunked else 'SINGLE-PASS'}")
        if self.skipped_files:
            print(f"Skipped:        {len(self.skipped_files)} generated/lock files")
        print()
        for chunk in self.chunks:
            print(f"  {chunk.summary_line()}")
            for f in chunk.files:
                print(f"    [{f.priority}] {f.path}  (+{f.additions}/-{f.deletions})")
        print(f"{'='*60}\n")

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ---------------------------------------------------------------------------
# GitLab API client (minimal, no dependencies)
# ---------------------------------------------------------------------------

class GitLabClient:
    def __init__(self, gitlab_url: str, token: str):
        self.base = gitlab_url.rstrip("/") + "/api/v4"
        self.token = token

    def _get(self, path: str, params: dict = None) -> dict | list:
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": self.token})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def get_mr(self, project_id: str, mr_iid: int) -> dict:
        pid = urllib.parse.quote(project_id, safe="")
        return self._get(f"/projects/{pid}/merge_requests/{mr_iid}")

    def get_mr_diffs(self, project_id: str, mr_iid: int, page: int = 1) -> list[dict]:
        """Returns list of {old_path, new_path, diff, additions, deletions}"""
        pid = urllib.parse.quote(project_id, safe="")
        return self._get(
            f"/projects/{pid}/merge_requests/{mr_iid}/diffs",
            {"page": page, "per_page": 100}
        )

    def post_mr_note(self, project_id: str, mr_iid: int, body: str) -> dict:
        import urllib.request as ur
        pid = urllib.parse.quote(project_id, safe="")
        url = f"{self.base}/projects/{pid}/merge_requests/{mr_iid}/notes"
        data = json.dumps({"body": body}).encode()
        req = ur.Request(url, data=data, headers={
            "PRIVATE-TOKEN": self.token,
            "Content-Type": "application/json",
        }, method="POST")
        with ur.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


# ---------------------------------------------------------------------------
# Core chunker
# ---------------------------------------------------------------------------

class MRChunker:
    def __init__(
        self,
        gitlab_url: str = "https://gitlab.com",
        token: str = "",
        max_chunk_tokens: int = TOKEN_CHUNK_TARGET,
        trigger_tokens: int = TOKEN_TRIGGER,
        skip_generated: bool = True,
    ):
        self.client = GitLabClient(gitlab_url, token)
        self.max_chunk_tokens = max_chunk_tokens
        self.trigger_tokens = trigger_tokens
        self.skip_generated = skip_generated

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_chunk_plan(self, project_id: str, mr_iid: int) -> ChunkPlan:
        """Fetch MR diff and return a full ChunkPlan."""
        mr = self.client.get_mr(project_id, mr_iid)
        diffs = self._fetch_all_diffs(project_id, mr_iid)

        files, skipped = self._classify_files(diffs)
        total_tokens = sum(f.estimated_tokens for f in files)

        chunked = total_tokens > self.trigger_tokens
        if chunked:
            chunks = self._pack_chunks(files)
        else:
            chunks = [self._make_single_chunk(files)]

        return ChunkPlan(
            mr_id=str(mr_iid),
            mr_title=mr.get("title", "Unknown MR"),
            total_files=len(diffs),
            total_estimated_tokens=total_tokens,
            chunked=chunked,
            chunks=chunks,
            skipped_files=skipped,
        )

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimate from raw text."""
        return max(1, len(text) // CHARS_PER_TOKEN)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_all_diffs(self, project_id: str, mr_iid: int) -> list[dict]:
        """Paginate through all MR diffs."""
        all_diffs, page = [], 1
        while True:
            batch = self.client.get_mr_diffs(project_id, mr_iid, page)
            if not batch:
                break
            all_diffs.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return all_diffs

    def _get_priority(self, path: str) -> int:
        for priority, patterns in PRIORITY_PATTERNS:
            for pat in patterns:
                if re.search(pat, path, re.IGNORECASE):
                    return priority
        return DEFAULT_PRIORITY

    def _is_generated(self, path: str) -> bool:
        # P6 is listed first in PRIORITY_PATTERNS so it gets matched first
        return self._get_priority(path) == 6

    def _classify_files(self, diffs: list[dict]) -> tuple[list[FileEntry], list[str]]:
        """Convert raw diff entries to FileEntry objects, separating skipped files."""
        files, skipped = [], []
        for d in diffs:
            path = d.get("new_path") or d.get("old_path", "unknown")
            if self.skip_generated and self._is_generated(path):
                skipped.append(path)
                continue

            diff_text = d.get("diff", "")
            additions = d.get("a_mode") and diff_text.count("\n+") or diff_text.count("\n+")
            deletions = diff_text.count("\n-")
            # Better: count actual diff lines
            add_lines = sum(1 for line in diff_text.splitlines() if line.startswith("+") and not line.startswith("+++"))
            del_lines = sum(1 for line in diff_text.splitlines() if line.startswith("-") and not line.startswith("---"))

            est_tokens = self.estimate_tokens(diff_text)

            files.append(FileEntry(
                path=path,
                additions=add_lines,
                deletions=del_lines,
                estimated_tokens=max(est_tokens, 100),  # floor
                priority=self._get_priority(path),
                diff_snippet=diff_text[:500],
            ))

        # Sort by priority (ascending = higher priority first), then path
        files.sort(key=lambda f: (f.priority, f.path))
        return files, skipped

    def _recommended_agent(self, files: list[FileEntry]) -> str:
        priorities = {f.priority for f in files}
        has_security = 1 in priorities
        has_logic    = any(p in priorities for p in [2, 3, 4])
        if has_security and has_logic:
            return "mixed"
        if has_security:
            return "security"
        return "code_review"

    def _pack_chunks(self, files: list[FileEntry]) -> list[Chunk]:
        """
        Bin-pack files into chunks using a greedy first-fit approach,
        respecting priority order and token limits.
        """
        chunks: list[Chunk] = []
        current_files: list[FileEntry] = []
        current_tokens = 0
        chunk_id = 1

        for f in files:
            if f.estimated_tokens > self.max_chunk_tokens:
                # Oversized single file — gets its own chunk with a warning
                if current_files:
                    chunks.append(self._make_chunk(chunk_id, current_files))
                    chunk_id += 1
                    current_files, current_tokens = [], 0
                chunks.append(self._make_chunk(chunk_id, [f]))
                chunk_id += 1
                continue

            if current_tokens + f.estimated_tokens > self.max_chunk_tokens and current_files:
                chunks.append(self._make_chunk(chunk_id, current_files))
                chunk_id += 1
                current_files, current_tokens = [], 0

            current_files.append(f)
            current_tokens += f.estimated_tokens

        if current_files:
            chunks.append(self._make_chunk(chunk_id, current_files))

        return chunks

    def _make_chunk(self, chunk_id: int, files: list[FileEntry]) -> Chunk:
        return Chunk(
            chunk_id=chunk_id,
            files=files,
            estimated_tokens=sum(f.estimated_tokens for f in files),
            recommended_agent=self._recommended_agent(files),
            priority_min=min(f.priority for f in files),
        )

    def _make_single_chunk(self, files: list[FileEntry]) -> Chunk:
        return self._make_chunk(1, files)


# ---------------------------------------------------------------------------
# Cross-chunk context serializer (used between agent calls)
# ---------------------------------------------------------------------------

@dataclass
class ChunkSummary:
    chunk_id: int
    total_chunks: int
    files_processed: list[str]
    findings: list[dict]            # [{file, severity, summary}]
    imports_exported: list[str]     # symbols/modules exported
    open_questions: list[str]       # unresolved cross-file concerns

    def to_context_header(self) -> str:
        """Compact text to prepend to the next chunk's agent call."""
        lines = [
            "=== CROSS-CHUNK CONTEXT (read-only) ===",
            f"Chunks completed: {self.chunk_id}/{self.total_chunks}",
        ]
        if self.imports_exported:
            lines.append(f"Key exports seen: {', '.join(self.imports_exported[:20])}")
        if self.open_questions:
            lines.append("Open questions from prior chunks:")
            for q in self.open_questions:
                lines.append(f"  • {q}")
        if self.findings:
            crit = [f for f in self.findings if f.get("severity") in ("CRITICAL", "HIGH")]
            if crit:
                lines.append(f"Critical/High findings so far: {len(crit)}")
                for f in crit[:5]:
                    lines.append(f"  ⚠ [{f['severity']}] {f['file']}: {f['summary'][:100]}")
        lines.append("=== END CONTEXT ===\n")
        return "\n".join(lines)

    @classmethod
    def empty(cls, chunk_id: int, total_chunks: int) -> "ChunkSummary":
        return cls(chunk_id, total_chunks, [], [], [], [])


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

class FindingsAggregator:
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def __init__(self):
        self._seen: dict[tuple, dict] = {}  # (file, finding_type) → best finding
        self.open_questions: list[str] = []

    def ingest_chunk_summary(self, summary: ChunkSummary):
        for finding in summary.findings:
            key = (finding.get("file", ""), finding.get("type", finding.get("summary", "")[:60]))
            existing = self._seen.get(key)
            if existing is None:
                self._seen[key] = finding
            else:
                # Keep highest severity
                if self.SEVERITY_ORDER.get(finding.get("severity", "INFO"), 99) < \
                   self.SEVERITY_ORDER.get(existing.get("severity", "INFO"), 99):
                    self._seen[key] = finding
        self.open_questions.extend(summary.open_questions)

    def get_sorted_findings(self) -> list[dict]:
        findings = list(self._seen.values())
        findings.sort(key=lambda f: self.SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))
        return findings

    def render_markdown_report(self, plan: ChunkPlan, chunk_summaries: list[ChunkSummary]) -> str:
        findings = self.get_sorted_findings()
        sev_counts = {}
        for f in findings:
            s = f.get("severity", "INFO")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        overall_risk = "🟢 LOW"
        if sev_counts.get("CRITICAL", 0) > 0:
            overall_risk = "🔴 CRITICAL"
        elif sev_counts.get("HIGH", 0) > 0:
            overall_risk = "🟠 HIGH"
        elif sev_counts.get("MEDIUM", 0) > 0:
            overall_risk = "🟡 MEDIUM"

        # Findings table
        if findings:
            table_rows = "\n".join(
                f"| {i+1} | {f.get('severity','?')} | `{f.get('file','?')}` | {f.get('summary','')[:100]} | {f.get('line','-')} |"
                for i, f in enumerate(findings)
            )
            findings_section = f"""| # | Severity | File | Finding | Line |
|---|----------|------|---------|------|
{table_rows}"""
        else:
            findings_section = "_No findings detected._"

        # Open questions
        unresolved = [q for q in self.open_questions if not q.startswith("RESOLVED:")]
        oq_section = "\n".join(f"- {q}" for q in unresolved) if unresolved else "_None — all cross-chunk concerns resolved._"

        # Per-chunk details
        chunk_details = ""
        for cs in chunk_summaries:
            chunk_details += f"\n**Chunk {cs.chunk_id}** — {len(cs.files_processed)} files\n"
            for fp in cs.files_processed:
                chunk_details += f"  - `{fp}`\n"

        return f"""# 🔍 Pipeline Analysis Report
**MR:** {plan.mr_title} (#{plan.mr_id})
**Analyzed:** {plan.total_files} files | ~{plan.total_estimated_tokens:,} estimated tokens | {len(plan.chunks)} chunk(s)

---

## Executive Summary
Overall risk level: **{overall_risk}**
{sev_counts.get('CRITICAL',0)} critical, {sev_counts.get('HIGH',0)} high, {sev_counts.get('MEDIUM',0)} medium, {sev_counts.get('LOW',0)} low findings across {plan.total_files} changed files.

---

## Findings

{findings_section}

---

## Unresolved Cross-Chunk Questions
{oq_section}

---

## Recommendations
{"⚠️ **Immediate action required** — resolve CRITICAL findings before merging." if sev_counts.get('CRITICAL',0) else "Review HIGH findings before merging." if sev_counts.get('HIGH',0) else "No blocking issues found. Standard review applies."}

---

## Processing Details
<details>
<summary>Chunk-by-chunk file breakdown</summary>

{chunk_details}
</details>

---
*Generated by **Pipeline** — Large Context Orchestrator for GitLab Duo*
*[Studio Zelda | GitLab AI Hackathon 2026]*
"""


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_mr_url(url: str) -> tuple[str, int]:
    """
    Parse GitLab MR URL into (project_id, mr_iid).
    e.g. https://gitlab.com/mygroup/myproject/-/merge_requests/42
         → ("mygroup/myproject", 42)
    """
    m = re.match(r"https?://[^/]+/(.+)/-/merge_requests/(\d+)", url)
    if not m:
        raise ValueError(f"Cannot parse MR URL: {url}")
    return m.group(1), int(m.group(2))


def main():
    parser = argparse.ArgumentParser(
        description="Pipeline MR Chunker — build a chunk plan for a GitLab MR"
    )
    parser.add_argument("--mr-url", required=True, help="Full GitLab MR URL")
    parser.add_argument("--token", default=os.getenv("GITLAB_TOKEN", ""), help="GitLab personal access token")
    parser.add_argument("--gitlab-url", default="https://gitlab.com", help="GitLab instance base URL")
    parser.add_argument("--max-chunk-tokens", type=int, default=TOKEN_CHUNK_TARGET)
    parser.add_argument("--json", action="store_true", help="Output plan as JSON")
    parser.add_argument("--post-note", action="store_true", help="Post plan as MR note")
    args = parser.parse_args()

    if not args.token:
        parser.error("--token or GITLAB_TOKEN env var required")

    project_id, mr_iid = parse_mr_url(args.mr_url)

    chunker = MRChunker(
        gitlab_url=args.gitlab_url,
        token=args.token,
        max_chunk_tokens=args.max_chunk_tokens,
    )

    print(f"Fetching MR diff for {project_id}!{mr_iid}...")
    plan = chunker.build_chunk_plan(project_id, mr_iid)

    if args.json:
        print(plan.to_json())
    else:
        plan.print_plan()

    if args.post_note:
        note_body = f"🔄 **Pipeline** chunk plan ready.\n\n"
        note_body += f"**Mode:** {'Chunked' if plan.chunked else 'Single-pass'}\n"
        note_body += f"**Chunks:** {len(plan.chunks)}\n"
        note_body += f"**Est. tokens:** ~{plan.total_estimated_tokens:,}\n\n"
        for chunk in plan.chunks:
            note_body += f"- {chunk.summary_line()}\n"
        chunker.client.post_mr_note(project_id, mr_iid, note_body)
        print("✅ Chunk plan posted as MR note.")


if __name__ == "__main__":
    main()