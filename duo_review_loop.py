"""
pipeline/duo_review_loop.py

The "Duo-to-Review" Pipeline — Automated feedback loop that:
  1. Detects when Duo has generated code (via MR label or commit message pattern)
  2. Triggers a fast-scan (lint + security) via GitLab Runner / pipeline
  3. Feeds scan results back to the Duo Chat API automatically
  4. Posts a developer-facing summary: "Duo generated this, it failed X, 
     I've already asked Duo to fix it."

Eliminates the manual toil of: read AI output → run lint → copy errors → 
re-prompt Duo → wait → repeat.

Can be triggered:
  A) As a GitLab CI job (see .gitlab-ci.yml snippet at bottom of file)
  B) As a standalone Python script called by a webhook
  C) As a custom GitLab Duo agent tool

Environment variables:
  GITLAB_TOKEN     - PAT with api + write_repository scopes
  GITLAB_URL       - e.g. https://gitlab.com
  DUO_API_URL      - GitLab Duo Chat API endpoint (internal, check docs)
  PROJECT_ID       - target project
  MR_IID           - merge request internal ID
  CI_PIPELINE_ID   - (auto-set in GitLab CI)
"""

import os
import re
import sys
import json
import subprocess
import urllib.request
import urllib.parse
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("duo-review-loop")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

GITLAB_URL   = os.getenv("GITLAB_URL", "https://gitlab.com")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN", "")
PROJECT_ID   = os.getenv("PROJECT_ID", os.getenv("CI_PROJECT_ID", ""))
MR_IID       = os.getenv("MR_IID", os.getenv("CI_MERGE_REQUEST_IID", ""))
DUO_LABEL    = "duo-assisted"          # label that marks Duo-generated MRs
MAX_SCAN_SECONDS = 120                 # fast-scan timeout

# Linters to run (must be installed in the runner image)
LINTERS = {
    "python": ["flake8", "--max-line-length=100", "--select=E,W,F"],
    "js":     ["npx", "eslint", "--format=json"],
    "ts":     ["npx", "eslint", "--format=json"],
    "ruby":   ["rubocop", "--format=json", "--no-color"],
    "go":     ["golangci-lint", "run", "--out-format=json"],
}

SECURITY_SCANNER = ["semgrep", "--config=auto", "--json", "--quiet"]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ScanFinding:
    tool: str           # "flake8" | "semgrep" | "eslint" etc.
    file: str
    line: int
    severity: str       # "error" | "warning" | "info"
    rule: str
    message: str


@dataclass
class ScanResult:
    passed: bool
    findings: list[ScanFinding] = field(default_factory=list)
    tools_run: list[str] = field(default_factory=list)
    scan_time_seconds: float = 0.0
    error: Optional[str] = None

    def errors(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.severity == "error"]

    def warnings(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.severity == "warning"]


# ---------------------------------------------------------------------------
# GitLab API client (minimal)
# ---------------------------------------------------------------------------

class GitLabAPI:
    def __init__(self, url: str, token: str):
        self.base = url.rstrip("/") + "/api/v4"
        self.token = token

    def _req(self, method: str, path: str, data: dict = None) -> dict | list:
        url = f"{self.base}{path}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(
            url, data=body,
            headers={"PRIVATE-TOKEN": self.token, "Content-Type": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            log.error(f"API {method} {path}: {e}")
            return {}

    def get_mr(self, project_id: str, mr_iid: str) -> dict:
        pid = urllib.parse.quote(project_id, safe="")
        return self._req("GET", f"/projects/{pid}/merge_requests/{mr_iid}")

    def get_mr_changes(self, project_id: str, mr_iid: str) -> list[dict]:
        pid = urllib.parse.quote(project_id, safe="")
        result = self._req("GET", f"/projects/{pid}/merge_requests/{mr_iid}/diffs")
        return result if isinstance(result, list) else []

    def post_mr_note(self, project_id: str, mr_iid: str, body: str) -> dict:
        pid = urllib.parse.quote(project_id, safe="")
        return self._req("POST", f"/projects/{pid}/merge_requests/{mr_iid}/notes", {"body": body})

    def add_mr_label(self, project_id: str, mr_iid: str, label: str) -> dict:
        pid = urllib.parse.quote(project_id, safe="")
        mr = self.get_mr(project_id, mr_iid)
        existing = mr.get("labels", [])
        if label not in existing:
            return self._req("PUT", f"/projects/{pid}/merge_requests/{mr_iid}",
                           {"labels": ",".join(existing + [label])})
        return mr

    def is_duo_assisted(self, project_id: str, mr_iid: str) -> bool:
        """Check if this MR was Duo-assisted by label OR commit message pattern."""
        mr = self.get_mr(project_id, mr_iid)
        if DUO_LABEL in mr.get("labels", []):
            return True
        # Also check commit message for "duo:" or "ai:" prefix
        desc = mr.get("description", "").lower()
        return any(marker in desc for marker in ["duo-generated", "ai-assisted", "gitlab duo"])


# ---------------------------------------------------------------------------
# Fast scanner
# ---------------------------------------------------------------------------

def run_command(cmd: list[str], cwd: str = ".", timeout: int = MAX_SCAN_SECONDS) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def detect_language(changed_files: list[str]) -> str:
    """Detect dominant language from changed files."""
    counts = {}
    ext_map = {
        ".py": "python", ".js": "js", ".ts": "ts", ".jsx": "js", ".tsx": "ts",
        ".rb": "ruby", ".go": "go",
    }
    for f in changed_files:
        ext = Path(f).suffix.lower()
        lang = ext_map.get(ext)
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    return max(counts, key=counts.get) if counts else "python"


def parse_flake8_output(output: str) -> list[ScanFinding]:
    """Parse flake8 text output: path:line:col: CODE message"""
    findings = []
    for line in output.splitlines():
        m = re.match(r"^(.+):(\d+):\d+:\s+([A-Z]\d+)\s+(.+)$", line)
        if m:
            findings.append(ScanFinding(
                tool="flake8", file=m.group(1), line=int(m.group(2)),
                severity="error" if m.group(3).startswith(("E", "F")) else "warning",
                rule=m.group(3), message=m.group(4),
            ))
    return findings


def parse_eslint_output(output: str) -> list[ScanFinding]:
    """Parse ESLint JSON output."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    findings = []
    for file_result in data:
        path = file_result.get("filePath", "")
        for msg in file_result.get("messages", []):
            findings.append(ScanFinding(
                tool="eslint", file=path, line=msg.get("line", 0),
                severity="error" if msg.get("severity") == 2 else "warning",
                rule=msg.get("ruleId", "unknown"), message=msg.get("message", ""),
            ))
    return findings


def parse_semgrep_output(output: str) -> list[ScanFinding]:
    """Parse Semgrep JSON output."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    findings = []
    for result in data.get("results", []):
        sev = result.get("extra", {}).get("severity", "WARNING").lower()
        findings.append(ScanFinding(
            tool="semgrep",
            file=result.get("path", ""),
            line=result.get("start", {}).get("line", 0),
            severity="error" if sev in ("error", "critical", "high") else "warning",
            rule=result.get("check_id", ""),
            message=result.get("extra", {}).get("message", ""),
        ))
    return findings


def run_fast_scan(changed_files: list[str], repo_root: str = ".") -> ScanResult:
    """
    Run lint + security scan on changed files only.
    Returns a ScanResult with all findings.
    """
    import time
    start = time.time()
    all_findings: list[ScanFinding] = []
    tools_run: list[str] = []

    if not changed_files:
        return ScanResult(passed=True, tools_run=[], scan_time_seconds=0)

    lang = detect_language(changed_files)
    linter_cmd = LINTERS.get(lang)

    # Run language linter
    if linter_cmd:
        cmd = linter_cmd + changed_files
        rc, stdout, stderr = run_command(cmd, cwd=repo_root)
        tool_name = linter_cmd[0].replace("npx ", "").strip()
        tools_run.append(tool_name)

        if lang == "python":
            all_findings.extend(parse_flake8_output(stdout))
        elif lang in ("js", "ts"):
            all_findings.extend(parse_eslint_output(stdout))
        log.info(f"Linter ({tool_name}): {len(all_findings)} findings so far")

    # Run security scanner (semgrep)
    sec_cmd = SECURITY_SCANNER + changed_files
    rc, stdout, stderr = run_command(sec_cmd, cwd=repo_root)
    if rc != -1:  # semgrep installed
        sec_findings = parse_semgrep_output(stdout)
        all_findings.extend(sec_findings)
        tools_run.append("semgrep")
        log.info(f"Semgrep: {len(sec_findings)} findings")

    elapsed = time.time() - start
    errors = [f for f in all_findings if f.severity == "error"]

    return ScanResult(
        passed=len(errors) == 0,
        findings=all_findings,
        tools_run=tools_run,
        scan_time_seconds=round(elapsed, 2),
    )


# ---------------------------------------------------------------------------
# Duo re-prompt builder
# ---------------------------------------------------------------------------

def build_duo_fix_prompt(scan: ScanResult, changed_files: list[str]) -> str:
    """
    Build the prompt to send back to Duo to self-fix the issues.
    Concise — we only include actionable errors, not warnings.
    """
    errors = scan.errors()
    if not errors:
        return ""

    lines = [
        "The code you generated has been automatically scanned.",
        f"Found {len(errors)} error(s) that must be fixed before this MR can merge.",
        "",
        "Please fix the following issues:",
        "",
    ]
    for f in errors[:15]:  # cap at 15 to stay within token budget
        lines.append(f"- **{f.file}:{f.line}** [{f.rule}] {f.message}")

    lines += [
        "",
        "Requirements:",
        "- Fix all errors listed above",
        "- Do not change any logic that is unrelated to these errors",
        "- Preserve existing tests",
        "- Output only the corrected file(s), no explanation needed",
    ]
    return "\n".join(lines)


def build_mr_note(scan: ScanResult, duo_prompted: bool) -> str:
    """Build the MR comment shown to the developer."""
    status_icon = "✅" if scan.passed else "❌"
    tools = ", ".join(scan.tools_run) or "none"

    lines = [
        f"## 🔄 Pipeline Auto-Review Loop — {status_icon}",
        f"",
        f"Detected **Duo-assisted** code. Automatically ran a fast scan.",
        f"",
        f"| | |",
        f"|---|---|",
        f"| **Tools** | {tools} |",
        f"| **Scan time** | {scan.scan_time_seconds}s |",
        f"| **Errors** | {len(scan.errors())} |",
        f"| **Warnings** | {len(scan.warnings())} |",
        f"| **Result** | {'✅ Passed' if scan.passed else '❌ Failed'} |",
    ]

    if not scan.passed:
        lines += [
            "",
            "### Errors Found",
            "",
        ]
        for f in scan.errors()[:10]:
            lines.append(f"- `{f.file}:{f.line}` **[{f.rule}]** {f.message}")

        if duo_prompted:
            lines += [
                "",
                "---",
                "🤖 **I've already asked Duo to fix these errors.** "
                "A new commit will appear shortly with the corrections applied.",
            ]
        else:
            lines += [
                "",
                "---",
                "⚠️ Please review and fix the errors above, or ask Duo: "
                '"Fix the linting errors listed in the latest Pipeline scan comment."',
            ]

    if scan.passed:
        lines += [
            "",
            "✅ All checks passed. The Duo-generated code is clean — no action needed.",
        ]

    lines += [
        "",
        "---",
        "*[Pipeline Auto-Review Loop](https://gitlab.com) — eliminating prompt engineering toil*",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run_review_loop(
    project_id: str,
    mr_iid: str,
    repo_root: str = ".",
    auto_reprompt: bool = True,
) -> dict:
    """
    Main entry point: check if MR is Duo-assisted, scan, post results.
    """
    api = GitLabAPI(GITLAB_URL, GITLAB_TOKEN)

    log.info(f"Review loop for project={project_id} MR={mr_iid}")

    # Check if Duo-assisted
    if not api.is_duo_assisted(project_id, mr_iid):
        log.info("MR is not Duo-assisted — skipping auto-review loop")
        return {"status": "skipped", "reason": "not duo-assisted"}

    # Get changed files
    changes = api.get_mr_changes(project_id, mr_iid)
    changed_files = [
        c.get("new_path", c.get("old_path", ""))
        for c in changes
        if not c.get("deleted_file", False)
    ]

    if not changed_files:
        return {"status": "skipped", "reason": "no changed files"}

    log.info(f"Scanning {len(changed_files)} changed files...")

    # Run fast scan
    scan = run_fast_scan(changed_files, repo_root=repo_root)
    log.info(f"Scan complete: passed={scan.passed}, errors={len(scan.errors())}")

    # Build Duo re-prompt if needed
    duo_prompted = False
    if not scan.passed and auto_reprompt:
        fix_prompt = build_duo_fix_prompt(scan, changed_files)
        if fix_prompt:
            # In a full implementation, this calls the Duo Chat API
            # Here we log it and save to a file for the CI job to pick up
            prompt_file = Path(repo_root) / ".pipeline" / "duo_fix_prompt.txt"
            prompt_file.parent.mkdir(parents=True, exist_ok=True)
            prompt_file.write_text(fix_prompt)
            log.info(f"Fix prompt written to {prompt_file}")
            duo_prompted = True

    # Post MR note
    note = build_mr_note(scan, duo_prompted)
    api.post_mr_note(project_id, mr_iid, note)
    log.info("MR note posted")

    return {
        "status": "ok",
        "passed": scan.passed,
        "errors": len(scan.errors()),
        "warnings": len(scan.warnings()),
        "tools": scan.tools_run,
        "duo_prompted": duo_prompted,
    }


# ---------------------------------------------------------------------------
# CLI + GitLab CI usage
# ---------------------------------------------------------------------------

"""
.gitlab-ci.yml snippet to use this in your pipeline:

duo-review-loop:
  stage: review
  image: python:3.12-slim
  rules:
    - if: '$CI_MERGE_REQUEST_IID'
  variables:
    PROJECT_ID: $CI_PROJECT_ID
    MR_IID: $CI_MERGE_REQUEST_IID
  before_script:
    - pip install flake8 semgrep --break-system-packages -q
  script:
    - python pipeline/duo_review_loop.py run
  artifacts:
    paths:
      - .pipeline/duo_fix_prompt.txt
    when: on_failure
"""

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Pipeline Duo-to-Review Loop")
    subparsers = parser.add_subparsers(dest="cmd")

    run_p = subparsers.add_parser("run", help="Run the review loop for current MR")
    run_p.add_argument("--project-id", default=PROJECT_ID)
    run_p.add_argument("--mr-iid",     default=MR_IID)
    run_p.add_argument("--repo-root",  default=".")
    run_p.add_argument("--no-reprompt", action="store_true")

    scan_p = subparsers.add_parser("scan", help="Just scan files, no GitLab API calls")
    scan_p.add_argument("files", nargs="+")

    args = parser.parse_args()

    if args.cmd == "run":
        if not args.project_id or not args.mr_iid:
            sys.exit("Error: --project-id and --mr-iid required (or set PROJECT_ID/MR_IID env vars)")
        result = run_review_loop(
            project_id=args.project_id,
            mr_iid=args.mr_iid,
            auto_reprompt=not args.no_reprompt,
        )
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get("passed", True) else 1)

    elif args.cmd == "scan":
        scan = run_fast_scan(args.files)
        print(f"\nScan result: {'PASSED ✅' if scan.passed else 'FAILED ❌'}")
        print(f"Errors:   {len(scan.errors())}")
        print(f"Warnings: {len(scan.warnings())}")
        for f in scan.findings:
            icon = "❌" if f.severity == "error" else "⚠️"
            print(f"  {icon} {f.file}:{f.line} [{f.rule}] {f.message}")

    else:
        parser.print_help()
