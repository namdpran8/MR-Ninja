"""
pipeline/impact_dashboard.py

Financial Optimization — AI Impact Dashboard

Automates the measurement of GitLab Duo's ROI by:
  1. Querying GitLab's Value Stream Analytics API for MR cycle times
  2. Splitting MRs into "Duo-Assisted" vs "Manual" cohorts (via label)
  3. Computing statistical comparison (median cycle time, throughput, etc.)
  4. Generating a Markdown + JSON report, auto-posted to a tracking issue

Answers the "Is this worth it?" question with hard data — automatically,
every month, without a human touching a spreadsheet.

Schedule via GitLab CI:
  impact-dashboard:
    stage: report
    rules:
      - if: '$CI_PIPELINE_SOURCE == "schedule"'  # monthly schedule
    script:
      - python pipeline/impact_dashboard.py report --post-issue

Environment variables:
  GITLAB_TOKEN      - PAT with api scope
  GITLAB_URL        - e.g. https://gitlab.com
  PROJECT_ID        - project to analyze
  DUO_LABEL         - label on Duo-assisted MRs (default: duo-assisted)
  REPORT_ISSUE_IID  - optional: issue number to post report as comment
"""

import os
import json
import math
import statistics
import urllib.request
import urllib.parse
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("impact-dashboard")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

GITLAB_URL       = os.getenv("GITLAB_URL", "https://gitlab.com")
GITLAB_TOKEN     = os.getenv("GITLAB_TOKEN", "")
PROJECT_ID       = os.getenv("PROJECT_ID", os.getenv("CI_PROJECT_ID", ""))
DUO_LABEL        = os.getenv("DUO_LABEL", "duo-assisted")
REPORT_ISSUE_IID = os.getenv("REPORT_ISSUE_IID", "")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MRMetrics:
    iid: int
    title: str
    author: str
    created_at: datetime
    merged_at: Optional[datetime]
    closed_at: Optional[datetime]
    labels: list[str]
    additions: int
    deletions: int
    commits: int
    review_comments: int
    duo_assisted: bool = False

    @property
    def cycle_time_hours(self) -> Optional[float]:
        """Hours from MR creation to merge."""
        if self.merged_at and self.created_at:
            delta = self.merged_at - self.created_at
            return delta.total_seconds() / 3600
        return None

    @property
    def cycle_time_days(self) -> Optional[float]:
        t = self.cycle_time_hours
        return round(t / 24, 2) if t is not None else None

    @property
    def code_churn(self) -> int:
        return self.additions + self.deletions


@dataclass
class CohortStats:
    name: str
    label: str
    mrs: list[MRMetrics]

    @property
    def merged_mrs(self) -> list[MRMetrics]:
        return [m for m in self.mrs if m.cycle_time_hours is not None]

    @property
    def cycle_times(self) -> list[float]:
        return [m.cycle_time_hours for m in self.merged_mrs]

    @property
    def median_cycle_time_hours(self) -> Optional[float]:
        ct = self.cycle_times
        return round(statistics.median(ct), 2) if ct else None

    @property
    def mean_cycle_time_hours(self) -> Optional[float]:
        ct = self.cycle_times
        return round(statistics.mean(ct), 2) if ct else None

    @property
    def p90_cycle_time_hours(self) -> Optional[float]:
        ct = sorted(self.cycle_times)
        if not ct:
            return None
        idx = int(math.ceil(0.9 * len(ct))) - 1
        return round(ct[max(0, idx)], 2)

    @property
    def throughput_per_week(self) -> float:
        """Average MRs merged per week over the reporting period."""
        if not self.merged_mrs:
            return 0.0
        dates = [m.merged_at for m in self.merged_mrs if m.merged_at]
        if len(dates) < 2:
            return len(dates)
        span_days = (max(dates) - min(dates)).days or 1
        return round(len(dates) / (span_days / 7), 2)

    @property
    def avg_comments(self) -> Optional[float]:
        if not self.mrs:
            return None
        return round(statistics.mean(m.review_comments for m in self.mrs), 1)

    @property
    def avg_churn(self) -> Optional[float]:
        if not self.mrs:
            return None
        return round(statistics.mean(m.code_churn for m in self.mrs), 0)


@dataclass
class ImpactReport:
    project_name: str
    period_start: datetime
    period_end: datetime
    duo_cohort: CohortStats
    manual_cohort: CohortStats
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def cycle_time_improvement_pct(self) -> Optional[float]:
        d = self.duo_cohort.median_cycle_time_hours
        m = self.manual_cohort.median_cycle_time_hours
        if d is None or m is None or m == 0:
            return None
        return round((m - d) / m * 100, 1)

    @property
    def roi_verdict(self) -> str:
        pct = self.cycle_time_improvement_pct
        if pct is None:
            return "⚪ Insufficient data"
        if pct > 20:
            return f"🟢 Strong ROI — Duo-assisted MRs merge {pct}% faster"
        if pct > 5:
            return f"🟡 Positive ROI — {pct}% cycle time improvement"
        if pct > -5:
            return "🟡 Neutral — No significant difference yet"
        return f"🔴 Investigate — Duo-assisted MRs are {abs(pct)}% slower"


# ---------------------------------------------------------------------------
# GitLab API client
# ---------------------------------------------------------------------------

class GitLabAPI:
    def __init__(self, url: str, token: str):
        self.base = url.rstrip("/") + "/api/v4"
        self.token = token

    def _get(self, path: str, params: dict = None) -> dict | list:
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": self.token})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            log.error(f"API GET {path}: {e}")
            return {}

    def _post(self, path: str, data: dict) -> dict:
        url = f"{self.base}{path}"
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"PRIVATE-TOKEN": self.token, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            log.error(f"API POST {path}: {e}")
            return {}

    def get_project(self, pid: str) -> dict:
        return self._get(f"/projects/{urllib.parse.quote(pid, safe='')}")

    def get_mrs(self, pid: str, state: str = "merged", after: str = None, per_page: int = 100) -> list[dict]:
        """Paginate through merged MRs."""
        all_mrs, page = [], 1
        encoded = urllib.parse.quote(pid, safe="")
        while True:
            result = self._get(f"/projects/{encoded}/merge_requests", {
                "state": state, "per_page": per_page, "page": page,
                "created_after": after,
            })
            if not result or not isinstance(result, list):
                break
            all_mrs.extend(result)
            if len(result) < per_page:
                break
            page += 1
        return all_mrs

    def get_mr_detail(self, pid: str, mr_iid: int) -> dict:
        encoded = urllib.parse.quote(pid, safe="")
        return self._get(f"/projects/{encoded}/merge_requests/{mr_iid}", {"statistics": "true"})

    def post_issue_note(self, pid: str, issue_iid: str, body: str) -> dict:
        encoded = urllib.parse.quote(pid, safe="")
        return self._post(f"/projects/{encoded}/issues/{issue_iid}/notes", {"body": body})

    def create_issue(self, pid: str, title: str, description: str) -> dict:
        encoded = urllib.parse.quote(pid, safe="")
        return self._post(f"/projects/{encoded}/issues", {
            "title": title,
            "description": description,
            "labels": "pipeline-report",
        })


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def collect_mr_metrics(api: GitLabAPI, project_id: str, since_days: int = 30) -> list[MRMetrics]:
    """Fetch all merged MRs from the last N days and build MRMetrics objects."""
    after = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()
    raw_mrs = api.get_mrs(project_id, state="merged", after=after)
    log.info(f"Fetched {len(raw_mrs)} merged MRs from last {since_days} days")

    metrics = []
    for mr in raw_mrs:
        iid = mr.get("iid")
        labels = mr.get("labels", [])

        # Get statistics (additions/deletions/commits)
        stats = mr.get("changes_count") or 0
        additions  = mr.get("additions",  0)
        deletions  = mr.get("deletions",  0)

        metrics.append(MRMetrics(
            iid=iid,
            title=mr.get("title", ""),
            author=mr.get("author", {}).get("name", "unknown"),
            created_at=parse_dt(mr.get("created_at")),
            merged_at=parse_dt(mr.get("merged_at")),
            closed_at=parse_dt(mr.get("closed_at")),
            labels=labels,
            additions=additions,
            deletions=deletions,
            commits=mr.get("commits") or 0,
            review_comments=mr.get("user_notes_count", 0),
            duo_assisted=DUO_LABEL in labels,
        ))

    return metrics


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(project_id: str, since_days: int = 30) -> ImpactReport:
    api = GitLabAPI(GITLAB_URL, GITLAB_TOKEN)

    project = api.get_project(project_id)
    project_name = project.get("name", project_id)

    all_metrics = collect_mr_metrics(api, project_id, since_days)

    duo_mrs    = [m for m in all_metrics if m.duo_assisted]
    manual_mrs = [m for m in all_metrics if not m.duo_assisted]

    log.info(f"Duo-assisted: {len(duo_mrs)} MRs | Manual: {len(manual_mrs)} MRs")

    period_end   = datetime.now(timezone.utc)
    period_start = period_end - timedelta(days=since_days)

    return ImpactReport(
        project_name=project_name,
        period_start=period_start,
        period_end=period_end,
        duo_cohort=CohortStats("Duo-Assisted", DUO_LABEL, duo_mrs),
        manual_cohort=CohortStats("Manual", "no-duo", manual_mrs),
    )


def format_hours(h: Optional[float]) -> str:
    if h is None:
        return "N/A"
    if h < 24:
        return f"{h:.1f}h"
    return f"{h/24:.1f}d"


def render_markdown_report(report: ImpactReport) -> str:
    d = report.duo_cohort
    m = report.manual_cohort
    pct = report.cycle_time_improvement_pct
    pct_str = f"{'+' if pct and pct > 0 else ''}{pct}%" if pct is not None else "N/A"

    period = (
        f"{report.period_start.strftime('%b %d')} – "
        f"{report.period_end.strftime('%b %d, %Y')}"
    )

    return f"""# 📊 Pipeline AI Impact Dashboard
**Project:** {report.project_name}
**Period:** {period}
**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}

---

## Verdict: {report.roi_verdict}

---

## Cohort Comparison

| Metric | 🤖 Duo-Assisted | 👤 Manual | Δ |
|--------|-----------------|-----------|---|
| **MRs analyzed** | {len(d.mrs)} | {len(m.mrs)} | — |
| **Median cycle time** | {format_hours(d.median_cycle_time_hours)} | {format_hours(m.median_cycle_time_hours)} | **{pct_str}** |
| **Mean cycle time** | {format_hours(d.mean_cycle_time_hours)} | {format_hours(m.mean_cycle_time_hours)} | — |
| **P90 cycle time** | {format_hours(d.p90_cycle_time_hours)} | {format_hours(m.p90_cycle_time_hours)} | — |
| **Throughput (MR/week)** | {d.throughput_per_week} | {m.throughput_per_week} | — |
| **Avg review comments** | {d.avg_comments or 'N/A'} | {m.avg_comments or 'N/A'} | — |
| **Avg code churn (lines)** | {int(d.avg_churn) if d.avg_churn else 'N/A'} | {int(m.avg_churn) if m.avg_churn else 'N/A'} | — |

---

## Interpretation

{"✅ **Duo is delivering ROI.** Cycle time improvement shows developers are shipping faster with AI assistance." if pct and pct > 10 else
 "⚠️ **Mixed signal.** The difference may be too small or the Duo-assisted cohort too small to draw conclusions yet. Consider:" if pct and abs(pct) <= 10 else
 "❌ **Investigate Duo usage patterns.** Slower cycle times with Duo may indicate prompt engineering overhead is outweighing the benefit." if pct and pct < -5 else
 "ℹ️ **Not enough data.** More Duo-assisted MRs needed (minimum ~20) for statistical significance."}

### What to do next
{"- Continue current Duo usage patterns" if pct and pct > 10 else ""}
{"- Identify top Duo users and document their prompting techniques as team playbooks" if pct and pct > 0 else ""}
{"- Run team training on effective Duo prompting — the context scaffolding tool can reduce prompt toil" if pct is None or pct <= 10 else ""}
{"- Label more MRs with `{DUO_LABEL}` to grow the sample size" if len(d.mrs) < 20 else ""}
{"- Check if teams with slow Duo MRs need training vs. teams with fast ones" if pct and pct < 0 else ""}

---

## Top Duo-Assisted MRs (Fastest)
{_top_mrs_table(d.merged_mrs)}

---

*Generated by **Pipeline** — AI Impact Dashboard · [Studio Zelda GitLab AI Hackathon 2026]*
*To disable: remove the `{DUO_LABEL}` label from MRs or cancel the CI schedule.*
"""


def _top_mrs_table(mrs: list[MRMetrics], top_n: int = 5) -> str:
    fast = sorted(
        [m for m in mrs if m.cycle_time_hours is not None],
        key=lambda m: m.cycle_time_hours
    )[:top_n]

    if not fast:
        return "_No merged Duo-assisted MRs in this period._"

    rows = ["| MR | Author | Cycle Time | Churn |", "|---|---|---|---|"]
    for m in fast:
        rows.append(
            f"| !{m.iid} {m.title[:50]}{'…' if len(m.title) > 50 else ''} "
            f"| {m.author} | {format_hours(m.cycle_time_hours)} | +{m.additions}/-{m.deletions} |"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Pipeline AI Impact Dashboard")
    subparsers = parser.add_subparsers(dest="cmd")

    rep = subparsers.add_parser("report", help="Generate impact report")
    rep.add_argument("--project-id",   default=PROJECT_ID)
    rep.add_argument("--since-days",   type=int, default=30)
    rep.add_argument("--output",       choices=["markdown", "json"], default="markdown")
    rep.add_argument("--post-issue",   action="store_true", help="Post report to tracking issue")
    rep.add_argument("--issue-iid",    default=REPORT_ISSUE_IID)
    rep.add_argument("--create-issue", action="store_true", help="Create a new issue for the report")

    args = parser.parse_args()

    if args.cmd == "report":
        if not args.project_id:
            parser.error("--project-id or PROJECT_ID env var required")

        log.info(f"Generating report for {args.project_id} (last {args.since_days} days)...")
        report = generate_report(args.project_id, args.since_days)

        if args.output == "json":
            # Simple JSON summary
            print(json.dumps({
                "project": report.project_name,
                "period_days": args.since_days,
                "duo_mrs": len(report.duo_cohort.mrs),
                "manual_mrs": len(report.manual_cohort.mrs),
                "duo_median_cycle_hours": report.duo_cohort.median_cycle_time_hours,
                "manual_median_cycle_hours": report.manual_cohort.median_cycle_time_hours,
                "cycle_time_improvement_pct": report.cycle_time_improvement_pct,
                "verdict": report.roi_verdict,
            }, indent=2))
        else:
            md = render_markdown_report(report)
            print(md)

            api = GitLabAPI(GITLAB_URL, GITLAB_TOKEN)

            if args.post_issue and args.issue_iid:
                result = api.post_issue_note(args.project_id, args.issue_iid, md)
                if result:
                    log.info(f"✅ Report posted to issue #{args.issue_iid}")
                else:
                    log.error("❌ Failed to post report to issue")

            if args.create_issue:
                title = f"📊 Pipeline AI Impact Report — {datetime.now().strftime('%B %Y')}"
                result = api.create_issue(args.project_id, title, md)
                if result:
                    iid = result.get("iid", "?")
                    log.info(f"✅ Report issue created: #{iid}")
    else:
        parser.print_help()
