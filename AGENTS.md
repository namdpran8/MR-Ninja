# Pipeline — Large Context Orchestrator Rules

## Purpose
This file provides persistent context and operating rules for the **Mr Ninja**
agent running inside GitLab Duo Agent Platform. It is automatically injected into every agent
session within this project.
---

## Chunking Rules

- **Trigger threshold**: If the estimated token count of the full input exceeds **150,000 tokens**,
  mandatory chunking must be applied before any analysis.
- **Token estimation heuristic**: `tokens ≈ len(text_in_bytes) / 4`
- **Target chunk size**: 40,000 – 80,000 tokens per chunk.
- **Hard chunk ceiling**: Never exceed 100,000 tokens in a single agent sub-call.

## Chunk Ordering Strategy (MR Diffs)

Process files in the following priority order to maximize early signal:

1. **Security-critical files first** — `*.env`, `*.yaml`, `*.yml`, `Dockerfile*`, `*.tf`,
   `requirements*.txt`, `package*.json`, `Gemfile*`, `*.toml`, auth/permission modules.
2. **Directly changed files** — files with actual diff hunks (`+++`/`---` lines in the diff).
3. **Entry points & interfaces** — `main.*`, `app.*`, `index.*`, API route files.
4. **Dependency/shared modules** — imported by multiple changed files.
5. **Test files** — process last unless the MR is explicitly test-focused.
6. **Generated or lock files** — skip unless security-flagged.

## Cross-Chunk State (What to Carry Forward)

After processing each chunk, the orchestrator MUST produce and carry:

```
CHUNK_SUMMARY:
  chunk_id: <int>
  files_processed: [<list of file paths>]
  findings: [<brief finding per file, max 2 sentences each>]
  imports_exported: [<symbols/modules exported that downstream chunks may need>]
  open_questions: [<cross-file concerns requiring later chunks to resolve>]
```

This summary is prepended (compressed) to the next chunk call — never the full prior output.

## Aggregation Rules

- **Deduplicate** findings by file path + finding type. Keep the highest-severity instance.

- **Severity ladder**: CRITICAL > HIGH > MEDIUM > LOW > INFO

- **Final report format**: Markdown with sections — Executive Summary, Findings Table,
  Per-Chunk Details (collapsible), Recommendations, Re-run Flag.

- If any chunk produced an `open_question` that was never resolved, flag it explicitly in the report.

## Agent Invocation Policy

- Invoke `@GitLab Duo Security Analyst` for chunks containing security-critical files.

- Invoke `@GitLab Duo Code Review` for logic/architecture chunks.

- For mixed chunks, invoke Security Analyst first, then Code Review.

- Always pass `chunk_id` and `total_chunks` in the sub-agent call header so agents know their context.

## Hard Constraints

- **Never** pass raw full-file content when a diff hunk is sufficient.

- **Never** repeat a file in two chunks.

- **Always** post a WIP comment on the MR at the start: `🔄 Pipeline orchestrator running — chunk plan attached.`

- **Always** post the final report as a threaded MR note, not a standalone comment.

- If the GitLab API rate-limits a tool call, wait 2 seconds and retry once before failing gracefully.
