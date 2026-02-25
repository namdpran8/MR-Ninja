# Pipeline — Large Context Orchestrator for GitLab Duo

> **GitLab AI Hackathon 2026** — "You Orchestrate. AI Accelerates."
> Team: 

---

## The Problem

GitLab Duo Agent Platform caps context at ~150,000–200,000 tokens per call.
For real enterprise monorepos — hundreds of changed files, massive diffs — this means
**truncated MR reviews, incomplete vulnerability scans, and frustrated developers.**

## The Solution

**Pipeline** is a custom GitLab Duo orchestrator agent that:

1. **Estimates** the token footprint of any MR or codebase path
2. **Chunks** intelligently — security files first, then logic, then tests
3. **Routes** each chunk to the right specialist (Security Analyst or Code Review)
4. **Carries context** between chunks so cross-file concerns aren't lost
5. **Aggregates** everything into a single unified Markdown report posted to the MR

Large MR that would normally fail or truncate? Pipeline handles it seamlessly.

---

## Repository Structure

```
pipeline-mvp/
├── AGENTS.md                  # Persistent rules injected into every agent session
├── agent_system_prompt.md     # Full system prompt → paste into GitLab Duo Agent config
├── pipeline/
│   └── mr_chunker.py          # Core chunking logic (Python, zero external deps)
├── tests/
│   └── test_mr_chunker.py     # Unit tests (pytest)
└── README.md
```

---

## Quick Start

### 1. Set Up the GitLab Agent

1. Go to your project → **Automate > Agents > New Agent**
2. Name: `Large Context Orchestrator`
3. Paste the contents of `agent_system_prompt.md` into the **System Prompt** field
4. Enable tools: `get_merge_request_diff`, `get_file_content`, `list_files`,
   `search_code`, `create_merge_request_note`
5. Save and test with: `@Large Context Orchestrator Analyze MR: [your MR link]`

### 2. Add AGENTS.md to Your Repo

Copy `AGENTS.md` to the root of any project you want Pipeline to analyze.
GitLab Duo automatically injects it into agent sessions.

### 3. Run the Chunker Locally (for testing)

```bash
# Install (zero dependencies beyond stdlib)
git clone https://gitlab.com/<your-group>/pipeline-mvp
cd pipeline-mvp

# Run against any MR
export GITLAB_TOKEN=<your-PAT>

python pipeline/mr_chunker.py \
  --mr-url https://gitlab.com/mygroup/myproject/-/merge_requests/42 \
  --token $GITLAB_TOKEN

# Post the chunk plan as an MR note
python pipeline/mr_chunker.py \
  --mr-url https://gitlab.com/mygroup/myproject/-/merge_requests/42 \
  --token $GITLAB_TOKEN \
  --post-note

# Output as JSON (for integration with CI pipelines)
python pipeline/mr_chunker.py \
  --mr-url https://gitlab.com/mygroup/myproject/-/merge_requests/42 \
  --token $GITLAB_TOKEN \
  --json
```

### 4. Run Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## How Chunking Works

```
MR Diff (500 files, ~800k tokens)
         │
         ▼
┌─────────────────────┐
│  Token Estimation   │  ~4 chars/token heuristic
└────────┬────────────┘
         │ > 150k tokens?
         ▼
┌─────────────────────────────────────────────┐
│  Priority Sort                              │
│  P1: .env, Dockerfile, *.tf, auth/*         │ ← Security-critical
│  P2: main.py, app.js, routes/*              │ ← Entry points
│  P3: Changed files (default)               │
│  P5: tests/                                │ ← Process last
│  P6: package-lock.json (skip)              │
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│  Greedy Bin Packing                         │
│  Target: 70k tokens/chunk                  │
│  Max:    100k tokens/chunk                 │
│  One file per chunk max if oversized        │
└─────────────────────────────────────────────┘
         │
         ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Chunk 1    │  │   Chunk 2    │  │   Chunk 3    │
│ 🔐 Security  │  │ 🔎 Code Rev  │  │ 🔎 Code Rev  │
│ [.env, tf…]  │  │ [src/…]      │  │ [tests/…]    │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │  summary →      │  summary →      │
       └─────────────────┴─────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  Aggregator          │
              │  Dedupe · Sort       │
              │  Resolve questions   │
              └──────────────────────┘
                         │
                         ▼
              📋 Unified MR Report
```

---

## Hackathon Fit

| Criterion | How Pipeline addresses it |
|-----------|--------------------------|
| **Orchestration** | Chains chunker → specialist agents → aggregator |
| **Agentic workflows** | Multi-step, stateful, human-in-loop ready |
| **Real enterprise pain** | Monorepos, large MRs, compliance scans |
| **Native GitLab** | Custom agent + AGENTS.md + built-in tools only |
| **Demo-able** | Before: truncated. After: full report. |
| **Green Agent bonus** | Efficient chunking reduces redundant LLM calls |

---

## Roadmap (Post-MVP)

- [ ] YAML flow definition for native GitLab Duo Flow support
- [ ] VS Code extension hook — auto-trigger on MR open
- [ ] Token usage metrics per chunk (cost tracking)
- [ ] Incremental mode — re-analyze only changed chunks on new commits
- [ ] MCP integration for external security scanners (Semgrep, Trivy)

---

## License

MIT — see LICENSE

---
