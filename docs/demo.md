# Mr Ninja — Demo Guide

## Quick Demo (No GitLab Required)

The fastest way to see Mr Ninja in action is the demo simulation mode.
It generates a synthetic 512-file monorepo MR and analyzes it end-to-end.

### Prerequisites

- Python 3.11+
- pip

### Run the Demo

```bash
# Install dependencies
pip install -r requirements.txt

# Run demo simulation
python -m demo.simulate_large_mr

# Or with custom file count
python -m demo.simulate_large_mr --files 1000

# Save the report to a file
python -m demo.simulate_large_mr --files 512 --output report.md
```

### What the Demo Does

1. **Generates** 512 synthetic files across 15 microservices:
   - Python and JavaScript source files
   - Configuration files (YAML)
   - Dockerfiles
   - Environment files (.env) with intentional secrets
   - Package manifests with dependency issues
   - Test files
   - Auth handlers with intentional vulnerabilities (SQL injection, eval(), etc.)

2. **Runs the full pipeline**:
   - Token estimation (~200k-800k tokens total)
   - File priority classification (P1-P6)
   - Greedy bin-packing into ~70k-token chunks
   - Sequential chunk processing with cross-chunk context
   - Security analysis, code review, and dependency scanning
   - Result aggregation and deduplication

3. **Produces a Markdown report** with:
   - Executive summary with risk score
   - Findings table sorted by severity
   - Unresolved cross-chunk questions
   - Recommendations
   - Per-chunk processing details

### Expected Demo Output

```
==============================================================
  MR NINJA — DEMO MODE
  Large Context Orchestrator for GitLab Duo
==============================================================

[1/3] Generating 512 synthetic files...
       Generated 512 files across 15 services

[2/3] Running Mr Ninja analysis pipeline...

============================================================
MR NINJA CHUNK PLAN
============================================================
MR:             Demo: Large Monorepo MR (512 files) (#demo-512)
Total files:    512
Est. tokens:    ~340,000
Mode:           CHUNKED

  Chunk 1 (~65,000 tokens | 42 files) -> Security Analyst
  Chunk 2 (~70,000 tokens | 48 files) -> Code Review
  Chunk 3 (~68,000 tokens | 45 files) -> Code Review
  ...
============================================================

[3/3] Generating final report...

# Mr Ninja Analysis Report

**Risk Level:** CRITICAL (Score: 85/100)
**Scanned:** 512 files | ~340,000 tokens | 6 chunks

## Executive Summary

| Metric         | Value |
|---------------|-------|
| Files scanned  | 512   |
| Critical       | 8     |
| High           | 15    |
| Medium         | 22    |

## Findings

| # | Severity | File | Issue | Recommendation |
|---|----------|------|-------|----------------|
| 1 | CRITICAL | auth/handler.py | Hardcoded secret | Move to env vars |
| 2 | CRITICAL | payments/.env | Private key in source | Remove immediately |
| 3 | HIGH | orders/src/handler.py | Unsafe eval() | Use safe parser |
...
```

## Live GitLab Demo

To analyze a real merge request:

### 1. Set up environment

```bash
export GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"
export GITLAB_URL="https://gitlab.com"
```

### 2. Run via CLI

```bash
python -c "
from agents.orchestrator import Orchestrator

orchestrator = Orchestrator(
    gitlab_url='https://gitlab.com',
    gitlab_token='$GITLAB_TOKEN',
    post_comments=True,
)
report = orchestrator.analyze_mr('your-group/your-project', 42)
print(f'Found {len(report.findings)} issues')
"
```

### 3. Run via FastAPI

```bash
# Start the server
uvicorn app:app --host 0.0.0.0 --port 8000

# Analyze an MR
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "mr_url": "https://gitlab.com/group/project/-/merge_requests/42",
    "gitlab_token": "glpat-xxxxxxxxxxxxxxxxxxxx",
    "post_comment": true
  }'

# Run demo via API
curl -X POST http://localhost:8000/demo
```

## Generate a Synthetic Monorepo

You can also generate a full file-system repo for manual inspection:

```bash
python -m demo.generate_large_repo --output-dir ./demo/sample_repo --files 512
```

This creates actual files on disk — useful for exploring the synthetic
directory structure and file contents.

## Running Tests

```bash
# All tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ -v --cov=core --cov=agents --cov-report=term-missing

# Specific test file
python -m pytest tests/test_chunking.py -v
```
