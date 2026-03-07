# Mr Ninja

**Large repo merge request assistant** -- chunk oversized Merge Requests and run multi-agent security analysis.

AI agents often caps context at limited tokens per agent call. A single MR in a monorepo can generate 500k-1M call of diff content, causing truncated reviews and missed vulnerabilities. Mr Ninja solves this by intelligently decomposing large MRs into priority-sorted chunks, processing each through specialist agents, and posting a unified report.

---

## Install

```bash
pip install mr-ninja
```

Or from source:

```bash
git clone https://gitlab.com/your-group/mr-ninja.git
cd mr-ninja
pip install -e ".[dev]"
```

## Quick Start

### Analyze a GitLab MR

```bash
export GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"

# Analyze by URL
mr-ninja analyze https://gitlab.com/group/project/-/merge_requests/42

# Analyze by project + MR IID
mr-ninja analyze --project group/project --mr 42

# Post results as an MR comment
mr-ninja analyze https://gitlab.com/group/project/-/merge_requests/42 --post-comment

# Save report to file
mr-ninja analyze https://gitlab.com/group/project/-/merge_requests/42 -o report.md
```

### Run a Demo (No GitLab Required)

```bash
# Simulate a 512-file MR analysis
mr-ninja demo

# Custom file count
mr-ninja demo --files 1000

# Save report
mr-ninja demo --files 512 -o report.md
```

### Start the REST API Server

```bash
mr-ninja serve
mr-ninja serve --host 127.0.0.1 --port 9000

# Then call the API
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"mr_url": "https://gitlab.com/group/project/-/merge_requests/42", "gitlab_token": "glpat-xxx"}'

# Run demo via API (no token needed)
curl -X POST http://localhost:8000/demo
```

### Docker

```bash
docker build -t mr-ninja .
docker run -p 8000:8000 -e GITLAB_TOKEN=glpat-xxx mr-ninja
```

---

## How It Works

```
500+ file MR (~800k tokens)
         |
         v
   +--------------+
   |   Mr Ninja   |
   | Orchestrator |
   +------+-------+
          |
    +-----+-----+
    |     |     |
    v     v     v
 Chunk  Chunk  Chunk     Each fits within Duo's context limit
  1      2      3
  |      |      |
  v      v      v
 Agent  Agent  Agent     Security / Code Review / Dependency
  |      |      |
  +------+------+
         |
    +----v----+
    |Aggregate|
    | & Post  |
    +---------+
         |
         v
   Unified MR Report
```

1. **Detect** -- Estimates token footprint. If >150k tokens, activates chunking.
2. **Plan** -- Classifies files by priority (security-critical first, tests last) and bin-packs into ~70k-token chunks.
3. **Process** -- Runs each chunk through specialist agents (Security Analyst, Code Reviewer, Dependency Analyzer).
4. **Carry Context** -- Generates compact cross-chunk summaries so findings and dependencies are tracked across chunks.
5. **Aggregate** -- Deduplicates findings, ranks by severity, calculates risk score.
6. **Report** -- Posts a unified Markdown report as an MR comment.

### File Priority System

| Priority | Category | Examples | Order |
|----------|----------|----------|-------|
| P1 | Security-critical | `.env`, `Dockerfile`, `*.tf`, `auth/*`, `*.pem` | First |
| P2 | Entry points | `main.*`, `app.*`, `routes/*`, `api/*` | Second |
| P3 | Changed files | All other source files | Third |
| P4 | Shared modules | Imported by multiple changed files | Fourth |
| P5 | Test files | `tests/*`, `*_test.*`, `*.spec.*` | Last |
| P6 | Generated | `package-lock.json`, `*.min.js`, `dist/*` | Skipped |

### Specialist Agents

| Agent | Detects |
|-------|---------|
| **Security Analyst** | Hardcoded secrets, SQL injection, XSS, eval/exec, shell injection, SSL bypass, pickle, private keys |
| **Code Reviewer** | Bare exceptions, debug prints, TODO/FIXME, global state, long sleeps |
| **Dependency Analyzer** | Wildcard version pins, deprecated packages, broad version ranges |

---

## Example Output

```
Risk Level: CRITICAL (Score: 85/100)
Files scanned: 512
Chunks processed: 6
Processing time: 2.3s

Critical vulnerabilities: 8
High vulnerabilities: 15
Medium issues: 22

Top Issues:
1. [CRITICAL] auth/handler.py -- Hardcoded API key (sk-live-...)
2. [CRITICAL] payments/.env -- Database password in source
3. [CRITICAL] orders/auth_handler.py -- SQL injection via string concat
4. [HIGH] gateway/src/handler.py -- Unsafe eval() execution
5. [HIGH] users/service.py -- Shell injection (subprocess shell=True)

Recommendation: BLOCK MERGE -- resolve all CRITICAL findings before merging.
```

---

## Project Structure

```
mr-ninja/
|-- src/mr_ninja/
|   |-- __init__.py              # Package version
|   |-- __main__.py              # python -m mr_ninja support
|   |-- cli.py                   # CLI entrypoint (analyze, demo, serve)
|   |-- server.py                # FastAPI REST API
|   |-- agents/
|   |   |-- orchestrator.py      # Central coordinator
|   |   |-- chunk_planner.py     # MR diff -> chunk plan
|   |   |-- chunk_processor.py   # Specialist agent runner
|   |   |-- summarizer.py        # Cross-chunk context manager
|   |   +-- aggregator.py        # Findings deduplication & report
|   |-- core/
|   |   |-- models.py            # Pydantic data models
|   |   |-- token_estimator.py   # Token count estimation engine
|   |   +-- chunking_engine.py   # File classification & bin-packing
|   |-- gitlab/
|   |   +-- gitlab_client.py     # GitLab REST API connector (stdlib only)
|   |-- demo/
|   |   |-- simulate_large_mr.py # MR simulation & analysis
|   |   +-- generate_large_repo.py
|   +-- flows/
|       +-- agent_flow.yaml      # Pipeline flow definition
|-- tests/
|   |-- test_token_estimator.py
|   |-- test_chunking.py
|   |-- test_aggregation.py
|   +-- test_orchestrator.py
|-- pyproject.toml               # Package config & tool settings
|-- Dockerfile
|-- .gitlab-ci.yml               # CI/CD pipeline
|-- AGENTS.md                    # GitLab Duo agent rules
|-- CONTRIBUTING.md              # Development & publishing guide
|-- LICENSE                      # MIT
+-- README.md
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/analyze` | Analyze a GitLab MR |
| `POST` | `/demo` | Run demo (no GitLab needed) |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/redoc` | ReDoc API docs |

### POST /analyze

```json
{
  "mr_url": "https://gitlab.com/group/project/-/merge_requests/42",
  "gitlab_token": "glpat-xxxxxxxxxxxxxxxxxxxx",
  "max_chunk_tokens": 70000,
  "post_comment": true
}
```

### Response

```json
{
  "status": "ok",
  "mr_id": "42",
  "chunks_processed": 6,
  "total_findings": 45,
  "critical_findings": 8,
  "overall_risk": "CRITICAL",
  "report_markdown": "# Mr Ninja Analysis Report\n...",
  "processing_time_seconds": 2.3
}
```

---

## Python API

```python
from mr_ninja.agents.orchestrator import Orchestrator

orchestrator = Orchestrator(
    gitlab_url="https://gitlab.com",
    gitlab_token="glpat-xxx",
    post_comments=True,
)

# Analyze by project + MR IID
report = orchestrator.analyze_mr("group/project", 42)

# Analyze by URL
report = orchestrator.analyze_mr_from_url(
    "https://gitlab.com/group/project/-/merge_requests/42"
)

print(f"Risk: {report.overall_risk.value}")
print(f"Findings: {len(report.findings)}")
```

---

## Development

```bash
git clone https://gitlab.com/your-group/mr-ninja.git
cd mr-ninja
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=mr_ninja --cov-report=term-missing

# Lint
ruff check src/

# Type check
mypy src/mr_ninja/core/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for packaging, publishing, and release guides.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| API Framework | FastAPI |
| Data Models | Pydantic v2 |
| HTTP Client | urllib (stdlib -- zero dependencies) |
| CI/CD | GitLab CI |
| Container | Docker |
| Testing | pytest + pytest-cov |

---

## License

Copyright [2026] [Pranshu Namdeo and Chukwunonso Richard License]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


