# Mr Ninja — System Architecture

## Overview

Mr Ninja is a **Large Context Wrapper Agent** that solves the GitLab Duo Agent Platform's ~200,000 token context limit. It intelligently chunks large merge requests and codebases, processes them through phased specialist agents, and aggregates results into a unified analysis report.

## Architecture Diagram

```
                              ┌────────────────────────┐
                              │     FastAPI Service     │
                              │       (app.py)         │
                              └───────────┬────────────┘
                                          │
                              ┌───────────▼────────────┐
                              │     ORCHESTRATOR       │
                              │  (agents/orchestrator) │
                              │                        │
                              │  Coordinates the full  │
                              │  analysis pipeline     │
                              └───────────┬────────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
          ┌─────────▼──────────┐  ┌──────▼───────┐  ┌─────────▼──────────┐
          │   CHUNK PLANNER    │  │  GITLAB API  │  │  TOKEN ESTIMATOR   │
          │                    │  │  CONNECTOR   │  │                    │
          │  - Fetch MR diffs  │  │              │  │  - 4 chars/token   │
          │  - Classify files  │  │  - MR diffs  │  │  - Content-type    │
          │  - Priority sort   │  │  - File read │  │    multipliers     │
          │  - Bin-pack chunks │  │  - MR notes  │  │  - Threshold check │
          └─────────┬──────────┘  └──────────────┘  └────────────────────┘
                    │
                    │  ChunkPlan
                    │
          ┌─────────▼──────────┐
          │   CHUNK PROCESSOR  │  (sequential, one chunk at a time)
          │                    │
          │  For each chunk:   │
          │  ┌───────────────┐ │
          │  │Security Analyst│ │  P1 chunks → security scan
          │  │               │ │
          │  │Code Reviewer  │ │  P2-P4 chunks → code quality
          │  │               │ │
          │  │Dependency     │ │  Package files → dep analysis
          │  │Analyzer       │ │
          │  └───────────────┘ │
          └─────────┬──────────┘
                    │
                    │  ChunkSummary (per chunk)
                    │
          ┌─────────▼──────────┐
          │ CONTEXT SUMMARIZER │
          │                    │
          │ - Accumulates      │
          │   findings         │
          │ - Tracks exports   │
          │ - Open questions   │
          │ - Compresses       │────→ Cross-chunk context
          │   context header   │      (prepended to next chunk)
          └─────────┬──────────┘
                    │
                    │  All ChunkSummaries
                    │
          ┌─────────▼──────────┐
          │  RESULT AGGREGATOR │
          │                    │
          │  - Deduplicate     │
          │  - Severity rank   │
          │  - Risk score      │
          │  - Markdown report │
          └─────────┬──────────┘
                    │
                    ▼
          ┌────────────────────┐
          │  FINAL REPORT      │
          │                    │
          │  - Posted as MR    │
          │    comment         │
          │  - Returned via    │
          │    API             │
          └────────────────────┘
```

## Data Flow

```
MR URL
  │
  ▼
GitLab API ──→ Raw Diffs (500+ files)
  │
  ▼
Token Estimator ──→ Total: ~800k tokens (exceeds 150k threshold)
  │
  ▼
Chunk Planner ──→ ChunkPlan with N chunks
  │                ├── Chunk 1: P1 security files (~60k tokens)
  │                ├── Chunk 2: P2 entry points  (~70k tokens)
  │                ├── Chunk 3: P3 source files   (~65k tokens)
  │                ├── ...
  │                └── Chunk N: P5 test files     (~50k tokens)
  │
  ▼
Chunk Processor (sequential loop)
  │
  │  Chunk 1 ──→ Security Analyst ──→ ChunkSummary 1
  │  ↓ context
  │  Chunk 2 ──→ Code Reviewer    ──→ ChunkSummary 2
  │  ↓ context
  │  Chunk 3 ──→ Code Reviewer    ──→ ChunkSummary 3
  │  ...
  │
  ▼
Result Aggregator ──→ AnalysisReport
  │
  ▼
Markdown Report ──→ Posted to MR as comment
```

## Component Details

### 1. Token Estimator (`core/token_estimator.py`)

- **Heuristic**: 1 token ≈ 4 characters
- **Content-type multipliers**: JSON/YAML get 1.15x, minified JS gets 1.3x
- **Threshold**: Chunking triggers at 150,000 total tokens
- **Target**: Each chunk aims for 70,000 tokens (hard cap: 100,000)

### 2. Chunking Engine (`core/chunking_engine.py`)

- **Classification**: Regex-based file priority classification (P1-P6)
- **Algorithm**: Greedy first-fit bin-packing
- **Ordering**: Security-critical files first, tests last
- **Generated files**: Automatically skipped (lock files, node_modules, etc.)

### 3. Chunk Processor (`agents/chunk_processor.py`)

Each chunk runs through specialist analysis:

| Agent | Trigger | Checks |
|-------|---------|--------|
| Security Analyst | P1 files or MIXED chunks | Hardcoded secrets, SQL injection, XSS, eval(), shell injection, SSL bypass |
| Code Reviewer | P2-P4 files | Bare except, debug prints, TODOs, global state |
| Dependency Analyzer | Package manifests | Wildcard versions, deprecated packages, broad ranges |

### 4. Context Summarizer (`agents/summarizer.py`)

After each chunk, a compact context summary is generated:
- CRITICAL/HIGH findings always carried forward
- Open questions tracked until resolved
- Exported symbols shared with downstream chunks
- Max 2,000 tokens of context overhead

### 5. Result Aggregator (`agents/aggregator.py`)

- **Deduplication**: Same (file, title) → keep highest severity
- **Sorting**: CRITICAL → HIGH → MEDIUM → LOW → INFO
- **Risk Score**: Weighted sum (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1), max 100
- **Report**: Markdown with executive summary, findings table, recommendations

## Models (`core/models.py`)

All data contracts are Pydantic models:

| Model | Purpose |
|-------|---------|
| `FileEntry` | Single file with metadata and token estimate |
| `Chunk` | Group of files for a single agent call |
| `ChunkPlan` | Complete analysis plan |
| `Finding` | Single security/quality/dependency finding |
| `ChunkSummary` | Cross-chunk context carrier |
| `AnalysisReport` | Final aggregated report |
| `AnalyzeRequest` | API request model |
| `AnalyzeResponse` | API response model |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service health check |
| POST | `/analyze` | Analyze a GitLab MR |
| POST | `/demo` | Run demo analysis (no GitLab needed) |
| GET | `/docs` | Swagger UI documentation |

## GitLab Integration

The system uses these GitLab API endpoints:
- `GET /projects/:id/merge_requests/:iid` — MR metadata
- `GET /projects/:id/merge_requests/:iid/diffs` — MR file diffs
- `POST /projects/:id/merge_requests/:iid/notes` — Post MR comments
- `GET /projects/:id/repository/files/:path` — Read file content
- `GET /projects/:id/repository/tree` — List repository files

## Security Considerations

- GitLab tokens are passed via environment variables or request body (never logged)
- API retry logic prevents abuse (max 2 retries with 2s delay)
- Rate limiting respected via `429` response handling
- No data persisted to disk in production mode
