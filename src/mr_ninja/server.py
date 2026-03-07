"""
mr_ninja.server

FastAPI service for Mr Ninja -- Large Context Orchestrator for GitLab Duo.

Provides REST endpoints to:
- Analyze a merge request (POST /analyze)
- Check service health (GET /health)
- Run a demo analysis (POST /demo)

Start the server:
    mr-ninja serve
    uvicorn mr_ninja.server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from mr_ninja.agents.orchestrator import Orchestrator
from mr_ninja.core.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("mr_ninja.app")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Mr Ninja",
    description=(
        "Large Context Orchestrator for GitLab Duo. "
        "Analyzes large merge requests by chunking them into smaller pieces "
        "and processing each chunk through specialist agents."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint. Returns service status."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        service="mr-ninja",
    )


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_mr(request: AnalyzeRequest):
    """Analyze a GitLab merge request.

    Accepts an MR URL or project_id + mr_iid, fetches the diffs,
    chunks them, runs specialist agents on each chunk, and returns
    an aggregated analysis report.

    The analysis is performed synchronously — for very large MRs,
    this may take 30-60 seconds.
    """
    logger.info(f"Received analysis request: {request.mr_url or request.project_id}")

    # Use env vars as defaults if not provided in request
    gitlab_token = request.gitlab_token or os.getenv("GITLAB_TOKEN", "")
    gitlab_url = request.gitlab_url or os.getenv("GITLAB_URL", "https://gitlab.com")

    if not gitlab_token:
        raise HTTPException(
            status_code=400,
            detail="gitlab_token is required (or set GITLAB_TOKEN env var)",
        )

    if not request.mr_url and (not request.project_id or not request.mr_iid):
        raise HTTPException(
            status_code=400,
            detail="Provide either mr_url or both project_id and mr_iid",
        )

    orchestrator = Orchestrator(
        gitlab_url=gitlab_url,
        gitlab_token=gitlab_token,
        max_chunk_tokens=request.max_chunk_tokens,
        post_comments=request.post_comment,
    )

    updated_request = AnalyzeRequest(
        mr_url=request.mr_url,
        project_id=request.project_id,
        mr_iid=request.mr_iid,
        gitlab_url=gitlab_url,
        gitlab_token=gitlab_token,
        max_chunk_tokens=request.max_chunk_tokens,
        post_comment=request.post_comment,
    )

    response = orchestrator.analyze_request(updated_request)

    if response.status == "error":
        raise HTTPException(status_code=500, detail=response.error)

    return response


@app.post("/demo", response_model=AnalyzeResponse, tags=["Demo"])
async def run_demo():
    """Run a demo analysis using synthetic data.

    Generates a simulated 500+ file MR and analyzes it, returning
    the full analysis report. No GitLab connection required.
    """
    logger.info("Running demo analysis...")

    # Import the demo generator
    from mr_ninja.demo.simulate_large_mr import generate_demo_files

    # Generate synthetic files
    files = generate_demo_files(file_count=512)

    # Run the orchestrator in demo mode
    orchestrator = Orchestrator(
        post_comments=False,
        use_duo_agents=False,
    )
    report = orchestrator.analyze_files(
        files=files,
        mr_id="demo-512",
        mr_title="Demo: Large Monorepo MR (512 files)",
    )

    # Get the plan for markdown rendering
    from mr_ninja.agents.chunk_planner import ChunkPlanner
    planner = ChunkPlanner()
    plan = planner.plan_from_files(files, "demo-512", "Demo: Large Monorepo MR (512 files)")
    markdown = orchestrator.aggregator.render_markdown(
        plan, report.processing_time_seconds
    )

    return AnalyzeResponse(
        status="ok",
        mr_id=report.mr_id,
        chunks_processed=report.chunks_processed,
        total_findings=len(report.findings),
        critical_findings=report.critical_count,
        overall_risk=report.overall_risk.value,
        report_markdown=markdown,
        processing_time_seconds=report.processing_time_seconds,
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    """Run the FastAPI server via uvicorn."""
    import uvicorn

    host = os.getenv("MR_NINJA_HOST", "0.0.0.0")
    port = int(os.getenv("MR_NINJA_PORT", "8000"))

    logger.info(f"Starting Mr Ninja server on {host}:{port}")
    uvicorn.run(
        "mr_ninja.server:app",
        host=host,
        port=port,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    main()
