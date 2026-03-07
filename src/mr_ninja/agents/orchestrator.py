"""
agents/orchestrator.py

Mr Ninja Orchestrator Agent — the main entry point.

This is the central coordinator that ties together all components:
1. ChunkPlanner — determines how to split the MR
2. ChunkProcessor — analyzes each chunk with specialist agents
3. ContextSummarizer — maintains cross-chunk context
4. ResultAggregator — combines all results into a final report

The orchestrator runs the full pipeline:
    Detect -> Plan -> Process chunks -> Summarize -> Aggregate -> Report

It can operate in two modes:
- Live mode: fetches real MR data from GitLab
- Demo mode: processes synthetic data for demonstration
"""

from __future__ import annotations

import logging
import time

from mr_ninja.agents.aggregator import ResultAggregator
from mr_ninja.agents.chunk_planner import ChunkPlanner
from mr_ninja.agents.chunk_processor import ChunkProcessor
from mr_ninja.agents.summarizer import ContextSummarizer
from mr_ninja.core.chunking_engine import ChunkingEngine
from mr_ninja.core.models import (
    AnalysisReport,
    AnalyzeRequest,
    AnalyzeResponse,
    ChunkPlan,
    FileEntry,
)
from mr_ninja.core.token_estimator import TokenEstimator
from mr_ninja.gitlab.gitlab_client import GitLabClient

logger = logging.getLogger("mr_ninja.orchestrator")


class Orchestrator:
    """Central orchestrator for the Mr Ninja pipeline.

    Coordinates the full analysis workflow:
    1. Accept an MR URL or file list
    2. Build a chunk plan (via ChunkPlanner)
    3. Process each chunk sequentially (via ChunkProcessor)
    4. Maintain cross-chunk context (via ContextSummarizer)
    5. Aggregate results (via ResultAggregator)
    6. Generate and post the final report

    Args:
        gitlab_url: GitLab instance base URL.
        gitlab_token: Personal access token with api scope.
        max_chunk_tokens: Target tokens per chunk.
        post_comments: Whether to post results as MR comments.
        use_duo_agents: Whether to use real GitLab Duo agents (vs heuristics).
    """

    def __init__(
        self,
        gitlab_url: str = "https://gitlab.com",
        gitlab_token: str = "",
        max_chunk_tokens: int = 70_000,
        post_comments: bool = True,
        use_duo_agents: bool = False,
    ):
        # Core components
        self.gitlab_client = GitLabClient(
            gitlab_url=gitlab_url, token=gitlab_token
        )
        self.token_estimator = TokenEstimator()
        self.chunking_engine = ChunkingEngine(
            target_tokens=max_chunk_tokens
        )

        # Agent components
        self.planner = ChunkPlanner(
            gitlab_client=self.gitlab_client,
            chunking_engine=self.chunking_engine,
            token_estimator=self.token_estimator,
        )
        self.processor = ChunkProcessor(use_duo_agents=use_duo_agents)
        self.summarizer = ContextSummarizer()
        self.aggregator = ResultAggregator()

        # Configuration
        self.post_comments = post_comments
        self.gitlab_url = gitlab_url
        self.gitlab_token = gitlab_token

    def analyze_mr(
        self,
        project_id: str,
        mr_iid: int,
    ) -> AnalysisReport:
        """Analyze a merge request end-to-end.

        This is the main entry point for live GitLab MR analysis.

        Args:
            project_id: GitLab project ID or URL-encoded path.
            mr_iid: Merge request internal ID.

        Returns:
            Complete AnalysisReport with all findings.
        """
        start = time.time()

        logger.info(f"Starting MR analysis: {project_id} !{mr_iid}")

        # Post a WIP comment on the MR
        if self.post_comments:
            self._post_wip_comment(project_id, mr_iid)

        # Phase 1: Plan
        logger.info("Phase 1: Building chunk plan...")
        plan = self.planner.plan_from_mr(project_id, mr_iid)
        self.planner.print_plan(plan)

        # Phase 2-4: Process, Summarize, Aggregate
        report = self._execute_plan(plan, start)

        # Phase 5: Post final report
        if self.post_comments:
            markdown = self.aggregator.render_markdown(
                plan, processing_time=report.processing_time_seconds
            )
            self._post_final_report(project_id, mr_iid, markdown)

        return report

    def analyze_mr_from_url(self, mr_url: str) -> AnalysisReport:
        """Analyze an MR from its full URL.

        Parses the URL to extract project_id and mr_iid,
        then delegates to analyze_mr().

        Args:
            mr_url: Full GitLab MR URL.

        Returns:
            Complete AnalysisReport.
        """
        gitlab_base, project_id, mr_iid = GitLabClient.parse_mr_url(mr_url)

        # Re-initialize client if the URL points to a different GitLab instance
        if gitlab_base.rstrip("/") != self.gitlab_url.rstrip("/"):
            self.gitlab_client = GitLabClient(
                gitlab_url=gitlab_base, token=self.gitlab_token
            )
            self.planner.gitlab = self.gitlab_client

        return self.analyze_mr(project_id, mr_iid)

    def analyze_files(
        self,
        files: list[FileEntry],
        mr_id: str = "demo",
        mr_title: str = "Demo Analysis",
    ) -> AnalysisReport:
        """Analyze a list of FileEntry objects (demo/offline mode).

        Skips GitLab API calls entirely. Useful for demos and testing.

        Args:
            files: Pre-built list of FileEntry objects.
            mr_id: Identifier for this analysis run.
            mr_title: Human-readable title.

        Returns:
            Complete AnalysisReport.
        """
        start = time.time()

        logger.info(
            f"Starting file analysis (demo mode): "
            f"{len(files)} files, {mr_title}"
        )

        # Phase 1: Plan
        plan = self.planner.plan_from_files(files, mr_id, mr_title)
        self.planner.print_plan(plan)

        # Phase 2-4: Process, Summarize, Aggregate
        return self._execute_plan(plan, start)

    def analyze_request(self, request: AnalyzeRequest) -> AnalyzeResponse:
        """Handle an API analysis request (FastAPI endpoint).

        Args:
            request: Incoming AnalyzeRequest.

        Returns:
            AnalyzeResponse with results summary.
        """
        try:
            # Update credentials if provided
            if request.gitlab_token:
                self.gitlab_client = GitLabClient(
                    gitlab_url=request.gitlab_url,
                    token=request.gitlab_token,
                )
                self.planner.gitlab = self.gitlab_client

            # Determine project_id and mr_iid
            if request.mr_url:
                _, project_id, mr_iid = GitLabClient.parse_mr_url(
                    request.mr_url
                )
            else:
                project_id = request.project_id
                mr_iid = request.mr_iid

            self.post_comments = request.post_comment

            # Run analysis
            report = self.analyze_mr(project_id, mr_iid)

            # Render markdown
            plan = self.planner.plan_from_mr(project_id, mr_iid)
            markdown = self.aggregator.render_markdown(
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

        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            return AnalyzeResponse(
                status="error",
                error=str(e),
            )

    # ------------------------------------------------------------------
    # Internal pipeline execution
    # ------------------------------------------------------------------

    def _execute_plan(
        self,
        plan: ChunkPlan,
        start_time: float,
    ) -> AnalysisReport:
        """Execute a chunk plan: process all chunks, summarize, aggregate.

        This is the core pipeline loop:
        For each chunk:
            1. Get cross-chunk context from summarizer
            2. Process chunk with the appropriate specialist agent
            3. Feed chunk summary back to summarizer
            4. Feed chunk summary to aggregator

        Args:
            plan: The chunk plan to execute.
            start_time: Pipeline start timestamp (for timing).

        Returns:
            Final AnalysisReport.
        """
        total_chunks = plan.chunk_count

        logger.info(
            f"Executing plan: {total_chunks} chunk(s), "
            f"{plan.total_estimated_tokens:,} tokens"
        )

        for chunk in plan.chunks:
            # Get cross-chunk context from previous chunks
            context = self.summarizer.get_context_for_next_chunk()

            logger.info(
                f"--- Chunk {chunk.chunk_id}/{total_chunks} ---"
            )
            if context:
                logger.debug(f"Cross-chunk context ({len(context)} chars)")

            # Process the chunk
            summary = self.processor.process_chunk(
                chunk=chunk,
                prior_context=context,
                total_chunks=total_chunks,
            )

            # Feed results to summarizer and aggregator
            self.summarizer.ingest_chunk_summary(summary)
            self.aggregator.ingest_summary(summary)

            logger.info(
                f"Chunk {chunk.chunk_id} done: "
                f"{len(summary.findings)} findings"
            )

        # Build final report
        elapsed = time.time() - start_time
        report = self.aggregator.build_report(plan, processing_time=elapsed)

        # Log final stats
        stats = self.summarizer.get_summary_stats()
        logger.info(
            f"Analysis complete in {elapsed:.2f}s: "
            f"{stats['total_findings']} total findings, "
            f"{stats['open_questions']} open questions"
        )

        return report

    # ------------------------------------------------------------------
    # GitLab comment helpers
    # ------------------------------------------------------------------

    def _post_wip_comment(self, project_id: str, mr_iid: int) -> None:
        """Post a WIP/in-progress comment on the MR."""
        try:
            self.gitlab_client.create_merge_request_note(
                project_id,
                mr_iid,
                "Mr Ninja orchestrator running — analyzing MR in chunks. "
                "Full report will be posted shortly.",
            )
            logger.info("Posted WIP comment on MR")
        except Exception as e:
            logger.warning(f"Could not post WIP comment: {e}")

    def _post_final_report(
        self,
        project_id: str,
        mr_iid: int,
        markdown: str,
    ) -> None:
        """Post the final analysis report as an MR comment."""
        try:
            self.gitlab_client.create_merge_request_note(
                project_id, mr_iid, markdown
            )
            logger.info("Posted final report on MR")
        except Exception as e:
            logger.warning(f"Could not post final report: {e}")
