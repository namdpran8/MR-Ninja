"""
mr_ninja.cli

Command-line interface for Mr Ninja.

Usage:
    mr-ninja analyze <mr-url>          Analyze a GitLab merge request
    mr-ninja analyze --project <id> --mr <iid>
    mr-ninja demo [--files N] [--output FILE]
    mr-ninja serve [--host HOST] [--port PORT]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from mr_ninja import __version__


def _setup_logging(verbose: bool = False) -> None:
    """Configure logging for the CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# -----------------------------------------------------------------------
# Subcommand handlers
# -----------------------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyze a GitLab merge request."""
    from mr_ninja.agents.orchestrator import Orchestrator

    _setup_logging(args.verbose)

    gitlab_token = args.token or os.getenv("GITLAB_TOKEN", "")
    gitlab_url = args.gitlab_url or os.getenv("GITLAB_URL", "https://gitlab.com")

    if not gitlab_token:
        print("Error: GitLab token is required.")
        print("  Set GITLAB_TOKEN environment variable or use --token.")
        return 1

    orchestrator = Orchestrator(
        gitlab_url=gitlab_url,
        gitlab_token=gitlab_token,
        max_chunk_tokens=args.max_tokens,
        post_comments=args.post_comment,
    )

    if args.mr_url:
        report = orchestrator.analyze_mr_from_url(args.mr_url)
    elif args.project and args.mr:
        report = orchestrator.analyze_mr(args.project, args.mr)
    else:
        print("Error: provide an MR URL or both --project and --mr.")
        return 1

    # Render and print report
    from mr_ninja.agents.chunk_planner import ChunkPlanner

    planner = ChunkPlanner()
    plan = planner.plan_from_files(
        [],  # not needed for rendering
        mr_id=report.mr_id,
        mr_title=report.mr_title,
    )
    markdown = orchestrator.aggregator.render_markdown(
        plan, report.processing_time_seconds
    )
    print(markdown)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"\nReport saved to: {args.output}")

    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Run a demo analysis with synthetic data."""
    from mr_ninja.demo.simulate_large_mr import run_demo

    _setup_logging(args.verbose)
    run_demo(file_count=args.files, output_file=args.output or "")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the FastAPI server."""
    _setup_logging(args.verbose)

    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is required to run the server.")
        print("  pip install mr-ninja")
        return 1

    host = args.host or os.getenv("MR_NINJA_HOST", "0.0.0.0")
    port = args.port or int(os.getenv("MR_NINJA_PORT", "8000"))

    print(f"Starting Mr Ninja server on {host}:{port}")
    print(f"  Docs:   http://{host}:{port}/docs")
    print(f"  Health: http://{host}:{port}/health")

    uvicorn.run(
        "mr_ninja.server:app",
        host=host,
        port=port,
        reload=args.reload,
        log_level="debug" if args.verbose else "info",
    )
    return 0


# -----------------------------------------------------------------------
# Argument parser
# -----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mr-ninja",
        description="Mr Ninja -- Large Context Orchestrator for GitLab Duo",
        epilog="https://gitlab.com/your-group/mr-ninja",
    )
    parser.add_argument(
        "--version", action="version", version=f"mr-ninja {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- analyze ---------------------------------------------------------
    p_analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a GitLab merge request",
        description="Fetch an MR, chunk it, run specialist agents, and report findings.",
    )
    p_analyze.add_argument(
        "mr_url",
        nargs="?",
        default="",
        help="Full GitLab MR URL (e.g. https://gitlab.com/group/project/-/merge_requests/42)",
    )
    p_analyze.add_argument(
        "--project", default="", help="GitLab project ID or path"
    )
    p_analyze.add_argument(
        "--mr", type=int, default=0, help="Merge request IID"
    )
    p_analyze.add_argument(
        "--token", default="", help="GitLab private token (or set GITLAB_TOKEN)"
    )
    p_analyze.add_argument(
        "--gitlab-url", default="", help="GitLab instance URL (default: https://gitlab.com)"
    )
    p_analyze.add_argument(
        "--max-tokens",
        type=int,
        default=70_000,
        help="Target tokens per chunk (default: 70000)",
    )
    p_analyze.add_argument(
        "--post-comment",
        action="store_true",
        default=False,
        help="Post the report as an MR comment",
    )
    p_analyze.add_argument(
        "--output", "-o", default="", help="Save report to file"
    )
    p_analyze.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )

    # -- demo ------------------------------------------------------------
    p_demo = subparsers.add_parser(
        "demo",
        help="Run a demo analysis with synthetic data",
        description="Generate synthetic files and run the full analysis pipeline.",
    )
    p_demo.add_argument(
        "--files",
        type=int,
        default=512,
        help="Number of files to simulate (default: 512)",
    )
    p_demo.add_argument(
        "--output", "-o", default="", help="Save report to file"
    )
    p_demo.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )

    # -- serve -----------------------------------------------------------
    p_serve = subparsers.add_parser(
        "serve",
        help="Start the REST API server",
        description="Launch the FastAPI server for HTTP-based MR analysis.",
    )
    p_serve.add_argument(
        "--host", default="", help="Bind host (default: 0.0.0.0)"
    )
    p_serve.add_argument(
        "--port", type=int, default=0, help="Bind port (default: 8000)"
    )
    p_serve.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development"
    )
    p_serve.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    handlers = {
        "analyze": cmd_analyze,
        "demo": cmd_demo,
        "serve": cmd_serve,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if os.getenv("MR_NINJA_DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
