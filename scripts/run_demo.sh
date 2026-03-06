#!/usr/bin/env bash
# scripts/run_demo.sh
#
# Run the Mr Ninja demo simulation.
# Generates a synthetic 512-file MR and analyzes it end-to-end.
#
# Usage:
#   ./scripts/run_demo.sh
#   ./scripts/run_demo.sh --files 1000
#   ./scripts/run_demo.sh --output report.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=============================================="
echo "  MR NINJA — Demo Runner"
echo "  Large Context Orchestrator for GitLab Duo"
echo "=============================================="
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 is not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python: $PYTHON_VERSION"

# Install dependencies if needed
if ! python3 -c "import pydantic" 2>/dev/null; then
    echo ""
    echo "Installing dependencies..."
    pip install -r "$PROJECT_DIR/requirements.txt" --quiet
fi

echo ""

# Parse arguments
FILES=${1:-512}
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --files)
            FILES="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        *)
            FILES="$1"
            shift
            ;;
    esac
done

# Run the demo
cd "$PROJECT_DIR"

if [ -n "$OUTPUT" ]; then
    python3 -m demo.simulate_large_mr --files "$FILES" --output "$OUTPUT"
else
    python3 -m demo.simulate_large_mr --files "$FILES"
fi

echo ""
echo "Demo complete."
