#!/bin/bash
# Preview the Mr Ninja website locally

echo "🥷 Mr Ninja Website Preview"
echo "=========================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "❌ Python is not installed. Please install Python 3 to run this script."
    exit 1
fi

# Determine Python command
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
else
    PYTHON_CMD=python
fi

# Navigate to public directory
cd "$(dirname "$0")/public" || exit 1

# Start simple HTTP server
PORT=8000
echo "🚀 Starting local server on http://localhost:$PORT"
echo "📂 Serving files from: $(pwd)"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Try to open browser (platform-specific)
sleep 1
if command -v xdg-open &> /dev/null; then
    xdg-open "http://localhost:$PORT" 2>/dev/null &
elif command -v open &> /dev/null; then
    open "http://localhost:$PORT" 2>/dev/null &
fi

# Start server
$PYTHON_CMD -m http.server $PORT
