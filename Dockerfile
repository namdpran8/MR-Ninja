FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (better layer caching)
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir .

# Expose the FastAPI service port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run the FastAPI service via the installed CLI
CMD ["mr-ninja", "serve", "--host", "0.0.0.0", "--port", "8000"]
