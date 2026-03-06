# Contributing to Mr Ninja

## Development Setup

```bash
git clone https://gitlab.com/your-group/mr-ninja.git
cd mr-ninja
pip install -e ".[dev]"
```

Run the test suite to verify your setup:

```bash
pytest
```

## Project Layout

Source code lives under `src/mr_ninja/` (the [src layout](https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/)). Tests are in `tests/` at the repo root.

```
src/mr_ninja/          # Installable package
tests/                 # Test suite (imports from mr_ninja.*)
pyproject.toml         # All project config + tool settings
```

## Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=mr_ninja --cov-report=term-missing

# Specific test file
pytest tests/test_chunking.py -v
```

## Linting & Type Checking

```bash
# Lint with ruff
ruff check src/

# Auto-fix lint issues
ruff check src/ --fix

# Type check
mypy src/mr_ninja/core/ --ignore-missing-imports
```

---

## Publishing to PyPI

### 1. Bump the version

Edit `src/mr_ninja/__init__.py`:

```python
__version__ = "1.1.0"
```

Also update the `version` field in `pyproject.toml`.

### 2. Build the distribution

```bash
python -m build
```

This creates `dist/mr_ninja-1.1.0.tar.gz` and `dist/mr_ninja-1.1.0-py3-none-any.whl`.

### 3. Upload to PyPI

```bash
# Test PyPI first
twine upload --repository testpypi dist/*

# Production PyPI
twine upload dist/*
```

You need a PyPI account and API token. Set the token in `~/.pypirc` or pass it via `--username __token__ --password pypi-xxx`.

### 4. Verify

```bash
pip install mr-ninja==1.1.0
mr-ninja --version
```

---

## Publishing to GitLab/GitHub Releases

### GitLab

1. Tag the commit:

```bash
git tag -a v1.1.0 -m "Release v1.1.0"
git push origin v1.1.0
```

2. The CI pipeline includes a `build:pypi` job that runs on version tags (`v*.*.*`) and produces the dist artifacts.

3. Create a release in GitLab UI (Repository > Releases) or via API:

```bash
# Create release via CLI
glab release create v1.1.0 \
  --title "v1.1.0" \
  --notes "Release notes here" \
  dist/mr_ninja-1.1.0.tar.gz \
  dist/mr_ninja-1.1.0-py3-none-any.whl
```

### GitHub

```bash
gh release create v1.1.0 \
  --title "v1.1.0" \
  --notes "Release notes here" \
  dist/mr_ninja-1.1.0.tar.gz \
  dist/mr_ninja-1.1.0-py3-none-any.whl
```

---

## Docker Release

### Build and push to a registry

```bash
# Build
docker build -t mr-ninja:1.1.0 .
docker tag mr-ninja:1.1.0 mr-ninja:latest

# Push to GitLab Container Registry
docker tag mr-ninja:1.1.0 registry.gitlab.com/your-group/mr-ninja:1.1.0
docker tag mr-ninja:1.1.0 registry.gitlab.com/your-group/mr-ninja:latest
docker push registry.gitlab.com/your-group/mr-ninja:1.1.0
docker push registry.gitlab.com/your-group/mr-ninja:latest

# Push to Docker Hub
docker tag mr-ninja:1.1.0 youruser/mr-ninja:1.1.0
docker push youruser/mr-ninja:1.1.0
```

### Multi-arch build (for production)

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t registry.gitlab.com/your-group/mr-ninja:1.1.0 \
  --push .
```

The CI pipeline automatically builds and pushes Docker images on merges to `main`.

---

## Release Checklist

1. Update version in `src/mr_ninja/__init__.py` and `pyproject.toml`
2. Update CHANGELOG.md
3. Run full test suite: `pytest`
4. Build: `python -m build`
5. Test install: `pip install dist/mr_ninja-*.whl && mr-ninja --version`
6. Tag: `git tag -a v1.1.0 -m "v1.1.0" && git push origin v1.1.0`
7. Upload to PyPI: `twine upload dist/*`
8. Create GitLab/GitHub release with artifacts
9. Docker image is built automatically by CI

---

## Code Style

- Line length: 120 characters
- Formatter/linter: ruff
- Type hints: use them for public API functions
- Docstrings: Google style, required for classes and public methods
- Imports: absolute (`from mr_ninja.core.models import ...`), sorted by ruff/isort

## Adding a New Specialist Agent

1. Add detection patterns to `src/mr_ninja/agents/chunk_processor.py`
2. Add the agent type to `AgentType` enum in `src/mr_ninja/core/models.py`
3. Update the dispatch logic in `ChunkProcessor.process_chunk()`
4. Add tests in `tests/test_orchestrator.py`
