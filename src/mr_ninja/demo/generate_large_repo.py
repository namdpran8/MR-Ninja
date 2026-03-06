"""
demo/generate_large_repo.py

Generates a synthetic monorepo with 500+ files for demonstration purposes.

Creates realistic directory structures, file contents, and intentional
security vulnerabilities that Mr Ninja's analysis pipeline will detect.

Usage:
    python -m demo.generate_large_repo --output-dir ./demo/sample_repo --files 512
"""

from __future__ import annotations

import argparse
import os
import random
import string
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Service definitions (simulate a microservices monorepo)
# ---------------------------------------------------------------------------

SERVICES = [
    "auth", "users", "payments", "notifications", "orders",
    "products", "inventory", "analytics", "gateway", "admin",
    "search", "messaging", "billing", "shipping", "reports",
]

LANGUAGES = {
    "python": {
        "ext": ".py",
        "dirs": ["src", "utils", "models", "services", "handlers"],
        "test_dir": "tests",
    },
    "javascript": {
        "ext": ".js",
        "dirs": ["src", "lib", "middleware", "controllers", "routes"],
        "test_dir": "__tests__",
    },
    "typescript": {
        "ext": ".ts",
        "dirs": ["src", "lib", "types", "services", "api"],
        "test_dir": "tests",
    },
}


# ---------------------------------------------------------------------------
# File content templates
# ---------------------------------------------------------------------------

def python_service_file(service: str, module: str) -> str:
    """Generate a Python service module with realistic content."""
    return f'''"""
{service}/{module}.py

{service.title()} service — {module} module.
Part of the monorepo platform.
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, List

logger = logging.getLogger("{service}.{module}")


class {service.title()}{module.title()}Service:
    """Handles {module} operations for the {service} service."""

    def __init__(self, config: Dict = None):
        self.config = config or {{}}
        self.db_url = os.getenv("{service.upper()}_DB_URL", "localhost:5432")
        self._cache: Dict = {{}}
        logger.info(f"{service.title()} {module} service initialized")

    def process(self, data: Dict) -> Dict:
        """Process incoming {module} data."""
        if not data:
            raise ValueError("Data cannot be empty")

        result = {{
            "service": "{service}",
            "module": "{module}",
            "timestamp": datetime.utcnow().isoformat(),
            "processed": True,
            "items": len(data),
        }}

        logger.info(f"Processed {{len(data)}} items in {module}")
        return result

    def validate(self, payload: Dict) -> bool:
        """Validate the incoming payload."""
        required_fields = ["id", "type", "data"]
        for field in required_fields:
            if field not in payload:
                logger.warning(f"Missing required field: {{field}}")
                return False
        return True

    def get_by_id(self, item_id: str) -> Optional[Dict]:
        """Retrieve an item by ID."""
        if item_id in self._cache:
            return self._cache[item_id]
        # In production, this would query the database
        return None

    def list_all(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """List all items with pagination."""
        items = list(self._cache.values())
        return items[offset:offset + limit]

    def delete(self, item_id: str) -> bool:
        """Delete an item by ID."""
        if item_id in self._cache:
            del self._cache[item_id]
            logger.info(f"Deleted item {{item_id}}")
            return True
        return False
'''


def python_test_file(service: str, module: str) -> str:
    """Generate a Python test file."""
    return f'''"""
Tests for {service}/{module}.py
"""

import pytest
from unittest.mock import patch, MagicMock


class Test{service.title()}{module.title()}:
    """Test suite for {service.title()}{module.title()}Service."""

    def test_process_valid_data(self):
        """Test processing valid data."""
        data = {{"key": "value", "count": 42}}
        # Service would be imported and tested here
        assert data is not None

    def test_process_empty_data(self):
        """Test processing empty data raises error."""
        with pytest.raises(ValueError):
            raise ValueError("Data cannot be empty")

    def test_validate_payload(self):
        """Test payload validation."""
        valid = {{"id": "123", "type": "test", "data": {{}}}}
        assert all(k in valid for k in ["id", "type", "data"])

    def test_get_by_id_not_found(self):
        """Test retrieving non-existent item."""
        result = None  # Would call service.get_by_id("nonexistent")
        assert result is None

    def test_list_all_with_pagination(self):
        """Test list with pagination parameters."""
        items = list(range(10))
        page = items[5:8]
        assert len(page) == 3
'''


def javascript_file(service: str, module: str) -> str:
    """Generate a JavaScript module."""
    return f'''/**
 * {service}/{module}.js
 *
 * {service.title()} service — {module} module.
 */

const logger = require("./logger");

class {service.title()}{module.title()}Controller {{
  constructor(config = {{}}) {{
    this.config = config;
    this.items = new Map();
    logger.info(`{service.title()} {module} controller initialized`);
  }}

  async handleRequest(req, res) {{
    try {{
      const data = req.body;
      if (!data || !data.id) {{
        return res.status(400).json({{ error: "Missing required field: id" }});
      }}

      const result = await this.process(data);
      return res.json(result);
    }} catch (error) {{
      logger.error(`Error in {module}: ${{error.message}}`);
      return res.status(500).json({{ error: "Internal server error" }});
    }}
  }}

  async process(data) {{
    return {{
      service: "{service}",
      module: "{module}",
      timestamp: new Date().toISOString(),
      processed: true,
    }};
  }}

  getById(id) {{
    return this.items.get(id) || null;
  }}

  deleteById(id) {{
    return this.items.delete(id);
  }}
}}

module.exports = {{ {service.title()}{module.title()}Controller }};
'''


def config_file(service: str) -> str:
    """Generate a service configuration file."""
    return f'''# {service.title()} Service Configuration
service:
  name: {service}
  version: "1.0.0"
  port: {random.randint(3000, 9000)}

database:
  host: "${{DB_HOST}}"
  port: 5432
  name: {service}_db
  pool_size: 10

logging:
  level: info
  format: json

features:
  caching: true
  rate_limiting: true
  metrics: true
'''


def dockerfile_content(service: str) -> str:
    """Generate a Dockerfile."""
    return f'''FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE {random.randint(3000, 9000)}

CMD ["python", "-m", "{service}.main"]
'''


def requirements_file() -> str:
    """Generate a requirements.txt with some known-vulnerable versions."""
    return '''# Core dependencies
fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.0
sqlalchemy==2.0.23

# Utilities
requests==2.31.0
python-dotenv==1.0.0
redis==5.0.1
celery==5.3.6

# Testing
pytest==7.4.3
pytest-cov==4.1.0
'''


def env_file(service: str) -> str:
    """Generate a .env file with intentional security issues."""
    fake_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return f'''# {service.title()} Environment
DATABASE_URL=postgresql://admin:password123@db.internal:5432/{service}_db
REDIS_URL=redis://localhost:6379/0
API_KEY={fake_key}
SECRET_KEY=super-secret-key-dont-commit-this
JWT_SECRET=my-jwt-secret-{service}
AWS_ACCESS_KEY_ID=AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}
AWS_SECRET_ACCESS_KEY={''.join(random.choices(string.ascii_letters + string.digits, k=40))}
DEBUG=true
'''


def vulnerable_python_file(service: str) -> str:
    """Generate a Python file with intentional security vulnerabilities."""
    return f'''"""
{service}/auth_handler.py

Authentication handler with INTENTIONAL vulnerabilities for demo purposes.
DO NOT use in production.
"""

import os
import pickle
import subprocess

# Hardcoded credentials (VULN: hardcoded secrets)
DB_PASSWORD = "admin123!"
API_TOKEN = "sk-live-{''.join(random.choices(string.ascii_letters, k=24))}"


def authenticate_user(username, password):
    """Authenticate user against database."""
    # VULN: SQL injection via string concatenation
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    return query


def execute_command(user_input):
    """Execute a system command."""
    # VULN: Command injection via shell=True
    result = subprocess.call(user_input, shell=True)
    return result


def process_data(raw_data):
    """Process incoming data."""
    # VULN: Unsafe eval
    result = eval(raw_data)
    return result


def load_session(session_data):
    """Load user session."""
    # VULN: Unsafe deserialization
    return pickle.loads(session_data)


def render_template(user_content):
    """Render user content."""
    # VULN: XSS via innerHTML pattern
    html = f"<div id='content'></div><script>document.getElementById('content').innerHTML = '{{user_content}}';</script>"
    return html


def make_request(url):
    """Make external request."""
    # VULN: SSL verification disabled
    import requests
    response = requests.get(url, verify=False)
    return response.text
'''


def package_json(service: str) -> str:
    """Generate a package.json with version issues."""
    return f'''{{
  "name": "@monorepo/{service}",
  "version": "1.0.0",
  "description": "{service.title()} service",
  "main": "src/index.js",
  "scripts": {{
    "start": "node src/index.js",
    "test": "jest",
    "lint": "eslint src/"
  }},
  "dependencies": {{
    "express": "^4.18.2",
    "lodash": "*",
    "axios": ">=0.21.0",
    "moment": "^2.29.4",
    "jsonwebtoken": "^9.0.0"
  }},
  "devDependencies": {{
    "jest": "^29.7.0",
    "eslint": "^8.54.0"
  }}
}}
'''


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def generate_repo(output_dir: str, file_count: int = 512) -> list[str]:
    """Generate a synthetic monorepo with the specified number of files.

    Creates a realistic directory structure with:
    - Multiple services
    - Python, JavaScript, and TypeScript files
    - Config files, Dockerfiles, requirements.txt
    - Intentional security vulnerabilities
    - Test files

    Args:
        output_dir: Directory to create the repo in.
        file_count: Target number of files to generate.

    Returns:
        List of generated file paths.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    generated: list[str] = []
    files_per_service = max(1, file_count // len(SERVICES))

    for service in SERVICES:
        service_dir = out / service
        service_dir.mkdir(exist_ok=True)

        # Pick a language for this service
        lang = random.choice(list(LANGUAGES.keys()))
        lang_config = LANGUAGES[lang]

        # Create subdirectories
        for subdir in lang_config["dirs"]:
            (service_dir / subdir).mkdir(exist_ok=True)

        # Generate source files
        modules = [
            "handler", "service", "repository", "validator",
            "middleware", "config", "utils", "client",
            "processor", "scheduler", "cache", "metrics",
        ]

        for i, module in enumerate(modules[:files_per_service]):
            subdir = random.choice(lang_config["dirs"])
            ext = lang_config["ext"]
            filepath = service_dir / subdir / f"{module}{ext}"

            if lang == "python":
                content = python_service_file(service, module)
            elif lang == "javascript":
                content = javascript_file(service, module)
            else:
                content = javascript_file(service, module)  # TS similar

            filepath.write_text(content, encoding="utf-8")
            generated.append(str(filepath.relative_to(out)))

        # Generate test files
        test_dir = service_dir / lang_config["test_dir"]
        test_dir.mkdir(exist_ok=True)
        for module in modules[:3]:
            test_path = test_dir / f"test_{module}{lang_config['ext']}"
            if lang == "python":
                test_path.write_text(
                    python_test_file(service, module), encoding="utf-8"
                )
            else:
                test_path.write_text(
                    f"// Test file for {service}/{module}\n"
                    f"describe('{module}', () => {{\n"
                    f"  test('should work', () => {{\n"
                    f"    expect(true).toBe(true);\n"
                    f"  }});\n"
                    f"}});\n",
                    encoding="utf-8",
                )
            generated.append(str(test_path.relative_to(out)))

        # Config files
        config_path = service_dir / "config.yaml"
        config_path.write_text(config_file(service), encoding="utf-8")
        generated.append(str(config_path.relative_to(out)))

        # Dockerfile
        docker_path = service_dir / "Dockerfile"
        docker_path.write_text(dockerfile_content(service), encoding="utf-8")
        generated.append(str(docker_path.relative_to(out)))

        # Requirements / package.json
        if lang == "python":
            req_path = service_dir / "requirements.txt"
            req_path.write_text(requirements_file(), encoding="utf-8")
            generated.append(str(req_path.relative_to(out)))
        else:
            pkg_path = service_dir / "package.json"
            pkg_path.write_text(package_json(service), encoding="utf-8")
            generated.append(str(pkg_path.relative_to(out)))

        # Intentional vulnerable file (1 per service)
        vuln_path = service_dir / "auth_handler.py"
        vuln_path.write_text(
            vulnerable_python_file(service), encoding="utf-8"
        )
        generated.append(str(vuln_path.relative_to(out)))

        # .env file (intentional security issue)
        env_path = service_dir / ".env"
        env_path.write_text(env_file(service), encoding="utf-8")
        generated.append(str(env_path.relative_to(out)))

    # Root-level files
    root_readme = out / "README.md"
    root_readme.write_text(
        "# Monorepo Platform\n\n"
        "Multi-service platform with 15 microservices.\n\n"
        f"Total services: {len(SERVICES)}\n",
        encoding="utf-8",
    )
    generated.append("README.md")

    root_ci = out / ".gitlab-ci.yml"
    root_ci.write_text(
        "stages:\n  - test\n  - build\n  - deploy\n\n"
        "test:\n  script:\n    - pytest\n",
        encoding="utf-8",
    )
    generated.append(".gitlab-ci.yml")

    print(f"Generated {len(generated)} files in {output_dir}")
    return generated


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a synthetic monorepo for Mr Ninja demo"
    )
    parser.add_argument(
        "--output-dir",
        default="./demo/sample_repo",
        help="Directory to generate the repo in",
    )
    parser.add_argument(
        "--files",
        type=int,
        default=512,
        help="Target number of files to generate",
    )
    args = parser.parse_args()

    generate_repo(args.output_dir, args.files)
