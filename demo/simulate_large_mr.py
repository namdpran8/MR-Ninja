"""
demo/simulate_large_mr.py

Simulates a large merge request with 500+ files for demo purposes.

Instead of fetching from GitLab, this creates synthetic FileEntry objects
with realistic diff content — including intentional security vulnerabilities,
code quality issues, and dependency risks.

Usage:
    python -m demo.simulate_large_mr
    python -m demo.simulate_large_mr --files 1000 --output report.md
"""

from __future__ import annotations

import argparse
import os
import random
import string
import sys
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import FileEntry, FilePriority


# ---------------------------------------------------------------------------
# Service/directory structure for realistic diff generation
# ---------------------------------------------------------------------------

SERVICES = [
    "auth", "users", "payments", "notifications", "orders",
    "products", "inventory", "analytics", "gateway", "admin",
    "search", "messaging", "billing", "shipping", "reports",
]

SUBDIRS = ["src", "lib", "utils", "models", "services", "handlers", "api"]

MODULES = [
    "handler", "service", "repository", "validator", "middleware",
    "config", "utils", "client", "processor", "scheduler",
    "cache", "metrics", "router", "controller", "manager",
]


# ---------------------------------------------------------------------------
# Diff content generators with intentional issues
# ---------------------------------------------------------------------------

def _random_python_diff(service: str, module: str, include_vulns: bool = False) -> str:
    """Generate a realistic Python diff chunk."""
    base = f"""@@ -1,20 +1,35 @@
+import os
+import json
+import logging
+from typing import Optional, Dict
+
+logger = logging.getLogger("{service}.{module}")
+
+
+class {service.title()}{module.title()}:
+    \"\"\"Handles {module} operations for {service} service.\"\"\"
+
+    def __init__(self, config: Dict = None):
+        self.config = config or {{}}
+        self._data: Dict = {{}}
+
+    def process(self, data: Dict) -> Dict:
+        if not data:
+            raise ValueError("Empty data")
+        result = {{"service": "{service}", "processed": True}}
+        logger.info(f"Processed {{len(data)}} items")
+        return result
+
+    def get(self, item_id: str) -> Optional[Dict]:
+        return self._data.get(item_id)
"""

    if include_vulns:
        vulns = random.choice([
            f'\n+    API_KEY = "sk-live-{"".join(random.choices(string.ascii_letters, k=20))}"\n',
            '\n+    def run_cmd(self, cmd):\n+        result = eval(cmd)\n+        return result\n',
            '\n+    def query(self, user_input):\n+        sql = "SELECT * FROM users WHERE name=\'" + user_input + "\'"\n+        return sql\n',
            '\n+    def execute(self, cmd):\n+        import subprocess\n+        subprocess.call(cmd, shell=True)\n',
            '\n+    password = "admin123!"\n+    secret_key = "super-secret-key"\n',
            '\n+    def load(self, data):\n+        import pickle\n+        return pickle.loads(data)\n',
            '\n+    def fetch(self, url):\n+        import requests\n+        return requests.get(url, verify=False)\n',
        ])
        base += vulns

    return base


def _random_js_diff(service: str, module: str, include_vulns: bool = False) -> str:
    """Generate a realistic JavaScript diff chunk."""
    base = f"""@@ -1,15 +1,30 @@
+const express = require('express');
+const logger = require('./logger');
+
+class {service.title()}{module.title()}Controller {{
+  constructor(config = {{}}) {{
+    this.config = config;
+    this.items = new Map();
+  }}
+
+  async handleRequest(req, res) {{
+    try {{
+      const data = req.body;
+      const result = await this.process(data);
+      return res.json(result);
+    }} catch (error) {{
+      logger.error(`Error: ${{error.message}}`);
+      return res.status(500).json({{ error: 'Internal error' }});
+    }}
+  }}
+}}
+
+module.exports = {{ {service.title()}{module.title()}Controller }};
"""

    if include_vulns:
        vulns = random.choice([
            '\n+  // TODO: fix security issue with authentication\n+  const apiKey = "hardcoded-api-key-12345";\n',
            '\n+  element.innerHTML = userInput;\n',
            '\n+  dangerouslySetInnerHTML={{__html: userContent}}\n',
        ])
        base += vulns

    return base


def _config_diff(service: str) -> str:
    """Generate a config file diff."""
    return f"""@@ -1,10 +1,15 @@
+# {service.title()} Service Configuration
+service:
+  name: {service}
+  version: "2.0.0"
+  port: {random.randint(3000, 9000)}
+
+database:
+  host: "${{DB_HOST}}"
+  port: 5432
+  name: {service}_db
+
+logging:
+  level: info
"""


def _env_diff(service: str) -> str:
    """Generate an .env file diff with secrets."""
    key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return f"""@@ -0,0 +1,8 @@
+DATABASE_URL=postgresql://admin:password123@db:5432/{service}
+API_KEY={key}
+SECRET_KEY=super-secret-key-for-{service}
+JWT_SECRET=jwt-secret-{service}
+AWS_ACCESS_KEY_ID=AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}
+DEBUG=true
"""


def _test_diff(service: str, module: str) -> str:
    """Generate a test file diff."""
    return f"""@@ -0,0 +1,20 @@
+import pytest
+
+class Test{service.title()}{module.title()}:
+    def test_process(self):
+        data = {{"key": "value"}}
+        assert data is not None
+
+    def test_empty_input(self):
+        with pytest.raises(ValueError):
+            raise ValueError("empty")
+
+    def test_get_by_id(self):
+        result = None
+        assert result is None
+
+    # TODO: add more tests
+    def test_placeholder(self):
+        print("running placeholder test")
+        pass
"""


def _dockerfile_diff(service: str) -> str:
    """Generate a Dockerfile diff."""
    return f"""@@ -0,0 +1,10 @@
+FROM python:3.11-slim
+
+WORKDIR /app
+COPY requirements.txt .
+RUN pip install --no-cache-dir -r requirements.txt
+COPY . .
+
+EXPOSE {random.randint(3000, 9000)}
+CMD ["python", "-m", "{service}.main"]
"""


def _package_json_diff(service: str) -> str:
    """Generate a package.json diff with dependency issues."""
    return f"""@@ -0,0 +1,15 @@
+{{
+  "name": "@monorepo/{service}",
+  "version": "1.0.0",
+  "dependencies": {{
+    "express": "^4.18.2",
+    "lodash": "*",
+    "axios": ">=0.21.0",
+    "moment": "^2.29.4"
+  }},
+  "devDependencies": {{
+    "jest": "^29.7.0"
+  }}
+}}
"""


# ---------------------------------------------------------------------------
# File generator
# ---------------------------------------------------------------------------

def generate_demo_files(file_count: int = 512) -> list[FileEntry]:
    """Generate a list of synthetic FileEntry objects simulating a large MR.

    Creates realistic files across multiple services with:
    - Source files (Python, JavaScript)
    - Config files (YAML)
    - Security-critical files (.env, Dockerfile, requirements.txt)
    - Test files
    - Package manifests
    - Intentional vulnerabilities sprinkled throughout

    Args:
        file_count: Target number of files to generate.

    Returns:
        List of FileEntry objects ready for the chunk planner.
    """
    files: list[FileEntry] = []
    files_per_service = max(1, file_count // len(SERVICES))

    for service in SERVICES:
        # Source files
        lang = random.choice(["python", "javascript"])
        ext = ".py" if lang == "python" else ".js"

        for i, module in enumerate(MODULES[:files_per_service]):
            subdir = random.choice(SUBDIRS)
            path = f"{service}/{subdir}/{module}{ext}"

            # ~20% of files get intentional vulnerabilities
            include_vulns = random.random() < 0.20

            if lang == "python":
                diff = _random_python_diff(service, module, include_vulns)
            else:
                diff = _random_js_diff(service, module, include_vulns)

            additions = diff.count("\n+")
            deletions = diff.count("\n-")
            tokens = max(100, len(diff) // 4)

            files.append(FileEntry(
                path=path,
                additions=additions,
                deletions=deletions,
                estimated_tokens=tokens,
                diff_content=diff,
                language=lang,
            ))

        # .env file (security critical)
        env_diff = _env_diff(service)
        files.append(FileEntry(
            path=f"{service}/.env",
            additions=env_diff.count("\n+"),
            deletions=0,
            estimated_tokens=max(100, len(env_diff) // 4),
            diff_content=env_diff,
        ))

        # Dockerfile
        docker_diff = _dockerfile_diff(service)
        files.append(FileEntry(
            path=f"{service}/Dockerfile",
            additions=docker_diff.count("\n+"),
            deletions=0,
            estimated_tokens=max(100, len(docker_diff) // 4),
            diff_content=docker_diff,
        ))

        # Config file
        cfg_diff = _config_diff(service)
        files.append(FileEntry(
            path=f"{service}/config.yaml",
            additions=cfg_diff.count("\n+"),
            deletions=0,
            estimated_tokens=max(100, len(cfg_diff) // 4),
            diff_content=cfg_diff,
        ))

        # Requirements / package.json
        if lang == "python":
            req_diff = "+fastapi==0.104.1\n+uvicorn==0.24.0\n+requests==2.31.0\n"
            files.append(FileEntry(
                path=f"{service}/requirements.txt",
                additions=3,
                deletions=0,
                estimated_tokens=100,
                diff_content=req_diff,
            ))
        else:
            pkg_diff = _package_json_diff(service)
            files.append(FileEntry(
                path=f"{service}/package.json",
                additions=pkg_diff.count("\n+"),
                deletions=0,
                estimated_tokens=max(100, len(pkg_diff) // 4),
                diff_content=pkg_diff,
            ))

        # Test files
        for module in MODULES[:3]:
            test_diff = _test_diff(service, module)
            files.append(FileEntry(
                path=f"{service}/tests/test_{module}.py",
                additions=test_diff.count("\n+"),
                deletions=0,
                estimated_tokens=max(100, len(test_diff) // 4),
                diff_content=test_diff,
            ))

    # Root-level CI config
    ci_diff = (
        "@@ -0,0 +1,5 @@\n"
        "+stages:\n+  - test\n+  - build\n+  - deploy\n"
    )
    files.append(FileEntry(
        path=".gitlab-ci.yml",
        additions=4,
        deletions=0,
        estimated_tokens=100,
        diff_content=ci_diff,
    ))

    print(f"Generated {len(files)} synthetic file entries for demo")
    return files


# ---------------------------------------------------------------------------
# Main demo runner
# ---------------------------------------------------------------------------

def run_demo(file_count: int = 512, output_file: str = "") -> None:
    """Run the full Mr Ninja demo pipeline.

    1. Generate synthetic files
    2. Run the orchestrator
    3. Print (and optionally save) the final report

    Args:
        file_count: Number of files to simulate.
        output_file: Optional path to save the Markdown report.
    """
    from agents.orchestrator import Orchestrator

    print("=" * 70)
    print("  MR NINJA — DEMO MODE")
    print("  Large Context Orchestrator for GitLab Duo")
    print("=" * 70)
    print()

    # Step 1: Generate files
    print(f"[1/3] Generating {file_count} synthetic files...")
    files = generate_demo_files(file_count)
    print(f"       Generated {len(files)} files across {len(SERVICES)} services")
    print()

    # Step 2: Run analysis
    print("[2/3] Running Mr Ninja analysis pipeline...")
    print()

    orchestrator = Orchestrator(
        post_comments=False,
        use_duo_agents=False,
    )

    report = orchestrator.analyze_files(
        files=files,
        mr_id=f"demo-{file_count}",
        mr_title=f"Demo: Large Monorepo MR ({file_count} files)",
    )

    # Step 3: Generate report
    print()
    print("[3/3] Generating final report...")

    from agents.chunk_planner import ChunkPlanner
    planner = ChunkPlanner()
    plan = planner.plan_from_files(
        files, f"demo-{file_count}",
        f"Demo: Large Monorepo MR ({file_count} files)",
    )

    markdown = orchestrator.aggregator.render_markdown(
        plan, report.processing_time_seconds
    )

    print()
    print("=" * 70)
    print("  FINAL REPORT")
    print("=" * 70)
    print()
    print(markdown)

    # Save to file if requested
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"\nReport saved to: {output_file}")

    # Print summary
    print()
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  Files scanned:      {report.total_files_scanned}")
    print(f"  Chunks processed:   {report.chunks_processed}")
    print(f"  Total findings:     {len(report.findings)}")
    print(f"  Critical:           {report.critical_count}")
    print(f"  High:               {report.high_count}")
    print(f"  Medium:             {report.medium_count}")
    print(f"  Overall risk:       {report.overall_risk.value}")
    print(f"  Processing time:    {report.processing_time_seconds:.2f}s")
    print("=" * 70)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mr Ninja — Simulate and analyze a large MR"
    )
    parser.add_argument(
        "--files",
        type=int,
        default=512,
        help="Number of files to simulate (default: 512)",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Save the final report to a file (Markdown)",
    )
    args = parser.parse_args()

    run_demo(file_count=args.files, output_file=args.output)
