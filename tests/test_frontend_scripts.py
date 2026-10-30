"""Validate inline JavaScript extracted from Jinja templates (when Node.js is installed)."""
from pathlib import Path
import re
import shutil
import subprocess

import pytest

TEMPLATES = list(Path(__file__).resolve().parents[1].joinpath("templates").glob("*.html"))


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p:p.name)
def test_inline_script_parses(template, tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    html = template.read_text(encoding="utf-8")
    scripts = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, flags=re.DOTALL | re.IGNORECASE)
    for index, script in enumerate(scripts):
        # Replace Jinja substitutions with valid JavaScript values, without executing templates.
        script = re.sub(r"\{\{.*?\}\}", "null", script, flags=re.DOTALL)
        js_file = tmp_path / f"{template.stem}-{index}.js"
        js_file.write_text(script, encoding="utf-8")
        check = subprocess.run([node,"--check",str(js_file)], capture_output=True, text=True)
        assert check.returncode == 0, f"{template.name}: {check.stderr}"
