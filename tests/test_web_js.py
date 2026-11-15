"""Run browser event regressions against the real app.js without a browser or network."""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_browser_event_regressions():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is needed to execute the browser event harness")
    result = subprocess.run([node, str(Path(__file__).with_name("web_events.cjs"))],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
