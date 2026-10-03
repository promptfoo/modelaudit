"""Helpers for isolated Python import checks."""

import subprocess
import sys


def assert_scanners_absent_in_subprocess(code: str) -> None:
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, check=True, text=True)
    assert result.stdout.strip() == "False"
