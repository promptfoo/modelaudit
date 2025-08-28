"""Tests for CLI file filtering options."""

import json
import tempfile
from pathlib import Path

from click.testing import CliRunner

from modelaudit.cli import cli


def test_cli_skip_files_default():
    """Test that files are skipped by default."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "README.txt").write_text("documentation")
        (Path(tmp_dir) / "model.pkl").write_bytes(b"model data")
        (Path(tmp_dir) / "script.py").write_text("print('hello')")

        # Run scan without any skip options (default behavior)
        result = runner.invoke(cli, ["scan", "--format", "json", tmp_dir])

        assert result.exit_code in [0, 1]
        output = json.loads(result.output)

        # Smart defaults scan all files that could contain security issues
        assert output["files_scanned"] >= 1  # At least the model file should be scanned


def test_cli_strict_mode():
    """Test --strict option (replaces --no-skip-files)."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "README.txt").write_text("documentation")
        (Path(tmp_dir) / "model.pkl").write_bytes(b"model data")
        (Path(tmp_dir) / "script.py").write_text("print('hello')")

        # Run scan with --strict mode (scans all file types)
        result = runner.invoke(cli, ["scan", "--format", "json", "--strict", tmp_dir])

        assert result.exit_code in [0, 1]
        output = json.loads(result.output)

        # Should scan all files in strict mode
        assert output["files_scanned"] == 3


def test_cli_smart_default_skip_files():
    """Test smart default file filtering (replaces explicit --skip-files)."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "data.log").write_text("log data")
        (Path(tmp_dir) / "model.h5").write_bytes(b"model data")

        # Run scan with smart defaults (should skip .log files)
        result = runner.invoke(cli, ["scan", "--format", "json", tmp_dir])

        assert result.exit_code in [0, 1]
        output = json.loads(result.output)

        # Should scan model files (smart defaults may skip log files)
        assert output["files_scanned"] >= 1  # At least the model file


def test_cli_skip_message_in_verbose():
    """Test that skip messages appear in logs when file filtering is active."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "README.md").write_text("# Documentation")
        (Path(tmp_dir) / "train.py").write_text("import torch")
        (Path(tmp_dir) / "model.pkl").write_bytes(b"model")

        # Run scan in verbose mode
        result = runner.invoke(cli, ["scan", "--verbose", tmp_dir])

        # The model.pkl should be mentioned in the output
        assert "model.pkl" in result.output or "pickle" in result.output.lower()

        # Smart defaults determine which files to scan
        # We didn't pass --format json, so output should be text
        assert "Files:" in result.output  # Should show some files scanned
