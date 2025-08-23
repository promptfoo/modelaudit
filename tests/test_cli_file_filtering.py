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

        # Should scan model.pkl and README.txt (for security scanning)
        assert output["files_scanned"] == 2


def test_cli_no_skip_files():
    """Test --no-skip-files option."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "README.txt").write_text("documentation")
        (Path(tmp_dir) / "model.pkl").write_bytes(b"model data")
        (Path(tmp_dir) / "script.py").write_text("print('hello')")

        # Run scan with --no-skip-files
        result = runner.invoke(cli, ["scan", "--format", "json", "--no-skip-files", tmp_dir])

        assert result.exit_code in [0, 1]
        output = json.loads(result.output)

        # Should scan all files
        assert output["files_scanned"] == 3


def test_cli_explicit_skip_files():
    """Test explicit --skip-files option."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "data.log").write_text("log data")
        (Path(tmp_dir) / "model.h5").write_bytes(b"model data")

        # Run scan with explicit --skip-files
        result = runner.invoke(cli, ["scan", "--format", "json", "--skip-files", tmp_dir])

        assert result.exit_code in [0, 1]
        output = json.loads(result.output)

        # Should only scan model.h5
        assert output["files_scanned"] == 1


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

        # With skip files enabled, should only scan 2 files (model.pkl + README.md)
        # We didn't pass --format json, so output should be text
        assert "Files: 2" in result.output
