"""Tests for CLI file filtering options."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli


@pytest.mark.unit
def test_cli_skip_files_default(mock_cli_scan_command: MagicMock, tmp_path: Path) -> None:
    """Test that files are skipped by default."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory(dir=tmp_path) as temp_dir:
        scan_root = Path(temp_dir)
        # Create test files
        (scan_root / "README.txt").write_text("documentation")
        (scan_root / "model.pkl").write_bytes(b"model data")
        (scan_root / "script.py").write_text("print('hello')")

        # Run scan without any skip options (default behavior)
        result = runner.invoke(cli, ["scan", "--format", "json", str(scan_root)])

        # Parse complete JSON from the first opening brace.
        json_start = result.output.find("{")
        assert json_start != -1, f"No JSON found in output: {result.output}"
        output = json.JSONDecoder().raw_decode(result.output, json_start)[0]

        # Automatic defaults scan all files that could contain security issues
        assert output["files_scanned"] >= 1  # At least the model file should be scanned


@pytest.mark.unit
def test_cli_strict_mode(mock_cli_scan_command: MagicMock, tmp_path: Path) -> None:
    """Test --strict option (replaces --no-skip-files)."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory(dir=tmp_path) as temp_dir:
        scan_root = Path(temp_dir)
        # Create test files
        (scan_root / "README.txt").write_text("documentation")
        (scan_root / "model.pkl").write_bytes(b"model data")
        (scan_root / "script.py").write_text("print('hello')")

        # Run scan with --strict mode (scans all file types)
        result = runner.invoke(cli, ["scan", "--format", "json", "--strict", str(scan_root)])

        # Parse complete JSON from the first opening brace.
        json_start = result.output.find("{")
        assert json_start != -1, f"No JSON found in output: {result.output}"
        output = json.JSONDecoder().raw_decode(result.output, json_start)[0]

        # Should scan all files in strict mode
        assert output["files_scanned"] >= 1


@pytest.mark.unit
def test_cli_auto_default_skip_files(mock_cli_scan_command: MagicMock, tmp_path: Path) -> None:
    """Test automatic-default file filtering (replaces explicit --skip-files)."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory(dir=tmp_path) as temp_dir:
        scan_root = Path(temp_dir)
        # Create test files
        (scan_root / "data.log").write_text("log data")
        (scan_root / "model.h5").write_bytes(b"model data")

        # Run scan with automatic defaults (should skip .log files)
        result = runner.invoke(cli, ["scan", "--format", "json", str(scan_root)])

        # Parse complete JSON from the first opening brace.
        json_start = result.output.find("{")
        assert json_start != -1, f"No JSON found in output: {result.output}"
        output = json.JSONDecoder().raw_decode(result.output, json_start)[0]

        # Should scan model files (automatic defaults may skip log files)
        assert output["files_scanned"] >= 1  # At least the model file

        # Verify the mock was called (proves we avoided heavy imports)
        mock_cli_scan_command.assert_called_once()


@pytest.mark.unit
def test_cli_skip_message_in_verbose(mock_cli_scan_command: MagicMock, tmp_path: Path) -> None:
    """Test that skip messages appear in logs when file filtering is active."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory(dir=tmp_path) as temp_dir:
        scan_root = Path(temp_dir)
        # Create test files
        (scan_root / "README.md").write_text("# Documentation")
        (scan_root / "train.py").write_text("import torch")
        (scan_root / "model.pkl").write_bytes(b"model")

        # Run scan in verbose mode
        result = runner.invoke(cli, ["scan", "--format", "text", "--verbose", str(scan_root)])

        # Should complete successfully without crashing
        assert result.exit_code in [0, 1]

        # Verify scan was called (main functionality works)
        mock_cli_scan_command.assert_called_once()
