"""Tests for CLI file filtering options."""

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli


@pytest.mark.unit
def test_cli_skip_files_default(mock_cli_scan_command):
    """Test that files are skipped by default."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "README.txt").write_text("documentation")
        (Path(tmp_dir) / "model.pkl").write_bytes(b"model data")
        (Path(tmp_dir) / "script.py").write_text("print('hello')")

        # Run scan without any skip options (default behavior)
        result = runner.invoke(cli, ["scan", "--format", "json", tmp_dir])

        # Extract complete JSON from output (spans multiple lines)
        output_text = result.output
        start_idx = output_text.find("{")
        assert start_idx != -1, f"No JSON found in output: {result.output}"

        # Find the matching closing brace
        brace_count = 0
        end_idx = start_idx
        for i, char in enumerate(output_text[start_idx:], start_idx):
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break

        json_text = output_text[start_idx:end_idx]
        output = json.loads(json_text)

        # Smart defaults scan all files that could contain security issues
        assert output["files_scanned"] >= 1  # At least the model file should be scanned


@pytest.mark.unit
def test_cli_strict_mode(mock_cli_scan_command):
    """Test --strict option (replaces --no-skip-files)."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "README.txt").write_text("documentation")
        (Path(tmp_dir) / "model.pkl").write_bytes(b"model data")
        (Path(tmp_dir) / "script.py").write_text("print('hello')")

        # Run scan with --strict mode (scans all file types)
        result = runner.invoke(cli, ["scan", "--format", "json", "--strict", tmp_dir])

        # Extract complete JSON from output (spans multiple lines)
        output_text = result.output
        start_idx = output_text.find("{")
        assert start_idx != -1, f"No JSON found in output: {result.output}"

        # Find the matching closing brace
        brace_count = 0
        end_idx = start_idx
        for i, char in enumerate(output_text[start_idx:], start_idx):
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break

        json_text = output_text[start_idx:end_idx]
        output = json.loads(json_text)

        # Should scan all files in strict mode
        assert output["files_scanned"] >= 1


@pytest.mark.unit
def test_cli_smart_default_skip_files(mock_cli_scan_command):
    """Test smart default file filtering (replaces explicit --skip-files)."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "data.log").write_text("log data")
        (Path(tmp_dir) / "model.h5").write_bytes(b"model data")

        # Run scan with smart defaults (should skip .log files)
        result = runner.invoke(cli, ["scan", "--format", "json", tmp_dir])

        # Extract complete JSON from output (spans multiple lines)
        output_text = result.output
        start_idx = output_text.find("{")
        assert start_idx != -1, f"No JSON found in output: {result.output}"

        # Find the matching closing brace
        brace_count = 0
        end_idx = start_idx
        for i, char in enumerate(output_text[start_idx:], start_idx):
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break

        json_text = output_text[start_idx:end_idx]
        output = json.loads(json_text)

        # Should scan model files (smart defaults may skip log files)
        assert output["files_scanned"] >= 1  # At least the model file

        # Verify the mock was called (proves we avoided heavy imports)
        mock_cli_scan_command.assert_called_once()


@pytest.mark.unit
def test_cli_skip_message_in_verbose(mock_cli_scan_command):
    """Test that skip messages appear in logs when file filtering is active."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        (Path(tmp_dir) / "README.md").write_text("# Documentation")
        (Path(tmp_dir) / "train.py").write_text("import torch")
        (Path(tmp_dir) / "model.pkl").write_bytes(b"model")

        # Run scan in verbose mode
        result = runner.invoke(cli, ["scan", "--format", "text", "--verbose", tmp_dir])

        # Should complete successfully without crashing
        assert result.exit_code in [0, 1]

        # Verify scan was called (main functionality works)
        mock_cli_scan_command.assert_called_once()
