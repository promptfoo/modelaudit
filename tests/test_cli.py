import ctypes
import errno
import hashlib
import importlib
import json
import logging
import os
import re
import stat
import struct
import subprocess
import sys
import types
import zipfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from modelaudit import __version__
from modelaudit import cli as cli_module
from modelaudit.cache.trusted_config_store import TrustedConfigStore
from modelaudit.cli import (
    _create_path_progress_callback,
    _display_error,
    _display_path,
    _display_scan_path,
    _explicit_local_shard_family_groups,
    _format_scan_output,
    _local_path_will_be_scanned,
    _resolve_scan_runtime_config,
    _ScanPathState,
    _summarize_progress_tree,
    cli,
    expand_paths,
    format_text_output,
)
from modelaudit.core import scan_model_directory_or_file
from modelaudit.models import FileMetadataModel, ModelAuditResultModel, create_initial_audit_result
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos
from tests.cli_output import parse_click_json_output
from tests.helpers import create_mock_pytorch_zip


def test_local_txt_zip_prefilter_uses_bounded_zip_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "many.txt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")

    def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("CLI prefilter must not materialize ZIP entries")

    monkeypatch.setattr("modelaudit.scanners.zip_scanner.zipfile.ZipFile", fail_zipfile_open)

    assert _local_path_will_be_scanned(str(archive_path), skip_non_model_files=True) is True


_HF_TEST_REVISION = "a" * 40


def default_remote_cache_dir() -> str:
    """Compute the CLI's default remote cache root at assertion time."""
    return str(Path.home() / ".modelaudit" / "cache")


def strip_ansi(text: str) -> str:
    """Strip ANSI color codes from text for testing."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _make_trusted_shard_parent(path: Path, *, parents: bool = False) -> None:
    """Create a shard parent without inheriting group-write test umasks."""
    path.mkdir(parents=parents)
    path.chmod(0o755)


def _bert_like_multilingual_vocab_bytes(*tail_tokens: str) -> bytes:
    tokens = [
        "[PAD]",
        "[UNK]",
        "[CLS]",
        "[SEP]",
        "[MASK]",
        "the",
        "und",
        "de",
        "la",
        "\u4e2d",
        "\u56fd",
        "\u8a9e",
        "\u03b1",
        "\u03b2",
        *[f"token{index}" for index in range(128)],
        *[f"##piece{index}" for index in range(8)],
        *tail_tokens,
    ]
    return ("\n".join(tokens) + "\n").encode()


def create_mock_scan_result(**kwargs: Any) -> ModelAuditResultModel:
    """Create a mock ModelAuditResultModel for testing."""
    result = create_initial_audit_result()

    # Set default values
    result.bytes_scanned = kwargs.get("bytes_scanned", 1024)
    result.files_scanned = kwargs.get("files_scanned", 1)
    result.has_errors = kwargs.get("has_errors", False)
    result.success = kwargs.get("success", True)

    # Add issues if provided
    if "issues" in kwargs:
        import time

        from modelaudit.scanners.base import Issue

        issues = []
        for issue_dict in kwargs["issues"]:
            issue = Issue(
                message=issue_dict.get("message", "Test issue"),
                severity=issue_dict.get("severity", "warning"),
                location=issue_dict.get("location"),
                timestamp=time.time(),
                details=issue_dict.get("details", {}),
                why=None,
                type=issue_dict.get("type"),
            )
            issues.append(issue)
        result.issues = issues

    # Add assets if provided
    if "assets" in kwargs:
        from modelaudit.models import AssetModel

        assets = []
        for asset_dict in kwargs["assets"]:
            asset = AssetModel(
                path=asset_dict.get("path", "/test/path"),
                type=asset_dict.get("type", "test"),
                size=asset_dict.get("size", 0),
                is_streamed=asset_dict.get("is_streamed"),
                tensors=asset_dict.get("tensors"),
                keys=asset_dict.get("keys"),
                contents=asset_dict.get("contents"),
            )
            assets.append(asset)
        result.assets = assets

    # Add scanners if provided
    if "scanners" in kwargs:
        result.scanner_names = kwargs["scanners"]

    # Add file metadata if provided
    if "file_metadata" in kwargs:
        from modelaudit.models import FileMetadataModel

        result.file_metadata = {
            path: metadata if isinstance(metadata, FileMetadataModel) else FileMetadataModel(**metadata)
            for path, metadata in kwargs["file_metadata"].items()
        }

    result.finalize_statistics()
    return result


def assert_huggingface_acquisition_error_payload(
    payload: dict[str, Any],
    source_key: str,
    *,
    blocked: bool,
    expected_revision: str | None = None,
) -> None:
    """Assert stable JSON semantics for a failed Hugging Face acquisition."""
    assert payload["success"] is False
    assert payload["has_errors"] is True
    assert payload["bytes_scanned"] == 0
    assert payload["files_scanned"] == 0
    assert payload["assets"] == []
    metadata = payload["file_metadata"][source_key]
    reason = "huggingface_acquisition_blocked" if blocked else "huggingface_acquisition_error"
    assert metadata["source"] == "huggingface"
    assert metadata["source_url"] == source_key
    assert metadata["acquisition_error"] is True
    assert metadata["blocked"] is blocked
    assert metadata["error_category"] == ("blocked" if blocked else "acquisition_error")
    assert metadata["operational_error"] is True
    assert metadata["operational_error_reason"] == reason
    assert metadata["scan_outcome"] == "inconclusive"
    assert metadata["scan_outcome_reason"] == reason
    assert metadata["scan_outcome_reasons"] == [reason]
    if expected_revision is not None:
        assert metadata["requested_revision"] == expected_revision
    issue = next(issue for issue in payload["issues"] if issue["type"] == "huggingface_acquisition_error")
    assert issue["severity"] == "info"
    assert issue["location"] == source_key
    assert issue["details"]["source"] == "huggingface"
    assert issue["details"]["source_url"] == source_key
    assert issue["details"]["acquisition_error"] is True
    assert issue["details"]["blocked"] is blocked
    assert issue["details"]["error_category"] == ("blocked" if blocked else "acquisition_error")
    assert issue["details"]["scan_outcome"] == "inconclusive"
    assert issue["details"]["scan_outcome_reason"] == reason
    assert issue["details"]["scan_outcome_reasons"] == [reason]


def test_format_scan_json_redacts_sources_without_corrupting_result_metadata() -> None:
    first_url = "s3://bucket/model.pkl?token=first-secret"
    second_url = "s3://bucket/model.pkl?token=second-secret"
    result = create_mock_scan_result(
        issues=[
            {
                "message": f"Dangerous payload from {first_url}",
                "severity": "critical",
                "location": first_url,
                "details": {
                    first_url: {"finding": "first"},
                    second_url: {"finding": "second"},
                    "refreshToken": "nested-secret",
                    "password_policy": "preserve-near-match",
                },
            }
        ],
        file_metadata={
            first_url: {"file_size": 1, "source_url": first_url},
            second_url: {"file_size": 2, "source_url": second_url},
        },
    )
    original_metadata_keys = list(result.file_metadata)

    output = _format_scan_output(
        result,
        [first_url, second_url],
        output_format="json",
        verbose=True,
    )

    payload: dict[str, Any] = json.loads(output)
    assert list(result.file_metadata) == original_metadata_keys
    assert len(payload["file_metadata"]) == 2
    assert [metadata["file_size"] for metadata in payload["file_metadata"].values()] == [1, 2]
    assert list(payload["issues"][0]["details"].values()) == [
        {"finding": "first"},
        {"finding": "second"},
        "<redacted>",
        "preserve-near-match",
    ]
    assert "first-secret" not in output
    assert "second-secret" not in output
    assert "nested-secret" not in output

    text_output = _format_scan_output(
        result,
        [first_url, second_url],
        output_format="text",
        verbose=True,
    )
    assert "first-secret" not in text_output
    assert "second-secret" not in text_output
    assert "nested-secret" not in text_output


def test_format_scan_json_preserves_pydantic_json_serialization() -> None:
    result = create_mock_scan_result(
        issues=[
            {
                "message": "Serializable details",
                "severity": "warning",
                "details": {
                    "path": Path("models/model.pkl"),
                    "timestamp": datetime(2026, 6, 8, 12, 30, tzinfo=timezone.utc),
                },
            }
        ]
    )

    payload = json.loads(_format_scan_output(result, [], output_format="json", verbose=True))

    assert payload["issues"][0]["details"] == {
        "path": str(Path("models") / "model.pkl"),
        "timestamp": "2026-06-08T12:30:00Z",
    }


def test_cli_help():
    """Test the CLI help command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "scan" in result.output  # Should list the scan command


def test_cli_version():
    """Test the CLI version command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_summarize_progress_tree_walks_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Directory progress totals should come from one recursive traversal."""
    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()
    (tmp_path / "root.bin").write_bytes(b"abc")
    (nested_dir / "child.bin").write_bytes(b"de")

    original_rglob = Path.rglob
    rglob_calls = 0

    def counting_rglob(path: Path, pattern: str) -> Any:
        nonlocal rglob_calls
        rglob_calls += 1
        return original_rglob(path, pattern)

    monkeypatch.setattr(Path, "rglob", counting_rglob)

    assert _summarize_progress_tree(str(tmp_path)) == (5, 3)
    assert rglob_calls == 1


def test_scan_command_help():
    """Test the scan command help."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "--blacklist" in result.output
    assert "--format" in result.output
    assert "--output" in result.output
    assert "--timeout" in result.output
    assert "--verbose" in result.output
    assert "--max-size" in result.output  # Updated from --max-file-size
    assert "--strict" in result.output  # New consolidated flag
    assert "--no-whitelist" in result.output
    assert "--dry-run" in result.output  # New flag
    assert "Defaults:" in result.output or "Automatic defaults:" in result.output


def test_scan_invalid_severity_level_option(tmp_path):
    """Invalid severity override values should fail fast."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--severity", "S101=SEVERE"])

    assert result.exit_code == 2
    assert "Invalid severity level" in result.output
    assert "CRITICAL" in result.output


def test_scan_unknown_rule_code_in_severity_option(tmp_path):
    """Unknown rule codes in --severity should fail fast."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--severity", "S9999=CRITICAL"])

    assert result.exit_code == 2
    assert "Unknown rule code" in result.output
    assert "S9999" in result.output


def test_scan_unknown_rule_code_in_suppress_option(tmp_path):
    """Unknown rule codes in --suppress should fail fast."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--suppress", "S9999"])

    assert result.exit_code == 2
    assert "Unknown rule code" in result.output
    assert "S9999" in result.output


def test_scan_does_not_auto_load_untrusted_local_config(tmp_path: Path) -> None:
    """Scanning should not auto-apply suppressions from local config files."""
    import tarfile

    model_file = tmp_path / "evil.tar"
    with tarfile.open(model_file, "w") as tar:
        payload_file = tmp_path / "payload.txt"
        payload_file.write_text("content")
        tar.add(payload_file, arcname="../evil.txt")

    (tmp_path / ".modelaudit.toml").write_text('suppress = ["S405"]\n')

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(model_file), "--format", "json"], catch_exceptions=False)

    assert result.exit_code == 1
    output_payload = parse_click_json_output(result.output)
    assert any(issue.get("rule_code") == "S405" for issue in output_payload.get("issues", []))


def test_scan_json_subprocess_separates_logs_from_stdout_for_findings(tmp_path: Path) -> None:
    """Real process execution keeps JSON parseable without leaking finding payloads to logs."""
    import tarfile

    model_file = tmp_path / "evil.tar"
    with tarfile.open(model_file, "w") as tar:
        payload_file = tmp_path / "payload.txt"
        payload_file.write_text("content")
        tar.add(payload_file, arcname="../evil.txt")

    completed = subprocess.run(
        [sys.executable, "-m", "modelaudit", "scan", str(model_file), "--format", "json"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert completed.stdout.lstrip().startswith("{")
    output_payload = json.loads(completed.stdout)
    assert any(issue.get("rule_code") == "S405" for issue in output_payload.get("issues", []))
    assert "Security finding recorded" in completed.stderr
    assert "../evil.txt" not in completed.stderr


def test_scan_json_subprocess_single_skipped_file_keeps_stdout_parseable(tmp_path: Path) -> None:
    """Single-file skips should not prepend human text ahead of JSON stdout."""
    skipped_file = tmp_path / "skip.py"
    skipped_file.write_text("print('hello')\n")

    completed = subprocess.run(
        [sys.executable, "-m", "modelaudit", "scan", str(skipped_file), "--format", "json"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "Skipping non-model file:" not in completed.stdout
    assert completed.stdout.lstrip().startswith("{")

    output_payload = json.loads(completed.stdout)
    assert output_payload["files_scanned"] == 0
    assert output_payload["issues"] == []


def test_scan_json_subprocess_scans_tensorflow_metagraph_named_python(tmp_path: Path) -> None:
    """Content-routed binary model files must bypass explicit-path Python skipping."""
    if not _has_tf_protos():
        pytest.skip("TensorFlow protobuf stubs unavailable")

    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    metagraph = meta_graph_pb2.MetaGraphDef()
    node = metagraph.graph_def.node.add()
    node.name = "pyfunc_node"
    node.op = "PyFunc"
    payload = tmp_path / "payload.py"
    payload.write_bytes(metagraph.SerializeToString())

    env = {**os.environ, "PROMPTFOO_DISABLE_TELEMETRY": "1"}
    completed = subprocess.run(
        [sys.executable, "-m", "modelaudit", "scan", str(payload), "--format", "json", "--no-cache"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert completed.returncode == 1
    output_payload = json.loads(completed.stdout)
    assert output_payload["files_scanned"] == 1
    assert "tf_metagraph" in output_payload["scanner_names"]
    assert any(issue["message"] == "Dangerous TensorFlow operation: PyFunc" for issue in output_payload["issues"])


def test_scan_json_subprocess_mixed_directory_keeps_stdout_parseable(tmp_path: Path) -> None:
    """Directory scans should remain valid JSON when non-model files are skipped."""
    import pickle

    skipped_file = tmp_path / "skip.py"
    skipped_file.write_text("print('hello')\n")
    model_file = tmp_path / "safe.pkl"
    model_file.write_bytes(pickle.dumps({"ok": 1}))

    completed = subprocess.run(
        [sys.executable, "-m", "modelaudit", "scan", str(tmp_path), "--format", "json"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert "Skipping non-model file:" not in completed.stdout
    assert completed.stdout.lstrip().startswith("{")

    output_payload = json.loads(completed.stdout)
    assert output_payload["files_scanned"] >= 1
    assert any(asset.get("path") == str(model_file) for asset in output_payload.get("assets", []))


def test_scan_sarif_subprocess_single_skipped_file_reports_cli_exit_code(tmp_path: Path) -> None:
    """SARIF invocation metadata should reflect the CLI exit code for skipped scans."""
    skipped_file = tmp_path / "skip.py"
    skipped_file.write_text("print('hello')\n")
    env = {**os.environ, "PROMPTFOO_DISABLE_TELEMETRY": "1"}

    completed = subprocess.run(
        [sys.executable, "-m", "modelaudit", "scan", str(skipped_file), "--format", "sarif", "--no-cache"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert completed.returncode == 2
    sarif_payload = json.loads(completed.stdout)
    invocation = sarif_payload["runs"][0]["invocations"][0]
    assert invocation["exitCode"] == 2
    assert invocation["executionSuccessful"] is False
    assert invocation["exitCodeDescription"] == "No files were scanned"
    assert invocation["properties"]["filesScanned"] == 0


def test_scan_sarif_subprocess_preserves_modelaudit_rule_codes() -> None:
    """SARIF rule identifiers should match ModelAudit rule codes from JSON output."""
    model_file = Path("tests/assets/samples/pickles/malicious_system_call.pkl").resolve()
    env = {**os.environ, "PROMPTFOO_DISABLE_TELEMETRY": "1"}

    json_completed = subprocess.run(
        [sys.executable, "-m", "modelaudit", "scan", str(model_file), "--format", "json", "--no-cache"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    sarif_completed = subprocess.run(
        [sys.executable, "-m", "modelaudit", "scan", str(model_file), "--format", "sarif", "--no-cache"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert json_completed.returncode == 1
    assert sarif_completed.returncode == 1

    json_payload = json.loads(json_completed.stdout)
    expected_rule_codes = {issue["rule_code"] for issue in json_payload["issues"] if issue.get("rule_code")}
    assert "S201" in expected_rule_codes

    sarif_payload = json.loads(sarif_completed.stdout)
    run = sarif_payload["runs"][0]
    result_rule_ids = {result["ruleId"] for result in run["results"]}
    result_property_rule_codes = {
        result["properties"]["rule_code"] for result in run["results"] if result.get("properties")
    }
    driver_rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    driver_property_rule_codes = {
        rule["properties"]["rule_code"] for rule in run["tool"]["driver"]["rules"] if rule.get("properties")
    }

    assert expected_rule_codes <= result_rule_ids
    assert expected_rule_codes <= result_property_rule_codes
    assert expected_rule_codes <= driver_rule_ids
    assert expected_rule_codes <= driver_property_rule_codes
    assert run["invocations"][0]["exitCode"] == 1
    assert run["invocations"][0]["executionSuccessful"] is True


def test_scan_can_apply_local_config_once_when_confirmed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Interactive scans can apply a local config for the current run only."""
    import tarfile

    model_file = tmp_path / "evil.tar"
    with tarfile.open(model_file, "w") as tar:
        payload = tmp_path / "payload.txt"
        payload.write_text("content")
        tar.add(payload, arcname="../evil.txt")

    (tmp_path / ".modelaudit.toml").write_text('suppress = ["S405"]\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("modelaudit.cli.can_use_trusted_local_config", lambda output_format: output_format == "text")
    monkeypatch.setattr(
        "modelaudit.cli.get_trusted_config_store",
        lambda: TrustedConfigStore(tmp_path / "cache" / "trusted_local_configs.json"),
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(model_file), "--format", "text"], input="y\n", catch_exceptions=False)
    output = strip_ansi(result.output)

    assert result.exit_code == 0
    assert "Found local ModelAudit config" in output
    assert "Using local ModelAudit config" in output
    assert "NO ISSUES FOUND" in output
    trust_store = TrustedConfigStore(tmp_path / "cache" / "trusted_local_configs.json")
    assert not trust_store.store_path.exists()


def test_scan_can_remember_trusted_local_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing to trust a local config should persist for future interactive runs."""
    import tarfile

    model_file = tmp_path / "evil.tar"
    with tarfile.open(model_file, "w") as tar:
        payload = tmp_path / "payload.txt"
        payload.write_text("content")
        tar.add(payload, arcname="../evil.txt")

    (tmp_path / ".modelaudit.toml").write_text('suppress = ["S405"]\n')
    trust_store = TrustedConfigStore(tmp_path / "cache" / "trusted_local_configs.json")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("modelaudit.cli.can_use_trusted_local_config", lambda output_format: output_format == "text")
    monkeypatch.setattr("modelaudit.cli.get_trusted_config_store", lambda: trust_store)

    runner = CliRunner()
    first_result = runner.invoke(
        cli,
        ["scan", str(model_file), "--format", "text"],
        input="a\n",
        catch_exceptions=False,
    )
    second_result = runner.invoke(cli, ["scan", str(model_file), "--format", "text"], catch_exceptions=False)

    assert first_result.exit_code == 0
    assert second_result.exit_code == 0
    assert trust_store.store_path.exists()
    assert "Found local ModelAudit config" in strip_ansi(first_result.output)
    assert "Found local ModelAudit config" not in strip_ansi(second_result.output)


def test_scan_reprompts_when_trusted_local_config_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Remembered trust should be invalidated when the local config file changes."""
    import tarfile

    model_file = tmp_path / "evil.tar"
    with tarfile.open(model_file, "w") as tar:
        payload = tmp_path / "payload.txt"
        payload.write_text("content")
        tar.add(payload, arcname="../evil.txt")

    config_path = tmp_path / ".modelaudit.toml"
    config_path.write_text('suppress = ["S405"]\n')
    trust_store = TrustedConfigStore(tmp_path / "cache" / "trusted_local_configs.json")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("modelaudit.cli.can_use_trusted_local_config", lambda output_format: output_format == "text")
    monkeypatch.setattr("modelaudit.cli.get_trusted_config_store", lambda: trust_store)

    runner = CliRunner()
    first_result = runner.invoke(
        cli,
        ["scan", str(model_file), "--format", "text"],
        input="a\n",
        catch_exceptions=False,
    )

    config_path.write_text("suppress = []\n")
    second_result = runner.invoke(
        cli,
        ["scan", str(model_file), "--format", "text"],
        input="n\n",
        catch_exceptions=False,
    )

    assert first_result.exit_code == 0
    assert second_result.exit_code == 1
    assert trust_store.store_path.exists()
    assert "Found local ModelAudit config" in strip_ansi(first_result.output)
    assert "Found local ModelAudit config" in strip_ansi(second_result.output)


def test_scan_disables_cache_when_local_config_is_applied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Applying a local config should bypass scan-result caching for safety."""
    target_file = tmp_path / "model.dat"
    target_file.write_bytes(b"test content")
    (tmp_path / ".modelaudit.toml").write_text('suppress = ["S710"]\n')

    captured: dict[str, object] = {}

    def fake_scan_model_directory_or_file(path: str, **kwargs: Any) -> ModelAuditResultModel:
        captured["path"] = path
        captured.update(kwargs)
        return create_mock_scan_result()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("modelaudit.cli.can_use_trusted_local_config", lambda output_format: output_format == "text")
    monkeypatch.setattr(
        "modelaudit.cli.get_trusted_config_store",
        lambda: TrustedConfigStore(tmp_path / "cache" / "trusted_local_configs.json"),
    )
    monkeypatch.setattr("modelaudit.cli.scan_model_directory_or_file", fake_scan_model_directory_or_file)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(target_file), "--format", "text"], input="y\n", catch_exceptions=False)

    assert result.exit_code == 0
    assert captured["cache_enabled"] is False


def test_scan_nonexistent_file():
    """Test scanning a nonexistent file."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "nonexistent_file.pkl"])
    # The CLI might exit with a non-zero code for errors
    # But it should mention the error in the output
    assert "Error" in result.output
    assert "not exist" in result.output.lower() or "not found" in result.output.lower()


def test_scan_file(tmp_path):
    """Test scanning a file."""
    # Create a test file
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file)], catch_exceptions=True)

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    # With automatic defaults, non-model files may be skipped or shown differently
    # Just check that it completed successfully
    assert result.exit_code == 0


def test_scan_directory(tmp_path):
    """Test scanning a directory."""
    # Create a test directory with files
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()
    (test_dir / "file1.pkl").write_bytes(b"test content 1")
    (test_dir / "file2.bin").write_bytes(b"test content 2")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_dir)], catch_exceptions=True)

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    # Verify that the scan produced results (works with both text and JSON formats)
    assert (
        "Files:" in result.output
        or "Size:" in result.output
        or "bytes_scanned" in result.output
        or "files_scanned" in result.output
    )


def test_scan_multiple_paths(tmp_path):
    """Test scanning multiple paths."""
    # Create test files
    file1 = tmp_path / "file1.dat"
    file1.write_bytes(b"test content 1")

    file2 = tmp_path / "file2.dat"
    file2.write_bytes(b"test content 2")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(file1), str(file2)], catch_exceptions=True)

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    # Verify that the scan produced results (works with both text and JSON formats)
    assert (
        "Files:" in result.output
        or "Size:" in result.output
        or "bytes_scanned" in result.output
        or "files_scanned" in result.output
    )


def test_scan_multiple_cross_directory_shards_reconciles_complete_family(tmp_path: Path) -> None:
    """Explicit shard paths should be reconciled across their separate parent directories."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard_paths: list[str] = []
    for shard_index in range(1, 4):
        shard_dir = tmp_path / f"part-{shard_index}"
        _make_trusted_shard_parent(shard_dir)
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00003.safetensors"
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
        shard_paths.append(str(shard_path))

    result = CliRunner().invoke(
        cli,
        ["scan", *shard_paths, "--assume-shard-family", "--format", "json", "--no-cache"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["files_scanned"] == 3
    assert output_payload["success"] is True
    assert not any(
        check.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for check in output_payload["checks"]
    )
    assert not any(
        issue.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for issue in output_payload["issues"]
    )


def test_scan_cross_directory_shards_ignores_duplicate_explicit_argument(tmp_path: Path) -> None:
    """Repeating one exact shard argument must not invalidate a complete family."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard_paths: list[str] = []
    for shard_index in range(1, 3):
        shard_dir = tmp_path / f"part-{shard_index}"
        _make_trusted_shard_parent(shard_dir)
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
        shard_paths.append(str(shard_path))

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            *shard_paths,
            shard_paths[0],
            "--assume-shard-family",
            "--format",
            "json",
            "--no-cache",
        ],
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["files_scanned"] == 2
    assert output_payload["success"] is True
    assert not any(
        record.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for record in [*output_payload["checks"], *output_payload["issues"]]
    )


def test_scan_cross_directory_shards_preserves_nonexistent_path_error(tmp_path: Path) -> None:
    """Shard reconciliation must not clear a separate caller-level path error."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard_paths: list[str] = []
    for shard_index in range(1, 3):
        shard_dir = tmp_path / f"part-{shard_index}"
        _make_trusted_shard_parent(shard_dir)
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
        shard_paths.append(str(shard_path))
    nonexistent_path = tmp_path / "missing.safetensors"

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            *shard_paths,
            str(nonexistent_path),
            "--assume-shard-family",
            "--format",
            "json",
            "--no-cache",
        ],
        catch_exceptions=False,
    )

    assert result.exit_code == 2, result.output
    assert f"Path does not exist: {nonexistent_path}" in result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["has_errors"] is True
    assert output_payload["success"] is False
    assert not any(
        check.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for check in output_payload["checks"]
    )
    assert not any(
        issue.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for issue in output_payload["issues"]
    )


def test_scan_multiple_cross_directory_shards_reconciles_independent_families(tmp_path: Path) -> None:
    """Explicit opt-in should keep independently templated shard families separate."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard_paths: list[str] = []
    for family_name in ("model-a", "model-b"):
        for shard_index, shard_directory_name in ((1, "left"), (2, "right")):
            shard_dir = tmp_path / family_name / shard_directory_name
            _make_trusted_shard_parent(shard_dir, parents=True)
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
            shard_paths.append(str(shard_path))

    result = CliRunner().invoke(
        cli,
        ["scan", *shard_paths, "--assume-shard-family", "--format", "json", "--no-cache"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["files_scanned"] == 4
    assert output_payload["success"] is True
    assert not any(
        check.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for check in output_payload["checks"]
    )
    assert not any(
        issue.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for issue in output_payload["issues"]
    )


def test_scan_cross_directory_shards_keeps_ambiguous_incomplete_families(tmp_path: Path) -> None:
    """Unmatched shards must not complete each other through a shared fallback group."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard_paths: list[str] = []
    incomplete_paths: set[str] = set()
    for family_name, shard_directory_name, shard_index in (
        ("complete", "left", 1),
        ("complete", "right", 2),
        ("incomplete-a", "left", 1),
        ("incomplete-b", "right", 2),
    ):
        shard_dir = tmp_path / family_name / shard_directory_name
        _make_trusted_shard_parent(shard_dir, parents=True)
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
        shard_paths.append(str(shard_path))
        if family_name.startswith("incomplete-"):
            incomplete_paths.add(str(shard_path))

    result = CliRunner().invoke(
        cli,
        ["scan", *shard_paths, "--assume-shard-family", "--format", "json", "--no-cache"],
        catch_exceptions=False,
    )

    assert result.exit_code == 2, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["files_scanned"] == 4
    assert output_payload["success"] is False
    missing_locations = {
        issue.get("location")
        for issue in output_payload["issues"]
        if issue.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
    }
    assert missing_locations == incomplete_paths


def test_scan_directory_does_not_assume_cross_directory_shard_family(tmp_path: Path) -> None:
    """The explicit-family opt-in must not combine shards discovered through a directory input."""
    header = b'{"__metadata__":{"format":"pt"}}'
    for shard_index, family_name in ((1, "model-a"), (2, "model-b")):
        shard_dir = tmp_path / family_name
        shard_dir.mkdir()
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header)

    result = CliRunner().invoke(
        cli,
        ["scan", str(tmp_path), "--assume-shard-family", "--format", "json", "--no-cache"],
        catch_exceptions=False,
    )

    assert result.exit_code == 2, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["success"] is False
    assert any(
        check.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for check in output_payload["checks"]
    )
    assert any(
        issue.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for issue in output_payload["issues"]
    )


def test_explicit_shard_family_groups_reject_resolved_non_shard_target(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """A shard-looking symlink must not opt its non-shard target into reconciliation."""
    target = tmp_path / "payload.bin"
    target.write_bytes(b"not a shard")
    shard_link = tmp_path / "model-00001-of-00002.safetensors"
    shard_link.symlink_to(target)

    assert _explicit_local_shard_family_groups((str(shard_link),)) == {}


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes are required")
def test_explicit_shard_family_groups_reject_publicly_writable_parents(tmp_path: Path) -> None:
    """Cross-directory reconciliation must not trust mutable public staging directories."""
    shard_paths: list[str] = []
    for shard_index in range(1, 3):
        shard_dir = tmp_path / f"part-{shard_index}"
        shard_dir.mkdir(mode=0o777)
        shard_dir.chmod(0o777)
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(b"shard")
        shard_paths.append(str(shard_path))

    assert _explicit_local_shard_family_groups(tuple(shard_paths)) == {}


def test_scan_multiple_cross_directory_shards_requires_explicit_family_opt_in(tmp_path: Path) -> None:
    """Numeric directory names must not silently merge unrelated local checkpoints."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard_paths: list[str] = []
    for shard_index in range(1, 3):
        shard_dir = tmp_path / f"checkpoint-{shard_index}"
        shard_dir.mkdir()
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
        shard_paths.append(str(shard_path))

    result = CliRunner().invoke(
        cli,
        ["scan", *shard_paths, "--format", "json", "--no-cache"],
        catch_exceptions=False,
    )

    assert result.exit_code == 2, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["success"] is False
    assert any(
        check.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for check in output_payload["checks"]
    )
    assert any(
        issue.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for issue in output_payload["issues"]
    )


def test_scan_with_blacklist(tmp_path):
    """Test scanning with blacklist patterns."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(test_file), "--blacklist", "pattern1", "--blacklist", "pattern2"],
        catch_exceptions=True,
    )

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    assert result.exit_code == 0  # Command should complete successfully
    # With automatic defaults, the specific output format may vary


def test_scan_json_output(tmp_path):
    """Test scanning with JSON output format."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--format", "json"])

    # For JSON output, we should be able to parse the output as JSON
    # regardless of the exit code
    try:
        output_json = parse_click_json_output(result.output)
        assert "files_scanned" in output_json
        assert "issues" in output_json
        assert output_json["files_scanned"] == 1
    except json.JSONDecodeError:
        pytest.fail("Output is not valid JSON")


def test_strict_json_incomplete_coverage_exits_2(tmp_path: Path) -> None:
    """Strict JSON should expose incomplete coverage and terminate truthfully."""
    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"bounded coverage")
    scan_result = create_mock_scan_result(
        success=False,
        files_scanned=1,
        file_metadata={
            str(test_file): {
                "analysis_incomplete": True,
                "scan_outcome_reasons": ["bounded_probe_exhausted"],
            }
        },
    )

    with patch("modelaudit.cli.scan_model_directory_or_file", return_value=scan_result):
        result = CliRunner().invoke(cli, ["scan", str(test_file), "--strict", "--format", "json"])

    assert result.exit_code == 2, result.output
    payload = parse_click_json_output(result.output)
    assert payload["success"] is False
    assert payload["has_errors"] is False
    assert payload["file_metadata"][str(test_file)]["analysis_incomplete"] is True
    assert payload["file_metadata"][str(test_file)]["scan_outcome_reasons"] == ["bounded_probe_exhausted"]


def test_scan_output_file(tmp_path: Path) -> None:
    """Test scanning with output to a file."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    output_file = tmp_path / "output.txt"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--output", str(output_file)])

    assert result.exit_code == 0, result.output
    # Successful report generation must install a non-empty file.
    assert output_file.exists()
    assert output_file.read_text()  # Should not be empty
    assert f"Results written to {output_file}" in result.output


def test_scan_json_output_to_file(tmp_path: Path) -> None:
    """Test scanning with JSON output to a file - JSON should be valid and not mixed with progress."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    output_file = tmp_path / "output.json"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--format", "json", "--output", str(output_file)])

    assert result.exit_code == 0, result.output
    # The file should be created
    assert output_file.exists()

    # JSON in file should be valid and parseable
    try:
        output_json = json.loads(output_file.read_text())
        assert "files_scanned" in output_json
        assert "issues" in output_json
        assert output_json["files_scanned"] == 1
    except json.JSONDecodeError:
        pytest.fail("JSON output file is not valid JSON")

    # Stdout should contain confirmation message (and potentially progress output)
    assert f"Results written to {output_file}" in result.output


def test_scan_output_confirmation_escapes_terminal_controls(tmp_path: Path) -> None:
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")
    output_file = tmp_path / "report\nFORGED\x1b[2J.json"
    scan_result = create_mock_scan_result(files_scanned=1, issues=[])

    with (
        patch("modelaudit.cli.scan_model_directory_or_file", return_value=scan_result),
        patch("modelaudit.cli._preflight_output_text_file"),
        patch("modelaudit.cli._write_output_text_file") as mock_write_output,
    ):
        result = CliRunner().invoke(
            cli,
            ["scan", str(test_file), "--format", "json", "--output", str(output_file)],
        )

    assert result.exit_code == 0, result.output
    assert mock_write_output.call_args.args[0] == str(output_file)
    assert "report\\nFORGED\\x1b[2J.json" in result.output
    assert "\nFORGED" not in result.output
    assert "\x1b" not in result.output


def test_scan_json_to_stdout_no_progress_interference(tmp_path):
    """Test that JSON to stdout remains valid (no progress output mixed in)."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--format", "json"])

    # Output should be valid JSON when going to stdout (no progress interference)
    try:
        output_json = parse_click_json_output(result.output)
        assert "files_scanned" in output_json
        assert "issues" in output_json
    except json.JSONDecodeError:
        pytest.fail("JSON output to stdout is not valid JSON - may be corrupted by progress")


def test_scan_sbom_output(tmp_path):
    """Test scanning with SBOM output."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    sbom_file = tmp_path / "sbom.json"

    runner = CliRunner()
    runner.invoke(cli, ["scan", str(test_file), "--sbom", str(sbom_file)])

    assert sbom_file.exists()
    try:
        json.loads(sbom_file.read_text())
    except json.JSONDecodeError:
        pytest.fail("SBOM output is not valid JSON")


def test_scan_sbom_preserves_format_character_filename_identity(tmp_path: Path) -> None:
    import hashlib
    import pickle

    content = pickle.dumps({"weights": [1, 2, 3]})
    model_path = tmp_path / "model\u202ename.pkl"
    model_path.write_bytes(content)
    sbom_file = tmp_path / "sbom.json"
    scan_result = create_mock_scan_result(
        assets=[{"path": str(model_path), "type": "pickle", "size": len(content)}],
    )

    with patch("modelaudit.cli.scan_model_directory_or_file", return_value=scan_result):
        result = CliRunner().invoke(
            cli,
            ["scan", "--quiet", "--no-cache", "--sbom", str(sbom_file), str(model_path)],
        )

    assert result.exit_code == 0, result.output
    sbom = json.loads(sbom_file.read_text())
    component = next(component for component in sbom["components"] if component["name"] == model_path.name)
    assert component["name"] == "model\u202ename.pkl"
    assert component["hashes"] == [{"alg": "SHA-256", "content": hashlib.sha256(content).hexdigest()}]


def test_cli_report_writers_reject_symlink_outputs(tmp_path: Path, requires_symlinks: None) -> None:
    """CLI report outputs must not follow attacker-controlled symlink targets."""
    model_tree = tmp_path / "model_tree"
    model_tree.mkdir()
    test_file = model_tree / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    cases = [
        (
            ["scan", str(test_file), "--format", "json", "--output", str(model_tree / "report.json"), "--no-cache"],
            model_tree / "report.json",
            tmp_path / "victim_report.txt",
        ),
        (
            ["scan", str(test_file), "--format", "text", "--output", str(model_tree / "report.txt"), "--no-cache"],
            model_tree / "report.txt",
            tmp_path / "victim_report_text.txt",
        ),
        (
            ["scan", str(test_file), "--format", "sarif", "--output", str(model_tree / "report.sarif"), "--no-cache"],
            model_tree / "report.sarif",
            tmp_path / "victim_report_sarif.txt",
        ),
        (
            ["scan", str(test_file), "--sbom", str(model_tree / "sbom.json"), "--no-cache"],
            model_tree / "sbom.json",
            tmp_path / "victim_sbom.txt",
        ),
        (
            ["metadata", str(test_file), "--format", "json", "--output", str(model_tree / "metadata.json")],
            model_tree / "metadata.json",
            tmp_path / "victim_metadata.txt",
        ),
        (
            ["scan", "--list-scanners", "--format", "json", "--output", str(model_tree / "scanners.json")],
            model_tree / "scanners.json",
            tmp_path / "victim_scanners.txt",
        ),
    ]

    for args, symlink_path, victim_path in cases:
        sentinel = f"sentinel:{victim_path.name}"
        victim_path.write_text(sentinel)
        symlink_path.symlink_to(victim_path)

        result = runner.invoke(cli, args)

        assert result.exit_code == 2
        assert "Refusing to write output through symlink" in result.output
        assert victim_path.read_text() == sentinel
        assert symlink_path.is_symlink()


def test_cli_report_writers_reject_symlinked_parent_directory(tmp_path: Path, requires_symlinks: None) -> None:
    """CLI report outputs must not follow attacker-controlled parent directory symlinks."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    redirected_dir = tmp_path / "redirected"
    redirected_dir.symlink_to(outside_dir, target_is_directory=True)
    output_path = redirected_dir / "scanners.json"

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "Refusing to write output through symlink" in result.output
    assert not (outside_dir / "scanners.json").exists()


def test_cli_report_writers_allow_protected_parent_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """A parent link in a non-replaceable directory may resolve to a stable target."""
    protected_dir = tmp_path / "protected"
    protected_dir.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    linked_dir = protected_dir / "linked"
    linked_dir.symlink_to(target_dir, target_is_directory=True)
    monkeypatch.setattr(cli_module, "_directory_can_replace_entries", lambda _path: False)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(linked_dir / "scanners.json")],
    )

    assert result.exit_code == 0, result.output
    assert json.loads((target_dir / "scanners.json").read_text())["scanners"]


def test_link_detection_ignores_nonredirecting_windows_reparse_points() -> None:
    """Cloud placeholders must not be treated like symlinks or junctions."""
    path = MagicMock(spec=Path)
    path_stat = MagicMock()
    path_stat.st_mode = stat.S_IFREG
    path_stat.st_file_attributes = stat.FILE_ATTRIBUTE_REPARSE_POINT
    path_stat.st_reparse_tag = 0x9000001A
    path.lstat.return_value = path_stat

    assert not cli_module._is_link_like_path(path)

    path_stat.st_reparse_tag = 0xA000000C
    assert cli_module._is_link_like_path(path)


def test_cli_report_writers_reject_symlink_before_dotdot(tmp_path: Path, requires_symlinks: None) -> None:
    """Lexical normalization must not change symlink-aware kernel path resolution."""
    safe_dir = tmp_path / "safe"
    safe_dir.mkdir()
    outside_parent = tmp_path / "outside"
    outside_child = outside_parent / "child"
    outside_child.mkdir(parents=True)
    (safe_dir / "redirected").symlink_to(outside_child, target_is_directory=True)
    output_path = safe_dir / "redirected" / ".." / "victim.json"

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "Refusing to write output through symlink" in result.output
    assert not (safe_dir / "victim.json").exists()
    assert not (outside_parent / "victim.json").exists()


def test_cli_report_writers_allow_dotdot_without_links(tmp_path: Path) -> None:
    """Ordinary parent traversal should retain normal filesystem semantics."""
    output_dir = tmp_path / "output"
    child_dir = output_dir / "child"
    child_dir.mkdir(parents=True)
    output_path = child_dir / ".." / "scanners.json"

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads((output_dir / "scanners.json").read_text())["scanners"]


def test_cli_report_writers_reject_dotdot_after_regular_file(tmp_path: Path) -> None:
    """Pinned ``..`` handling must retain the kernel's intermediate-directory checks."""
    regular_file = tmp_path / "not-a-directory"
    regular_file.write_text("sentinel")
    output_path = regular_file / ".." / "scanners.json"

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    if os.name == "nt":
        assert "non-directory component" in result.output
    assert regular_file.read_text() == "sentinel"
    assert not (tmp_path / "scanners.json").exists()


def test_cli_report_writers_reject_dotdot_after_missing_component(tmp_path: Path) -> None:
    """Missing intermediate components must not disappear during Windows normalization."""
    output_path = tmp_path / "missing-directory" / ".." / "scanners.json"

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert not (tmp_path / "scanners.json").exists()


def test_windows_dotdot_validation_rejects_invalid_intermediate_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the Windows-only raw component guard on every CI platform."""
    regular_file = tmp_path / "not-a-directory"
    regular_file.write_text("sentinel")
    file_output = regular_file / ".." / "scanners.json"
    missing_output = tmp_path / "missing-directory" / ".." / "scanners.json"

    monkeypatch.setattr(cli_module, "Path", type(tmp_path))
    monkeypatch.setattr(cli_module.os, "name", "nt")

    with pytest.raises(cli_module._OutputWriteError, match="non-directory component"):
        cli_module._validated_absolute_output_path(str(file_output))
    with pytest.raises(cli_module._OutputWriteError, match="invalid parent component"):
        cli_module._validated_absolute_output_path(str(missing_output))


def test_cli_report_writers_pin_dotdot_before_parent_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A renamed child must not change the parent selected by a validated ``..``."""
    safe_dir = tmp_path / "safe"
    child_dir = safe_dir / "child"
    child_dir.mkdir(parents=True)
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    output_path = child_dir / ".." / "scanners.json"
    original_open = cli_module.os.open
    original_supports_dir_fd = cli_module.os.supports_dir_fd
    moved = False

    def rename_child_after_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal moved
        opened_fd = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == "child" and not moved:
            child_dir.rename(target_dir / "relocated")
            moved = True
        return opened_fd

    monkeypatch.setattr(cli_module.os, "open", rename_child_after_open)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        {rename_child_after_open if function is original_open else function for function in original_supports_dir_fd},
    )

    cli_module._write_output_text_file(str(output_path), "secret")

    assert (safe_dir / "scanners.json").read_text() == "secret"
    assert not (target_dir / "scanners.json").exists()


def test_cli_report_writers_normalize_unicode_encode_failure(
    tmp_path: Path,
) -> None:
    """Unencodable rendered evidence must fail with exit code 2 and clean its temp file."""
    output_path = tmp_path / "scanners.json"

    with pytest.raises(cli_module._OutputWriteError) as exc_info:
        cli_module._write_output_text_file(str(output_path), "unsafe\udcfftext")

    assert exc_info.value.exit_code == 2
    assert "Unable to encode output" in str(exc_info.value)
    assert not output_path.exists()
    assert not list(tmp_path.glob(".modelaudit-output-*.tmp"))
    assert not list(tmp_path.glob(".modelaudit-output-*.probe"))


def test_cli_report_writers_preserve_existing_output_on_unicode_encode_failure(tmp_path: Path) -> None:
    """Encoding validation must finish before an existing report is truncated."""
    output_path = tmp_path / "scanners.json"
    output_path.write_text("sentinel")

    with pytest.raises(cli_module._OutputWriteError) as exc_info:
        cli_module._write_output_text_file(str(output_path), "unsafe\udcfftext")

    assert exc_info.value.exit_code == 2
    assert "Unable to encode output" in str(exc_info.value)
    assert output_path.read_text() == "sentinel"


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative staging is required")
def test_cli_report_writers_preserve_existing_output_on_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A staged write failure must leave the existing report intact."""
    output_path = tmp_path / "scanners.json"
    output_path.write_text("sentinel")

    def fail_fsync(_fd: int) -> None:
        raise OSError(errno.EIO, "simulated fsync failure")

    monkeypatch.setattr(cli_module.os, "fsync", fail_fsync)

    with pytest.raises(cli_module._OutputWriteError) as exc_info:
        cli_module._write_output_text_file(str(output_path), "replacement")

    assert exc_info.value.exit_code == 2
    assert "simulated fsync failure" in str(exc_info.value)
    assert output_path.read_text() == "sentinel"
    assert not list(tmp_path.glob(".modelaudit-output-*.tmp"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory fsync is required")
def test_cli_report_writers_fsync_published_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful report write must persist both content and its directory entry."""
    output_path = tmp_path / "scanners.json"
    original_fsync = os.fsync
    synced_file_types: list[int] = []

    def record_fsync(fd: int) -> None:
        synced_file_types.append(stat.S_IFMT(os.fstat(fd).st_mode))
        original_fsync(fd)

    monkeypatch.setattr(cli_module.os, "fsync", record_fsync)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert stat.S_IFREG in synced_file_types
    assert stat.S_IFDIR in synced_file_types


def test_cli_report_writers_reject_missing_path_with_trailing_separator(tmp_path: Path) -> None:
    """A directory-spelled output must not silently become a regular file."""
    output_path = tmp_path / "new-output"

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", f"{output_path}{os.sep}"],
    )

    assert result.exit_code == 2
    assert "trailing separator" in result.output
    assert not output_path.exists()


def test_cli_report_writers_reject_missing_path_with_final_dot_component(tmp_path: Path) -> None:
    """Raw directory syntax must not normalize into a different output filename."""
    output_path = tmp_path / "missing-output"

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", f"{output_path}{os.sep}."],
    )

    assert result.exit_code == 2
    assert "final dot component" in result.output
    assert not output_path.exists()


def test_absolute_output_path_rejects_windows_alternate_data_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows report paths must identify a file, not a hidden named stream."""
    monkeypatch.setattr(cli_module.os, "name", "nt")

    with pytest.raises(cli_module._OutputWriteError, match="alternate data stream"):
        cli_module._absolute_output_path(r"C:\reports\scan.json:hidden")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permits colons in regular filenames")
def test_cli_report_writers_allow_posix_colon_filename(tmp_path: Path) -> None:
    """The Windows stream guard must not reject a valid POSIX filename."""
    output_path = tmp_path / "scan:report.json"

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(output_path.read_text())["scanners"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX parent persistence handles are required")
def test_cli_report_writers_open_parent_sync_handle_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A parent that cannot be reopened for fsync must fail before publication work."""
    output_path = tmp_path / "scanners.json"
    staging_open = MagicMock()

    def reject_parent_sync(_output_path: str, _parent_fd: int) -> int:
        raise cli_module._OutputWriteError("simulated parent sync open failure")

    monkeypatch.setattr(cli_module, "_open_posix_output_parent_sync_fd", reject_parent_sync)
    monkeypatch.setattr(cli_module, "_open_posix_output_staging_directory", staging_open)

    with pytest.raises(cli_module._OutputWriteError, match="simulated parent sync open failure"):
        cli_module._write_output_text_file(str(output_path), "report")

    staging_open.assert_not_called()
    assert not output_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative staging is required")
@pytest.mark.parametrize("output_option", ["--output", "--sbom"])
def test_scan_preflights_report_destination_before_scan_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_option: str,
) -> None:
    """Unsupported atomic output destinations must be rejected before scan orchestration."""
    test_file = tmp_path / "model.pkl"
    test_file.write_bytes(b"not a pickle")
    output_path = tmp_path / "report.json"
    resolve_scan_paths = MagicMock(side_effect=AssertionError("scan path resolution must not start"))

    def reject_staging(_output_path: str, _parent_fd: int, _staging_name: str) -> int:
        raise PermissionError(errno.EACCES, "simulated read-only output directory")

    monkeypatch.setattr(cli_module, "_open_posix_output_staging_directory", reject_staging)
    monkeypatch.setattr(cli_module, "_resolve_scan_paths", resolve_scan_paths)

    result = CliRunner().invoke(cli, ["scan", str(test_file), output_option, str(output_path), "--no-cache"])

    assert result.exit_code == 2
    assert "simulated read-only output directory" in result.output
    resolve_scan_paths.assert_not_called()
    assert not output_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link installation is required")
@pytest.mark.parametrize("output_option", ["--output", "--sbom"])
def test_scan_preflights_hard_link_installation_before_scan_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_option: str,
) -> None:
    test_file = tmp_path / "model.pkl"
    test_file.write_bytes(b"not a pickle")
    output_path = tmp_path / "report.json"
    resolve_scan_paths = MagicMock(side_effect=AssertionError("scan path resolution must not start"))
    original_link = cli_module.os.link
    original_supports_dir_fd = cli_module.os.supports_dir_fd

    def reject_hard_link(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.EOPNOTSUPP, "simulated filesystem without hard links")

    monkeypatch.setattr(cli_module.os, "link", reject_hard_link)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        {reject_hard_link if function is original_link else function for function in original_supports_dir_fd},
    )
    monkeypatch.setattr(cli_module, "_resolve_scan_paths", resolve_scan_paths)

    result = CliRunner().invoke(cli, ["scan", str(test_file), output_option, str(output_path), "--no-cache"])

    assert result.exit_code == 2
    assert "simulated filesystem without hard links" in result.output
    resolve_scan_paths.assert_not_called()
    assert not output_path.exists()
    assert not list(tmp_path.glob(".modelaudit-output-*.tmp"))
    assert not list(tmp_path.glob(".modelaudit-output-*.probe"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative staging is required")
@pytest.mark.parametrize("output_option", ["--output", "--sbom"])
def test_scan_preflights_existing_report_metadata_before_scan_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_option: str,
) -> None:
    """Unpreservable report metadata must fail before scan orchestration."""
    test_file = tmp_path / "model.pkl"
    test_file.write_bytes(b"not a pickle")
    output_path = tmp_path / "report.json"
    output_path.write_text("sentinel")
    resolve_scan_paths = MagicMock(side_effect=AssertionError("scan path resolution must not start"))

    def reject_metadata(_output_path: str, _source_fd: int, _target_fd: int) -> None:
        raise cli_module._OutputWriteError("simulated metadata preservation failure")

    monkeypatch.setattr(cli_module, "_copy_posix_output_metadata", reject_metadata)
    monkeypatch.setattr(cli_module, "_resolve_scan_paths", resolve_scan_paths)

    result = CliRunner().invoke(cli, ["scan", str(test_file), output_option, str(output_path), "--no-cache"])

    assert result.exit_code == 2
    assert "simulated metadata preservation failure" in result.output
    resolve_scan_paths.assert_not_called()
    assert output_path.read_text() == "sentinel"
    assert not list(tmp_path.glob(".modelaudit-output-*.tmp"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX sticky-directory semantics are required")
@pytest.mark.parametrize("output_option", ["--output", "--sbom"])
def test_scan_preflights_sticky_directory_replacement_before_scan_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_option: str,
) -> None:
    test_file = tmp_path / "model.pkl"
    test_file.write_bytes(b"not a pickle")
    output_path = tmp_path / "report.json"
    output_path.write_text("sentinel")
    resolve_scan_paths = MagicMock(side_effect=AssertionError("scan path resolution must not start"))

    monkeypatch.setattr(
        cli_module,
        "_validate_posix_output_replacement_permission",
        MagicMock(side_effect=cli_module._OutputWriteError("simulated sticky-directory replacement denial")),
    )
    monkeypatch.setattr(cli_module, "_resolve_scan_paths", resolve_scan_paths)

    result = CliRunner().invoke(cli, ["scan", str(test_file), output_option, str(output_path), "--no-cache"])

    assert result.exit_code == 2
    assert "simulated sticky-directory replacement denial" in result.output
    resolve_scan_paths.assert_not_called()
    assert output_path.read_text() == "sentinel"


@pytest.mark.parametrize("output_option", ["--output", "--sbom"])
def test_scan_preflights_windows_temp_creation_before_scan_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_option: str,
) -> None:
    """Windows report staging failures must be discovered before scanning."""
    test_file = tmp_path / "model.pkl"
    test_file.write_bytes(b"not a pickle")
    output_path = tmp_path / "report.json"
    resolve_scan_paths = MagicMock(side_effect=AssertionError("scan path resolution must not start"))
    close_handle = MagicMock()

    monkeypatch.setattr(cli_module, "Path", type(tmp_path))
    monkeypatch.setattr(cli_module.os, "name", "nt")
    monkeypatch.setattr(cli_module, "_open_output_parent_directory", lambda _path: (output_path, None, 101))
    monkeypatch.setattr(cli_module, "_validate_existing_output_path", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli_module, "_open_windows_output_parent_lock", lambda *_args: 202)
    monkeypatch.setattr(
        cli_module,
        "_open_windows_output_temp_file",
        MagicMock(side_effect=cli_module._OutputWriteError("simulated Windows temp creation failure")),
    )
    monkeypatch.setattr(cli_module, "_close_windows_handle", close_handle)
    monkeypatch.setattr(cli_module, "_resolve_scan_paths", resolve_scan_paths)

    result = CliRunner().invoke(cli, ["scan", str(test_file), output_option, str(output_path), "--no-cache"])

    assert result.exit_code == 2
    assert "simulated Windows temp creation failure" in result.output
    resolve_scan_paths.assert_not_called()
    assert [close_call.args for close_call in close_handle.call_args_list] == [(202,), (101,)]


@pytest.mark.parametrize("output_option", ["--output", "--sbom"])
def test_scan_preflights_windows_efs_output_before_scan_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_option: str,
) -> None:
    """EFS reports must fail closed before scanning or creating a replacement."""
    test_file = tmp_path / "model.pkl"
    test_file.write_bytes(b"not a pickle")
    output_path = tmp_path / "report.json"
    output_path.write_text("sentinel")
    resolve_scan_paths = MagicMock(side_effect=AssertionError("scan path resolution must not start"))
    create_temp = MagicMock(side_effect=AssertionError("temporary output must not be created"))
    close_handle = MagicMock()

    monkeypatch.setattr(cli_module, "Path", type(tmp_path))
    monkeypatch.setattr(cli_module.os, "name", "nt")
    monkeypatch.setattr(cli_module, "_open_output_parent_directory", lambda _path: (output_path, None, 101))
    monkeypatch.setattr(
        cli_module,
        "_validate_existing_output_path",
        lambda *_args, **_kwargs: output_path.stat(),
    )
    monkeypatch.setattr(cli_module, "_open_windows_output_parent_lock", lambda *_args: 202)
    monkeypatch.setattr(
        cli_module,
        "_open_existing_output_file",
        lambda *_args, **_kwargs: os.open(output_path, os.O_WRONLY),
    )
    monkeypatch.setattr(
        cli_module,
        "_reject_windows_encrypted_output",
        MagicMock(side_effect=cli_module._OutputWriteError("EFS protection cannot be preserved")),
    )
    monkeypatch.setattr(cli_module, "_open_windows_output_temp_file", create_temp)
    monkeypatch.setattr(cli_module, "_close_windows_handle", close_handle)
    monkeypatch.setattr(cli_module, "_resolve_scan_paths", resolve_scan_paths)

    result = CliRunner().invoke(cli, ["scan", str(test_file), output_option, str(output_path), "--no-cache"])

    assert result.exit_code == 2
    assert "EFS protection cannot be preserved" in result.output
    resolve_scan_paths.assert_not_called()
    create_temp.assert_not_called()
    assert output_path.read_text() == "sentinel"
    assert [close_call.args for close_call in close_handle.call_args_list] == [(202,), (101,)]


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative staging is required")
def test_cli_report_writers_stage_new_output_in_private_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The installed temp source must live in a private directory distinct from the output parent."""
    output_path = tmp_path / "scanners.json"
    original_link = cli_module.os.link
    original_supports_dir_fd = cli_module.os.supports_dir_fd
    observed_stage_modes: list[int] = []

    def inspect_staging_then_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        assert src_dir_fd is not None
        assert dst_dir_fd is not None
        assert src_dir_fd != dst_dir_fd
        observed_stage_modes.append(stat.S_IMODE(os.fstat(src_dir_fd).st_mode))
        original_link(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(cli_module.os, "link", inspect_staging_then_link)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        {inspect_staging_then_link if function is original_link else function for function in original_supports_dir_fd},
    )

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert observed_stage_modes
    assert all(mode & 0o077 == 0 for mode in observed_stage_modes)
    assert json.loads(output_path.read_text())["scanners"]
    assert not list(tmp_path.glob(".modelaudit-output-*.tmp"))
    assert not list(tmp_path.glob(".modelaudit-output-*.probe"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative installation is required")
def test_cli_report_writers_do_not_replace_destination_created_during_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A destination created after validation must win instead of being overwritten."""
    output_path = tmp_path / "scanners.json"
    original_link = cli_module.os.link
    original_supports_dir_fd = cli_module.os.supports_dir_fd

    def create_destination_then_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        if destination != output_path.name:
            original_link(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
            return
        assert dst_dir_fd is not None
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dst_dir_fd)
        with os.fdopen(destination_fd, "w") as destination_file:
            destination_file.write("sentinel")
        original_link(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(cli_module.os, "link", create_destination_then_link)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        {
            create_destination_then_link if function is original_link else function
            for function in original_supports_dir_fd
        },
    )

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "Unable to write output" in result.output
    assert output_path.read_text() == "sentinel"
    assert not list(tmp_path.glob(".modelaudit-output-*.tmp"))


@pytest.mark.skipif(not hasattr(os, "setxattr"), reason="Extended attributes are unavailable")
def test_cli_report_writers_preserve_existing_xattrs(tmp_path: Path) -> None:
    """Overwriting an existing report must preserve its security metadata."""
    output_path = tmp_path / "scanners.json"
    output_path.write_text("stale")
    attribute_name = b"user.modelaudit_test"
    try:
        os.setxattr(output_path, attribute_name, b"keep")
    except OSError as exc:
        pytest.skip(f"Extended attributes are unsupported: {exc}")

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert os.getxattr(output_path, attribute_name) == b"keep"


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor metadata is required")
def test_copy_posix_output_metadata_preserves_security_xattrs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Atomic replacement must retain security and trusted xattr namespaces."""
    source_path = tmp_path / "source.json"
    target_path = tmp_path / "target.json"
    source_path.write_text("source")
    target_path.write_text("target")
    attribute_values = {
        "security.selinux": b"label",
        "trusted.modelaudit": b"trusted",
        "user.modelaudit": b"user",
    }
    copied: dict[str, bytes] = {}

    monkeypatch.setattr(cli_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli_module, "_posix_fd_has_extended_acl", lambda _path, _fd: False)
    monkeypatch.setattr(cli_module.os, "listxattr", lambda _fd: list(attribute_values), raising=False)
    monkeypatch.setattr(cli_module.os, "getxattr", lambda _fd, name: attribute_values[name], raising=False)
    monkeypatch.setattr(
        cli_module.os, "setxattr", lambda _fd, name, value: copied.__setitem__(name, value), raising=False
    )

    with source_path.open("rb") as source_file, target_path.open("r+b") as target_file:
        cli_module._copy_posix_output_metadata(
            str(source_path),
            source_file.fileno(),
            target_file.fileno(),
        )

    assert copied == attribute_values


def test_cli_report_writers_replace_hard_link_without_modifying_alias(tmp_path: Path) -> None:
    """Atomic replacement must leave an existing hard-link alias unchanged."""
    victim_path = tmp_path / "victim.txt"
    output_path = tmp_path / "scanners.json"
    victim_path.write_text("sentinel")
    output_path.hardlink_to(victim_path)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(output_path.read_text())["scanners"]
    assert victim_path.read_text() == "sentinel"
    assert not output_path.samefile(victim_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative staging is required")
def test_cli_report_writers_reject_unpreservable_extended_acl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An existing report must remain intact when its ACL cannot be preserved."""
    output_path = tmp_path / "scanners.json"
    output_path.write_text("sentinel")
    monkeypatch.setattr(cli_module, "_posix_fd_has_extended_acl", lambda _path, _fd: True)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "Unable to preserve extended output ACL" in result.output
    assert output_path.read_text() == "sentinel"


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors are required")
def test_directory_can_replace_entries_allows_darwin_root_without_acl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ordinary root-owned macOS aliases such as /tmp must remain usable."""
    monkeypatch.setattr(cli_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli_module, "_darwin_fd_has_extended_acl", lambda _fd: False)
    monkeypatch.setattr(Path, "stat", lambda _path: types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755))
    monkeypatch.setattr(cli_module.os, "open", lambda *_args, **_kwargs: 123)
    monkeypatch.setattr(cli_module.os, "close", lambda _fd: None)
    monkeypatch.setattr(cli_module.os, "access", lambda *_args, **_kwargs: False)

    assert not cli_module._directory_can_replace_entries(Path("/"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors are required")
def test_directory_can_replace_entries_rejects_darwin_extended_acl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hidden macOS ACL grant must make a symlink parent untrusted."""
    monkeypatch.setattr(cli_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli_module, "_darwin_fd_has_extended_acl", lambda _fd: True)

    assert cli_module._directory_can_replace_entries(Path("/"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX ACL metadata is required")
def test_directory_can_replace_entries_rejects_linux_access_acl_for_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A root-owned directory can still be replaceable through a POSIX ACL."""
    monkeypatch.setattr(cli_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(Path, "stat", lambda _path: types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755))
    monkeypatch.setattr(cli_module.os, "listxattr", lambda _path: ["system.posix_acl_access"], raising=False)
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 0)

    assert cli_module._directory_can_replace_entries(Path("/protected"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX sticky-directory semantics are required")
def test_sticky_directory_replacement_rejects_unowned_output(monkeypatch: pytest.MonkeyPatch) -> None:
    parent_stat = types.SimpleNamespace(st_mode=stat.S_IFDIR | stat.S_ISVTX | 0o777, st_uid=1001)
    output_stat = cast(os.stat_result, types.SimpleNamespace(st_uid=1002))
    monkeypatch.setattr(cli_module.os, "fstat", lambda _fd: parent_stat)
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 1003)

    with pytest.raises(cli_module._OutputWriteError, match=r"sticky directory.*Permission denied"):
        cli_module._validate_posix_output_replacement_permission("/tmp/report.json", 123, output_stat)


@pytest.mark.skipif(os.name != "posix", reason="POSIX sticky-directory semantics are required")
@pytest.mark.parametrize(
    ("effective_uid", "parent_uid", "output_uid"), [(0, 1001, 1002), (1001, 1001, 1002), (1002, 1001, 1002)]
)
def test_sticky_directory_replacement_allows_privileged_or_owned_output(
    monkeypatch: pytest.MonkeyPatch,
    effective_uid: int,
    parent_uid: int,
    output_uid: int,
) -> None:
    parent_stat = types.SimpleNamespace(st_mode=stat.S_IFDIR | stat.S_ISVTX | 0o777, st_uid=parent_uid)
    output_stat = cast(os.stat_result, types.SimpleNamespace(st_uid=output_uid))
    monkeypatch.setattr(cli_module.os, "fstat", lambda _fd: parent_stat)
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: effective_uid)

    cli_module._validate_posix_output_replacement_permission("/tmp/report.json", 123, output_stat)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative staging is required")
def test_cli_report_writers_do_not_disclose_output_through_late_hard_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hard link created after validation must retain only the old report content."""
    output_path = tmp_path / "scanners.json"
    alias_path = tmp_path / "late-alias.json"
    output_path.write_text("stale")
    original_rename = cli_module.os.rename
    original_supports_dir_fd = cli_module.os.supports_dir_fd

    def link_destination_then_rename(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        alias_path.hardlink_to(output_path)
        original_rename(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(cli_module.os, "rename", link_destination_then_rename)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        {
            link_destination_then_rename if function is original_rename else function
            for function in original_supports_dir_fd
        },
    )

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(output_path.read_text())["scanners"]
    assert alias_path.read_text() == "stale"
    assert not output_path.samefile(alias_path)


@pytest.mark.skipif(os.access not in os.supports_dir_fd, reason="Descriptor-relative access checks are required")
def test_cli_report_writers_check_permissions_through_open_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permission validation must use the same pinned parent as replacement."""
    output_path = tmp_path / "scanners.json"
    output_path.write_text("stale")
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    access_calls: list[tuple[str | Path, dict[str, object]]] = []
    original_access = cli_module.os.access
    supports_effective_ids = original_access in os.supports_effective_ids
    supports_follow_symlinks = original_access in os.supports_follow_symlinks

    def record_access(
        path: str | Path,
        mode: int,
        *,
        dir_fd: int | None = None,
        effective_ids: bool = False,
        follow_symlinks: bool = True,
    ) -> bool:
        access_calls.append(
            (
                path,
                {
                    "dir_fd": dir_fd,
                    "effective_ids": effective_ids,
                    "follow_symlinks": follow_symlinks,
                },
            )
        )
        return original_access(
            path,
            mode,
            dir_fd=dir_fd,
            effective_ids=effective_ids,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(cli_module.os, "access", record_access)
    monkeypatch.setattr(cli_module.os, "supports_dir_fd", {*os.supports_dir_fd, record_access})
    effective_id_functions = {record_access} if supports_effective_ids else set()
    follow_symlink_functions = {record_access} if supports_follow_symlinks else set()
    monkeypatch.setattr(cli_module.os, "supports_effective_ids", effective_id_functions)
    monkeypatch.setattr(cli_module.os, "supports_follow_symlinks", follow_symlink_functions)
    try:
        cli_module._validate_existing_output_path(str(output_path), output_path, parent_fd=parent_fd)
    finally:
        os.close(parent_fd)

    assert len(access_calls) == 1
    access_path, access_kwargs = access_calls[0]
    assert access_path == output_path.name
    assert access_kwargs["dir_fd"] == parent_fd
    assert access_kwargs["effective_ids"] is supports_effective_ids
    assert access_kwargs["follow_symlinks"] is (not supports_follow_symlinks)


def test_cli_report_writers_recheck_parent_links_on_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Fallback platforms must validate a parent swapped after the initial check."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    original_output_dir = tmp_path / "original-output"
    redirected_dir = tmp_path / "redirected"
    redirected_dir.mkdir()
    victim_path = redirected_dir / "scanners.json"
    victim_path.write_text("sentinel")
    output_path = output_dir / victim_path.name
    guard_handle = 123
    lock_handle = 456
    closed_handles: list[int] = []

    def swap_parent_then_open(path: str) -> tuple[Path, int | None, int | None]:
        opened_path = cli_module._validated_absolute_output_path(path)
        output_dir.rename(original_output_dir)
        output_dir.symlink_to(redirected_dir, target_is_directory=True)
        return opened_path, None, guard_handle

    monkeypatch.setattr(cli_module, "_open_output_parent_directory", swap_parent_then_open)
    monkeypatch.setattr(cli_module, "_open_windows_output_parent_lock", lambda *_args: lock_handle)
    monkeypatch.setattr(cli_module, "_close_windows_handle", closed_handles.append)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "Refusing to write output through symlink" in result.output
    assert victim_path.read_text() == "sentinel"
    assert not list(redirected_dir.glob(".scanners.json.*.tmp"))
    assert closed_handles == ([lock_handle, guard_handle] if os.name == "nt" else [guard_handle])


def test_cli_report_writers_do_not_truncate_late_hard_link_on_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A destination replaced after validation must not expose its inode to writes."""
    output_path = tmp_path / "scanners.json"
    victim_path = tmp_path / "victim.txt"
    victim_path.write_text("sentinel")
    original_validate = cli_module._validated_absolute_output_path
    validation_count = 0
    guard_handle = 123
    lock_handle = 456
    closed_handles: list[int] = []

    def install_hard_link_after_validation(path: str) -> Path:
        nonlocal validation_count
        validated_path = original_validate(path)
        validation_count += 1
        if validation_count == 2:
            output_path.hardlink_to(victim_path)
        return validated_path

    monkeypatch.setattr(
        cli_module,
        "_open_output_parent_directory",
        lambda path: (original_validate(path), None, guard_handle),
    )
    monkeypatch.setattr(cli_module, "_open_windows_output_parent_lock", lambda *_args: lock_handle)
    monkeypatch.setattr(cli_module, "_close_windows_handle", closed_handles.append)
    monkeypatch.setattr(cli_module, "_validated_absolute_output_path", install_hard_link_after_validation)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert victim_path.read_text() == "sentinel"
    assert output_path.samefile(victim_path)
    assert closed_handles == ([lock_handle, guard_handle] if os.name == "nt" else [guard_handle])


def test_cli_report_writers_keep_windows_parent_guard_through_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Windows parent guard must remain live until atomic installation finishes."""
    output_path = tmp_path / "scanners.json"
    guard_handle = 123
    lock_handle = 456
    closed_handles: list[int] = []

    monkeypatch.setattr(
        cli_module,
        "_open_output_parent_directory",
        lambda _path: (output_path, None, guard_handle),
    )
    monkeypatch.setattr(cli_module, "_open_windows_output_parent_lock", lambda *_args: lock_handle)
    monkeypatch.setattr(cli_module, "_close_windows_handle", closed_handles.append)

    if os.name == "nt":
        original_windows_replace = cli_module._replace_windows_output_file

        def guarded_windows_replace(
            output: str,
            temp_fd: int,
            destination_path: Path,
            *,
            replace_existing: bool,
        ) -> None:
            assert closed_handles == []
            original_windows_replace(
                output,
                temp_fd,
                destination_path,
                replace_existing=replace_existing,
            )

        monkeypatch.setattr(cli_module, "_replace_windows_output_file", guarded_windows_replace)
    else:
        original_replace = cli_module.os.replace

        def guarded_replace(source: Path, destination: Path) -> None:
            assert closed_handles == []
            original_replace(source, destination)

        monkeypatch.setattr(cli_module.os, "replace", guarded_replace)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert closed_handles == ([lock_handle, guard_handle] if os.name == "nt" else [guard_handle])
    assert json.loads(output_path.read_text())["scanners"]


@pytest.mark.parametrize(("replace_existing", "expected_flags"), [(False, 0), (True, 0x00000003)])
def test_windows_output_rename_uses_absolute_destination_path(
    monkeypatch: pytest.MonkeyPatch,
    replace_existing: bool,
    expected_flags: int,
) -> None:
    """The extended rename request must be absolute and allow a pinned target handle."""
    import ctypes.wintypes as wintypes

    captured: dict[str, object] = {}

    class FileRenameInfo(ctypes.Structure):
        _fields_ = [
            ("flags", wintypes.DWORD),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            ("file_name", wintypes.WCHAR * 1),
        ]

    class SetFileInformationByHandle:
        argtypes: tuple[object, ...] | None = None
        restype: object | None = None

        def __call__(
            self,
            _handle: int,
            information_class: int,
            buffer: ctypes.c_void_p,
            _buffer_size: int,
        ) -> bool:
            rename_info = ctypes.cast(buffer, ctypes.POINTER(FileRenameInfo)).contents
            captured["information_class"] = information_class
            captured["root_directory"] = rename_info.root_directory
            captured["flags"] = rename_info.flags
            captured["file_name_length"] = rename_info.file_name_length
            file_name_address = ctypes.addressof(rename_info) + FileRenameInfo.file_name.offset
            captured["file_name"] = ctypes.string_at(
                file_name_address,
                rename_info.file_name_length,
            ).decode("utf-16-le")
            return True

    set_file_information = SetFileInformationByHandle()
    kernel32 = types.SimpleNamespace(SetFileInformationByHandle=set_file_information)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setitem(sys.modules, "msvcrt", types.SimpleNamespace(get_osfhandle=lambda fd: fd))

    destination_path = Path(r"C:\reports\output.txt")
    cli_module._replace_windows_output_file(
        str(destination_path),
        123,
        destination_path,
        replace_existing=replace_existing,
    )

    assert captured == {
        "information_class": 22,
        "root_directory": None,
        "flags": expected_flags,
        "file_name_length": len(str(destination_path).encode("utf-16-le")),
        "file_name": str(destination_path),
    }


def test_windows_existing_output_open_checks_dacl_write_and_metadata_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existing reports need DACL-enforced write, replace, and metadata access."""
    captured: dict[str, object] = {}

    class CreateFileW:
        argtypes: tuple[object, ...] | None = None
        restype: object | None = None

        def __call__(
            self,
            path: str,
            desired_access: int,
            share_mode: int,
            _security_attributes: object,
            creation_disposition: int,
            flags: int,
            _template: object,
        ) -> int:
            captured.update(
                path=path,
                desired_access=desired_access,
                share_mode=share_mode,
                creation_disposition=creation_disposition,
                flags=flags,
            )
            return 321

    def open_osfhandle(handle: int, flags: int) -> int:
        captured["handle"] = handle
        captured["os_flags"] = flags
        return 7

    create_file = CreateFileW()
    kernel32 = types.SimpleNamespace(CreateFileW=create_file)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setitem(sys.modules, "msvcrt", types.SimpleNamespace(open_osfhandle=open_osfhandle))

    destination_path = Path(r"C:\reports\output.txt")
    output_fd = cli_module._open_windows_existing_output_file(str(destination_path), destination_path)

    assert output_fd == 7
    assert captured == {
        "path": str(destination_path),
        "desired_access": 0x0002 | 0x0080 | 0x00020000 | 0x00010000,
        "share_mode": 0x00000001 | 0x00000002 | 0x00000004,
        "creation_disposition": 3,
        "flags": 0x00200000,
        "handle": 321,
        "os_flags": os.O_WRONLY | getattr(os, "O_BINARY", 0),
    }


@pytest.mark.parametrize(
    ("preserve_security", "expected_security_access"),
    [(False, 0), (True, 0x00040000 | 0x00080000)],
)
def test_windows_output_temp_file_uses_minimum_access_and_normal_attributes(
    monkeypatch: pytest.MonkeyPatch,
    preserve_security: bool,
    expected_security_access: int,
) -> None:
    """Published Windows reports must not retain FILE_ATTRIBUTE_TEMPORARY."""
    captured: dict[str, object] = {}

    class CreateFileW:
        argtypes: tuple[object, ...] | None = None
        restype: object | None = None

        def __call__(
            self,
            path: str,
            desired_access: int,
            share_mode: int,
            _security_attributes: object,
            creation_disposition: int,
            flags: int,
            _template: object,
        ) -> int:
            captured.update(
                path=path,
                desired_access=desired_access,
                share_mode=share_mode,
                creation_disposition=creation_disposition,
                flags=flags,
            )
            return 321

    create_file = CreateFileW()
    kernel32 = types.SimpleNamespace(CreateFileW=create_file)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setitem(
        sys.modules,
        "msvcrt",
        types.SimpleNamespace(open_osfhandle=lambda handle, flags: captured.update(handle=handle, os_flags=flags) or 7),
    )

    destination_path = Path(r"C:\reports\output.txt")
    temp_fd, temp_path = cli_module._open_windows_output_temp_file(
        str(destination_path),
        destination_path,
        ".modelaudit-output.tmp",
        preserve_security=preserve_security,
    )

    assert temp_fd == 7
    assert temp_path == destination_path.parent / ".modelaudit-output.tmp"
    assert captured == {
        "path": str(temp_path),
        "desired_access": 0x40000000 | 0x00010000 | 0x0080 | expected_security_access,
        "share_mode": 0,
        "creation_disposition": 1,
        "flags": 0x00000080,
        "handle": 321,
        "os_flags": os.O_WRONLY | getattr(os, "O_BINARY", 0),
    }


@pytest.mark.parametrize(("file_attributes", "expected"), [(0, False), (0x00004000, True)])
def test_windows_output_encryption_state_comes_from_pinned_handle(
    monkeypatch: pytest.MonkeyPatch,
    file_attributes: int,
    expected: bool,
) -> None:
    """EFS preservation must inspect the opened file rather than its path."""
    monkeypatch.setattr(
        cli_module.os,
        "fstat",
        lambda fd: types.SimpleNamespace(fd=fd, st_file_attributes=file_attributes),
    )

    assert cli_module._windows_output_is_encrypted(17) is expected


def test_windows_output_rejects_efs_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    """Atomic replacement must not silently replace EFS recipient metadata."""
    monkeypatch.setattr(cli_module, "_windows_output_is_encrypted", lambda _fd: True)

    with pytest.raises(cli_module._OutputWriteError, match="EFS protection cannot be preserved"):
        cli_module._reject_windows_encrypted_output("output.txt", 17)


def test_windows_output_security_preserves_owner_group_and_protected_dacl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Atomic replacement must preserve ownership, DACL, and inheritance state."""
    import ctypes.wintypes as wintypes

    captured: dict[str, object] = {}

    class GetSecurityInfo:
        argtypes: tuple[object, ...] | None = None
        restype: object | None = None

        def __call__(
            self,
            source_handle: int,
            object_type: int,
            security_information: int,
            owner: Any,
            group: Any,
            dacl: Any,
            _sacl: Any,
            descriptor: Any,
        ) -> int:
            captured["get"] = (source_handle, object_type, security_information)
            ctypes.cast(owner, ctypes.POINTER(wintypes.LPVOID)).contents.value = 11
            ctypes.cast(group, ctypes.POINTER(wintypes.LPVOID)).contents.value = 22
            ctypes.cast(dacl, ctypes.POINTER(wintypes.LPVOID)).contents.value = 33
            ctypes.cast(descriptor, ctypes.POINTER(wintypes.LPVOID)).contents.value = 44
            return 0

    class GetSecurityDescriptorControl:
        argtypes: tuple[object, ...] | None = None
        restype: object | None = None

        def __call__(self, descriptor: Any, control: Any, revision: Any) -> bool:
            captured["descriptor"] = ctypes.cast(descriptor, wintypes.LPVOID).value
            ctypes.cast(control, ctypes.POINTER(wintypes.WORD)).contents.value = 0x1000
            ctypes.cast(revision, ctypes.POINTER(wintypes.DWORD)).contents.value = 1
            return True

    class SetSecurityInfo:
        argtypes: tuple[object, ...] | None = None
        restype: object | None = None

        def __call__(
            self,
            target_handle: int,
            object_type: int,
            security_information: int,
            owner: Any,
            group: Any,
            dacl: Any,
            _sacl: Any,
        ) -> int:
            captured["set"] = (
                target_handle,
                object_type,
                security_information,
                owner.value,
                group.value,
                dacl.value,
            )
            return 0

    class LocalFree:
        argtypes: tuple[object, ...] | None = None
        restype: object | None = None

        def __call__(self, descriptor: Any) -> None:
            captured["freed"] = descriptor.value

    advapi32 = types.SimpleNamespace(
        GetSecurityInfo=GetSecurityInfo(),
        GetSecurityDescriptorControl=GetSecurityDescriptorControl(),
        SetSecurityInfo=SetSecurityInfo(),
    )
    kernel32 = types.SimpleNamespace(LocalFree=LocalFree())
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, **_kwargs: advapi32 if name == "advapi32" else kernel32,
        raising=False,
    )
    monkeypatch.setitem(sys.modules, "msvcrt", types.SimpleNamespace(get_osfhandle=lambda fd: fd + 1000))

    cli_module._copy_windows_output_security("output.txt", 5, 6)

    assert captured == {
        "get": (1005, 1, 0x00000001 | 0x00000002 | 0x00000004),
        "descriptor": 44,
        "set": (
            1006,
            1,
            0x00000001 | 0x00000002 | 0x00000004 | 0x80000000,
            11,
            22,
            33,
        ),
        "freed": 44,
    }


def test_cli_report_writers_fail_closed_without_secure_parent_primitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown path-only platforms must not silently use a racy replacement."""
    output_path = tmp_path / "scanners.json"
    monkeypatch.setattr(cli_module.os, "name", "unsupported")
    monkeypatch.setattr(cli_module, "_validated_absolute_output_path", lambda _path: output_path)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "Secure output writes are unsupported" in result.output
    assert not output_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory sharing semantics are required")
@pytest.mark.parametrize("output_name", ["scanners.json", "x"])
def test_cli_report_writers_windows_guard_blocks_final_parent_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_name: str,
) -> None:
    """The retained child lock must block the final parent-swap window."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    renamed_dir = tmp_path / "renamed"
    output_path = output_dir / output_name
    original_replace = cli_module._replace_windows_output_file

    def attempt_parent_swap(
        output: str,
        temp_fd: int,
        destination_path: Path,
        *,
        replace_existing: bool,
    ) -> None:
        with pytest.raises(OSError):
            output_dir.rename(renamed_dir)
        original_replace(
            output,
            temp_fd,
            destination_path,
            replace_existing=replace_existing,
        )

    monkeypatch.setattr(cli_module, "_replace_windows_output_file", attempt_parent_swap)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(output_path.read_text())["scanners"]


@pytest.mark.skipif(os.name != "nt", reason="Windows native replacement semantics are required")
def test_cli_report_writers_windows_atomically_overwrite_existing_output(tmp_path: Path) -> None:
    """Windows must request replacement only for the validated existing destination."""
    output_path = tmp_path / "scanners.json"
    output_path.write_text("stale")

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(output_path.read_text())["scanners"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes are required")
def test_cli_report_writers_fail_closed_for_write_only_parent_without_search_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A platform without a searchable directory handle must fail closed."""
    output_dir = tmp_path / "write-only"
    output_dir.mkdir()
    output_path = output_dir / "scanners.json"
    monkeypatch.setattr(cli_module.os, "O_PATH", 0, raising=False)
    monkeypatch.setattr(cli_module.os, "O_SEARCH", 0, raising=False)
    output_dir.chmod(0o333)
    try:
        result = CliRunner().invoke(
            cli,
            ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
        )
    finally:
        output_dir.chmod(0o700)

    assert result.exit_code == 2
    assert "Unable to write output" in result.output
    assert not output_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX component limits are required")
def test_cli_report_writers_support_long_valid_output_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The private temporary name must not make a valid destination too long."""
    output_path = tmp_path / f"{'r' * 240}.json"
    monkeypatch.setattr(cli_module.os, "O_PATH", 0, raising=False)
    monkeypatch.setattr(cli_module.os, "O_SEARCH", 0, raising=False)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(output_path.read_text())["scanners"]


@pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="An unprivileged POSIX user is required",
)
def test_cli_report_writers_preserve_read_only_output(tmp_path: Path) -> None:
    """Atomic replacement must not bypass an existing file's write permission."""
    output_path = tmp_path / "scanners.json"
    output_path.write_text("sentinel")
    output_path.chmod(0o444)
    try:
        result = CliRunner().invoke(
            cli,
            ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
        )
    finally:
        output_path.chmod(0o600)

    assert result.exit_code == 2
    assert "Permission denied" in result.output
    assert output_path.read_text() == "sentinel"


@pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="An unprivileged POSIX user is required",
)
def test_cli_report_writers_fail_closed_in_read_only_directory(tmp_path: Path) -> None:
    """Atomic replacement must not fall back to writing through the destination inode."""
    output_dir = tmp_path / "read-only-directory"
    output_dir.mkdir()
    output_path = output_dir / "scanners.json"
    output_path.write_text("sentinel")
    output_path.chmod(0o600)
    output_dir.chmod(0o500)
    try:
        result = CliRunner().invoke(
            cli,
            ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
        )
    finally:
        output_dir.chmod(0o700)

    assert result.exit_code == 2
    assert output_path.read_text() == "sentinel"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable on this platform")
def test_cli_report_writers_reject_fifo_output_without_blocking(tmp_path: Path) -> None:
    """A special-file output must fail closed instead of blocking or writing to it."""
    output_path = tmp_path / "report.fifo"
    os.mkfifo(output_path)

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "Unable to write output" in result.output or "non-regular file" in result.output


def test_scan_cleans_temp_artifacts_when_sbom_output_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An output refusal must not bypass deferred scan cleanup."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")
    cleanup = MagicMock()
    record_failure = MagicMock()
    flush = MagicMock()

    def reject_sbom(*_args: object, **_kwargs: object) -> None:
        raise cli_module._OutputWriteError("refused test SBOM")

    monkeypatch.setattr(cli_module, "_write_scan_sbom", reject_sbom)
    monkeypatch.setattr(cli_module, "_cleanup_temp_artifacts", cleanup)
    monkeypatch.setattr(cli_module, "record_scan_failed", record_failure)
    monkeypatch.setattr(cli_module, "flush_telemetry", flush)

    result = CliRunner().invoke(
        cli,
        ["scan", str(test_file), "--sbom", str(tmp_path / "sbom.json"), "--no-cache"],
    )

    assert result.exit_code == 2
    assert "refused test SBOM" in result.output
    cleanup.assert_called_once()
    record_failure.assert_called_once()
    flush.assert_called_once()


def test_cli_report_writers_create_regular_output_files(tmp_path: Path) -> None:
    """Normal report output paths should still be created and overwritten."""
    model_tree = tmp_path / "model_tree"
    model_tree.mkdir()
    test_file = model_tree / "test_file.dat"
    test_file.write_bytes(b"test content")

    report_file = model_tree / "report.json"
    sbom_file = model_tree / "sbom.json"
    metadata_file = model_tree / "metadata.json"

    runner = CliRunner()
    scan_result = runner.invoke(
        cli,
        ["scan", str(test_file), "--format", "json", "--output", str(report_file), "--no-cache"],
    )
    sbom_result = runner.invoke(cli, ["scan", str(test_file), "--sbom", str(sbom_file), "--no-cache"])
    metadata_result = runner.invoke(
        cli,
        ["metadata", str(test_file), "--format", "json", "--output", str(metadata_file)],
    )
    catalog_file = model_tree / "scanners.json"
    catalog_result = runner.invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(catalog_file)],
    )

    assert scan_result.exit_code == 0, scan_result.output
    assert sbom_result.exit_code == 0, sbom_result.output
    assert metadata_result.exit_code == 0, metadata_result.output
    assert catalog_result.exit_code == 0, catalog_result.output
    assert json.loads(report_file.read_text())["files_scanned"] == 1
    assert json.loads(sbom_file.read_text())["bomFormat"] == "CycloneDX"
    assert json.loads(metadata_file.read_text())["file"] == test_file.name
    assert json.loads(catalog_file.read_text())["scanners"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are required")
def test_cli_report_writers_atomically_overwrite_regular_file_and_preserve_mode(tmp_path: Path) -> None:
    """A normal existing output should be replaced without changing its access mode."""
    output_path = tmp_path / "scanners.json"
    output_path.write_text("stale")
    output_path.chmod(0o640)
    original_inode = output_path.stat().st_ino

    result = CliRunner().invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json", "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(output_path.read_text())["scanners"]
    assert output_path.stat().st_ino != original_inode
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o640


def test_scan_output_utf8_locale(tmp_path):
    """Ensure output file is valid UTF-8 even with ASCII locale."""
    test_file = tmp_path / "utf8_test.dat"
    test_file.write_bytes(b"test content")

    output_file = tmp_path / "output.txt"

    runner = CliRunner()
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C"})
    runner.invoke(cli, ["scan", str(test_file), "--output", str(output_file)], env=env)

    assert output_file.exists()
    try:
        output_file.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        pytest.fail("Output file is not valid UTF-8")


def test_scan_sbom_utf8_locale(tmp_path):
    """Ensure SBOM file is valid UTF-8 even with ASCII locale."""
    test_file = tmp_path / "utf8_test.dat"
    test_file.write_bytes(b"test content")

    sbom_file = tmp_path / "sbom.json"

    runner = CliRunner()
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C"})
    runner.invoke(cli, ["scan", str(test_file), "--sbom", str(sbom_file)], env=env)

    assert sbom_file.exists()
    try:
        sbom_file.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        pytest.fail("SBOM file is not valid UTF-8")


def test_scan_verbose_mode(tmp_path):
    """Test scanning in verbose mode."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    # Use catch_exceptions=True to handle any errors in the CLI
    result = runner.invoke(
        cli,
        ["scan", str(test_file), "--verbose"],
        catch_exceptions=True,
    )

    # In verbose mode, we should see more output
    # With automatic defaults and new output format, check for successful completion
    assert result.output  # Should have some output
    assert result.exit_code == 0  # Should complete successfully
    # New output format may not contain "Scanning" text


def test_scan_max_file_size(tmp_path):
    """Test scanning with max file size limit."""
    # Create a file larger than our limit
    test_file = tmp_path / "large_file.dat"
    test_file.write_bytes(b"x" * 1000)  # 1000 bytes

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            str(test_file),
            "--max-size",
            "500",  # 500 bytes limit
        ],
        catch_exceptions=True,
    )

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    # Note: JSON output format doesn't include file paths
    assert "500" in result.output or "File too large" in result.output  # Should mention the max file size or error


@pytest.mark.parametrize(
    "cloud_url",
    [
        "s3://bucket/model.bin",
        "r2://bucket/model.bin",
        "gcs://bucket/model.bin",
        "https://bucket.s3.amazonaws.com/model.bin",
        "https://storage.googleapis.com/bucket/model.bin",
        "https://account.r2.cloudflarestorage.com/bucket/model.bin",
    ],
)
def test_cloud_auto_size_limit_applies_to_download_budget(tmp_path: Path, cloud_url: str) -> None:
    runtime = _resolve_scan_runtime_config(
        [cloud_url],
        format="json",
        output=None,
        timeout=None,
        max_size=None,
        cache_dir=str(tmp_path / "cache"),
        progress=False,
        no_cache=False,
        no_whitelist=False,
        stream=False,
        strict=False,
        verbose=False,
        quiet=True,
        scanners=(),
        exclude_scanners=(),
        suppress=(),
        severity=(),
        scan_start_time=0.0,
    )

    assert runtime.max_file_size == 50 * 1024 * 1024 * 1024
    assert runtime.max_download_bytes == runtime.max_file_size
    assert runtime.explicit_max_download_bytes is None


def test_format_text_output():
    """Test the format_text_output function."""
    # Create a sample results dictionary
    results = {
        "path": "/path/to/model",
        "files_scanned": 5,
        "bytes_scanned": 1024,
        "duration": 0.5,
        "issues": [
            {
                "message": "Test issue",
                "severity": "warning",
                "location": "test.pkl",
                "details": {"test": "value"},
            },
        ],
        "has_errors": False,
    }

    # Test normal output
    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "Files:" in clean_output and "5" in clean_output
    assert "Test issue" in clean_output
    assert "warning" in clean_output.lower()

    # Test verbose output
    output = format_text_output(results, verbose=True)
    clean_output = strip_ansi(output)
    assert "Files:" in clean_output and "5" in clean_output
    assert "Test issue" in clean_output
    assert "warning" in clean_output.lower()
    # Verbose might include details, but we can't guarantee it


def test_format_text_output_escapes_terminal_controls_in_issues(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [
            {
                "message": "unsafe\x1b[2Jtitle\x07",
                "severity": "warning",
                "location": "archive.zip\nFORGED",
                "why": "why\ttext",
                "details": {"detail\x7fkey": "value\rnext"},
            },
        ],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=True)

    assert "\x1b[2J" not in output
    assert "\x07" not in output
    assert "\x7f" not in output
    assert "archive.zip\nFORGED" not in output
    assert "value\rnext" not in output
    assert "unsafe\\x1b[2Jtitle\\x07" in output
    assert "archive.zip\\nFORGED" in output
    assert "why\\ttext" in output
    assert "detail\\x7fkey:" in output
    assert "value\\rnext" in output


def test_format_text_output_escapes_terminal_controls_in_failed_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "total_checks": 1,
        "passed_checks": 0,
        "failed_checks": 1,
        "checks": [
            {
                "status": "failed",
                "name": "Member\x1bName",
                "message": "bad\r\nline",
            },
        ],
        "issues": [],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)

    assert "\x1bName" not in output
    assert "bad\r\nline" not in output
    assert "Member\\x1bName: bad\\r\\nline" in output


def test_format_text_output_escapes_unicode_controls_and_preserves_missing_location(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    results = {
        "files_scanned": 1,
        "issues": [
            {
                "message": "hidden\u200djoiner\U000e0001tag",
                "severity": "warning",
                "location": None,
            },
        ],
        "has_errors": False,
    }

    output = format_text_output(results)

    assert "[None]" not in output
    assert "\u200d" not in output
    assert "\U000e0001" not in output
    assert "hidden\\u200djoiner\\U000e0001tag" in output


def test_format_text_output_escapes_untrusted_model_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    results = {
        "files_scanned": 1,
        "file_metadata": {
            "config.json": {
                "model_info": {
                    "model_type": "bert\x1b[2J",
                    "architectures": ["Safe", "Spoof\u202eName"],
                    "num_layers": "12\nFORGED",
                    "hidden_size": "768\u200bhidden",
                    "vocab_size": "oops\x07",
                    "framework_version": "4.0\rnext",
                },
            },
        },
        "issues": [],
        "has_errors": False,
    }

    output = format_text_output(results)

    assert "bert\\x1b[2J" in output
    assert "Safe, Spoof\\u202eName" in output
    assert "12\\nFORGED" in output
    assert "768\\u200bhidden" in output
    assert "oops\\x07" in output
    assert "4.0\\rnext" in output


def test_display_helpers_escape_terminal_controls() -> None:
    path = "model\x1b[2J\u202efile.pkl"
    error = RuntimeError("failed\nFORGED\u200btext")

    assert _display_path(path) == "model\\x1b[2J\\u202efile.pkl"
    assert _display_error(error, path) == "failed\\nFORGED\\u200btext"


def test_display_scan_path_preserves_exact_local_path_for_reports() -> None:
    path = "model\nname\u202e.pkl"

    assert _display_scan_path(path) == path
    assert _display_path(path) == "model\\nname\\u202e.pkl"


def test_metadata_terminal_messages_escape_controls(tmp_path: Path) -> None:
    model_path = tmp_path / "model.bin"
    model_path.write_bytes(b"model")
    output_path = tmp_path / "metadata\nFORGED.json"

    with (
        patch("modelaudit.metadata_extractor.ModelMetadataExtractor.extract", return_value={}),
        patch("modelaudit.cli._write_output_text_file") as mock_write_output,
    ):
        result = CliRunner().invoke(
            cli,
            ["metadata", str(model_path), "--format", "json", "--output", str(output_path)],
        )

    assert result.exit_code == 0, result.output
    assert mock_write_output.call_args.args[0] == str(output_path)
    assert "metadata\\nFORGED.json" in result.output
    assert "\nFORGED" not in result.output

    with patch(
        "modelaudit.metadata_extractor.ModelMetadataExtractor.extract",
        side_effect=RuntimeError("failed\nFORGED\x1b[2J"),
    ):
        error_result = CliRunner().invoke(cli, ["metadata", str(model_path)])

    assert error_result.exit_code == 1
    assert "failed\\nFORGED\\x1b[2J" in error_result.output
    assert "\nFORGED" not in error_result.output
    assert "\x1b" not in error_result.output


def test_skipped_path_and_suppression_messages_escape_terminal_controls(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    runtime = cast(
        Any,
        types.SimpleNamespace(skip_non_model_files=True, show_styled_output=True),
    )

    skipped_path = tmp_path / "skip\x1b[2J.py"

    with patch("modelaudit.cli._local_path_will_be_scanned", return_value=False):
        assert cli_module._should_skip_non_model_file(str(skipped_path), runtime, verbose=True)
    cli_module._announce_suppressed_preferred_scanners(
        [{"location": "archive\nFORGED.pkl", "scanner_id": "pickle\u202escanner"}]
    )

    captured = capsys.readouterr()
    assert "Skipping non-model file:" in captured.out
    assert "skip\\x1b[2J.py" in captured.out
    assert "archive\\nFORGED.pkl" in captured.err
    assert "pickle\\u202escanner" in captured.err


def test_format_metadata_table_escapes_untrusted_values() -> None:
    single_output = cli_module._format_metadata_table(
        {
            "file": "model\x1b[2J.onnx",
            "format": "onnx\u202e",
            "file_size": "unknown\nFORGED",
            "producer\u200bname": "tool\x07",
            "metadata": {"key\rnext": "value\u2066hidden"},
            "tags": ["safe", "tag\U000e0001hidden"],
        }
    )
    directory_output = cli_module._format_metadata_table(
        {
            "directory": "models\nFORGED",
            "summary": {"total_files": 1, "formats": {"gguf\u202e": 1}},
            "files": [
                {
                    "file": "bad\x1b[2J.gguf",
                    "error": "decode\rfailed",
                }
            ],
        }
    )

    assert "model\\x1b[2J.onnx" in single_output
    assert "onnx\\u202e" in single_output
    assert "unknown\\nFORGED" in single_output
    assert "Producer\\u200bName: tool\\x07" in single_output
    assert "key\\rnext: value\\u2066hidden" in single_output
    assert "tag\\U000e0001hidden" in single_output
    assert "models\\nFORGED" in directory_output
    assert "gguf\\u202e: 1" in directory_output
    assert "bad\\x1b[2J.gguf (error: decode\\rfailed)" in directory_output


def test_format_text_output_only_debug_issues():
    """Ensure debug-only issues result in a success status."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [
            {"message": "Debug info", "severity": "debug", "location": "file.pkl"},
        ],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "No security issues detected" in clean_output
    assert "NO ISSUES FOUND" in clean_output


def test_format_text_output_operational_errors_status():
    """Ensure operational errors are surfaced in final text status."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [],
        "has_errors": True,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "SCAN COMPLETED WITH OPERATIONAL ERRORS" in clean_output
    assert "NO ISSUES FOUND" not in clean_output


def test_format_text_output_complete_benign_scan_remains_clean() -> None:
    """Fully covered benign scans should keep the clean text status."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [],
        "file_metadata": {"model.pkl": {"scan_outcome_reasons": []}},
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "No security issues detected" in clean_output
    assert "NO ISSUES FOUND" in clean_output
    assert "Incomplete security coverage" not in clean_output


def test_format_text_output_incomplete_coverage_without_findings_is_not_clean() -> None:
    """Incomplete coverage without findings should not be presented as a clean scan."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [],
        "file_metadata": {
            "model.bin": {
                "analysis_incomplete": True,
                "scan_outcome_reasons": ["bounded_probe_exhausted"],
            },
        },
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "Incomplete security coverage" in clean_output
    assert "bounded_probe_exhausted" in clean_output
    assert "SCAN COVERAGE INCOMPLETE" in clean_output
    assert "No security issues detected" not in clean_output
    assert "NO ISSUES FOUND" not in clean_output


def test_format_text_output_incomplete_coverage_with_security_findings_is_explicit() -> None:
    """Security findings should remain visible when coverage is incomplete."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [
            {"message": "Dangerous pickle global", "severity": "warning", "location": "model.pkl"},
        ],
        "file_metadata": {"model.pkl": {"scan_outcome": "inconclusive"}},
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "Dangerous pickle global" in clean_output
    assert "Incomplete security coverage" in clean_output
    assert "WARNINGS DETECTED; COVERAGE INCOMPLETE" in clean_output
    assert "NO ISSUES FOUND" not in clean_output


def test_format_text_output_issue_only_incomplete_coverage_without_findings_is_not_clean() -> None:
    """Issue details should surface incomplete coverage even without file metadata."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [
            {
                "message": "DVC output limit exceeded - not all declared outputs were scanned",
                "severity": "info",
                "location": "model.dvc",
                "type": "dvc_output_limit_exceeded",
                "details": {
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "reason": "dvc_output_limit_exceeded",
                },
            },
        ],
        "checks": [],
        "file_metadata": {},
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "Incomplete security coverage" in clean_output
    assert "model.dvc: dvc_output_limit_exceeded" in clean_output
    assert "SCAN COVERAGE INCOMPLETE" in clean_output
    assert "No security issues detected" not in clean_output
    assert "NO ISSUES FOUND" not in clean_output


def test_format_text_output_check_only_incomplete_coverage_without_findings_is_not_clean() -> None:
    """Check details should surface incomplete coverage even without file metadata."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [],
        "checks": [
            {
                "name": "DVC Output Resolution",
                "status": "failed",
                "message": "DVC output resolution incomplete",
                "severity": "info",
                "location": "model.dvc",
                "details": {"analysis_incomplete": True, "scan_outcome_reason": "dvc_analysis_incomplete"},
            },
        ],
        "file_metadata": {},
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "Incomplete security coverage" in clean_output
    assert "model.dvc: dvc_analysis_incomplete" in clean_output
    assert "SCAN COVERAGE INCOMPLETE" in clean_output
    assert "No security issues detected" not in clean_output
    assert "NO ISSUES FOUND" not in clean_output


def test_format_text_output_consolidated_check_incomplete_coverage_is_not_clean() -> None:
    """Consolidated check findings should still surface incomplete coverage."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [],
        "checks": [
            {
                "name": "DVC Output Resolution",
                "status": "failed",
                "message": "DVC output resolution incomplete",
                "severity": "info",
                "location": "model.dvc",
                "details": {
                    "component_count": 2,
                    "findings": [
                        {"analysis_incomplete": True, "scan_outcome_reason": "dvc_output_limit_exceeded"},
                        {"component": "covered-sibling"},
                    ],
                },
            },
        ],
        "file_metadata": {},
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "Incomplete security coverage" in clean_output
    assert "model.dvc: dvc_output_limit_exceeded" in clean_output
    assert "SCAN COVERAGE INCOMPLETE" in clean_output
    assert "No security issues detected" not in clean_output
    assert "NO ISSUES FOUND" not in clean_output


def test_format_text_output_issue_only_incomplete_coverage_with_security_findings_is_explicit() -> None:
    """Issue-only coverage gaps should not hide security findings."""
    results = {
        "files_scanned": 2,
        "bytes_scanned": 20,
        "duration": 0.1,
        "issues": [
            {
                "message": "DVC output resolution incomplete",
                "severity": "info",
                "location": "model.dvc",
                "details": {"analysis_incomplete": True, "scan_outcome_reason": "dvc_analysis_incomplete"},
            },
            {"message": "Dangerous pickle global", "severity": "warning", "location": "payload.pkl"},
        ],
        "file_metadata": {},
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "Dangerous pickle global" in clean_output
    assert "Incomplete security coverage" in clean_output
    assert "WARNINGS DETECTED; COVERAGE INCOMPLETE" in clean_output
    assert "NO ISSUES FOUND" not in clean_output


def test_text_cli_incomplete_coverage_path_status_is_not_clean(tmp_path: Path) -> None:
    """Per-path CLI progress should not call an incomplete scan clean."""
    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"weights")
    mock_result = create_initial_audit_result()
    mock_result.files_scanned = 1
    mock_result.bytes_scanned = len(b"weights")
    mock_result.success = False
    mock_result.file_metadata[str(test_file)] = FileMetadataModel(
        analysis_incomplete=True,
        scan_outcome_reasons=["bounded_probe_exhausted"],
    )

    runner = CliRunner()
    with patch("modelaudit.cli.scan_model_directory_or_file", return_value=mock_result):
        result = runner.invoke(
            cli,
            ["scan", str(test_file), "--format", "text", "--no-cache"],
            catch_exceptions=False,
        )

    clean_output = strip_ansi(result.output)
    assert result.exit_code == 2
    assert f"Scanned {test_file}: Coverage incomplete" in clean_output
    assert f"Scanned {test_file}: Clean" not in clean_output
    assert "No security issues detected" not in clean_output
    assert "SCAN COVERAGE INCOMPLETE" in clean_output


def test_format_text_output_only_info_issues():
    """Ensure info-only issues result in a success status."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [
            {"message": "Info message", "severity": "info", "location": "file.pkl"},
        ],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "1 Info" in clean_output
    assert "INFORMATIONAL FINDINGS" in clean_output  # Info issues show INFORMATIONAL FINDINGS
    assert "WARNINGS DETECTED" not in clean_output


def test_format_text_output_debug_and_info_issues():
    """Ensure debug and info issues (no warnings) result in a success status."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [
            {"message": "Debug info", "severity": "debug", "location": "file1.pkl"},
            {"message": "Info message", "severity": "info", "location": "file2.pkl"},
        ],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=True)
    clean_output = strip_ansi(output)
    assert "1 Info" in clean_output
    assert "1 Debug" in clean_output
    assert "INFORMATIONAL FINDINGS" in clean_output  # Info issues show INFORMATIONAL FINDINGS
    assert "WARNINGS DETECTED" not in clean_output


def test_format_text_output_fast_scan_duration():
    """Test duration formatting for very fast scans (< 0.01 seconds)."""
    results = {
        "path": "/path/to/model",
        "files_scanned": 1,
        "bytes_scanned": 512,
        "duration": 0.005,  # Very fast scan < 0.01 seconds
        "issues": [],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)

    # Should show 3 decimal places for very fast scans
    assert "Duration:" in clean_output and "0.005s" in clean_output
    assert "Files:" in clean_output and "1" in clean_output
    assert "No security issues detected" in clean_output


def test_scan_huggingface_url_help():
    """Test that HuggingFace URL examples are in the help text."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "hf://user/llama" in result.output  # Updated to new example format
    assert "s3://bucket/models/" in result.output
    assert "models:/model/v1" in result.output


def test_scan_jfrog_url_help():
    """Test that JFrog authentication is mentioned in the help text."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "JFROG_API_TOKEN" in result.output  # Updated to check for auth info instead of URL example


def test_scan_mlflow_url_help():
    """Test that MLflow URL examples are in the help text."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "models:/model/v1" in result.output  # Updated to match new example format
    assert "MLFLOW_TRACKING_URI" in result.output  # Check for auth info


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_huggingface_url_success(mock_rmtree, mock_scan, mock_download, mock_is_hf_url, tmp_path):
    """Test successful scanning of a HuggingFace URL."""
    # Setup mocks
    mock_is_hf_url.return_value = True
    # Create a real temp directory for the test
    test_model_dir = tmp_path / "test_model"
    test_model_dir.mkdir()
    # Create a dummy file inside to make it look like a real model
    (test_model_dir / "model.bin").write_text("dummy model")

    mock_download.return_value = test_model_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=1024, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "--format", "text", "https://huggingface.co/test/model"])

    # Should succeed
    assert result.exit_code == 0
    # With automatic defaults and new output format, check for successful completion
    assert (
        "SCAN SUMMARY" in result.output
        or "Files:" in result.output
        or "Duration:" in result.output
        or "Clean" in result.output
        or "Downloaded" in result.output
    )

    # Verify download was called
    mock_download.assert_called_once()

    # Verify scan was called with downloaded path
    mock_scan.assert_called_once()
    call_args = mock_scan.call_args
    assert call_args[0][0] == str(test_model_dir)
    provenance = call_args.kwargs["_trusted_source_provenance"]
    assert provenance.model_id == "test/model"
    assert provenance.model_source == "huggingface"

    # Verify cleanup was attempted (only when not using cache)
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_huggingface_url_passes_max_size_to_download(
    mock_rmtree: MagicMock,
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_hf_url: MagicMock,
    tmp_path: Path,
) -> None:
    """Repository HuggingFace downloads should receive the parsed acquisition budget."""
    mock_is_hf_url.return_value = True
    downloaded_dir = tmp_path / "downloaded"
    downloaded_dir.mkdir()
    (downloaded_dir / "model.bin").write_bytes(b"weights")
    mock_download.return_value = downloaded_dir
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--quiet", "--no-cache", "--max-size", "2KB", "--timeout", "7", "hf://test/model"],
    )

    assert result.exit_code == 0
    assert mock_download.call_args.kwargs["max_size"] == 2048
    assert mock_download.call_args.kwargs["timeout_seconds"] == 7
    mock_rmtree.assert_called()


def test_scan_huggingface_metadata_preview_escapes_model_id(tmp_path: Path) -> None:
    downloaded_dir = tmp_path / "downloaded"
    downloaded_dir.mkdir()
    (downloaded_dir / "model.bin").write_bytes(b"weights")

    with (
        patch("modelaudit.cli.is_huggingface_url", return_value=True),
        patch(
            "modelaudit.utils.sources.huggingface.get_model_info",
            return_value={
                "model_id": "org/model\nFORGED\u202e",
                "total_size": 1024,
                "file_count": "2\x1b[2J",
            },
        ),
        patch("modelaudit.cli.download_model", return_value=downloaded_dir),
        patch(
            "modelaudit.cli.scan_model_directory_or_file",
            return_value=create_mock_scan_result(files_scanned=1, issues=[]),
        ),
        patch("shutil.rmtree"),
    ):
        result = CliRunner().invoke(cli, ["scan", "--no-cache", "--format", "text", "hf://org/model"])

    assert result.exit_code == 0, result.output
    assert "org/model\\nFORGED\\u202e" in result.output
    assert "2\\x1b[2J files" in result.output
    assert "org/model\nFORGED\u202e" not in result.output


def test_scan_huggingface_metadata_preflight_verbose_log_is_sanitized(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    url = "https://huggingface.co/org/model?token=secret-token"
    downloaded_dir = tmp_path / "downloaded"
    downloaded_dir.mkdir()
    (downloaded_dir / "model.bin").write_bytes(b"weights")

    with (
        patch("modelaudit.cli.is_huggingface_url", return_value=True),
        patch(
            "modelaudit.utils.sources.huggingface.get_model_info",
            side_effect=RuntimeError(f"metadata failed for {url}\nFORGED"),
        ),
        patch("modelaudit.cli.download_model", return_value=downloaded_dir),
        patch(
            "modelaudit.cli.scan_model_directory_or_file",
            return_value=create_mock_scan_result(files_scanned=1, issues=[]),
        ),
        patch("shutil.rmtree"),
        caplog.at_level(logging.DEBUG, logger="modelaudit"),
    ):
        result = CliRunner().invoke(
            cli,
            ["scan", "--verbose", "--no-cache", "--format", "text", url],
        )

    assert result.exit_code == 0, result.output
    assert "https://huggingface.co/org/model" in caplog.text
    assert "metadata failed" in caplog.text
    assert "\\nFORGED" in caplog.text
    assert "secret-token" not in caplog.text
    assert "?token=" not in caplog.text


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.download_model")
def test_scan_huggingface_url_download_failure(
    mock_download: MagicMock,
    mock_is_hf_url: MagicMock,
) -> None:
    """Test handling of download failure for HuggingFace URL."""
    # Setup mocks
    mock_is_hf_url.return_value = True
    mock_download.side_effect = Exception("Download failed")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "--format", "text", "https://huggingface.co/test/model"])

    # Should fail with error code 2
    assert result.exit_code == 2
    assert "Error processing model" in result.output or "Error downloading model" in result.output
    assert "Download failed" in result.output
    assert "MODEL ACQUISITION FAILED" in result.output
    assert "No model artifacts were scanned for failed Hugging Face source(s)." in result.output
    assert "blocked Hugging Face source(s)" not in result.output
    assert "SCAN COMPLETED WITH OPERATIONAL ERRORS" not in result.output


@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_huggingface_gated_text_reports_blocked_without_artifact_scan(
    mock_scan: MagicMock,
    mock_download: MagicMock,
) -> None:
    """Text output must not present gated acquisition as a generic completed scan."""
    url = f"https://huggingface.co/test/gated?revision={_HF_TEST_REVISION}&token=hf_secret"
    mock_download.side_effect = RuntimeError("GatedRepoError: 403 Forbidden")

    result = CliRunner().invoke(cli, ["scan", "--quiet", "--no-cache", "--format", "text", url])

    output = strip_ansi(result.output)
    assert result.exit_code == 2
    assert "MODEL ACQUISITION BLOCKED" in output
    assert "No model artifacts were scanned for blocked Hugging Face source(s)." in output
    assert "NO FILES SCANNED" not in output
    assert "SCAN COMPLETED WITH OPERATIONAL ERRORS" not in output
    assert "hf_secret" not in output
    mock_scan.assert_not_called()


@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_huggingface_gated_json_reports_acquisition_error(
    mock_scan: MagicMock,
    mock_download: MagicMock,
) -> None:
    """Gated repositories must not produce successful empty JSON results."""
    url = f"https://huggingface.co/test/gated?revision={_HF_TEST_REVISION}&token=hf_secret"
    mock_download.side_effect = RuntimeError(
        "GatedRepoError: 403 Forbidden for https://huggingface.co/test/gated?token=hf_secret\nFORGED"
    )

    with (
        patch("modelaudit.cli.record_scan_completed") as mock_completed,
        patch("modelaudit.cli.record_scan_failed") as mock_failed,
    ):
        result = CliRunner().invoke(cli, ["scan", "--quiet", "--no-cache", "--format", "json", url])

    parsed = parse_click_json_output(result.output)
    source_key = f"https://huggingface.co/test/gated@{_HF_TEST_REVISION}"
    assert result.exit_code == 2
    assert "hf_secret" not in result.output
    assert "\\nFORGED" in result.output
    assert_huggingface_acquisition_error_payload(
        parsed,
        source_key,
        blocked=True,
        expected_revision=_HF_TEST_REVISION,
    )
    mock_scan.assert_not_called()
    mock_completed.assert_not_called()
    mock_failed.assert_called_once()
    assert mock_failed.call_args.args[1] == "Model acquisition failed"


@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_huggingface_transient_json_reports_acquisition_failed_not_blocked(
    mock_scan: MagicMock,
    mock_download: MagicMock,
) -> None:
    """Non-auth acquisition failures should fail closed without pretending to be gated."""
    url = f"https://huggingface.co/test/model?revision={_HF_TEST_REVISION}"
    mock_download.side_effect = RuntimeError("Connection timed out while listing repository files")

    result = CliRunner().invoke(cli, ["scan", "--quiet", "--no-cache", "--format", "json", url])

    parsed = parse_click_json_output(result.output)
    source_key = f"https://huggingface.co/test/model@{_HF_TEST_REVISION}"
    assert result.exit_code == 2
    assert_huggingface_acquisition_error_payload(
        parsed,
        source_key,
        blocked=False,
        expected_revision=_HF_TEST_REVISION,
    )
    mock_scan.assert_not_called()


@patch("modelaudit.cli.download_file_from_hf")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_huggingface_file_unauthorized_json_reports_acquisition_error(
    mock_scan: MagicMock,
    mock_download_file: MagicMock,
) -> None:
    """Direct HF file auth failures should share repository acquisition semantics."""
    url = f"https://huggingface.co/test/gated/resolve/{_HF_TEST_REVISION}/model.bin?token=hf_secret"
    mock_download_file.side_effect = RuntimeError("401 Unauthorized for https://huggingface.co/test/gated")

    result = CliRunner().invoke(cli, ["scan", "--quiet", "--no-cache", "--format", "json", url])

    parsed = parse_click_json_output(result.output)
    source_key = f"https://huggingface.co/test/gated/resolve/{_HF_TEST_REVISION}/model.bin"
    assert result.exit_code == 2
    assert "hf_secret" not in result.output
    assert_huggingface_acquisition_error_payload(
        parsed,
        source_key,
        blocked=True,
        expected_revision=_HF_TEST_REVISION,
    )
    mock_scan.assert_not_called()


@patch("modelaudit.cli.download_file_from_hf")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_huggingface_file_encoded_revision_source_key_is_not_double_suffixed(
    mock_scan: MagicMock,
    mock_download_file: MagicMock,
) -> None:
    """Direct file URLs already carry revisions in their path, including encoded slash refs."""
    url = "https://huggingface.co/test/gated/resolve/refs%2Fpr%2F1/model.bin"
    mock_download_file.side_effect = RuntimeError("403 Forbidden")

    result = CliRunner().invoke(cli, ["scan", "--quiet", "--no-cache", "--format", "json", url])

    parsed = parse_click_json_output(result.output)
    source_key = "https://huggingface.co/test/gated/resolve/refs%2Fpr%2F1/model.bin"
    assert result.exit_code == 2
    assert f"{source_key}@refs/pr/1" not in result.output
    assert_huggingface_acquisition_error_payload(
        parsed,
        source_key,
        blocked=True,
        expected_revision="refs/pr/1",
    )
    mock_scan.assert_not_called()


@patch("modelaudit.core.scan_model_streaming")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
def test_scan_huggingface_streaming_gated_json_reports_acquisition_error(
    mock_download_streaming: MagicMock,
    mock_scan_streaming: MagicMock,
) -> None:
    """Streaming acquisition failures must not claim a completed stream scan."""
    url = f"https://huggingface.co/test/gated?revision={_HF_TEST_REVISION}"
    mock_download_streaming.side_effect = RuntimeError("GatedRepoError: 403 Forbidden")

    result = CliRunner().invoke(cli, ["scan", "--quiet", "--stream", "--format", "json", url])

    parsed = parse_click_json_output(result.output)
    source_key = f"https://huggingface.co/test/gated@{_HF_TEST_REVISION}"
    assert result.exit_code == 2
    assert_huggingface_acquisition_error_payload(
        parsed,
        source_key,
        blocked=True,
        expected_revision=_HF_TEST_REVISION,
    )
    mock_scan_streaming.assert_not_called()
    assert "Streaming scan complete" not in result.output


@patch("modelaudit.core.scan_model_streaming")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
def test_scan_huggingface_streaming_late_failure_is_not_acquisition_error(
    mock_download_streaming: MagicMock,
    mock_scan_streaming: MagicMock,
    tmp_path: Path,
) -> None:
    """A stream failure after yielding an artifact must not claim zero artifact acquisition."""
    streamed_file = tmp_path / "model.bin"
    streamed_file.write_bytes(b"payload")

    def interrupted_stream() -> Iterator[tuple[Path, bool]]:
        yield streamed_file, False
        raise RuntimeError("GatedRepoError: 403 Forbidden after first artifact")

    def consume_stream(file_generator: Iterator[tuple[Path, bool]], **_kwargs: Any) -> ModelAuditResultModel:
        for _file_path, _is_last in file_generator:
            pass
        return create_mock_scan_result(files_scanned=1, issues=[])

    mock_download_streaming.return_value = interrupted_stream()
    mock_scan_streaming.side_effect = consume_stream

    result = CliRunner().invoke(
        cli,
        ["scan", "--quiet", "--stream", "--format", "json", "https://huggingface.co/test/gated"],
    )

    parsed = parse_click_json_output(result.output)
    assert result.exit_code == 2
    assert parsed["success"] is False
    assert parsed["has_errors"] is True
    assert not any(issue.get("type") == "huggingface_acquisition_error" for issue in parsed["issues"])
    assert parsed["file_metadata"] == {}
    assert "no model artifacts were scanned" not in result.output.lower()


@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_huggingface_benign_successful_acquisition_not_marked_acquisition_error(
    mock_rmtree: MagicMock,
    mock_scan: MagicMock,
    mock_download: MagicMock,
    tmp_path: Path,
) -> None:
    """Clean successful HF acquisition should stay a normal successful scan."""
    downloaded_dir = tmp_path / "downloaded"
    downloaded_dir.mkdir()
    (downloaded_dir / "model.safetensors").write_bytes(b"safe")
    mock_download.return_value = downloaded_dir
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    result = CliRunner().invoke(
        cli,
        ["scan", "--quiet", "--no-cache", "--format", "json", "https://huggingface.co/test/clean"],
    )

    parsed = parse_click_json_output(result.output)
    assert result.exit_code == 0
    assert parsed["success"] is True
    assert parsed["has_errors"] is False
    assert parsed["files_scanned"] == 1
    assert parsed["file_metadata"] == {}
    assert not any(issue.get("type") == "huggingface_acquisition_error" for issue in parsed["issues"])
    mock_scan.assert_called_once()
    mock_rmtree.assert_called_once()


@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_huggingface_malicious_successful_acquisition_still_reports_security_findings(
    mock_rmtree: MagicMock,
    mock_scan: MagicMock,
    mock_download: MagicMock,
    tmp_path: Path,
) -> None:
    """The acquisition-error path must not hide malicious content after a successful download."""
    downloaded_dir = tmp_path / "downloaded"
    downloaded_dir.mkdir()
    (downloaded_dir / "model.bin").write_bytes(b"malicious")
    mock_download.return_value = downloaded_dir
    mock_scan.return_value = create_mock_scan_result(
        files_scanned=1,
        issues=[
            {
                "message": "Malicious pickle opcode detected",
                "severity": "critical",
                "location": str(downloaded_dir / "model.bin"),
                "type": "pickle_rce",
            }
        ],
    )

    result = CliRunner().invoke(
        cli,
        ["scan", "--quiet", "--no-cache", "--format", "json", "https://huggingface.co/test/malicious"],
    )

    parsed = parse_click_json_output(result.output)
    assert result.exit_code == 1
    assert parsed["files_scanned"] == 1
    assert parsed["issues"][0]["type"] == "pickle_rce"
    assert parsed["file_metadata"] == {}
    mock_scan.assert_called_once()
    mock_rmtree.assert_called_once()


@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_huggingface_blocked_source_does_not_hide_local_malicious_findings(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    tmp_path: Path,
) -> None:
    """Operational acquisition errors must not suppress findings from other inputs."""
    local_model = tmp_path / "local.bin"
    local_model.write_bytes(b"malicious")
    mock_download.side_effect = RuntimeError("GatedRepoError: 403 Forbidden")
    mock_scan.return_value = create_mock_scan_result(
        files_scanned=1,
        issues=[
            {
                "message": "Malicious pickle opcode detected",
                "severity": "critical",
                "location": str(local_model),
                "type": "pickle_rce",
            }
        ],
    )
    blocked_url = f"https://huggingface.co/test/gated?revision={_HF_TEST_REVISION}"

    result = CliRunner().invoke(
        cli,
        ["scan", "--quiet", "--no-cache", "--format", "json", str(local_model), blocked_url],
    )

    parsed = parse_click_json_output(result.output)
    source_key = f"https://huggingface.co/test/gated@{_HF_TEST_REVISION}"
    assert result.exit_code == 2
    assert parsed["success"] is False
    assert parsed["files_scanned"] == 1
    assert any(issue["type"] == "pickle_rce" for issue in parsed["issues"])
    assert_huggingface_acquisition_error_payload(
        {
            **parsed,
            "bytes_scanned": 0,
            "files_scanned": 0,
            "assets": [],
        },
        source_key,
        blocked=True,
        expected_revision=_HF_TEST_REVISION,
    )
    mock_scan.assert_called_once()


@patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
@patch("modelaudit.utils.sources.huggingface.get_model_size", return_value=None)
@patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={"", ".bin"})
@patch(
    "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
    return_value=(["notes.unknown"], _HF_TEST_REVISION, None),
)
@patch("huggingface_hub.snapshot_download")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_huggingface_no_scannable_listing_fails_closed(
    mock_scan: MagicMock,
    mock_snapshot_download: MagicMock,
    _mock_list_repo_files: MagicMock,
    _mock_get_extensions: MagicMock,
    _mock_get_model_size: MagicMock,
    _mock_detect_content: MagicMock,
) -> None:
    """Unsupported-only repositories should exit 2 without downloading or scanning."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--no-cache", "--format", "json", "https://huggingface.co/test/model"],
    )

    parsed = parse_click_json_output(result.output)
    assert result.exit_code == 2
    assert parsed["has_errors"] is True
    assert parsed["files_scanned"] == 0
    assert "repository listing contains no recognized ModelAudit-scannable files" in result.output
    mock_snapshot_download.assert_not_called()
    mock_scan.assert_not_called()


@patch("modelaudit.cli.download_file_from_hf")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_huggingface_file_passes_max_size_and_cleans_temp_dir(
    mock_rmtree: MagicMock,
    mock_scan: MagicMock,
    mock_download_file: MagicMock,
    tmp_path: Path,
) -> None:
    """Direct HuggingFace file downloads should receive the parsed acquisition budget."""
    downloaded_file = tmp_path / "model.bin"
    downloaded_file.write_bytes(b"weights")
    mock_download_file.return_value = downloaded_file
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--quiet",
            "--no-cache",
            "--max-size",
            "2KB",
            "https://huggingface.co/test/model/resolve/main/model.bin",
        ],
    )

    assert result.exit_code == 0
    assert mock_download_file.call_args.kwargs["max_size"] == 2048
    mock_rmtree.assert_called()


@patch("modelaudit.cli.download_file_from_hf")
def test_scan_huggingface_file_download_failure_redacts_url(
    mock_download_file: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Redact secrets from chained direct-file download failures."""

    def raise_chained_download_error(*_args: Any, **_kwargs: Any) -> None:
        try:
            raise ValueError(
                "Failed request https://huggingface.co/test/model/resolve/main/file.bin?token=hf_secret\nFORGED\x1b[2J"
            )
        except ValueError as cause:
            raise RuntimeError("Download failed") from cause

    mock_download_file.side_effect = raise_chained_download_error

    runner = CliRunner()
    with caplog.at_level(logging.ERROR, logger="modelaudit"):
        result = runner.invoke(
            cli,
            ["scan", "--verbose", "https://huggingface.co/test/model/resolve/main/file.bin?token=hf_secret"],
        )

    output = strip_ansi(result.output)
    assert result.exit_code == 2
    assert "hf_secret" not in output
    assert "token=" not in output
    assert "https://huggingface.co/test/model/resolve/main/file.bin" in output
    assert "hf_secret" not in caplog.text
    assert "token=" not in caplog.text
    assert "\nFORGED" not in caplog.text
    assert "\x1b" not in caplog.text


@pytest.mark.parametrize(("max_size", "expected_bytes"), [("2KB", 2048), ("0", 0)])
@patch("modelaudit.cli.download_file_from_hf")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_huggingface_file_passes_max_size_to_download(
    mock_scan: MagicMock,
    mock_download_file: MagicMock,
    tmp_path: Path,
    max_size: str,
    expected_bytes: int,
) -> None:
    """Direct HuggingFace file downloads should receive the CLI download budget before fetch."""
    downloaded_file = tmp_path / "model.bin"
    downloaded_file.write_bytes(b"model")
    mock_download_file.return_value = downloaded_file
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=4,
        issues=[],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["test_scanner"],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--no-cache",
            "--format",
            "json",
            "--max-size",
            max_size,
            "https://huggingface.co/test/model/resolve/main/model.bin",
        ],
    )

    assert result.exit_code == 0
    mock_download_file.assert_called_once()
    assert mock_download_file.call_args.kwargs["max_size"] == expected_bytes
    assert mock_scan.call_args.args[0] == str(downloaded_file)


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_huggingface_url_with_issues(mock_rmtree, mock_scan, mock_download, mock_is_hf_url, tmp_path):
    """Test scanning a HuggingFace URL that has security issues."""
    # Setup mocks
    mock_is_hf_url.return_value = True
    # Create a real temp directory for the test
    test_model_dir = tmp_path / "test_model"
    test_model_dir.mkdir()
    # Create a dummy file inside to make it look like a real model
    (test_model_dir / "model.pkl").write_text("dummy model")

    mock_download.return_value = test_model_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=2048,
        issues=[
            {
                "message": "Dangerous import detected",
                "severity": "critical",
                "location": "model.pkl",
            }
        ],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["pickle_scanner"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--format", "text", "--no-cache", "hf://test/malicious-model"])

    # Should exit with code 1 (security issues found)
    assert result.exit_code == 1
    assert (
        "Downloaded" in result.output
        or "issue" in result.output.lower()
        or "Downloaded successfully" in result.output
        or "Downloading from" in result.output
    )

    # Verify cleanup was still attempted
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_huggingface_no_cache_uses_ephemeral_cache_dir(
    mock_rmtree: MagicMock,
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_hf_url: MagicMock,
    tmp_path: Path,
) -> None:
    """No-cache HuggingFace model scans should use a private temp cache, not HF's shared cache."""
    mock_is_hf_url.return_value = True
    downloaded_dir = tmp_path / "downloaded"
    downloaded_dir.mkdir()
    (downloaded_dir / "model.safetensors").write_bytes(b"weights")
    mock_download.return_value = downloaded_dir
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--quiet", "--no-cache", "hf://test/model"])

    assert result.exit_code == 0
    cache_dir = mock_download.call_args.kwargs["cache_dir"]
    assert isinstance(cache_dir, Path)
    assert cache_dir.name.startswith("modelaudit_hf_")
    mock_rmtree.assert_called()


@patch("tempfile.mkdtemp")
@patch("shutil.rmtree")
@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.download_model")
def test_scan_huggingface_no_cache_download_failure_cleans_ephemeral_cache_dir(
    mock_download: MagicMock,
    mock_is_hf_url: MagicMock,
    mock_rmtree: MagicMock,
    mock_mkdtemp: MagicMock,
    tmp_path: Path,
) -> None:
    """No-cache HuggingFace failures should still clean up the private temp cache directory."""
    mock_is_hf_url.return_value = True
    temp_cache_dir = tmp_path / "modelaudit_hf_failed"
    temp_cache_dir.mkdir()
    mock_mkdtemp.return_value = str(temp_cache_dir)
    mock_download.side_effect = Exception("Download failed")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "hf://test/model"])

    assert result.exit_code == 2
    mock_rmtree.assert_called_once_with(str(temp_cache_dir))


@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_no_whitelist_passes_config_and_preserves_critical_exit_code(mock_scan: MagicMock, tmp_path: Path) -> None:
    """--no-whitelist should disable downgrade config and keep CRITICAL findings as exit-code 1."""
    test_file = tmp_path / "model.pkl"
    test_file.write_bytes(b"dummy")

    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=2048,
        issues=[
            {
                "message": "Dangerous import detected",
                "severity": "critical",
                "location": "model.pkl",
                "details": {},
            }
        ],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["pickle_scanner"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--format", "json", "--no-whitelist"])

    assert result.exit_code == 1
    mock_scan.assert_called_once()
    assert mock_scan.call_args.kwargs["use_hf_whitelist"] is False


@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_defaults_keep_whitelist_enabled(mock_scan: MagicMock, tmp_path: Path) -> None:
    """Without flags, whitelist downgrading remains enabled for backward compatibility."""
    test_file = tmp_path / "model.pkl"
    test_file.write_bytes(b"dummy")
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--format", "json"])

    assert result.exit_code == 0
    mock_scan.assert_called_once()
    assert mock_scan.call_args.kwargs["use_hf_whitelist"] is True


@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_strict_implies_no_whitelist_and_no_cache(mock_scan: MagicMock, tmp_path: Path) -> None:
    """--strict should imply both --no-whitelist and --no-cache."""
    test_file = tmp_path / "model.pkl"
    test_file.write_bytes(b"dummy")
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--format", "json", "--strict"])

    assert result.exit_code == 0
    mock_scan.assert_called_once()
    assert mock_scan.call_args.kwargs["use_hf_whitelist"] is False
    assert mock_scan.call_args.kwargs["cache_enabled"] is False
    assert mock_scan.call_args.kwargs["skip_file_types"] is False


@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_default_skips_non_model_python_files(mock_scan: MagicMock, tmp_path: Path) -> None:
    test_file = tmp_path / "helper.py"
    test_file.write_text("print('not a model')\n")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--format", "json"])
    parsed = parse_click_json_output(result.output)

    assert result.exit_code == 2
    mock_scan.assert_not_called()
    assert parsed["files_scanned"] == 0


@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_strict_scans_non_model_python_files(mock_scan: MagicMock, tmp_path: Path) -> None:
    test_file = tmp_path / "helper.py"
    test_file.write_text("print('not a model')\n")
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--format", "json", "--strict"])

    assert result.exit_code == 0
    mock_scan.assert_called_once()
    assert mock_scan.call_args.kwargs["skip_file_types"] is False


@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_mixed_paths_and_urls(mock_scan):
    """Test scanning both local paths and HuggingFace URLs in one command."""
    runner = CliRunner()

    with patch("modelaudit.cli.is_huggingface_url") as mock_is_hf, patch("os.path.exists") as mock_exists:
        # Setup mocks - first arg is local path, second is URL
        mock_is_hf.side_effect = [False, True]
        mock_exists.return_value = False  # Local path doesn't exist

        result = runner.invoke(cli, ["scan", "/local/path/model.pkl", "https://huggingface.co/test/model"])

        # Should report error for missing local file
        assert "Path does not exist: /local/path/model.pkl" in result.output


@patch("modelaudit.cli.is_pytorch_hub_url")
@patch("modelaudit.cli.download_pytorch_hub_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_pytorchhub_url_success(mock_rmtree, mock_scan, mock_download, mock_is_ph_url, tmp_path):
    """Test scanning a PyTorch Hub URL successfully."""
    mock_is_ph_url.return_value = True
    test_dir = tmp_path / "hub"
    test_dir.mkdir()
    (test_dir / "model.pt").write_text("dummy")
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=1, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://pytorch.org/hub/pytorch_vision_resnet/"])

    assert result.exit_code == 0
    mock_download.assert_called_once()
    mock_scan.assert_called_once()
    # With automatic defaults, PyTorch Hub URLs enable caching by default, so no cleanup
    mock_rmtree.assert_not_called()


@patch("modelaudit.cli.is_pytorch_hub_url")
@patch("modelaudit.cli.download_pytorch_hub_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_pytorchhub_url_passes_max_download_bytes(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_ph_url: MagicMock,
    tmp_path: Path,
) -> None:
    mock_is_ph_url.return_value = True
    test_dir = tmp_path / "hub"
    test_dir.mkdir()
    (test_dir / "model.pt").write_text("dummy")
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=1,
        issues=[],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["test"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://pytorch.org/hub/pytorch_vision_resnet/", "--max-size", "5KB"])

    assert result.exit_code == 0
    assert mock_download.call_args.kwargs["max_size"] == 5 * 1024


@pytest.mark.parametrize(
    "selection_args",
    [
        ["--scanners", "pickle"],
        ["--exclude-scanner", "onnx", "--exclude-scanner", "weight_distribution"],
    ],
)
@patch("modelaudit.cli.is_pytorch_hub_url")
@patch("modelaudit.cli.download_pytorch_hub_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_pytorchhub_url_passes_selected_scanner_extensions(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_ph_url: MagicMock,
    selection_args: list[str],
    tmp_path: Path,
) -> None:
    mock_is_ph_url.return_value = True
    test_dir = tmp_path / "hub"
    test_dir.mkdir()
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", *selection_args, "--quiet", "https://pytorch.org/hub/pytorch_vision_resnet/"],
    )

    assert result.exit_code == 0
    extensions = mock_download.call_args.kwargs["scannable_extensions"]
    assert ".pkl" in extensions
    assert ".onnx" not in extensions


@pytest.mark.parametrize("scanner_id", ["keras_h5", "zip"])
@patch("modelaudit.cli.is_pytorch_hub_url")
@patch("modelaudit.cli.download_pytorch_hub_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_pytorchhub_url_preserves_header_routed_artifacts(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_ph_url: MagicMock,
    scanner_id: str,
    tmp_path: Path,
) -> None:
    mock_is_ph_url.return_value = True
    test_dir = tmp_path / "hub"
    test_dir.mkdir()
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--scanners", scanner_id, "--quiet", "https://pytorch.org/hub/pytorch_vision_resnet/"],
    )

    assert result.exit_code == 0
    assert mock_download.call_args.kwargs["scannable_extensions"] is None


@patch("modelaudit.cli.is_pytorch_hub_url")
@patch("modelaudit.utils.sources.pytorch_hub.download_pytorch_hub_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_pytorchhub_stream_passes_max_download_bytes(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_ph_url: MagicMock,
) -> None:
    mock_is_ph_url.return_value = True
    mock_scan_streaming.return_value = create_mock_scan_result(
        bytes_scanned=1,
        issues=[],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["test"],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "https://pytorch.org/hub/pytorch_vision_resnet/", "--stream", "--max-size", "5KB"],
    )

    assert result.exit_code == 0
    assert mock_download_streaming.call_args.kwargs["max_size"] == 5 * 1024
    assert mock_download_streaming.call_args.kwargs["timeout"] > 0
    assert mock_scan_streaming.call_args.kwargs["shard_family_group"].startswith("stream-invocation:")


@pytest.mark.parametrize(
    "selection_args",
    [
        ["--scanners", "pickle"],
        ["--exclude-scanner", "onnx", "--exclude-scanner", "weight_distribution"],
    ],
)
@patch("modelaudit.cli.is_pytorch_hub_url")
@patch("modelaudit.utils.sources.pytorch_hub.download_pytorch_hub_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_pytorchhub_stream_passes_selected_scanner_extensions(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_ph_url: MagicMock,
    selection_args: list[str],
) -> None:
    mock_is_ph_url.return_value = True
    mock_download_streaming.return_value = iter(())
    mock_scan_streaming.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--stream",
            *selection_args,
            "--quiet",
            "https://pytorch.org/hub/pytorch_vision_resnet/",
        ],
    )

    assert result.exit_code == 0
    extensions = mock_download_streaming.call_args.kwargs["scannable_extensions"]
    assert ".pkl" in extensions
    assert ".onnx" not in extensions


@patch("modelaudit.cli.is_pytorch_hub_url")
@patch("modelaudit.cli.download_pytorch_hub_model")
def test_scan_pytorchhub_url_download_failure(mock_download, mock_is_ph_url):
    """Test download failure for PyTorch Hub URL."""
    mock_is_ph_url.return_value = True
    mock_download.side_effect = Exception("boom")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://pytorch.org/hub/pytorch_vision_resnet/"])

    assert result.exit_code == 2
    assert "Error downloading model" in result.output


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_success(mock_scan_streaming, mock_download_streaming, mock_is_hf_url, tmp_path):
    """Test streaming scan with --stream flag."""
    # Setup mocks
    mock_is_hf_url.return_value = True

    # Create temporary files for streaming
    test_files = []
    for i in range(3):
        test_file = tmp_path / f"model_shard_{i}.bin"
        test_file.write_text(f"dummy content {i}")
        test_files.append(test_file)

    # Mock file generator
    def file_generator():
        for i, f in enumerate(test_files):
            yield (f, i == len(test_files) - 1)

    mock_download_streaming.return_value = file_generator()

    # Mock streaming scan result with content_hash
    mock_result = create_mock_scan_result(bytes_scanned=300, files_scanned=3, has_errors=False)
    mock_result.content_hash = "a" * 64  # Mock SHA256 hash
    mock_scan_streaming.return_value = mock_result

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "--format", "json", "https://huggingface.co/test/streaming-model"])

    # Should succeed
    assert result.exit_code == 0

    # Verify streaming functions were called
    mock_download_streaming.assert_called_once()
    mock_scan_streaming.assert_called_once()
    streaming_provenance = mock_scan_streaming.call_args.kwargs["_trusted_source_provenance"]
    assert streaming_provenance.model_id == "test/streaming-model"
    assert streaming_provenance.model_source == "huggingface"
    assert mock_scan_streaming.call_args.kwargs["shard_family_group"].startswith("stream-invocation:")

    # Verify content_hash is in JSON output
    try:
        output_json = parse_click_json_output(result.output)
        assert "content_hash" in output_json
        assert output_json["content_hash"] == "a" * 64
        assert output_json["files_scanned"] == 3
    except json.JSONDecodeError:
        pytest.fail("Output is not valid JSON")


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
def test_scan_huggingface_cached_stream_reconciles_snapshot_alias_shards(
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """A cache-enabled HF stream should trust aliases of one logical snapshot parent."""
    mock_is_hf_url.return_value = True
    header = b'{"__metadata__":{"format":"pt"}}'
    cache_root = tmp_path / "persistent-cache"
    _make_trusted_shard_parent(cache_root / "huggingface", parents=True)
    snapshot_dir = cache_root / "huggingface" / "models--test--model" / "snapshots" / _HF_TEST_REVISION
    _make_trusted_shard_parent(snapshot_dir, parents=True)
    alias_root = cache_root / "huggingface" / "test" / "model"
    _make_trusted_shard_parent(alias_root, parents=True)
    first_alias = alias_root / "cache-a"
    second_alias = alias_root / "cache-b"
    first_alias.symlink_to(snapshot_dir, target_is_directory=True)
    second_alias.symlink_to(snapshot_dir, target_is_directory=True)

    def file_generator() -> Iterator[tuple[Path, bool]]:
        for shard_index, alias_path in ((1, first_alias), (2, second_alias)):
            shard_name = f"model-{shard_index:05d}-of-00002.safetensors"
            snapshot_path = snapshot_dir / shard_name
            snapshot_path.write_bytes(struct.pack("<Q", len(header)) + header)
            yield (alias_path / shard_name, shard_index == 2)

    mock_download_streaming.return_value = file_generator()

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--stream",
            "--quiet",
            "--format",
            "json",
            "--cache-dir",
            str(cache_root),
            "hf://test/model",
        ],
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["success"] is True
    assert output_payload["files_scanned"] == 2
    assert not any(
        record.get("details", {}).get("scan_outcome_reason") == "missing_model_shards"
        for record in [*output_payload["checks"], *output_payload["issues"]]
    )


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
def test_scan_huggingface_streaming_omits_multilingual_vocab_cc_token(
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
    tmp_path: Path,
) -> None:
    """Streamed Hugging Face tokenizer vocabularies should retain vocabulary context."""
    mock_is_hf_url.return_value = True
    model_dir = tmp_path / "huggingface" / "google-bert" / "bert-base-multilingual-uncased"
    model_dir.mkdir(parents=True)
    vocab_path = model_dir / "tokenizer-multilingual.txt"
    vocab_path.write_bytes(_bert_like_multilingual_vocab_bytes("zombie"))
    mock_download_streaming.return_value = iter([(vocab_path, True)])

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--stream",
            "--quiet",
            "--format",
            "json",
            "--scanners",
            "text",
            "hf://google-bert/bert-base-multilingual-uncased",
        ],
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["files_scanned"] == 1
    assert not output_payload["issues"]
    assert not [
        check
        for check in output_payload["checks"]
        if check.get("name") == "Network Communication Detection"
        and check.get("details", {}).get("type") == "cc_pattern"
    ]
    assert mock_download_streaming.call_args.kwargs["scannable_extensions"] == frozenset(
        {".txt", ".md", ".markdown", ".rst"}
    )


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_passes_selected_scanner_extensions(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
) -> None:
    """Selected scanners should constrain HuggingFace streaming prefilters."""
    mock_is_hf_url.return_value = True
    mock_download_streaming.return_value = iter(())
    mock_scan_streaming.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "--scanners", "llamafile", "--quiet", "hf://test/model"])

    assert result.exit_code == 0
    assert mock_download_streaming.call_args.kwargs["scannable_extensions"] == frozenset({"", ".exe", ".llamafile"})
    assert "llamafile" in mock_download_streaming.call_args.kwargs["scannable_scanner_ids"]
    assert "include_all_files" not in mock_download_streaming.call_args.kwargs


@pytest.mark.parametrize("scanner_args", [[], ["--scanners", "zip"]])
@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_preserves_header_routed_unknown_suffixes(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
    scanner_args: list[str],
) -> None:
    """Default and header-routed scans should request bounded unknown-suffix coverage."""
    mock_is_hf_url.return_value = True
    mock_download_streaming.return_value = iter(())
    mock_scan_streaming.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", *scanner_args, "--quiet", "hf://test/model"])

    assert result.exit_code == 0
    assert mock_download_streaming.call_args.kwargs["include_all_files"] is True
    if scanner_args:
        assert "scannable_extensions" not in mock_download_streaming.call_args.kwargs


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_preserves_selected_extensionless_filenames(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
) -> None:
    """Selected filename-routed scanners should keep extensionless remote candidates."""
    mock_is_hf_url.return_value = True
    mock_download_streaming.return_value = iter(())
    mock_scan_streaming.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "--scanners", "metadata", "--quiet", "hf://test/model"])

    assert result.exit_code == 0
    assert "" not in mock_download_streaming.call_args.kwargs["scannable_extensions"]
    assert mock_download_streaming.call_args.kwargs["scannable_filenames"] == frozenset({"readme", "model_card"})


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_passes_max_size_to_download(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
    tmp_path: Path,
) -> None:
    """Streaming HuggingFace downloads should receive the parsed acquisition budget."""
    mock_is_hf_url.return_value = True

    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"weights")
    mock_download_streaming.return_value = iter([(test_file, True)])
    mock_scan_streaming.return_value = create_mock_scan_result(bytes_scanned=7, files_scanned=1, has_errors=False)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--stream", "--quiet", "--max-size", "2KB", "--timeout", "7", "hf://test/model"],
    )

    assert result.exit_code == 0
    assert mock_download_streaming.call_args.kwargs["max_size"] == 2048
    assert mock_download_streaming.call_args.kwargs["timeout_seconds"] == 7


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
@patch("shutil.rmtree")
def test_scan_huggingface_strict_streaming_uses_ephemeral_cache_dir(
    mock_rmtree: MagicMock,
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
    tmp_path: Path,
) -> None:
    """Strict streaming scans should use a private temp cache instead of the shared HF cache."""
    mock_is_hf_url.return_value = True

    streamed_file = tmp_path / "weights.bin"
    streamed_file.write_bytes(b"weights")

    def file_generator():
        yield (streamed_file, True)

    mock_download_streaming.return_value = file_generator()
    mock_scan_streaming.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "--strict", "--quiet", "hf://test/model"])

    assert result.exit_code == 0
    cache_dir = mock_download_streaming.call_args.kwargs["cache_dir"]
    assert isinstance(cache_dir, Path)
    assert cache_dir.name.startswith("modelaudit_hf_")
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_sbom_includes_streamed_assets(
    mock_scan_streaming, mock_download_streaming, mock_is_hf_url, tmp_path
):
    """Streaming scans should build SBOM components from discovered artifacts."""
    mock_is_hf_url.return_value = True

    streamed_files = []
    file_hashes = {}
    file_sizes = {}
    for name in ("config.json", "model.safetensors", "tokenizer.json"):
        file_path = tmp_path / name
        content = f"streamed content for {name}".encode()
        file_path.write_bytes(content)
        streamed_files.append(file_path)
        import hashlib

        file_hashes[str(file_path)] = hashlib.sha256(content).hexdigest()
        file_sizes[str(file_path)] = len(content)

    def file_generator():
        for index, file_path in enumerate(streamed_files):
            yield (file_path, index == len(streamed_files) - 1)

    mock_download_streaming.return_value = file_generator()

    mock_result = create_mock_scan_result(
        bytes_scanned=sum(file_path.stat().st_size for file_path in streamed_files),
        files_scanned=len(streamed_files),
        has_errors=False,
        assets=[
            {
                "path": str(file_path),
                "type": "safetensors",
                "is_streamed": True,
                "size": file_sizes[str(file_path)],
            }
            for file_path in streamed_files
        ],
        file_metadata={
            str(file_path): {
                "file_size": file_sizes[str(file_path)],
                "file_hashes": {"sha256": file_hashes[str(file_path)]},
            }
            for file_path in streamed_files
        },
    )
    mock_scan_streaming.return_value = mock_result

    for file_path in streamed_files:
        file_path.unlink()

    sbom_file = tmp_path / "streamed.sbom.json"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "--quiet", "--sbom", str(sbom_file), "hf://test/model"])

    assert result.exit_code == 0
    assert sbom_file.exists()
    sbom_data = json.loads(sbom_file.read_text())
    components = {component["name"]: component for component in sbom_data["components"]}

    assert set(components) == {file_path.name for file_path in streamed_files}
    assert "model" not in components

    for file_path in streamed_files:
        component = components[file_path.name]
        properties = {prop["name"]: prop["value"] for prop in component["properties"]}

        assert properties["size"] == str(file_sizes[str(file_path)])
        assert component["hashes"][0]["alg"] == "SHA-256"
        assert component["hashes"][0]["content"] == file_hashes[str(file_path)]


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.is_huggingface_file_url", return_value=False)
@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_huggingface_sbom_excludes_download_cache_files(
    mock_scan, mock_download, mock_is_hf_file_url, mock_is_hf_url, tmp_path
):
    """Remote SBOM generation should ignore HuggingFace cache bookkeeping files."""
    mock_is_hf_url.return_value = True

    downloaded_dir = tmp_path / "gpt2"
    downloaded_dir.mkdir()
    real_files = {
        downloaded_dir / "config.json": b'{"model_type":"gpt2"}',
        downloaded_dir / "merges.txt": b"merge rules",
        downloaded_dir / "model.safetensors": b"weights",
    }
    for file_path, content in real_files.items():
        file_path.write_bytes(content)

    cache_dir = downloaded_dir / ".cache" / "huggingface" / "download"
    cache_dir.mkdir(parents=True)
    (cache_dir / "config.json.metadata").write_text(
        "c5ee24cb16019beea0893ab7796b1df96625c6b8\n821d1aa69520101d6e0737f78a042ae25b19e5c0\n1712656091.123\n"
    )
    (cache_dir / ".gitignore").write_text("*\n")

    mock_download.return_value = downloaded_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=sum(len(content) for content in real_files.values()),
        files_scanned=len(real_files),
        has_errors=False,
        assets=[
            {
                "path": str(file_path),
                "type": "streaming",
                "size": len(content),
            }
            for file_path, content in real_files.items()
        ],
    )

    sbom_file = tmp_path / "downloaded.sbom.json"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--quiet", "--sbom", str(sbom_file), "hf://test/model"])

    assert result.exit_code == 0

    sbom_data = json.loads(sbom_file.read_text())
    component_names = {component["name"] for component in sbom_data["components"]}

    assert component_names == {file_path.name for file_path in real_files}
    assert "config.json.metadata" not in component_names
    assert ".gitignore" not in component_names


def test_scan_directory_skips_huggingface_cache_bookkeeping(tmp_path):
    """Directory scans should not surface HuggingFace cache bookkeeping files as assets."""
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "config.json").write_text('{"model_type":"gpt2"}')
    (model_dir / "model.safetensors").write_bytes(b"weights")

    cache_dir = model_dir / ".cache" / "huggingface" / "download"
    cache_dir.mkdir(parents=True)
    (cache_dir / "config.json.metadata").write_text(
        "c5ee24cb16019beea0893ab7796b1df96625c6b8\n821d1aa69520101d6e0737f78a042ae25b19e5c0\n1712656091.123\n"
    )
    (cache_dir / ".gitignore").write_text("*\n")

    result = scan_model_directory_or_file(str(model_dir))

    asset_names = {os.path.basename(asset.path) for asset in result.assets}
    assert "config.json" in asset_names
    assert "model.safetensors" in asset_names
    assert "config.json.metadata" not in asset_names
    assert ".gitignore" not in asset_names


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_incomplete_result_reports_failed_progress(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
    tmp_path: Path,
) -> None:
    """Partial HF stream results must not claim a completed streaming scan."""
    mock_is_hf_url.return_value = True

    test_file = tmp_path / "malicious.pkl"
    test_file.write_text("malicious content")
    mock_download_streaming.return_value = iter([(test_file, False)])
    mock_scan_streaming.return_value = create_mock_scan_result(
        bytes_scanned=100,
        files_scanned=1,
        issues=[
            {
                "message": "Dangerous import detected before interruption",
                "severity": "critical",
                "location": "malicious.pkl",
            },
            {
                "message": "Streaming source interrupted before all artifacts could be scanned",
                "severity": "info",
                "location": "hf://test/model",
                "type": "streaming_source_interrupted",
                "details": {
                    "operational_error": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "streaming_source_interrupted",
                },
            },
        ],
        has_errors=True,
        success=False,
    )

    result = CliRunner().invoke(cli, ["scan", "--stream", "--format", "text", "hf://test/model"])
    clean_output = strip_ansi(result.output)

    assert result.exit_code == 2
    assert "Streaming scan complete" not in clean_output
    assert "Streaming scan incomplete" in clean_output
    assert "SCAN SUMMARY" in clean_output
    assert "SCAN COMPLETED WITH OPERATIONAL ERRORS" in clean_output
    assert "Dangerous import detected before interruption" in clean_output
    mock_download_streaming.assert_called_once()
    mock_scan_streaming.assert_called_once()


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_security_findings_keep_complete_progress(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
    tmp_path: Path,
) -> None:
    """Security findings without operational errors should keep the complete banner."""
    mock_is_hf_url.return_value = True

    test_file = tmp_path / "malicious.pkl"
    test_file.write_text("malicious content")
    mock_download_streaming.return_value = iter([(test_file, True)])
    mock_scan_streaming.return_value = create_mock_scan_result(
        bytes_scanned=100,
        files_scanned=1,
        issues=[
            {
                "message": "Dangerous import detected",
                "severity": "critical",
                "location": "malicious.pkl",
            }
        ],
        has_errors=False,
        success=True,
    )

    result = CliRunner().invoke(cli, ["scan", "--stream", "--format", "text", "hf://test/malicious-model"])
    clean_output = strip_ansi(result.output)

    assert result.exit_code == 1
    assert "Streaming scan complete" in clean_output
    assert "Streaming scan incomplete" not in clean_output
    assert "CRITICAL SECURITY ISSUES FOUND" in clean_output
    assert "Dangerous import detected" in clean_output
    mock_download_streaming.assert_called_once()
    mock_scan_streaming.assert_called_once()


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_with_issues(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_hf_url: MagicMock,
    tmp_path: Path,
) -> None:
    """Test streaming scan with security issues detected."""
    mock_is_hf_url.return_value = True

    # Mock file generator
    test_file = tmp_path / "malicious.pkl"
    test_file.write_text("malicious content")

    def file_generator() -> Iterator[tuple[Path, bool]]:
        yield (test_file, True)

    mock_download_streaming.return_value = file_generator()

    # Mock scan result with issues
    mock_result = create_mock_scan_result(
        bytes_scanned=100,
        files_scanned=1,
        issues=[{"message": "Dangerous import detected", "severity": "critical", "location": "malicious.pkl"}],
        has_errors=False,
    )
    mock_result.content_hash = "b" * 64
    mock_scan_streaming.return_value = mock_result

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "hf://test/malicious-model"])

    # Should exit with code 1 (security issues found)
    assert result.exit_code == 1

    # Verify streaming functions were called
    mock_download_streaming.assert_called_once()
    mock_scan_streaming.assert_called_once()


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
def test_scan_huggingface_streaming_download_failure(mock_download_streaming, mock_is_hf_url):
    """Test handling of download failure in streaming mode."""
    mock_is_hf_url.return_value = True
    mock_download_streaming.side_effect = Exception("Streaming download failed")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "https://huggingface.co/test/model"])

    # Should fail with error code 2
    assert result.exit_code == 2
    assert "Error" in result.output


@pytest.mark.parametrize(("malicious", "expected_exit_code"), [(False, 0), (True, 1)])
@patch("modelaudit.utils.sources.huggingface._run_huggingface_download_with_deadline")
@patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={"", ".bin"})
@patch(
    "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
    return_value=(["model.unknown"], _HF_TEST_REVISION, None),
)
@patch("huggingface_hub.hf_hub_download")
def test_scan_huggingface_streaming_routes_unknown_suffix_by_content(
    mock_hf_hub_download: MagicMock,
    _mock_list_repo_files: MagicMock,
    _mock_get_extensions: MagicMock,
    mock_run_download: MagicMock,
    tmp_path: Path,
    malicious: bool,
    expected_exit_code: int,
) -> None:
    """Bounded unknown-suffix files should preserve benign and malicious content routing."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.unknown", malicious=malicious)
    mock_hf_hub_download.return_value = str(model_path)
    mock_run_download.side_effect = lambda _operation, download_kwargs, _deadline, _repo_id, *, direct_download: str(
        direct_download(**download_kwargs)
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--stream", "--no-cache", "--format", "json", "hf://test/model"],
    )

    parsed = parse_click_json_output(result.output)
    assert result.exit_code == expected_exit_code
    assert parsed["has_errors"] is False
    assert parsed["files_scanned"] == 1
    assert (parsed["failed_checks"] > 0) is malicious
    mock_hf_hub_download.assert_called_once()
    mock_run_download.assert_called_once()


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.utils.sources.huggingface.download_model_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_huggingface_streaming_scan_errors(mock_scan_streaming, mock_download_streaming, mock_is_hf_url, tmp_path):
    """Test handling of scan errors during streaming."""
    mock_is_hf_url.return_value = True

    # Mock file generator
    test_file = tmp_path / "test.bin"
    test_file.write_text("test content")

    def file_generator():
        yield (test_file, True)

    mock_download_streaming.return_value = file_generator()

    # Mock scan result with errors
    mock_result = create_mock_scan_result(bytes_scanned=100, files_scanned=1, has_errors=True)
    mock_result.content_hash = "c" * 64
    mock_scan_streaming.return_value = mock_result

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "hf://test/model"])

    # Should exit with code 2 (scan errors)
    assert result.exit_code == 2

    # Verify streaming functions were called
    mock_download_streaming.assert_called_once()
    mock_scan_streaming.assert_called_once()


def test_scan_stream_help():
    """Test that --stream flag appears in help."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--stream" in result.output
    assert "download files one-by-one" in result.output.lower() or "stream" in result.output.lower()


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_cloud_url_success(
    mock_rmtree: MagicMock,
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_cloud: MagicMock,
    tmp_path: Path,
) -> None:
    """Test scanning a cloud storage URL successfully."""
    mock_is_cloud.return_value = True
    test_dir = tmp_path / "cloud"
    test_dir.mkdir()
    (test_dir / "model.bin").write_text("dummy")
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=123, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "s3://bucket/model.bin"])

    assert result.exit_code == 0
    mock_download.assert_called_once()
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_cloud_url_passes_scanner_selection_to_content_filter(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_cloud: MagicMock,
    tmp_path: Path,
) -> None:
    mock_is_cloud.return_value = True
    downloaded_file = tmp_path / "weights.payload"
    downloaded_file.write_bytes(b"weights")
    mock_download.return_value = downloaded_file
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    result = CliRunner().invoke(
        cli,
        ["scan", "--no-cache", "--scanners", "safetensors", "--quiet", "s3://bucket/models/"],
    )

    assert result.exit_code == 0
    assert mock_download.call_args.kwargs["scannable_extensions"] == frozenset({".safetensors"})
    assert mock_download.call_args.kwargs["scannable_filenames"] == frozenset()
    assert mock_download.call_args.kwargs["scanner_selection"]["enabled_scanner_ids"] == ["safetensors"]


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.utils.sources.cloud_storage.download_from_cloud_streaming")
@patch("modelaudit.core.scan_model_streaming")
def test_scan_cloud_url_streaming_passes_scanner_selection_to_content_filter(
    mock_scan_streaming: MagicMock,
    mock_download_streaming: MagicMock,
    mock_is_cloud: MagicMock,
) -> None:
    mock_is_cloud.return_value = True
    mock_download_streaming.return_value = iter(())
    mock_scan_streaming.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    result = CliRunner().invoke(
        cli,
        ["scan", "--stream", "--scanners", "safetensors", "--quiet", "s3://bucket/models/"],
    )

    assert result.exit_code == 0
    assert mock_download_streaming.call_args.kwargs["scannable_extensions"] == frozenset({".safetensors"})
    assert mock_download_streaming.call_args.kwargs["scannable_filenames"] == frozenset()
    assert mock_download_streaming.call_args.kwargs["scanner_selection"]["enabled_scanner_ids"] == ["safetensors"]
    assert mock_scan_streaming.call_args.kwargs["shard_family_group"].startswith("stream-invocation:")


@patch("os.remove")
@patch("shutil.rmtree")
@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_cloud_file_no_cache_cleans_up_downloaded_file(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_cloud: MagicMock,
    mock_rmtree: MagicMock,
    mock_remove: MagicMock,
    tmp_path: Path,
) -> None:
    """No-cache cloud scans should delete downloaded files, not treat them as directories."""
    mock_is_cloud.return_value = True
    downloaded_file = tmp_path / "downloaded-model.bin"
    downloaded_file.write_bytes(b"weights")
    mock_download.return_value = downloaded_file
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=123, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "s3://bucket/model.bin"])

    assert result.exit_code == 0
    mock_remove.assert_called_once_with(str(downloaded_file))
    mock_rmtree.assert_not_called()


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
def test_scan_cloud_url_download_failure(mock_download: MagicMock, mock_is_cloud: MagicMock) -> None:
    """Test download failure for cloud storage URL."""
    mock_is_cloud.return_value = True
    mock_download.side_effect = Exception("boom")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "s3://bucket/model.bin"])

    assert result.exit_code == 2
    assert "Error downloading" in result.output


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
def test_scan_cloud_url_download_failure_redacts_signed_url(mock_download: MagicMock, mock_is_cloud: MagicMock) -> None:
    """Signed cloud URL secrets should not leak through shared CLI output."""
    url = "s3://bucket/model.bin?X-Amz-Signature=secret"
    mock_is_cloud.return_value = True
    mock_download.side_effect = Exception(f"Forbidden while opening {url}")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", url])

    assert result.exit_code == 2
    assert "s3://bucket/model.bin" in result.output
    assert "X-Amz-Signature" not in result.output
    assert "secret" not in result.output


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
def test_scan_cloud_url_download_failure_verbose_log_redacts_signed_url(
    mock_download: MagicMock,
    mock_is_cloud: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verbose cloud errors should not append raw signed URLs through tracebacks."""
    url = "s3://bucket/model.bin?X-Amz-Signature=deadbeef&token=secret-token"
    mock_is_cloud.return_value = True
    mock_download.side_effect = Exception(f"Forbidden while opening {url}")
    runner = CliRunner()

    with caplog.at_level(logging.ERROR, logger="modelaudit"):
        result = runner.invoke(cli, ["scan", "--verbose", url])

    assert result.exit_code == 2
    assert "s3://bucket/model.bin" in caplog.text
    assert "deadbeef" not in caplog.text
    assert "secret-token" not in caplog.text
    assert "X-Amz-Signature" not in caplog.text


def test_scan_cloud_url_dry_run_failure_redacts_signed_url() -> None:
    """Cloud preview failures should redact signed URLs embedded in provider errors."""
    url = "s3://bucket/model.bin?X-Amz-Signature=deadbeef&token=secret-token"
    runner = CliRunner()

    with (
        patch("modelaudit.cli.is_cloud_url", return_value=True),
        patch("modelaudit.utils.sources.cloud_storage.analyze_cloud_target", new_callable=AsyncMock) as mock_analyze,
    ):
        mock_analyze.side_effect = Exception(f"Forbidden while opening {url}")
        result = runner.invoke(cli, ["scan", "--dry-run", url])

    assert result.exit_code == 2
    assert "s3://bucket/model.bin" in result.output
    assert "deadbeef" not in result.output
    assert "secret-token" not in result.output
    assert "X-Amz-Signature" not in result.output


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
def test_scan_cloud_url_download_failure_sbom_redacts_signed_url(
    mock_download: MagicMock, mock_is_cloud: MagicMock, tmp_path: Path
) -> None:
    """SBOM fallback paths should not persist raw signed cloud URLs."""
    url = "s3://bucket/model.bin?X-Amz-Signature=deadbeef&token=secret-token"
    sbom_file = tmp_path / "scan.sbom.json"
    mock_is_cloud.side_effect = lambda candidate: candidate.startswith("s3://")
    mock_download.side_effect = Exception(f"Forbidden while opening {url}")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--quiet", "--sbom", str(sbom_file), url])

    assert result.exit_code == 2
    sbom_text = sbom_file.read_text()
    assert "s3://bucket/model.bin" in sbom_text
    assert "deadbeef" not in sbom_text
    assert "secret-token" not in sbom_text
    assert "X-Amz-Signature" not in sbom_text


def test_display_path_redacts_signed_stream_url() -> None:
    """stream:// display values should keep routing context without signed query material."""
    url = "stream://https://models.example/model.bin?X-Amz-Signature=secret&token=hidden"

    display_path = _display_path(url)
    display_error = _display_error(f"Forbidden while opening {url}", url)

    assert display_path == "stream://https://models.example/model.bin"
    assert "stream://https://models.example/model.bin" in display_error
    assert "X-Amz-Signature" not in display_error
    assert "hidden" not in display_error


def test_display_path_redacts_mixed_case_signed_urls() -> None:
    """URI scheme and host casing must not bypass display redaction."""
    stream_url = "STREAM://HTTPS://BUCKET.S3.AMAZONAWS.COM/model.bin?X-Amz-Signature=stream-secret"
    cloud_url = "HTTPS://BUCKET.S3.AMAZONAWS.COM/model.bin?X-Amz-Signature=cloud-secret"

    assert _display_path(stream_url) == "stream://https://bucket.s3.amazonaws.com/model.bin"
    assert _display_path(cloud_url) == "https://bucket.s3.amazonaws.com/model.bin"


@patch("modelaudit.cli.download_from_cloud")
def test_scan_rejects_cleartext_cloud_url_without_leaking_credentials(mock_download: MagicMock) -> None:
    url = "HTTP://BUCKET.S3.AMAZONAWS.COM:80/model.bin?X-Amz-Signature=cloud-secret"

    result = CliRunner().invoke(cli, ["scan", url])

    assert result.exit_code == 2
    assert "Cleartext cloud storage URL is not supported" in result.output
    assert "http://bucket.s3.amazonaws.com:80/model.bin" in result.output.lower()
    assert "cloud-secret" not in result.output
    mock_download.assert_not_called()


@patch("modelaudit.cli.download_pytorch_hub_model")
def test_scan_rejects_cleartext_pytorch_hub_url_without_downloading(mock_download: MagicMock) -> None:
    url = "HTTP://PYTORCH.ORG:80/hub/pytorch_vision_resnet/?token=hub-secret"

    result = CliRunner().invoke(cli, ["scan", url])

    assert result.exit_code == 2
    assert "Cleartext PyTorch Hub URL is not supported" in result.output
    assert "http://pytorch.org:80/hub/pytorch_vision_resnet/" in result.output.lower()
    assert "hub-secret" not in result.output
    mock_download.assert_not_called()


def test_progress_initial_status_redacts_signed_stream_url() -> None:
    """Initial progress status should not expose signed stream URLs."""
    url = "stream://https://bucket.s3.amazonaws.com/model.bin?X-Amz-Signature=deadbeef&token=secret-token"

    class _Stats:
        total_bytes = 0
        total_items = 0

    class _Tracker:
        stats = _Stats()

        def __init__(self) -> None:
            self.messages: list[str] = []

        def set_phase(self, _phase: object, message: str) -> None:
            self.messages.append(message)

        def update_bytes(self, _bytes_processed: int, _message: str) -> None:
            pass

    tracker = _Tracker()
    callback = _create_path_progress_callback(spinner=None, progress_tracker=tracker, actual_path=url)

    assert callback is not None
    assert tracker.messages == ["Starting scan: stream://https://bucket.s3.amazonaws.com/model.bin"]


def test_scan_path_state_redacts_stream_fallback_for_sbom() -> None:
    """Fallback SBOM paths for stream:// scans must not persist signed query strings."""
    url = "stream://https://bucket.s3.amazonaws.com/model.bin?X-Amz-Signature=secret"
    path_state = _ScanPathState()

    path_state.track_streaming_paths_for_sbom(create_initial_audit_result(), url)

    assert path_state.scanned_paths == ["stream://https://bucket.s3.amazonaws.com/model.bin"]


def test_scan_path_state_omits_empty_local_streaming_inventory_for_sbom(tmp_path: Path) -> None:
    """A local streamed inventory with no assets must not fall back to re-inventorying the directory."""
    model_dir = tmp_path / "only-sidecars"
    model_dir.mkdir()
    path_state = _ScanPathState()

    path_state.track_streaming_paths_for_sbom(create_initial_audit_result(), str(model_dir))

    assert path_state.sbom_paths_resolved is True
    assert path_state.scanned_paths == []


def test_scan_path_state_preserves_local_asset_path_for_sbom() -> None:
    local_path = "model\nname.pkl"
    scan_result = create_mock_scan_result(assets=[{"path": local_path, "type": "pickle"}])
    path_state = _ScanPathState()

    path_state.track_streaming_paths_for_sbom(scan_result, None)

    assert path_state.scanned_paths == [local_path]


def test_progress_callback_escapes_model_controlled_messages(tmp_path: Path) -> None:
    model_path = tmp_path / "model\nname.pkl"

    class _Stats:
        total_bytes = 0
        total_items = 0

    class _Tracker:
        stats = _Stats()

        def __init__(self) -> None:
            self.messages: list[str] = []

        def set_phase(self, _phase: object, message: str) -> None:
            self.messages.append(message)

        def update_bytes(self, _bytes_processed: int, message: str) -> None:
            self.messages.append(message)

    tracker = _Tracker()
    callback = _create_path_progress_callback(
        spinner=None,
        progress_tracker=tracker,
        actual_path=str(model_path),
    )

    assert callback is not None
    callback("Scanning member\nFORGED\x1b[2J", 50.0)

    assert tracker.messages[0].endswith("model\\nname.pkl")
    assert tracker.messages[1:] == ["Scanning member\\nFORGED\\x1b[2J", "Scanning member\\nFORGED\\x1b[2J"]


def test_progress_callback_wrapper_escapes_spinner_message() -> None:
    callback = MagicMock()
    spinner = types.SimpleNamespace(text="")
    wrapped_callback = cli_module.create_progress_callback_wrapper(callback, spinner)

    assert wrapped_callback is not None
    wrapped_callback("Scanning member\nFORGED\x1b[2J", 50.0)

    callback.assert_called_once_with("Scanning member\nFORGED\x1b[2J", 50.0)
    assert spinner.text == "Scanning member\\nFORGED\\x1b[2J"


def test_scan_stream_unexpected_verbose_error_omits_raw_traceback(caplog: pytest.LogCaptureFixture) -> None:
    """Verbose stream failures must not reintroduce signed URLs through exception tracebacks."""
    url = "stream://https://bucket.s3.amazonaws.com/model.bin?X-Amz-Signature=deadbeef&token=secret-token"
    runner = CliRunner()

    with (
        caplog.at_level(logging.ERROR, logger="modelaudit"),
        patch(
            "modelaudit.cli._resolve_scan_source_for_path",
            side_effect=RuntimeError(f"unexpected failure for {url}"),
        ),
    ):
        result = runner.invoke(cli, ["scan", "--verbose", url])

    assert result.exit_code == 2
    assert "stream://https://bucket.s3.amazonaws.com/model.bin" in caplog.text
    assert "deadbeef" not in caplog.text
    assert "secret-token" not in caplog.text
    assert "X-Amz-Signature" not in caplog.text


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_cloud_stream_verbose_scan_failure_omits_raw_traceback(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_cloud: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Post-download stream failures must not leak the signed URL through tracebacks."""
    url = "s3://bucket/model.pkl?X-Amz-Signature=deadbeef&token=secret-token"
    stream_path = f"stream://{url}"
    mock_is_cloud.side_effect = lambda candidate: candidate.startswith("s3://")
    mock_download.return_value = stream_path
    mock_scan.side_effect = RuntimeError(f"scan failed for {url}")
    runner = CliRunner()

    with caplog.at_level(logging.ERROR, logger="modelaudit"):
        result = runner.invoke(cli, ["scan", "--verbose", url])

    assert result.exit_code == 2
    assert "s3://bucket/model.pkl" in caplog.text
    assert "deadbeef" not in caplog.text
    assert "secret-token" not in caplog.text
    assert "X-Amz-Signature" not in caplog.text


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_cloud_url_with_issues(
    mock_rmtree: MagicMock,
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_cloud: MagicMock,
    tmp_path: Path,
) -> None:
    """Test scanning a cloud storage URL that has issues."""
    mock_is_cloud.return_value = True
    test_dir = tmp_path / "cloud"
    test_dir.mkdir()
    (test_dir / "model.pkl").write_text("dummy")
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=123,
        issues=[{"message": "bad", "severity": "critical", "location": "model.pkl"}],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["pickle"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "gs://bucket/model.pkl"])

    assert result.exit_code == 1
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_cloud_url_no_cache_with_cache_dir_cleans_downloads(
    mock_rmtree: MagicMock,
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_cloud: MagicMock,
    tmp_path: Path,
) -> None:
    """--no-cache must not preserve remote downloads just because --cache-dir was provided."""
    mock_is_cloud.return_value = True
    test_dir = tmp_path / "cloud-nocache"
    test_dir.mkdir()
    (test_dir / "model.bin").write_text("dummy")
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=123, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test"]
    )

    cache_dir = tmp_path / "cache"
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "--cache-dir", str(cache_dir), "s3://bucket/model.bin"])

    assert result.exit_code == 0
    mock_download.assert_called_once()
    assert mock_download.call_args.kwargs["cache_dir"] is None
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_cloud_url_strict_disables_selective_prefiltering(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_is_cloud: MagicMock,
    tmp_path: Path,
) -> None:
    """Strict mode should disable cloud-side selective filtering."""
    mock_is_cloud.return_value = True
    test_dir = tmp_path / "cloud-strict"
    test_dir.mkdir()
    (test_dir / "helper.py").write_text("print('strict cloud file')\n")
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--strict", "s3://bucket/model-prefix/"])

    assert result.exit_code == 0
    mock_download.assert_called_once()
    assert mock_download.call_args.kwargs["selective"] is False
    mock_scan.assert_called_once()
    assert mock_scan.call_args.kwargs["skip_file_types"] is False


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_success(
    mock_scan_jfrog: MagicMock,
    mock_is_jfrog: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Test scanning a JFrog URL."""
    monkeypatch.setenv("HOME", str(tmp_path))
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = create_mock_scan_result(
        bytes_scanned=512, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://company.jfrog.io/artifactory/repo/model.bin"])

    assert result.exit_code == 0
    mock_scan_jfrog.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        api_token=None,
        access_token=None,
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        strict_license=False,
        skip_file_types=True,
        cache_enabled=True,
        cache_dir=default_remote_cache_dir(),
        selective_download=True,
        use_hf_whitelist=True,
    )


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_passes_selected_exact_filenames(
    mock_scan_jfrog: MagicMock,
    mock_is_jfrog: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = create_mock_scan_result(files_scanned=1, issues=[])

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--scanners",
            "metadata",
            "--quiet",
            "https://company.jfrog.io/artifactory/repo/models/",
        ],
    )

    assert result.exit_code == 0
    assert mock_scan_jfrog.call_args.kwargs["scannable_filenames"] == frozenset({"readme", "model_card"})
    assert mock_scan_jfrog.call_args.kwargs["scanner_selection"]["enabled_scanner_ids"] == ["metadata"]


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_with_max_size_forwards_download_budget(
    mock_scan_jfrog: MagicMock,
    mock_is_jfrog: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """CLI --max-size should cap JFrog acquisition before scan-time limits run."""
    monkeypatch.setenv("HOME", str(tmp_path))
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = create_mock_scan_result(
        bytes_scanned=5, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--max-size", "5B", "https://company.jfrog.io/artifactory/repo/model.bin"])

    assert result.exit_code == 0
    mock_scan_jfrog.assert_called_once()
    call_kwargs = mock_scan_jfrog.call_args.kwargs
    assert call_kwargs["max_download_size"] == 5
    assert call_kwargs["max_file_size"] == 5
    assert call_kwargs["max_total_size"] == 5


@patch("modelaudit.cli.generate_auto_defaults")
@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_does_not_forward_implicit_file_limit_as_total_budget(
    mock_scan_jfrog: MagicMock,
    mock_is_jfrog: MagicMock,
    mock_auto_defaults: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Implicit per-file defaults must not become cumulative JFrog folder limits."""
    monkeypatch.setenv("HOME", str(tmp_path))
    mock_is_jfrog.return_value = True
    mock_auto_defaults.return_value = {
        "format": "json",
        "max_file_size": 10,
        "max_total_size": 0,
        "selective_download": True,
        "skip_non_model_files": True,
        "timeout": 3600,
        "use_cache": False,
        "use_hf_whitelist": True,
    }
    mock_scan_jfrog.return_value = create_mock_scan_result(
        bytes_scanned=16,
        issues=[],
        files_scanned=2,
        assets=[],
        has_errors=False,
        scanners=["test_scanner"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://company.jfrog.io/artifactory/repo/models/"])

    assert result.exit_code == 0
    mock_scan_jfrog.assert_called_once()
    call_kwargs = mock_scan_jfrog.call_args.kwargs
    assert call_kwargs["max_file_size"] == 10
    assert call_kwargs["max_total_size"] == 0
    assert "max_download_size" not in call_kwargs


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_download_failure(mock_scan_jfrog, mock_is_jfrog):
    """Test handling of JFrog download failures."""
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.side_effect = Exception("fail")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://company.jfrog.io/artifactory/repo/model.bin"])

    assert result.exit_code == 2
    assert "Error downloading/scanning model" in result.output


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_download_failure_redacts_sensitive_url(mock_scan_jfrog, mock_is_jfrog):
    """JFrog CLI errors should not print URL credentials or query tokens."""
    raw_url = "https://user:leaky-pass@company.jfrog.io/artifactory/repo/model.bin?token=leaky-token"
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.side_effect = Exception(f"failed to fetch {raw_url}")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", raw_url])

    assert result.exit_code == 2
    assert "https://<credentials-redacted>@company.jfrog.io/artifactory/repo/model.bin" in result.output
    assert "user:leaky-pass" not in result.output
    assert "leaky-token" not in result.output
    assert "?token=" not in result.output


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_scan_rejected_jfrog_url_redacts_sensitive_url(scheme: str) -> None:
    """Rejected local or plaintext JFrog URLs must be redacted in generic path errors."""
    raw_url = f"{scheme}://user:leaky-pass@localhost/artifactory/repo/model.bin?token=leaky-token"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", raw_url])

    assert result.exit_code == 2
    assert f"{scheme}://<credentials-redacted>@localhost/artifactory/repo/model.bin" in result.output
    assert "user:leaky-pass" not in result.output
    assert "leaky-token" not in result.output
    assert "?token=" not in result.output


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_with_auth(
    mock_scan_jfrog: MagicMock,
    mock_is_jfrog: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Test scanning a JFrog URL with authentication."""
    monkeypatch.setenv("HOME", str(tmp_path))
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = create_mock_scan_result(
        bytes_scanned=512, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    # Use environment variable instead of CLI flag
    result = runner.invoke(
        cli,
        [
            "scan",
            "https://company.jfrog.io/artifactory/repo/model.bin",
            "--timeout",
            "600",
        ],
        env={"JFROG_API_TOKEN": "test-token"},
    )

    assert result.exit_code == 0
    mock_scan_jfrog.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        api_token="test-token",
        access_token=None,
        timeout=600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        strict_license=False,
        skip_file_types=True,
        cache_enabled=True,
        cache_dir=default_remote_cache_dir(),
        selective_download=True,
        use_hf_whitelist=True,
    )


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_with_cache_dir(mock_scan_jfrog: MagicMock, mock_is_jfrog: MagicMock, tmp_path: Path) -> None:
    """Test scanning a JFrog URL with an explicit cache directory."""
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = create_mock_scan_result(
        bytes_scanned=512, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    cache_dir = tmp_path / "jfrog-cache"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--cache-dir", str(cache_dir), "https://company.jfrog.io/artifactory/repo/model.bin"],
    )

    assert result.exit_code == 0
    mock_scan_jfrog.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        api_token=None,
        access_token=None,
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        strict_license=False,
        skip_file_types=True,
        cache_enabled=True,
        cache_dir=str(cache_dir),
        selective_download=True,
        use_hf_whitelist=True,
    )


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_no_cache_overrides_cache_dir(
    mock_scan_jfrog: MagicMock, mock_is_jfrog: MagicMock, tmp_path: Path
) -> None:
    """Test that --no-cache disables JFrog caching even when --cache-dir is set."""
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = create_mock_scan_result(
        bytes_scanned=512, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    cache_dir = tmp_path / "jfrog-cache"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--cache-dir",
            str(cache_dir),
            "--no-cache",
            "https://company.jfrog.io/artifactory/repo/model.bin",
        ],
    )

    assert result.exit_code == 0
    mock_scan_jfrog.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        api_token=None,
        access_token=None,
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        strict_license=False,
        skip_file_types=True,
        cache_enabled=False,
        cache_dir=None,
        selective_download=True,
        use_hf_whitelist=True,
    )


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_strict_disables_selective_prefiltering(
    mock_scan_jfrog: MagicMock, mock_is_jfrog: MagicMock
) -> None:
    """Strict JFrog scans should disable folder prefiltering before scanning."""
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = create_mock_scan_result(
        bytes_scanned=512, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--strict", "https://company.jfrog.io/artifactory/repo/models/"])

    assert result.exit_code == 0
    assert mock_scan_jfrog.call_args.kwargs["selective_download"] is False
    assert mock_scan_jfrog.call_args.kwargs["skip_file_types"] is False
    assert mock_scan_jfrog.call_args.kwargs["use_hf_whitelist"] is False
    assert mock_scan_jfrog.call_args.kwargs["cache_enabled"] is False
    assert mock_scan_jfrog.call_args.kwargs["cache_dir"] is None


@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_success(
    mock_scan_mlflow: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Test successful scanning of an MLflow URI."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Setup mock
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=1024, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", "--format", "text", "models:/TestModel/1"], env={"MLFLOW_TRACKING_URI": "http://localhost:5000"}
    )

    # Should succeed
    assert result.exit_code == 0
    # Check for scan summary or successful completion indicators
    assert (
        "SCAN SUMMARY" in result.output
        or "Files:" in result.output
        or "Duration:" in result.output
        or "Clean" in result.output
    )

    # Verify MLflow scan was called with correct parameters
    mock_scan_mlflow.assert_called_once_with(
        "models:/TestModel/1",
        registry_uri="http://localhost:5000",
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        cache_enabled=True,
        cache_dir=default_remote_cache_dir(),
        use_hf_whitelist=True,
    )


@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_with_options(
    mock_scan_mlflow: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Test MLflow URI scanning with additional options."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Setup mock
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=2048,
        issues=[{"message": "Test issue", "severity": "warning"}],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["test_scanner"],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "models:/TestModel/Production",
            "--timeout",
            "600",
            "--max-size",
            "5000000",  # Combined limit (using the larger value)
            "--verbose",
        ],
        env={"MLFLOW_TRACKING_URI": "http://mlflow.example.com"},
    )

    # Should succeed with findings
    assert result.exit_code == 1  # Exit code 1 indicates issues found

    # Verify MLflow scan was called with environment-based options
    mock_scan_mlflow.assert_called_once_with(
        "models:/TestModel/Production",
        registry_uri="http://mlflow.example.com",
        timeout=600,
        blacklist_patterns=None,
        max_file_size=5000000,
        max_total_size=5000000,
        cache_enabled=True,
        cache_dir=default_remote_cache_dir(),
        use_hf_whitelist=True,
    )


@patch("modelaudit.cli.record_download_completed")
@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_budget_refusal_is_not_recorded_as_completed(
    mock_scan_mlflow: MagicMock,
    mock_record_download_completed: MagicMock,
) -> None:
    """Budget refusals should not emit successful-download telemetry."""
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=0,
        issues=[
            {
                "message": "Unable to determine MLflow artifact size before download",
                "severity": "info",
                "type": "mlflow_download_budget",
            }
        ],
        files_scanned=0,
        has_errors=True,
        success=False,
        scanners=["mlflow"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--format", "text", "models:/TestModel/1"])

    assert result.exit_code == 2
    assert "Download refused by configured size budget" in result.output
    mock_record_download_completed.assert_not_called()


@patch("modelaudit.cli.record_download_completed")
@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_trust_refusal_is_not_recorded_as_completed(
    mock_scan_mlflow: MagicMock,
    mock_record_download_completed: MagicMock,
) -> None:
    """MLflow artifact trust refusals should not emit successful-download telemetry."""
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=0,
        issues=[
            {
                "message": "MLflow artifact repository is not in the configured allowlist",
                "severity": "info",
                "type": "mlflow_artifact_trust",
            }
        ],
        files_scanned=0,
        has_errors=True,
        success=False,
        scanners=["mlflow"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--format", "text", "models:/TestModel/1"])

    assert result.exit_code == 2
    assert "Download refused by MLflow artifact trust policy" in result.output
    mock_record_download_completed.assert_not_called()


@patch("modelaudit.cli.record_download_completed")
@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_path_refusal_is_not_recorded_as_completed(
    mock_scan_mlflow: MagicMock,
    mock_record_download_completed: MagicMock,
) -> None:
    """Staging safety refusals must not emit successful-download output or telemetry."""
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=0,
        issues=[
            {
                "message": "MLflow staging directory changed during artifact download",
                "severity": "info",
                "type": "mlflow_download_path",
            }
        ],
        files_scanned=0,
        has_errors=True,
        success=False,
        scanners=["mlflow"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--format", "text", "models:/TestModel/1"])

    assert result.exit_code == 2
    assert "Download refused by MLflow staging safety checks" in result.output
    assert "Downloaded and scanned successfully" not in result.output
    mock_record_download_completed.assert_not_called()


@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_with_cache_dir(mock_scan_mlflow: MagicMock, tmp_path: Path) -> None:
    """Test scanning an MLflow URI with an explicit cache directory."""
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=1024, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    cache_dir = tmp_path / "mlflow-cache"
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--cache-dir", str(cache_dir), "models:/TestModel/1"])

    assert result.exit_code == 0
    mock_scan_mlflow.assert_called_once_with(
        "models:/TestModel/1",
        registry_uri=None,
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        cache_enabled=True,
        cache_dir=str(cache_dir),
        use_hf_whitelist=True,
    )


@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_no_cache_overrides_cache_dir(mock_scan_mlflow: MagicMock, tmp_path: Path) -> None:
    """Test that --no-cache disables MLflow caching even when --cache-dir is set."""
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=1024, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    cache_dir = tmp_path / "mlflow-cache"
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--cache-dir", str(cache_dir), "--no-cache", "models:/TestModel/1"])

    assert result.exit_code == 0
    mock_scan_mlflow.assert_called_once_with(
        "models:/TestModel/1",
        registry_uri=None,
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        cache_enabled=False,
        cache_dir=None,
        use_hf_whitelist=True,
    )


@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_error(
    mock_scan_mlflow: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test error handling for MLflow URI scanning."""
    mock_scan_mlflow.side_effect = Exception("MLflow connection failed token=mlflow_secret\nFORGED\x1b[2J")

    runner = CliRunner()
    with caplog.at_level(logging.ERROR, logger="modelaudit"):
        result = runner.invoke(cli, ["scan", "--verbose", "models:/TestModel/1"])

    assert result.exit_code == 2
    assert "Error downloading model" in result.output
    assert "MLflow connection failed" in result.output
    assert "mlflow_secret" not in result.output
    assert "\nFORGED" not in result.output
    assert "\x1b" not in result.output
    assert "mlflow_secret" not in caplog.text
    assert "\nFORGED" not in caplog.text
    assert "\x1b" not in caplog.text


@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_error_redacts_registry_credentials(
    mock_scan_mlflow: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """MLflow client errors must not expose registry URLs or auth material."""
    raw_secret_parts = [
        "user:pass",
        "RELATIVEPASS1234567890",
        "QUERYSECRET1234567890",
        "HEADERSECRET1234567890",
        "PROXYSECRET1234567890",
        "PATHSECRET1234567890",
    ]
    mock_scan_mlflow.side_effect = RuntimeError(
        "registry_uri=https://user:pass@mlflow.example.test/api?token=QUERYSECRET1234567890 "
        "artifact_uri=//user:RELATIVEPASS1234567890@mlflow.example.test/model "
        "authorization=Bearer HEADERSECRET1234567890 "
        "proxy-authorization=ApiKey PROXYSECRET1234567890"
    )

    caplog.set_level(logging.ERROR, logger="modelaudit")
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--verbose", "models:/PrivateModel/access_token=PATHSECRET1234567890"],
    )

    assert result.exit_code == 2
    assert "Error downloading model from models:/PrivateModel/access_token=<redacted>" in result.output
    assert "<redacted>" in result.output
    for secret in raw_secret_parts:
        assert secret not in result.output
        assert secret not in caplog.text


@patch("modelaudit.integrations.mlflow.scan_mlflow_model")
def test_scan_mlflow_uri_json_format(mock_scan_mlflow):
    """Test MLflow URI scanning with JSON output format."""
    # Setup mock
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=1024,
        issues=[],
        files_scanned=1,
        assets=[{"path": "model.pkl", "type": "pickle"}],
        has_errors=False,
        scanners=["pickle"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "models:/TestModel/1", "--format", "json"])

    # Should succeed and output JSON
    assert result.exit_code == 0

    # Should contain JSON output
    assert "bytes_scanned" in result.output
    assert "files_scanned" in result.output
    assert "assets" in result.output


def test_is_mlflow_uri():
    """Test the is_mlflow_uri helper function."""
    from modelaudit.cli import is_mlflow_uri

    # Test valid MLflow URIs
    assert is_mlflow_uri("models:/MyModel/1")
    assert is_mlflow_uri("models:/MyModel/Production")
    assert is_mlflow_uri("models:/MyModel/Staging")

    # Test invalid URIs
    assert not is_mlflow_uri("/path/to/model.pkl")
    assert not is_mlflow_uri("https://huggingface.co/model")
    assert not is_mlflow_uri("hf://model")
    assert not is_mlflow_uri("model.pkl")
    assert not is_mlflow_uri("models:invalid")


def test_format_text_output_normal_scan_duration():
    """Test duration formatting for normal scans (>= 0.01 seconds)."""
    results = {
        "path": "/path/to/model",
        "files_scanned": 2,
        "bytes_scanned": 2048,
        "duration": 0.25,  # Normal scan >= 0.01 seconds
        "issues": [],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)

    # Should show 2 decimal places for normal scans
    assert "Duration:" in clean_output and "0.25s" in clean_output
    assert "Files:" in clean_output and "2" in clean_output
    assert "No security issues detected" in clean_output


def test_format_text_output_edge_case_duration():
    """Test duration formatting for edge case exactly at 0.01 seconds."""
    results = {
        "path": "/path/to/model",
        "files_scanned": 1,
        "bytes_scanned": 1024,
        "duration": 0.01,  # Edge case exactly at threshold
        "issues": [],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)

    # Should show 2 decimal places (>= 0.01 branch)
    assert "Duration:" in clean_output and "0.01s" in clean_output
    assert "Files:" in clean_output and "1" in clean_output
    assert "No security issues detected" in clean_output


def test_format_text_output_very_fast_scan_with_issues():
    """Test duration formatting for very fast scan with issues."""
    results = {
        "path": "/path/to/model",
        "files_scanned": 1,
        "bytes_scanned": 256,
        "duration": 0.003,  # Very fast scan with issues
        "issues": [
            {
                "message": "Suspicious pattern detected",
                "severity": "warning",
                "location": "malicious.pkl",
                "details": {"pattern": "eval"},
            },
        ],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)

    # Should show 3 decimal places for very fast scans
    assert "Duration:" in clean_output and "0.003s" in clean_output
    assert "Files:" in clean_output and "1" in clean_output
    assert "Suspicious pattern detected" in clean_output
    assert "warning" in output.lower()


def test_exit_code_clean_scan(tmp_path):
    """Test exit code 0 when scan is clean with no issues."""
    import pickle

    # Create a clean pickle file that should have no security issues
    test_file = tmp_path / "clean_model.pkl"
    data = {
        "weights": [1.0, 2.0, 3.0],
        "biases": [0.1, 0.2, 0.3],
        "model_name": "clean_model",
    }
    with (test_file).open("wb") as f:
        pickle.dump(data, f)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--format", "text", str(test_file)])

    # Should exit with code 0 for clean scan
    assert result.exit_code == 0, f"Expected exit code 0, got {result.exit_code}. Output: {result.output}"
    # The output might not say "No issues found" if there are debug messages,
    # so let's be less strict
    assert "scan completed successfully" in result.output.lower() or "no issues found" in result.output.lower()


def test_exit_code_security_issues(tmp_path):
    """Test exit code 1 when security issues are found."""
    import pickle

    # Create a malicious pickle file
    evil_pickle_path = tmp_path / "malicious.pkl"

    class MaliciousClass:
        def __reduce__(self):
            return (os.system, ('echo "This is a malicious pickle"',))

    with evil_pickle_path.open("wb") as f:
        pickle.dump(MaliciousClass(), f)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--format", "text", str(evil_pickle_path)])

    # Should exit with code 1 for security findings
    assert result.exit_code == 1, f"Expected exit code 1, got {result.exit_code}. Output: {result.output}"
    # Check for error, warning, or critical in output
    output_lower = result.output.lower()
    assert "error" in output_lower or "warning" in output_lower or "critical" in output_lower, (
        f"Expected 'error', 'warning', or 'critical' in output, but got: {result.output}"
    )


def test_exit_code_security_issues_streaming_local_directory(tmp_path: Path) -> None:
    """Streaming local-directory scans should keep security findings as exit code 1 without deleting originals."""
    import pickle

    evil_pickle_path = tmp_path / "malicious.pkl"
    expected_global = f"{os.system.__module__}.system"

    class MaliciousClass:
        def __reduce__(self):
            return (os.system, ('echo "This is a malicious pickle"',))

    with evil_pickle_path.open("wb") as f:
        pickle.dump(MaliciousClass(), f)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "--format", "text", str(tmp_path)])

    assert result.exit_code == 1, f"Expected exit code 1, got {result.exit_code}. Output: {result.output}"
    assert expected_global in result.output, f"Expected malicious finding in output, got: {result.output}"
    assert evil_pickle_path.exists()


def test_exit_code_streaming_symlink_traversal_without_safe_files(tmp_path: Path, requires_symlinks: None) -> None:
    """Streaming traversal findings should exit 1 even when no files are ultimately scanned."""
    import pickle

    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    with (outside_dir / "secret.pkl").open("wb") as f:
        pickle.dump({"data": "secret"}, f)

    symlink_path = base_dir / "link.pkl"
    symlink_path.symlink_to(outside_dir / "secret.pkl")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--stream", "--format", "text", str(base_dir)])

    output = strip_ansi(result.output)

    assert result.exit_code == 1, f"Expected exit code 1, got {result.exit_code}. Output: {result.output}"
    assert str(symlink_path) in output
    assert "Path traversal outside scanned directory" in output
    assert "CRITICAL SECURITY ISSUES FOUND" in output
    assert "NO FILES SCANNED" not in output


def test_cli_streaming_local_download_sidecars_excluded_from_inventory_and_sbom(tmp_path: Path) -> None:
    """CLI streaming scans should not count Hugging Face local-dir sidecars."""
    model_dir = tmp_path / "downloaded-model"
    model_dir.mkdir()
    config_path = model_dir / "config.json"
    config_path.write_text('{"model_type":"bert"}', encoding="utf-8")
    vocab_path = model_dir / "vocab.txt"
    vocab_path.write_text("[PAD]\n[UNK]\n", encoding="utf-8")

    download_root = model_dir / ".cache" / "huggingface" / "download"
    download_root.mkdir(parents=True)
    (download_root / "config.json.metadata").write_text(
        "c5ee24cb16019beea0893ab7796b1df96625c6b8\n821d1aa69520101d6e0737f78a042ae25b19e5c0\n1712656091.123\n",
        encoding="utf-8",
    )
    (download_root / "config.json.lock").touch()
    (download_root / "vocab.txt.metadata").write_text(
        "c5ee24cb16019beea0893ab7796b1df96625c6b8\n821d1aa69520101d6e0737f78a042ae25b19e5c0\n1712656091.123\n",
        encoding="utf-8",
    )
    (model_dir / ".cache" / "huggingface" / "CACHEDIR.TAG").write_text(
        "Signature: 8a477f597d28d172789f06886806bc55\n"
        "# This file is a cache directory tag created by huggingface_hub.\n"
        "# For information about cache directory tags, see:\n"
        "#\thttps://bford.info/cachedir/\n",
        encoding="utf-8",
    )
    sbom_file = tmp_path / "stream.sbom.json"
    file_hashes = [
        hashlib.sha256(config_path.read_bytes()).hexdigest(),
        hashlib.sha256(vocab_path.read_bytes()).hexdigest(),
    ]
    expected_content_hash = hashlib.sha256("".join(sorted(file_hashes)).encode()).hexdigest()

    result = CliRunner().invoke(
        cli,
        ["scan", "--stream", "--format", "json", "--no-cache", "--sbom", str(sbom_file), str(model_dir)],
    )

    assert result.exit_code == 0, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["files_scanned"] == 2
    assert output_payload["content_hash"] == expected_content_hash
    assert {Path(asset["path"]).relative_to(model_dir).as_posix() for asset in output_payload["assets"]} == {
        "config.json",
        "vocab.txt",
    }
    assert not any(".cache/huggingface" in path for path in output_payload["file_metadata"])
    assert not any(".cache/huggingface" in (check.get("location") or "") for check in output_payload["checks"])
    assert not any(".cache/huggingface" in (issue.get("location") or "") for issue in output_payload["issues"])

    sbom_data = json.loads(sbom_file.read_text())
    component_names = {component["name"] for component in sbom_data["components"]}
    assert component_names == {"config.json", "vocab.txt"}


def test_cli_streaming_empty_hf_cache_sidecars_do_not_populate_sbom(tmp_path: Path) -> None:
    """A zero-asset streaming scan should not re-inventory skipped Hugging Face cache tags for SBOM."""
    model_dir = tmp_path / "downloaded-model"
    cachedir_tag = model_dir / ".cache" / "huggingface" / "CACHEDIR.TAG"
    cachedir_tag.parent.mkdir(parents=True)
    cachedir_tag.write_text(
        "Signature: 8a477f597d28d172789f06886806bc55\n"
        "# This file is a cache directory tag created by huggingface_hub.\n"
        "# For information about cache directory tags, see:\n"
        "#\thttps://bford.info/cachedir/\n",
        encoding="utf-8",
    )
    sbom_file = tmp_path / "stream-empty.sbom.json"

    result = CliRunner().invoke(
        cli,
        ["scan", "--stream", "--format", "json", "--no-cache", "--sbom", str(sbom_file), str(model_dir)],
    )

    assert result.exit_code == 2, result.output
    output_payload = parse_click_json_output(result.output)
    assert output_payload["files_scanned"] == 0
    assert output_payload["assets"] == []
    assert output_payload["file_metadata"] == {}
    assert output_payload["success"] is True

    sbom_text = sbom_file.read_text()
    sbom_data = json.loads(sbom_text)
    assert sbom_data.get("components", []) == []
    assert "CACHEDIR.TAG" not in sbom_text


def test_exit_code_scan_errors(tmp_path):
    """Test exit code 2 when errors occur during scanning."""
    runner = CliRunner()

    # Try to scan a non-existent file
    result = runner.invoke(cli, ["scan", "/path/that/does/not/exist/file.pkl"])

    # Should exit with code 2 for scan errors
    assert result.exit_code == 2
    assert "Error" in result.output


def test_doctor_command():
    """Test the doctor command for scanner diagnostics."""
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])

    assert result.exit_code == 0
    assert "ModelAudit Scanner Diagnostic Report" in result.output
    assert "Python version:" in result.output
    assert "NumPy status:" in result.output
    assert "Total scanners:" in result.output
    assert "Loaded successfully:" in result.output
    assert "Failed to load:" in result.output


def test_doctor_command_with_show_failed():
    """Test the doctor command with --show-failed flag."""
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--show-failed"])

    assert result.exit_code == 0
    assert "ModelAudit Scanner Diagnostic Report" in result.output

    # Should show failed scanners if any exist
    if "Failed to load: 0" not in result.output:
        assert "Failed Scanners:" in result.output or "Recommendations:" in result.output


def test_doctor_command_numpy_status():
    """Test that doctor command provides NumPy compatibility information."""
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])

    assert result.exit_code == 0
    assert "NumPy" in result.output

    # Should provide either success message or recommendations
    success_indicators = ["All scanners loaded successfully!", "Recommendations:"]
    assert any(indicator in result.output for indicator in success_indicators)


# --- expand_paths and glob-empty-scan-paths tests ---


class TestExpandPaths:
    """Tests for the expand_paths function."""

    def test_expand_paths_literal_file(self, tmp_path):
        """Literal file path is resolved and returned."""
        f = tmp_path / "model.pkl"
        f.write_bytes(b"data")
        expanded, missing = expand_paths((str(f),))
        assert len(expanded) == 1
        assert str(f.resolve()) in expanded[0]
        assert missing == []

    def test_expand_paths_nonexistent_literal(self):
        """Non-existent literal path is kept as-is (no glob)."""
        expanded, missing = expand_paths(("/no/such/file.pkl",))
        assert expanded == ["/no/such/file.pkl"]
        assert missing == []

    def test_expand_paths_glob_matches(self, tmp_path):
        """Glob pattern that matches files returns them."""
        (tmp_path / "a.pkl").write_bytes(b"a")
        (tmp_path / "b.pkl").write_bytes(b"b")
        pattern = str(tmp_path / "*.pkl")
        expanded, missing = expand_paths((pattern,))
        assert len(expanded) == 2
        assert missing == []

    def test_expand_paths_glob_no_match(self, tmp_path):
        """Glob pattern matching nothing is reported in missing_globs."""
        pattern = str(tmp_path / "*.nonexistent")
        expanded, missing = expand_paths((pattern,))
        assert expanded == []
        assert missing == [pattern]

    def test_expand_paths_mixed_globs(self, tmp_path):
        """Mix of matching and non-matching globs."""
        (tmp_path / "model.h5").write_bytes(b"data")
        good = str(tmp_path / "*.h5")
        bad = str(tmp_path / "*.zzz")
        expanded, missing = expand_paths((good, bad))
        assert len(expanded) == 1
        assert missing == [bad]

    def test_expand_paths_recursive_glob(self, tmp_path):
        """Recursive glob (**) works."""
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "deep.bin").write_bytes(b"x")
        pattern = str(tmp_path / "**" / "*.bin")
        expanded, missing = expand_paths((pattern,))
        assert len(expanded) >= 1
        assert missing == []

    def test_expand_paths_question_mark_glob(self, tmp_path):
        """Single-char wildcard (?) is treated as a glob."""
        (tmp_path / "a.pt").write_bytes(b"x")
        pattern = str(tmp_path / "?.pt")
        expanded, missing = expand_paths((pattern,))
        assert len(expanded) == 1
        assert missing == []

    def test_expand_paths_signed_cloud_url_is_not_a_glob(self):
        """Signed cloud URLs may contain query wildcards but are not local globs."""
        url = "s3://bucket/model.bin?X-Amz-Signature=secret"

        expanded, missing = expand_paths((url,))
        assert expanded == [url]
        assert missing == []

    def test_expand_paths_url_query_is_not_glob(self):
        """Remote URLs with query strings should stay literal."""
        url = "https://company.jfrog.io/artifactory/repo/model.bin?token=secret"

        expanded, missing = expand_paths((url,))
        assert expanded == [url]
        assert missing == []

    def test_expand_paths_empty_input(self):
        """Empty tuple returns empty results."""
        expanded, missing = expand_paths(())
        assert expanded == []
        assert missing == []


class TestScanGlobFailFast:
    """Tests for scan command behavior with unmatched globs."""

    def test_scan_unmatched_glob_exits_2(self, tmp_path):
        """Scan with only unmatched globs exits with code 2."""
        runner = CliRunner()
        pattern = str(tmp_path / "*.nonexistent_extension")
        result = runner.invoke(cli, ["scan", pattern])
        assert result.exit_code == 2
        assert "No matching paths found" in strip_ansi(result.output + (result.stderr or ""))

    def test_scan_unmatched_glob_warns(self, tmp_path):
        """Scan with a mix of valid file + unmatched glob warns but continues."""
        f = tmp_path / "real.dat"
        f.write_bytes(b"content")
        bad_glob = str(tmp_path / "*.zzzzz")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(f), bad_glob], catch_exceptions=True)
        # Should NOT exit 2 since there's a valid path
        assert result.exit_code != 2
        # Warning should appear in stderr
        combined = strip_ansi(result.output + (result.stderr or ""))
        assert "did not match any files" in combined or "Warning" in combined

    @patch("modelaudit.cli.record_scan_failed")
    @patch("modelaudit.cli.flush_telemetry")
    def test_scan_unmatched_glob_records_telemetry(self, mock_flush, mock_record_failed, tmp_path):
        """Telemetry is recorded and flushed on early exit."""
        runner = CliRunner()
        pattern = str(tmp_path / "*.nonexistent_extension")
        runner.invoke(cli, ["scan", pattern])
        mock_record_failed.assert_called_once()
        # Duration should be a positive float, not hardcoded 0.0
        duration_arg = mock_record_failed.call_args[0][0]
        assert isinstance(duration_arg, float)
        assert duration_arg >= 0.0
        assert mock_record_failed.call_args[0][1] == "No matching paths"
        mock_flush.assert_called_once()

    @patch("modelaudit.cli.record_scan_started")
    @patch("modelaudit.cli.record_command_used")
    @patch("modelaudit.cli.record_scan_failed")
    @patch("modelaudit.cli.flush_telemetry")
    def test_scan_invalid_max_size_records_telemetry(
        self,
        mock_flush: MagicMock,
        mock_record_failed: MagicMock,
        mock_record_command: MagicMock,
        mock_record_started: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Invalid --max-size records failure telemetry without preserving its value."""
        runner = CliRunner()
        target = tmp_path / "model.pkl"
        target.write_bytes(b"content")
        sensitive_max_size = "secret-model-name"

        result = runner.invoke(cli, ["scan", str(target), "--max-size", sensitive_max_size])

        assert result.exit_code == 2
        assert "Error parsing --max-size" in result.output
        mock_record_failed.assert_called_once()
        duration_arg = mock_record_failed.call_args[0][0]
        assert isinstance(duration_arg, float)
        assert duration_arg >= 0.0
        assert "Invalid max-size" in mock_record_failed.call_args[0][1]
        command_options = mock_record_command.call_args.kwargs
        scan_options = mock_record_started.call_args.args[1]
        assert command_options["has_max_file_size"] is True
        assert scan_options["has_max_file_size"] is True
        assert sensitive_max_size not in repr(mock_record_command.call_args)
        assert sensitive_max_size not in repr(mock_record_started.call_args)
        mock_flush.assert_called_once()
