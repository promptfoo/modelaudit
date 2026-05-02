"""Scanner selection policy and routing regressions."""

from __future__ import annotations

import json
import os
import pickle
import zipfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from modelaudit.cache import reset_cache_manager
from modelaudit.cli import cli
from modelaudit.core import scan_file, scan_model_directory_or_file
from modelaudit.scanner_registry_metadata import get_scanner_registry_metadata
from modelaudit.scanner_selection import (
    collect_suppressed_preferred_scanners,
    normalize_scanner_selection_config,
    policy_from_config,
    resolve_scanner_ids,
    resolve_scanner_selection_policy,
    scanner_catalog,
    selected_scanner_extensions,
)
from modelaudit.scanners.archive_dispatch import scan_nested_file
from modelaudit.utils.sources.cloud_storage import filter_scannable_files as filter_cloud_scannable_files
from modelaudit.utils.sources.jfrog import filter_scannable_files as filter_jfrog_scannable_files
from tests.helpers import create_mock_pytorch_zip


def _build_malicious_pickle() -> bytes:
    """Build a deterministic pickle payload with an unsafe reducer target."""

    class DangerousPayload:
        def __reduce__(self) -> tuple[Any, tuple[str]]:
            return (os.system, ("echo scanner-selection-test",))

    return pickle.dumps(DangerousPayload())


def _has_pickle_execution_finding(result: Any) -> bool:
    for issue in result.issues:
        issue_text = f"{issue.message} {issue.details}".lower()
        if issue.rule_code == "S201" or "os.system" in issue_text or "eval" in issue_text:
            return True
    return False


def test_scanner_name_resolution_accepts_ids_classes_and_common_aliases() -> None:
    assert resolve_scanner_ids(["pickle", "PickleScanner", "TensorflowSavedModelScanner", "H5Scanner"]) == (
        "pickle",
        "tf_savedmodel",
        "keras_h5",
    )


def test_hardcoded_user_facing_aliases_resolve() -> None:
    """Pin the issue-facing aliases so class renames can't silently break selection."""
    cases = {
        "H5Scanner": "keras_h5",
        "TensorflowSavedModelScanner": "tf_savedmodel",
        "TensorFlowSavedModelScanner": "tf_savedmodel",
        "TensorflowMetaGraphScanner": "tf_metagraph",
        "TensorFlowMetaGraphScanner": "tf_metagraph",
    }
    for alias, expected_id in cases.items():
        assert resolve_scanner_ids([alias]) == (expected_id,), f"alias {alias!r} failed to resolve"


def test_every_registered_scanner_resolves_by_id_and_class() -> None:
    metadata = get_scanner_registry_metadata()

    for scanner_id, scanner_info in metadata.items():
        assert resolve_scanner_ids([scanner_id]) == (scanner_id,)
        assert resolve_scanner_ids([str(scanner_info["class"])]) == (scanner_id,)


def test_selection_policy_uses_allowlist_minus_exclusions() -> None:
    policy = resolve_scanner_selection_policy(
        scanners=["PickleScanner", "zip"],
        exclude_scanners=["ZipScanner"],
    )

    assert policy.active
    assert policy.enabled_scanner_ids == frozenset({"pickle"})
    assert policy.allows("pickle")
    assert not policy.allows("zip")


def test_normalized_selection_rehydrates_without_alias_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    config = normalize_scanner_selection_config({"scanners": ["PickleScanner"], "exclude_scanners": ["zip"]})

    def fail_resolve(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("normalized selection should not re-resolve aliases")

    monkeypatch.setattr("modelaudit.scanner_selection.resolve_scanner_selection_policy", fail_resolve)

    policy = policy_from_config(config)

    assert policy.active
    assert policy.enabled_scanner_ids == frozenset({"pickle"})
    assert policy.exact_scanner_ids == frozenset({"pickle"})
    assert policy.exclude_scanner_ids == frozenset({"zip"})


def test_scan_file_exact_scanner_allows_pickle_detection(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    result = scan_file(str(path), config={"scanners": ["PickleScanner"], "cache_enabled": False})

    assert result.scanner_name == "pickle"
    assert _has_pickle_execution_finding(result)


def test_scan_file_excluded_scanner_is_explicit_skip(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    result = scan_file(str(path), config={"exclude_scanners": ["pickle"], "cache_enabled": False})

    assert result.scanner_name == "scanner_selection"
    assert result.success
    assert not result.issues
    assert any(check.name == "Scanner Selection" for check in result.checks)
    assert result.metadata["skipped_scanner_id"] == "pickle"


def test_collect_suppressed_preferred_scanners_derives_from_checks(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    result = scan_file(str(path), config={"exclude_scanners": ["pickle"], "cache_enabled": False})

    suppressions = collect_suppressed_preferred_scanners(result.checks)
    assert suppressions
    assert {entry["scanner_id"] for entry in suppressions} == {"pickle"}
    assert all(entry["location"] == str(path) for entry in suppressions)


def test_preferred_scanner_skip_is_warning_and_tracks_suppressed_ids(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    result = scan_file(str(path), config={"exclude_scanners": ["pickle"], "cache_enabled": False})

    from modelaudit.scanner_results import IssueSeverity

    selection_checks = [c for c in result.checks if c.name == "Scanner Selection"]
    assert selection_checks, "expected preferred-scanner skip to emit a Scanner Selection check"
    assert any(c.severity == IssueSeverity.WARNING for c in selection_checks)
    assert any(
        c.details.get("kind") == "preferred" and c.details.get("skipped_scanner_id") == "pickle"
        for c in selection_checks
    )


def test_cli_warns_on_preferred_scanner_suppression(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            str(path),
            "--exclude-scanner",
            "pickle",
            "--format",
            "json",
            "--no-cache",
            "--quiet",
        ],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 0
    assert "scanner selection suppressed the preferred scanner" in result.stderr.lower()
    output = json.loads(result.stdout)
    assert "pickle" in (output.get("scanner_selection") or {}).get("suppressed_preferred_scanner_ids", [])


def test_nested_archive_dispatch_honors_selection_policy(tmp_path: Path) -> None:
    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.pkl", _build_malicious_pickle())

    zip_only = scan_file(str(archive_path), config={"scanners": ["zip"], "cache_enabled": False})
    assert zip_only.scanner_name == "zip"
    assert not _has_pickle_execution_finding(zip_only)
    assert any(check.name == "Scanner Selection" for check in zip_only.checks)

    zip_and_pickle = scan_file(
        str(archive_path),
        config={"scanners": ["zip", "pickle"], "cache_enabled": False},
    )
    assert zip_and_pickle.scanner_name == "zip"
    assert _has_pickle_execution_finding(zip_and_pickle)


def test_selected_zip_scanner_handles_zip_backed_extension_fallback(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    result = scan_file(str(model_path), config={"scanners": ["zip"], "cache_enabled": False})

    assert result.scanner_name == "zip"
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pytorch_zip"
        for check in result.checks
    )


def test_nested_selected_zip_scanner_handles_zip_backed_extension_fallback(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    result = scan_nested_file(str(model_path), config={"scanners": ["zip"], "cache_enabled": False})

    assert result.scanner_name == "zip"
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pytorch_zip"
        for check in result.checks
    )


def test_embedded_pickle_helpers_honor_selection_policy(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=True)

    pytorch_only = scan_file(str(model_path), config={"scanners": ["pytorch_zip"], "cache_enabled": False})
    assert pytorch_only.scanner_name == "pytorch_zip"
    assert not _has_pickle_execution_finding(pytorch_only)
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pickle"
        for check in pytorch_only.checks
    )

    pytorch_and_pickle = scan_file(
        str(model_path),
        config={"scanners": ["pytorch_zip", "pickle"], "cache_enabled": False},
    )
    assert pytorch_and_pickle.scanner_name == "pytorch_zip"
    assert _has_pickle_execution_finding(pytorch_and_pickle)


def test_directory_scan_preserves_selected_text_scanner_skip_extensions(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    result = scan_model_directory_or_file(
        str(tmp_path),
        scanners=["text"],
        cache_enabled=False,
        skip_file_types=True,
    )

    assert result.files_scanned == 1
    assert result.scanner_names == ["text"]
    assert result.scanner_selection
    assert result.scanner_selection["enabled_scanner_ids"] == ["text"]


def test_cache_key_includes_scanner_selection_policy(tmp_path: Path) -> None:
    path = tmp_path / "benign.pkl"
    path.write_bytes(pickle.dumps({"payload": "x" * 2048}))
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    skip_result = scan_file(
        str(path),
        config={
            "scanners": ["manifest"],
            "cache_enabled": True,
            "cache_dir": str(cache_dir),
            "min_cache_file_size": 0,
        },
    )

    pickle_result = scan_file(
        str(path),
        config={
            "scanners": ["pickle"],
            "cache_enabled": True,
            "cache_dir": str(cache_dir),
            "min_cache_file_size": 0,
        },
    )
    reset_cache_manager()

    assert skip_result.scanner_name == "scanner_selection"
    assert pickle_result.scanner_name == "pickle"


def test_cli_accepts_scanner_selection_options(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            str(path),
            "--scanners",
            "PickleScanner",
            "--format",
            "json",
            "--no-cache",
            "--quiet",
        ],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 1
    output = json.loads(result.output)
    assert output["scanner_names"] == ["pickle"]
    assert output["scanner_selection"]["enabled_scanner_ids"] == ["pickle"]


def test_cli_lists_scanners_without_scan_path() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--list-scanners"], env={"PROMPTFOO_DISABLE_TELEMETRY": "1"})

    assert result.exit_code == 0
    assert "pickle (PickleScanner)" in result.output
    assert "tf_savedmodel" in result.output


def test_cli_lists_scanners_as_json() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--list-scanners", "--format", "json"],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["scanners"] == scanner_catalog()
    assert any(scanner["id"] == "pickle" and scanner["class"] == "PickleScanner" for scanner in output["scanners"])


def test_cli_rejects_unknown_scanner(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(path), "--scanners", "NopeScanner"],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 2
    assert "Unknown scanner name" in result.output


def test_cli_unknown_scanner_suggests_closest_match(tmp_path: Path) -> None:
    path = tmp_path / "payload.pkl"
    path.write_bytes(_build_malicious_pickle())

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(path), "--scanners", "picle"],
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1"},
    )

    assert result.exit_code == 2
    assert "did you mean" in result.output.lower()
    assert "pickle" in result.output


def test_remote_prefilters_use_selected_scanner_extensions() -> None:
    policy = resolve_scanner_selection_policy(scanners=["safetensors"])
    extensions = selected_scanner_extensions(policy)
    files = [
        {"path": "model.pkl"},
        {"path": "weights.safetensors"},
        {"path": "checkpoint.pt"},
    ]

    assert filter_cloud_scannable_files(files, scannable_extensions=extensions) == [{"path": "weights.safetensors"}]
    assert filter_jfrog_scannable_files(files, scannable_extensions=extensions) == [{"path": "weights.safetensors"}]


def test_remote_prefilters_fail_open_for_header_routed_scanners() -> None:
    policy = resolve_scanner_selection_policy(scanners=["zip"])

    assert selected_scanner_extensions(policy, conservative=True) is None

    files = [
        {"path": "s3://bucket/model.pt"},
        {"path": "s3://bucket/readme.md"},
    ]

    assert {"path": "s3://bucket/model.pt"} in filter_cloud_scannable_files(files, scannable_extensions=None)
    assert {"path": "s3://bucket/model.pt"} in filter_jfrog_scannable_files(files, scannable_extensions=None)


def test_remote_prefilters_preserve_selected_extensionless_scanners() -> None:
    policy = resolve_scanner_selection_policy(scanners=["llamafile"])
    extensions = selected_scanner_extensions(policy, conservative=True)
    files = [
        {"path": "s3://bucket/model"},
        {"path": "s3://bucket/model.exe"},
        {"path": "s3://bucket/notes.txt"},
    ]

    assert extensions is not None
    assert "" in extensions
    assert filter_cloud_scannable_files(files, scannable_extensions=extensions) == [
        {"path": "s3://bucket/model"},
        {"path": "s3://bucket/model.exe"},
    ]
    assert filter_jfrog_scannable_files(files, scannable_extensions=extensions) == [
        {"path": "s3://bucket/model"},
        {"path": "s3://bucket/model.exe"},
    ]
