"""Tests for TorchServe .mar scanner."""

from __future__ import annotations

import json
import pickle
import zipfile
from pathlib import Path
from typing import Any

from modelaudit import core
from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.torchserve_mar_scanner import TorchServeMarScanner


def _create_mar_archive(
    tmp_path: Path,
    manifest: dict[str, Any] | str | None,
    entries: dict[str, bytes],
    filename: str = "model.mar",
) -> Path:
    mar_path = tmp_path / filename
    with zipfile.ZipFile(mar_path, "w") as archive:
        if manifest is not None:
            manifest_bytes = (
                manifest.encode("utf-8")
                if isinstance(manifest, str)
                else json.dumps(manifest).encode(
                    "utf-8",
                )
            )
            archive.writestr("MAR-INF/MANIFEST.json", manifest_bytes)

        for name, data in entries.items():
            archive.writestr(name, data)

    return mar_path


def _build_malicious_pickle() -> bytes:
    import os as os_module

    class DangerousPayload:
        def __reduce__(self):
            return (os_module.system, ("echo torchserve-mar-test",))

    return pickle.dumps(DangerousPayload())


def _failed_checks(result: ScanResult, check_name: str) -> list[Any]:
    return [check for check in result.checks if check.name == check_name and check.status == CheckStatus.FAILED]


def test_can_handle_valid_mar_archive(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
        },
    )

    assert TorchServeMarScanner.can_handle(str(mar_path))


def test_can_handle_rejects_non_zip_and_missing_manifest(tmp_path: Path) -> None:
    non_zip_mar = tmp_path / "not_zip.mar"
    non_zip_mar.write_bytes(b"not a zip archive")
    assert not TorchServeMarScanner.can_handle(str(non_zip_mar))

    missing_manifest_mar = _create_mar_archive(tmp_path, manifest=None, entries={"weights.bin": b"weights"})
    assert not TorchServeMarScanner.can_handle(str(missing_manifest_mar))


def test_scan_benign_mar_with_safe_handler(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin", "extraFiles": "labels.json"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "labels.json": b'{"0": "cat"}',
        },
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")
    assert len(handler_failures) == 0


def test_scan_detects_malicious_pickle_payload_in_serialized_file(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "model.pkl"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "model.pkl": _build_malicious_pickle(),
        },
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    serialized_security_checks = _failed_checks(result, "TorchServe Serialized Payload Security")
    assert len(serialized_security_checks) >= 1
    assert any(":model.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_detects_path_traversal_member_names(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
            "../../evil.pkl": _build_malicious_pickle(),
        },
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    traversal_failures = _failed_checks(result, "TorchServe MAR Path Traversal Protection")
    assert len(traversal_failures) >= 1
    assert traversal_failures[0].severity == IssueSeverity.CRITICAL


def test_scan_reports_missing_manifest_when_forced(tmp_path: Path) -> None:
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries={"handler.py": b"def handle(data, context):\n    return data\n"},
        filename="missing_manifest.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    manifest_failures = _failed_checks(result, "TorchServe Manifest Presence")
    assert len(manifest_failures) == 1


def test_scan_handles_corrupt_mar_gracefully(tmp_path: Path) -> None:
    mar_path = tmp_path / "corrupt.mar"
    mar_path.write_bytes(b"PK\x03\x04this-is-not-a-valid-zip")

    result = TorchServeMarScanner().scan(str(mar_path))
    archive_failures = _failed_checks(result, "TorchServe MAR Archive Validation")
    assert len(archive_failures) == 1
    assert result.success is False


def test_scan_detects_nested_zip_payloads(tmp_path: Path) -> None:
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as nested:
        nested.writestr("payload.pkl", _build_malicious_pickle())

    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "nested.zip",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
            "nested.zip": nested_zip.read_bytes(),
        },
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    assert any(".mar:nested.zip" in (issue.location or "") for issue in result.issues)


def test_core_routes_mar_to_dedicated_scanner(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
        },
    )

    result = core.scan_file(str(mar_path))
    assert result.scanner_name == "torchserve_mar"
    assert result.scanner_name != "unknown"


def test_false_positive_reduction_comments_and_strings_only(tmp_path: Path) -> None:
    handler_code = b"""
def handle(data, context):
    # os.system("should not run")
    marker = "subprocess.Popen should not trigger from string"
    return {"marker": marker}
"""
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={"handler.py": handler_code, "weights.bin": b"weights"},
        filename="comments_only.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")
    assert len(handler_failures) == 0


def test_bypass_prevention_comments_do_not_suppress_real_call_detection(tmp_path: Path) -> None:
    handler_code = b"""
def handle(data, context):
    # os.system("decoy")
    # subprocess.Popen("decoy")
    \"\"\"docstring with eval('decoy')\"\"\"
    import subprocess as sp
    return sp.run(["echo", "real-call"])
"""
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={"handler.py": handler_code, "weights.bin": b"weights"},
        filename="bypass_attempt.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")
    assert len(handler_failures) >= 1
    assert handler_failures[0].severity == IssueSeverity.CRITICAL
    assert "subprocess.run" in handler_failures[0].message


def test_manifest_read_is_bounded(tmp_path: Path) -> None:
    oversized_manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "A" * (TorchServeMarScanner.MAX_MANIFEST_BYTES + 10),
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=oversized_manifest,
        entries={"handler.py": b"def handle(data, context):\n    return data\n", "weights.bin": b"weights"},
        filename="oversized_manifest.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    manifest_size_failures = _failed_checks(result, "TorchServe Manifest Size Limit")
    assert len(manifest_size_failures) == 1
