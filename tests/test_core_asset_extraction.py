import ast
import inspect
import ntpath
import pickle
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import numpy as np
import pytest

from modelaudit.core import (
    HEADER_FORMAT_TO_SCANNER_ID,
    _extract_primary_asset_from_location,
    scan_file,
    scan_model_directory_or_file,
)
from modelaudit.scanners import _registry
from modelaudit.utils.file import detection


def test_extract_primary_asset_windows_path_with_archive() -> None:
    location = r"C:\\Users\\test\\archive.zip:inner\\file"
    with patch("modelaudit.core.os.path.splitdrive", ntpath.splitdrive):
        assert _extract_primary_asset_from_location(location) == r"C:\\Users\\test\\archive.zip"


def test_extract_primary_asset_windows_path_without_archive() -> None:
    location = r"C:\\Users\\test\\file.txt"
    with patch("modelaudit.core.os.path.splitdrive", ntpath.splitdrive):
        assert _extract_primary_asset_from_location(location) == r"C:\\Users\\test\\file.txt"


def test_extract_primary_asset_preserves_spaces_in_path() -> None:
    location = "/tmp/group one/model a.pkl"
    assert _extract_primary_asset_from_location(location) == "/tmp/group one/model a.pkl"


def test_check_consolidation_keeps_distinct_duplicate_groups_with_spaces(tmp_path: Path) -> None:
    group_one = tmp_path / "group one"
    group_two = tmp_path / "group two"
    group_one.mkdir()
    group_two.mkdir()

    for path in (group_one / "dup a.pkl", group_one / "dup b.pkl"):
        with path.open("wb") as handle:
            pickle.dump({"group": 1}, handle)

    for path in (group_two / "other a.pkl", group_two / "other b.pkl"):
        with path.open("wb") as handle:
            pickle.dump({"group": 2}, handle)

    result = scan_model_directory_or_file(str(tmp_path))
    path_exists_checks = [check for check in result.checks if check.name == "Path Exists"]

    assert len(path_exists_checks) == 2
    duplicate_groups = {frozenset(check.details["duplicate_files"]) for check in path_exists_checks}
    assert duplicate_groups == {
        frozenset({str(group_one / "dup a.pkl"), str(group_one / "dup b.pkl")}),
        frozenset({str(group_two / "other a.pkl"), str(group_two / "other b.pkl")}),
    }

    for check in path_exists_checks:
        assert check.location in check.details["duplicate_files"]
        assert "\n" not in (check.location or "")


@pytest.mark.skipif(sys.platform == "win32", reason="Windows paths cannot contain newline characters")
def test_check_consolidation_handles_newlines_in_file_paths(tmp_path: Path) -> None:
    group = tmp_path / "group\nnewline"
    group.mkdir()

    for path in (group / "dup a.pkl", group / "dup b.pkl"):
        with path.open("wb") as handle:
            pickle.dump({"group": "newline"}, handle)

    result = scan_model_directory_or_file(str(tmp_path))
    path_exists_checks = [check for check in result.checks if check.name == "Path Exists"]

    assert len(path_exists_checks) == 1
    check = path_exists_checks[0]
    expected_paths = {str(group / "dup a.pkl"), str(group / "dup b.pkl")}
    assert set(check.details["duplicate_files"]) == expected_paths
    assert check.location in expected_paths


def test_npz_member_checks_keep_archive_member_locations(tmp_path: Path) -> None:
    class _ExecPayload:
        def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
            return (exec, ("print('owned')",))

    archive_path = tmp_path / "payload.npz"
    np.savez(archive_path, safe=np.arange(3), payload=np.array([_ExecPayload()], dtype=object))

    result = scan_model_directory_or_file(str(archive_path))
    payload_checks = [
        check
        for check in result.checks
        if check.status.value == "failed"
        and (check.details.get("zip_entry") == "payload.npy" or ":payload.npy" in (check.location or ""))
    ]

    assert any(
        check.location == f"{archive_path}:payload.npy" and check.details.get("zip_entry") == "payload.npy"
        for check in payload_checks
    ), f"Expected archive-member check location, got: {[(c.location, c.details) for c in payload_checks]}"
    assert not any(check.location and not check.location.startswith(f"{archive_path}:") for check in payload_checks), (
        f"Unexpected non-archive check locations: {[c.location for c in payload_checks]}"
    )


def test_check_consolidation_keeps_distinct_npz_member_findings(tmp_path: Path) -> None:
    class ExecPayload:
        def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
            return (exec, ("print('owned')",))

    archive_path = tmp_path / "payload.npz"
    np.savez(archive_path, safe=np.arange(3), payload=np.array([ExecPayload()], dtype=object))

    result = scan_model_directory_or_file(str(archive_path))
    cve_checks = [
        check for check in result.checks if check.name.startswith("CVE-2019-6446") and check.status.value == "failed"
    ]

    assert len(cve_checks) == 1
    assert cve_checks[0].location == f"{archive_path}:payload.npy"
    assert cve_checks[0].details.get("zip_entry") == "payload.npy"


def test_check_consolidation_keeps_nested_npz_member_findings_distinct(tmp_path: Path) -> None:
    class ExecPayload:
        def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
            return (exec, ("print('owned')",))

    inner_npz = tmp_path / "inner.npz"
    np.savez(
        inner_npz,
        payload_a=np.array([ExecPayload()], dtype=object),
        payload_b=np.array([ExecPayload()], dtype=object),
    )

    outer_zip = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer_zip, "w") as zf:
        zf.write(inner_npz, arcname="inner.npz")

    result = scan_model_directory_or_file(str(outer_zip))
    cve_checks = [
        check for check in result.checks if check.name.startswith("CVE-2019-6446") and check.status.value == "failed"
    ]

    assert len(cve_checks) == 2
    assert {check.details.get("zip_entry") for check in cve_checks} == {
        "inner.npz:payload_a.npy",
        "inner.npz:payload_b.npy",
    }


def test_detect_file_format_outputs_have_primary_routing_or_registered_scanner() -> None:
    source = inspect.getsource(detection.detect_file_format)
    function_ast = ast.parse(source)

    returned_formats: set[str] = set()
    for node in ast.walk(function_ast):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            returned_formats.add(node.value.value)

    ignored_formats = {"unknown", "directory"}
    registered_scanner_ids = set(_registry._scanners.keys())

    unmapped_formats = sorted(
        format_name
        for format_name in returned_formats
        if format_name not in ignored_formats
        and format_name not in HEADER_FORMAT_TO_SCANNER_ID
        and format_name not in registered_scanner_ids
    )

    assert not unmapped_formats, f"Formats must have primary routing or registered scanners: {unmapped_formats}"


def test_scan_skops_file_does_not_emit_format_validation_mismatch(tmp_path: Path) -> None:
    skops_file = tmp_path / "model.skops"
    with zipfile.ZipFile(skops_file, "w") as zf:
        zf.writestr("schema.json", '{"version": "1.0"}')

    result = scan_file(str(skops_file))

    assert result.scanner_name == "skops"
    mismatch_messages = [check.message for check in result.checks if check.name == "Format Validation"]
    assert not mismatch_messages, f"Unexpected format mismatch checks: {mismatch_messages}"
