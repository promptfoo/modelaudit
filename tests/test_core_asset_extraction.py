import ntpath
import pickle
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from modelaudit.core import _extract_primary_asset_from_location, scan_model_directory_or_file


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
