import ntpath
import pickle
from pathlib import Path
from unittest.mock import patch

from modelaudit.core import _extract_primary_asset_from_location, scan_model_directory_or_file


def test_extract_primary_asset_windows_path_with_archive() -> None:
    location = r"C:\\Users\\test\\archive.zip:inner\\file"
    with patch("modelaudit.core.os.path.splitdrive", ntpath.splitdrive):
        assert _extract_primary_asset_from_location(location) == r"C:\\Users\\test\\archive.zip"


def test_extract_primary_asset_windows_path_without_archive() -> None:
    location = r"C:\\Users\\test\\file.txt"
    with patch("modelaudit.core.os.path.splitdrive", ntpath.splitdrive):
        assert _extract_primary_asset_from_location(location) == r"C:\\Users\\test\\file.txt"


def test_extract_primary_asset_preserves_spaces_in_duplicate_locations() -> None:
    location = "/tmp/group one/model a.pkl\n/tmp/group one/model b.pkl"
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
    assert {frozenset((check.location or "").splitlines()) for check in path_exists_checks} == {
        frozenset({str(group_one / "dup a.pkl"), str(group_one / "dup b.pkl")}),
        frozenset({str(group_two / "other a.pkl"), str(group_two / "other b.pkl")}),
    }
