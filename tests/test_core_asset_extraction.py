import ntpath
from unittest.mock import patch

from modelaudit.core import _extract_primary_asset_from_location


def test_extract_primary_asset_windows_path_with_archive():
    location = r"C:\\Users\\test\\archive.zip:inner\\file"
    with patch("modelaudit.core.os.path.splitdrive", ntpath.splitdrive):
        assert _extract_primary_asset_from_location(location) == r"C:\\Users\\test\\archive.zip"


def test_extract_primary_asset_windows_path_without_archive():
    location = r"C:\\Users\\test\\file.txt"
    with patch("modelaudit.core.os.path.splitdrive", ntpath.splitdrive):
        assert _extract_primary_asset_from_location(location) == r"C:\\Users\\test\\file.txt"
