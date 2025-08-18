"""Tests for header vs extension detection logic."""

import pickle

from modelaudit.core import scan_file
from modelaudit.scanners.base import IssueSeverity


def test_header_extension_mismatch_warning(tmp_path):
    """A .bin file containing pickle data should NOT trigger a warning (common for PyTorch/HF models)."""
    file_path = tmp_path / "model.bin"
    with file_path.open("wb") as f:
        pickle.dump({"a": 1}, f)

    result = scan_file(str(file_path))

    assert result.scanner_name == "pickle"
    # Should NOT have header mismatch warnings for .bin files with pickle data
    # This is expected behavior for PyTorch and HuggingFace models
    assert not any(
        issue.severity == IssueSeverity.DEBUG and "header" in issue.message.lower() for issue in result.issues
    )
