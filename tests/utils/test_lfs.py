"""Tests for Git LFS pointer detection utilities."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from modelaudit.utils.lfs import (
    LFS_MAX_POINTER_SIZE,
    LFS_SIGNATURE,
    LFSPointerInfo,
    check_lfs_pointer,
    get_lfs_issue_details,
    get_lfs_remediation_steps,
    is_lfs_pointer,
    parse_lfs_pointer,
)

# Sample LFS pointer content (standard format)
VALID_LFS_POINTER = b"""version https://git-lfs.github.com/spec/v1
oid sha256:4d7c5a28a1b2c3d4e5f67890123456789abcdef0123456789abcdef01234567
size 7516192768
"""

# LFS pointer with extra whitespace (should still parse)
LFS_POINTER_WITH_WHITESPACE = b"""version https://git-lfs.github.com/spec/v1
oid sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567
size 1024

"""

# Malformed LFS pointer (missing size)
MALFORMED_LFS_POINTER_NO_SIZE = b"""version https://git-lfs.github.com/spec/v1
oid sha256:4d7c5a28a1b2c3d4e5f67890123456789abcdef0123456789abcdef01234567
"""

# Malformed LFS pointer (missing oid)
MALFORMED_LFS_POINTER_NO_OID = b"""version https://git-lfs.github.com/spec/v1
size 1024
"""

# Binary pickle header (protocol 4)
PICKLE_HEADER = b"\x80\x04\x95" + b"\x00" * 100

# SafeTensors header (8-byte length + JSON)
SAFETENSORS_HEADER = struct.pack("<Q", 50) + b'{"__metadata__": {}, "weight": {}}' + b"\x00" * 20


class TestIsLfsPointer:
    """Tests for the is_lfs_pointer function."""

    def test_valid_lfs_pointer(self, tmp_path: Path) -> None:
        """Detect a valid LFS pointer file."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(VALID_LFS_POINTER)

        assert is_lfs_pointer(file_path) is True

    def test_lfs_pointer_with_whitespace(self, tmp_path: Path) -> None:
        """Detect LFS pointer with extra whitespace."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(LFS_POINTER_WITH_WHITESPACE)

        assert is_lfs_pointer(file_path) is True

    def test_binary_pickle_not_lfs(self, tmp_path: Path) -> None:
        """Binary pickle files are not LFS pointers."""
        file_path = tmp_path / "model.pkl"
        file_path.write_bytes(PICKLE_HEADER)

        assert is_lfs_pointer(file_path) is False

    def test_safetensors_not_lfs(self, tmp_path: Path) -> None:
        """SafeTensors files are not LFS pointers."""
        file_path = tmp_path / "model.safetensors"
        file_path.write_bytes(SAFETENSORS_HEADER)

        assert is_lfs_pointer(file_path) is False

    def test_large_file_not_lfs(self, tmp_path: Path) -> None:
        """Files larger than LFS_MAX_POINTER_SIZE cannot be LFS pointers."""
        file_path = tmp_path / "large_model.bin"
        # Create a file larger than the max pointer size
        file_path.write_bytes(b"x" * (LFS_MAX_POINTER_SIZE + 100))

        assert is_lfs_pointer(file_path) is False

    def test_file_exactly_at_limit(self, tmp_path: Path) -> None:
        """File exactly at LFS_MAX_POINTER_SIZE should be checked."""
        # Create valid LFS pointer padded to exactly the limit
        content = VALID_LFS_POINTER + b" " * (LFS_MAX_POINTER_SIZE - len(VALID_LFS_POINTER))
        file_path = tmp_path / "edge_case.bin"
        file_path.write_bytes(content)

        assert is_lfs_pointer(file_path) is True

    def test_empty_file_not_lfs(self, tmp_path: Path) -> None:
        """Empty files are not LFS pointers."""
        file_path = tmp_path / "empty.bin"
        file_path.write_bytes(b"")

        assert is_lfs_pointer(file_path) is False

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        """Non-existent files return False (no exception)."""
        file_path = tmp_path / "does_not_exist.bin"

        assert is_lfs_pointer(file_path) is False

    def test_directory_not_lfs(self, tmp_path: Path) -> None:
        """Directories are not LFS pointers."""
        assert is_lfs_pointer(tmp_path) is False

    def test_partial_signature_not_lfs(self, tmp_path: Path) -> None:
        """File with partial LFS signature is not an LFS pointer."""
        file_path = tmp_path / "partial.bin"
        # Only part of the signature
        file_path.write_bytes(b"version https://git-lfs")

        assert is_lfs_pointer(file_path) is False

    def test_signature_constant_value(self) -> None:
        """Verify the LFS signature constant is correct."""
        assert LFS_SIGNATURE == b"version https://git-lfs.github.com/spec/v1"


class TestParseLfsPointer:
    """Tests for the parse_lfs_pointer function."""

    def test_parse_valid_pointer(self, tmp_path: Path) -> None:
        """Parse a valid LFS pointer and extract metadata."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(VALID_LFS_POINTER)

        info = parse_lfs_pointer(file_path)

        assert info is not None
        assert info.version == "https://git-lfs.github.com/spec/v1"
        assert info.oid == "sha256:4d7c5a28a1b2c3d4e5f67890123456789abcdef0123456789abcdef01234567"
        assert info.size == 7516192768

    def test_parse_extracts_hash_algorithm(self, tmp_path: Path) -> None:
        """Verify hash algorithm extraction from oid."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(VALID_LFS_POINTER)

        info = parse_lfs_pointer(file_path)

        assert info is not None
        assert info.hash_algorithm == "sha256"
        assert info.content_hash == "4d7c5a28a1b2c3d4e5f67890123456789abcdef0123456789abcdef01234567"

    def test_parse_pointer_with_whitespace(self, tmp_path: Path) -> None:
        """Parse pointer with extra whitespace."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(LFS_POINTER_WITH_WHITESPACE)

        info = parse_lfs_pointer(file_path)

        assert info is not None
        assert info.size == 1024

    def test_parse_malformed_no_size_returns_none(self, tmp_path: Path) -> None:
        """Malformed pointer without size field returns None."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(MALFORMED_LFS_POINTER_NO_SIZE)

        info = parse_lfs_pointer(file_path)

        assert info is None

    def test_parse_malformed_no_oid_returns_none(self, tmp_path: Path) -> None:
        """Malformed pointer without oid field returns None."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(MALFORMED_LFS_POINTER_NO_OID)

        info = parse_lfs_pointer(file_path)

        assert info is None

    def test_parse_binary_file_returns_none(self, tmp_path: Path) -> None:
        """Binary files return None (not valid pointers)."""
        file_path = tmp_path / "model.pkl"
        file_path.write_bytes(PICKLE_HEADER)

        info = parse_lfs_pointer(file_path)

        assert info is None

    def test_parse_large_file_returns_none(self, tmp_path: Path) -> None:
        """Files too large to be pointers return None."""
        file_path = tmp_path / "large.bin"
        file_path.write_bytes(b"x" * (LFS_MAX_POINTER_SIZE + 100))

        info = parse_lfs_pointer(file_path)

        assert info is None

    def test_parse_nonexistent_file_returns_none(self, tmp_path: Path) -> None:
        """Non-existent files return None (no exception)."""
        file_path = tmp_path / "does_not_exist.bin"

        info = parse_lfs_pointer(file_path)

        assert info is None


class TestLFSPointerInfo:
    """Tests for the LFSPointerInfo dataclass."""

    def test_format_expected_size_bytes(self) -> None:
        """Format small sizes in bytes."""
        info = LFSPointerInfo(version="v1", oid="sha256:abc", size=500)
        assert info.format_expected_size() == "500 B"

    def test_format_expected_size_kilobytes(self) -> None:
        """Format KB-range sizes."""
        info = LFSPointerInfo(version="v1", oid="sha256:abc", size=2048)
        assert "KB" in info.format_expected_size()

    def test_format_expected_size_megabytes(self) -> None:
        """Format MB-range sizes."""
        info = LFSPointerInfo(version="v1", oid="sha256:abc", size=5 * 1024 * 1024)
        assert "MB" in info.format_expected_size()

    def test_format_expected_size_gigabytes(self) -> None:
        """Format GB-range sizes (typical for models)."""
        info = LFSPointerInfo(version="v1", oid="sha256:abc", size=7516192768)
        formatted = info.format_expected_size()
        assert "GB" in formatted
        assert "7.0" in formatted

    def test_hash_algorithm_sha256(self) -> None:
        """Extract sha256 algorithm."""
        info = LFSPointerInfo(version="v1", oid="sha256:abcdef", size=100)
        assert info.hash_algorithm == "sha256"

    def test_hash_algorithm_unknown_format(self) -> None:
        """Handle oid without colon separator."""
        info = LFSPointerInfo(version="v1", oid="abcdef123456", size=100)
        assert info.hash_algorithm == "unknown"
        assert info.content_hash == "abcdef123456"

    def test_dataclass_is_frozen(self) -> None:
        """LFSPointerInfo should be immutable."""
        info = LFSPointerInfo(version="v1", oid="sha256:abc", size=100)
        with pytest.raises(AttributeError):
            info.size = 200  # type: ignore[misc]


class TestCheckLfsPointer:
    """Tests for the check_lfs_pointer convenience function."""

    def test_returns_true_and_info_for_valid_pointer(self, tmp_path: Path) -> None:
        """Valid pointer returns (True, info)."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(VALID_LFS_POINTER)

        is_pointer, info = check_lfs_pointer(file_path)

        assert is_pointer is True
        assert info is not None
        assert info.size == 7516192768

    def test_returns_false_and_none_for_binary_file(self, tmp_path: Path) -> None:
        """Binary file returns (False, None)."""
        file_path = tmp_path / "model.pkl"
        file_path.write_bytes(PICKLE_HEADER)

        is_pointer, info = check_lfs_pointer(file_path)

        assert is_pointer is False
        assert info is None

    def test_returns_true_with_none_for_malformed_pointer(self, tmp_path: Path) -> None:
        """Malformed pointer (has signature but bad content) returns (True, None)."""
        file_path = tmp_path / "model.bin"
        # Has LFS signature but invalid content after
        content = LFS_SIGNATURE + b"\ninvalid content here\n"
        file_path.write_bytes(content)

        is_pointer, info = check_lfs_pointer(file_path)

        assert is_pointer is True
        assert info is None  # Parsing failed but it's still recognized as an LFS file


class TestGetLfsIssueDetails:
    """Tests for the get_lfs_issue_details function."""

    def test_details_with_valid_info(self, tmp_path: Path) -> None:
        """Generate full details when pointer info is available."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(VALID_LFS_POINTER)

        info = parse_lfs_pointer(file_path)
        details = get_lfs_issue_details(file_path, info)

        assert details["file_path"] == str(file_path)
        assert details["actual_size_bytes"] == len(VALID_LFS_POINTER)
        assert details["issue_type"] == "lfs_pointer"
        assert details["lfs_version"] == "https://git-lfs.github.com/spec/v1"
        assert details["expected_size_bytes"] == 7516192768
        assert "GB" in details["expected_size_human"]
        assert details["hash_algorithm"] == "sha256"

    def test_details_without_info(self, tmp_path: Path) -> None:
        """Generate partial details when pointer info is None."""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(b"version https://git-lfs.github.com/spec/v1\nbad\n")

        details = get_lfs_issue_details(file_path, None)

        assert details["file_path"] == str(file_path)
        assert details["issue_type"] == "lfs_pointer"
        assert "lfs_version" not in details
        assert "expected_size_bytes" not in details


class TestGetLfsRemediationSteps:
    """Tests for the get_lfs_remediation_steps function."""

    def test_default_remediation_steps(self) -> None:
        """Get default remediation steps."""
        steps = get_lfs_remediation_steps()

        assert len(steps) >= 3
        assert any("git lfs pull" in step for step in steps)
        assert any("huggingface-cli" in step for step in steps)

    def test_remediation_with_repo_hint(self) -> None:
        """Include repo-specific download command."""
        steps = get_lfs_remediation_steps(repo_hint="meta-llama/Llama-2-7b")

        assert any("meta-llama/Llama-2-7b" in step for step in steps)


class TestLfsIntegrationWithScan:
    """Integration tests for LFS detection in the scanning flow."""

    def test_scan_detects_lfs_pointer(self, tmp_path: Path) -> None:
        """Full scan correctly identifies LFS pointer as critical issue."""
        from modelaudit.core import scan_file

        file_path = tmp_path / "model.bin"
        file_path.write_bytes(VALID_LFS_POINTER)

        result = scan_file(str(file_path))

        # Should have critical issue
        assert len(result.issues) > 0
        critical_issues = [i for i in result.issues if i.severity.value == "critical"]
        assert len(critical_issues) >= 1

        # Check issue content
        lfs_issue = critical_issues[0]
        assert "lfs" in lfs_issue.message.lower() or "pointer" in lfs_issue.message.lower()

    def test_scan_lfs_pointer_provides_remediation(self, tmp_path: Path) -> None:
        """Scan output includes remediation steps."""
        from modelaudit.core import scan_file

        file_path = tmp_path / "model.bin"
        file_path.write_bytes(VALID_LFS_POINTER)

        result = scan_file(str(file_path))

        # Check that remediation is in the details
        assert len(result.issues) > 0
        issue = result.issues[0]
        assert "details" in dir(issue) or hasattr(issue, "details")
        if issue.details:
            assert "remediation" in issue.details
            remediation = issue.details["remediation"]
            assert any("git lfs" in step.lower() for step in remediation)

    def test_scan_real_binary_not_flagged_as_lfs(self, tmp_path: Path) -> None:
        """Real binary files are not incorrectly flagged as LFS pointers."""
        from modelaudit.core import scan_file

        file_path = tmp_path / "model.pkl"
        file_path.write_bytes(PICKLE_HEADER)

        result = scan_file(str(file_path))

        # Should not have LFS-related critical issues
        lfs_issues = [
            i
            for i in result.issues
            if i.severity.value == "critical" and ("lfs" in i.message.lower() or "pointer" in i.message.lower())
        ]
        assert len(lfs_issues) == 0

    def test_scan_lfs_pointer_scanner_name(self, tmp_path: Path) -> None:
        """LFS pointer detection uses correct scanner name."""
        from modelaudit.core import scan_file

        file_path = tmp_path / "model.bin"
        file_path.write_bytes(VALID_LFS_POINTER)

        result = scan_file(str(file_path))

        assert result.scanner_name == "lfs_check"

    def test_scan_lfs_returns_early(self, tmp_path: Path) -> None:
        """LFS pointer detection returns early without running other scanners."""
        from modelaudit.core import scan_file

        file_path = tmp_path / "model.bin"
        file_path.write_bytes(VALID_LFS_POINTER)

        result = scan_file(str(file_path))

        # Should have finished with success=False
        assert result.success is False
        # Scanner name should be lfs_check, not any format-specific scanner
        assert result.scanner_name == "lfs_check"


class TestEdgeCases:
    """Edge case tests for robustness."""

    def test_lfs_pointer_with_crlf_line_endings(self, tmp_path: Path) -> None:
        """Handle Windows-style line endings."""
        content = b"version https://git-lfs.github.com/spec/v1\r\noid sha256:abc123\r\nsize 1024\r\n"
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(content)

        assert is_lfs_pointer(file_path) is True
        info = parse_lfs_pointer(file_path)
        assert info is not None
        assert info.size == 1024

    def test_lfs_pointer_with_extra_fields(self, tmp_path: Path) -> None:
        """Handle LFS pointers with additional (future) fields."""
        content = b"""version https://git-lfs.github.com/spec/v1
oid sha256:abc123
size 1024
ext custom_extension
"""
        file_path = tmp_path / "model.bin"
        file_path.write_bytes(content)

        assert is_lfs_pointer(file_path) is True
        info = parse_lfs_pointer(file_path)
        assert info is not None
        assert info.size == 1024

    def test_file_starting_with_version_but_not_lfs(self, tmp_path: Path) -> None:
        """File starting with 'version' but not LFS signature."""
        content = b"version 1.0.0\nsome other content"
        file_path = tmp_path / "config.txt"
        file_path.write_bytes(content)

        assert is_lfs_pointer(file_path) is False

    def test_symlink_to_lfs_pointer(self, tmp_path: Path) -> None:
        """Symlink to LFS pointer should be detected."""
        real_file = tmp_path / "real.bin"
        real_file.write_bytes(VALID_LFS_POINTER)

        symlink = tmp_path / "symlink.bin"
        symlink.symlink_to(real_file)

        assert is_lfs_pointer(symlink) is True
        info = parse_lfs_pointer(symlink)
        assert info is not None
