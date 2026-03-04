"""
Tests for CVE-2025-10155: Pickle fallback for .bin extension mismatch.

Protocol 0/1 pickles don't start with the standard 0x80 magic bytes,
so files disguised with a .bin extension could bypass detection. This test
suite verifies that:

1. detect_file_format() correctly identifies protocol 0 pickles in .bin files
2. The PickleScanner detects malicious payloads in .bin files
3. BINARY_CODE_PATTERNS includes posix/nt internal module names
"""

from pathlib import Path
from typing import Any

from modelaudit.detectors.suspicious_symbols import BINARY_CODE_PATTERNS
from modelaudit.scanners import PickleScanner
from modelaudit.scanners.base import IssueSeverity
from modelaudit.utils.file.detection import detect_file_format

PROTOCOL1_POSIX_PAYLOAD = b"cposix\nsystem\nq\x00(X\x02\x00\x00\x00idq\x01tq\x02Rq\x03."


class TestCVE202510155FormatDetection:
    """Test that detect_file_format identifies protocol 0/1 pickles in .bin files."""

    def test_protocol0_global_opcode_detected_as_pickle(self, tmp_path: Path) -> None:
        """Protocol 0 pickle starting with GLOBAL opcode 'c' should be detected."""
        bin_path = tmp_path / "model.bin"
        # Protocol 0: cmodule\nname\n... (GLOBAL opcode)
        bin_path.write_bytes(b"cposix\nsystem\n(S'echo pwned'\ntR.")
        assert detect_file_format(str(bin_path)) == "pickle"

    def test_protocol0_mark_opcode_detected_as_pickle(self, tmp_path: Path) -> None:
        """Protocol 0 pickle starting with MARK '(' followed by GLOBAL opcode."""
        bin_path = tmp_path / "model.bin"
        # MARK + ... + GLOBAL opcode
        bin_path.write_bytes(b"(cposix\nsystem\nS'echo pwned'\ntR.")
        assert detect_file_format(str(bin_path)) == "pickle"

    def test_protocol2_still_detected(self, tmp_path: Path) -> None:
        """Protocol 2+ pickles in .bin files should still be detected."""
        bin_path = tmp_path / "model.bin"
        # Protocol 2 magic bytes
        bin_path.write_bytes(b"\x80\x02cposix\nsystem\n.")
        assert detect_file_format(str(bin_path)) == "pickle"

    def test_protocol1_global_opcode_detected_as_pickle(self, tmp_path: Path) -> None:
        """Protocol 1 payloads using GLOBAL + memo opcodes should be detected."""
        bin_path = tmp_path / "model.bin"
        bin_path.write_bytes(PROTOCOL1_POSIX_PAYLOAD)
        assert detect_file_format(str(bin_path)) == "pickle"

    def test_safetensors_bin_not_misdetected(self, tmp_path: Path) -> None:
        """Safetensors .bin files (JSON header) should not be detected as pickle."""
        bin_path = tmp_path / "model.bin"
        bin_path.write_bytes(b'{"__metadata__": {}, "weight": {}}')
        assert detect_file_format(str(bin_path)) == "safetensors"

    def test_zip_bin_not_misdetected(self, tmp_path: Path) -> None:
        """ZIP .bin files should not be detected as pickle."""
        import zipfile

        bin_path = tmp_path / "model.bin"
        with zipfile.ZipFile(bin_path, "w") as zf:
            zf.writestr("data.pkl", b"test")
        assert detect_file_format(str(bin_path)) == "zip"

    def test_regular_bin_not_misdetected(self, tmp_path: Path) -> None:
        """Regular binary .bin files should not be misdetected as pickle."""
        bin_path = tmp_path / "model.bin"
        # Random-looking binary data that doesn't match pickle patterns
        bin_path.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
        assert detect_file_format(str(bin_path)) == "pytorch_binary"

    def test_bracket_start_not_misdetected(self, tmp_path: Path) -> None:
        """A .bin file starting with ']' but lacking pickle opcodes should not be detected as pickle.

        ']' is the EMPTY_LIST opcode in pickle protocol 0/1 and could appear at the
        start of a pickle stream. Without a subsequent GLOBAL opcode ('c') or protocol
        2+ magic byte (0x80), it should not be classified as pickle.
        """
        bin_path = tmp_path / "model.bin"
        bin_path.write_bytes(b"]not a pickle content here")
        assert detect_file_format(str(bin_path)) == "pytorch_binary"

    def test_brace_start_not_misdetected(self, tmp_path: Path) -> None:
        """A .bin file starting with '}' but lacking pickle opcodes should not be detected as pickle.

        '}' is the EMPTY_DICT opcode in pickle protocol 0/1 and could appear at the
        start of a pickle stream. Without a subsequent GLOBAL opcode ('c') or protocol
        2+ magic byte (0x80), it should not be classified as pickle.
        """
        bin_path = tmp_path / "model.bin"
        bin_path.write_bytes(b"}not a pickle or json content")
        assert detect_file_format(str(bin_path)) == "pytorch_binary"


class TestCVE202510155PickleScanning:
    """Test that malicious protocol 0 pickles in .bin files are caught by PickleScanner."""

    @staticmethod
    def _has_critical_symbol_issue(result: Any, symbol: str) -> bool:
        return any(
            issue.severity == IssueSeverity.CRITICAL
            and (
                symbol in issue.message
                or symbol == f"{issue.details.get('module', '')}.{issue.details.get('function', '')}"
                or symbol == issue.details.get("import_reference")
                or symbol == issue.details.get("associated_global")
            )
            for issue in result.issues
        )

    def test_posix_system_in_bin_detected(self, tmp_path: Path) -> None:
        """posix.system payload in a .bin file should be caught."""
        bin_path = tmp_path / "payload.bin"
        # Protocol 0 pickle: GLOBAL posix.system, then REDUCE
        bin_path.write_bytes(b"cposix\nsystem\n(S'echo pwned'\ntR.")

        scanner = PickleScanner()
        result = scanner.scan(str(bin_path))

        assert self._has_critical_symbol_issue(result, "posix.system"), (
            f"Expected CRITICAL issue for posix.system. Issues: {[i.message for i in result.issues]}"
        )

    def test_nt_system_in_bin_detected(self, tmp_path: Path) -> None:
        """nt.system payload in a .bin file should be caught."""
        bin_path = tmp_path / "payload.bin"
        # Protocol 0 pickle: GLOBAL nt.system, then REDUCE
        bin_path.write_bytes(b"cnt\nsystem\n(S'cmd /c whoami'\ntR.")

        scanner = PickleScanner()
        result = scanner.scan(str(bin_path))

        assert self._has_critical_symbol_issue(result, "nt.system"), (
            f"Expected CRITICAL issue for nt.system. Issues: {[i.message for i in result.issues]}"
        )

    def test_protocol2_posix_in_bin_detected(self, tmp_path: Path) -> None:
        """Protocol 2 pickle with posix.system in .bin should also be caught."""
        bin_path = tmp_path / "payload.bin"
        # Protocol 2 header + GLOBAL opcode for posix.system
        bin_path.write_bytes(b"\x80\x02cposix\nsystem\n(S'id'\ntR.")

        scanner = PickleScanner()
        result = scanner.scan(str(bin_path))

        assert self._has_critical_symbol_issue(result, "posix.system"), (
            f"Expected CRITICAL issue for posix.system in protocol 2 payload. "
            f"Issues: {[i.message for i in result.issues]}"
        )

    def test_protocol1_posix_in_bin_detected(self, tmp_path: Path) -> None:
        """Protocol 1 payload with posix.system in .bin should be flagged CRITICAL."""
        bin_path = tmp_path / "payload.bin"
        bin_path.write_bytes(PROTOCOL1_POSIX_PAYLOAD)

        scanner = PickleScanner()
        result = scanner.scan(str(bin_path))

        assert self._has_critical_symbol_issue(result, "posix.system"), (
            f"Expected CRITICAL issue for protocol 1 posix.system. Issues: {[i.message for i in result.issues]}"
        )

    def test_comment_token_does_not_bypass_detection(self, tmp_path: Path) -> None:
        """A single comment token should not suppress protocol 0 pickle detection in .bin files."""
        bin_path = tmp_path / "payload.bin"
        # Insert a comment marker between GLOBAL and argument setup.
        bin_path.write_bytes(b"cposix\nsystem\n#\n(S'echo pwned'\ntR.")

        scanner = PickleScanner()
        result = scanner.scan(str(bin_path))

        assert self._has_critical_symbol_issue(result, "posix.system"), (
            "Expected CRITICAL posix.system detection despite comment-token injection"
        )


class TestCVE202510155BinaryPatterns:
    """Test that BINARY_CODE_PATTERNS includes posix/nt internal module patterns."""

    def test_posix_system_in_patterns(self) -> None:
        """posix\\nsystem should be in BINARY_CODE_PATTERNS."""
        assert b"posix\nsystem" in BINARY_CODE_PATTERNS

    def test_posix_popen_in_patterns(self) -> None:
        """posix\\npopen should be in BINARY_CODE_PATTERNS."""
        assert b"posix\npopen" in BINARY_CODE_PATTERNS

    def test_nt_system_in_patterns(self) -> None:
        """nt\\nsystem should be in BINARY_CODE_PATTERNS."""
        assert b"nt\nsystem" in BINARY_CODE_PATTERNS

    def test_nt_popen_in_patterns(self) -> None:
        """nt\\npopen should be in BINARY_CODE_PATTERNS."""
        assert b"nt\npopen" in BINARY_CODE_PATTERNS
