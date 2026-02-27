"""
Tests for CVE-2025-10155: Pickle fallback for .bin extension mismatch.

Protocol 0/1 pickles don't start with the standard 0x80 magic bytes,
so files disguised with a .bin extension could bypass detection. This test
suite verifies that:

1. detect_file_format() correctly identifies protocol 0 pickles in .bin files
2. The PickleScanner detects malicious payloads in .bin files
3. BINARY_CODE_PATTERNS includes posix/nt internal module names
"""

from modelaudit.detectors.suspicious_symbols import BINARY_CODE_PATTERNS
from modelaudit.scanners import PickleScanner
from modelaudit.scanners.base import IssueSeverity
from modelaudit.utils.file.detection import detect_file_format


class TestCVE202510155FormatDetection:
    """Test that detect_file_format identifies protocol 0/1 pickles in .bin files."""

    def test_protocol0_global_opcode_detected_as_pickle(self, tmp_path):
        """Protocol 0 pickle starting with GLOBAL opcode 'c' should be detected."""
        bin_path = tmp_path / "model.bin"
        # Protocol 0: cmodule\nname\n... (GLOBAL opcode)
        bin_path.write_bytes(b"cposix\nsystem\n(S'echo pwned'\ntR.")
        assert detect_file_format(str(bin_path)) == "pickle"

    def test_protocol0_mark_opcode_detected_as_pickle(self, tmp_path):
        """Protocol 0 pickle starting with MARK '(' followed by GLOBAL opcode."""
        bin_path = tmp_path / "model.bin"
        # MARK + ... + GLOBAL opcode
        bin_path.write_bytes(b"(cposix\nsystem\nS'echo pwned'\ntR.")
        assert detect_file_format(str(bin_path)) == "pickle"

    def test_protocol2_still_detected(self, tmp_path):
        """Protocol 2+ pickles in .bin files should still be detected."""
        bin_path = tmp_path / "model.bin"
        # Protocol 2 magic bytes
        bin_path.write_bytes(b"\x80\x02cposix\nsystem\n.")
        assert detect_file_format(str(bin_path)) == "pickle"

    def test_safetensors_bin_not_misdetected(self, tmp_path):
        """Safetensors .bin files (JSON header) should not be detected as pickle."""
        bin_path = tmp_path / "model.bin"
        bin_path.write_bytes(b'{"__metadata__": {}, "weight": {}}')
        assert detect_file_format(str(bin_path)) == "safetensors"

    def test_zip_bin_not_misdetected(self, tmp_path):
        """ZIP .bin files should not be detected as pickle."""
        import zipfile

        bin_path = tmp_path / "model.bin"
        with zipfile.ZipFile(bin_path, "w") as zf:
            zf.writestr("data.pkl", b"test")
        assert detect_file_format(str(bin_path)) == "zip"

    def test_regular_bin_not_misdetected(self, tmp_path):
        """Regular binary .bin files should not be misdetected as pickle."""
        bin_path = tmp_path / "model.bin"
        # Random-looking binary data that doesn't match pickle patterns
        bin_path.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
        assert detect_file_format(str(bin_path)) == "pytorch_binary"

    def test_bracket_start_not_misdetected(self, tmp_path):
        """A .bin file starting with ']' but lacking pickle opcodes should not be detected as pickle.

        ']' is the EMPTY_LIST opcode in pickle protocol 0/1 and could appear at the
        start of a pickle stream. Without a subsequent GLOBAL opcode ('c') or protocol
        2+ magic byte (0x80), it should not be classified as pickle.
        """
        bin_path = tmp_path / "model.bin"
        bin_path.write_bytes(b"]not a pickle content here")
        result = detect_file_format(str(bin_path))
        assert result != "pickle", f"Expected non-pickle format, got {result!r}"

    def test_brace_start_not_misdetected(self, tmp_path):
        """A .bin file starting with '}' but lacking pickle opcodes should not be detected as pickle.

        '}' is the EMPTY_DICT opcode in pickle protocol 0/1 and could appear at the
        start of a pickle stream. Without a subsequent GLOBAL opcode ('c') or protocol
        2+ magic byte (0x80), it should not be classified as pickle.
        """
        bin_path = tmp_path / "model.bin"
        bin_path.write_bytes(b"}not a pickle or json content")
        result = detect_file_format(str(bin_path))
        assert result != "pickle", f"Expected non-pickle format, got {result!r}"


class TestCVE202510155PickleScanning:
    """Test that malicious protocol 0 pickles in .bin files are caught by PickleScanner."""

    def test_posix_system_in_bin_detected(self, tmp_path):
        """posix.system payload in a .bin file should be caught."""
        bin_path = tmp_path / "payload.bin"
        # Protocol 0 pickle: GLOBAL posix.system, then REDUCE
        bin_path.write_bytes(b"cposix\nsystem\n(S'echo pwned'\ntR.")

        scanner = PickleScanner()
        result = scanner.scan(str(bin_path))

        assert len(result.issues) > 0, "Should detect posix.system in .bin pickle"
        critical = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical) > 0, "posix.system should be CRITICAL"

    def test_nt_system_in_bin_detected(self, tmp_path):
        """nt.system payload in a .bin file should be caught."""
        bin_path = tmp_path / "payload.bin"
        # Protocol 0 pickle: GLOBAL nt.system, then REDUCE
        bin_path.write_bytes(b"cnt\nsystem\n(S'cmd /c whoami'\ntR.")

        scanner = PickleScanner()
        result = scanner.scan(str(bin_path))

        assert len(result.issues) > 0, "Should detect nt.system in .bin pickle"
        critical = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical) > 0, "nt.system should be CRITICAL"

    def test_protocol2_posix_in_bin_detected(self, tmp_path):
        """Protocol 2 pickle with posix.system in .bin should also be caught."""
        bin_path = tmp_path / "payload.bin"
        # Protocol 2 header + GLOBAL opcode for posix.system
        bin_path.write_bytes(b"\x80\x02cposix\nsystem\n(S'id'\ntR.")

        scanner = PickleScanner()
        result = scanner.scan(str(bin_path))

        assert len(result.issues) > 0, "Should detect posix.system in protocol 2 .bin pickle"


class TestCVE202510155BinaryPatterns:
    """Test that BINARY_CODE_PATTERNS includes posix/nt internal module patterns."""

    def test_posix_system_in_patterns(self):
        """posix\\nsystem should be in BINARY_CODE_PATTERNS."""
        assert b"posix\nsystem" in BINARY_CODE_PATTERNS

    def test_posix_popen_in_patterns(self):
        """posix\\npopen should be in BINARY_CODE_PATTERNS."""
        assert b"posix\npopen" in BINARY_CODE_PATTERNS

    def test_nt_system_in_patterns(self):
        """nt\\nsystem should be in BINARY_CODE_PATTERNS."""
        assert b"nt\nsystem" in BINARY_CODE_PATTERNS

    def test_nt_popen_in_patterns(self):
        """nt\\npopen should be in BINARY_CODE_PATTERNS."""
        assert b"nt\npopen" in BINARY_CODE_PATTERNS
