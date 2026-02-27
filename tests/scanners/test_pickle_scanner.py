import os
import pickle
import struct
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

# Skip if dill is not available before importing it
pytest.importorskip("dill")

import dill

from modelaudit.detectors.suspicious_symbols import (
    BINARY_CODE_PATTERNS,
    EXECUTABLE_SIGNATURES,
)
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner
from tests.assets.generators.generate_advanced_pickle_tests import (
    generate_memo_based_attack,
    generate_multiple_pickle_attack,
    generate_stack_global_attack,
)
from tests.assets.generators.generate_evil_pickle import EvilClass

# Add the parent directory to sys.path to allow importing modelaudit
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# Import only what we need for the pickle scanner test


class TestPickleScanner(unittest.TestCase):
    def setUp(self):
        # Path to assets/samples/pickles/evil.pickle sample
        self.evil_pickle_path = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"

        # Create the evil pickle if it doesn't exist
        if not self.evil_pickle_path.exists():
            evil_obj = EvilClass()
            with self.evil_pickle_path.open("wb") as f:
                pickle.dump(evil_obj, f)

    def test_scan_evil_pickle(self):
        """Test that the scanner can detect the malicious pickle
        created by assets/generators/generate_evil_pickle.py"""
        scanner = PickleScanner()
        result = scanner.scan(str(self.evil_pickle_path))

        # Check that the scan completed successfully
        assert result.success

        # Check that issues were found
        assert result.has_errors

        # Print the found issues for debugging
        print(f"Found {len(result.issues)} issues:")
        for issue in result.issues:
            print(f"  - {issue.severity.name}: {issue.message}")

        # Check that specific issues were detected
        has_reduce_detection = False
        has_os_system_detection = False

        for issue in result.issues:
            if "REDUCE" in issue.message:
                has_reduce_detection = True
            if "posix.system" in issue.message or "os.system" in issue.message:
                has_os_system_detection = True

        assert has_reduce_detection, "Failed to detect REDUCE opcode"
        assert has_os_system_detection, "Failed to detect os.system/posix.system reference"

    def test_scan_dill_pickle(self):
        """Scanner should flag suspicious dill references"""
        dill_pickle_path = Path(__file__).parent.parent / "assets/samples/pickles/dill_func.pkl"
        if not dill_pickle_path.exists():

            def func(x):
                return x

            with dill_pickle_path.open("wb") as f:
                dill.dump(func, f)

        scanner = PickleScanner()
        result = scanner.scan(str(dill_pickle_path))

        assert result.success
        assert result.has_errors or result.has_warnings
        assert any("dill" in issue.message for issue in result.issues)

    def test_scan_nonexistent_file(self):
        """Scanner returns failure and error issue for missing file"""
        scanner = PickleScanner()
        result = scanner.scan("nonexistent_file.pkl")

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    def test_scan_bin_file_with_suspicious_binary_content(self):
        """Test scanning .bin file with suspicious code patterns in binary data"""
        scanner = PickleScanner()

        # Create a temporary .bin file with pickle header + suspicious binary content
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"weights": [1.0, 2.0, 3.0]}
                pickle.dump(simple_data, f)

                # Add suspicious binary content
                pattern_import = BINARY_CODE_PATTERNS[0]
                pattern_eval = next(p for p in BINARY_CODE_PATTERNS if p.startswith(b"eval"))
                suspicious_content = b"some_data" + pattern_import + b"more_data" + pattern_eval + b"end_data"
                f.write(suspicious_content)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should find suspicious patterns
                suspicious_issues = [
                    issue for issue in result.issues if "suspicious code pattern" in issue.message.lower()
                ]
                assert len(suspicious_issues) >= 2  # Should find both "import os" and "eval("

                # Check metadata
                assert "pickle_bytes" in result.metadata
                assert "binary_bytes" in result.metadata
                assert result.metadata["binary_bytes"] > 0

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_with_executable_signatures(self):
        """Test scanning .bin file with executable signatures in binary data"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"model": "test"}
                pickle.dump(simple_data, f)

                # Add binary content with executable signatures
                f.write(b"some_padding")
                sigs = list(EXECUTABLE_SIGNATURES.keys())
                f.write(sigs[0])  # PE signature
                f.write(b"padding" * 10)
                f.write(b"This program cannot be run in DOS mode")  # DOS stub
                f.write(b"more_padding")
                f.write(sigs[1])  # Another signature
                f.write(b"end_padding")
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should find executable signatures
                executable_issues = [
                    issue for issue in result.issues if "executable signature" in issue.message.lower()
                ]
                assert len(executable_issues) >= 2  # Should find both PE and ELF signatures

                # Check that errors are reported for executable signatures
                error_issues = [issue for issue in executable_issues if issue.severity == IssueSeverity.CRITICAL]
                assert len(error_issues) >= 2

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_clean_binary_content(self):
        """Test scanning .bin file with clean binary content (no issues)"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"weights": [1.0, 2.0, 3.0]}
                pickle.dump(simple_data, f)

                # Add clean binary content (simulating tensor data)
                clean_content = b"\x00" * 1000 + b"\x01" * 500 + b"\xff" * 200
                f.write(clean_content)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should not find any suspicious patterns in binary content
                binary_issues = [issue for issue in result.issues if "binary data" in issue.message.lower()]
                assert len(binary_issues) == 0
            finally:
                os.unlink(f.name)


class TestPickleScannerAdvanced(unittest.TestCase):
    def setUp(self) -> None:
        # Ensure advanced pickle assets exist
        generate_stack_global_attack()
        generate_memo_based_attack()
        generate_multiple_pickle_attack()

    def test_stack_global_detection(self) -> None:
        scanner = PickleScanner()
        result = scanner.scan(str(Path(__file__).parent.parent / "assets" / "pickles" / "stack_global_attack.pkl"))

        assert len(result.issues) > 0, "Expected issues to be detected for STACK_GLOBAL attack"
        os_issues = [
            i
            for i in result.issues
            if "os" in i.message.lower() or "posix" in i.message.lower() or "nt" in i.message.lower()
        ]
        assert len(os_issues) > 0, f"Expected OS-related issues, but found: {[i.message for i in result.issues]}"

    def test_memo_object_tracking(self) -> None:
        scanner = PickleScanner()
        result = scanner.scan(str(Path(__file__).parent.parent / "assets" / "pickles" / "memo_attack.pkl"))

        assert len(result.issues) > 0, "Expected issues to be detected for memo-based attack"
        subprocess_issues = [i for i in result.issues if "subprocess" in i.message.lower()]
        assert len(subprocess_issues) > 0, (
            f"Expected subprocess issues, but found: {[i.message for i in result.issues]}"
        )

    def test_multiple_pickle_streams(self) -> None:
        scanner = PickleScanner()
        result = scanner.scan(str(Path(__file__).parent.parent / "assets" / "pickles" / "multiple_stream_attack.pkl"))

        assert len(result.issues) > 0, "Expected issues to be detected for multiple pickle streams"
        eval_issues = [i for i in result.issues if "eval" in i.message.lower()]
        assert len(eval_issues) > 0, f"Expected eval issues, but found: {[i.message for i in result.issues]}"

    def test_reduce_pattern_detects_memoized_callable(self) -> None:
        """REDUCE analysis should resolve memoized call targets (BINGET/LONG_BINGET)."""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                payload = bytearray(b"\x80\x02")
                payload += b"cposix\nsystem\n"  # GLOBAL posix.system
                payload += b"q\x01"  # BINPUT 1 (memoize callable)
                payload += b"0"  # POP original callable from stack
                # Add filler opcodes so target isn't adjacent to REDUCE
                for i in range(12):
                    filler = f"f{i}".encode()
                    payload += b"X" + struct.pack("<I", len(filler)) + filler
                    payload += b"0"
                payload += b"h\x01"  # BINGET 1
                arg = b"echo test"
                payload += b"X" + struct.pack("<I", len(arg)) + arg
                payload += b"\x85R."  # TUPLE1 + REDUCE + STOP

                f.write(payload)
                f.flush()
                f.close()

                result = scanner.scan(f.name)

                reduce_pattern_checks = [c for c in result.checks if c.name == "Reduce Pattern Analysis"]
                assert reduce_pattern_checks, "Expected Reduce Pattern Analysis check"
                assert any(c.status.value == "failed" for c in reduce_pattern_checks), (
                    "Reduce Pattern Analysis should fail for memoized posix.system REDUCE target"
                )
                assert any("posix.system" in c.message for c in reduce_pattern_checks), (
                    "Expected posix.system in Reduce Pattern Analysis message: "
                    f"{[c.message for c in reduce_pattern_checks]}"
                )

            finally:
                os.unlink(f.name)

    def test_stack_global_uses_actual_stack_not_popped_decoys(self) -> None:
        """STACK_GLOBAL resolution should follow stack semantics, not nearby popped strings."""
        scanner = PickleScanner()

        import os
        import tempfile

        def short_binunicode(value: bytes) -> bytes:
            return b"\x8c" + bytes([len(value)]) + value

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                payload = bytearray(b"\x80\x04")
                payload += short_binunicode(b"os")
                payload += short_binunicode(b"system")

                # Push/pop decoys that should NOT affect STACK_GLOBAL target.
                for i in range(6):
                    junk = f"junk{i}".encode()
                    payload += short_binunicode(junk)
                    payload += b"0"  # POP

                # Safe-looking decoys near STACK_GLOBAL that are immediately popped.
                payload += short_binunicode(b"torch._utils")
                payload += b"0"
                payload += short_binunicode(b"_rebuild_tensor_v2")
                payload += b"0"

                payload += b"\x93"  # STACK_GLOBAL (should still resolve to os.system)
                payload += short_binunicode(b"echo test")
                payload += b"\x85R."

                f.write(payload)
                f.flush()
                f.close()

                result = scanner.scan(f.name)

                stack_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Module Check"]
                assert stack_checks, "Expected STACK_GLOBAL Module Check"
                assert any(
                    c.status.value == "failed" and ("posix.system" in c.message or "os.system" in c.message)
                    for c in stack_checks
                ), f"Expected failed STACK_GLOBAL check for os/posix.system, got: {[c.message for c in stack_checks]}"

                reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
                assert any(
                    c.status.value == "failed" and ("posix.system" in c.message or "os.system" in c.message)
                    for c in reduce_checks
                ), f"Expected REDUCE check to resolve os/posix.system, got: {[c.message for c in reduce_checks]}"

            finally:
                os.unlink(f.name)

    def test_scan_regular_pickle_file(self):
        """Test that regular .pkl files don't trigger binary content scanning"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                # Write a simple pickle
                simple_data = {"weights": [1.0, 2.0, 3.0]}
                pickle.dump(simple_data, f)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should not have pickle_bytes or binary_bytes metadata (not a .bin file)
                assert "pickle_bytes" not in result.metadata
                assert "binary_bytes" not in result.metadata

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_pytorch_high_confidence_skips_binary_scan(self):
        """Test that high-confidence PyTorch models skip binary scanning to avoid false positives"""
        scanner = PickleScanner()

        # Create a complex ML-like data structure that might trigger some ML detection
        # Focus on collections.OrderedDict which is a common PyTorch pattern
        import collections
        import os
        import tempfile

        # Create nested OrderedDict structures that mimic PyTorch state_dict patterns
        complex_ml_data = collections.OrderedDict(
            [
                ("features.0.weight", "tensor_data_placeholder"),
                ("features.0.bias", "tensor_data_placeholder"),
                ("features.3.weight", "tensor_data_placeholder"),
                ("features.3.bias", "tensor_data_placeholder"),
                ("classifier.weight", "tensor_data_placeholder"),
                ("classifier.bias", "tensor_data_placeholder"),
                ("_metadata", collections.OrderedDict([("version", 1)])),
                ("_modules", collections.OrderedDict()),
                ("_parameters", collections.OrderedDict()),
            ],
        )

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                pickle.dump(complex_ml_data, f)

                # Add binary content that would normally trigger warnings
                suspicious_binary_content = (
                    b"MZ"
                    + b"padding" * 100
                    + b"This program cannot be run in DOS mode"
                    + b"more_data"
                    + b"import os"
                    + b"eval("
                    + b"subprocess.call"
                )
                f.write(suspicious_binary_content)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Check the ML context that was detected
                ml_context = result.metadata.get("ml_context", {})
                ml_confidence = ml_context.get("overall_confidence", 0)
                is_pytorch = "pytorch" in ml_context.get("frameworks", {})

                # Test the logic: if pytorch detected with high confidence, binary scan should be skipped
                if is_pytorch and ml_confidence > 0.7:
                    # Should have skipped binary scanning
                    assert result.metadata.get("binary_scan_skipped") is True
                    assert "High-confidence PyTorch model detected" in result.metadata.get("skip_reason", "")

                    # Should not find binary-related issues (since binary scan was skipped)
                    binary_issues = [
                        issue
                        for issue in result.issues
                        if "binary data" in issue.message.lower() or "executable signature" in issue.message.lower()
                    ]
                    assert len(binary_issues) == 0, (
                        f"Found unexpected binary issues: {[issue.message for issue in binary_issues]}"
                    )
                else:
                    # If conditions not met, binary scan should proceed normally
                    assert result.metadata.get("binary_scan_skipped") is not True
                    print(
                        f"ML confidence too low ({ml_confidence}) or PyTorch not detected ({is_pytorch}) - "
                        f"binary scan proceeded normally"
                    )

                # Should have metadata about the scan regardless
                assert "pickle_bytes" in result.metadata
                assert "binary_bytes" in result.metadata
                assert result.metadata["binary_bytes"] > 0

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_low_confidence_performs_binary_scan(self):
        """Test that low-confidence ML models still perform binary scanning"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Create a pickle with minimal ML context (low confidence)
                low_confidence_data = {
                    "data": [1, 2, 3, 4, 5],
                    "some_weights": [0.1, 0.2, 0.3],
                }
                pickle.dump(low_confidence_data, f)

                # Add binary content with executable signatures
                f.write(b"some_padding")
                f.write(b"\x7fELF")  # Linux ELF executable signature
                f.write(b"more_padding")
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should NOT have skipped binary scanning
                assert result.metadata.get("binary_scan_skipped") is not True

                # Should have performed binary scan and found the ELF signature
                executable_issues = [
                    issue for issue in result.issues if "executable signature" in issue.message.lower()
                ]
                assert len(executable_issues) >= 1, "Should have found ELF signature"

            finally:
                os.unlink(f.name)

    def test_pe_file_detection_requires_dos_stub(self):
        """Test that PE file detection requires both MZ signature and DOS stub message"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"test": "data"}
                pickle.dump(simple_data, f)

                # Add MZ signature WITHOUT DOS stub (should not trigger PE detection)
                f.write(b"some_padding")
                f.write(b"MZ")  # PE signature but no DOS stub
                f.write(b"random_data" * 50)  # Random data without DOS stub message
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should NOT find PE executable signature (missing DOS stub)
                pe_issues = [issue for issue in result.issues if "windows executable (pe)" in issue.message.lower()]
                assert len(pe_issues) == 0, (
                    f"Should not detect PE without DOS stub, but found: {[issue.message for issue in pe_issues]}"
                )

            finally:
                os.unlink(f.name)

    def test_pe_file_detection_with_dos_stub(self):
        """Test that PE file detection works when both MZ signature and DOS stub are present"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"test": "data"}
                pickle.dump(simple_data, f)

                # Add proper PE signature WITH DOS stub
                f.write(b"some_padding")
                f.write(b"MZ")  # PE signature
                f.write(b"dos_header_data" * 5)  # Some padding
                f.write(b"This program cannot be run in DOS mode")  # DOS stub message
                f.write(b"more_data" * 10)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should find PE executable signature
                pe_issues = [issue for issue in result.issues if "windows executable (pe)" in issue.message.lower()]
                assert len(pe_issues) >= 1, "Should detect PE with DOS stub"

                pe_error_issues = [issue for issue in pe_issues if issue.severity == IssueSeverity.CRITICAL]
                assert len(pe_error_issues) >= 1, "PE detection should be CRITICAL severity"

            finally:
                os.unlink(f.name)

    def test_nested_pickle_detection(self):
        """Scanner should detect nested pickle bytes and encoded payloads"""
        scanner = PickleScanner()

        import base64
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                inner = {"a": 1}
                inner_bytes = pickle.dumps(inner)
                outer = {
                    "raw": inner_bytes,
                    "enc": base64.b64encode(inner_bytes).decode("ascii"),
                }
                pickle.dump(outer, f)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                result = scanner.scan(f.name)

                assert result.success

                nested_issues = [
                    i
                    for i in result.issues
                    if "nested pickle payload" in i.message.lower() or "encoded pickle payload" in i.message.lower()
                ]
                assert nested_issues
                assert any(i.severity == IssueSeverity.CRITICAL for i in nested_issues)

            finally:
                os.unlink(f.name)


class TestCVE20251716PipMainBlocklist(unittest.TestCase):
    """Test CVE-2025-1716: pickle bypass via pip.main() as callable."""

    def test_pip_main_detected_as_critical(self):
        """Pickle with GLOBAL pip.main + REDUCE should be flagged CRITICAL."""
        # Protocol 2 pickle: GLOBAL pip\nmain\n, EMPTY_TUPLE, REDUCE, STOP
        payload = b"\x80\x02cpip\nmain\n)R."
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(payload)
            f.flush()
            try:
                scanner = PickleScanner()
                result = scanner.scan(f.name)

                # Should have CRITICAL issues referencing pip.main
                critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
                assert len(critical_issues) > 0, (
                    f"pip.main should be flagged as CRITICAL. Issues: {[i.message for i in result.issues]}"
                )
                assert any("pip" in i.message for i in critical_issues), (
                    f"Should reference pip in message. Issues: {[i.message for i in critical_issues]}"
                )
            finally:
                os.unlink(f.name)

    def test_pip_internal_main_detected(self):
        """Pickle with GLOBAL pip._internal.main should be flagged."""
        payload = b"\x80\x02cpip._internal\nmain\n)R."
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(payload)
            f.flush()
            try:
                scanner = PickleScanner()
                result = scanner.scan(f.name)

                critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
                assert len(critical_issues) > 0, (
                    f"pip._internal.main should be flagged. Issues: {[i.message for i in result.issues]}"
                )
            finally:
                os.unlink(f.name)

    def test_pip_main_in_always_dangerous(self):
        """Verify pip.main is in ALWAYS_DANGEROUS_FUNCTIONS set."""
        from modelaudit.scanners.pickle_scanner import ALWAYS_DANGEROUS_FUNCTIONS

        assert "pip.main" in ALWAYS_DANGEROUS_FUNCTIONS
        assert "pip._internal.main" in ALWAYS_DANGEROUS_FUNCTIONS
        assert "pip._internal.cli.main.main" in ALWAYS_DANGEROUS_FUNCTIONS

    def test_pip_module_in_always_dangerous_modules(self):
        """Verify pip module prefixes are in ALWAYS_DANGEROUS_MODULES set."""
        from modelaudit.scanners.pickle_scanner import ALWAYS_DANGEROUS_MODULES

        assert "pip" in ALWAYS_DANGEROUS_MODULES
        assert "pip._internal" in ALWAYS_DANGEROUS_MODULES


if __name__ == "__main__":
    unittest.main()
