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
from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
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

    def test_advanced_global_reference_issue_has_rule_code(self) -> None:
        """Dangerous advanced global references should carry a rule code."""
        scanner = PickleScanner()
        result = scanner.scan(str(Path(__file__).parent.parent / "assets" / "pickles" / "stack_global_attack.pkl"))

        advanced_issues = [i for i in result.issues if i.message.startswith("Suspicious reference ")]
        assert advanced_issues, f"Expected advanced global issues, got: {[i.message for i in result.issues]}"
        assert all(i.rule_code for i in advanced_issues), (
            f"Expected rule codes on advanced global issues, got: {[i.rule_code for i in advanced_issues]}"
        )

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


class TestPickleScannerBlocklistHardening(unittest.TestCase):
    """Regression tests for fickling/picklescan bypass hardening."""

    @staticmethod
    def _craft_global_reduce_pickle(module: str, func: str) -> bytes:
        """Craft a minimal pickle that uses GLOBAL + REDUCE to call module.func.

        The resulting pickle is: PROTO 2 | GLOBAL 'module func' | MARK | TUPLE | REDUCE | STOP
        This is structurally valid but should be caught by the scanner without
        actually being unpickled.
        """

        # Use protocol 2
        proto = b"\x80\x02"
        # GLOBAL opcode: 'c' followed by "module\nfunc\n"
        global_op = b"c" + f"{module}\n{func}\n".encode()
        # MARK + empty TUPLE (arguments) + REDUCE + STOP
        call_ops = b"(" + b"t" + b"R" + b"."
        return proto + global_op + call_ops

    def _scan_bytes(self, data: bytes) -> ScanResult:
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(data)
            f.flush()
            path = f.name
        try:
            scanner = PickleScanner()
            return scanner.scan(path)
        finally:
            os.unlink(path)

    # ------------------------------------------------------------------
    # Fix 1: pkgutil trampoline — must be CRITICAL
    # ------------------------------------------------------------------
    def test_pkgutil_resolve_name_critical(self) -> None:
        """pkgutil.resolve_name is a dynamic resolution trampoline to arbitrary callables."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("pkgutil", "resolve_name"))
        assert result.success
        assert result.has_errors
        critical = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        pkgutil_issues = [i for i in critical if "pkgutil" in i.message]
        assert pkgutil_issues, f"Expected CRITICAL pkgutil issue, got: {[i.message for i in result.issues]}"

    # ------------------------------------------------------------------
    # Fix 1: uuid RCE — must be CRITICAL
    # ------------------------------------------------------------------
    def test_uuid_get_command_stdout_critical(self) -> None:
        """uuid._get_command_stdout internally calls subprocess.Popen."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("uuid", "_get_command_stdout"))
        assert result.success
        assert result.has_errors
        critical = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        uuid_issues = [i for i in critical if "uuid" in i.message]
        assert uuid_issues, f"Expected CRITICAL uuid issue, got: {[i.message for i in result.issues]}"

    # ------------------------------------------------------------------
    # Fix 2: Multi-stream exploit (benign stream 1 + malicious stream 2)
    # ------------------------------------------------------------------
    def test_multi_stream_benign_then_malicious(self) -> None:
        """Scanner must detect malicious globals in stream 2 even if stream 1 is benign."""
        import io

        buf = io.BytesIO()
        # Stream 1: benign
        pickle.dump({"safe": True}, buf, protocol=2)
        # Stream 2: malicious — os.system via GLOBAL+REDUCE
        buf.write(self._craft_global_reduce_pickle("os", "system"))
        data = buf.getvalue()

        result = self._scan_bytes(data)
        assert result.success
        assert result.has_errors
        os_issues = [
            i
            for i in result.issues
            if i.severity == IssueSeverity.CRITICAL and ("os" in i.message.lower() or "posix" in i.message.lower())
        ]
        assert os_issues, f"Expected CRITICAL os issue in stream 2, got: {[i.message for i in result.issues]}"

    def test_multi_stream_separator_byte_resync(self) -> None:
        """Scanner must detect malicious stream even with junk separator bytes between streams."""
        import io

        buf = io.BytesIO()
        # Stream 1: benign
        pickle.dump({"safe": True}, buf, protocol=2)
        # Junk separator byte (non-pickle byte between streams)
        buf.write(b"\x00")
        # Stream 2: malicious — os.system via GLOBAL+REDUCE
        buf.write(self._craft_global_reduce_pickle("os", "system"))
        data = buf.getvalue()

        result = self._scan_bytes(data)
        assert result.success
        assert result.has_errors
        os_issues = [
            i
            for i in result.issues
            if i.severity == IssueSeverity.CRITICAL and ("os" in i.message.lower() or "posix" in i.message.lower())
        ]
        assert os_issues, f"Expected CRITICAL os issue after separator byte, got: {[i.message for i in result.issues]}"

    def test_multi_stream_malformed_first_stream_still_detects_second(self) -> None:
        """Scanner must detect malicious stream 2 even when stream 1 is malformed.

        A malformed first stream that triggers a ValueError during parsing must
        not cause the scanner to return early and skip subsequent streams.
        """
        import io

        buf = io.BytesIO()
        # Stream 1: starts with valid proto + benign GLOBAL, then malformed
        # bytes that cause a ValueError (invalid UTF-8 in GLOBAL arg).
        # This triggers the stream_error + had_opcodes early-return path.
        buf.write(b"\x80\x02cbuiltins\nlen\nq\x00c\xff\n")
        # Stream 2: malicious — os.system via GLOBAL+REDUCE
        buf.write(self._craft_global_reduce_pickle("os", "system"))
        data = buf.getvalue()

        result = self._scan_bytes(data)
        assert result.success
        assert result.has_errors
        os_issues = [
            i
            for i in result.issues
            if i.severity == IssueSeverity.CRITICAL and ("os" in i.message.lower() or "posix" in i.message.lower())
        ]
        assert os_issues, (
            f"Expected CRITICAL os issue from stream 2 after malformed stream 1, "
            f"got: {[i.message for i in result.issues]}"
        )

    # ------------------------------------------------------------------
    # Fix 3: EXT opcode registry bypass
    # ------------------------------------------------------------------
    def test_ext_reduce_extension_registry_is_flagged(self) -> None:
        """EXT1/EXT2/EXT4 + REDUCE payloads should be flagged as dangerous."""
        import copyreg
        from contextlib import suppress

        inverted_registry = getattr(copyreg, "_inverted_registry", {})
        extension_registry = getattr(copyreg, "_extension_registry", {})
        existing_code = extension_registry.get(("os", "system"))

        def _pick_free_code(start: int, end: int) -> int:
            for candidate in range(start, end + 1):
                if candidate not in inverted_registry:
                    return candidate
            pytest.skip(f"No free copyreg extension code available in range {start}-{end}")

        cases = [
            ("EXT1", b"\x82", _pick_free_code(1, 255), lambda code: bytes([code])),
            ("EXT2", b"\x83", _pick_free_code(256, 65535), lambda code: struct.pack("<H", code)),
            ("EXT4", b"\x84", _pick_free_code(65536, 131072), lambda code: struct.pack("<I", code)),
        ]

        try:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.remove_extension("os", "system", existing_code)

            for _opcode_name, opcode, ext_code, encode in cases:
                copyreg.add_extension("os", "system", ext_code)
                try:
                    # PROTO 2 | EXT*(code) | MARK | STRING | TUPLE | REDUCE | STOP
                    payload = b"\x80\x02" + opcode + encode(ext_code) + b'(S"echo pwned"\ntR.'
                    result = self._scan_bytes(payload)

                    assert result.success
                    assert result.has_errors
                    reduce_issues = [i for i in result.issues if "reduce" in i.message.lower()]
                    assert reduce_issues, f"Expected REDUCE issue, got: {[i.message for i in result.issues]}"
                    assert any("os.system" in i.message or "posix.system" in i.message for i in reduce_issues), (
                        f"Expected resolved os/posix.system in REDUCE issues, got: {[i.message for i in reduce_issues]}"
                    )
                finally:
                    with suppress(ValueError):
                        copyreg.remove_extension("os", "system", ext_code)
        finally:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.add_extension("os", "system", existing_code)

    def test_ext_unresolved_code_still_flagged(self) -> None:
        """EXT1/EXT2/EXT4 with codes NOT in copyreg registry should still be flagged."""
        import copyreg

        inverted_registry = getattr(copyreg, "_inverted_registry", {})

        def _pick_unregistered_code(start: int, end: int) -> int:
            for candidate in range(start, end + 1):
                if candidate not in inverted_registry:
                    return candidate
            pytest.skip(f"No unregistered copyreg code in range {start}-{end}")

        cases = [
            ("EXT1", b"\x82", _pick_unregistered_code(1, 255), lambda code: bytes([code])),
            ("EXT2", b"\x83", _pick_unregistered_code(256, 65535), lambda code: struct.pack("<H", code)),
            ("EXT4", b"\x84", _pick_unregistered_code(65536, 131072), lambda code: struct.pack("<I", code)),
        ]

        for opcode_name, opcode, ext_code, encode in cases:
            # Verify the code is truly unregistered
            assert ext_code not in inverted_registry, (
                f"{opcode_name} code {ext_code} unexpectedly in copyreg._inverted_registry"
            )
            # PROTO 2 | EXT*(code) | MARK | STRING | TUPLE | REDUCE | STOP
            payload = b"\x80\x02" + opcode + encode(ext_code) + b'(S"echo pwned"\ntR.'
            result = self._scan_bytes(payload)

            assert result.success, f"{opcode_name}: scan did not succeed"
            assert result.has_errors, (
                f"{opcode_name}: unresolved EXT code {ext_code} + REDUCE was not flagged, "
                f"issues: {[i.message for i in result.issues]}"
            )
            # The scanner should flag the REDUCE even when the EXT target is unresolved
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert critical_issues, (
                f"{opcode_name}: expected CRITICAL issue for unresolved EXT code {ext_code}, "
                f"got: {[i.message for i in result.issues]}"
            )

    # ------------------------------------------------------------------
    # Fix 3b: ZIP proto0/1 extension bypass
    # ------------------------------------------------------------------
    def test_zip_entry_with_proto0_pickle_text_extension_is_detected(self) -> None:
        """Protocol 0 pickle payloads in ZIP entries should not be skipped by extension."""
        import tempfile
        import zipfile

        from modelaudit.core import scan_file

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "payload.zip"

            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("payload.txt", b'cos\nsystem\n(S"echo pwned"\ntR.')

            result = scan_file(str(zip_path))

            assert result.success
            assert result.has_errors
            critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert any("os.system" in msg or "posix.system" in msg for msg in critical_messages), (
                f"Expected critical os/posix.system issue, got: {critical_messages}"
            )

    # ------------------------------------------------------------------
    # Fix 3c: parser crash resilience on mixed malformed payloads
    # ------------------------------------------------------------------
    def test_malformed_unicode_tail_still_flags_dangerous_global(self) -> None:
        """Malformed tails should not suppress opcode-level dangerous global detection."""
        # Valid prefix with dangerous GLOBAL, followed by malformed GLOBAL bytes
        # that previously caused parse fallback before opcode analysis completed.
        payload = b"\x80\x02cbuiltins\n__import__\nq\x00c\xff\n"

        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors

        critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert any("__import__" in msg for msg in critical_messages), (
            f"Expected CRITICAL __import__ detection, got: {critical_messages}"
        )

    def test_malformed_unicode_tail_with_benign_prefix_does_not_raise_critical(self) -> None:
        """Malformed tails after benign opcodes should not create CRITICAL findings."""
        payload = b"\x80\x02cbuiltins\nlen\nq\x00c\xff\n"

        result = self._scan_bytes(payload)

        assert result.success
        critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert not critical_messages, f"Unexpected CRITICAL benign detection: {critical_messages}"

    # ------------------------------------------------------------------
    # Fix 3: joblib.load loader trampoline bypass
    # ------------------------------------------------------------------
    def test_joblib_load_reduce_is_critical(self) -> None:
        """joblib.load + REDUCE should be treated as dangerous, not allowlisted."""
        payload = b"\x80\x04cjoblib\nload\n\x8c\x0bpayload.pkl\x85R."
        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors
        critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert any("joblib.load" in msg for msg in critical_messages), (
            f"Expected CRITICAL joblib.load issue, got: {critical_messages}"
        )

    # ------------------------------------------------------------------
    # Fix 4: NEWOBJ_EX with dangerous class
    # ------------------------------------------------------------------
    def test_newobj_ex_dangerous_class(self) -> None:
        """NEWOBJ_EX opcode with a dangerous class should be flagged."""
        # Craft pickle: PROTO 4 | GLOBAL 'os _wrap_close' | EMPTY_TUPLE | EMPTY_DICT | NEWOBJ_EX | STOP
        # Protocol 4 is needed for NEWOBJ_EX (opcode 0x92)
        proto = b"\x80\x04"
        global_op = b"c" + b"os\n_wrap_close\n"
        empty_tuple = b")"
        empty_dict = b"}"
        newobj_ex = b"\x92"  # NEWOBJ_EX opcode
        stop = b"."
        data = proto + global_op + empty_tuple + empty_dict + newobj_ex + stop

        result = self._scan_bytes(data)
        assert result.success
        assert result.has_errors
        os_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL and "os" in i.message.lower()]
        assert os_issues, f"Expected CRITICAL os issue for NEWOBJ_EX, got: {[i.message for i in result.issues]}"

    # ------------------------------------------------------------------
    # Fix 1: Spot-check newly-added modules
    # ------------------------------------------------------------------
    def test_smtplib_blocked(self) -> None:
        """smtplib module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("smtplib", "SMTP"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "smtplib" in i.message for i in result.issues), (
            f"Expected CRITICAL smtplib issue, got: {[i.message for i in result.issues]}"
        )

    def test_sqlite3_blocked(self) -> None:
        """sqlite3 module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("sqlite3", "connect"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "sqlite3" in i.message for i in result.issues), (
            f"Expected CRITICAL sqlite3 issue, got: {[i.message for i in result.issues]}"
        )

    def test_tarfile_blocked(self) -> None:
        """tarfile module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("tarfile", "open"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "tarfile" in i.message for i in result.issues), (
            f"Expected CRITICAL tarfile issue, got: {[i.message for i in result.issues]}"
        )

    # NOTE: ctypes test omitted — ctypes added to ALWAYS_DANGEROUS_MODULES in PR #518

    def test_marshal_blocked(self) -> None:
        """marshal module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("marshal", "loads"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "marshal" in i.message for i in result.issues), (
            f"Expected CRITICAL marshal issue, got: {[i.message for i in result.issues]}"
        )

    def test_cloudpickle_blocked(self) -> None:
        """cloudpickle module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("cloudpickle", "loads"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "cloudpickle" in i.message for i in result.issues), (
            f"Expected CRITICAL cloudpickle issue, got: {[i.message for i in result.issues]}"
        )

    def test_webbrowser_blocked(self) -> None:
        """webbrowser module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("webbrowser", "open"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "webbrowser" in i.message for i in result.issues), (
            f"Expected CRITICAL webbrowser issue, got: {[i.message for i in result.issues]}"
        )


class TestCVE20251716PipMainBlocklist(unittest.TestCase):
    """Test CVE-2025-1716: pickle bypass via pip.main() as callable."""

    def test_pip_main_detected_as_critical(self) -> None:
        """Pickle with GLOBAL pip.main + REDUCE should be flagged CRITICAL."""
        # Protocol 2 pickle: GLOBAL pip\nmain\n, EMPTY_TUPLE, REDUCE, STOP
        payload = b"\x80\x02cpip\nmain\n)R."
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(payload)
            f.flush()
            path = f.name
        try:
            scanner = PickleScanner()
            result = scanner.scan(path)

            # Should have CRITICAL issues referencing pip.main
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, (
                f"pip.main should be flagged as CRITICAL. Issues: {[i.message for i in result.issues]}"
            )
            assert any("pip" in i.message for i in critical_issues), (
                f"Should reference pip in message. Issues: {[i.message for i in critical_issues]}"
            )
        finally:
            os.unlink(path)

    def test_pip_internal_main_detected(self) -> None:
        """Pickle with GLOBAL pip._internal.main should be flagged."""
        payload = b"\x80\x02cpip._internal\nmain\n)R."
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(payload)
            f.flush()
            path = f.name
        try:
            scanner = PickleScanner()
            result = scanner.scan(path)

            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, (
                f"pip._internal.main should be flagged. Issues: {[i.message for i in result.issues]}"
            )
            assert any("pip" in i.message.lower() for i in critical_issues), (
                f"Should reference pip in message. Issues: {[i.message for i in critical_issues]}"
            )
        finally:
            os.unlink(path)

    def test_comment_token_does_not_bypass_pip_detection(self) -> None:
        """Embedding a comment-like token in a malicious pip payload must not suppress detection."""
        # Build a pickle that includes a benign SHORT_BINUNICODE string containing "#"
        # before the dangerous pip.main GLOBAL+REDUCE sequence.
        # Protocol 2: PROTO 2, SHORT_BINUNICODE "# comment", POP, GLOBAL pip\nmain\n, EMPTY_TUPLE, REDUCE, STOP
        comment_token = b"# this is a comment"
        comment_op = b"\x8c" + bytes([len(comment_token)]) + comment_token  # SHORT_BINUNICODE
        pop_op = b"0"  # POP to discard the string from the stack
        payload = b"\x80\x02" + comment_op + pop_op + b"cpip\nmain\n)R."
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(payload)
            f.flush()
            path = f.name
        try:
            scanner = PickleScanner()
            result = scanner.scan(path)

            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, (
                f"Comment token must not suppress pip.main detection. Issues: {[i.message for i in result.issues]}"
            )
            assert any("pip" in i.message.lower() for i in critical_issues), (
                f"Should reference pip in message despite comment token. Issues: {[i.message for i in critical_issues]}"
            )
        finally:
            os.unlink(path)

    def test_pip_main_in_always_dangerous(self) -> None:
        """Verify pip.main is in ALWAYS_DANGEROUS_FUNCTIONS set."""
        from modelaudit.scanners.pickle_scanner import ALWAYS_DANGEROUS_FUNCTIONS

        assert "pip.main" in ALWAYS_DANGEROUS_FUNCTIONS
        assert "pip._internal.main" in ALWAYS_DANGEROUS_FUNCTIONS
        assert "pip._internal.cli.main.main" in ALWAYS_DANGEROUS_FUNCTIONS
        assert "pip._vendor.distlib.scripts.ScriptMaker" in ALWAYS_DANGEROUS_FUNCTIONS

    def test_pip_module_in_always_dangerous_modules(self) -> None:
        """Verify pip module prefixes are in ALWAYS_DANGEROUS_MODULES set."""
        from modelaudit.scanners.pickle_scanner import ALWAYS_DANGEROUS_MODULES

        assert "pip" in ALWAYS_DANGEROUS_MODULES
        assert "pip._internal" in ALWAYS_DANGEROUS_MODULES
        assert "pip._internal.cli" in ALWAYS_DANGEROUS_MODULES
        assert "pip._internal.cli.main" in ALWAYS_DANGEROUS_MODULES
        assert "pip._vendor" in ALWAYS_DANGEROUS_MODULES
        assert "pip._vendor.distlib" in ALWAYS_DANGEROUS_MODULES
        assert "pip._vendor.distlib.scripts" in ALWAYS_DANGEROUS_MODULES

    def test_prefix_matching_catches_deep_pip_submodules(self) -> None:
        """Verify _is_dangerous_module catches pip sub-modules not explicitly listed."""
        from modelaudit.scanners.pickle_scanner import _is_dangerous_module

        # These are not explicitly in the set but should match via prefix
        assert _is_dangerous_module("pip._internal.cli.main_parser")
        assert _is_dangerous_module("pip._vendor.distlib.scripts.run")
        assert _is_dangerous_module("pip._internal.commands.install")
        # Non-pip modules should not match
        assert not _is_dangerous_module("pipx.main")
        assert not _is_dangerous_module("pipeline.process")


def test_scan_legitimate_pytorch_pickle_memory_error_is_non_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Memory limits on legitimate .pt files should be surfaced as informational scanner limitation."""
    model_path = tmp_path / "legitimate_model.pt"
    header = b"\x80\x02ctorch\nOrderedDict\nq\x00."
    model_path.write_bytes(header + b"state_dict" + b"\x00" * (1024 * 1024 + 64))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj: {("torch", "OrderedDict")},
    )

    result = PickleScanner().scan(str(model_path))

    resource_limit_checks = [check for check in result.checks if check.name == "Pickle Parse Resource Limit"]
    assert len(resource_limit_checks) == 1
    resource_limit_check = resource_limit_checks[0]
    assert resource_limit_check.status == CheckStatus.FAILED
    assert resource_limit_check.severity == IssueSeverity.INFO
    assert resource_limit_check.details["reason"] == "memory_limit_on_legitimate_model"
    assert resource_limit_check.details["exception_type"] == "MemoryError"
    assert resource_limit_check.details["analysis_incomplete"] is True
    assert resource_limit_check.details["scanner_limitation"] is True

    assert result.metadata["memory_limited"] is True
    assert result.metadata["scanner_limitation"] is True
    assert result.metadata["analysis_incomplete"] is True

    info_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.INFO]
    assert len(info_issues) == 1
    assert info_issues[0].message == "Scan limited by model complexity and memory budget"
    assert not any(
        issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        and "Unable to parse pickle file" in issue.message
        for issue in result.issues
    )


def test_scan_legitimate_pytorch_bin_memory_error_is_informational(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Memory limits on legitimate pytorch_model.bin should be informational only."""
    model_path = tmp_path / "pytorch_model.bin"
    header = b"\x80\x02ctorch\nOrderedDict\nq\x00."
    model_path.write_bytes(header + b"state_dict" + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj: {("torch._utils", "_rebuild_tensor_v2"), ("collections", "OrderedDict")},
    )

    result = PickleScanner().scan(str(model_path))

    resource_limit_checks = [check for check in result.checks if check.name == "Pickle Parse Resource Limit"]
    assert len(resource_limit_checks) == 1
    resource_limit_check = resource_limit_checks[0]
    assert resource_limit_check.status == CheckStatus.FAILED
    assert resource_limit_check.severity == IssueSeverity.INFO
    assert resource_limit_check.details["reason"] == "memory_limit_on_legitimate_model"
    assert resource_limit_check.details["exception_type"] == "MemoryError"
    assert resource_limit_check.details["analysis_incomplete"] is True
    assert resource_limit_check.details["scanner_limitation"] is True
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_memory_error_with_dangerous_globals_not_downgraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dangerous globals must keep MemoryError path as warning, not limitation-info downgrade."""
    model_path = tmp_path / "pytorch_model.bin"
    model_path.write_bytes(b"\x80\x02cbuiltins\neval\nq\x00." + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_is_legitimate_pytorch_model",
        lambda self, path: True,  # force heuristic pass; dangerous-global gate must still block downgrade
    )
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj: {("builtins", "eval")},
    )

    result = PickleScanner().scan(str(model_path))

    assert not any(check.name == "Pickle Parse Resource Limit" for check in result.checks)
    format_validation_checks = [check for check in result.checks if check.name == "Pickle Format Validation"]
    assert len(format_validation_checks) == 1
    assert format_validation_checks[0].status == CheckStatus.FAILED
    assert format_validation_checks[0].severity == IssueSeverity.WARNING
    assert format_validation_checks[0].details["exception_type"] == "MemoryError"


if __name__ == "__main__":
    unittest.main()
