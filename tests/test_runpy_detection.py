"""
Test detection of runpy module usage in pickle files.

The runpy module allows execution of arbitrary Python modules and scripts,
making it a critical security risk when found in pickle files.
"""

import os
import tempfile

from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.suspicious_symbols import SUSPICIOUS_GLOBALS


class TestRunpyDetection:
    """Test detection of dangerous runpy module usage."""

    def test_runpy_in_suspicious_globals(self):
        """Verify that runpy is marked as suspicious in SUSPICIOUS_GLOBALS."""
        assert "runpy" in SUSPICIOUS_GLOBALS
        # runpy should be marked as "*" (all functions are dangerous)
        assert SUSPICIOUS_GLOBALS["runpy"] == "*"

    def test_runpy_run_module_detection(self):
        """Test detection of runpy.run_module in pickle files."""
        scanner = PickleScanner()

        # Create a pickle with runpy.run_module
        # Protocol 2 pickle with GLOBAL opcode for runpy.run_module
        pickle_bytes = b"\x80\x02crunpy\nrun_module\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should have critical issues
            assert len(result.issues) > 0, "Should detect runpy.run_module"

            # Check for CRITICAL severity
            critical_issues = [i for i in result.issues if i.severity.name == "CRITICAL"]
            assert len(critical_issues) > 0, "runpy.run_module should be CRITICAL"

            # Check that runpy was specifically detected
            all_messages = " ".join(issue.message for issue in result.issues)
            all_details = " ".join(str(issue.details) for issue in result.issues)
            assert "runpy" in all_messages.lower() or "runpy" in all_details, "Should mention runpy"

        finally:
            os.unlink(temp_path)

    def test_runpy_run_path_detection(self):
        """Test detection of runpy.run_path in pickle files."""
        scanner = PickleScanner()

        # Create a pickle with runpy.run_path
        pickle_bytes = b"\x80\x02crunpy\nrun_path\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect as dangerous
            assert len(result.issues) > 0, "Should detect runpy.run_path"

            # Should have at least one CRITICAL issue
            critical_issues = [i for i in result.issues if i.severity.name == "CRITICAL"]
            assert len(critical_issues) > 0, "runpy.run_path should be CRITICAL"

        finally:
            os.unlink(temp_path)

    def test_runpy_with_arguments(self):
        """Test detection of runpy with arguments (more realistic attack)."""
        scanner = PickleScanner()

        # Create a pickle that uses runpy.run_module to execute os
        # This simulates: runpy.run_module('os').__dict__['system']('echo pwned')
        pickle_bytes = (
            b"\x80\x02"  # Protocol 2
            b"crunpy\nrun_module\n"  # Import runpy.run_module
            b"q\x00"  # BINPUT 0
            b"(S'os'\n"  # Argument: 'os' module
            b"tq\x01"  # TUPLE, BINPUT 1
            b"Rq\x02"  # REDUCE (calls run_module), BINPUT 2
            b"."  # STOP
        )

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect multiple issues (runpy and possibly 'os' in string)
            assert len(result.issues) > 0, "Should detect runpy with malicious argument"

            # Should have CRITICAL issues
            critical_issues = [i for i in result.issues if i.severity.name == "CRITICAL"]
            assert len(critical_issues) > 0, "runpy execution should be CRITICAL"

            # Check for runpy detection
            found_runpy = False
            for issue in result.issues:
                if "runpy" in issue.message.lower() or "runpy" in str(issue.details):
                    found_runpy = True
                    break
            assert found_runpy, "Should specifically detect runpy module"

        finally:
            os.unlink(temp_path)

    def test_runpy_run_module_as_main(self):
        """Test detection of runpy._run_module_as_main (internal but dangerous)."""
        scanner = PickleScanner()

        # Create a pickle with runpy._run_module_as_main
        pickle_bytes = b"\x80\x02crunpy\n_run_module_as_main\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect as dangerous
            assert len(result.issues) > 0, "Should detect runpy._run_module_as_main"

            # Check severity
            serious_issues = [i for i in result.issues if i.severity.name in ["CRITICAL", "WARNING"]]
            assert len(serious_issues) > 0, "runpy._run_module_as_main should be serious"

        finally:
            os.unlink(temp_path)

    def test_runpy_pattern_in_raw_content(self):
        """Test that 'runpy' pattern is detected in raw file content."""
        scanner = PickleScanner()

        # Create a file with 'runpy' in it (even if not a valid pickle)
        content = b"Some content with runpy module reference"

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect 'runpy' pattern
            pattern_detected = False
            for issue in result.issues:
                if "runpy" in issue.message.lower():
                    pattern_detected = True
                    assert issue.severity.name == "CRITICAL", "runpy pattern should be CRITICAL"
                    break

            assert pattern_detected, "Should detect 'runpy' pattern in raw content"

        finally:
            os.unlink(temp_path)

    def test_multiple_runpy_functions(self):
        """Test detection of various runpy functions."""
        scanner = PickleScanner()

        runpy_functions = [
            b"run_module",
            b"run_path",
            b"_run_module_as_main",
            b"_run_code",
        ]

        for func_bytes in runpy_functions:
            # Create pickle with specific runpy function
            pickle_bytes = b"\x80\x02crunpy\n" + func_bytes + b"\nq\x00."

            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                f.write(pickle_bytes)
                temp_path = f.name

            try:
                result = scanner.scan(temp_path)

                func_name = func_bytes.decode("utf-8")
                assert len(result.issues) > 0, f"Should detect runpy.{func_name}"

                # All runpy functions should trigger warnings or critical issues
                serious_issues = [i for i in result.issues if i.severity.name in ["CRITICAL", "WARNING"]]
                assert len(serious_issues) > 0, f"runpy.{func_name} should be flagged as serious"

            finally:
                os.unlink(temp_path)

    def test_obfuscated_runpy_import(self):
        """Test detection of obfuscated runpy imports."""
        scanner = PickleScanner()

        # Test with different module name formats that might be used
        test_cases = [
            b"\x80\x02c__main__\nrunpy\nq\x00.",  # __main__.runpy
            b"\x80\x02cglobals\nrunpy\nq\x00.",  # globals.runpy
        ]

        for pickle_bytes in test_cases:
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                f.write(pickle_bytes)
                temp_path = f.name

            try:
                result = scanner.scan(temp_path)

                # Should detect 'runpy' pattern at minimum
                runpy_detected = any(
                    "runpy" in issue.message.lower() or "runpy" in str(issue.details) for issue in result.issues
                )
                assert runpy_detected, "Should detect runpy even in obfuscated imports"

            finally:
                os.unlink(temp_path)

    def test_runpy_severity_levels(self):
        """Test that runpy is consistently flagged as CRITICAL."""
        scanner = PickleScanner()

        # Create a pickle with runpy that would execute malicious code
        pickle_bytes = (
            b"\x80\x02"  # Protocol 2
            b"crunpy\nrun_module\n"  # runpy.run_module
            b"p0\n"
            b"(S'subprocess'\n"  # Run subprocess module
            b"p1\n"
            b"tp2\n"
            b"Rp3\n"  # REDUCE - execute
            b"."  # STOP
        )

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should have multiple CRITICAL issues (runpy + subprocess)
            critical_issues = [i for i in result.issues if i.severity.name == "CRITICAL"]
            assert len(critical_issues) >= 2, "Should have multiple CRITICAL issues for runpy + subprocess"

            # Verify runpy is among the critical issues
            runpy_critical = any(
                "runpy" in issue.message.lower() or ("module" in issue.details and issue.details["module"] == "runpy")
                for issue in critical_issues
            )
            assert runpy_critical, "runpy should be flagged as CRITICAL"

        finally:
            os.unlink(temp_path)
