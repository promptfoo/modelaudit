"""
Test enhanced detection of __builtin__ operators.

This test verifies that ModelAudit can detect various forms of
dangerous builtin functions, including:
- __builtin__ (Python 2 style)
- __builtins__ (alternative reference)
- builtins (Python 3 style)
"""

import os
import tempfile

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.suspicious_symbols import SUSPICIOUS_GLOBALS


class TestBuiltinDetection:
    """Test detection of dangerous builtin functions."""

    def test_suspicious_globals_include_all_builtin_variants(self):
        """Verify that SUSPICIOUS_GLOBALS includes all builtin variants."""
        # Check that all builtin variants are in SUSPICIOUS_GLOBALS
        assert "__builtin__" in SUSPICIOUS_GLOBALS
        assert "__builtins__" in SUSPICIOUS_GLOBALS
        assert "builtins" in SUSPICIOUS_GLOBALS

        # Check that dangerous functions are listed for __builtin__
        builtin_funcs = SUSPICIOUS_GLOBALS["__builtin__"]
        assert isinstance(builtin_funcs, list)
        assert "eval" in builtin_funcs
        assert "exec" in builtin_funcs
        assert "execfile" in builtin_funcs
        assert "compile" in builtin_funcs
        assert "__import__" in builtin_funcs

        # Check that dangerous functions are listed for __builtins__
        builtins_funcs = SUSPICIOUS_GLOBALS["__builtins__"]
        assert isinstance(builtins_funcs, list)
        assert "eval" in builtins_funcs
        assert "exec" in builtins_funcs

        # Check that dangerous functions are listed for builtins (Python 3)
        builtins3_funcs = SUSPICIOUS_GLOBALS["builtins"]
        assert isinstance(builtins3_funcs, list)
        assert "eval" in builtins3_funcs
        assert "exec" in builtins3_funcs

    def test_pickle_scanner_detects_builtin_eval(self):
        """Test that PickleScanner detects __builtin__.eval as critical."""
        scanner = PickleScanner()

        # Create a pickle with __builtin__.eval
        pickle_bytes = b"\x80\x02c__builtin__\neval\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should have critical issues
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, "Should detect __builtin__.eval as CRITICAL"

            # Check that it specifically detected __builtin__.eval
            found_builtin_eval = False
            for issue in critical_issues:
                if (
                    "module" in issue.details
                    and issue.details["module"] == "__builtin__"
                    and issue.details.get("function") == "eval"
                ):
                    found_builtin_eval = True
                    break

            assert found_builtin_eval, "Should specifically detect __builtin__.eval"

        finally:
            os.unlink(temp_path)

    def test_pickle_scanner_detects_all_builtin_variants(self):
        """Test detection of various __builtin__ format variations."""
        test_cases = [
            # (pickle_bytes, expected_module, expected_function, description)
            (b"\x80\x02c__builtin__\neval\nq\x00.", "__builtin__", "eval", "Python 2 eval"),
            (b"\x80\x02c__builtin__\nexec\nq\x00.", "__builtin__", "exec", "Python 2 exec"),
            (b"\x80\x02c__builtin__\nexecfile\nq\x00.", "__builtin__", "execfile", "Python 2 execfile"),
            (b"\x80\x02c__builtin__\ncompile\nq\x00.", "__builtin__", "compile", "Python 2 compile"),
            (b"\x80\x02c__builtins__\neval\nq\x00.", "__builtins__", "eval", "Alternative builtins eval"),
            (b"\x80\x02cbuiltins\neval\nq\x00.", "builtins", "eval", "Python 3 eval"),
            (b"\x80\x02cbuiltins\nexec\nq\x00.", "builtins", "exec", "Python 3 exec"),
            (b"\x80\x02c__builtin__\n__import__\nq\x00.", "__builtin__", "__import__", "Dynamic import"),
        ]

        scanner = PickleScanner()

        for pickle_bytes, expected_module, expected_function, description in test_cases:
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                f.write(pickle_bytes)
                temp_path = f.name

            try:
                result = scanner.scan(temp_path)

                # Should detect as dangerous
                assert len(result.issues) > 0, f"Failed to detect {description}"

                # Should have at least one critical or warning issue
                serious_issues = [i for i in result.issues if i.severity.name in ["CRITICAL", "WARNING"]]
                assert len(serious_issues) > 0, f"{description} should be flagged as serious"

                # Check for specific detection
                found = False
                for issue in result.issues:
                    details = issue.details
                    if details.get("module") == expected_module and details.get("function") == expected_function:
                        found = True
                        assert issue.severity.name in ["CRITICAL", "WARNING"], (
                            f"{description} should be CRITICAL or WARNING"
                        )
                        break

                assert found, f"Should specifically detect {expected_module}.{expected_function} ({description})"

            finally:
                os.unlink(temp_path)

    def test_builtin_in_decode_exec_chain(self):
        """Test detection of __builtin__.eval in decode-exec chains."""
        scanner = PickleScanner()

        # Create a pickle with base64.decode followed by __builtin__.eval
        pickle_bytes = (
            b"\x80\x02"  # Protocol 2
            b"cbase64\nb64decode\n"  # First: base64.b64decode
            b"q\x00"
            b"c__builtin__\neval\n"  # Then: __builtin__.eval
            b"q\x01"
            b"."  # STOP
        )

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect both the decode and the eval
            all_messages = " ".join(issue.message for issue in result.issues)
            all_details = " ".join(str(issue.details) for issue in result.issues)

            assert "base64" in all_messages.lower() or "base64" in all_details, "Should detect base64 decode"
            assert "__builtin__" in all_messages or "__builtin__" in all_details, "Should detect __builtin__"

            # Should have at least one CRITICAL issue
            assert any(issue.severity.name == "CRITICAL" for issue in result.issues), "Should have CRITICAL severity"

        finally:
            os.unlink(temp_path)

    def test_obfuscated_builtin_references(self):
        """Test that obfuscated builtin references are detected."""
        from modelaudit.scanners.pickle_scanner import is_suspicious_global

        # Test direct matches
        assert is_suspicious_global("__builtin__", "eval") is True
        assert is_suspicious_global("__builtins__", "exec") is True
        assert is_suspicious_global("builtins", "compile") is True

        # Test that safe functions are not flagged
        assert is_suspicious_global("__builtin__", "len") is False
        assert is_suspicious_global("builtins", "print") is False

        # Test dangerous functions from other modules
        assert is_suspicious_global("os", "system") is True
        assert is_suspicious_global("subprocess", "call") is True

    def test_severity_levels_for_builtins(self):
        """Test that builtin eval/exec are flagged with appropriate severity."""
        scanner = PickleScanner()

        # Most dangerous: __builtin__.eval with actual code
        pickle_with_code = (
            b"\x80\x02"  # Protocol 2
            b"c__builtin__\neval\n"  # __builtin__.eval
            b"p0\n"
            b'(S\'__import__("os").system("echo pwned")\'\n'  # Malicious code
            b"p1\n"
            b"tp2\n"
            b"Rp3\n"  # REDUCE - actually calls eval
            b"."  # STOP
        )

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_with_code)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should have multiple CRITICAL issues
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) >= 2, "Should have multiple CRITICAL issues for eval with malicious code"

            # Should detect both the eval and the os.system in the string
            all_messages = " ".join(issue.message for issue in result.issues)
            assert "eval" in all_messages.lower(), "Should mention eval"

        finally:
            os.unlink(temp_path)


class TestEnhancedSuspiciousGlobalFunction:
    """Test the enhanced is_suspicious_global function."""

    def test_is_suspicious_global_enhanced_detection(self):
        """Test that the enhanced function detects all builtin variants."""
        from modelaudit.scanners.pickle_scanner import is_suspicious_global

        # Test all builtin module variants
        builtin_modules = ["__builtin__", "__builtins__", "builtins"]
        dangerous_funcs = ["eval", "exec", "execfile", "compile", "__import__"]

        for module in builtin_modules:
            for func in dangerous_funcs:
                # Skip execfile for Python 3 style builtins (it doesn't exist)
                if module == "builtins" and func == "execfile":
                    continue

                result = is_suspicious_global(module, func)
                assert result is True, f"Should detect {module}.{func} as suspicious"

    def test_is_suspicious_global_safe_builtins(self):
        """Test that safe builtin functions are not flagged."""
        from modelaudit.scanners.pickle_scanner import is_suspicious_global

        safe_funcs = ["len", "str", "int", "float", "list", "dict", "set", "tuple", "print", "abs", "min", "max"]

        for func in safe_funcs:
            assert is_suspicious_global("__builtin__", func) is False, f"Should not flag __builtin__.{func}"
            assert is_suspicious_global("builtins", func) is False, f"Should not flag builtins.{func}"

    def test_is_suspicious_global_other_dangerous_modules(self):
        """Test that other dangerous modules are still detected."""
        from modelaudit.scanners.pickle_scanner import is_suspicious_global

        # These should all be suspicious
        assert is_suspicious_global("os", "system") is True
        assert is_suspicious_global("os", "exec") is True
        assert is_suspicious_global("subprocess", "call") is True
        assert is_suspicious_global("subprocess", "Popen") is True
        assert is_suspicious_global("sys", "exit") is True

        # Safe modules should not be flagged
        assert is_suspicious_global("json", "loads") is False
        assert is_suspicious_global("math", "sqrt") is False
