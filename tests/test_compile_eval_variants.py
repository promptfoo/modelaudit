"""
Test detection of compile(), eval() and related code execution variants.

These functions allow dynamic code execution and are commonly used in
sophisticated pickle-based attacks.
"""

import os
import tempfile

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.suspicious_symbols import DANGEROUS_BUILTINS


class TestCompileEvalVariants:
    """Test detection of various code execution patterns."""

    def test_compile_in_dangerous_builtins(self):
        """Verify that compile and related functions are in DANGEROUS_BUILTINS."""
        assert "compile" in DANGEROUS_BUILTINS
        assert "globals" in DANGEROUS_BUILTINS
        assert "locals" in DANGEROUS_BUILTINS
        assert "setattr" in DANGEROUS_BUILTINS
        assert "getattr" in DANGEROUS_BUILTINS

    def test_compile_detection(self):
        """Test detection of compile() function in pickle files."""
        scanner = PickleScanner()

        # Create a pickle with compile function
        # Protocol 2 pickle with compile reference
        pickle_bytes = b"\x80\x02cbuiltins\ncompile\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should have critical issues
            assert len(result.issues) > 0, "Should detect compile function"

            # Check for CRITICAL severity (compile is dangerous)
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, "compile should be CRITICAL"

            # Check that compile was detected
            all_messages = " ".join(issue.message for issue in result.issues)
            assert "compile" in all_messages.lower(), "Should mention compile"

        finally:
            os.unlink(temp_path)

    def test_globals_detection(self):
        """Test detection of globals() function."""
        scanner = PickleScanner()

        # Create a pickle with globals() reference
        pickle_bytes = b"\x80\x02cbuiltins\nglobals\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect as dangerous
            assert len(result.issues) > 0, "Should detect globals()"

            # Check that globals was detected in patterns
            pattern_detected = False
            for issue in result.issues:
                if "globals" in issue.message.lower():
                    pattern_detected = True
                    assert issue.severity == IssueSeverity.CRITICAL, "globals should be CRITICAL"
                    break

            assert pattern_detected, "Should detect globals pattern"

        finally:
            os.unlink(temp_path)

    def test_locals_detection(self):
        """Test detection of locals() function."""
        scanner = PickleScanner()

        # Create a pickle with locals() reference
        pickle_bytes = b"\x80\x02cbuiltins\nlocals\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect as dangerous
            assert len(result.issues) > 0, "Should detect locals()"

            # Check that locals was detected
            pattern_detected = False
            for issue in result.issues:
                if "locals" in issue.message.lower():
                    pattern_detected = True
                    assert issue.severity == IssueSeverity.CRITICAL, "locals should be CRITICAL"
                    break

            assert pattern_detected, "Should detect locals pattern"

        finally:
            os.unlink(temp_path)

    def test_builtins_access_detection(self):
        """Test detection of __builtins__ access."""
        scanner = PickleScanner()

        # Create a pickle with __builtins__ reference
        pickle_bytes = b"\x80\x02c__builtins__\neval\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should have critical issues
            assert len(result.issues) > 0, "Should detect __builtins__ access"

            # Check for CRITICAL severity
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, "__builtins__ access should be CRITICAL"

            # Check that __builtins__ was detected
            pattern_detected = False
            for issue in result.issues:
                if "__builtins__" in issue.message.lower() or "builtins" in issue.message.lower():
                    pattern_detected = True
                    break

            assert pattern_detected, "Should detect __builtins__ pattern"

        finally:
            os.unlink(temp_path)

    def test_compile_with_exec_mode(self):
        """Test detection of compile() with exec mode (most dangerous)."""
        scanner = PickleScanner()

        # Create a pickle that uses compile with exec mode
        # This simulates: compile('import os; os.system("cmd")', '<string>', 'exec')
        pickle_bytes = (
            b"\x80\x02"  # Protocol 2
            b"cbuiltins\ncompile\n"  # Import compile
            b"q\x00"  # BINPUT 0
            b"(S'import os; os.system(\"cmd\")'\n"  # Code to compile
            b"S'<string>'\n"  # Filename
            b"S'exec'\n"  # Mode: exec (most dangerous)
            b"tq\x01"  # TUPLE, BINPUT 1
            b"Rq\x02"  # REDUCE (calls compile)
            b"."  # STOP
        )

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect multiple issues (compile, os, system)
            assert len(result.issues) > 0, "Should detect compile with malicious code"

            # Should have CRITICAL issues
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, "compile with exec mode should be CRITICAL"

        finally:
            os.unlink(temp_path)

    def test_eval_with_globals_manipulation(self):
        """Test detection of eval with globals() manipulation."""
        scanner = PickleScanner()

        # Create a pickle that manipulates globals for eval
        # This simulates: eval('__import__("os").system("cmd")', globals())
        pickle_bytes = (
            b"\x80\x02"  # Protocol 2
            b"(cbuiltins\neval\n"  # Import eval
            b"p0\n"  # PUT 0
            b'S\'__import__("os").system("cmd")\'\n'  # Code to eval
            b"p1\n"  # PUT 1
            b"cbuiltins\nglobals\n"  # Import globals
            b"p2\n"  # PUT 2
            b"(tp3\n"  # Empty tuple for globals() call, PUT 3
            b"Rp4\n"  # REDUCE - call globals(), PUT 4
            b"tp5\n"  # Tuple of (code, globals_dict), PUT 5
            b"Rp6\n"  # REDUCE - call eval with globals
            b"."  # STOP
        )

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect multiple dangerous patterns
            assert len(result.issues) > 0, "Should detect eval with globals manipulation"

            # Check for both eval and globals detection
            found_eval = False
            found_globals = False
            for issue in result.issues:
                if "eval" in issue.message.lower():
                    found_eval = True
                if "globals" in issue.message.lower():
                    found_globals = True

            assert found_eval, "Should detect eval"
            assert found_globals, "Should detect globals"

        finally:
            os.unlink(temp_path)

    def test_eval_in_reduce_attack(self):
        """Test detection of eval used in __reduce__ for malicious unpickling."""
        scanner = PickleScanner()

        # Create a pickle that contains eval in a __reduce__ context
        # This simulates creating an object that executes code when unpickled
        pickle_bytes = (
            b"\x80\x02"  # Protocol 2
            b"cbuiltins\neval\n"  # Import eval
            b"q\x00"  # BINPUT 0
            b'(S\'__import__("os").system("echo pwned")\'\n'  # Malicious code
            b"tq\x01"  # TUPLE, BINPUT 1
            b"Rq\x02"  # REDUCE - execute eval
            b"."  # STOP
        )

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect dangerous patterns
            assert len(result.issues) > 0, "Should detect eval in __reduce__ attack"

            # Should detect eval
            found_eval = False
            for issue in result.issues:
                if "eval" in issue.message.lower():
                    found_eval = True
                    break

            assert found_eval, "Should detect eval in __reduce__"

        finally:
            os.unlink(temp_path)

    def test_setattr_getattr_detection(self):
        """Test detection of setattr/getattr for attribute manipulation."""
        scanner = PickleScanner()

        # Test setattr
        pickle_bytes = b"\x80\x02cbuiltins\nsetattr\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect dangerous builtin
            assert len(result.issues) > 0, "Should detect setattr"

            # Check message mentions the dangerous function
            dangerous_detected = any(
                "setattr" in issue.message.lower() or "dangerous" in issue.message.lower() for issue in result.issues
            )
            assert dangerous_detected, "Should flag setattr as dangerous"

        finally:
            os.unlink(temp_path)

        # Test getattr
        pickle_bytes = b"\x80\x02cbuiltins\ngetattr\nq\x00."

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pickle_bytes)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect dangerous builtin
            assert len(result.issues) > 0, "Should detect getattr"

        finally:
            os.unlink(temp_path)

    def test_all_new_patterns_detected(self):
        """Test that all new dangerous patterns are properly detected."""
        scanner = PickleScanner()

        new_patterns = [
            b"compile",
            b"__builtins__",
            b"globals",
            b"locals",
        ]

        for pattern in new_patterns:
            # Create a simple file with the pattern
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                f.write(b"test content with " + pattern + b" in it")
                temp_path = f.name

            try:
                result = scanner.scan(temp_path)

                # Should detect the pattern
                pattern_name = pattern.decode("utf-8")
                assert len(result.issues) > 0, f"Should detect {pattern_name} pattern"

                # Check that pattern is mentioned
                pattern_found = any(pattern_name in issue.message.lower() for issue in result.issues)
                assert pattern_found, f"Should mention {pattern_name} in issues"

            finally:
                os.unlink(temp_path)
