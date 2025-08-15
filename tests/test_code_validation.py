"""Tests for code validation utilities."""

from modelaudit.utils.code_validation import (
    extract_dangerous_constructs,
    is_code_potentially_dangerous,
    validate_python_syntax,
)


class TestValidatePythonSyntax:
    """Test Python syntax validation."""

    def test_valid_syntax(self):
        """Test validation of valid Python code."""
        valid_code = """
def hello():
    print("Hello, world!")
    return 42
"""
        is_valid, error = validate_python_syntax(valid_code)
        assert is_valid is True
        assert error is None

    def test_invalid_syntax(self):
        """Test validation of invalid Python code."""
        invalid_code = "def broken(:\n    pass"
        is_valid, error = validate_python_syntax(invalid_code)
        assert is_valid is False
        assert "Syntax error" in error
        assert "line 1" in error

    def test_empty_code(self):
        """Test validation of empty code."""
        is_valid, error = validate_python_syntax("")
        assert is_valid is False
        assert "Empty" in error

    def test_none_code(self):
        """Test validation of None input."""
        is_valid, error = validate_python_syntax(None)
        assert is_valid is False
        assert "invalid" in error

    def test_complex_valid_code(self):
        """Test validation of complex valid code."""
        complex_code = """
import os
import sys

class MyClass:
    def __init__(self):
        self.value = 42

    @property
    def doubled(self):
        return self.value * 2

    async def process(self):
        for i in range(10):
            yield i ** 2
"""
        is_valid, error = validate_python_syntax(complex_code)
        assert is_valid is True
        assert error is None


class TestExtractDangerousConstructs:
    """Test dangerous construct extraction."""

    def test_dangerous_imports(self):
        """Test detection of dangerous imports."""
        code = """
import os
import subprocess
from sys import exit
from socket import socket
"""
        constructs = extract_dangerous_constructs(code)
        assert "os" in constructs["imports"]
        assert "subprocess" in constructs["imports"]
        assert "from sys" in constructs["imports"]
        assert "from socket" in constructs["imports"]

    def test_eval_exec_detection(self):
        """Test detection of eval/exec calls."""
        code = """
result = eval("2 + 2")
exec("print('hello')")
compiled = compile("x = 1", "<string>", "exec")
module = __import__("os")
"""
        constructs = extract_dangerous_constructs(code)
        assert "eval" in constructs["eval_exec"]
        assert "exec" in constructs["eval_exec"]
        assert "compile" in constructs["eval_exec"]
        assert "__import__" in constructs["eval_exec"]

    def test_file_operations(self):
        """Test detection of file operations."""
        code = """
with open("/etc/passwd", "r") as f:
    data = f.read()
"""
        constructs = extract_dangerous_constructs(code)
        assert "open" in constructs["file_operations"]

    def test_subprocess_operations(self):
        """Test detection of subprocess operations."""
        code = """
import os
import subprocess

os.system("ls -la")
subprocess.run(["echo", "hello"])
proc = subprocess.Popen(["cat", "/etc/passwd"])
"""
        constructs = extract_dangerous_constructs(code)
        assert "os.system" in constructs["subprocess_operations"]
        assert "subprocess.run" in constructs["subprocess_operations"]
        assert "subprocess.Popen" in constructs["subprocess_operations"]

    def test_network_operations(self):
        """Test detection of network operations."""
        code = """
import socket

s = socket.socket()
s.connect(("evil.com", 80))
"""
        constructs = extract_dangerous_constructs(code)
        assert "socket.socket" in constructs["network_operations"]
        # Note: connect is a method call on the socket object, not socket.connect
        # This would require more complex AST analysis to track variable assignments

    def test_safe_code(self):
        """Test that safe code has no dangerous constructs."""
        code = """
def add(a, b):
    return a + b

result = add(1, 2)
print(result)
"""
        constructs = extract_dangerous_constructs(code)
        assert not constructs["imports"]
        assert not constructs["eval_exec"]
        assert not constructs["file_operations"]
        assert not constructs["subprocess_operations"]
        assert not constructs["network_operations"]

    def test_invalid_code(self):
        """Test handling of invalid code."""
        code = "this is not valid python {"
        constructs = extract_dangerous_constructs(code)
        # Should return empty constructs on parse failure
        assert not any(constructs.values())


class TestIsCodePotentiallyDangerous:
    """Test dangerous code detection."""

    def test_high_risk_code(self):
        """Test detection of high risk code."""
        code = """
import os
eval("__import__('os').system('rm -rf /')")
"""
        is_dangerous, description = is_code_potentially_dangerous(code, "low")
        assert is_dangerous is True
        assert "Dynamic code execution" in description
        assert "eval" in description

    def test_medium_risk_code(self):
        """Test detection of medium risk code."""
        code = """
with open("/etc/passwd", "r") as f:
    print(f.read())
"""
        is_dangerous_low, _ = is_code_potentially_dangerous(code, "low")
        is_dangerous_high, _ = is_code_potentially_dangerous(code, "high")
        assert is_dangerous_low is True
        assert is_dangerous_high is False

    def test_low_risk_code(self):
        """Test detection of low risk code."""
        code = "import os"
        is_dangerous_low, _ = is_code_potentially_dangerous(code, "low")
        is_dangerous_medium, _ = is_code_potentially_dangerous(code, "medium")
        assert is_dangerous_low is False
        assert is_dangerous_medium is False

    def test_safe_code(self):
        """Test that safe code is not flagged."""
        code = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
"""
        is_dangerous, description = is_code_potentially_dangerous(code, "low")
        assert is_dangerous is False
        assert "No dangerous constructs" in description

    def test_multiple_risks(self):
        """Test code with multiple risk types."""
        code = """
import os
import subprocess

os.system("ls")
subprocess.run(["echo", "hello"])
eval("2 + 2")
open("/tmp/test", "w")
"""
        is_dangerous, description = is_code_potentially_dangerous(code, "low")
        assert is_dangerous is True
        assert "Dynamic code execution" in description
        assert "Subprocess operations" in description
        assert "File operations" in description
        assert "Dangerous imports" in description
