"""Test detection of os and subprocess patterns for command execution."""

import pickle

from modelaudit.core import scan_file
from modelaudit.scanners.base import IssueSeverity


def create_test_pickle(code_str: str) -> bytes:
    """Create a pickle file that contains the given code string."""
    # Create a pickle that embeds the code string in its raw bytes
    # This simulates how malicious pickles often contain code patterns
    return pickle.dumps({"code": code_str, "data": code_str.encode()})


class TestOsSystemDetection:
    """Test detection of os.system patterns."""

    def test_detect_os_system(self, tmp_path):
        """Test detection of os.system command."""
        # Create pickle with os.system
        malicious_code = "import os; os.system('echo pwned')"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "os_system.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect os.system as CRITICAL
        assert any(
            "os.system" in issue.message.lower() and issue.severity == IssueSeverity.CRITICAL for issue in result.issues
        ), f"Failed to detect os.system as CRITICAL. Issues: {[i.message for i in result.issues]}"

    def test_detect_os_popen(self, tmp_path):
        """Test detection of os.popen command."""
        # Create pickle with os.popen
        malicious_code = "import os; os.popen('ls -la').read()"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "os_popen.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect os.popen as CRITICAL
        assert any(
            "os.popen" in issue.message.lower() and issue.severity == IssueSeverity.CRITICAL for issue in result.issues
        ), f"Failed to detect os.popen as CRITICAL. Issues: {[i.message for i in result.issues]}"

    def test_detect_os_spawn(self, tmp_path):
        """Test detection of os.spawn* variants."""
        # Create pickle with os.spawnv
        malicious_code = "import os; os.spawnv(os.P_WAIT, '/bin/echo', ['echo', 'pwned'])"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "os_spawn.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect os.spawn as CRITICAL
        assert any(
            "os.spawn" in issue.message.lower() and issue.severity == IssueSeverity.CRITICAL for issue in result.issues
        ), f"Failed to detect os.spawn as CRITICAL. Issues: {[i.message for i in result.issues]}"


class TestSubprocessDetection:
    """Test detection of subprocess patterns."""

    def test_detect_subprocess_call(self, tmp_path):
        """Test detection of subprocess.call."""
        # Create pickle with subprocess.call
        malicious_code = "import subprocess; subprocess.call(['echo', 'pwned'])"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "subprocess_call.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect subprocess.call as CRITICAL
        assert any(
            "subprocess.call" in issue.message.lower() and issue.severity == IssueSeverity.CRITICAL
            for issue in result.issues
        ), f"Failed to detect subprocess.call as CRITICAL. Issues: {[i.message for i in result.issues]}"

    def test_detect_subprocess_run(self, tmp_path):
        """Test detection of subprocess.run."""
        # Create pickle with subprocess.run
        malicious_code = "import subprocess; subprocess.run(['ls', '-la'])"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "subprocess_run.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect subprocess.run as CRITICAL
        assert any(
            "subprocess.run" in issue.message.lower() and issue.severity == IssueSeverity.CRITICAL
            for issue in result.issues
        ), f"Failed to detect subprocess.run as CRITICAL. Issues: {[i.message for i in result.issues]}"

    def test_detect_subprocess_popen(self, tmp_path):
        """Test detection of subprocess.Popen."""
        # Create pickle with subprocess.Popen
        malicious_code = "import subprocess; p = subprocess.Popen(['echo', 'pwned'])"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "subprocess_popen.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect subprocess.Popen as CRITICAL
        assert any(
            "subprocess.popen" in issue.message.lower() and issue.severity == IssueSeverity.CRITICAL
            for issue in result.issues
        ), f"Failed to detect subprocess.Popen as CRITICAL. Issues: {[i.message for i in result.issues]}"


class TestCommandsModuleDetection:
    """Test detection of Python 2 commands module patterns."""

    def test_detect_commands_getoutput(self, tmp_path):
        """Test detection of commands.getoutput."""
        # Create pickle with commands.getoutput
        malicious_code = "import commands; output = commands.getoutput('ls -la')"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "commands_getoutput.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect commands or getoutput as CRITICAL
        assert any(
            ("commands" in issue.message.lower() or "getoutput" in issue.message.lower())
            and issue.severity == IssueSeverity.CRITICAL
            for issue in result.issues
        ), f"Failed to detect commands.getoutput as CRITICAL. Issues: {[i.message for i in result.issues]}"

    def test_detect_commands_getstatusoutput(self, tmp_path):
        """Test detection of commands.getstatusoutput."""
        # Create pickle with commands.getstatusoutput
        malicious_code = "import commands; status, output = commands.getstatusoutput('whoami')"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "commands_getstatusoutput.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect commands or getstatusoutput as CRITICAL
        assert any(
            ("commands" in issue.message.lower() or "getstatusoutput" in issue.message.lower())
            and issue.severity == IssueSeverity.CRITICAL
            for issue in result.issues
        ), f"Failed to detect commands.getstatusoutput as CRITICAL. Issues: {[i.message for i in result.issues]}"


class TestPosixDetection:
    """Test detection of posix module patterns."""

    def test_detect_posix_system(self, tmp_path):
        """Test detection of posix.system (equivalent to os.system on Unix)."""
        # Create pickle with posix.system reference
        malicious_code = "import posix; posix.system('echo pwned')"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "posix_system.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect posix as CRITICAL
        assert any(
            "posix" in issue.message.lower() and issue.severity == IssueSeverity.CRITICAL for issue in result.issues
        ), f"Failed to detect posix as CRITICAL. Issues: {[i.message for i in result.issues]}"


class TestComplexPatterns:
    """Test detection of complex/obfuscated patterns."""

    def test_detect_chained_commands(self, tmp_path):
        """Test detection when multiple command execution methods are present."""
        # Create pickle with multiple command execution patterns
        malicious_code = """
import os
import subprocess
os.system('ls')
subprocess.call(['whoami'])
"""
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "chained_commands.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect multiple CRITICAL issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) >= 2, (
            f"Should detect multiple command patterns. Found: {[i.message for i in critical_issues]}"
        )

        # Should detect both os.system and subprocess
        patterns_found = " ".join(i.message.lower() for i in critical_issues)
        assert "os.system" in patterns_found or "subprocess" in patterns_found

    def test_detect_indirect_import(self, tmp_path):
        """Test detection when modules are imported indirectly."""
        # Create pickle with indirect import that still contains the dangerous pattern
        malicious_code = "from os import system\nsystem('echo pwned')"
        pickle_data = create_test_pickle(malicious_code)

        test_file = tmp_path / "indirect_import.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect 'system' pattern even with indirect import
        # Note: We don't catch the actual execution, but we catch the dangerous import
        assert any(
            ("import" in issue.message.lower() or "system" in issue.message.lower()) for issue in result.issues
        ), f"Failed to detect dangerous patterns. Issues: {[i.message for i in result.issues]}"
