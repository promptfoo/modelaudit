"""Tests for shebang context verification in PyTorchBinaryScanner"""

import pytest

from modelaudit.scanners.pytorch_binary_scanner import PyTorchBinaryScanner


class TestShebangContextVerification:
    """Test suite for shebang context verification logic"""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance for testing"""
        return PyTorchBinaryScanner()

    def test_valid_bash_shebang(self, scanner):
        """Test that valid bash shebang is recognized"""
        data = b"#!/bin/bash\necho 'test'\n"
        assert scanner._verify_shebang_context(data, 0) is True

    def test_valid_sh_shebang(self, scanner):
        """Test that valid sh shebang is recognized"""
        data = b"#!/bin/sh\nls -la\n"
        assert scanner._verify_shebang_context(data, 0) is True

    def test_valid_python_shebang(self, scanner):
        """Test that valid python shebang is recognized"""
        data = b"#!/usr/bin/python\nprint('hello')\n"
        assert scanner._verify_shebang_context(data, 0) is True

    def test_valid_python3_shebang(self, scanner):
        """Test that valid python3 shebang is recognized"""
        data = b"#!/usr/bin/python3\nimport sys\n"
        assert scanner._verify_shebang_context(data, 0) is True

    def test_valid_env_bash_shebang(self, scanner):
        """Test that valid env bash shebang is recognized"""
        data = b"#!/usr/bin/env bash\ncd /tmp\n"
        assert scanner._verify_shebang_context(data, 0) is True

    def test_valid_env_python_shebang(self, scanner):
        """Test that valid env python shebang is recognized"""
        data = b"#!/usr/bin/env python\nprint('test')\n"
        assert scanner._verify_shebang_context(data, 0) is True

    def test_shebang_with_space_after_interpreter(self, scanner):
        """Test shebang with space after interpreter"""
        data = b"#!/bin/bash \necho test\n"
        assert scanner._verify_shebang_context(data, 0) is True

    def test_shebang_with_carriage_return(self, scanner):
        """Test shebang with carriage return (Windows style)"""
        data = b"#!/bin/bash\r\necho test\r\n"
        assert scanner._verify_shebang_context(data, 0) is True

    def test_invalid_shebang_no_interpreter(self, scanner):
        """Test that shebang without valid interpreter is rejected"""
        data = b"#!/random_junk\nsome data\n"
        assert scanner._verify_shebang_context(data, 0) is False

    def test_invalid_shebang_incomplete_path(self, scanner):
        """Test that incomplete interpreter path is rejected"""
        data = b"#!/bin/\ndata\n"
        assert scanner._verify_shebang_context(data, 0) is False

    def test_coincidental_shebang_in_binary_data(self, scanner):
        """Test that coincidental shebang bytes in random data are rejected"""
        # This simulates the OpenVINO false positive case
        data = b"#!/\xfc\x8a\x12\xff\x03"  # #!/ followed by random bytes
        assert scanner._verify_shebang_context(data, 0) is False

    def test_shebang_pattern_mid_chunk(self, scanner):
        """Test shebang verification at non-zero offset in chunk"""
        data = b"random data #!/bin/bash\necho test\n more data"
        assert scanner._verify_shebang_context(data, 12) is True

    def test_shebang_too_short(self, scanner):
        """Test that data too short for complete shebang is rejected"""
        data = b"#!/bin/"  # Too short
        assert scanner._verify_shebang_context(data, 0) is False

    def test_shebang_at_chunk_boundary(self, scanner):
        """Test shebang at end of chunk with insufficient data"""
        data = b"#!/bi"  # Truncated
        assert scanner._verify_shebang_context(data, 0) is False

    def test_multiple_valid_interpreters(self, scanner):
        """Test various valid interpreter paths"""
        interpreters = [
            b"#!/bin/bash",
            b"#!/bin/sh",
            b"#!/bin/zsh",
            b"#!/bin/dash",
            b"#!/usr/bin/python",
            b"#!/usr/bin/python3",
            b"#!/usr/bin/perl",
            b"#!/usr/bin/ruby",
            b"#!/usr/bin/env",
        ]

        for interp in interpreters:
            data = interp + b"\ntest\n"
            assert scanner._verify_shebang_context(data, 0) is True, f"Failed for {interp!r}"

    def test_env_with_interpreter_argument(self, scanner):
        """Test env shebang with interpreter as argument"""
        data = b"#!/usr/bin/env python3\nimport os\n"
        assert scanner._verify_shebang_context(data, 0) is True

    def test_shebang_without_newline_at_end(self, scanner):
        """Test shebang recognition when followed by command without newline"""
        data = b"#!/bin/bash\ncommand"
        assert scanner._verify_shebang_context(data, 0) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
