"""Tests for weak hash algorithm detection (Requirement 28: Hash Collisions or Weak Hashes)."""

import json

import pytest

from modelaudit.scanners.base import CheckStatus
from modelaudit.scanners.manifest_scanner import HASH_INTEGRITY_KEYS, HEX_PATTERN, ManifestScanner


class TestHexPattern:
    """Test the HEX_PATTERN regex."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("d41d8cd98f00b204e9800998ecf8427e", True),  # MD5
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", True),  # SHA1
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", True),  # SHA256
            ("ABCDEF0123456789", True),  # uppercase
            ("abcdef0123456789", True),  # lowercase
            ("AbCdEf0123456789", True),  # mixed case
            ("not-a-hex-string", False),
            ("hello world", False),
            ("12345g6789", False),  # 'g' is not hex
            ("", False),
        ],
    )
    def test_hex_pattern(self, value, expected):
        """Test that HEX_PATTERN correctly identifies hex strings."""
        result = bool(HEX_PATTERN.match(value))
        assert result == expected


class TestHashIntegrityKeys:
    """Test that all expected hash-related keys are defined."""

    def test_common_keys_included(self):
        """Verify common hash/checksum keys are in the list."""
        expected_keys = ["hash", "checksum", "md5", "sha1", "sha256", "digest"]
        for key in expected_keys:
            assert key in HASH_INTEGRITY_KEYS, f"Expected '{key}' in HASH_INTEGRITY_KEYS"


class TestWeakHashDetection:
    """Test weak hash detection in ManifestScanner."""

    @pytest.fixture
    def scanner(self):
        """Create a ManifestScanner instance."""
        return ManifestScanner()

    def test_md5_hash_detected(self, scanner, tmp_path):
        """Test that MD5 hashes are detected as weak."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "checksum": "d41d8cd98f00b204e9800998ecf8427e",  # MD5 (32 chars)
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        assert len(weak_hash_checks) == 1
        assert weak_hash_checks[0].status == CheckStatus.FAILED
        assert weak_hash_checks[0].severity.name == "WARNING"
        assert weak_hash_checks[0].details["algorithm"] == "MD5"

    def test_sha1_hash_detected(self, scanner, tmp_path):
        """Test that SHA1 hashes are detected as weak."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "file_hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 (40 chars)
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        assert len(weak_hash_checks) == 1
        assert weak_hash_checks[0].status == CheckStatus.FAILED
        assert weak_hash_checks[0].severity.name == "WARNING"
        assert weak_hash_checks[0].details["algorithm"] == "SHA1"

    def test_sha256_hash_not_flagged_as_weak(self, scanner, tmp_path):
        """Test that SHA256 hashes are NOT flagged as weak."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 (64 chars)
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        # Should have one check that passed (strong hash)
        assert len(weak_hash_checks) == 1
        assert weak_hash_checks[0].status == CheckStatus.PASSED
        assert weak_hash_checks[0].details["algorithm"] == "SHA256"

    def test_sha512_hash_not_flagged_as_weak(self, scanner, tmp_path):
        """Test that SHA512 hashes are NOT flagged as weak."""
        # SHA512 is 128 hex characters
        sha512_hash = (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "digest": sha512_hash,
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        assert len(weak_hash_checks) == 1
        assert weak_hash_checks[0].status == CheckStatus.PASSED
        assert weak_hash_checks[0].details["algorithm"] == "SHA512"

    def test_non_hash_key_not_checked(self, scanner, tmp_path):
        """Test that non-hash keys with 32-char values are NOT flagged."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            # This is 32 chars but 'id' is not a hash key
            "id": "d41d8cd98f00b204e9800998ecf8427e",
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        assert len(weak_hash_checks) == 0

    def test_non_hex_value_not_checked(self, scanner, tmp_path):
        """Test that non-hex values in hash keys are not flagged."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "checksum": "this-is-not-a-valid-hex-string!",
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        assert len(weak_hash_checks) == 0

    def test_nested_hash_detection(self, scanner, tmp_path):
        """Test that weak hashes in nested structures are detected."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "files": {
                "weights": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                }
            },
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        assert len(weak_hash_checks) == 1
        assert weak_hash_checks[0].status == CheckStatus.FAILED
        assert "files.weights.md5" in weak_hash_checks[0].details["key"]

    def test_multiple_weak_hashes_detected(self, scanner, tmp_path):
        """Test that multiple weak hashes in same config are all detected."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [
            c for c in result.checks if c.name == "Weak Hash Detection" and c.status == CheckStatus.FAILED
        ]
        assert len(weak_hash_checks) == 2

        algorithms = {c.details["algorithm"] for c in weak_hash_checks}
        assert algorithms == {"MD5", "SHA1"}

    def test_hash_in_array_detected(self, scanner, tmp_path):
        """Test that weak hashes in arrays are detected."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "checksums": [
                {"file": "model.bin", "md5": "d41d8cd98f00b204e9800998ecf8427e"},
            ],
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [
            c for c in result.checks if c.name == "Weak Hash Detection" and c.status == CheckStatus.FAILED
        ]
        assert len(weak_hash_checks) == 1

    def test_why_message_includes_cwe(self, scanner, tmp_path):
        """Test that the 'why' message includes CWE reference."""
        config_file = tmp_path / "config.json"
        config_content = {
            "checksum": "d41d8cd98f00b204e9800998ecf8427e",
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [
            c for c in result.checks if c.name == "Weak Hash Detection" and c.status == CheckStatus.FAILED
        ]
        assert len(weak_hash_checks) == 1
        assert "CWE-328" in weak_hash_checks[0].why

    def test_various_hash_key_names(self, scanner, tmp_path):
        """Test detection with various hash key naming conventions."""
        test_cases = [
            ("hash", "d41d8cd98f00b204e9800998ecf8427e"),
            ("checksum", "d41d8cd98f00b204e9800998ecf8427e"),
            ("digest", "d41d8cd98f00b204e9800998ecf8427e"),
            ("file_hash", "d41d8cd98f00b204e9800998ecf8427e"),
            ("model_hash", "d41d8cd98f00b204e9800998ecf8427e"),
            ("weight_hash", "d41d8cd98f00b204e9800998ecf8427e"),
            ("integrity", "d41d8cd98f00b204e9800998ecf8427e"),
        ]

        for key_name, hash_value in test_cases:
            config_file = tmp_path / f"config_{key_name}.json"
            config_content = {key_name: hash_value}
            config_file.write_text(json.dumps(config_content))

            result = scanner.scan(str(config_file))

            weak_hash_checks = [
                c for c in result.checks if c.name == "Weak Hash Detection" and c.status == CheckStatus.FAILED
            ]
            assert len(weak_hash_checks) == 1, f"Expected weak hash detection for key '{key_name}'"

    def test_mixed_strong_and_weak_hashes(self, scanner, tmp_path):
        """Test config with both strong and weak hashes."""
        config_file = tmp_path / "config.json"
        config_content = {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",  # Weak
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Strong
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        all_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        weak_checks = [c for c in all_hash_checks if c.status == CheckStatus.FAILED]
        strong_checks = [c for c in all_hash_checks if c.status == CheckStatus.PASSED]

        assert len(weak_checks) == 1
        assert weak_checks[0].details["algorithm"] == "MD5"

        assert len(strong_checks) == 1
        assert strong_checks[0].details["algorithm"] == "SHA256"


class TestEdgeCases:
    """Test edge cases for weak hash detection."""

    @pytest.fixture
    def scanner(self):
        return ManifestScanner()

    def test_empty_config(self, scanner, tmp_path):
        """Test that empty configs don't cause errors."""
        config_file = tmp_path / "config.json"
        config_file.write_text("{}")

        result = scanner.scan(str(config_file))

        weak_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        assert len(weak_hash_checks) == 0

    def test_config_with_only_non_string_values(self, scanner, tmp_path):
        """Test config with numeric and boolean values."""
        config_file = tmp_path / "config.json"
        config_content = {
            "checksum": 12345,  # Not a string
            "hash": True,  # Not a string
            "digest": None,  # Not a string (will be serialized as null)
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [c for c in result.checks if c.name == "Weak Hash Detection"]
        assert len(weak_hash_checks) == 0

    def test_uppercase_hex_hash(self, scanner, tmp_path):
        """Test that uppercase hex hashes are detected."""
        config_file = tmp_path / "config.json"
        config_content = {
            "checksum": "D41D8CD98F00B204E9800998ECF8427E",  # MD5 uppercase
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        weak_hash_checks = [
            c for c in result.checks if c.name == "Weak Hash Detection" and c.status == CheckStatus.FAILED
        ]
        assert len(weak_hash_checks) == 1
        assert weak_hash_checks[0].details["algorithm"] == "MD5"
