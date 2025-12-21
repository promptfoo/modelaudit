"""Tests for name policy blacklist module."""


from modelaudit.name_policies.blacklist import BLACKLIST_PATTERNS, check_model_name_policies


class TestBlacklistPatterns:
    """Tests for BLACKLIST_PATTERNS constant."""

    def test_blacklist_patterns_is_list(self):
        """Test that BLACKLIST_PATTERNS is a list."""
        assert isinstance(BLACKLIST_PATTERNS, list)

    def test_blacklist_patterns_has_defaults(self):
        """Test that BLACKLIST_PATTERNS has default patterns."""
        assert "malicious" in BLACKLIST_PATTERNS
        assert "unsafe" in BLACKLIST_PATTERNS


class TestCheckModelNamePolicies:
    """Tests for check_model_name_policies function."""

    def test_clean_name_passes(self):
        """Test that a clean model name passes."""
        blocked, reason = check_model_name_policies("bert-base-uncased")
        assert blocked is False
        assert reason == ""

    def test_malicious_name_blocked(self):
        """Test that a name containing 'malicious' is blocked."""
        blocked, reason = check_model_name_policies("malicious-model")
        assert blocked is True
        assert "malicious" in reason.lower()

    def test_unsafe_name_blocked(self):
        """Test that a name containing 'unsafe' is blocked."""
        blocked, reason = check_model_name_policies("unsafe-loader")
        assert blocked is True
        assert "unsafe" in reason.lower()

    def test_case_insensitive_matching(self):
        """Test that matching is case insensitive."""
        blocked, _reason = check_model_name_policies("MALICIOUS-MODEL")
        assert blocked is True

        blocked, _reason = check_model_name_policies("Unsafe-Model")
        assert blocked is True

    def test_partial_match(self):
        """Test that partial matches work."""
        blocked, _reason = check_model_name_policies("thismaliciousmodel")
        assert blocked is True

    def test_additional_patterns(self):
        """Test with additional custom patterns."""
        blocked, reason = check_model_name_policies("dangerous-model", ["dangerous"])
        assert blocked is True
        assert "dangerous" in reason.lower()

    def test_additional_patterns_no_match(self):
        """Test with additional patterns that don't match."""
        blocked, reason = check_model_name_policies("safe-model", ["dangerous"])
        assert blocked is False
        assert reason == ""

    def test_empty_additional_patterns(self):
        """Test with empty additional patterns list."""
        blocked, _reason = check_model_name_policies("bert-base", [])
        assert blocked is False

    def test_none_additional_patterns(self):
        """Test with None additional patterns."""
        blocked, _reason = check_model_name_policies("bert-base", None)
        assert blocked is False

    def test_combined_patterns(self):
        """Test that both default and additional patterns are checked."""
        # Should match default pattern
        blocked, _reason = check_model_name_policies("malicious-thing", ["custom"])
        assert blocked is True

        # Should match additional pattern
        blocked, _reason = check_model_name_policies("custom-thing", ["custom"])
        assert blocked is True

    def test_empty_model_name(self):
        """Test with empty model name."""
        blocked, reason = check_model_name_policies("")
        assert blocked is False
        assert reason == ""

    def test_special_characters_in_name(self):
        """Test model names with special characters."""
        blocked, _reason = check_model_name_policies("model@v1.0-beta")
        assert blocked is False

    def test_numeric_model_name(self):
        """Test model names with numbers."""
        blocked, _reason = check_model_name_policies("gpt-4-turbo-128k")
        assert blocked is False
