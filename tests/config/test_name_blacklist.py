"""Tests for config name blacklist module."""

from modelaudit.config.name_blacklist import BLACKLIST_PATTERNS, check_model_name_policies


class TestBlacklistPatterns:
    """Tests for BLACKLIST_PATTERNS constant."""

    def test_blacklist_patterns_is_list(self):
        """Test that BLACKLIST_PATTERNS is a list."""
        assert isinstance(BLACKLIST_PATTERNS, list)


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

    def test_case_insensitive_matching(self):
        """Test that matching is case insensitive."""
        blocked, _reason = check_model_name_policies("MALICIOUS-MODEL")
        assert blocked is True

    def test_additional_patterns(self):
        """Test with additional custom patterns."""
        blocked, reason = check_model_name_policies("dangerous-model", ["dangerous"])
        assert blocked is True
        assert "dangerous" in reason.lower()

    def test_none_additional_patterns(self):
        """Test with None additional patterns."""
        blocked, _reason = check_model_name_policies("bert-base", None)
        assert blocked is False
