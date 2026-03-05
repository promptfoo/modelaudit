"""Tests for scanner rule mapping helpers."""

from modelaudit.rules import RuleRegistry
from modelaudit.scanners.rule_mapper import (
    get_embedded_code_rule_code,
    get_generic_rule_code,
    get_network_rule_code,
    get_secret_rule_code,
)


def test_rule_mapper_returns_registered_codes() -> None:
    """Mapped rule codes should always exist in RuleRegistry."""
    sample_codes = [
        get_secret_rule_code("OpenAI API Key"),
        get_embedded_code_rule_code("TorchScript jit payload"),
        get_network_rule_code("explicit_network_pattern beacon"),
        get_generic_rule_code("URL detected in model: https://evil.example"),
    ]

    for code in sample_codes:
        assert code is not None
        assert RuleRegistry.get_rule(code) is not None


def test_generic_rule_prefers_network_codes_for_urls() -> None:
    """URL-like network messages should map to network rules, not encoding rules."""
    assert get_generic_rule_code("Network communication pattern: https://evil.example") == "S309"


def test_network_rule_mapping_prioritizes_exfiltration_patterns() -> None:
    """Explicit exfil/C2 indicators should map to S310."""
    assert get_network_rule_code("blacklisted_domain c2.example beacon") == "S310"
