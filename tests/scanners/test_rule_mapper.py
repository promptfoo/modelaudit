"""Tests for scanner rule mapping helpers."""

import pytest

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


def test_embedded_code_rule_maps_dynamic_module_execution_before_executable_text() -> None:
    """Dynamic module execution contains an "exe" prefix but belongs to runpy."""
    assert get_embedded_code_rule_code("Dynamic module execution detected") == "S108"
    assert get_embedded_code_rule_code("TorchScript Dynamic module execution detected") == "S108"


@pytest.mark.parametrize(
    ("message", "expected_rule_code"),
    [
        ("Web browser launch detected", "S109"),
        ("Native library loading detected", "S110"),
        ("Custom ONNX operator detected", "S1111"),
    ],
)
def test_embedded_code_rule_maps_specific_finding_types(message: str, expected_rule_code: str) -> None:
    assert get_embedded_code_rule_code(message) == expected_rule_code


@pytest.mark.parametrize(
    ("message", "expected_rule_code"),
    [
        ("Type mismatch between payload and extension", "S901"),
        ("ObFuScAtEd payload blob", "S604"),
        ("OpenAI API Key exposed in artifact", "S701"),
        ("TorchScript JIT payload embedded in model", "S510"),
        ("Unsafe PyTorch torch.load usage detected", "S1101"),
    ],
)
def test_generic_rule_covers_non_network_dispatch_categories(message: str, expected_rule_code: str) -> None:
    """Generic dispatch should reach every non-network mapper in rule order."""
    assert get_generic_rule_code(message) == expected_rule_code


def test_network_rule_mapping_prioritizes_exfiltration_patterns() -> None:
    """Explicit exfil/C2 indicators should map to S310."""
    assert get_network_rule_code("blacklisted_domain c2.example beacon") == "S310"


def test_generic_rule_does_not_map_protocol_version_to_persistent_id() -> None:
    """Generic protocol-version text should not be classified as persistent ID use."""
    assert get_generic_rule_code("Valid pickle protocol version 4") is None


@pytest.mark.parametrize(
    "message",
    [
        "Stack depth exceeded while scanning pickle stream",
        "Scan timed out after opcode count threshold",
    ],
)
def test_generic_rule_ignores_internal_operational_messages(message: str) -> None:
    """Operational timeout/depth notices should not surface as rule violations."""
    assert get_generic_rule_code(message) is None


def test_generic_rule_maps_unknown_opcodes_to_internal_fallback_rule() -> None:
    """Unknown opcode diagnostics should map to the generic internal fallback rule."""
    assert get_generic_rule_code("Unknown opcode FOO encountered while parsing") == "S999"
