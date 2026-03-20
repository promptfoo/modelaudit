"""Tests for the ModelAudit rule system."""

import tempfile
from pathlib import Path

import pytest

from modelaudit.cache.trusted_config_store import TrustedConfigStore
from modelaudit.config import ModelAuditConfig, reset_config, set_config
from modelaudit.config.local_config import find_local_config_for_paths
from modelaudit.rules import RuleRegistry, Severity
from modelaudit.scanners.base import Issue, IssueSeverity, ScanResult


class TestRuleRegistry:
    """Test the rule registry functionality."""

    def test_initialize(self):
        """Test that rules are initialized properly."""
        RuleRegistry.initialize()
        assert len(RuleRegistry.get_all_rules()) == 110  # Current count via public API

    def test_get_rule(self):
        """Test getting a specific rule."""
        rule = RuleRegistry.get_rule("S101")
        assert rule is not None
        assert rule.code == "S101"
        assert rule.name == "os module import"
        assert rule.default_severity == Severity.CRITICAL

    def test_get_nonexistent_rule(self):
        """Test getting a rule that doesn't exist."""
        rule = RuleRegistry.get_rule("S9999")
        assert rule is None

    def test_find_matching_rule(self):
        """Test finding rules by message patterns."""
        # Test exact pattern match
        match = RuleRegistry.find_matching_rule("import os")
        assert match is not None
        code, _rule = match
        assert code == "S101"

        # Test another pattern
        match = RuleRegistry.find_matching_rule("import sys")
        assert match is not None
        code, _rule = match
        assert code == "S102"

        # Test no match
        match = RuleRegistry.find_matching_rule("this should not match anything")
        assert match is None

    def test_get_all_rules(self):
        """Test getting all rules."""
        rules = RuleRegistry.get_all_rules()
        assert len(rules) == 110
        assert "S101" in rules
        assert "S1110" in rules

    def test_get_rules_by_range(self):
        """Test getting rules by numeric range."""
        # Get code execution rules (S100-S199)
        rules = RuleRegistry.get_rules_by_range(100, 199)
        assert all(100 <= int(code[1:]) <= 199 for code in rules)
        assert "S101" in rules
        assert "S110" in rules
        assert "S201" not in rules  # Pickle rule, not in range

        # Get pickle rules (S200-S299)
        rules = RuleRegistry.get_rules_by_range(200, 299)
        assert all(200 <= int(code[1:]) <= 299 for code in rules)
        assert "S201" in rules
        assert "S101" not in rules


class TestConfiguration:
    """Test configuration loading and management."""

    def test_default_config(self):
        """Test default configuration with no file."""
        config = ModelAuditConfig()
        assert len(config.suppress) == 0
        assert len(config.severity) == 0
        assert len(config.ignore) == 0

    def test_load_from_toml(self):
        """Test loading configuration from TOML file."""
        config_content = """
suppress = ["S710", "S801"]

[severity]
S301 = "HIGH"
S701 = "CRITICAL"

[ignore]
"tests/**" = ["S101", "S102"]
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(config_content)
            config_path = Path(f.name)

        try:
            config = ModelAuditConfig.load(config_path)
            assert "S710" in config.suppress
            assert "S801" in config.suppress
            assert config.severity["S301"] == Severity.HIGH
            assert config.severity["S701"] == Severity.CRITICAL
            assert "tests/**" in config.ignore
            assert "S101" in config.ignore["tests/**"]
        finally:
            config_path.unlink()

    def test_load_from_pyproject(self, tmp_path: Path) -> None:
        """Explicit pyproject paths should load the [tool.modelaudit] section."""
        config_path = tmp_path / "pyproject.toml"
        config_path.write_text(
            """
[tool.modelaudit]
suppress = ["S710"]

[tool.modelaudit.severity]
S301 = "HIGH"
""".strip()
            + "\n"
        )

        config = ModelAuditConfig.load(config_path)

        assert config.suppress == {"S710"}
        assert config.severity["S301"] == Severity.HIGH

    def test_is_suppressed(self):
        """Test rule suppression checking."""
        config = ModelAuditConfig()
        config.suppress = {"S710", "S801"}

        assert config.is_suppressed("S710")
        assert config.is_suppressed("S801")
        assert not config.is_suppressed("S101")

    def test_is_suppressed_with_file_pattern(self):
        """Test file-specific suppression."""
        config = ModelAuditConfig()
        config.ignore = {
            "tests/*.py": ["S101", "S102"],
            "*.pkl": ["S201"],
        }

        assert config.is_suppressed("S101", "tests/test_foo.py")
        assert config.is_suppressed("S201", "model.pkl")
        assert not config.is_suppressed("S101", "src/main.py")

    def test_get_severity(self):
        """Test severity override retrieval."""
        config = ModelAuditConfig()
        config.severity = {
            "S301": Severity.HIGH,
            "S701": Severity.CRITICAL,
        }

        assert config.get_severity("S301", Severity.MEDIUM) == Severity.HIGH
        assert config.get_severity("S701", Severity.MEDIUM) == Severity.CRITICAL
        assert config.get_severity("S999", Severity.LOW) == Severity.LOW  # No override

    def test_from_cli_args(self):
        """Test creating config from CLI arguments."""
        config = ModelAuditConfig.from_cli_args(
            suppress=["S710", "S801"], severity={"S301": "HIGH", "S701": "CRITICAL"}
        )

        assert "S710" in config.suppress
        assert "S801" in config.suppress
        assert config.severity["S301"] == Severity.HIGH
        assert config.severity["S701"] == Severity.CRITICAL

    def test_from_cli_args_rejects_unknown_rule_codes(self):
        """Unknown CLI rule codes should fail fast."""
        with pytest.raises(ValueError, match="Unknown rule code"):
            ModelAuditConfig.from_cli_args(suppress=["S9999"])

        with pytest.raises(ValueError, match="Unknown rule code"):
            ModelAuditConfig.from_cli_args(severity={"S9999": "CRITICAL"})

    def test_from_cli_args_rejects_invalid_severity(self):
        """Invalid CLI severity values should fail fast."""
        with pytest.raises(ValueError, match="Invalid severity"):
            ModelAuditConfig.from_cli_args(severity={"S301": "SEVERE"})

    def test_from_cli_args_uses_provided_base_config(self) -> None:
        """CLI overrides should merge onto an explicitly supplied base config."""
        base_config = ModelAuditConfig()
        base_config.suppress = {"S710"}

        config = ModelAuditConfig.from_cli_args(suppress=["S801"], base_config=base_config)

        assert config.suppress == {"S710", "S801"}
        assert base_config.suppress == {"S710"}

    def test_ignore_range_expansion(self):
        """Test that ignore ranges expand correctly."""
        config = ModelAuditConfig()
        config._parse_config({"ignore": {"tests/**": ["S200-S202", "S999"]}})

        assert "tests/**" in config.ignore
        assert set(config.ignore["tests/**"]) == {"S201", "S202", "S999"}
        assert config.is_suppressed("S201", "tests/example.py")
        assert not config.is_suppressed("S203", "tests/example.py")

    def test_parse_config_filters_unknown_codes(self):
        """Unknown config rule codes should be ignored instead of persisted."""
        config = ModelAuditConfig()
        config._parse_config(
            {
                "suppress": ["S710", "S700-S702", "s9999"],
                "severity": {"s301": "HIGH", "S302": "INVALID", "S9999": "CRITICAL"},
                "ignore": {"tests/**": ["S200-S202", "S9999", "all"]},
            }
        )

        assert config.suppress == {"S701", "S702", "S710"}
        assert config.severity == {"S301": Severity.HIGH}
        assert set(config.ignore["tests/**"]) == {"S201", "S202", "ALL"}


def test_load_does_not_auto_discover_local_config_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Local config files should not be auto-loaded unless explicitly enabled."""
    (tmp_path / ".modelaudit.toml").write_text('suppress = ["S710"]\n')
    monkeypatch.chdir(tmp_path)

    config = ModelAuditConfig.load()

    assert "S710" not in config.suppress


def test_load_can_discover_local_config_when_opted_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Local config discovery remains available for explicit trusted flows."""
    (tmp_path / ".modelaudit.toml").write_text('suppress = ["S710"]\n')
    monkeypatch.chdir(tmp_path)

    config = ModelAuditConfig.load(discover_local=True)

    assert "S710" in config.suppress


def test_find_local_config_for_paths_uses_shared_ancestor(tmp_path: Path) -> None:
    """All scanned paths under the same config root should resolve one candidate."""
    root = tmp_path / "repo"
    nested = root / "models" / "nested"
    sibling = root / "models" / "other"
    nested.mkdir(parents=True)
    sibling.mkdir(parents=True)
    (root / ".modelaudit.toml").write_text('suppress = ["S710"]\n')
    first_file = nested / "model.pkl"
    second_file = sibling / "model.pkl"
    first_file.write_bytes(b"test")
    second_file.write_bytes(b"other")

    candidate = find_local_config_for_paths([str(first_file), str(second_file)])

    assert candidate is not None
    assert candidate.config_dir == root
    assert candidate.config_path == root / ".modelaudit.toml"


def test_find_local_config_for_paths_returns_none_for_mixed_roots(tmp_path: Path) -> None:
    """Mixed local config roots should not auto-resolve to any one candidate."""
    repo_one = tmp_path / "repo-one"
    repo_two = tmp_path / "repo-two"
    (repo_one / "models").mkdir(parents=True)
    (repo_two / "models").mkdir(parents=True)
    (repo_one / ".modelaudit.toml").write_text('suppress = ["S710"]\n')
    (repo_two / ".modelaudit.toml").write_text('suppress = ["S801"]\n')
    first = repo_one / "models" / "model-one.pkl"
    second = repo_two / "models" / "model-two.pkl"
    first.write_bytes(b"one")
    second.write_bytes(b"two")

    candidate = find_local_config_for_paths([str(first), str(second)])

    assert candidate is None


def test_trusted_config_store_invalidates_when_config_changes(tmp_path: Path) -> None:
    """Changing a trusted config should require trust to be re-established."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    config_path = repo_root / ".modelaudit.toml"
    config_path.write_text('suppress = ["S710"]\n')
    store = TrustedConfigStore(tmp_path / "cache" / "trusted_local_configs.json")

    candidate = find_local_config_for_paths([str(config_path)])
    assert candidate is not None

    store.trust(candidate)
    assert store.is_trusted(candidate)

    config_path.write_text('suppress = ["S801"]\n')

    assert not store.is_trusted(candidate)


def test_trusted_config_store_rejects_broken_symlink_ancestor(tmp_path: Path, requires_symlinks: None) -> None:
    """Trust records should not be written through broken symlink ancestors."""
    cache_root = tmp_path / "redirected-cache"
    cache_root.symlink_to(tmp_path / "missing-cache", target_is_directory=True)

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    config_path = repo_root / ".modelaudit.toml"
    config_path.write_text('suppress = ["S710"]\n')
    candidate = find_local_config_for_paths([str(config_path)])

    assert candidate is not None

    store = TrustedConfigStore(cache_root / "trusted_local_configs.json")
    store.trust(candidate)

    assert not store.store_path.exists()


class TestScanResultIntegration:
    """Test integration with ScanResult class."""

    def setup_method(self):
        """Reset config before each test."""
        reset_config()

    def test_add_issue_with_auto_detection(self):
        """Test that issues auto-detect rule codes."""
        result = ScanResult("test_scanner")
        result.add_issue("import os", severity=IssueSeverity.CRITICAL)

        assert len(result.issues) == 1
        assert result.issues[0].rule_code == "S101"
        assert result.issues[0].message == "import os"

    def test_add_issue_with_explicit_rule(self):
        """Test adding issue with explicit rule code."""
        result = ScanResult("test_scanner")
        result.add_issue("Custom message", severity=IssueSeverity.WARNING, rule_code="S301")

        assert len(result.issues) == 1
        assert result.issues[0].rule_code == "S301"

    def test_add_issue_with_suppression(self):
        """Test that suppressed rules are not added."""
        config = ModelAuditConfig()
        config.suppress = {"S710"}
        set_config(config)

        result = ScanResult("test_scanner")
        result.add_issue("entropy high", severity=IssueSeverity.INFO)

        # Should be suppressed (S710 matches entropy patterns)
        assert len(result.issues) == 0

    def test_add_issue_with_severity_override(self):
        """Test that severity overrides work."""
        config = ModelAuditConfig()
        config.severity = {"S301": Severity.CRITICAL}
        set_config(config)

        result = ScanResult("test_scanner")
        result.add_issue("import socket", severity=IssueSeverity.WARNING)

        assert len(result.issues) == 1
        # Should be upgraded to CRITICAL
        assert result.issues[0].severity == IssueSeverity.CRITICAL

    def test_add_check_with_rule_detection(self):
        """Test that checks also detect rules."""
        result = ScanResult("test_scanner")
        result.add_check(
            name="Import Check", passed=False, message="import subprocess", severity=IssueSeverity.CRITICAL
        )

        assert len(result.issues) == 1
        assert result.issues[0].rule_code == "S103"

    def test_issue_string_representation(self):
        """Test that issues display with rule codes."""
        issue = Issue(
            message="import os",
            severity=IssueSeverity.CRITICAL,
            rule_code="S101",
            location=None,
            details={},
            why=None,
            type=None,
        )

        issue_str = str(issue)
        assert "[S101]" in issue_str
        assert "CRITICAL" in issue_str
        assert "import os" in issue_str


class TestRulePatterns:
    """Test that rule patterns match expected messages."""

    def test_code_execution_patterns(self):
        """Test S100-S199 patterns."""
        test_cases = [
            ("import os", "S101"),
            ("from os import system", "S101"),
            ("import sys", "S102"),
            ("import subprocess", "S103"),
            ("eval(code)", "S104"),
            ("exec(code)", "S104"),
            ("compile(source)", "S105"),
            ("__import__('os')", "S101"),  # Matches S101 pattern first
            ("import importlib", "S107"),
            ("import runpy", "S108"),
            ("import webbrowser", "S109"),
            ("import ctypes", "S110"),
        ]

        for message, expected_code in test_cases:
            match = RuleRegistry.find_matching_rule(message)
            assert match is not None, f"No match for '{message}'"
            code, _ = match
            assert code == expected_code, f"Expected {expected_code} for '{message}', got {code}"

    def test_pickle_patterns(self):
        """Test S200-S299 patterns."""
        test_cases = [
            ("pickle opcode REDUCE detected", "S201"),
            ("dangerous INST opcode", "S202"),
            ("pickle OBJ found", "S203"),
            ("NEWOBJ opcode", "S203"),  # Matches OBJ pattern first
            ("STACK_GLOBAL opcode", "S205"),
            ("GLOBAL opcode imports module", "S206"),
        ]

        for message, expected_code in test_cases:
            match = RuleRegistry.find_matching_rule(message)
            assert match is not None, f"No match for '{message}'"
            code, _ = match
            assert code == expected_code, f"Expected {expected_code} for '{message}', got {code}"
