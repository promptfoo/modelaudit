"""
Rule system for ModelAudit - Simple, centralized rule definitions and management.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from .rule_catalog import RULE_CATALOG


class Severity(str, Enum):
    """Severity levels for rules."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Rule:
    """Single rule definition."""

    code: str
    name: str
    default_severity: Severity
    description: str
    message_patterns: list[re.Pattern[str]]

    def matches_message(self, message: str) -> bool:
        """Check if this rule matches a given message."""
        return any(pattern.search(message) for pattern in self.message_patterns)


class RuleRegistry:
    """Central registry for all security rules."""

    _rules: ClassVar[dict[str, Rule]] = {}
    _message_match_cache: ClassVar[dict[str, tuple[str, Rule] | None]] = {}
    _initialized = False

    @classmethod
    def initialize(cls):
        """Initialize all rules. Called once at startup."""
        if cls._initialized:
            return

        cls._message_match_cache.clear()
        for catalog_entry in RULE_CATALOG:
            cls._add_rule(
                catalog_entry.code,
                catalog_entry.name,
                Severity(catalog_entry.severity),
                catalog_entry.description,
                list(catalog_entry.patterns),
            )

        cls._initialized = True

    @classmethod
    def reset_for_testing(cls) -> None:
        """Reset registry state for tests that need deterministic initialization."""
        cls._rules.clear()
        cls._message_match_cache.clear()
        cls._initialized = False

    @classmethod
    def _add_rule(cls, code: str, name: str, severity: Severity, description: str, patterns: list[str]) -> None:
        """Add a rule to the registry."""
        compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        cls._rules[code] = Rule(code, name, severity, description, compiled_patterns)
        cls._message_match_cache.clear()

    @classmethod
    def get_rule(cls, code: str) -> Rule | None:
        """Get a rule by its code."""
        cls.initialize()
        return cls._rules.get(code)

    @classmethod
    def find_matching_rule(cls, message: str | None) -> tuple[str, Rule] | None:
        """Find the first rule that matches a message."""
        if not message or not message.strip():
            return None

        cls.initialize()
        if message in cls._message_match_cache:
            return cls._message_match_cache[message]

        match: tuple[str, Rule] | None = None
        for code, rule in cls._rules.items():
            if rule.matches_message(message):
                match = (code, rule)
                break

        # Bound cache growth for long-running scans with highly variable messages.
        if len(cls._message_match_cache) >= 4096:
            cls._message_match_cache.clear()
        cls._message_match_cache[message] = match
        return match

    @classmethod
    def get_all_rules(cls) -> dict[str, Rule]:
        """Get all registered rules."""
        cls.initialize()
        return cls._rules.copy()

    @classmethod
    def get_rules_by_range(cls, start: int, end: int) -> dict[str, Rule]:
        """Get rules in a numeric range (e.g., S100-S199)."""
        cls.initialize()
        result = {}
        for code, rule in cls._rules.items():
            if code.startswith("S"):
                try:
                    num = int(code[1:])
                    if start <= num <= end:
                        result[code] = rule
                except ValueError:
                    continue
        return result
