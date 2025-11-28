"""
Configuration management for ModelAudit rule system.
Supports TOML-based configuration for suppressing rules and adjusting severity.
"""

from __future__ import annotations

import contextlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore

from ..rules import Severity

logger = logging.getLogger(__name__)

RULE_RANGE_PATTERN = re.compile(r"^S(\d+)-S(\d+)$")


def _expand_rule_codes(codes: list[str]) -> list[str]:
    """Expand rule ranges like S200-S299 into explicit codes."""
    expanded: list[str] = []
    for code in codes:
        match = RULE_RANGE_PATTERN.match(code)
        if match:
            start, end = match.groups()
            start_num, end_num = int(start), int(end)
            if end_num < start_num:
                logger.warning("Invalid rule range %s (end before start); skipping", code)
                continue
            expanded.extend([f"S{num}" for num in range(start_num, end_num + 1)])
        else:
            expanded.append(code)
    return expanded


@dataclass
class ModelAuditConfig:
    """Configuration for ModelAudit scanning."""

    suppress: set[str] = field(default_factory=set)
    severity: dict[str, Severity] = field(default_factory=dict)
    ignore: dict[str, list[str]] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> ModelAuditConfig:
        """
        Load configuration from file or use defaults.

        Search order:
        1. Specified path (if provided)
        2. .modelaudit.toml in current directory
        3. pyproject.toml [tool.modelaudit] section
        4. Default empty config
        """
        config = cls()

        if path and path.exists():
            config._load_from_file(path)
            return config

        modelaudit_toml = Path(".modelaudit.toml")
        if modelaudit_toml.exists():
            config._load_from_file(modelaudit_toml)
            return config

        pyproject_toml = Path("pyproject.toml")
        if pyproject_toml.exists():
            config._load_from_pyproject(pyproject_toml)
            return config

        return config

    def _load_from_file(self, path: Path) -> None:
        """Load configuration from a TOML file."""
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
                self._parse_config(data)
        except Exception as exc:
            logger.debug("Failed to load config from %s: %s", path, exc)

    def _load_from_pyproject(self, path: Path) -> None:
        """Load configuration from pyproject.toml [tool.modelaudit] section."""
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
            tool_section = data.get("tool", {})
            modelaudit_section = tool_section.get("modelaudit")
            if modelaudit_section:
                self._parse_config(modelaudit_section)
        except Exception as exc:
            logger.debug("Failed to load config from pyproject.toml: %s", exc)

    def _parse_config(self, data: dict[str, Any]) -> None:
        """Parse configuration dictionary into this object."""
        if "suppress" in data and isinstance(data["suppress"], list):
            self.suppress = set(_expand_rule_codes(data["suppress"]))

        if "severity" in data and isinstance(data["severity"], dict):
            for rule_code, severity_str in data["severity"].items():
                with contextlib.suppress(ValueError, AttributeError):
                    self.severity[rule_code] = Severity(severity_str.upper())

        if "ignore" in data and isinstance(data["ignore"], dict):
            expanded: dict[str, list[str]] = {}
            for pattern, codes in data["ignore"].items():
                if not isinstance(codes, list):
                    continue
                expanded[pattern] = _expand_rule_codes(codes)
            self.ignore = expanded

        if "options" in data and isinstance(data["options"], dict):
            self.options = data["options"]

    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """
        Check if a file path matches a glob-style pattern.

        Note: This uses fnmatch, not full gitignore semantics.
        """
        from fnmatch import fnmatch

        return fnmatch(file_path, pattern) or fnmatch(Path(file_path).name, pattern)

    def is_suppressed(self, rule_code: str, file_path: str | None = None) -> bool:
        """Check if a rule should be suppressed for a file path."""
        if rule_code in self.suppress:
            return True

        if file_path and self.ignore:
            for pattern, rules in self.ignore.items():
                if self._matches_pattern(file_path, pattern) and (rule_code in rules or "ALL" in rules):
                    return True
        return False

    def get_severity(self, rule_code: str, default: Severity) -> Severity:
        """Get the configured severity for a rule."""
        return self.severity.get(rule_code, default)

    @classmethod
    def from_cli_args(
        cls, suppress: list[str] | None = None, severity: dict[str, str] | None = None
    ) -> ModelAuditConfig:
        """
        Create config from CLI arguments merged with file config.
        """
        config = cls.load()

        if suppress:
            config.suppress.update(_expand_rule_codes(list(suppress)))

        if severity:
            for rule_code, severity_str in severity.items():
                with contextlib.suppress(ValueError, AttributeError):
                    config.severity[rule_code] = Severity(severity_str.upper())

        return config


_global_config: ModelAuditConfig | None = None


def get_config() -> ModelAuditConfig:
    """Get the global configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = ModelAuditConfig.load()
    return _global_config


def set_config(config: ModelAuditConfig) -> None:
    """Set the global configuration instance."""
    global _global_config
    _global_config = config


def reset_config() -> None:
    """Reset the global configuration (useful for testing)."""
    global _global_config
    _global_config = None
