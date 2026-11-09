"""
Configuration management for ModelAudit rule system.
Supports TOML-based configuration for suppressing rules and adjusting severity.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable, Iterator, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore

from ..rules import RuleRegistry, Severity

logger = logging.getLogger(__name__)

RULE_RANGE_PATTERN = re.compile(r"^S(\d+)-S(\d+)$")


DISABLE_REVIEWED_CITATIONS_CONFIG_KEY = "_disable_reviewed_citations"
_MAX_REVIEWED_CITATION_BYTES = 2 * 1024 * 1024
_MAX_REVIEWED_CITATION_SITES = 4096
_Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_NonemptyText = Annotated[str, Field(min_length=1)]


class _ReviewedCitation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    rule: Literal["S309"]
    type: Literal["url_detected"]
    role: Literal["readme_documentation"]
    sha256: _Sha256
    position: int = Field(ge=0)
    fingerprint: str = Field(pattern=r"^text-doc-network:[0-9a-f]{24}$")
    url: _NonemptyText
    raw_span: _NonemptyText
    related_sha256: _Sha256
    reason: _NonemptyText


class _ReviewedCitationFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(ge=1, le=1)
    sites: list[_ReviewedCitation] = Field(max_length=_MAX_REVIEWED_CITATION_SITES)


def _unique_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate JSON object member")
    return obj


CitationKey = tuple[str, int, str]
CitationIndex = Mapping[CitationKey, dict[str, Any]]


@dataclass(frozen=True, eq=False)
class _LoadedReviewedCitations(Mapping[CitationKey, dict[str, Any]]):
    """A validated policy owns its stored rows and returns independent evidence dictionaries."""

    _sites: Mapping[CitationKey, Mapping[str, Any]]
    digest: str

    def __getitem__(self, key: CitationKey) -> dict[str, Any]:
        return dict(self._sites[key])

    def __iter__(self) -> Iterator[CitationKey]:
        return iter(self._sites)

    def __len__(self) -> int:
        return len(self._sites)


def reviewed_citation_digest(sites: CitationIndex) -> str:
    if isinstance(sites, _LoadedReviewedCitations):
        return sites.digest
    encoded = json.dumps(sorted(sites.items()), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def load_reviewed_citations(path: Path) -> CitationIndex:
    """Load an explicitly selected, versioned set of operator-reviewed documentation findings."""
    try:
        if not path.is_file():
            raise ValueError("expected a regular decision file")
        with path.open("rb") as source:
            data = source.read(_MAX_REVIEWED_CITATION_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"cannot read decision file: {exc.strerror}") from exc
    if len(data) > _MAX_REVIEWED_CITATION_BYTES:
        raise ValueError("decision file exceeds the 2 MiB limit")
    try:
        document = _ReviewedCitationFile.model_validate(json.loads(data, object_pairs_hook=_unique_json_keys))
    except ValidationError as exc:
        error = exc.errors(include_input=False, include_context=False)[0]
        location = ".".join(str(part) for part in error["loc"])
        raise ValueError(f"invalid decision file at {location or 'root'}: {error['msg']}") from exc
    except (UnicodeError, RecursionError, ValueError) as exc:
        raise ValueError(f"invalid decision JSON: {exc}") from exc

    indexed: dict[tuple[str, int, str], dict[str, Any]] = {}
    for index, site in enumerate(document.sites):
        key = (site.sha256, site.position, site.fingerprint)
        row = site.model_dump()
        if key in indexed and indexed[key] != row:
            raise ValueError(f"sites.{index} conflicts with an earlier decision for the same citation")
        indexed[key] = row
    frozen = MappingProxyType({key: MappingProxyType(row) for key, row in indexed.items()})
    return _LoadedReviewedCitations(frozen, reviewed_citation_digest(indexed))


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


def _summarize_codes(codes: set[str], limit: int = 10) -> str:
    """Summarize a set of codes for warning logs."""
    sorted_codes = sorted(codes)
    if len(sorted_codes) <= limit:
        return ", ".join(sorted_codes)
    remaining = len(sorted_codes) - limit
    return f"{', '.join(sorted_codes[:limit])}, ... (+{remaining} more)"


@dataclass
class ModelAuditConfig:
    """Configuration for ModelAudit scanning."""

    suppress: set[str] = field(default_factory=set)
    severity: dict[str, Severity] = field(default_factory=dict)
    ignore: dict[str, list[str]] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)
    reviewed_citations: CitationIndex = field(default_factory=dict)

    reviewed_citation_aliases: frozenset[Path] = frozenset()

    def copy(self) -> ModelAuditConfig:
        """Return a shallow copy of this configuration."""
        return ModelAuditConfig(
            suppress=set(self.suppress),
            severity=dict(self.severity),
            ignore={pattern: list(rules) for pattern, rules in self.ignore.items()},
            options=dict(self.options),
            reviewed_citations={key: row.copy() for key, row in self.reviewed_citations.items()},
            reviewed_citation_aliases=self.reviewed_citation_aliases,
        )

    @classmethod
    def load(cls, path: Path | None = None, *, discover_local: bool = False) -> ModelAuditConfig:
        """
        Load configuration from file or use defaults.

        Search order:
        1. Specified path (if provided)
        2. .modelaudit.toml in current directory (when discover_local=True)
        3. pyproject.toml [tool.modelaudit] section (when discover_local=True)
        4. Default empty config
        """
        config = cls()

        if path and path.exists():
            if path.name == "pyproject.toml":
                config._load_from_pyproject(path)
            else:
                config._load_from_file(path)
            return config

        if discover_local:
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
        valid_rule_codes = set(RuleRegistry.get_all_rules().keys())

        if "suppress" in data and isinstance(data["suppress"], list):
            raw_suppress = [str(code).strip().upper() for code in data["suppress"] if isinstance(code, str)]
            expanded_suppress = _expand_rule_codes(raw_suppress)
            unknown_suppress = {code for code in expanded_suppress if code not in valid_rule_codes}
            if unknown_suppress:
                logger.warning(
                    "Ignoring unknown suppress rule code(s): %s",
                    _summarize_codes(unknown_suppress),
                )
            self.suppress = {code for code in expanded_suppress if code in valid_rule_codes}

        if "severity" in data and isinstance(data["severity"], dict):
            for rule_code, severity_str in data["severity"].items():
                normalized_code = str(rule_code).strip().upper()
                if normalized_code not in valid_rule_codes:
                    logger.warning("Ignoring unknown severity override rule code: %s", normalized_code)
                    continue
                try:
                    self.severity[normalized_code] = Severity(str(severity_str).strip().upper())
                except (ValueError, AttributeError):
                    logger.warning(
                        "Ignoring invalid severity '%s' for rule %s",
                        severity_str,
                        normalized_code,
                    )

        if "ignore" in data and isinstance(data["ignore"], dict):
            expanded: dict[str, list[str]] = {}
            for pattern, codes in data["ignore"].items():
                if not isinstance(codes, list):
                    continue
                raw_codes = [str(code).strip().upper() for code in codes if isinstance(code, str)]
                expanded_codes = _expand_rule_codes(raw_codes)

                valid_codes: list[str] = []
                unknown_codes: set[str] = set()
                for code in expanded_codes:
                    if code == "ALL" or code in valid_rule_codes:
                        valid_codes.append(code)
                    else:
                        unknown_codes.add(code)

                if unknown_codes:
                    logger.warning(
                        "Ignoring unknown ignore rule code(s) for pattern '%s': %s",
                        pattern,
                        _summarize_codes(unknown_codes),
                    )

                if valid_codes:
                    expanded[pattern] = list(dict.fromkeys(valid_codes))
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
        cls,
        suppress: list[str] | None = None,
        severity: dict[str, str] | None = None,
        *,
        base_config: ModelAuditConfig | None = None,
    ) -> ModelAuditConfig:
        """
        Create config from CLI arguments merged with file config.
        """
        config = base_config.copy() if base_config is not None else cls.load(discover_local=False)
        valid_rule_codes = set(RuleRegistry.get_all_rules().keys())

        if suppress:
            expanded_suppress = _expand_rule_codes(list(suppress))
            unknown_suppress = sorted({code for code in expanded_suppress if code not in valid_rule_codes})
            if unknown_suppress:
                unknown = ", ".join(unknown_suppress)
                raise ValueError(f"Unknown rule code(s) in --suppress: {unknown}")
            config.suppress.update(expanded_suppress)

        if severity:
            for rule_code, severity_str in severity.items():
                normalized_code = rule_code.upper()
                if normalized_code not in valid_rule_codes:
                    raise ValueError(f"Unknown rule code in --severity: {normalized_code}")
                try:
                    config.severity[normalized_code] = Severity(severity_str.upper())
                except (ValueError, AttributeError) as exc:
                    raise ValueError(
                        f"Invalid severity '{severity_str}' for rule {normalized_code}. "
                        "Use one of: CRITICAL, HIGH, MEDIUM, LOW, INFO."
                    ) from exc

        return config


_global_config: ModelAuditConfig | None = None


_scan_rule_config: ContextVar[ModelAuditConfig | None] = ContextVar("scan_rule_config", default=None)


def bind_scan_rule_config(config: ModelAuditConfig) -> Callable[[], None]:
    """Bind operator decisions to this scan and return its context cleanup."""
    token = _scan_rule_config.set(config)
    return lambda: _scan_rule_config.reset(token)


def get_config() -> ModelAuditConfig:
    """Get the active scan configuration or the process default."""
    scan_config = _scan_rule_config.get()
    if scan_config is not None:
        return scan_config
    global _global_config
    if _global_config is None:
        _global_config = ModelAuditConfig.load(discover_local=False)
    return _global_config


def set_config(config: ModelAuditConfig) -> None:
    """Set the global configuration instance."""
    global _global_config
    _global_config = config


def reset_config() -> None:
    """Reset the global configuration (useful for testing)."""
    global _global_config
    _global_config = None
