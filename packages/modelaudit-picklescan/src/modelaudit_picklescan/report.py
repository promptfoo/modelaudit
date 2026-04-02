"""Typed result models for standalone pickle analysis."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScanStatus(str, Enum):
    """Operational completeness of a pickle scan."""

    COMPLETE = "complete"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class SafetyVerdict(str, Enum):
    """Safety decision derived from scan evidence and scan completeness."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severity values for findings and notices."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    """Summary of how much pickle content was analyzed."""

    bytes_scanned: int = 0
    bytes_total: int | None = None
    opcode_count: int | None = None
    raw_scan_complete: bool | None = None
    opcode_scan_complete: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "bytes_scanned": self.bytes_scanned,
            "bytes_total": self.bytes_total,
            "opcode_count": self.opcode_count,
            "raw_scan_complete": self.raw_scan_complete,
            "opcode_scan_complete": self.opcode_scan_complete,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A WARNING/CRITICAL security finding."""

    message: str
    severity: Severity
    location: str | None = None
    rule_code: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    why: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in {Severity.WARNING, Severity.CRITICAL}:
            raise ValueError(f"finding severity must be warning/critical, got {self.severity.value}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "severity": self.severity.value,
            "location": self.location,
            "rule_code": self.rule_code,
            "details": deepcopy(self.details),
            "why": self.why,
        }


@dataclass(frozen=True, slots=True)
class Notice:
    """A DEBUG/INFO explainability or coverage note."""

    message: str
    severity: Severity = Severity.INFO
    location: str | None = None
    code: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in {Severity.DEBUG, Severity.INFO}:
            raise ValueError(f"notice severity must be debug/info, got {self.severity.value}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "severity": self.severity.value,
            "location": self.location,
            "code": self.code,
            "details": deepcopy(self.details),
        }


@dataclass(frozen=True, slots=True)
class ScanError:
    """An operational scanner failure."""

    message: str
    category: str
    location: str | None = None
    exception_type: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "category": self.category,
            "location": self.location,
            "exception_type": self.exception_type,
            "details": deepcopy(self.details),
        }


@dataclass(frozen=True, slots=True)
class PickleReport:
    """Standalone pickle scan report with explicit safety and completeness semantics."""

    source: str
    status: ScanStatus
    verdict: SafetyVerdict
    findings: tuple[Finding, ...] = ()
    notices: tuple[Notice, ...] = ()
    errors: tuple[ScanError, ...] = ()
    coverage: CoverageSummary = field(default_factory=CoverageSummary)
    metadata: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0

    @property
    def has_security_findings(self) -> bool:
        return bool(self.findings)

    @property
    def is_clean(self) -> bool:
        return self.status == ScanStatus.COMPLETE and self.verdict == SafetyVerdict.CLEAN and not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "notices": [notice.to_dict() for notice in self.notices],
            "errors": [error.to_dict() for error in self.errors],
            "coverage": self.coverage.to_dict(),
            "metadata": deepcopy(self.metadata),
            "duration_s": self.duration_s,
            "has_security_findings": self.has_security_findings,
            "is_clean": self.is_clean,
        }
