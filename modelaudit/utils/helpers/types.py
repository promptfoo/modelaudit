"""Common type aliases for ModelAudit using Python 3.10+ features."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, Protocol, TypeAlias, TypedDict

# Configuration types
ConfigValue: TypeAlias = str | int | bool | list[str] | dict[str, Any]
ConfigDict: TypeAlias = dict[str, ConfigValue]
NestedDict: TypeAlias = dict[str, Any]

# File and path types
FilePath: TypeAlias = str
FileSize: TypeAlias = int
PathList: TypeAlias = list[FilePath]

# Model scanning types
ScanMetadata: TypeAlias = dict[str, Any]
CheckDetails: TypeAlias = dict[str, Any] | None
IssueDict: TypeAlias = dict[str, Any]

# Tensor and ML types
TensorShape: TypeAlias = tuple[int, ...]
LayerInfo: TypeAlias = dict[str, Any]
ModelWeights: TypeAlias = dict[str, Any]

# Network and URL types
URLString: TypeAlias = str
Headers: TypeAlias = dict[str, str]
QueryParams: TypeAlias = dict[str, str | list[str]]

# Progress and callback types
ProgressValue: TypeAlias = float  # 0.0 to 1.0
ProgressCallback: TypeAlias = Callable[[str, ProgressValue], None]

# Security and detection types
PatternMatch: TypeAlias = dict[str, Any]
SecurityFinding: TypeAlias = dict[str, Any]
RiskScore: TypeAlias = float  # 0.0 to 1.0

# SARIF and reporting types
SARIFRule: TypeAlias = dict[str, Any]
SARIFResult: TypeAlias = dict[str, Any]
SARIFArtifact: TypeAlias = dict[str, Any]

# Hash and caching types
HashString: TypeAlias = str
CacheKey: TypeAlias = str
CacheValue: TypeAlias = Any

# Magic bytes and file format types
MagicBytes: TypeAlias = bytes
FileFormat: TypeAlias = str
FileExtension: TypeAlias = str

# Literal types for Python 3.10+
SeverityLevel: TypeAlias = Literal["debug", "info", "warning", "critical"]
CheckStatusType: TypeAlias = Literal["passed", "failed", "skipped"]
ScanFormatType: TypeAlias = Literal["text", "json", "sarif", "sbom"]
LogLevelType: TypeAlias = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


# TypedDict for structured configurations (Python 3.10+)
class ScanConfigTypedDict(TypedDict, total=False):
    """Typed configuration dictionary for scanning options."""

    timeout: int
    max_file_size: int
    max_total_size: int
    verbose: bool
    blacklist_patterns: list[str]
    strict_license: bool
    skip_file_types: bool


class IssueDataTypedDict(TypedDict):
    """Typed dictionary for issue data structure."""

    name: str
    passed: bool
    message: str
    severity: SeverityLevel
    location: str
    details: dict[str, Any] | None


class ScanResultMetadataTypedDict(TypedDict, total=False):
    """Typed dictionary for scan result metadata."""

    file_size: int
    scan_duration: float
    scanner_name: str
    scanner_version: str
    disabled_checks: list[str]
    custom_domains: list[str]


# Protocol classes for better duck typing (Python 3.10+)
class ScannerProtocol(Protocol):
    """Protocol for scanner implementations."""

    name: str
    description: str

    def can_handle(self, path: FilePath) -> bool:
        """Check if this scanner can handle the given file."""
        ...

    def scan(self, path: FilePath) -> Any:  # Should return ScanResult
        """Scan the given file and return results."""
        ...


class ProgressTrackerProtocol(Protocol):
    """Protocol for progress tracking implementations."""

    def update_progress(self, message: str, progress: ProgressValue) -> None:
        """Update progress with a message and completion percentage."""
        ...

    def set_total_steps(self, total: int) -> None:
        """Set the total number of steps for progress tracking."""
        ...


class FileHandlerProtocol(Protocol):
    """Protocol for file handling implementations."""

    def read_bytes(self, num_bytes: int) -> bytes:
        """Read specified number of bytes from file."""
        ...

    def seek(self, position: int) -> None:
        """Seek to specific position in file."""
        ...

    def close(self) -> None:
        """Close the file handler."""
        ...
