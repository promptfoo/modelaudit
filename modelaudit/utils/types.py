"""Common type aliases for ModelAudit."""

# ruff: noqa: UP006, UP035, UP045
# TypeAlias values are runtime expressions, not annotations.
# Must use typing.Dict/List/Union/Optional for Python 3.9 compat.

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Dict, List, Literal, Optional, Protocol, Tuple, TypedDict, Union

from typing_extensions import TypeAlias

# Configuration types
ConfigValue: TypeAlias = Union[str, int, bool, List[str], Dict[str, Any]]
ConfigDict: TypeAlias = Dict[str, ConfigValue]
NestedDict: TypeAlias = Dict[str, Any]

# File and path types
FilePath: TypeAlias = str
FileSize: TypeAlias = int
PathList: TypeAlias = List[FilePath]

# Model scanning types
ScanMetadata: TypeAlias = Dict[str, Any]
CheckDetails: TypeAlias = Optional[Dict[str, Any]]
IssueDict: TypeAlias = Dict[str, Any]

# Tensor and ML types
TensorShape: TypeAlias = Tuple[int, ...]
LayerInfo: TypeAlias = Dict[str, Any]
ModelWeights: TypeAlias = Dict[str, Any]

# Network and URL types
URLString: TypeAlias = str
Headers: TypeAlias = Dict[str, str]
QueryParams: TypeAlias = Dict[str, Union[str, List[str]]]

# Progress and callback types
ProgressValue: TypeAlias = float  # 0.0 to 1.0
ProgressCallback: TypeAlias = Callable[[str, ProgressValue], None]

# Security and detection types
PatternMatch: TypeAlias = Dict[str, Any]
SecurityFinding: TypeAlias = Dict[str, Any]
RiskScore: TypeAlias = float  # 0.0 to 1.0

# SARIF and reporting types
SARIFRule: TypeAlias = Dict[str, Any]
SARIFResult: TypeAlias = Dict[str, Any]
SARIFArtifact: TypeAlias = Dict[str, Any]

# Hash and caching types
HashString: TypeAlias = str
CacheKey: TypeAlias = str
CacheValue: TypeAlias = Any

# Magic bytes and file format types
MagicBytes: TypeAlias = bytes
FileFormat: TypeAlias = str
FileExtension: TypeAlias = str

# Literal types
SeverityLevel: TypeAlias = Literal["debug", "info", "warning", "critical"]
CheckStatusType: TypeAlias = Literal["passed", "failed", "skipped"]
ScanFormatType: TypeAlias = Literal["text", "json", "sarif", "sbom"]
LogLevelType: TypeAlias = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


# TypedDict for structured configurations
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
    details: Optional[Dict[str, Any]]


class ScanResultMetadataTypedDict(TypedDict, total=False):
    """Typed dictionary for scan result metadata."""

    file_size: int
    scan_duration: float
    scanner_name: str
    scanner_version: str
    disabled_checks: list[str]
    custom_domains: list[str]


# Protocol classes for better duck typing
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
