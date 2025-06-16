import json
import logging
import os
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, ClassVar, Optional

# Configure logging
logger = logging.getLogger("modelaudit.scanners")


class IssueSeverity(Enum):
    """Enum for issue severity levels"""

    DEBUG = "debug"  # Debug information
    INFO = "info"  # Informational, not a security concern
    WARNING = "warning"  # Potential issue, needs review
    CRITICAL = "critical"  # Definite security concern


class Issue:
    """Represents a single issue found during scanning"""

    def __init__(
        self,
        message: str,
        severity: IssueSeverity = IssueSeverity.WARNING,
        location: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        self.message = message
        self.severity = severity
        self.location = location  # File position, line number, etc.
        self.details = details or {}
        self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        """Convert the issue to a dictionary for serialization"""
        return {
            "message": self.message,
            "severity": self.severity.value,
            "location": self.location,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    def __str__(self) -> str:
        """String representation of the issue"""
        prefix = f"[{self.severity.value.upper()}]"
        if self.location:
            prefix += f" ({self.location})"
        return f"{prefix}: {self.message}"


class ScanResult:
    """Collects and manages issues found during scanning"""

    def __init__(self, scanner_name: str = "unknown"):
        self.scanner_name = scanner_name
        self.issues: list[Issue] = []
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.bytes_scanned: int = 0
        self.success: bool = True
        self.metadata: dict[str, Any] = {}

    def add_issue(
        self,
        message: str,
        severity: IssueSeverity = IssueSeverity.WARNING,
        location: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Add an issue to the result"""
        issue = Issue(message, severity, location, details)
        self.issues.append(issue)
        log_level = (
            logging.CRITICAL
            if severity == IssueSeverity.CRITICAL
            else (
                logging.WARNING
                if severity == IssueSeverity.WARNING
                else (logging.INFO if severity == IssueSeverity.INFO else logging.DEBUG)
            )
        )
        logger.log(log_level, str(issue))

    def merge(self, other: "ScanResult") -> None:
        """Merge another scan result into this one"""
        self.issues.extend(other.issues)
        self.bytes_scanned += other.bytes_scanned
        # Merge metadata dictionaries
        for key, value in other.metadata.items():
            if (
                key in self.metadata
                and isinstance(self.metadata[key], dict)
                and isinstance(value, dict)
            ):
                self.metadata[key].update(value)
            else:
                self.metadata[key] = value

    def finish(self, success: bool = True) -> None:
        """Mark the scan as finished"""
        self.end_time = time.time()
        self.success = success

    @property
    def duration(self) -> float:
        """Return the duration of the scan in seconds"""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    @property
    def has_errors(self) -> bool:
        """Return True if there are any critical-level issues"""
        return any(issue.severity == IssueSeverity.CRITICAL for issue in self.issues)

    @property
    def has_warnings(self) -> bool:
        """Return True if there are any warning-level issues"""
        return any(issue.severity == IssueSeverity.WARNING for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        """Convert the scan result to a dictionary for serialization"""
        return {
            "scanner": self.scanner_name,
            "success": self.success,
            "duration": self.duration,
            "bytes_scanned": self.bytes_scanned,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": self.metadata,
            "has_errors": self.has_errors,
            "has_warnings": self.has_warnings,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert the scan result to a JSON string"""
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        """Return a human-readable summary of the scan result"""
        error_count = sum(
            1 for issue in self.issues if issue.severity == IssueSeverity.CRITICAL
        )
        warning_count = sum(
            1 for issue in self.issues if issue.severity == IssueSeverity.WARNING
        )
        info_count = sum(
            1 for issue in self.issues if issue.severity == IssueSeverity.INFO
        )

        result = []
        result.append(f"Scan completed in {self.duration:.2f}s")
        result.append(
            f"Scanned {self.bytes_scanned} bytes with scanner '{self.scanner_name}'",
        )
        result.append(
            f"Found {len(self.issues)} issues ({error_count} critical, "
            f"{warning_count} warnings, {info_count} info)",
        )

        # If there are any issues, show them
        if self.issues:
            result.append("\nIssues:")
            for issue in self.issues:
                result.append(f"  {issue}")

        return "\n".join(result)

    def __str__(self) -> str:
        """String representation of the scan result"""
        return self.summary()


class BaseScanner(ABC):
    """Base class for all scanners"""

    name: ClassVar[str] = "base"
    description: ClassVar[str] = "Base scanner class"
    supported_extensions: ClassVar[list[str]] = []

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """Initialize the scanner with configuration"""
        self.config = config or {}
        self.timeout = self.config.get("timeout", 300)  # Default 5 minutes
        self.current_file_path = ""  # Track the current file being scanned
        self.chunk_size = self.config.get(
            "chunk_size",
            10 * 1024 * 1024,
        )  # Default: 10MB chunks

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Return True if this scanner can handle the file at the given path"""
        # Basic implementation checks file extension
        # Subclasses should override for more sophisticated detection
        file_ext = os.path.splitext(path)[1].lower()
        return file_ext in cls.supported_extensions

    @abstractmethod
    def scan(self, path: str) -> ScanResult:
        """Scan the model file or directory at the given path"""
        pass

    def _create_result(self) -> ScanResult:
        """Create a new ScanResult instance for this scanner"""
        return ScanResult(scanner_name=self.name)

    def _check_path(self, path: str) -> Optional[ScanResult]:
        """Common path checks and validation

        Returns:
            None if path is valid, otherwise a ScanResult with errors
        """
        result = self._create_result()

        # Check if path exists
        if not os.path.exists(path):
            result.add_issue(
                f"Path does not exist: {path}",
                severity=IssueSeverity.CRITICAL,
                details={"path": path},
            )
            result.finish(success=False)
            return result

        # Check if path is readable
        if not os.access(path, os.R_OK):
            result.add_issue(
                f"Path is not readable: {path}",
                severity=IssueSeverity.CRITICAL,
                details={"path": path},
            )
            result.finish(success=False)
            return result

        return None  # Path is valid

    def get_file_size(self, path: str) -> int:
        """Get the size of a file in bytes"""
        return os.path.getsize(path) if os.path.isfile(path) else 0
