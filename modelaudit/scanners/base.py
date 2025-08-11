import json
import logging
import os
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, ClassVar, Optional

from ..context.unified_context import UnifiedMLContext
from ..explanations import get_message_explanation
from ..interrupt_handler import check_interrupted

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
        why: Optional[str] = None,
    ):
        self.message = message
        self.severity = severity
        self.location = location  # File position, line number, etc.
        self.details = details or {}
        self.why = why  # Explanation of why this is a security concern
        self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        """Convert the issue to a dictionary for serialization"""
        result = {
            "message": self.message,
            "severity": self.severity.value,
            "location": self.location,
            "details": self.details,
            "timestamp": self.timestamp,
        }
        if self.why:
            result["why"] = self.why
        return result

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
        self.checks_performed: list[dict[str, Any]] = []  # Track all checks, not just issues
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.bytes_scanned: int = 0
        self.success: bool = True
        self.metadata: dict[str, Any] = {}

    def add_check(
        self,
        check_name: str,
        passed: bool = True,
        details: Optional[str] = None,
        category: Optional[str] = None,
    ) -> None:
        """Record a security check that was performed"""
        check_record = {
            "scanner": self.scanner_name,
            "check_name": check_name,
            "passed": passed,
            "timestamp": time.time(),
        }
        if details:
            check_record["details"] = details
        if category:
            check_record["category"] = category
        self.checks_performed.append(check_record)

    def add_issue(
        self,
        message: str,
        severity: IssueSeverity = IssueSeverity.WARNING,
        location: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        why: Optional[str] = None,
    ) -> None:
        """Add an issue to the result"""
        if why is None:
            # Pass scanner name as context for more specific explanations
            why = get_message_explanation(message, context=self.scanner_name)
        issue = Issue(message, severity, location, details, why)
        self.issues.append(issue)
        
        # Also record this as a failed check
        self.add_check(
            check_name=message.split(':')[0] if ':' in message else message[:50],
            passed=False,
            category=self._categorize_issue(message),
        )
        
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
    
    def _categorize_issue(self, message: str) -> str:
        """Categorize an issue based on its message"""
        msg_lower = message.lower()
        if any(word in msg_lower for word in ['eval', 'exec', 'import', 'subprocess', 'system', 'pyfunc', 'lambda', 'reduce']):
            return "Code Execution"
        elif any(word in msg_lower for word in ['file', 'path', 'traversal', 'directory', 'shutil']):
            return "File System"
        elif any(word in msg_lower for word in ['socket', 'network', 'http', 'url']):
            return "Network Operations"
        elif any(word in msg_lower for word in ['pickle', 'joblib', 'serial', 'deserial', 'opcode']):
            return "Serialization"
        elif any(word in msg_lower for word in ['tensor', 'weight', 'model', 'layer', 'shape']):
            return "Model Integrity"
        elif any(word in msg_lower for word in ['license', 'copyright', 'gpl']):
            return "License Compliance"
        elif any(word in msg_lower for word in ['blacklist', 'policy', 'forbidden']):
            return "Security Policy"
        elif any(word in msg_lower for word in ['config', 'setting', 'parameter']):
            return "Configuration"
        elif any(word in msg_lower for word in ['size', 'length', 'overflow', 'validation']):
            return "Data Validation"
        else:
            return "General"

    def merge(self, other: "ScanResult") -> None:
        """Merge another scan result into this one"""
        self.issues.extend(other.issues)
        self.checks_performed.extend(other.checks_performed)
        self.bytes_scanned += other.bytes_scanned
        # Merge metadata dictionaries
        for key, value in other.metadata.items():
            if key in self.metadata and isinstance(self.metadata[key], dict) and isinstance(value, dict):
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
            "checks_performed": self.checks_performed,
            "metadata": self.metadata,
            "has_errors": self.has_errors,
            "has_warnings": self.has_warnings,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert the scan result to a JSON string"""
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        """Return a human-readable summary of the scan result"""
        error_count = sum(1 for issue in self.issues if issue.severity == IssueSeverity.CRITICAL)
        warning_count = sum(1 for issue in self.issues if issue.severity == IssueSeverity.WARNING)
        info_count = sum(1 for issue in self.issues if issue.severity == IssueSeverity.INFO)

        result = []
        result.append(f"Scan completed in {self.duration:.2f}s")
        result.append(
            f"Scanned {self.bytes_scanned} bytes with scanner '{self.scanner_name}'",
        )
        result.append(
            f"Found {len(self.issues)} issues ({error_count} critical, {warning_count} warnings, {info_count} info)",
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
        self.max_file_read_size = self.config.get(
            "max_file_read_size",
            0,
        )  # Default unlimited
        self._path_validation_result: Optional[ScanResult] = None
        self.context: Optional[UnifiedMLContext] = None  # Will be initialized when scanning a file

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

    def _initialize_context(self, path: str) -> None:
        """Initialize the unified context for the current file."""
        from pathlib import Path as PathlibPath

        path_obj = PathlibPath(path)
        file_size = self.get_file_size(path)
        file_type = path_obj.suffix.lower()
        self.context = UnifiedMLContext(file_path=path_obj, file_size=file_size, file_type=file_type)

    def _create_result(self) -> ScanResult:
        """Create a new ScanResult instance for this scanner"""
        result = ScanResult(scanner_name=self.name)

        # Automatically merge any stored path validation warnings
        if hasattr(self, "_path_validation_result") and self._path_validation_result:
            result.merge(self._path_validation_result)
            # Clear the stored result to avoid duplicate merging
            self._path_validation_result = None

        return result

    def _check_path(self, path: str) -> Optional[ScanResult]:
        """Common path checks and validation

        Returns:
            None if path is valid or has only warnings, otherwise a ScanResult with critical errors
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

        # Validate file type consistency for files (security check)
        if os.path.isfile(path):
            try:
                from modelaudit.utils.filetype import (
                    detect_file_format_from_magic,
                    detect_format_from_extension,
                    validate_file_type,
                )

                if not validate_file_type(path):
                    header_format = detect_file_format_from_magic(path)
                    ext_format = detect_format_from_extension(path)
                    result.add_issue(
                        (
                            f"File type validation failed: extension indicates {ext_format} but magic bytes "
                            f"indicate {header_format}. This could indicate file spoofing, corruption, or a "
                            f"security threat."
                        ),
                        severity=IssueSeverity.WARNING,  # Warning level to allow scan to continue
                        location=path,
                        details={
                            "header_format": header_format,
                            "extension_format": ext_format,
                            "security_check": "file_type_validation",
                        },
                    )
            except Exception as e:
                # Don't fail the scan if file type validation has an error
                result.add_issue(
                    f"File type validation error: {e!s}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"exception": str(e), "exception_type": type(e).__name__},
                )

        # Store validation warnings for the scanner to merge later
        self._path_validation_result = result if result.issues else None

        # Only return result for CRITICAL issues that should stop the scan
        critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
        if critical_issues:
            return result

        return None  # Path is valid, scanner should continue and merge warnings if any

    def get_file_size(self, path: str) -> int:
        """Get the size of a file in bytes."""
        try:
            return os.path.getsize(path) if os.path.isfile(path) else 0
        except OSError:
            # If the file becomes inaccessible during scanning, treat the size
            # as zero rather than raising an exception.
            return 0

    def _check_size_limit(self, path: str) -> Optional[ScanResult]:
        """Check if the file exceeds the configured size limit."""
        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        if self.max_file_read_size and self.max_file_read_size > 0 and file_size > self.max_file_read_size:
            result.add_issue(
                f"File too large: {file_size} bytes (max: {self.max_file_read_size})",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "file_size": file_size,
                    "max_file_read_size": self.max_file_read_size,
                },
                why="Large files may consume excessive memory or processing time. Consider whether this file "
                "size is expected for your use case.",
            )
            result.finish(success=False)
            return result

        return None

    def _read_file_safely(self, path: str) -> bytes:
        """Read a file with size validation and chunking."""
        data = bytearray()
        file_size = self.get_file_size(path)

        if self.max_file_read_size and self.max_file_read_size > 0 and file_size > self.max_file_read_size:
            raise ValueError(
                f"File too large: {file_size} bytes (max: {self.max_file_read_size})",
            )

        with open(path, "rb") as f:
            while True:
                # Check for interrupts during file reading
                check_interrupted()

                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                data.extend(chunk)
                if self.max_file_read_size and self.max_file_read_size > 0 and len(data) > self.max_file_read_size:
                    raise ValueError(
                        f"File read exceeds limit: {len(data)} bytes (max: {self.max_file_read_size})",
                    )
        return bytes(data)

    def check_interrupted(self) -> None:
        """Check if the scan has been interrupted.

        Scanners should call this method periodically during long operations.
        Raises KeyboardInterrupt if an interrupt has been requested.
        """
        check_interrupted()
