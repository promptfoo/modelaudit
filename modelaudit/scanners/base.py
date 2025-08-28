import hashlib
import json
import logging
import os

# Progress tracking imports with circular dependency detection
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, ClassVar, Optional

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from ..context.unified_context import UnifiedMLContext
from ..explanations import get_message_explanation
from ..interrupt_handler import check_interrupted

# Progress tracking imports with circular dependency detection
PROGRESS_AVAILABLE = False
ProgressTracker = None
ProgressPhase = None

# Try to import progress tracking, handle circular import gracefully
try:
    from ..progress import ProgressTracker  # type: ignore

    PROGRESS_AVAILABLE = True
except (ImportError, RecursionError):
    # Keep None values to indicate unavailable
    pass

# Configure logging
logger = logging.getLogger("modelaudit.scanners")


class IssueSeverity(Enum):
    """Enum for issue severity levels"""

    DEBUG = "debug"  # Debug information
    INFO = "info"  # Informational, not a security concern
    WARNING = "warning"  # Potential issue, needs review
    CRITICAL = "critical"  # Definite security concern


class CheckStatus(Enum):
    """Enum for check status"""

    PASSED = "passed"  # Check passed successfully
    FAILED = "failed"  # Check failed (issue found)
    SKIPPED = "skipped"  # Check was skipped


class Check(BaseModel):
    """Pydantic model representing a single security check performed during scanning"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",  # Allow extra fields for extensibility
    )

    name: str = Field(..., description="Name of the check performed")
    status: CheckStatus = Field(..., description="Whether the check passed or failed")
    message: str = Field(..., description="Description of what was checked")
    severity: Optional[IssueSeverity] = Field(None, description="Severity (only for failed checks)")
    location: Optional[str] = Field(None, description="File position, line number, etc.")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional check details")
    why: Optional[str] = Field(None, description="Explanation (mainly for failed checks)")
    timestamp: float = Field(default_factory=time.time, description="Timestamp when check was performed")

    @field_serializer("status")
    def serialize_status(self, status: CheckStatus) -> str:
        """Serialize status enum to string value"""
        return status.value

    @field_serializer("severity")
    def serialize_severity(self, severity: Optional[IssueSeverity]) -> Optional[str]:
        """Serialize severity enum to string value"""
        return severity.value if severity else None

    def to_dict(self) -> dict[str, Any]:
        """Convert the check to a dictionary for serialization (backward compatibility)"""
        return self.model_dump(exclude_none=True, mode="json")

    def __str__(self) -> str:
        """String representation of the check"""
        status_symbol = "✓" if self.status == CheckStatus.PASSED else "✗"
        prefix = f"[{status_symbol}] {self.name}"
        if self.location:
            prefix += f" ({self.location})"
        return f"{prefix}: {self.message}"


class Issue(BaseModel):
    """Pydantic model representing a single issue found during scanning"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",  # Allow extra fields for extensibility
    )

    message: str = Field(..., description="Description of the issue")
    severity: IssueSeverity = Field(default=IssueSeverity.WARNING, description="Issue severity level")
    location: Optional[str] = Field(None, description="File position, line number, etc.")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details about the issue")
    why: Optional[str] = Field(None, description="Explanation of why this is a security concern")
    timestamp: float = Field(default_factory=time.time, description="Timestamp when issue was detected")
    type: Optional[str] = Field(None, description="Type of issue for categorization")

    @field_serializer("severity")
    def serialize_severity(self, severity: IssueSeverity) -> str:
        """Serialize severity enum to string value"""
        return severity.value

    def to_dict(self) -> dict[str, Any]:
        """Convert the issue to a dictionary for serialization (backward compatibility)"""
        return self.model_dump(exclude_none=True, mode="json")

    def __str__(self) -> str:
        """String representation of the issue"""
        severity_str = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        prefix = f"[{severity_str.upper()}]"
        if self.location:
            prefix += f" ({self.location})"
        return f"{prefix}: {self.message}"


class ScanResult:
    """Collects and manages issues found during scanning"""

    def __init__(self, scanner_name: str = "unknown"):
        self.scanner_name = scanner_name
        self.issues: list[Issue] = []
        self.checks: list[Check] = []  # All checks performed (passed and failed)
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.bytes_scanned: int = 0
        self.success: bool = True
        self.metadata: dict[str, Any] = {}

    def add_check(
        self,
        name: str,
        passed: bool,
        message: str,
        severity: Optional[IssueSeverity] = None,
        location: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        why: Optional[str] = None,
    ) -> None:
        """Add a check result (passed or failed)"""
        status = CheckStatus.PASSED if passed else CheckStatus.FAILED

        # For failed checks, ensure we have a severity
        if not passed and severity is None:
            severity = IssueSeverity.WARNING

        check = Check(
            name=name,
            status=status,
            message=message,
            severity=severity,
            location=location,
            details=details or {},
            why=why,
        )
        self.checks.append(check)

        # If the check failed, also add it as an issue for backward compatibility
        if not passed:
            if why is None:
                why = get_message_explanation(message, context=self.scanner_name)
            # Severity should never be None here due to check above, but add assertion for type checker
            assert severity is not None
            issue = Issue(
                message=message,
                severity=severity,
                location=location,
                details=details or {},
                why=why,
                type=f"{self.scanner_name}_check",
            )
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
        else:
            # Log successful checks at DEBUG level
            logger.debug(f"Check passed: {name} - {message}")

    def add_issue(
        self,
        message: str,
        severity: IssueSeverity = IssueSeverity.WARNING,
        location: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        why: Optional[str] = None,
    ) -> None:
        """Add an issue to the result (for backward compatibility)"""
        if why is None:
            # Pass scanner name as context for more specific explanations
            why = get_message_explanation(message, context=self.scanner_name)

        issue = Issue(
            message=message,
            severity=severity,
            location=location,
            details=details or {},
            why=why,
            type=f"{self.scanner_name}_issue",
        )
        self.issues.append(issue)

        # Also add as a failed check for consistency
        check_name = details.get("check_name", "Security Check") if details else "Security Check"
        check = Check(
            name=check_name,
            status=CheckStatus.FAILED,
            message=message,
            severity=severity,
            location=location,
            details=details or {},
            why=why,
        )
        self.checks.append(check)

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
        self.checks.extend(other.checks)  # Merge checks as well
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
            "checks": [check.to_dict() for check in self.checks],  # Include all checks
            "metadata": self.metadata,
            "has_errors": self.has_errors,
            "has_warnings": self.has_warnings,
            "total_checks": len(self.checks),
            "passed_checks": sum(1 for c in self.checks if c.status == CheckStatus.PASSED),
            "failed_checks": sum(1 for c in self.checks if c.status == CheckStatus.FAILED),
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
        self.timeout = self.config.get("timeout", 3600)  # Default 1 hour for large models
        self.current_file_path = ""  # Track the current file being scanned
        self.chunk_size = self.config.get(
            "chunk_size",
            10 * 1024 * 1024 * 1024,
        )  # Default: 10GB chunks
        self.max_file_read_size = self.config.get(
            "max_file_read_size",
            0,
        )  # Default unlimited
        self._path_validation_result: Optional[ScanResult] = None
        self.context: Optional[UnifiedMLContext] = None  # Will be initialized when scanning a file
        self.scan_start_time: Optional[float] = None  # Track scan start time for timeout

        # Progress tracking setup
        self.progress_tracker: Optional[Any] = None
        self._enable_progress = self.config.get("enable_progress", False) and PROGRESS_AVAILABLE

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

    def scan_with_cache(self, path: str) -> ScanResult:
        """
        Scan with optional caching support.

        This method provides caching capabilities for individual scanners.
        If caching is disabled in the config, it falls back to the regular scan() method.

        Args:
            path: Path to the file to scan

        Returns:
            ScanResult object (either from cache or fresh scan)
        """
        # Check if caching is enabled in scanner config
        cache_enabled = self.config.get("cache_enabled", True)
        cache_dir = self.config.get("cache_dir")

        # If caching is disabled, proceed with direct scan
        if not cache_enabled:
            return self.scan(path)

        # Use cache manager for scanner-level caching
        try:
            from ..cache import get_cache_manager

            cache_manager = get_cache_manager(cache_dir, enabled=True)

            # Create cache-aware scan function
            def cached_scanner_wrapper(fpath: str) -> dict:
                result = self.scan(fpath)
                return result.to_dict()

            # Get cached result or perform scan
            result_dict = cache_manager.cached_scan(path, cached_scanner_wrapper)

            # Convert back to ScanResult
            from ..utils.result_conversion import scan_result_from_dict

            return scan_result_from_dict(result_dict)

        except Exception as e:
            # If cache system fails, fall back to direct scanning
            logger.warning(f"Scanner cache error for {path} ({self.name}): {e}. Falling back to direct scan.")
            return self.scan(path)

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

    def _start_scan_timer(self) -> None:
        """Start the scan timer for timeout tracking"""
        self.scan_start_time = time.time()

    def _check_timeout(self, allow_partial: bool = False) -> bool:
        """Check if the scan has exceeded the timeout.

        Args:
            allow_partial: If True, return True on timeout instead of raising exception

        Returns:
            True if timeout exceeded and allow_partial is True, False otherwise

        Raises:
            TimeoutError: If the scan has exceeded the configured timeout and allow_partial is False
        """
        if self.scan_start_time is None:
            self.scan_start_time = time.time()
            return False

        elapsed = time.time() - self.scan_start_time
        if elapsed > self.timeout:
            if allow_partial:
                return True
            raise TimeoutError(f"Scan exceeded timeout of {self.timeout} seconds (elapsed: {elapsed:.1f}s)")

        return False

    def _get_remaining_time(self) -> float:
        """Get the remaining time before timeout.

        Returns:
            Remaining time in seconds, or timeout value if timer not started
        """
        if self.scan_start_time is None:
            return self.timeout

        elapsed = time.time() - self.scan_start_time
        remaining = self.timeout - elapsed
        return max(0, remaining)

    def _add_timeout_warning(self, result: ScanResult, bytes_scanned: int, total_bytes: int) -> None:
        """Add a warning to the result indicating the scan was incomplete due to timeout.

        Args:
            result: The scan result to add the warning to
            bytes_scanned: Number of bytes scanned before timeout
            total_bytes: Total bytes in the file
        """
        percentage = (bytes_scanned / total_bytes * 100) if total_bytes > 0 else 0
        result.add_issue(
            f"Scan incomplete: Timeout after scanning {bytes_scanned:,} of {total_bytes:,} bytes ({percentage:.1f}%)",
            severity=IssueSeverity.WARNING,
            location=self.current_file_path,
            details={
                "bytes_scanned": bytes_scanned,
                "total_bytes": total_bytes,
                "percentage_complete": percentage,
                "timeout_seconds": self.timeout,
            },
        )

    def add_file_integrity_check(self, path: str, result: ScanResult) -> None:
        """Add file integrity check with hashes to the scan result.

        This should be called by scanners to record file hashes for compliance.
        """
        hashes = self.calculate_file_hashes(path)
        file_size = self.get_file_size(path)

        # Add the check
        result.add_check(
            name="File Integrity Hash",
            passed=True,  # Hash calculation itself is neutral
            message="File integrity hashes calculated",
            location=path,
            details={
                "md5": hashes["md5"],
                "sha256": hashes["sha256"],
                "sha512": hashes["sha512"],
                "file_size": file_size,
            },
        )

        # Also add to metadata for easy access
        result.metadata["file_hashes"] = hashes
        result.metadata["file_size"] = file_size

    def check_for_embedded_secrets(
        self,
        data: Any,
        result: ScanResult,
        context: str = "",
        enable_check: bool = True,
    ) -> int:
        """Check for embedded secrets, API keys, and credentials in data.

        Args:
            data: Data to check (bytes, str, dict, etc.)
            result: ScanResult to add findings to
            context: Context string for reporting
            enable_check: Whether to perform the check (allows disabling)

        Returns:
            Number of secrets detected
        """
        if not enable_check or not self.config.get("check_secrets", True):
            return 0

        try:
            from modelaudit.secrets_detector import SecretsDetector

            detector = SecretsDetector(self.config.get("secrets_config"))
            findings = detector.scan_model_weights(data, context)

            for finding in findings:
                severity_map = {
                    "CRITICAL": IssueSeverity.CRITICAL,
                    "WARNING": IssueSeverity.WARNING,
                    "INFO": IssueSeverity.INFO,
                }
                severity = severity_map.get(finding.get("severity", "WARNING"), IssueSeverity.WARNING)

                result.add_check(
                    name="Embedded Secrets Detection",
                    passed=False,
                    message=finding.get("message", "Secret detected"),
                    severity=severity,
                    location=finding.get("context", context),
                    details=finding,
                    why=finding.get("recommendation", "Remove sensitive data from model"),
                )

            # Add a passing check if no secrets were found
            if not findings and context:
                result.add_check(
                    name="Embedded Secrets Detection",
                    passed=True,
                    message="No embedded secrets detected",
                    location=context,
                )

            return len(findings)

        except ImportError:
            # SecretsDetector not available, log as debug
            logger.debug("SecretsDetector not available, skipping secrets check")
            return 0
        except Exception as e:
            logger.warning(f"Error checking for embedded secrets: {e}")
            return 0

    def collect_jit_script_findings(
        self,
        data: bytes,
        model_type: str = "unknown",
        context: str = "",
        enable_check: bool = True,
    ) -> list[dict]:
        """Collect JIT/script code findings without creating checks.

        Args:
            data: Binary model data to check
            model_type: Type of model (pytorch, tensorflow, etc.)
            context: Context string for reporting
            enable_check: Whether to perform the check (allows disabling)

        Returns:
            List of findings
        """
        if not enable_check or not self.config.get("check_jit_script", True):
            return []

        try:
            from modelaudit.jit_script_detector import JITScriptDetector

            detector = JITScriptDetector(self.config.get("jit_script_config"))
            findings = detector.scan_model(data, model_type, context)

            # Convert findings to dict format for consistency
            standardized_findings = []
            for finding in findings:
                if hasattr(finding, "model_dump"):
                    standardized_findings.append(finding.model_dump())
                elif hasattr(finding, "get"):
                    standardized_findings.append(dict(finding))
                else:
                    standardized_findings.append(
                        finding.__dict__ if hasattr(finding, "__dict__") else {"object": str(finding)}
                    )

            return standardized_findings

        except ImportError:
            logger.debug("JITScriptDetector not available, skipping JIT/Script check")
            return []
        except Exception as e:
            logger.warning(f"Error checking for JIT/Script code: {e}")
            return []

    def summarize_jit_script_findings(
        self,
        findings: list[dict],
        result: ScanResult,
        context: str = "",
    ) -> None:
        """Create a single aggregated check from JIT/script findings.

        Args:
            findings: List of findings to summarize
            result: ScanResult to add the summary check to
            context: Context string for reporting
        """
        if findings:
            # Map severity to IssueSeverity enum
            severity_map = {
                "CRITICAL": IssueSeverity.CRITICAL,
                "WARNING": IssueSeverity.WARNING,
                "INFO": IssueSeverity.INFO,
            }

            # Get highest severity across all findings
            max_severity = IssueSeverity.INFO
            for finding in findings:
                finding_severity = severity_map.get(finding.get("severity", "WARNING"), IssueSeverity.WARNING)
                if (finding_severity.value == "critical" and max_severity.value != "critical") or (
                    finding_severity.value == "warning" and max_severity.value == "info"
                ):
                    max_severity = finding_severity

            result.add_check(
                name="JIT/Script Code Execution Detection",
                passed=False,
                message=f"Found {len(findings)} JIT/Script code risks across file",
                severity=max_severity,
                location=context,
                details={
                    "findings_count": len(findings),
                    "findings": findings[:10],  # Include up to 10 examples
                    "total_findings": len(findings),
                },
                why="JIT/Script code patterns can execute arbitrary code during model loading",
            )
        else:
            result.add_check(
                name="JIT/Script Code Execution Detection",
                passed=True,
                message="No JIT/Script code execution risks detected",
                location=context,
            )

    def check_for_jit_script_code(
        self,
        data: bytes,
        result: ScanResult,
        model_type: str = "unknown",
        context: str = "",
        enable_check: bool = True,
    ) -> int:
        """Check for JIT/Script code execution risks in model data.

        Args:
            data: Binary model data to check
            result: ScanResult to add findings to
            model_type: Type of model (pytorch, tensorflow, onnx, etc.)
            context: Context string for reporting
            enable_check: Whether to perform the check (allows disabling)

        Returns:
            Number of JIT/Script risks detected
        """
        if not enable_check or not self.config.get("check_jit_script", True):
            return 0

        try:
            from modelaudit.jit_script_detector import JITScriptDetector

            detector = JITScriptDetector(self.config.get("jit_script_config"))
            findings = detector.scan_model(data, model_type, context)

            for finding in findings:
                severity_map = {
                    "CRITICAL": IssueSeverity.CRITICAL,
                    "WARNING": IssueSeverity.WARNING,
                    "INFO": IssueSeverity.INFO,
                }
                # Handle both dict and Pydantic model findings
                if hasattr(finding, "model_dump"):
                    # Pydantic model (JITScriptFinding)
                    severity_value = finding.severity if isinstance(finding.severity, str) else finding.severity.value
                    severity = severity_map.get(severity_value, IssueSeverity.WARNING)
                    message = finding.message
                    location = finding.context
                    recommendation = finding.recommendation or "Review JIT/Script code for security"
                    details = finding.model_dump()
                elif hasattr(finding, "get"):
                    # Dict format (backward compatibility)
                    severity = severity_map.get(finding.get("severity", "WARNING"), IssueSeverity.WARNING)
                    message = finding.get("message", "JIT/Script code risk detected")
                    location = finding.get("context", context)
                    recommendation = finding.get("recommendation", "Review JIT/Script code for security")
                    details = dict(finding)  # Ensure it's a dict
                else:
                    # Object with attributes but not Pydantic
                    severity_value = getattr(finding, "severity", "WARNING")
                    severity = severity_map.get(severity_value, IssueSeverity.WARNING)
                    message = getattr(finding, "message", "JIT/Script code risk detected")
                    location = getattr(finding, "context", context)
                    recommendation = getattr(finding, "recommendation", "Review JIT/Script code for security")
                    details = finding.__dict__ if hasattr(finding, "__dict__") else {"object": str(finding)}

                result.add_check(
                    name="JIT/Script Code Execution Detection",
                    passed=False,
                    message=message,
                    severity=severity,
                    location=location,
                    details=details,
                    why=recommendation,
                )

            # Add a passing check if no risks were found
            if not findings and context:
                result.add_check(
                    name="JIT/Script Code Execution Detection",
                    passed=True,
                    message="No JIT/Script code execution risks detected",
                    location=context,
                )

            return len(findings)

        except ImportError:
            # JITScriptDetector not available, log as debug
            logger.debug("JITScriptDetector not available, skipping JIT/Script check")
            return 0
        except Exception as e:
            logger.warning(f"Error checking for JIT/Script code: {e}")
            return 0

    def collect_network_communication_findings(
        self,
        data: bytes,
        context: str = "",
        enable_check: bool = True,
    ) -> list[dict]:
        """Collect network communication findings without creating checks.

        Args:
            data: Binary model data to check
            context: Context string for reporting
            enable_check: Whether to perform the check (allows disabling)

        Returns:
            List of findings
        """
        if not enable_check or not self.config.get("check_network_comm", True):
            return []

        try:
            from modelaudit.network_comm_detector import NetworkCommDetector

            detector = NetworkCommDetector(self.config.get("network_comm_config"))
            findings = detector.scan(data, context)
            return findings

        except ImportError:
            logger.debug("NetworkCommDetector not available, skipping network comm check")
            return []
        except Exception as e:
            logger.warning(f"Error checking for network communication: {e}")
            return []

    def summarize_network_communication_findings(
        self,
        findings: list[dict],
        result: ScanResult,
        context: str = "",
    ) -> None:
        """Create a single aggregated check from network communication findings.

        Args:
            findings: List of findings to summarize
            result: ScanResult to add the summary check to
            context: Context string for reporting
        """
        if findings:
            severity_map = {
                "CRITICAL": IssueSeverity.CRITICAL,
                "HIGH": IssueSeverity.CRITICAL,
                "MEDIUM": IssueSeverity.WARNING,
                "LOW": IssueSeverity.INFO,
            }

            # Get highest severity across all findings
            max_severity = IssueSeverity.INFO
            for finding in findings:
                finding_severity = severity_map.get(finding.get("severity", "WARNING"), IssueSeverity.WARNING)
                if (finding_severity.value == "critical" and max_severity.value != "critical") or (
                    finding_severity.value == "warning" and max_severity.value == "info"
                ):
                    max_severity = finding_severity

            result.add_check(
                name="Network Communication Detection",
                passed=False,
                message=f"Found {len(findings)} network communication patterns across file",
                severity=max_severity,
                location=context,
                details={
                    "findings_count": len(findings),
                    "findings": findings[:10],  # Include up to 10 examples
                    "total_findings": len(findings),
                },
                why="Models should not contain network communication capabilities",
            )
        else:
            result.add_check(
                name="Network Communication Detection",
                passed=True,
                message="No network communication patterns detected",
                location=context,
            )

    def check_for_network_communication(
        self,
        data: bytes,
        result: ScanResult,
        context: str = "",
        enable_check: bool = True,
    ) -> int:
        """Check for network communication patterns in model data.

        Args:
            data: Binary model data to check
            result: ScanResult to add findings to
            context: Context string for reporting
            enable_check: Whether to perform the check (allows disabling)

        Returns:
            Number of network communication patterns detected
        """
        if not enable_check or not self.config.get("check_network_comm", True):
            return 0

        try:
            from modelaudit.network_comm_detector import NetworkCommDetector

            detector = NetworkCommDetector(self.config.get("network_comm_config"))
            findings = detector.scan(data, context)

            for finding in findings:
                severity_map = {
                    "CRITICAL": IssueSeverity.CRITICAL,
                    "HIGH": IssueSeverity.CRITICAL,
                    "MEDIUM": IssueSeverity.WARNING,
                    "LOW": IssueSeverity.INFO,
                }
                severity = severity_map.get(finding.get("severity", "WARNING"), IssueSeverity.WARNING)

                result.add_check(
                    name="Network Communication Detection",
                    passed=False,
                    message=finding.get("message", "Network communication pattern detected"),
                    severity=severity,
                    location=finding.get("context", context),
                    details=finding,
                    why="Models should not contain network communication capabilities",
                )

            # Add a passing check if no patterns were found
            if not findings and context:
                result.add_check(
                    name="Network Communication Detection",
                    passed=True,
                    message="No network communication patterns detected",
                    location=context,
                )

            return len(findings)

        except ImportError:
            # NetworkCommDetector not available, log as debug
            logger.debug("NetworkCommDetector not available, skipping network comm check")
            return 0
        except Exception as e:
            logger.warning(f"Error checking for network communication: {e}")
            return 0

    def _check_path(self, path: str) -> Optional[ScanResult]:
        """Common path checks and validation

        Returns:
            None if path is valid or has only warnings, otherwise a ScanResult with critical errors
        """
        result = self._create_result()

        # Check if path exists
        if not os.path.exists(path):
            result.add_check(
                name="Path Exists",
                passed=False,
                message=f"Path does not exist: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result
        else:
            result.add_check(
                name="Path Exists",
                passed=True,
                message="Path exists",
                location=path,
                details={"path": path},
            )

        # Check if path is readable
        if not os.access(path, os.R_OK):
            result.add_check(
                name="Path Readable",
                passed=False,
                message=f"Path is not readable: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result
        else:
            result.add_check(
                name="Path Readable",
                passed=True,
                message="Path is readable",
                location=path,
                details={"path": path},
            )

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
                    result.add_check(
                        name="File Type Validation",
                        passed=False,
                        message=(
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
                else:
                    result.add_check(
                        name="File Type Validation",
                        passed=True,
                        message="File type validation passed",
                        location=path,
                    )
            except Exception as e:
                # Don't fail the scan if file type validation has an error
                result.add_check(
                    name="File Type Validation",
                    passed=False,
                    message=f"File type validation error: {e!s}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"exception": str(e), "exception_type": type(e).__name__},
                )

        # Store validation checks or warnings for the scanner to merge later
        self._path_validation_result = result if (result.issues or result.checks) else None

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

    def calculate_file_hashes(self, path: str) -> dict[str, str]:
        """Calculate MD5, SHA256, and SHA512 hashes of a file.

        Returns a dictionary with hash values or error messages.
        """
        hashes = {"md5": "", "sha256": "", "sha512": ""}

        if not os.path.isfile(path):
            return hashes

        try:
            # Calculate all hashes in a single pass for efficiency
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            sha512_hash = hashlib.sha512()

            with open(path, "rb") as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(8192), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    sha512_hash.update(chunk)

            hashes["md5"] = md5_hash.hexdigest()
            hashes["sha256"] = sha256_hash.hexdigest()
            hashes["sha512"] = sha512_hash.hexdigest()

        except Exception as e:
            logger.warning(f"Failed to calculate hashes for {path}: {e}")
            # Return empty hashes on error rather than failing

        return hashes

    def _check_size_limit(self, path: str) -> Optional[ScanResult]:
        """Check if the file exceeds the configured size limit."""
        file_size = self.get_file_size(path)

        if self.max_file_read_size and self.max_file_read_size > 0 and file_size > self.max_file_read_size:
            result = self._create_result()
            result.metadata["file_size"] = file_size
            result.add_check(
                name="File Size Limit",
                passed=False,
                message=f"File too large: {file_size} bytes (max: {self.max_file_read_size})",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "file_size": file_size,
                    "max_file_read_size": self.max_file_read_size,
                },
                why=(
                    "Large files may consume excessive memory or processing time. "
                    "Consider whether this file size is expected for your use case."
                ),
            )
            result.finish(success=False)
            return result

        if self.max_file_read_size and self.max_file_read_size > 0:
            if self._path_validation_result is None:
                self._path_validation_result = ScanResult(scanner_name=self.name)
            self._path_validation_result.metadata["file_size"] = file_size
            self._path_validation_result.add_check(
                name="File Size Limit",
                passed=True,
                message="File size within limit",
                location=path,
                details={
                    "file_size": file_size,
                    "max_file_read_size": self.max_file_read_size,
                },
            )
        else:
            if self._path_validation_result is None:
                self._path_validation_result = ScanResult(scanner_name=self.name)
            self._path_validation_result.metadata["file_size"] = file_size

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

    def _initialize_progress_tracker(self) -> None:
        """Initialize progress tracker for this scanner."""
        if self._enable_progress and ProgressTracker:
            self.progress_tracker = ProgressTracker()  # type: ignore
            logger.debug(f"Progress tracker initialized for {self.name} scanner")

    def _setup_progress_for_file(self, path: str) -> None:
        """Setup progress tracking for a specific file."""
        if self.progress_tracker and PROGRESS_AVAILABLE:
            file_size = self.get_file_size(path)
            self.progress_tracker.stats.total_bytes = file_size
            # Import locally to avoid circular import but ensure type safety
            from ..progress import ProgressPhase

            self.progress_tracker.set_phase(ProgressPhase.INITIALIZING, f"Starting scan: {path}")

    # All progress tracking methods disabled to fix CI circular import issues
    def _update_progress_bytes(self, bytes_processed: int, current_item: str = "") -> None:
        """Update progress with bytes processed."""
        if self.progress_tracker:
            self.progress_tracker.update_bytes(bytes_processed, current_item)

    def _increment_progress_bytes(self, bytes_delta: int, current_item: str = "") -> None:
        """Increment progress by a number of bytes."""
        if self.progress_tracker:
            self.progress_tracker.increment_bytes(bytes_delta, current_item)

    def _update_progress_items(self, items_processed: int, current_item: str = "") -> None:
        """Update progress with items processed."""
        if self.progress_tracker:
            self.progress_tracker.update_items(items_processed, current_item)

    def _increment_progress_items(self, items_delta: int = 1, current_item: str = "") -> None:
        """Increment progress by a number of items."""
        if self.progress_tracker:
            self.progress_tracker.increment_items(items_delta, current_item)

    def _set_progress_phase(self, phase: Any, message: str = "") -> None:
        """Set current progress phase."""
        if self.progress_tracker and PROGRESS_AVAILABLE:
            self.progress_tracker.set_phase(phase, message)

    def _next_progress_phase(self, message: str = "") -> bool:
        """Move to next progress phase."""
        if self.progress_tracker and hasattr(self.progress_tracker, "next_phase"):
            return self.progress_tracker.next_phase(message)
        return False

    def _set_progress_status(self, message: str) -> None:
        """Set progress status message."""
        if self.progress_tracker:
            self.progress_tracker.set_status(message)

    def _complete_progress(self) -> None:
        """Mark progress as complete."""
        if self.progress_tracker:
            self.progress_tracker.complete()

    def _report_progress_error(self, error: Exception) -> None:
        """Report an error to progress tracker."""
        if self.progress_tracker:
            self.progress_tracker.report_error(error)

    def scan_with_progress(self, path: str) -> ScanResult:
        """Scan with progress tracking enabled.

        This is a wrapper around the scan method that provides progress tracking.
        Subclasses should override scan() but can call this method for progress support.
        """
        self.current_file_path = path

        # Initialize progress tracking for this file
        if PROGRESS_AVAILABLE and self._enable_progress and not self.progress_tracker:
            self._initialize_progress_tracker()

        if self.progress_tracker:
            self._setup_progress_for_file(path)

        try:
            result = self.scan(path)
            self._complete_progress()
            return result
        except Exception as e:
            self._report_progress_error(e)
            raise

    def get_progress_stats(self) -> Optional[dict[str, Any]]:
        """Get current progress statistics."""
        if self.progress_tracker:
            return self.progress_tracker.get_stats()
        return None

    def add_progress_reporter(self, reporter: Any) -> None:
        """Add a progress reporter to this scanner."""
        # Initialize progress tracker if not already done
        if PROGRESS_AVAILABLE and self._enable_progress and not self.progress_tracker:
            self._initialize_progress_tracker()

        if self.progress_tracker:
            self.progress_tracker.add_reporter(reporter)

    def add_progress_callback(self, callback: Any) -> None:
        """Add a progress callback to this scanner."""
        # Initialize progress tracker if not already done
        if PROGRESS_AVAILABLE and self._enable_progress and not self.progress_tracker:
            self._initialize_progress_tracker()

        if self.progress_tracker:
            self.progress_tracker.add_callback(callback)
