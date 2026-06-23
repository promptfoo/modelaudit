import hashlib
import logging
import os
import re

# Progress tracking imports with circular dependency detection
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, ClassVar, Final, Literal

from ..analysis.unified_context import UnifiedMLContext
from ..scanner_results import (
    INCONCLUSIVE_SCAN_OUTCOME,
    OPERATIONAL_ERROR_METADATA_KEY,
    RAW_DETECTOR_ANALYSIS_INCOMPLETE_REASON,
    RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY,
    RAW_DETECTOR_FAILURES_METADATA_KEY,
    SCAN_OUTCOME_METADATA_KEY,
    Check,
    CheckStatus,
    Issue,
    IssueSeverity,
    ScanResult,
    mark_inconclusive_scan_result,
)
from ..utils.helpers.interrupt_handler import check_interrupted
from ._evidence_redaction import redact_evidence_string, redact_untrusted_error_message
from .rule_mapper import get_embedded_code_rule_code, get_network_rule_code, get_secret_rule_code

# Progress tracking imports with circular dependency detection
PROGRESS_AVAILABLE = False
ProgressTracker = None

# Try to import progress tracking, handle circular import gracefully
try:
    from ..progress import ProgressTracker  # type: ignore

    PROGRESS_AVAILABLE = True
except (ImportError, RecursionError):
    # Keep None values to indicate unavailable
    pass

# Configure logging
logger = logging.getLogger("modelaudit.scanners")

__all__ = [
    "INCONCLUSIVE_SCAN_OUTCOME",
    "BaseScanner",
    "Check",
    "CheckStatus",
    "Issue",
    "IssueSeverity",
    "ScanResult",
    "make_trusted_source_provenance",
]

TRUSTED_HUGGINGFACE_SOURCES = frozenset({"huggingface"})
FORMAT_VALIDATION_CONFIG_KEY: Final[str] = "_modelaudit_format_validation"
_TRUSTED_SOURCE_PROVENANCE_TOKEN: Final[object] = object()
_WHITELIST_STALE_WARNING_THRESHOLD_DAYS: Final[int] = 90
_WHITELIST_DOWNGRADE_EXEMPT_RULE_CODES: Final[frozenset[str]] = frozenset(
    {
        # S1xx — direct code-execution primitives (os/sys/subprocess/eval/compile/__import__/
        # importlib/runpy/webbrowser/ctypes/builtins). The embedded payload itself is the
        # threat, so whitelisted HF models must not hide these.
        "S101",
        "S102",
        "S103",
        "S104",
        "S105",
        "S106",
        "S107",
        "S108",
        "S109",
        "S110",
        "S111",
        "S112",
        "S113",
        "S114",
        "S115",
        # S3xx — HIGH-severity active network primitives (raw sockets, ftp, telnet,
        # exfiltration). HTTP/SMTP/DNS/IP/URL codes stay eligible for downgrade since
        # those are policy-grade rather than active-payload signals.
        "S301",
        "S304",
        "S305",
        "S310",
        # S4xx — filesystem-escape and archive-bomb detections.
        "S405",
        "S406",
        "S408",
        "S410",
        # S5xx — embedded executable / interpreter content.
        "S501",
        "S502",
        "S503",
        "S504",
        "S505",
        "S506",
        "S507",
        "S508",
        "S509",
    }
)
_WHITELIST_DOWNGRADE_EXEMPT_CHECK_NAMES: Final[frozenset[str]] = frozenset(
    {
        "Command/Network Correlation Check",
        "RKNN Command and Network Indicator Correlation",
    }
)
_WHITELIST_DOWNGRADE_EXEMPT_CORRELATION_DETAIL = "same_fragment_correlation"
_WHITELIST_DOWNGRADE_EXEMPT_CRITICAL_CHECK_NAMES: Final[frozenset[str]] = frozenset(
    {
        "Blacklist Pattern Check",
        "Command Indicator Check",
        "CoreML Custom Layer Check",
        "CoreML Custom Model Class Check",
        "Embedded PE Detection",
        "External Library Reference Check",
        "Protobuf String Injection Check",
        "Python Operator Detection",
        "Serialized Expression Payload Detection",
        "Suspicious Layer Type Detection",
        "TorchServe Handler Static Analysis",
        "Torch7 Lua Execution Primitive Analysis",
    }
)
# Word-boundary matching prevents incidental substrings (e.g. "executable" inside
# "ExecuTorch", "rce" inside "force") from suppressing whitelist downgrades.
_WHITELIST_DOWNGRADE_EXEMPT_KEYWORD_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:"
    r"arbitrary\s+code"
    r"|dangerous"
    r"|executable"
    r"|inconclusive"
    r"|path\s+traversal"
    r"|rce"
    r"|remote\s+code\s+execution"
    r"|unsafe\s+deserialization"
    r")\b",
    re.IGNORECASE,
)
DEFAULT_MAX_FILE_READ_SIZE: Final[int] = 512 * 1024 * 1024
DEFAULT_READ_CHUNK_SIZE: Final[int] = 8 * 1024 * 1024


@lru_cache(maxsize=16)
def _warn_if_whitelist_is_stale(generated_at: str) -> None:
    try:
        whitelist_generated_at = datetime.fromisoformat(generated_at).date()
    except ValueError:
        logger.debug(
            "Invalid WHITELIST_GENERATED_AT value %r; skipping whitelist staleness check.",
            generated_at,
        )
        return

    whitelist_age_days = (datetime.now(timezone.utc).date() - whitelist_generated_at).days
    if whitelist_age_days > _WHITELIST_STALE_WARNING_THRESHOLD_DAYS:
        logger.warning(
            "HuggingFace whitelist is %d days old. Consider updating for best supply chain coverage.",
            whitelist_age_days,
        )


@dataclass(frozen=True)
class _TrustedSourceProvenance:
    """Internal marker for source provenance derived by trusted call sites."""

    model_id: str
    model_source: str
    token: object


def make_trusted_source_provenance(model_id: str, model_source: str) -> object:
    """Create an internal provenance marker for trusted remote downloads."""
    return _TrustedSourceProvenance(
        model_id=model_id,
        model_source=model_source,
        token=_TRUSTED_SOURCE_PROVENANCE_TOKEN,
    )


class BaseScanner(ABC):
    """Base class for all scanners"""

    name: ClassVar[str] = "base"
    description: ClassVar[str] = "Base scanner class"
    supported_extensions: ClassVar[list[str]] = []
    default_max_file_read_size: ClassVar[int] = DEFAULT_MAX_FILE_READ_SIZE

    @classmethod
    def directory_owner_source_in_scope(cls, relative_parts: tuple[str, ...]) -> bool:
        """Return whether a directory-owner scan can read this regular file."""
        return bool(relative_parts)

    @classmethod
    def directory_owner_directory_in_scope(cls, relative_parts: tuple[str, ...]) -> bool:
        """Return whether a directory-owner scan can inspect this directory entry."""
        return bool(relative_parts)

    @classmethod
    def directory_owner_should_descend_into_directory(cls, relative_parts: tuple[str, ...]) -> bool:
        """Return whether a directory-owner namespace snapshot should descend into this directory."""
        return cls.directory_owner_directory_in_scope(relative_parts)

    @classmethod
    def directory_owner_source_counts_toward_limits(cls, relative_parts: tuple[str, ...]) -> bool:
        """Return whether one owner-readable file consumes aggregate scan budgets."""
        return cls.directory_owner_source_in_scope(relative_parts)

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the scanner with configuration"""
        self.config = config or {}
        self.timeout = self.config.get("timeout", 3600)  # Default 1 hour for large models
        self.current_file_path = ""  # Track the current file being scanned
        self.chunk_size = self.config.get(
            "chunk_size",
            DEFAULT_READ_CHUNK_SIZE,
        )
        self.max_file_read_size = self._resolve_max_file_read_size()
        self._path_validation_result: ScanResult | None = None
        self.context: UnifiedMLContext | None = None  # Will be initialized when scanning a file
        self.scan_start_time: float | None = None  # Track scan start time for timeout

        # Progress tracking setup
        self.progress_tracker: Any | None = None
        self._enable_progress = self.config.get("enable_progress", False) and PROGRESS_AVAILABLE

    @staticmethod
    def _normalize_positive_int_config(value: Any, default: int) -> int:
        """Return a positive integer config value, or default for invalid input."""
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return default
        return value

    def _resolve_max_file_read_size(self) -> int:
        """Resolve the scanner read cap, using a bounded class default when unset."""
        if "max_file_read_size" in self.config:
            value = self.config["max_file_read_size"]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return self.default_max_file_read_size
            return value

        if "max_file_size" in self.config:
            value = self.config["max_file_size"]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return self.default_max_file_read_size

        return self.default_max_file_read_size

    def _get_bool_config(self, key: str, default: bool = True) -> bool:
        """
        Helper method to parse boolean configuration values with flexible input handling.

        Args:
            key: Configuration key to retrieve
            default: Default value if key is not found

        Returns:
            Boolean value parsed from config, with string values like "false", "0", "no", "off"
            being treated as False
        """
        val = self.config.get(key, default)
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.strip().lower() not in {"false", "0", "no", "off"}
        return bool(val)

    @staticmethod
    def _result_metadata_whitelist_downgrade_exempt(result_metadata: dict[str, Any] | None) -> bool:
        """Return True when result-level metadata marks incomplete operational coverage."""
        metadata = result_metadata or {}
        return (
            metadata.get("analysis_incomplete") is True
            or metadata.get(OPERATIONAL_ERROR_METADATA_KEY) is True
            or metadata.get(SCAN_OUTCOME_METADATA_KEY) == INCONCLUSIVE_SCAN_OUTCOME
        )

    @staticmethod
    def _whitelist_downgrade_exempt(
        *,
        severity: IssueSeverity,
        details: dict[str, Any] | None,
        result_metadata: dict[str, Any] | None = None,
        message: str | None,
        rule_code: str | None,
        check_name: str | None,
    ) -> bool:
        """Return True for active payload or incomplete-coverage findings."""
        details = details or {}
        if details.get("analysis_incomplete") is True or details.get("operational_error") is True:
            return True
        if BaseScanner._result_metadata_whitelist_downgrade_exempt(result_metadata):
            return True
        if details.get("cve_id") or details.get("cve"):
            return True

        if (
            check_name in _WHITELIST_DOWNGRADE_EXEMPT_CHECK_NAMES
            and details.get(_WHITELIST_DOWNGRADE_EXEMPT_CORRELATION_DETAIL) is True
        ):
            return True

        if severity == IssueSeverity.CRITICAL and check_name in _WHITELIST_DOWNGRADE_EXEMPT_CRITICAL_CHECK_NAMES:
            return True

        if rule_code and (rule_code.startswith("S2") or rule_code in _WHITELIST_DOWNGRADE_EXEMPT_RULE_CODES):
            return True

        text = " ".join(value for value in (message, check_name) if value)
        return bool(_WHITELIST_DOWNGRADE_EXEMPT_KEYWORD_PATTERN.search(text))

    def _should_apply_whitelist(
        self,
        severity: IssueSeverity,
        *,
        details: dict[str, Any] | None = None,
        result_metadata: dict[str, Any] | None = None,
        message: str | None = None,
        rule_code: str | None = None,
        check_name: str | None = None,
    ) -> bool:
        """
        Check if the whitelist should be applied to downgrade an issue's severity.

        Args:
            severity: The original severity of the issue

        Returns:
            True if the issue should be downgraded to INFO, False otherwise
        """
        # Only downgrade severities higher than INFO.
        if severity in (IssueSeverity.INFO, IssueSeverity.DEBUG):
            return False

        if self._whitelist_downgrade_exempt(
            severity=severity,
            details=details,
            result_metadata=result_metadata,
            message=message,
            rule_code=rule_code,
            check_name=check_name,
        ):
            return False

        # Check if whitelist is enabled (default: True)
        use_whitelist = self._get_bool_config("use_hf_whitelist", default=True)
        if not use_whitelist:
            return False

        # Only trusted HuggingFace provenance is eligible for downgrades.
        # Local metadata-derived model IDs do not qualify; validated HF cache layouts do.
        if self.context and self.context.model_id and self.context.model_source in TRUSTED_HUGGINGFACE_SOURCES:
            from modelaudit.whitelists import WHITELIST_GENERATED_AT, is_whitelisted_model

            is_whitelisted = is_whitelisted_model(self.context.model_id)
            if not is_whitelisted:
                return False

            _warn_if_whitelist_is_stale(WHITELIST_GENERATED_AT)

            return True

        return False

    def _apply_whitelist_downgrade(
        self,
        severity: IssueSeverity,
        details: dict[str, Any] | None,
        *,
        result_metadata: dict[str, Any] | None = None,
        message: str | None = None,
        rule_code: str | None = None,
        check_name: str | None = None,
    ) -> tuple[IssueSeverity, dict[str, Any]]:
        """
        Apply whitelist downgrading logic to severity and details.

        Args:
            severity: The original severity
            details: The details dictionary (may be None)

        Returns:
            Tuple of (potentially modified severity, details dict)
        """
        original_severity = severity
        details = dict(details or {})
        if severity in (IssueSeverity.INFO, IssueSeverity.DEBUG):
            return severity, details

        has_whitelist_metadata = (
            details.get("whitelist_downgrade") is True or details.get("whitelist_downgrade_restored") is True
        )
        if has_whitelist_metadata:
            details.pop("whitelist_downgrade", None)
            details.pop("whitelist_downgrade_restored", None)
            details.pop("original_severity", None)
        if self._should_apply_whitelist(
            severity,
            details=details,
            result_metadata=result_metadata,
            message=message,
            rule_code=rule_code,
            check_name=check_name,
        ):
            severity = IssueSeverity.INFO
            details["whitelist_downgrade"] = True
            details["original_severity"] = original_severity.name

        return severity, details

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

    def scan_with_cache(self, path: str) -> ScanResult:
        """
        Scan with optional caching support.

        This method provides caching capabilities for individual scanners.
        Uses the unified cache decorator to eliminate duplicate caching logic.

        Args:
            path: Path to the file to scan

        Returns:
            ScanResult object (either from cache or fresh scan)
        """
        from ..utils.helpers.cache_decorator import cached_scan

        # Create cached version of the scan method
        @cached_scan()
        def cached_scan_method(scanner_self: "BaseScanner", file_path: str) -> ScanResult:
            return scanner_self.scan(file_path)

        return cached_scan_method(self, path)

    def _initialize_context(self, path: str) -> None:
        """Initialize the unified context for the current file."""
        from pathlib import Path as PathlibPath

        from modelaudit.utils.sources.huggingface_paths import extract_model_id_from_path

        path_obj = PathlibPath(path)
        file_size = self.get_file_size(path)
        file_type = path_obj.suffix.lower()

        model_id: str | None
        model_source: str | None
        trusted_provenance = self.config.get("_trusted_source_provenance")
        if (
            isinstance(trusted_provenance, _TrustedSourceProvenance)
            and trusted_provenance.token is _TRUSTED_SOURCE_PROVENANCE_TOKEN
            and trusted_provenance.model_source in TRUSTED_HUGGINGFACE_SOURCES
        ):
            # Preserve explicit remote provenance when a trusted caller already
            # resolved a downloaded artifact to a local path.
            model_id = trusted_provenance.model_id
            model_source = trusted_provenance.model_source
        else:
            model_id, model_source = extract_model_id_from_path(path)

        self.context = UnifiedMLContext(
            file_path=path_obj,
            file_size=file_size,
            file_type=file_type,
            model_id=model_id,
            model_source=model_source,
        )

    def _create_result(self) -> ScanResult:
        """Create a new ScanResult instance for this scanner"""
        result = ScanResult(scanner_name=self.name, scanner=self)

        # Automatically merge any stored path validation warnings
        if hasattr(self, "_path_validation_result") and self._path_validation_result:
            result.merge(self._path_validation_result)
            # Clear the stored result to avoid duplicate merging
            self._path_validation_result = None

        return result

    def _run_preflight_checks(
        self,
        path: str,
        *,
        check_size_limit: bool = True,
    ) -> ScanResult | None:
        """Run shared path and optional size validation before a scanner's heavy parsing starts."""
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        if check_size_limit:
            size_check_result = self._check_size_limit(path)
            if size_check_result:
                return size_check_result

        return None

    def _create_scan_result_after_preflight(
        self,
        path: str,
        *,
        check_size_limit: bool = True,
    ) -> ScanResult:
        """Create a scan result after shared preflight, or return the failing preflight result."""
        preflight_result = self._run_preflight_checks(path, check_size_limit=check_size_limit)
        if preflight_result:
            return preflight_result

        self.current_file_path = path
        return self._create_result()

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
        result.add_check(
            name="Scan Timeout Check",
            passed=False,
            message=(
                f"Scan incomplete: Timeout after scanning {bytes_scanned:,} "
                f"of {total_bytes:,} bytes ({percentage:.1f}%)"
            ),
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

    def _mark_raw_detector_analysis_incomplete(
        self,
        result: ScanResult,
        *,
        detector: str,
        context: str = "",
        error: BaseException | None = None,
        coverage_gap: str = "analysis_failed",
    ) -> None:
        mark_inconclusive_scan_result(result, RAW_DETECTOR_ANALYSIS_INCOMPLETE_REASON)
        location = redact_evidence_string(context or self.current_file_path, max_chars=500)
        failure_details: dict[str, Any] = {
            "detector": detector,
            "context": location,
            "coverage_gap": coverage_gap,
        }
        if error is not None:
            failure_details["exception_type"] = type(error).__name__
            failure_details["exception"] = redact_untrusted_error_message(error)

        failures = result.metadata.setdefault(RAW_DETECTOR_FAILURES_METADATA_KEY, [])
        if isinstance(failures, list) and len(failures) < 20:
            failures.append(failure_details)
        failed_detectors = result.metadata.setdefault(RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY, [])
        already_recorded = isinstance(failed_detectors, list) and detector in failed_detectors
        if isinstance(failed_detectors, list) and not already_recorded:
            failed_detectors.append(detector)
        self._remove_failed_raw_detector_clean_checks(result)
        if already_recorded:
            return

        result.add_check(
            name="Raw Detector Analysis Coverage",
            passed=False,
            message=f"{detector.replace('_', ' ').title()} raw detector analysis failed; scan coverage is incomplete",
            severity=IssueSeverity.INFO,
            location=location,
            details={
                "scan_outcome_reason": RAW_DETECTOR_ANALYSIS_INCOMPLETE_REASON,
                "analysis_incomplete": True,
                **failure_details,
            },
            rule_code="S902",
        )

    @staticmethod
    def _raw_detector_failed(result: ScanResult, detector: str) -> bool:
        failed_detectors = result.metadata.get(RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY)
        return isinstance(failed_detectors, list) and detector in failed_detectors

    @staticmethod
    def _remove_failed_raw_detector_clean_checks(result: ScanResult) -> None:
        result.remove_failed_raw_detector_clean_checks()

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
        if not enable_check or not self._get_bool_config("check_secrets", True):
            return 0

        try:
            findings = self.collect_embedded_secret_findings(
                data,
                context,
                enable_check=enable_check,
                raise_on_error=True,
            )
        except ImportError:
            logger.debug("SecretsDetector not available, skipping secrets check")
            self._mark_raw_detector_analysis_incomplete(
                result,
                detector="embedded_secrets",
                context=context,
                coverage_gap="detector_unavailable",
            )
            return 0
        except Exception as e:
            logger.warning("Error checking for embedded secrets: %s", redact_untrusted_error_message(e))
            self._mark_raw_detector_analysis_incomplete(
                result,
                detector="embedded_secrets",
                context=context,
                error=e,
            )
            return 0

        return self.add_embedded_secret_findings(findings, result, context=context)

    def collect_embedded_secret_findings(
        self,
        data: Any,
        context: str = "",
        enable_check: bool = True,
        raise_on_error: bool = False,
        max_findings: int | None = None,
    ) -> list[dict[str, Any]]:
        """Collect embedded secret findings without creating checks."""
        if not enable_check or not self._get_bool_config("check_secrets", True):
            return []

        try:
            from modelaudit.detectors.secrets import SecretsDetector

            detector_config = self.config.get("secrets_config")
            if max_findings is not None:
                if detector_config is not None and not isinstance(detector_config, dict):
                    raise TypeError("secrets_config must be a mapping")
                detector_config = {**(detector_config or {}), "max_findings": max_findings}
            detector = SecretsDetector(detector_config)
            findings = detector.scan_model_weights(data, context)
            return [dict(finding) for finding in findings]

        except ImportError:
            if raise_on_error:
                raise
            # SecretsDetector not available, log as debug
            logger.debug("SecretsDetector not available, skipping secrets check")
            return []
        except Exception as e:
            if raise_on_error:
                raise
            logger.warning("Error checking for embedded secrets: %s", redact_untrusted_error_message(e))
            return []

    def add_embedded_secret_findings(
        self,
        findings: list[dict[str, Any]],
        result: ScanResult,
        context: str = "",
    ) -> int:
        """Emit explicit embedded secret checks from detector findings and return the count."""
        for finding in findings:
            severity_map = {
                "CRITICAL": IssueSeverity.CRITICAL,
                "WARNING": IssueSeverity.WARNING,
                "INFO": IssueSeverity.INFO,
            }
            severity = severity_map.get(finding.get("severity", "WARNING"), IssueSeverity.WARNING)
            secret_descriptor = str(
                finding.get("secret_type") or finding.get("type") or finding.get("message") or "embedded_secret"
            )
            secret_rule_code = get_secret_rule_code(secret_descriptor)

            result.add_check(
                name="Embedded Secrets Detection",
                passed=False,
                message=finding.get("message", "Secret detected"),
                rule_code=secret_rule_code,
                severity=severity,
                location=finding.get("context", context),
                details=finding,
                why=finding.get("recommendation", "Remove sensitive data from model"),
            )

        if not findings and context and not self._raw_detector_failed(result, "embedded_secrets"):
            result.add_check(
                name="Embedded Secrets Detection",
                passed=True,
                message="No embedded secrets detected",
                location=context,
            )

        return len(findings)

    def collect_jit_script_findings(
        self,
        data: bytes,
        model_type: str = "unknown",
        context: str = "",
        enable_check: bool = True,
        raise_on_error: bool = False,
        result: ScanResult | None = None,
    ) -> list[dict]:
        """Collect JIT/script code findings without creating checks.

        Args:
            data: Binary model data to check
            model_type: Type of model (pytorch, tensorflow, etc.)
            context: Context string for reporting
            enable_check: Whether to perform the check (allows disabling)
            raise_on_error: Whether detector failures should propagate to the caller

        Returns:
            List of findings
        """
        if not enable_check or not self.config.get("check_jit_script", True):
            return []

        try:
            from modelaudit.detectors.jit_script import JITScriptDetector

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
            if raise_on_error:
                raise
            logger.debug("JITScriptDetector not available, skipping JIT/Script check")
            if result is not None:
                self._mark_raw_detector_analysis_incomplete(
                    result,
                    detector="jit_script",
                    context=context,
                    coverage_gap="detector_unavailable",
                )
            return []
        except Exception as e:
            if raise_on_error:
                raise
            logger.warning("Error checking for JIT/Script code: %s", redact_untrusted_error_message(e))
            if result is not None:
                self._mark_raw_detector_analysis_incomplete(
                    result,
                    detector="jit_script",
                    context=context,
                    error=e,
                )
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

            # Sanitize example findings to reduce PII/oversized fields
            sanitized_findings: list[dict] = []
            for f in findings[:10]:
                try:
                    d = dict(f)
                except Exception:
                    d = {"value": str(f)}
                d.pop("matched_text", None)
                for k, v in list(d.items()):
                    if isinstance(v, str) and len(v) > 200:
                        d[k] = v[:200] + "..."
                sanitized_findings.append(d)

            result.add_check(
                name="JIT/Script Code Execution Summary",
                passed=False,
                message=f"Found {len(findings)} JIT/Script code risks across file",
                severity=max_severity,
                location=context,
                details={
                    "findings_count": len(findings),
                    "findings": sanitized_findings,  # Redacted examples
                    "total_findings": len(findings),
                    "aggregated": True,
                    "aggregation_type": "summary",
                },
                why="JIT/Script code patterns can execute arbitrary code during model loading",
            )
        elif not self._raw_detector_failed(result, "jit_script"):
            result.add_check(
                name="JIT/Script Code Execution Summary",
                passed=True,
                message="No JIT/Script code execution risks detected",
                location=context,
                details={
                    "aggregated": True,
                    "aggregation_type": "summary",
                },
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
            from modelaudit.detectors.jit_script import JITScriptDetector

            detector = JITScriptDetector(self.config.get("jit_script_config"))
            findings = detector.scan_model(data, model_type, context)
            return self.add_jit_script_findings(findings, result, model_type=model_type, context=context)

        except ImportError:
            # JITScriptDetector not available, log as debug
            logger.debug("JITScriptDetector not available, skipping JIT/Script check")
            self._mark_raw_detector_analysis_incomplete(
                result,
                detector="jit_script",
                context=context,
                coverage_gap="detector_unavailable",
            )
            return 0
        except Exception as e:
            logger.warning("Error checking for JIT/Script code: %s", redact_untrusted_error_message(e))
            self._mark_raw_detector_analysis_incomplete(
                result,
                detector="jit_script",
                context=context,
                error=e,
            )
            return 0

    def add_jit_script_findings(
        self,
        findings: list[Any],
        result: ScanResult,
        model_type: str = "unknown",
        context: str = "",
    ) -> int:
        """Emit explicit JIT/Script checks from detector findings and return the count."""
        severity_map = {
            "CRITICAL": IssueSeverity.CRITICAL,
            "WARNING": IssueSeverity.WARNING,
            "INFO": IssueSeverity.INFO,
        }

        for finding in findings:
            # Handle both dict and Pydantic model findings.
            if hasattr(finding, "model_dump"):
                severity_value = finding.severity if isinstance(finding.severity, str) else finding.severity.value
                severity = severity_map.get(severity_value, IssueSeverity.WARNING)
                message = finding.message
                location = finding.context
                recommendation = finding.recommendation or "Review JIT/Script code for security"
                details = finding.model_dump()
            elif hasattr(finding, "get"):
                severity = severity_map.get(finding.get("severity", "WARNING"), IssueSeverity.WARNING)
                message = finding.get("message", "JIT/Script code risk detected")
                location = finding.get("context", context)
                recommendation = finding.get("recommendation", "Review JIT/Script code for security")
                details = dict(finding)
            else:
                severity_value = getattr(finding, "severity", "WARNING")
                severity = severity_map.get(severity_value, IssueSeverity.WARNING)
                message = getattr(finding, "message", "JIT/Script code risk detected")
                location = getattr(finding, "context", context)
                recommendation = getattr(finding, "recommendation", "Review JIT/Script code for security")
                details = finding.__dict__ if hasattr(finding, "__dict__") else {"object": str(finding)}

            finding_details = details.get("details") if isinstance(details, dict) else None
            if isinstance(finding_details, dict) and finding_details.get("analysis_incomplete"):
                reason = finding_details.get("reason")
                mark_inconclusive_scan_result(
                    result,
                    reason if isinstance(reason, str) and reason else "jit_script_analysis_incomplete",
                )

            jit_indicator = f"{details.get('type', '')} {message} {model_type}".strip()
            jit_rule_code = get_embedded_code_rule_code(jit_indicator)
            if not jit_rule_code:
                # JIT detector findings should consistently map to the JIT/TorchScript rule family.
                jit_rule_code = get_embedded_code_rule_code("jit")

            result.add_check(
                name="JIT/Script Code Execution Detection",
                passed=False,
                message=message,
                rule_code=jit_rule_code,
                severity=severity,
                location=location,
                details=details,
                why=recommendation,
            )

        if not findings and context and not self._raw_detector_failed(result, "jit_script"):
            result.add_check(
                name="JIT/Script Code Execution Detection",
                passed=True,
                message="No JIT/Script code execution risks detected",
                location=context,
            )

        return len(findings)

    def collect_network_communication_findings(
        self,
        data: bytes,
        context: str = "",
        enable_check: bool = True,
        raise_on_error: bool = False,
        max_findings: int | None = None,
        result: ScanResult | None = None,
    ) -> list[dict]:
        """Collect network communication findings without creating checks.

        Args:
            data: Binary model data to check
            context: Context string for reporting
            enable_check: Whether to perform the check (allows disabling)
            raise_on_error: Whether detector failures should propagate to the caller

        Returns:
            List of findings
        """
        if not enable_check or not self._get_bool_config("check_network_comm", True):
            return []

        try:
            from modelaudit.detectors.network_comm import NetworkCommDetector

            detector_config = self.config.get("network_comm_config")
            if max_findings is not None:
                if detector_config is not None and not isinstance(detector_config, dict):
                    raise TypeError("network_comm_config must be a mapping")
                detector_config = {**(detector_config or {}), "max_findings": max_findings}
            detector = NetworkCommDetector(detector_config)
            findings = detector.scan(data, context)
            return [dict(finding) for finding in findings]

        except ImportError:
            if raise_on_error:
                raise
            logger.debug("NetworkCommDetector not available, skipping network comm check")
            if result is not None:
                self._mark_raw_detector_analysis_incomplete(
                    result,
                    detector="network_communication",
                    context=context,
                    coverage_gap="detector_unavailable",
                )
            return []
        except Exception as e:
            if raise_on_error:
                raise
            logger.warning("Error checking for network communication: %s", redact_untrusted_error_message(e))
            if result is not None:
                self._mark_raw_detector_analysis_incomplete(
                    result,
                    detector="network_communication",
                    context=context,
                    error=e,
                )
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
            # Downgrade URL detections to INFO severity since URLs in model data
            # (vocabularies, training text) are not active security threats
            severity_map = {
                "CRITICAL": IssueSeverity.INFO,  # Downgraded from CRITICAL
                "HIGH": IssueSeverity.INFO,  # Downgraded from CRITICAL
                "MEDIUM": IssueSeverity.INFO,  # Downgraded from WARNING
                "LOW": IssueSeverity.INFO,
            }

            # All URL detections now use INFO severity
            max_severity = IssueSeverity.INFO
            for finding in findings:
                finding_severity = severity_map.get(finding.get("severity", "INFO"), IssueSeverity.INFO)
                # All findings are now INFO level
                max_severity = finding_severity

            # Extract unique patterns for the message
            unique_patterns: set[str] = set()
            for finding in findings[:10]:  # Check first 10 findings for patterns
                # Check multiple fields for pattern information
                # Exclude 'matched_text' to reduce PII leakage
                for field in ["pattern", "domain", "url", "message"]:
                    pattern = str(finding.get(field, "") or "").strip()
                    if pattern and len(pattern) < 50:
                        # Add short, meaningful patterns (avoid very long strings)
                        unique_patterns.add(pattern)

            # Sanitize example findings to reduce PII/oversized fields
            sanitized_findings: list[dict] = []
            for f in findings[:10]:
                try:
                    d = dict(f)
                except Exception:
                    d = {"value": str(f)}
                d.pop("matched_text", None)
                for k, v in list(d.items()):
                    if isinstance(v, str) and len(v) > 200:
                        d[k] = v[:200] + "..."
                sanitized_findings.append(d)

            pattern_summary = ", ".join(sorted(unique_patterns)[:5]) if unique_patterns else "various patterns"
            result.add_check(
                name="Network Communication Summary",
                passed=False,
                message=f"Found {len(findings)} network communication patterns ({pattern_summary}) across file",
                severity=max_severity,
                location=context,
                details={
                    "findings_count": len(findings),
                    "findings": sanitized_findings,  # Redacted examples
                    "total_findings": len(findings),
                    "patterns": sorted(unique_patterns)[:10],
                    "aggregated": True,
                    "aggregation_type": "summary",
                },
                why="Models should not contain network communication capabilities",
            )
        elif not self._raw_detector_failed(result, "network_communication"):
            result.add_check(
                name="Network Communication Summary",
                passed=True,
                message="No network communication patterns detected",
                location=context,
                details={
                    "aggregated": True,
                    "aggregation_type": "summary",
                },
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
        if not enable_check or not self._get_bool_config("check_network_comm", True):
            return 0

        try:
            from modelaudit.detectors.network_comm import NetworkCommDetector

            detector = NetworkCommDetector(self.config.get("network_comm_config"))
            findings = detector.scan(data, context)
            return self.add_network_communication_findings(findings, result, context=context)

        except ImportError:
            # NetworkCommDetector not available, log as debug
            logger.debug("NetworkCommDetector not available, skipping network comm check")
            self._mark_raw_detector_analysis_incomplete(
                result,
                detector="network_communication",
                context=context,
                coverage_gap="detector_unavailable",
            )
            return 0
        except Exception as e:
            logger.warning("Error checking for network communication: %s", redact_untrusted_error_message(e))
            self._mark_raw_detector_analysis_incomplete(
                result,
                detector="network_communication",
                context=context,
                error=e,
            )
            return 0

    def add_network_communication_findings(
        self,
        findings: list[dict[str, Any]],
        result: ScanResult,
        context: str = "",
    ) -> int:
        """Emit explicit network communication checks from detector findings and return the count."""
        for finding in findings:
            severity_map = {
                "CRITICAL": IssueSeverity.CRITICAL,
                "HIGH": IssueSeverity.CRITICAL,
                "WARNING": IssueSeverity.WARNING,
                "MEDIUM": IssueSeverity.WARNING,
                "LOW": IssueSeverity.INFO,
                "INFO": IssueSeverity.INFO,
                "DEBUG": IssueSeverity.DEBUG,
            }
            finding_severity = str(finding.get("severity", "WARNING")).upper()
            severity = severity_map.get(finding_severity, IssueSeverity.WARNING)
            network_indicator = " ".join(
                str(part)
                for part in [
                    finding.get("type", ""),
                    finding.get("message", ""),
                    finding.get("pattern", ""),
                    finding.get("pattern_type", ""),
                    finding.get("domain", ""),
                    finding.get("url", ""),
                ]
                if part
            )
            network_rule_code = get_network_rule_code(network_indicator)

            result.add_check(
                name="Network Communication Detection",
                passed=False,
                message=finding.get("message", "Network communication pattern detected"),
                rule_code=network_rule_code,
                severity=severity,
                location=finding.get("context", context),
                details=finding,
                why="Models should not contain network communication capabilities",
            )

        if not findings and context and not self._raw_detector_failed(result, "network_communication"):
            result.add_check(
                name="Network Communication Detection",
                passed=True,
                message="No network communication patterns detected",
                location=context,
            )

        return len(findings)

    def _check_path(self, path: str) -> ScanResult | None:
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
                from modelaudit.utils.file.detection import (
                    detect_file_format_from_magic,
                    detect_format_from_extension,
                    validate_file_type,
                )

                format_validation = self.config.get(FORMAT_VALIDATION_CONFIG_KEY)
                if isinstance(format_validation, dict) and format_validation.get("path") == os.path.abspath(path):
                    file_type_valid = bool(format_validation.get("file_type_valid", True))
                    header_format = str(format_validation.get("header_format", "unknown"))
                    ext_format = str(format_validation.get("extension_format", "unknown"))
                else:
                    file_type_valid = validate_file_type(path)
                    header_format = "unknown"
                    ext_format = "unknown"

                if not file_type_valid:
                    if header_format == "unknown" and ext_format == "unknown":
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
                        severity=IssueSeverity.INFO,  # Informational - format mismatch not necessarily a security issue
                        location=path,
                        details={
                            "header_format": header_format,
                            "extension_format": ext_format,
                            "security_check": "file_type_validation",
                        },
                        rule_code="S901",  # File type mismatch
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

    def calculate_file_hashes(self, path: str) -> dict[str, str | None]:
        """Calculate MD5, SHA256, and SHA512 hashes of a file.

        Returns a dictionary with hash values or None if calculation fails.
        Uses None instead of empty strings to satisfy Pydantic validation.
        """
        hashes: dict[str, str | None] = {"md5": None, "sha256": None, "sha512": None}

        if not os.path.isfile(path):
            return hashes

        try:
            # Calculate all hashes in a single pass for efficiency
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            sha512_hash = hashlib.sha512()

            with open(path, "rb") as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(DEFAULT_READ_CHUNK_SIZE), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    sha512_hash.update(chunk)

            hashes["md5"] = md5_hash.hexdigest()
            hashes["sha256"] = sha256_hash.hexdigest()
            hashes["sha512"] = sha512_hash.hexdigest()

        except Exception as e:
            logger.warning(f"Failed to calculate hashes for {path}: {e}")
            # Return None hashes on error - Pydantic will accept None but not empty strings

        return hashes

    def _check_size_limit(self, path: str) -> ScanResult | None:
        """Check if the file exceeds the configured size limit."""
        file_size = self.get_file_size(path)

        if self.max_file_read_size and self.max_file_read_size > 0 and file_size > self.max_file_read_size:
            result = self._create_result()
            result.metadata["file_size"] = file_size
            result.metadata["analysis_incomplete"] = True
            result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
            result.metadata["scan_outcome_reasons"] = ["max_file_read_size_exceeded"]
            result.add_check(
                name="File Size Limit",
                passed=False,
                message=f"File too large: {file_size} bytes (max: {self.max_file_read_size})",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "file_size": file_size,
                    "max_file_read_size": self.max_file_read_size,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "max_file_read_size_exceeded",
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
                self._path_validation_result = ScanResult(scanner_name=self.name, scanner=self)
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
                self._path_validation_result = ScanResult(scanner_name=self.name, scanner=self)
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

    def _prepare_progress_for_scan(self, path: str) -> None:
        """Initialize progress tracking and set up file-level progress state."""
        self.current_file_path = path

        if PROGRESS_AVAILABLE and self._enable_progress and not self.progress_tracker:
            self._initialize_progress_tracker()

        if self.progress_tracker:
            self._setup_progress_for_file(path)

    def _finalize_progress_for_scan(self, error: Exception | None = None) -> None:
        """Complete progress tracking or report a scan error."""
        if error is None:
            self._complete_progress()
            return

        self._report_progress_error(error)

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
        self._prepare_progress_for_scan(path)

        try:
            result = self.scan(path)
            self._finalize_progress_for_scan()
            return result
        except Exception as e:
            self._finalize_progress_for_scan(e)
            raise

    def get_progress_stats(self) -> dict[str, Any] | None:
        """Get current progress statistics."""
        if self.progress_tracker:
            return self.progress_tracker.get_stats()
        return None

    def add_progress_reporter(self, reporter: Any) -> None:
        """Add a progress reporter to this scanner."""
        self._add_progress_observer("add_reporter", reporter)

    def add_progress_callback(self, callback: Any) -> None:
        """Add a progress callback to this scanner."""
        self._add_progress_observer("add_callback", callback)

    def _add_progress_observer(
        self,
        method_name: Literal["add_reporter", "add_callback"],
        observer: Any,
    ) -> None:
        """Attach a progress reporter or callback, initializing tracking if needed."""
        # Initialize progress tracker if not already done
        if PROGRESS_AVAILABLE and self._enable_progress and not self.progress_tracker:
            self._initialize_progress_tracker()

        if self.progress_tracker:
            getattr(self.progress_tracker, method_name)(observer)

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract metadata from model file. Override in subclasses for format-specific extraction."""
        return {
            "format": getattr(self, "name", "unknown"),
            "description": getattr(self, "description", ""),
            "file_size": self.get_file_size(file_path),
        }
