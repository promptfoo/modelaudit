"""
Event definitions and collection for ModelAudit telemetry.

Implements PostHog 2025 best practices for event naming and structure.
Event naming convention: category:object_action
"""

import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Optional


class EventType(Enum):
    """Event type enumeration following PostHog naming conventions."""

    # CLI Events (category: cli)
    CLI_SCAN_START = "cli:scan_command_start"
    CLI_SCAN_COMPLETE = "cli:scan_command_complete"
    CLI_SCAN_ERROR = "cli:scan_command_error"
    CLI_VERSION_CHECK = "cli:version_command_execute"
    CLI_HELP_VIEW = "cli:help_command_execute"

    # Scanner Events (category: scanner)
    SCANNER_EXECUTE = "scanner:file_scan_execute"
    SCANNER_COMPLETE = "scanner:file_scan_complete"
    SCANNER_ERROR = "scanner:file_scan_error"
    SCANNER_TIMEOUT = "scanner:scan_timeout"
    SCANNER_SKIP = "scanner:file_skip"

    # File Processing Events (category: file)
    FILE_DETECT_FORMAT = "file:format_detect"
    FILE_SIZE_CHECK = "file:size_validate"
    FILE_READ_START = "file:content_read_start"
    FILE_READ_COMPLETE = "file:content_read_complete"

    # Issue Detection Events (category: issue)
    ISSUE_CRITICAL_FOUND = "issue:critical_security_detect"
    ISSUE_WARNING_FOUND = "issue:warning_security_detect"
    ISSUE_INFO_FOUND = "issue:info_security_detect"

    # Performance Events (category: performance)
    PERFORMANCE_SCAN_DURATION = "performance:scan_duration_measure"
    PERFORMANCE_MEMORY_USAGE = "performance:memory_usage_measure"
    PERFORMANCE_THROUGHPUT = "performance:bytes_throughput_measure"

    # Error Events (category: error)
    ERROR_EXCEPTION = "error:exception_occur"
    ERROR_FILE_ACCESS = "error:file_access_fail"
    ERROR_SCANNER_CRASH = "error:scanner_crash_occur"
    ERROR_TIMEOUT = "error:operation_timeout_occur"

    # Configuration Events (category: config)
    CONFIG_TELEMETRY_ENABLE = "config:telemetry_enable"
    CONFIG_TELEMETRY_DISABLE = "config:telemetry_disable"


@dataclass
class BaseEventData:
    """Base class for event data with common properties."""

    # Core identification
    session_id: str
    modelaudit_version: str
    python_version: str
    platform: str

    # Timing
    timestamp: float
    duration_ms: Optional[float] = None

    # Context
    is_ci_environment: bool = False
    is_development_mode: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, filtering None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ScanEventData(BaseEventData):
    """Event data for scan operations."""

    # Scan context
    total_files: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    scan_duration_ms: Optional[float] = None

    # Results
    issues_critical: int = 0
    issues_warning: int = 0
    issues_info: int = 0
    issues_total: int = 0

    # Configuration
    max_file_size: int = 0
    timeout_seconds: int = 300
    blacklist_patterns_count: int = 0
    output_format: str = "text"

    # File types processed
    file_extensions: Optional[str] = None  # Comma-separated list
    scanners_used: Optional[str] = None  # Comma-separated list


@dataclass
class ScannerEventData(BaseEventData):
    """Event data for individual scanner operations."""

    # Scanner identification
    scanner_name: str = "unknown"
    scanner_version: Optional[str] = None

    # File context
    file_path_hash: Optional[str] = None  # SHA256 hash for privacy
    file_extension: Optional[str] = None
    file_size_bytes: int = 0

    # Processing details
    processing_duration_ms: Optional[float] = None
    bytes_processed: int = 0

    # Results
    issues_found: int = 0
    highest_severity: str = "info"

    # Technical details
    memory_peak_mb: Optional[float] = None


@dataclass
class ErrorEventData(BaseEventData):
    """Event data for error tracking."""

    # Error identification
    error_type: str = "unknown"
    error_message: str = ""
    component: str = "unknown"  # cli, scanner, core, etc.
    operation: str = "unknown"  # scan, detect, read, etc.
    
    # Optional fields with defaults
    error_code: Optional[str] = None
    file_path_hash: Optional[str] = None
    stack_trace_hash: Optional[str] = None  # Hashed for privacy
    memory_usage_mb: Optional[float] = None


@dataclass
class PerformanceEventData(BaseEventData):
    """Event data for performance metrics."""

    # Performance metrics
    cpu_usage_percent: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    disk_io_mb: Optional[float] = None

    # Throughput metrics
    files_per_second: Optional[float] = None
    bytes_per_second: Optional[float] = None

    # Resource limits
    max_memory_mb: Optional[float] = None
    timeout_seconds: int = 300


class EventCollector:
    """Collects and validates events before sending to PostHog."""

    def __init__(self, session_id: str, modelaudit_version: str):
        self.session_id = session_id
        self.modelaudit_version = modelaudit_version
        self._event_count = 0
        self._session_start_time = time.time()

    def create_base_event_data(self, **kwargs) -> BaseEventData:
        """Create base event data with common properties."""
        import platform
        import sys

        return BaseEventData(
            session_id=self.session_id,
            modelaudit_version=self.modelaudit_version,
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            platform=platform.system(),
            timestamp=time.time(),
            **kwargs,
        )

    def create_scan_event(self, **kwargs) -> ScanEventData:
        """Create scan event data."""
        base_data = self.create_base_event_data()
        return ScanEventData(**asdict(base_data), **kwargs)

    def create_scanner_event(self, **kwargs) -> ScannerEventData:
        """Create scanner event data."""
        base_data = self.create_base_event_data()
        return ScannerEventData(**asdict(base_data), **kwargs)

    def create_error_event(self, **kwargs) -> ErrorEventData:
        """Create error event data."""
        base_data = self.create_base_event_data()
        return ErrorEventData(**asdict(base_data), **kwargs)

    def create_performance_event(self, **kwargs) -> PerformanceEventData:
        """Create performance event data."""
        base_data = self.create_base_event_data()
        return PerformanceEventData(**asdict(base_data), **kwargs)

    def increment_event_count(self) -> int:
        """Increment and return the current event count."""
        self._event_count += 1
        return self._event_count

    @property
    def session_duration_ms(self) -> float:
        """Get the current session duration in milliseconds."""
        return (time.time() - self._session_start_time) * 1000
