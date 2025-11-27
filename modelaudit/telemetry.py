"""
Telemetry system for ModelAudit - tracks usage analytics and performance metrics.
Follows privacy-first principles with comprehensive opt-out controls.
"""
# ruff: noqa: UP007

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar, Union, cast
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from . import __version__

# Type variable for generic function decoration
F = TypeVar("F", bound=Callable[..., Any])

try:
    from posthog import Posthog

    POSTHOG_AVAILABLE = True
except ImportError:
    POSTHOG_AVAILABLE = False
    Posthog = None

logger = logging.getLogger("modelaudit.telemetry")


def safe_telemetry(func: F) -> F:
    """
    Decorator that makes telemetry functions safe by catching all exceptions.

    This ensures telemetry failures never interrupt core functionality.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.debug(f"Telemetry function {func.__name__} failed silently: {e}")
            return None

    return cast(F, wrapper)


@contextmanager
def telemetry_context():
    """
    Context manager for safe telemetry operations.

    Ensures any telemetry errors don't propagate to core functionality.
    """
    try:
        yield
    except Exception as e:
        logger.debug(f"Telemetry operation failed silently: {e}")


def is_telemetry_available() -> bool:
    """Check if telemetry is available and working."""
    try:
        client = get_telemetry_client()
        if client is None:
            return False
        return not client._is_disabled()
    except Exception:
        return False


class TelemetryEvent(str, Enum):
    """Enumeration of all telemetry events that can be tracked."""

    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCANNER_USED = "scanner_used"
    FILE_TYPE_DETECTED = "file_type_detected"
    ISSUE_FOUND = "issue_found"
    COMMAND_USED = "command_used"
    FEATURE_USED = "feature_used"
    ERROR_OCCURRED = "error_occurred"
    PERFORMANCE_METRIC = "performance_metric"
    DOWNLOAD_STARTED = "download_started"
    DOWNLOAD_COMPLETED = "download_completed"


# PostHog configuration - follows Promptfoo's conventions
# Use PROMPTFOO_DISABLE_TELEMETRY=1 to disable (shared with Promptfoo)
POSTHOG_PROJECT_KEY = os.getenv("PROMPTFOO_POSTHOG_KEY", os.getenv("MODELAUDIT_POSTHOG_KEY", ""))
POSTHOG_HOST = os.getenv("PROMPTFOO_POSTHOG_HOST", "https://app.posthog.com")

# Promptfoo analytics endpoints for dual-track submission
EVENTS_ENDPOINT = "https://a.promptfoo.app"
KA_ENDPOINT = "https://ka.promptfoo.app/"
R_ENDPOINT = "https://r.promptfoo.app/"

# Timeout for analytics requests (in seconds)
ANALYTICS_TIMEOUT = 2.0


class UserConfig:
    """Manages user configuration and identity for telemetry."""

    def __init__(self):
        self._config_dir = Path.home() / ".modelaudit"
        self._config_file = self._config_dir / "user_config.json"
        self._config = self._load_config()

    def _load_config(self) -> dict[str, Any]:
        """Load user configuration from file."""
        if not self._config_file.exists():
            return {}

        try:
            with open(self._config_file) as f:
                config_data = json.load(f)
                return config_data if isinstance(config_data, dict) else {}
        except (json.JSONDecodeError, OSError) as e:
            logger.debug(f"Failed to load user config: {e}")
            return {}

    def _save_config(self) -> None:
        """Save user configuration to file."""
        try:
            self._config_dir.mkdir(exist_ok=True)
            with open(self._config_file, "w") as f:
                json.dump(self._config, f, indent=2)
        except OSError as e:
            logger.debug(f"Failed to save user config: {e}")

    @property
    def user_id(self) -> str:
        """Get or generate user ID."""
        if "user_id" not in self._config:
            self._config["user_id"] = str(uuid.uuid4())
            self._save_config()
        return str(self._config["user_id"])

    @property
    def email(self) -> str | None:
        """Get user email if available."""
        email = self._config.get("email")
        return str(email) if email is not None else None

    @email.setter
    def email(self, value: str | None) -> None:
        """Set user email."""
        if value:
            self._config["email"] = value
        elif "email" in self._config:
            del self._config["email"]
        self._save_config()

    @property
    def telemetry_enabled(self) -> bool:
        """Check if telemetry is enabled for this user."""
        # Default to TRUE - opt-out model for better analytics coverage
        # Users can disable via env var or config file
        enabled = self._config.get("telemetry_enabled", True)
        return bool(enabled)

    @telemetry_enabled.setter
    def telemetry_enabled(self, value: bool) -> None:
        """Set telemetry preference."""
        self._config["telemetry_enabled"] = value
        self._save_config()


class TelemetryClient:
    """Main telemetry client for ModelAudit analytics."""

    def __init__(self):
        self._user_config = UserConfig()
        self._posthog_client = None
        self._session_id = str(uuid.uuid4())
        self._telemetry_disabled_recorded = False

        # Initialize PostHog client if available and configured
        if POSTHOG_AVAILABLE and POSTHOG_PROJECT_KEY and not self._is_disabled():
            try:
                self._posthog_client = Posthog(
                    project_api_key=POSTHOG_PROJECT_KEY,
                    host=POSTHOG_HOST,
                )
                self._identify_user()
            except Exception as e:
                logger.debug(f"Failed to initialize PostHog client: {e}")
                self._posthog_client = None

    def _is_disabled(self) -> bool:
        """Check if telemetry is disabled via environment variables or user config."""
        # Check environment variables - use Promptfoo's standard env var
        if os.getenv("PROMPTFOO_DISABLE_TELEMETRY", "").lower() in ("1", "true", "yes"):
            return True
        if os.getenv("NO_ANALYTICS", "").lower() in ("1", "true", "yes"):
            return True
        if os.getenv("CI", "").lower() in ("1", "true", "yes"):
            return True
        if os.getenv("IS_TESTING", "").lower() in ("1", "true", "yes"):
            return True

        # Check user configuration - defaults to enabled (opt-out model)
        return not self._user_config.telemetry_enabled

    def _identify_user(self) -> None:
        """Identify user to PostHog."""
        if not self._posthog_client or self._is_disabled():
            return

        try:
            properties = {
                "email": self._user_config.email,
                "modelaudit_version": __version__,
                "platform": os.name,
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            }

            self._posthog_client.identify(distinct_id=self._user_config.user_id, properties=properties)
        except Exception as e:
            logger.debug(f"Failed to identify user: {e}")

    def _record_telemetry_disabled(self) -> None:
        """Mark that telemetry was disabled (no network calls for true decoupling)."""
        if not self._telemetry_disabled_recorded:
            # Just mark that we've acknowledged telemetry is disabled - no actual recording
            self._telemetry_disabled_recorded = True

    def _send_event_internal(self, event: TelemetryEvent, properties: dict[str, Any]) -> None:
        """Internal method to send events without checking disabled state."""
        event_properties = {
            **properties,
            "modelaudit_version": __version__,
            "session_id": self._session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": self._user_config.user_id,
            "platform": os.name,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        }

        # Send to PostHog if available
        if self._posthog_client:
            try:
                self._posthog_client.capture(
                    distinct_id=self._user_config.user_id, event=event.value, properties=event_properties
                )
            except Exception as e:
                logger.debug(f"Failed to send event to PostHog: {e}")

        # Send to Promptfoo's analytics endpoints for consistency
        self._send_to_promptfoo_endpoints(event.value, event_properties)

    def _send_to_promptfoo_endpoints(self, event: str, properties: dict[str, Any]) -> None:
        """Send event to Promptfoo's analytics endpoints following their pattern."""
        # Send to KA endpoint (following Promptfoo's pattern)
        try:
            ka_payload = {
                "profile_id": self._user_config.user_id,
                "email": self._hash_email(self._user_config.email),
                "events": [
                    {
                        "message_id": str(uuid.uuid4()),
                        "type": "track",
                        "event": event,
                        "properties": properties,
                        "sent_at": datetime.utcnow().isoformat(),
                    }
                ],
            }

            data = json.dumps(ka_payload).encode("utf-8")
            req = Request(
                KA_ENDPOINT,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"ModelAudit/{__version__}",
                },
            )

            with urlopen(req, timeout=ANALYTICS_TIMEOUT) as response:
                if response.status != 200:
                    logger.debug(f"KA endpoint returned status {response.status}")

        except (URLError, OSError) as e:
            logger.debug(f"Failed to send event to KA endpoint: {e}")

        # Send to R endpoint (following Promptfoo's pattern)
        try:
            r_payload = {
                "event": event,
                "environment": os.getenv("NODE_ENV", "development"),
                "email": self._hash_email(self._user_config.email),
                "meta": {
                    "user_id": self._user_config.user_id,
                    **properties,
                },
            }

            data = json.dumps(r_payload).encode("utf-8")
            req = Request(
                R_ENDPOINT,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"ModelAudit/{__version__}",
                },
            )

            with urlopen(req, timeout=ANALYTICS_TIMEOUT) as response:
                if response.status != 200:
                    logger.debug(f"R endpoint returned status {response.status}")

        except (URLError, OSError) as e:
            logger.debug(f"Failed to send event to R endpoint: {e}")

    def record_event(self, event: TelemetryEvent, properties: dict[str, Any] | None = None) -> None:
        """Record a telemetry event."""
        if properties is None:
            properties = {}

        if self._is_disabled():
            # Record that telemetry is disabled, but only once per session
            self._record_telemetry_disabled()
            return

        try:
            self._send_event_internal(event, properties)
        except Exception as e:
            logger.debug(f"Failed to record telemetry event: {e}")

    def _extract_model_name(self, path: str) -> str | None:
        """Extract model name from path or URL."""
        # HuggingFace format: hf://org/model or https://huggingface.co/org/model
        if "huggingface.co/" in path or path.startswith("hf://"):
            parts = path.replace("hf://", "").replace("https://huggingface.co/", "").split("/")
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
        # PyTorch Hub format: pytorch://org/repo/model
        if "pytorch" in path.lower() and "/" in path:
            parts = path.split("/")
            return "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
        # Local file: just the filename
        if "/" in path or "\\" in path:
            return Path(path).name
        return path

    def record_scan_started(self, paths: list[str], scan_options: dict[str, Any]) -> None:
        """Record that a scan has started."""
        self.record_event(
            TelemetryEvent.SCAN_STARTED,
            {
                "num_paths": len(paths),
                "paths": paths,
                "model_names": [self._extract_model_name(p) for p in paths],
                "source_types": [self._classify_source_type(p) for p in paths],
                "path_types": [self._classify_path(path) for path in paths],
                "timeout": scan_options.get("timeout"),
                "max_file_size": scan_options.get("max_file_size"),
                "format": scan_options.get("format", "text"),
                "has_blacklist": scan_options.get("has_blacklist", False),
                "num_blacklist_patterns": scan_options.get("num_blacklist_patterns", 0),
                "progress_enabled": scan_options.get("progress", True),
            },
        )

    def _classify_source_type(self, path: str) -> str:
        """Classify the source type of a path."""
        if "huggingface" in path.lower() or path.startswith("hf://"):
            return "huggingface"
        if "pytorch" in path.lower():
            return "pytorch_hub"
        if path.startswith("s3://"):
            return "s3"
        if path.startswith("gs://"):
            return "gcs"
        if path.startswith("http"):
            return "http"
        return "local"

    def record_scan_completed(self, duration: float, results: dict[str, Any]) -> None:
        """Record that a scan has completed successfully."""
        # Collect all unique issue types with counts
        issue_types: dict[str, int] = {}
        issue_details: list[dict[str, Any]] = []
        for asset in results.get("assets", []):
            file_path = asset.get("path", "")
            model_name = self._extract_model_name(file_path) if file_path else None
            for issue in asset.get("issues", []):
                issue_type = issue.get("message", "unknown")
                severity = issue.get("severity", "unknown")
                issue_types[issue_type] = issue_types.get(issue_type, 0) + 1
                # Capture first 50 issues in detail
                if len(issue_details) < 50:
                    issue_details.append(
                        {
                            "type": issue_type,
                            "severity": severity,
                            "scanner": issue.get("scanner", "unknown"),
                            "file_path": file_path,
                            "model_name": model_name,
                        }
                    )

        self.record_event(
            TelemetryEvent.SCAN_COMPLETED,
            {
                "duration": duration,
                "total_files": len(results.get("assets", [])),
                "total_issues": sum(len(asset.get("issues", [])) for asset in results.get("assets", [])),
                "issue_severities": self._count_issue_severities(results),
                "file_types": self._count_file_types(results),
                "scanners_used": list(
                    {scanner for asset in results.get("assets", []) for scanner in asset.get("scanners_used", [])}
                ),
                "issue_types": issue_types,
                "issue_details": issue_details,
                "files_scanned": [asset.get("path", "") for asset in results.get("assets", [])],
            },
        )

    def record_scan_failed(self, duration: float, error: Union[Exception, str]) -> None:
        """Record that a scan has failed."""
        self.record_event(
            TelemetryEvent.SCAN_FAILED,
            {
                "duration": duration,
                "error_type": type(error).__name__ if isinstance(error, Exception) else "str",
                "error_message": self._sanitize_error(error),
            },
        )

    def record_scanner_used(self, scanner_name: str, file_type: str, duration: float) -> None:
        """Record usage of a specific scanner."""
        self.record_event(
            TelemetryEvent.SCANNER_USED,
            {
                "scanner": scanner_name,
                "file_type": file_type,
                "duration": duration,
            },
        )

    def record_file_type_detected(self, file_path: str, detected_type: str, confidence: float = 1.0) -> None:
        """Record detection of a file type."""
        self.record_event(
            TelemetryEvent.FILE_TYPE_DETECTED,
            {
                "file_type": detected_type,
                "confidence": confidence,
                "file_extension": Path(file_path).suffix.lower(),
                "path_type": self._classify_path(file_path),
                "file_path": file_path,
                "model_name": self._extract_model_name(file_path),
            },
        )

    def record_issue_found(
        self,
        issue_type: str,
        severity: str,
        scanner: str,
        file_path: str | None = None,
    ) -> None:
        """Record that a security issue was found."""
        properties: dict[str, Any] = {
            "severity": severity,
            "scanner": scanner,
            "issue_type": issue_type,
            "issue_message": issue_type,  # Full message for analytics
        }

        if file_path:
            properties["file_path"] = file_path
            properties["model_name"] = self._extract_model_name(file_path)
            properties["file_extension"] = Path(file_path).suffix.lower()

        self.record_event(TelemetryEvent.ISSUE_FOUND, properties)

    def record_command_used(self, command: str, duration: float | None = None, **kwargs: Any) -> None:
        """Record usage of a CLI command."""
        properties: dict[str, Any] = {"command": command, **kwargs}
        if duration is not None:
            properties["duration"] = duration

        self.record_event(TelemetryEvent.COMMAND_USED, properties)

    def record_feature_used(self, feature: str, **kwargs: Any) -> None:
        """Record usage of a specific feature."""
        self.record_event(TelemetryEvent.FEATURE_USED, {"feature": feature, **kwargs})

    def record_error(self, error: Exception, context: str | None = None) -> None:
        """Record an error occurrence."""
        self.record_event(
            TelemetryEvent.ERROR_OCCURRED,
            {
                "error_type": type(error).__name__,
                "error_message": self._sanitize_error(error),
                "context": context,
            },
        )

    def record_performance_metric(self, metric_name: str, value: Union[int, float], unit: str = "ms") -> None:
        """Record a performance metric."""
        self.record_event(
            TelemetryEvent.PERFORMANCE_METRIC,
            {
                "metric": metric_name,
                "value": value,
                "unit": unit,
            },
        )

    def record_download_started(self, source_type: str, url: str, size_bytes: int | None = None) -> None:
        """Record that a download has started."""
        self.record_event(
            TelemetryEvent.DOWNLOAD_STARTED,
            {
                "source_type": source_type,
                "domain": self._extract_domain(url),
                "size_bytes": size_bytes,
                "url": url,
                "model_name": self._extract_model_name(url),
            },
        )

    def record_download_completed(
        self, source_type: str, duration: float, size_bytes: int, url: str | None = None
    ) -> None:
        """Record that a download has completed."""
        properties: dict[str, Any] = {
            "source_type": source_type,
            "duration": duration,
            "size_bytes": size_bytes,
            "speed_mbps": (size_bytes / (1024 * 1024)) / duration if duration > 0 else 0,
        }

        if url:
            properties["url"] = url
            properties["model_name"] = self._extract_model_name(url)

        self.record_event(TelemetryEvent.DOWNLOAD_COMPLETED, properties)

    def flush(self) -> None:
        """Flush any pending analytics events."""
        if self._posthog_client:
            try:
                self._posthog_client.flush()
            except Exception as e:
                logger.debug(f"Failed to flush PostHog events: {e}")

    def _classify_path(self, path: str) -> str:
        """Classify a path for analytics purposes."""
        path_lower = path.lower()

        if path_lower.startswith(("http://", "https://")):
            if "huggingface.co" in path_lower:
                return "huggingface"
            elif "pytorch.org" in path_lower:
                return "pytorch_hub"
            elif "jfrog" in path_lower:
                return "jfrog"
            else:
                return "http"
        elif path_lower.startswith(("s3://", "gs://", "azure://")):
            return "cloud_storage"
        elif path_lower.startswith("models:/"):
            return "mlflow"
        elif path_lower.startswith("hf://"):
            return "huggingface_shorthand"
        elif os.path.isdir(path):
            return "directory"
        elif os.path.isfile(path):
            return "file"
        else:
            return "unknown"

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for analytics."""
        try:
            return urlparse(url).netloc
        except Exception:
            return "unknown"

    def _hash_path(self, path: str) -> str:
        """Hash file path for privacy while maintaining analytics value."""
        # Use SHA-256 hash of the path for privacy
        return hashlib.sha256(path.encode()).hexdigest()[:16]  # First 16 chars for brevity

    def _hash_url(self, url: str) -> str:
        """Hash URL for privacy while maintaining analytics value."""
        # Remove query parameters and hash the clean URL
        try:
            parsed = urlparse(url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            return hashlib.sha256(clean_url.encode()).hexdigest()[:16]
        except Exception:
            return hashlib.sha256(url.encode()).hexdigest()[:16]

    def _hash_email(self, email: str | None) -> str | None:
        """Hash email for privacy - only send domain for analytics."""
        if not email:
            return None
        try:
            # Only keep the domain part, hash the local part
            if "@" in email:
                local, domain = email.rsplit("@", 1)
                local_hash = hashlib.sha256(local.encode()).hexdigest()[:8]
                return f"{local_hash}@{domain}"
            return hashlib.sha256(email.encode()).hexdigest()[:16]
        except Exception:
            return None

    def _sanitize_issue_type(self, message: str) -> str:
        """Extract issue type from message, removing sensitive details."""
        # Common issue type patterns - extract just the category
        issue_patterns = [
            "malicious_code",
            "dangerous_import",
            "pickle_exploit",
            "code_execution",
            "suspicious_opcode",
            "unsafe_lambda",
            "network_access",
            "file_access",
            "encoded_payload",
            "blacklisted_model",
            "weight_anomaly",
            "metadata_issue",
            "secret_exposure",
            "path_traversal",
            "compression_bomb",
            "unsafe_deserialization",
        ]
        message_lower = message.lower()
        for pattern in issue_patterns:
            if pattern.replace("_", " ") in message_lower or pattern in message_lower:
                return pattern
        # If no pattern matches, return a generic category based on severity keywords
        # Check more specific patterns FIRST (pickle before code since pickle opcode contains "code")
        if any(kw in message_lower for kw in ["pickle", "opcode", "reduce"]):
            return "pickle_related"
        if any(kw in message_lower for kw in ["exec", "eval", "import", "code"]):
            return "code_execution_related"
        if any(kw in message_lower for kw in ["network", "url", "http"]):
            return "network_related"
        if any(kw in message_lower for kw in ["file", "path", "directory"]):
            return "file_related"
        return "other"

    def _sanitize_error(self, error: Union[Exception, str]) -> str:
        """Sanitize error message to remove sensitive information."""
        import re

        error_str = str(error)
        # Remove URLs FIRST (before path matching can break them)
        error_str = re.sub(r"https?://[^\s]+", "[URL]", error_str)
        # Remove Windows-style paths
        error_str = re.sub(r"[A-Za-z]:\\[\w.\\-]+", "[PATH]", error_str)
        # Remove Unix-style paths (must come after URLs)
        error_str = re.sub(r"/[\w./-]+", "[PATH]", error_str)
        # Remove anything that looks like a token/key
        error_str = re.sub(r"[A-Za-z0-9_-]{20,}", "[REDACTED]", error_str)
        # Truncate to reasonable length
        return error_str[:100]

    def _count_issue_severities(self, results: dict[str, Any]) -> dict[str, int]:
        """Count issues by severity."""
        severities: dict[str, int] = {}
        for asset in results.get("assets", []):
            for issue in asset.get("issues", []):
                severity = issue.get("severity", "unknown")
                severities[severity] = severities.get(severity, 0) + 1
        return severities

    def _count_file_types(self, results: dict[str, Any]) -> dict[str, int]:
        """Count scanned files by type."""
        file_types: dict[str, int] = {}
        for asset in results.get("assets", []):
            file_type = asset.get("file_type", "unknown")
            file_types[file_type] = file_types.get(file_type, 0) + 1
        return file_types


# Global telemetry client instance
_telemetry_client = None


def get_telemetry_client() -> TelemetryClient | None:
    """Get the global telemetry client instance."""
    global _telemetry_client
    try:
        if _telemetry_client is None:
            _telemetry_client = TelemetryClient()
        return _telemetry_client
    except Exception as e:
        logger.debug(f"Failed to initialize telemetry client: {e}")
        return None


# Convenience functions for common telemetry operations - all wrapped for safety
@safe_telemetry
def record_event(event: TelemetryEvent, properties: dict[str, Any] | None = None) -> None:
    """Record a telemetry event using the global client."""
    client = get_telemetry_client()
    if client is not None:
        client.record_event(event, properties)


@safe_telemetry
def record_scan_started(paths: list[str], scan_options: dict[str, Any]) -> None:
    """Record that a scan has started."""
    client = get_telemetry_client()
    if client is not None:
        client.record_scan_started(paths, scan_options)


@safe_telemetry
def record_scan_completed(duration: float, results: dict[str, Any]) -> None:
    """Record that a scan has completed."""
    client = get_telemetry_client()
    if client is not None:
        client.record_scan_completed(duration, results)


@safe_telemetry
def record_scan_failed(duration: float, error: Union[Exception, str]) -> None:
    """Record that a scan has failed."""
    client = get_telemetry_client()
    if client is not None:
        client.record_scan_failed(duration, error)


@safe_telemetry
def record_command_used(command: str, duration: float | None = None, **kwargs: Any) -> None:
    """Record usage of a CLI command."""
    client = get_telemetry_client()
    if client is not None:
        client.record_command_used(command, duration, **kwargs)


@safe_telemetry
def record_feature_used(feature: str, **kwargs: Any) -> None:
    """Record usage of a specific feature."""
    client = get_telemetry_client()
    if client is not None:
        client.record_feature_used(feature, **kwargs)


@safe_telemetry
def record_scanner_used(scanner_name: str, file_type: str, duration: float) -> None:
    """Record usage of a specific scanner."""
    client = get_telemetry_client()
    if client is not None:
        client.record_scanner_used(scanner_name, file_type, duration)


@safe_telemetry
def record_file_type_detected(file_path: str, detected_type: str, confidence: float = 1.0) -> None:
    """Record detection of a file type."""
    client = get_telemetry_client()
    if client is not None:
        client.record_file_type_detected(file_path, detected_type, confidence)


@safe_telemetry
def record_issue_found(issue_type: str, severity: str, scanner: str, file_path: str | None = None) -> None:
    """Record that a security issue was found."""
    client = get_telemetry_client()
    if client is not None:
        client.record_issue_found(issue_type, severity, scanner, file_path)


@safe_telemetry
def record_download_started(source_type: str, url: str, size_bytes: int | None = None) -> None:
    """Record that a download has started."""
    client = get_telemetry_client()
    if client is not None:
        client.record_download_started(source_type, url, size_bytes)


@safe_telemetry
def record_download_completed(source_type: str, duration: float, size_bytes: int, url: str | None = None) -> None:
    """Record that a download has completed."""
    client = get_telemetry_client()
    if client is not None:
        client.record_download_completed(source_type, duration, size_bytes, url)


@safe_telemetry
def flush_telemetry() -> None:
    """Flush any pending telemetry events."""
    if _telemetry_client is not None:
        _telemetry_client.flush()


@safe_telemetry
def disable_telemetry() -> None:
    """Disable telemetry for the current user."""
    client = get_telemetry_client()
    if client is not None:
        client._user_config.telemetry_enabled = False


@safe_telemetry
def enable_telemetry() -> None:
    """Enable telemetry for the current user."""
    client = get_telemetry_client()
    if client is not None:
        client._user_config.telemetry_enabled = True


def is_telemetry_enabled() -> bool:
    """Check if telemetry is enabled."""
    try:
        client = get_telemetry_client()
        if client is None:
            return False
        return not client._is_disabled()
    except Exception:
        return False
