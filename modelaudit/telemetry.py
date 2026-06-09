"""
Telemetry system for ModelAudit - tracks usage analytics and performance metrics.
Follows privacy-first principles with comprehensive opt-out controls.
"""
# ruff: noqa: UP007

from __future__ import annotations

import atexit
import json
import logging
import os
import re
import sys
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar, Union, cast
from urllib.parse import ParseResult, urlparse

import yaml

from .scanner_registry_metadata import get_registered_scanner_extensions
from .version import __version__

# Type variable for generic function decoration
F = TypeVar("F", bound=Callable[..., Any])

# PostHog client for analytics
# We use Any for the client type since posthog may not be installed
try:
    from posthog import Posthog

    POSTHOG_AVAILABLE = True
except ImportError:
    POSTHOG_AVAILABLE = False
    Posthog = None  # type: ignore[misc,assignment]

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
        if client._is_disabled():
            return False
        client._ensure_posthog_client()
        return client._posthog_client is not None
    except Exception:
        return False


class TelemetryEvent(str, Enum):
    """Enumeration of all telemetry events that can be tracked.

    All events are prefixed with 'modelaudit_' to distinguish from Promptfoo events
    when sharing the same PostHog project.
    """

    SCAN_STARTED = "modelaudit_scan_started"
    SCAN_COMPLETED = "modelaudit_scan_completed"
    SCAN_FAILED = "modelaudit_scan_failed"
    SCANNER_USED = "modelaudit_scanner_used"
    FILE_TYPE_DETECTED = "modelaudit_file_type_detected"
    ISSUE_FOUND = "modelaudit_issue_found"
    COMMAND_USED = "modelaudit_command_used"
    FEATURE_USED = "modelaudit_feature_used"
    ERROR_OCCURRED = "modelaudit_error_occurred"
    PERFORMANCE_METRIC = "modelaudit_performance_metric"
    DOWNLOAD_STARTED = "modelaudit_download_started"
    DOWNLOAD_COMPLETED = "modelaudit_download_completed"


# PostHog configuration - follows Promptfoo's conventions
# Use PROMPTFOO_DISABLE_TELEMETRY=1 to disable (shared with Promptfoo)
# Uses Promptfoo's analytics proxy by default for shared project
#
# NOTE: The project API key (phc_...) is a PUBLIC key, safe to commit to git.
# It can only write events, not read private data. This is standard practice
# for client-side analytics (browsers, mobile apps, CLIs).
# See: https://posthog.com/docs/api
_DEFAULT_POSTHOG_KEY = "phc_E5n5uHnDo2eREJL1uqX1cIlbkoRby4yFWt3V94HqRRg"
POSTHOG_PROJECT_KEY = os.getenv("PROMPTFOO_POSTHOG_KEY", os.getenv("MODELAUDIT_POSTHOG_KEY", _DEFAULT_POSTHOG_KEY))
POSTHOG_HOST = os.getenv("PROMPTFOO_POSTHOG_HOST", "https://a.promptfoo.app")
_TELEMETRY_RULE_CODE_RE = re.compile(r"\bS\d{3,4}\b", re.IGNORECASE)
_TELEMETRY_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TELEMETRY_STABLE_ISSUE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+){1,15}$")
_TELEMETRY_SECRETLIKE_ISSUE_ID_RE = re.compile(
    r"^(?:sk|pk|rk|ghp|github_pat|xox[baprs]?|glpat|hf|akia|asia)[_-]",
    re.IGNORECASE,
)
_TELEMETRY_FILELIKE_ISSUE_ID_RE = re.compile(
    r"\.(?:bin|ckpt|gguf|gz|h5|hdf5|json|keras|nemo|onnx|pb|pickle|pkl|pt|pth|safetensors|tar|yaml|yml|zip)$",
    re.IGNORECASE,
)
_TELEMETRY_SAFE_FILE_EXTENSIONS = frozenset(get_registered_scanner_extensions())
_TELEMETRY_OTHER_EXTENSION = "other_extension"
_TELEMETRY_SCAN_ERROR_CATEGORIES = {
    "No matching paths": "no_matching_paths",
    "Invalid max-size": "invalid_max_size",
    "Invalid scanner selection": "invalid_scanner_selection",
    "Scan completed with errors": "scan_completed_with_errors",
    "No paths provided": "no_paths_provided",
    "Unable to prepare scan output": "output_preparation_failed",
    "Unable to write scan output": "output_write_failed",
}
_TRUE_ENV_VALUES = frozenset({"1", "true", "yes", "yup", "yeppers"})
# Vars whose CI providers set a truthy literal ("true"/"1").
_CI_TRUTHY_ENV_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "TRAVIS",
    "CIRCLECI",
    "GITLAB_CI",
    "APPVEYOR",
    "TF_BUILD",
    "BUILDKITE",
    "BUDDY",
)
# Vars whose CI providers set a marker value (build ID, version, commit SHA),
# so any non-empty value indicates CI. Promptfoo's upstream `getEnvBool` misses
# these; we diverge intentionally so analytics filters work in the wild.
_CI_PRESENCE_ENV_VARS = (
    "JENKINS",
    "CODEBUILD_BUILD_ID",
    "BITBUCKET_COMMIT",
    "TEAMCITY_VERSION",
)


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").lower() in _TRUE_ENV_VALUES


def _env_present(name: str) -> bool:
    return bool(os.getenv(name, "").strip())


def _is_running_in_ci() -> bool:
    """Detect CI for the `isRunningInCi` telemetry property.

    Mirrors Promptfoo's variable list but uses presence-based detection for
    marker-style vars (TEAMCITY_VERSION, CODEBUILD_BUILD_ID, BITBUCKET_COMMIT,
    JENKINS) that providers set to non-truthy values like build IDs.
    """
    if any(_env_truthy(name) for name in _CI_TRUTHY_ENV_VARS):
        return True
    return any(_env_present(name) for name in _CI_PRESENCE_ENV_VARS)


def _is_development_install() -> bool:
    """Check if running from a development/editable install (pip install -e).

    This prevents polluting production analytics with development test data.
    Uses importlib.metadata to properly detect editable installs.
    See: https://stackoverflow.com/questions/43348746/how-to-detect-if-module-is-installed-in-editable-mode
    """
    if _env_truthy("MODELAUDIT_DEV"):
        return True

    try:
        from importlib.metadata import Distribution

        dist = Distribution.from_name("modelaudit")
        direct_url_text = dist.read_text("direct_url.json")
        if direct_url_text:
            direct_url = json.loads(direct_url_text)
            if direct_url.get("dir_info", {}).get("editable", False):
                return True
    except Exception as exc:
        logger.debug("Unable to inspect editable install metadata: %s", exc)

    return False


# Cache the development check at module load time
_IS_DEVELOPMENT = _is_development_install()

# Env vars that gate the telemetry client's behavior. Changes here invalidate
# the cached client; `_CI_PRESENCE_ENV_VARS` are excluded because they only
# tag events with `isRunningInCi` and don't change disable state.
_BEHAVIOR_GATING_ENV_VARS = (
    "MODELAUDIT_TELEMETRY_DEV",
    "PROMPTFOO_DISABLE_TELEMETRY",
    "NO_ANALYTICS",
    "CI",
    "IS_TESTING",
    "MODELAUDIT_TELEMETRY_FLUSH_IMMEDIATELY",
)


def _runtime_signature() -> tuple[Any, ...]:
    """Capture runtime state that affects the cached telemetry client."""
    return (
        str(Path.home()),
        POSTHOG_AVAILABLE,
        POSTHOG_PROJECT_KEY,
        POSTHOG_HOST,
        _IS_DEVELOPMENT,
        *(_env_truthy(name) for name in _BEHAVIOR_GATING_ENV_VARS),
    )


class UserConfig:
    """Manages user configuration and identity for telemetry."""

    def __init__(self):
        self._config_dir = Path.home() / ".modelaudit"
        self._config_file = self._config_dir / "user_config.json"
        self._promptfoo_config_file = Path.home() / ".promptfoo" / "promptfoo.yaml"
        self._config = self._load_config()
        self._promptfoo_config_cache: dict[str, Any] | None = None
        self._promptfoo_config_loaded = False

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

    def _load_promptfoo_config(self) -> dict[str, Any] | None:
        """Load Promptfoo's global config once, caching the result.

        Returns the loaded mapping (possibly empty if the file is absent), or
        None if the file is unreadable or contains non-mapping data.
        """
        if self._promptfoo_config_loaded:
            return self._promptfoo_config_cache

        self._promptfoo_config_loaded = True

        if not self._promptfoo_config_file.exists():
            self._promptfoo_config_cache = {}
            return self._promptfoo_config_cache

        try:
            with open(self._promptfoo_config_file) as f:
                loaded = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as exc:
            logger.debug("Unable to read promptfoo telemetry config: %s", exc)
            return None

        if loaded is None:
            self._promptfoo_config_cache = {}
        elif isinstance(loaded, dict):
            self._promptfoo_config_cache = cast(dict[str, Any], loaded)
        else:
            logger.debug("Ignoring non-object promptfoo telemetry config")
            return None

        return self._promptfoo_config_cache

    def _persist_user_id_to_promptfoo(self, user_id: str, config: dict[str, Any]) -> bool:
        """Write user_id into promptfoo.yaml using auth.config's hardened atomic writer.

        Skips the disk write when the file already holds the same id.
        """
        if config.get("id") == user_id:
            self._promptfoo_config_cache = config
            return True

        try:
            from .auth.config import _write_yaml_atomic

            self._promptfoo_config_file.parent.mkdir(parents=True, exist_ok=True)
            updated = {**config, "id": user_id}
            _write_yaml_atomic(self._promptfoo_config_file, updated)
        except (OSError, ImportError) as exc:
            logger.debug("Unable to write promptfoo telemetry config: %s", exc)
            return False

        self._promptfoo_config_cache = updated
        return True

    @property
    def user_id(self) -> str:
        """Return a stable identifier, preferring Promptfoo's for cross-tool correlation."""
        promptfoo_config = self._load_promptfoo_config()
        if promptfoo_config is not None:
            existing = promptfoo_config.get("id")
            if isinstance(existing, str) and existing:
                return existing

        legacy = self._config.get("user_id")
        user_id = legacy if isinstance(legacy, str) and legacy else str(uuid.uuid4())

        if promptfoo_config is not None and self._persist_user_id_to_promptfoo(user_id, promptfoo_config):
            return user_id

        if self._config.get("user_id") != user_id:
            self._config["user_id"] = user_id
            self._save_config()
        return user_id

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

    # Type annotation for PostHog client (Any since posthog may not be installed)
    _posthog_client: Any

    def __init__(self) -> None:
        self._runtime_signature = _runtime_signature()
        self._user_config = UserConfig()
        self._posthog_client = None
        self._session_id = str(uuid.uuid4())
        self._telemetry_disabled_recorded = False
        self._atexit_flush_registered = False
        self._flush_immediately = _env_truthy("MODELAUDIT_TELEMETRY_FLUSH_IMMEDIATELY")

        self._ensure_posthog_client()

    def _is_disabled(self) -> bool:
        """Check if telemetry is disabled via environment variables or user config."""
        # Editable installs are off by default; MODELAUDIT_TELEMETRY_DEV=1 opts back in.
        if _IS_DEVELOPMENT and not _env_truthy("MODELAUDIT_TELEMETRY_DEV"):
            return True

        # `CI` here is the universal opt-out flag. The broader `_is_running_in_ci()`
        # only tags events; events from marker-only providers still get sent.
        if any(_env_truthy(name) for name in ("PROMPTFOO_DISABLE_TELEMETRY", "NO_ANALYTICS", "CI", "IS_TESTING")):
            return True

        return not self._user_config.telemetry_enabled

    def _identify_user(self) -> None:
        """Set user properties in PostHog.

        Note: PostHog Python SDK v7 replaced identify() with set().
        """
        if not self._posthog_client or self._is_disabled():
            return

        try:
            properties = {
                "source": "modelaudit",
                "email": self._user_config.email,
                "modelaudit_version": __version__,
                "platform": os.name,
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
                "isRunningInCi": _is_running_in_ci(),
            }

            # PostHog v7 uses set() instead of identify()
            self._posthog_client.set(distinct_id=self._user_config.user_id, properties=properties)
            if self._flush_immediately:
                self._posthog_client.flush()
        except Exception as e:
            logger.debug(f"Failed to set user properties: {e}")

    def _ensure_posthog_client(self) -> None:
        """Lazily initialize the transport when telemetry is currently allowed."""
        if self._posthog_client is not None:
            return
        if not POSTHOG_AVAILABLE or not POSTHOG_PROJECT_KEY or self._is_disabled():
            return

        try:
            self._posthog_client = Posthog(
                project_api_key=POSTHOG_PROJECT_KEY,
                host=POSTHOG_HOST,
            )
            self._identify_user()
            if not self._atexit_flush_registered:
                atexit.register(self.flush)
                self._atexit_flush_registered = True
        except Exception as e:
            logger.debug(f"Failed to initialize PostHog client: {e}")
            self._posthog_client = None

    def _record_telemetry_disabled(self) -> None:
        """Mark that telemetry was disabled (no network calls for true decoupling)."""
        if not self._telemetry_disabled_recorded:
            # Just mark that we've acknowledged telemetry is disabled - no actual recording
            self._telemetry_disabled_recorded = True

    def _parse_url_reference(self, path: str) -> ParseResult | None:
        """Parse URL-like model references without treating local paths as URLs."""
        if "://" not in path:
            return None
        try:
            parsed = urlparse(path)
        except Exception:
            return None
        return parsed if parsed.scheme else None

    def _extract_file_extension(self, path: str) -> str:
        """Extract a registered extension without emitting user-defined suffixes."""
        parsed = self._parse_url_reference(path)
        name_source = parsed.path if parsed else path
        extension = Path(name_source).suffix.lower()
        if not extension or extension in _TELEMETRY_SAFE_FILE_EXTENSIONS:
            return extension
        return _TELEMETRY_OTHER_EXTENSION

    def _build_path_properties(self, path: str) -> dict[str, Any]:
        """Build coarse telemetry properties for a file path."""
        return {
            "path_type": self._classify_path(path),
            "source_type": self._classify_source_type(path),
            "file_extension": self._extract_file_extension(path),
            "model_reference_type": self._extract_model_reference(path),
        }

    def _build_url_properties(self, url: str) -> dict[str, Any]:
        """Build coarse telemetry properties for a download URL."""
        return {
            "domain": self._extract_domain(url),
            "path_type": self._classify_path(url),
            "file_extension": self._extract_file_extension(url),
            "model_reference_type": self._extract_model_reference(url),
        }

    def _iter_result_issues(self, results: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize top-level issue records from scan results."""
        normalized: list[dict[str, Any]] = []
        for issue in results.get("issues", []):
            if isinstance(issue, dict):
                normalized.append(issue)
        return normalized

    def _iter_result_assets(self, results: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize asset records from scan results."""
        normalized: list[dict[str, Any]] = []
        for asset in results.get("assets", []):
            if isinstance(asset, dict):
                normalized.append(asset)
        return normalized

    def _count_values(self, values: list[str]) -> dict[str, int]:
        """Count values in a list, skipping empty items."""
        counts: dict[str, int] = {}
        for value in values:
            if not value:
                continue
            counts[value] = counts.get(value, 0) + 1
        return counts

    @staticmethod
    def _issue_text_rule_or_cve(value: Any) -> str | None:
        """Extract a stable rule/CVE token from untrusted issue text."""
        if not isinstance(value, str):
            return None

        stripped = value.strip()
        if not stripped:
            return None

        rule_match = _TELEMETRY_RULE_CODE_RE.search(stripped)
        if rule_match:
            return f"rule:{rule_match.group(0).upper()}"

        cve_match = _TELEMETRY_CVE_RE.search(stripped)
        if cve_match:
            return f"cve:{cve_match.group(0).upper()}"

        return None

    @classmethod
    def _sanitize_issue_identifier(cls, value: Any) -> str | None:
        """Return a stable telemetry issue identifier without preserving free-form text."""
        token_identifier = cls._issue_text_rule_or_cve(value)
        if token_identifier:
            return token_identifier

        if not isinstance(value, str):
            return None

        stripped = value.strip()
        if not stripped:
            return None

        if _TELEMETRY_SECRETLIKE_ISSUE_ID_RE.search(stripped) or _TELEMETRY_FILELIKE_ISSUE_ID_RE.search(stripped):
            return None

        if _TELEMETRY_STABLE_ISSUE_ID_RE.fullmatch(stripped):
            return stripped

        return None

    def _stable_issue_type(
        self,
        *,
        issue_type: Any = None,
        rule_code: Any = None,
        cve_id: Any = None,
        issue_message: Any = None,
    ) -> str:
        """Build the stable issue identifier used in telemetry payloads."""
        for candidate in (rule_code, cve_id):
            sanitized = self._sanitize_issue_identifier(candidate)
            if sanitized:
                return sanitized
        message_identifier = self._issue_text_rule_or_cve(issue_message)
        if message_identifier:
            return message_identifier
        sanitized_type = self._sanitize_issue_identifier(issue_type)
        if sanitized_type:
            return sanitized_type
        return "unknown_issue"

    def _issue_type_from_record(self, issue: dict[str, Any]) -> str:
        """Extract a stable issue identifier from a serialized issue record."""
        raw_details = issue.get("details")
        details = raw_details if isinstance(raw_details, dict) else {}
        return self._stable_issue_type(
            issue_type=issue.get("type"),
            rule_code=issue.get("rule_code") or details.get("rule_code"),
            cve_id=issue.get("cve_id") or details.get("cve_id"),
            issue_message=issue.get("message"),
        )

    def _send_event_internal(self, event: TelemetryEvent, properties: dict[str, Any]) -> None:
        """Internal method to send events without checking disabled state."""
        event_properties = {
            **properties,
            # Source identifier for filtering in shared PostHog project
            "source": "modelaudit",
            "modelaudit_version": __version__,
            "session_id": self._session_id,
            "user_id": self._user_config.user_id,
            "platform": sys.platform,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "isRunningInCi": _is_running_in_ci(),
        }

        # Send to PostHog
        if self._posthog_client:
            try:
                self._posthog_client.capture(
                    distinct_id=self._user_config.user_id, event=event.value, properties=event_properties
                )
                if self._flush_immediately:
                    self._posthog_client.flush()
            except Exception as e:
                logger.debug(f"Failed to send event to PostHog: {e}")

    def _extract_model_name(self, path: str) -> str | None:
        """Deprecated privacy guard for legacy callers.

        Telemetry must not emit raw filenames, repository IDs, bucket keys, or
        other user-controlled model identifiers. Use `_extract_model_reference`
        for a coarse source/extension bucket instead.
        """
        return None

    def _extract_model_reference(self, path: str) -> str:
        """Extract a coarse model reference class without preserving identity."""
        parsed = self._parse_url_reference(path)
        scheme = parsed.scheme.lower() if parsed else ""
        extension = self._extract_file_extension(path) or "no_extension"
        if scheme:
            return f"{self._classify_source_type(path)}:{extension}"
        return f"{self._classify_path(path)}:{extension}"

    def record_event(self, event: TelemetryEvent, properties: dict[str, Any] | None = None) -> None:
        """Record a telemetry event."""
        if properties is None:
            properties = {}

        if self._is_disabled():
            # Record that telemetry is disabled, but only once per session
            self._record_telemetry_disabled()
            return

        try:
            self._ensure_posthog_client()
            self._send_event_internal(event, properties)
        except Exception as e:
            logger.debug(f"Failed to record telemetry event: {e}")

    def record_scan_started(self, paths: list[str], scan_options: dict[str, Any]) -> None:
        """Record that a scan has started."""
        source_types = [self._classify_source_type(path) for path in paths]
        path_types = [self._classify_path(path) for path in paths]

        self.record_event(
            TelemetryEvent.SCAN_STARTED,
            {
                "num_paths": len(paths),
                "model_reference_types": [self._extract_model_reference(path) for path in paths],
                "file_extensions": [self._extract_file_extension(path) for path in paths],
                "file_extension_counts": self._count_values([self._extract_file_extension(path) for path in paths]),
                "source_types": source_types,
                "path_types": path_types,
                "source_type_counts": self._count_values(source_types),
                "path_type_counts": self._count_values(path_types),
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
        path_type = self._classify_path(path)
        if path_type in {"huggingface", "huggingface_shorthand"}:
            return "huggingface"
        if path_type == "pytorch_hub":
            return "pytorch_hub"
        if path_type in {"jfrog", "mlflow"}:
            return path_type

        parsed = self._parse_url_reference(path)
        scheme = parsed.scheme.lower() if parsed else ""
        if scheme == "pytorch":
            return "pytorch_hub"
        if scheme == "s3":
            return "s3"
        if scheme == "gs":
            return "gcs"
        if scheme == "azure":
            return "azure"
        if scheme in {"http", "https"}:
            return "http"
        if scheme and scheme != "file":
            return "other_remote"
        return "local"

    def record_scan_completed(self, duration: float, results: dict[str, Any]) -> None:
        """Record that a scan has completed successfully."""
        issues = self._iter_result_issues(results)
        assets = self._iter_result_assets(results)

        # Collect all unique issue types with counts
        issue_types: dict[str, int] = {}
        issue_details: list[dict[str, Any]] = []

        for issue in issues:
            issue_type = self._issue_type_from_record(issue)
            severity = str(issue.get("severity", "unknown"))
            issue_types[issue_type] = issue_types.get(issue_type, 0) + 1
            # Capture first 50 issues in detail without including raw paths or identifiers.
            if len(issue_details) < 50:
                raw_issue_location = issue.get("location")
                issue_location = raw_issue_location if isinstance(raw_issue_location, str) else ""
                issue_details.append(
                    {
                        "type": issue_type,
                        "severity": severity,
                        "location_type": self._classify_path(issue_location) if issue_location else "unknown",
                    }
                )

        scanner_names = [str(name) for name in results.get("scanner_names", []) if name]
        file_types: dict[str, int] = {}
        for asset in assets:
            file_type = str(asset.get("type", "unknown"))
            file_types[file_type] = file_types.get(file_type, 0) + 1

        self.record_event(
            TelemetryEvent.SCAN_COMPLETED,
            {
                "duration": duration,
                "total_files": int(results.get("files_scanned", len(assets))),
                "total_issues": len(issues),
                "issue_severities": self._count_issue_severities(results),
                "file_types": file_types,
                "scanners_used": sorted(set(scanner_names)),
                "issue_types": issue_types,
                "issue_details": issue_details,
                "asset_reference_types": [
                    self._extract_model_reference(str(asset.get("path", "")))
                    for asset in assets
                    if isinstance(asset.get("path", ""), str) and asset.get("path")
                ],
            },
        )

    def record_scan_failed(self, duration: float, error: Union[Exception, str]) -> None:
        """Record that a scan has failed."""
        self.record_event(
            TelemetryEvent.SCAN_FAILED,
            {
                "duration": duration,
                "error_type": type(error).__name__ if isinstance(error, Exception) else "str",
                "error_category": self._classify_scan_error(error),
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
                **self._build_path_properties(file_path),
            },
        )

    def record_issue_found(
        self,
        issue_type: str,
        severity: str,
        scanner: str,
        file_path: str | None = None,
        *,
        rule_code: str | None = None,
        cve_id: str | None = None,
        issue_message: str | None = None,
    ) -> None:
        """Record that a security issue was found."""
        stable_issue_type = self._stable_issue_type(
            issue_type=issue_type,
            rule_code=rule_code,
            cve_id=cve_id,
            issue_message=issue_message,
        )
        properties: dict[str, Any] = {
            "severity": severity,
            "scanner": scanner,
            "issue_type": stable_issue_type,
        }

        if file_path:
            properties.update(self._build_path_properties(file_path))

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
                "has_context": bool(context),
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
                "size_bytes": size_bytes,
                **self._build_url_properties(url),
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
            properties.update(self._build_url_properties(url))

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
            hostname = (urlparse(path).hostname or "").lower()
            if hostname == "huggingface.co" or hostname.endswith(".huggingface.co"):
                return "huggingface"
            elif hostname == "pytorch.org" or hostname.endswith(".pytorch.org"):
                return "pytorch_hub"
            elif hostname.endswith(".jfrog.io") or hostname == "jfrog.io":
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
        """Extract a provider bucket without preserving custom hostnames."""
        try:
            parsed = urlparse(url)
        except Exception:
            return "unknown"

        scheme = parsed.scheme.lower()
        if scheme in {"s3", "gs", "azure", "hf", "pytorch"}:
            return scheme

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return "unknown"
        if hostname == "huggingface.co" or hostname.endswith(".huggingface.co"):
            return "huggingface"
        if hostname == "pytorch.org" or hostname.endswith(".pytorch.org"):
            return "pytorch"
        if hostname == "jfrog.io" or hostname.endswith(".jfrog.io"):
            return "jfrog"
        if hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".local"):
            return "local"
        return "custom"

    def _extract_url_host(self, url: str) -> str:
        """Deprecated safe alias for callers that previously expected a host."""
        return self._extract_domain(url)

    @staticmethod
    def _classify_scan_error(error: Union[Exception, str]) -> str:
        """Map scan failures to a fixed category without serializing error text."""
        if isinstance(error, Exception):
            return "exception"
        for prefix, category in _TELEMETRY_SCAN_ERROR_CATEGORIES.items():
            if error == prefix or error.startswith(f"{prefix}:"):
                return category
        return "other"

    def _count_issue_severities(self, results: dict[str, Any]) -> dict[str, int]:
        """Count issues by severity."""
        severities: dict[str, int] = {}
        for issue in self._iter_result_issues(results):
            severity = str(issue.get("severity", "unknown"))
            severities[severity] = severities.get(severity, 0) + 1
        return severities


# Global telemetry client instance
_telemetry_client: TelemetryClient | None = None


def get_telemetry_client() -> TelemetryClient | None:
    """Get the global telemetry client instance."""
    global _telemetry_client
    try:
        current_signature = _runtime_signature()
        if _telemetry_client is None or getattr(_telemetry_client, "_runtime_signature", None) != current_signature:
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
def record_issue_found(
    issue_type: str,
    severity: str,
    scanner: str,
    file_path: str | None = None,
    *,
    rule_code: str | None = None,
    cve_id: str | None = None,
    issue_message: str | None = None,
) -> None:
    """Record that a security issue was found."""
    client = get_telemetry_client()
    if client is not None:
        client.record_issue_found(
            issue_type,
            severity,
            scanner,
            file_path,
            rule_code=rule_code,
            cve_id=cve_id,
            issue_message=issue_message,
        )


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
        client._ensure_posthog_client()


def is_telemetry_enabled() -> bool:
    """Check if telemetry is enabled."""
    try:
        client = get_telemetry_client()
        if client is None:
            return False
        return not client._is_disabled()
    except Exception:
        return False
