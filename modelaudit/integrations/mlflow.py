import hashlib
import logging
import ntpath
import os
import posixpath
import re
import shutil
import stat
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from ..detectors.network_comm import _redact_urls_in_text
from ..models import Check, CheckStatus, Issue, IssueSeverity, ModelAuditResultModel, create_initial_audit_result
from ..scanners._evidence_redaction import (
    MAX_PERCENT_DECODE_PASSES,
    MAX_REDACTION_VALUE_DEPTH,
    SENSITIVE_CONTAINER_KEY,
    redact_evidence_string,
    redact_evidence_value,
)
from ..utils.sources.cloud_storage import redact_cloud_error_for_display, redact_url_for_display

logger = logging.getLogger(__name__)

_MLFLOW_DOWNLOAD_BUDGET_CHECK = "MLflow Download Size Check"
_MLFLOW_ARTIFACT_TRUST_CHECK = "MLflow Artifact Trust Check"
_MLFLOW_ARTIFACT_TRUST_FAILURE_TYPE = "mlflow_artifact_trust"
_MLFLOW_ALLOWED_ARTIFACT_URIS_ENV = "MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS"
_DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES = 10000
_MAX_MLFLOW_ERROR_DISPLAY_CHARS = 512
_MLFLOW_COPY_CHUNK_SIZE = 1024 * 1024
_MLFLOW_DEFAULT_URI_PORTS = {"ftp": 21, "http": 80, "https": 443, "sftp": 22}
_MLFLOW_RESOURCE_DOES_NOT_EXIST = "RESOURCE_DOES_NOT_EXIST"
_MLFLOW_URI_SCHEMES_REQUIRING_AUTHORITY = {
    "abfss",
    "b2",
    "ftp",
    "gs",
    "http",
    "https",
    "mlflow-artifacts",
    "r2",
    "s3",
    "sftp",
    "wasbs",
}
_MLFLOW_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_OS_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_IS_WINDOWS = os.name == "nt"
_MLFLOW_SENSITIVE_KEY = rf"(?:{SENSITIVE_CONTAINER_KEY}|credentials?|jwt|session)"
_MLFLOW_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?<![\w-])[\"']?"
    rf"{_MLFLOW_SENSITIVE_KEY}"
    r"[\"']?\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|(?:(?:bearer|basic|token)\s+)?[^\s,;&}\]]+)"
)
_MLFLOW_BRACKETED_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?<![\w-])(?:[a-z_][\w-]*\.)*(?:headers?|params?|query)\s*\[\s*[\"']?"
    rf"(?:{_MLFLOW_SENSITIVE_KEY}|key)[\"']?\s*\]\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|(?:(?:bearer|basic|token)\s+)?[^\s,;&}\]]+)"
)
_MLFLOW_SENSITIVE_CONTAINER_PREFIX_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?<![\w-])[\"']?"
    rf"{_MLFLOW_SENSITIVE_KEY}"
    r"[\"']?\s*[:=]\s*)"
    r"(?P<open>[({\[])",
)
_MLFLOW_PROTOCOL_RELATIVE_URL_RE = re.compile(
    r"(?i)(?:(?:[\\/]|%(?:25)*(?:2f|5c)){2,})[^\s\"'<>]+",
)
_MLFLOW_BENIGN_AUTH_CONTEXT_RE = re.compile(
    r"(?i)\b(?:bearer|basic|token)(?=\s+(?:authentication|endpoint|refresh|service)\b)",
)


@dataclass(frozen=True)
class _MlflowArtifact:
    path: str
    size: int
    source_root: Path | None = None
    source_path: str | None = None


@dataclass(frozen=True)
class _MlflowArtifactInfo:
    path: str
    is_dir: bool
    file_size: int | None


@dataclass(frozen=True)
class _MlflowLocalSource:
    root: Path
    artifact_path: str | None
    destination_path: str | None


@dataclass(frozen=True)
class _MlflowDownloadPlan:
    artifacts: tuple[_MlflowArtifact, ...]
    root_uri: str
    local_artifact_root: Path
    artifact_path: str | None
    max_artifact_entries: int
    local_sources: tuple[_MlflowLocalSource, ...] = ()


@dataclass(frozen=True)
class _MlflowDelegatedDownloadTarget:
    artifact_repository: Any
    artifact_path: str | None
    destination_subdirectory: str | None = None
    optional_when_missing: bool = False


@dataclass(frozen=True)
class _MlflowDelegatedDownloadPlan:
    targets: tuple[_MlflowDelegatedDownloadTarget, ...]
    local_plan: _MlflowDownloadPlan | None = None


@dataclass(frozen=True)
class _MlflowDownloadRoot:
    path: Path
    stat: os.stat_result
    file_descriptor: int | None
    creation_time_ns: int | None


class _MlflowArtifactSizeChangedError(Exception):
    def __init__(self, actual_size: int, *, artifact_path: str | None = None, expected_size: int | None = None) -> None:
        super().__init__(f"artifact size changed to {actual_size} bytes")
        self.actual_size = actual_size
        self.artifact_path = artifact_path
        self.expected_size = expected_size


class _MlflowArtifactListingExceededError(Exception):
    pass


class _MlflowArtifactSetChangedError(Exception):
    def __init__(self, added_paths: set[str], removed_paths: set[str]) -> None:
        super().__init__("artifact file set changed after preflight")
        self.added_paths = added_paths
        self.removed_paths = removed_paths


def _finite_budget(max_file_size: int, max_total_size: int) -> bool:
    return max_file_size > 0 or max_total_size > 0


def _normalize_max_artifact_entries(value: Any) -> int:
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        return _DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES
    if normalized <= 0:
        return _DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES
    return normalized


def _split_mlflow_artifact_uri(mlflow_module: Any, model_uri: str) -> tuple[str, str | None]:
    splitter = getattr(getattr(mlflow_module, "artifacts", None), "_get_root_uri_and_artifact_path", None)
    if callable(splitter):
        try:
            split_result = splitter(model_uri)
        except Exception:
            split_result = None
        if isinstance(split_result, tuple) and len(split_result) == 2:
            root_uri, artifact_path = split_result
            if isinstance(root_uri, str):
                return root_uri, str(artifact_path) if artifact_path else None

    if not model_uri.startswith("models:/"):
        return model_uri, None

    model_ref = model_uri[len("models:/") :].lstrip("/")
    if not model_ref:
        return model_uri, None

    if "@" in model_ref:
        root_ref, separator, artifact_path = model_ref.partition("/")
        return f"models:/{root_ref}", artifact_path if separator and artifact_path else None

    parts = model_ref.split("/")
    if len(parts) <= 2:
        return model_uri, None
    return f"models:/{parts[0]}/{parts[1]}", "/".join(parts[2:])


def _mlflow_budget_failure_result(model_uri: str, message: str, details: dict[str, Any]) -> ModelAuditResultModel:
    result = create_initial_audit_result()
    result.scanner_names = ["mlflow"]
    result.has_errors = True
    result.success = False
    safe_model_uri = _redact_mlflow_detail_value_for_display(model_uri)
    safe_details = redact_evidence_value(
        _redact_mlflow_detail_value_for_display(details),
        max_string_chars=_MAX_MLFLOW_ERROR_DISPLAY_CHARS,
    )

    why = (
        "ModelAudit cannot safely acquire this MLflow artifact within the configured scan budget. "
        "Refusing the download avoids unbounded network, disk, or elapsed-time use before scanning begins."
    )
    result.checks.append(
        Check(
            name=_MLFLOW_DOWNLOAD_BUDGET_CHECK,
            status=CheckStatus.FAILED,
            message=message,
            severity=IssueSeverity.INFO,
            location=safe_model_uri,
            details=safe_details,
            why=why,
        )
    )
    result.issues.append(
        Issue(
            message=message,
            severity=IssueSeverity.INFO,
            location=safe_model_uri,
            details=safe_details,
            why=why,
            type="mlflow_download_budget",
        )
    )
    result.finalize_statistics()
    return result


def _mlflow_artifact_trust_failure_result(
    model_uri: str,
    message: str,
    details: dict[str, Any],
) -> ModelAuditResultModel:
    result = create_initial_audit_result()
    result.scanner_names = ["mlflow"]
    result.has_errors = True
    result.success = False
    safe_model_uri = _redact_mlflow_detail_value_for_display(model_uri)
    safe_details = redact_evidence_value(
        _redact_mlflow_detail_value_for_display(details),
        max_string_chars=_MAX_MLFLOW_ERROR_DISPLAY_CHARS,
    )

    why = (
        "ModelAudit requires non-local MLflow artifact repositories to match a local allowlist before delegating "
        "artifact retrieval to MLflow. Refusing the download avoids fetching from an unapproved registry-controlled "
        "artifact store before scanners run."
    )
    result.checks.append(
        Check(
            name=_MLFLOW_ARTIFACT_TRUST_CHECK,
            status=CheckStatus.FAILED,
            message=message,
            severity=IssueSeverity.INFO,
            location=safe_model_uri,
            details=safe_details,
            why=why,
        )
    )
    result.issues.append(
        Issue(
            message=message,
            severity=IssueSeverity.INFO,
            location=safe_model_uri,
            details=safe_details,
            why=why,
            type=_MLFLOW_ARTIFACT_TRUST_FAILURE_TYPE,
        )
    )
    result.finalize_statistics()
    return result


def _mlflow_download_safety_failure_result(
    model_uri: str,
    message: str,
    details: dict[str, Any],
) -> ModelAuditResultModel:
    result = create_initial_audit_result()
    result.scanner_names = ["mlflow"]
    result.has_errors = True
    result.success = False
    safe_model_uri = _redact_mlflow_detail_value_for_display(model_uri)
    safe_details = redact_evidence_value(
        _redact_mlflow_detail_value_for_display(details),
        max_string_chars=_MAX_MLFLOW_ERROR_DISPLAY_CHARS,
    )

    why = (
        "ModelAudit stages MLflow downloads in a private directory before scanning. "
        "Refusing paths outside that directory, unavailable entries, unsupported filesystem objects, directory "
        "links, and externally linked files "
        "prevents a registry or artifact backend from redirecting the scan to unintended local files or devices "
        "and from blocking or bypassing the scanner through the staged filesystem tree."
    )
    result.checks.append(
        Check(
            name="MLflow Download Path Check",
            status=CheckStatus.FAILED,
            message=message,
            severity=IssueSeverity.INFO,
            location=safe_model_uri,
            details=safe_details,
            why=why,
        )
    )
    result.issues.append(
        Issue(
            message=message,
            severity=IssueSeverity.INFO,
            location=safe_model_uri,
            details=safe_details,
            why=why,
            type="mlflow_download_path",
        )
    )
    result.finalize_statistics()
    return result


def _configured_mlflow_artifact_uri_prefixes() -> tuple[str, ...]:
    raw_prefixes = os.getenv(_MLFLOW_ALLOWED_ARTIFACT_URIS_ENV, "")
    return tuple(prefix for prefix in (value.strip() for value in raw_prefixes.split(",")) if prefix)


def _uri_path_is_within_prefix(path: str, prefix: str) -> bool:
    if prefix in {"", "/"}:
        return True
    normalized_prefix = prefix.removesuffix("/")
    normalized_path = path.removesuffix("/")
    return normalized_path == normalized_prefix or normalized_path.startswith(f"{normalized_prefix}/")


def _strictly_decode_mlflow_uri_path(path: str) -> str | None:
    index = 0
    while index < len(path):
        if path[index] != "%":
            index += 1
            continue
        if index + 2 >= len(path) or not all(
            character in "0123456789abcdefABCDEF" for character in path[index + 1 : index + 3]
        ):
            return None
        index += 3

    try:
        decoded_path = unquote(path, errors="strict")
    except UnicodeDecodeError:
        return None
    if "\x00" in decoded_path or "\\" in decoded_path:
        return None
    if _MLFLOW_PERCENT_ESCAPE_RE.search(decoded_path):
        return None
    if any(segment in {".", ".."} for segment in decoded_path.split("/")):
        return None
    return decoded_path


def _strictly_validate_mlflow_remote_uri_path(path: str) -> str | None:
    if "%" in path or "\x00" in path or "\\" in path:
        return None
    if any(segment in {".", ".."} for segment in path.split("/")):
        return None
    return path


def _normalized_mlflow_uri_authority(
    parsed_uri: Any, scheme: str
) -> tuple[str | None, str | None, str | None, int | None] | None:
    if not parsed_uri.netloc:
        if scheme in _MLFLOW_URI_SCHEMES_REQUIRING_AUTHORITY:
            return None
        return (None, None, None, None)
    try:
        hostname = parsed_uri.hostname
        port = parsed_uri.port
    except ValueError:
        return None
    if not hostname:
        return None
    if port is None:
        port = _MLFLOW_DEFAULT_URI_PORTS.get(scheme)
    return (
        parsed_uri.username,
        parsed_uri.password,
        hostname.lower().rstrip("."),
        port,
    )


def _local_path_from_mlflow_artifact_uri(uri: str) -> Path | None:
    try:
        parsed = urlparse(uri)
    except ValueError:
        return None
    if parsed.scheme and parsed.scheme != "file":
        return None

    if parsed.scheme == "file":
        if parsed.params or parsed.query or parsed.fragment:
            return None
        if parsed.netloc:
            try:
                hostname = parsed.hostname
                port = parsed.port
            except ValueError:
                return None
            if (
                parsed.username is not None
                or parsed.password is not None
                or port is not None
                or hostname is None
                or hostname.lower().rstrip(".") not in {"localhost", "127.0.0.1", "::1"}
            ):
                return None
        path = _strictly_decode_mlflow_uri_path(parsed.path)
        if path is None:
            return None
    else:
        path = uri

    try:
        return Path(path).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def _mlflow_artifact_uri_matches_prefix(artifact_uri: str, allowed_prefix: str) -> bool:
    artifact_path = _local_path_from_mlflow_artifact_uri(artifact_uri)
    prefix_path = _local_path_from_mlflow_artifact_uri(allowed_prefix)
    if artifact_path is not None and prefix_path is not None:
        try:
            return os.path.commonpath((prefix_path, artifact_path)) == str(prefix_path)
        except ValueError:
            return False

    try:
        artifact = urlparse(artifact_uri)
        prefix = urlparse(allowed_prefix)
    except ValueError:
        return False
    if not artifact.scheme or not prefix.scheme:
        return False
    if artifact.params or artifact.query or artifact.fragment or prefix.params or prefix.query or prefix.fragment:
        return False
    artifact_scheme = artifact.scheme.lower()
    prefix_scheme = prefix.scheme.lower()
    if artifact_scheme != prefix_scheme:
        return False
    if artifact_scheme in {"file", "models", "runs"}:
        return False
    if artifact_scheme in _MLFLOW_URI_SCHEMES_REQUIRING_AUTHORITY:
        artifact_authority = _normalized_mlflow_uri_authority(artifact, artifact_scheme)
        prefix_authority = _normalized_mlflow_uri_authority(prefix, prefix_scheme)
        if artifact_authority is None or prefix_authority is None or artifact_authority != prefix_authority:
            return False
    elif artifact.netloc != prefix.netloc:
        return False
    normalized_artifact_path = _strictly_validate_mlflow_remote_uri_path(artifact.path)
    normalized_prefix_path = _strictly_validate_mlflow_remote_uri_path(prefix.path)
    if normalized_artifact_path is None or normalized_prefix_path is None:
        return False
    return _uri_path_is_within_prefix(normalized_artifact_path, normalized_prefix_path)


def _mlflow_artifact_uri_is_allowlisted(artifact_uri: str) -> bool:
    return any(
        _mlflow_artifact_uri_matches_prefix(artifact_uri, allowed_prefix)
        for allowed_prefix in _configured_mlflow_artifact_uri_prefixes()
    )


def _normalize_mlflow_delegated_artifact_path(artifact_path: str | None) -> str | None:
    if artifact_path is None:
        return None
    validated_path = _strictly_validate_mlflow_remote_uri_path(artifact_path)
    if validated_path is None:
        raise ValueError("MLflow artifact path is ambiguous")
    if (
        not validated_path
        or posixpath.isabs(validated_path)
        or ntpath.isabs(validated_path)
        or ntpath.splitdrive(validated_path)[0]
    ):
        raise ValueError("MLflow artifact path is not relative")
    return validated_path


def _mlflow_delegated_download_targets(
    artifact_repository: Any,
    artifact_path: str | None,
) -> tuple[_MlflowDelegatedDownloadTarget, ...] | None:
    repository = _terminal_mlflow_artifact_repository(artifact_repository)
    if repository is None:
        return None
    if not _is_runs_mlflow_artifact_repository(repository):
        try:
            normalized_artifact_path = _normalize_mlflow_delegated_artifact_path(artifact_path)
        except ValueError:
            return None
        return (_MlflowDelegatedDownloadTarget(repository, normalized_artifact_path),)

    run_repository = _terminal_mlflow_artifact_repository(getattr(repository, "repo", None))
    if run_repository is None:
        return None
    wrapper_uri = getattr(repository, "artifact_uri", None)
    parse_runs_uri = getattr(repository, "parse_runs_uri", None)
    get_logged_model_repository = getattr(repository, "_get_logged_model_artifact_repo", None)
    if not isinstance(wrapper_uri, str) or not callable(parse_runs_uri):
        return None
    try:
        run_id, wrapper_path = parse_runs_uri(wrapper_uri)
    except Exception:
        return None
    try:
        normalized_wrapper_path = _normalize_mlflow_delegated_artifact_path(wrapper_path)
        normalized_artifact_path = _normalize_mlflow_delegated_artifact_path(artifact_path)
    except ValueError:
        return None
    if any("//" in path for path in (normalized_wrapper_path, normalized_artifact_path) if path is not None):
        return None
    effective_path = (
        posixpath.join(normalized_wrapper_path, normalized_artifact_path)
        if normalized_wrapper_path and normalized_artifact_path
        else normalized_wrapper_path or normalized_artifact_path
    )
    run_artifact_path = normalized_artifact_path
    repository_is_scoped = False
    if normalized_wrapper_path and effective_path:
        repository_scope = _runs_mlflow_repository_is_scoped(repository, run_repository, wrapper_uri)
        if repository_scope is None:
            return None
        repository_is_scoped = repository_scope
        if not repository_is_scoped:
            run_artifact_path = effective_path
    run_target = _MlflowDelegatedDownloadTarget(run_repository, run_artifact_path)
    targets = [run_target]
    if not effective_path:
        return tuple(targets)
    if not callable(get_logged_model_repository):
        return None

    model_name = effective_path.split("/", 1)[0]
    try:
        logged_model_repository = get_logged_model_repository(run_id=run_id, name=model_name)
    except Exception:
        return None
    if logged_model_repository is not None:
        terminal_logged_repository = _terminal_mlflow_artifact_repository(logged_model_repository)
        if terminal_logged_repository is None:
            return None
        model_name, separator, model_artifact_path = effective_path.partition("/")
        targets[0] = _MlflowDelegatedDownloadTarget(
            run_repository,
            run_artifact_path,
            optional_when_missing=True,
        )
        targets.append(
            _MlflowDelegatedDownloadTarget(
                terminal_logged_repository,
                model_artifact_path if separator and model_artifact_path else None,
                None if repository_is_scoped else model_name,
            )
        )
    return tuple(targets)


def _mlflow_artifact_repository_uris(
    targets: tuple[_MlflowDelegatedDownloadTarget, ...],
) -> tuple[str, ...] | None:
    artifact_uris: list[str] = []
    for target in targets:
        repository = target.artifact_repository
        if _local_mlflow_artifact_root(repository) is not None:
            continue
        artifact_uri = getattr(repository, "artifact_uri", None)
        if not isinstance(artifact_uri, str) or not artifact_uri:
            return None
        try:
            parsed_artifact_uri = urlparse(artifact_uri)
            artifact_scheme = parsed_artifact_uri.scheme.lower()
        except ValueError:
            return None
        if artifact_scheme in {"", "file"}:
            return None
        if target.artifact_path:
            separator = "" if parsed_artifact_uri.path.endswith("/") else "/"
            artifact_uri = parsed_artifact_uri._replace(
                path=f"{parsed_artifact_uri.path}{separator}{target.artifact_path}"
            ).geturl()
        if artifact_uri not in artifact_uris:
            artifact_uris.append(artifact_uri)
    return tuple(artifact_uris)


def _partition_mlflow_delegated_targets(
    targets: tuple[_MlflowDelegatedDownloadTarget, ...],
) -> tuple[tuple[_MlflowDelegatedDownloadTarget, ...], tuple[_MlflowLocalSource, ...]] | None:
    remote_targets: list[_MlflowDelegatedDownloadTarget] = []
    local_sources: list[_MlflowLocalSource] = []
    for target in targets:
        local_root = _local_mlflow_artifact_root(target.artifact_repository)
        if local_root is None:
            remote_targets.append(target)
            continue
        if remote_targets:
            return None
        local_sources.append(
            _MlflowLocalSource(
                local_root,
                target.artifact_path,
                target.destination_subdirectory,
            )
        )
    return tuple(remote_targets), tuple(local_sources)


def _unbounded_mlflow_download_policy_result(
    model_uri: str,
    details: dict[str, Any],
    targets: tuple[_MlflowDelegatedDownloadTarget, ...] | None,
) -> ModelAuditResultModel | None:
    artifact_uris = _mlflow_artifact_repository_uris(targets) if targets is not None else None
    untrusted_artifact_uris = (
        [artifact_uri for artifact_uri in artifact_uris if not _mlflow_artifact_uri_is_allowlisted(artifact_uri)]
        if artifact_uris is not None
        else []
    )
    if artifact_uris is not None and not untrusted_artifact_uris:
        return None

    artifact_uri = untrusted_artifact_uris[0] if untrusted_artifact_uris else None
    if artifact_uri is None and targets:
        candidate_uri = getattr(targets[0].artifact_repository, "artifact_uri", None)
        artifact_uri = candidate_uri if isinstance(candidate_uri, str) and candidate_uri else None
    details.update(
        {
            "reason": "artifact_uri_not_allowlisted",
            "artifact_repository_uri": artifact_uri,
            "artifact_repository_uris": list(artifact_uris) if artifact_uris is not None else None,
            "allowlist_env_var": _MLFLOW_ALLOWED_ARTIFACT_URIS_ENV,
        }
    )
    return _mlflow_artifact_trust_failure_result(
        model_uri,
        "MLflow artifact repository is not in the configured allowlist",
        details,
    )


def _trusted_mlflow_delegated_download_plan(
    model_uri: str,
    root_uri: str,
    details: dict[str, Any],
    artifact_repository: Any,
    *,
    max_file_size: int,
    max_total_size: int,
    max_artifact_entries: int,
) -> _MlflowDelegatedDownloadPlan | ModelAuditResultModel:
    targets = _mlflow_delegated_download_targets(artifact_repository, details.get("artifact_path"))
    if targets is None:
        return _mlflow_artifact_trust_failure_result(
            model_uri,
            "Unable to verify the MLflow artifact repository before download",
            details,
        )
    partitioned_targets = _partition_mlflow_delegated_targets(targets)
    if partitioned_targets is None:
        return _mlflow_artifact_trust_failure_result(
            model_uri,
            "Unable to safely compose remote MLflow artifacts before a local overlay",
            details,
        )
    remote_targets, local_sources = partitioned_targets
    policy_failure = _unbounded_mlflow_download_policy_result(model_uri, details, remote_targets)
    if policy_failure is not None:
        return policy_failure

    local_plan: _MlflowDownloadPlan | None = None
    if local_sources:
        local_plan_result = _preflight_local_mlflow_sources(
            model_uri,
            root_uri,
            local_sources,
            details,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            max_artifact_entries=max_artifact_entries,
        )
        if isinstance(local_plan_result, ModelAuditResultModel):
            return local_plan_result
        local_plan = local_plan_result
    return _MlflowDelegatedDownloadPlan(remote_targets, local_plan)


def _redact_mlflow_error_for_display(error: object) -> str:
    def _replace_sensitive_value(match: re.Match[str]) -> str:
        value = match.group("value")
        quote = value[0] if value[:1] in {'"', "'"} else ""
        return f"{match.group('prefix')}{quote}<redacted>{quote}"

    def _redact_protocol_relative_url(match: re.Match[str]) -> str:
        candidate = match.group(0)
        decoded = candidate
        for _ in range(MAX_PERCENT_DECODE_PASSES):
            next_decoded = unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded

        normalized = decoded.replace("\\/", "/").replace("\\", "/")
        if len(normalized) - len(normalized.lstrip("/")) < 2:
            return candidate
        normalized = f"//{normalized.lstrip('/')}"
        authority = normalized[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" not in authority:
            return candidate

        safe_url = redact_url_for_display(f"https:{normalized}")
        return safe_url.removeprefix("https:")

    def _redact_sensitive_containers(text: str) -> str:
        parts: list[str] = []
        cursor = 0
        closing_delimiters = {"(": ")", "[": "]", "{": "}"}

        while match := _MLFLOW_SENSITIVE_CONTAINER_PREFIX_RE.search(text, cursor):
            parts.append(text[cursor : match.start()])
            parts.append(f"{match.group('prefix')}<redacted>")
            stack = [closing_delimiters[match.group("open")]]
            quote: str | None = None
            escaped = False
            index = match.end()

            while index < len(text) and stack:
                character = text[index]
                if quote is not None:
                    if escaped:
                        escaped = False
                    elif character == "\\":
                        escaped = True
                    elif character == quote:
                        quote = None
                elif character in {'"', "'"}:
                    quote = character
                elif character in closing_delimiters:
                    if len(stack) >= MAX_REDACTION_VALUE_DEPTH:
                        index = len(text)
                        break
                    stack.append(closing_delimiters[character])
                elif character == stack[-1]:
                    stack.pop()
                index += 1

            if stack:
                cursor = len(text)
                break
            cursor = index

        parts.append(text[cursor:])
        return "".join(parts)

    redacted = _MLFLOW_PROTOCOL_RELATIVE_URL_RE.sub(_redact_protocol_relative_url, str(error))
    redacted = _redact_sensitive_containers(redacted)
    redacted = _MLFLOW_BRACKETED_SENSITIVE_ASSIGNMENT_RE.sub(_replace_sensitive_value, redacted)
    redacted = _MLFLOW_SENSITIVE_ASSIGNMENT_RE.sub(_replace_sensitive_value, redacted)
    contains_url = bool(
        re.search(r"(?i)(?:\b[a-z][a-z0-9+.-]*://|\bmodels:/)", redacted)
        or _MLFLOW_PROTOCOL_RELATIVE_URL_RE.search(redacted)
    )
    if contains_url:
        redacted = redact_cloud_error_for_display(_redact_urls_in_text(redacted))
    redacted = _MLFLOW_PROTOCOL_RELATIVE_URL_RE.sub(_redact_protocol_relative_url, redacted)
    redacted = _MLFLOW_BRACKETED_SENSITIVE_ASSIGNMENT_RE.sub(_replace_sensitive_value, redacted)
    redacted = _MLFLOW_SENSITIVE_ASSIGNMENT_RE.sub(_replace_sensitive_value, redacted)

    benign_auth_contexts: list[tuple[str, str]] = []

    def _protect_benign_auth_context(match: re.Match[str]) -> str:
        placeholder = f"MODELAUDITMLFLOWSAFECONTEXT{len(benign_auth_contexts)}"
        benign_auth_contexts.append((placeholder, match.group(0)))
        return placeholder

    redacted = _MLFLOW_BENIGN_AUTH_CONTEXT_RE.sub(_protect_benign_auth_context, redacted)
    if contains_url:
        redacted = redact_evidence_string(redacted, max_chars=None)
    else:
        redacted = "&".join(redact_evidence_string(part, max_chars=None) for part in redacted.split("&"))
    for placeholder, original in benign_auth_contexts:
        redacted = redacted.replace(placeholder, original)

    if len(redacted) <= _MAX_MLFLOW_ERROR_DISPLAY_CHARS:
        return redacted
    return f"{redacted[: _MAX_MLFLOW_ERROR_DISPLAY_CHARS - 3]}..."


def _mlflow_text_requires_specialized_redaction(text: str) -> bool:
    if "models:/" in text.lower():
        return True
    if _MLFLOW_BRACKETED_SENSITIVE_ASSIGNMENT_RE.search(text) or _MLFLOW_SENSITIVE_CONTAINER_PREFIX_RE.search(text):
        return True
    for match in _MLFLOW_PROTOCOL_RELATIVE_URL_RE.finditer(text):
        candidate = match.group(0)
        if candidate.startswith("//") and re.search(r"(?i)[a-z][a-z0-9+.-]*:$", text[: match.start()]):
            continue
        decoded = candidate
        for _ in range(MAX_PERCENT_DECODE_PASSES):
            next_decoded = unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        normalized = decoded.replace("\\/", "/").replace("\\", "/")
        authority = normalized.lstrip("/").split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in authority:
            return True
    return False


def _redact_mlflow_detail_value_for_display(value: Any, *, depth: int = 0) -> Any:
    if depth >= MAX_REDACTION_VALUE_DEPTH:
        return "<redacted>"
    if isinstance(value, str):
        specialized = (
            _redact_mlflow_error_for_display(value) if _mlflow_text_requires_specialized_redaction(value) else value
        )
        return redact_evidence_string(specialized, max_chars=_MAX_MLFLOW_ERROR_DISPLAY_CHARS)
    if isinstance(value, dict):
        return {
            key: _redact_mlflow_detail_value_for_display(nested_value, depth=depth + 1)
            for key, nested_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_mlflow_detail_value_for_display(item, depth=depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_mlflow_detail_value_for_display(item, depth=depth + 1) for item in value)
    return value


def _terminal_mlflow_artifact_repository(artifact_repository: Any) -> Any | None:
    """Unwrap transparent model adapters without discarding run overlay semantics."""
    try:
        from mlflow.store.artifact.models_artifact_repo import ModelsArtifactRepository
    except Exception:
        return artifact_repository

    repository = artifact_repository
    seen: set[int] = set()
    while isinstance(repository, ModelsArtifactRepository):
        repository_id = id(repository)
        if repository_id in seen:
            return None
        seen.add(repository_id)
        repository = getattr(repository, "repo", None)
        if repository is None:
            return None

    return repository


def _is_runs_mlflow_artifact_repository(artifact_repository: Any) -> bool:
    try:
        from mlflow.store.artifact.runs_artifact_repo import RunsArtifactRepository
    except Exception:
        return False
    return isinstance(artifact_repository, RunsArtifactRepository)


def _local_mlflow_artifact_root(artifact_repository: Any) -> Path | None:
    """Return a trusted local source root that ModelAudit can copy itself."""
    try:
        from mlflow.store.artifact.local_artifact_repo import LocalArtifactRepository
    except Exception:
        return None

    repository = _terminal_mlflow_artifact_repository(artifact_repository)

    if not isinstance(repository, LocalArtifactRepository):
        return None

    artifact_uri = getattr(repository, "artifact_uri", None)
    if isinstance(artifact_uri, str):
        try:
            parsed_artifact_uri = urlparse(artifact_uri)
        except ValueError:
            return None
        if parsed_artifact_uri.scheme == "file" and parsed_artifact_uri.netloc:
            try:
                hostname = parsed_artifact_uri.hostname
                port = parsed_artifact_uri.port
            except ValueError:
                return None
            if (
                parsed_artifact_uri.username is not None
                or parsed_artifact_uri.password is not None
                or port is not None
                or hostname is None
                or hostname.lower().rstrip(".") not in {"localhost", "127.0.0.1", "::1"}
            ):
                return None
        if not parsed_artifact_uri.scheme and artifact_uri.startswith(("//", "\\\\")):
            return None

    try:
        raw_artifact_dir = os.fspath(repository.artifact_dir)
    except TypeError:
        return None
    if raw_artifact_dir.startswith(("//", "\\\\")):
        return None
    try:
        artifact_root = Path(raw_artifact_dir).expanduser().resolve(strict=True)
    except (OSError, TypeError, ValueError):
        return None
    return artifact_root if artifact_root.is_dir() else None


def _runs_mlflow_repository_is_scoped(
    artifact_repository: Any,
    run_repository: Any,
    wrapper_uri: str,
) -> bool | None:
    """Return whether MLflow resolved the run repository at the wrapper path."""
    repository_uri = getattr(run_repository, "artifact_uri", None)
    get_underlying_uri = getattr(artifact_repository, "get_underlying_uri", None)
    if not isinstance(repository_uri, str) or not callable(get_underlying_uri):
        return None

    try:
        expected_uri = get_underlying_uri(wrapper_uri, getattr(artifact_repository, "tracking_uri", None))
    except TypeError:
        try:
            expected_uri = get_underlying_uri(wrapper_uri)
        except Exception:
            return None
    except Exception:
        return None
    if not isinstance(expected_uri, str):
        return None
    return repository_uri == expected_uri


def _local_runs_mlflow_sources(
    artifact_repository: Any,
    artifact_path: str | None,
) -> tuple[_MlflowLocalSource, ...] | None:
    """Resolve the local repositories that a runs:/ adapter overlays."""
    run_repository = getattr(artifact_repository, "repo", None)
    run_root = _local_mlflow_artifact_root(run_repository)
    if run_root is None:
        return None

    get_logged_model_repository = getattr(artifact_repository, "_get_logged_model_artifact_repo", None)
    parse_runs_uri = getattr(artifact_repository, "parse_runs_uri", None)
    wrapper_uri = getattr(artifact_repository, "artifact_uri", None)
    run_id: str | None = None
    wrapper_path: str | None = None
    if callable(parse_runs_uri) and isinstance(wrapper_uri, str):
        run_id, wrapper_path = parse_runs_uri(wrapper_uri)
    effective_path = (
        posixpath.join(wrapper_path, artifact_path) if wrapper_path and artifact_path else wrapper_path or artifact_path
    )

    run_artifact_path = artifact_path
    if wrapper_path and effective_path and isinstance(wrapper_uri, str):
        repository_is_scoped = _runs_mlflow_repository_is_scoped(
            artifact_repository,
            run_repository,
            wrapper_uri,
        )
        if repository_is_scoped is None:
            return None
        if not repository_is_scoped:
            run_artifact_path = effective_path

    sources = [_MlflowLocalSource(run_root, run_artifact_path, artifact_path)]
    if not effective_path or run_id is None or not callable(get_logged_model_repository):
        return tuple(sources)

    model_name, separator, model_artifact_path = effective_path.partition("/")
    try:
        logged_model_repository = get_logged_model_repository(run_id=run_id, name=model_name)
    except Exception:
        logger.debug("MLflow logged-model lookup failed; refusing an incomplete run artifact view")
        return None
    if logged_model_repository is None:
        return tuple(sources)

    logged_model_root = _local_mlflow_artifact_root(logged_model_repository)
    if logged_model_root is None:
        return None

    sources.append(
        _MlflowLocalSource(
            logged_model_root,
            model_artifact_path if separator and model_artifact_path else None,
            artifact_path,
        )
    )
    return tuple(sources)


def _is_local_mlflow_artifact_repository(artifact_repository: Any) -> bool:
    try:
        from mlflow.store.artifact.local_artifact_repo import LocalArtifactRepository
    except Exception:
        return False
    return isinstance(artifact_repository, LocalArtifactRepository)


def _copy_local_mlflow_artifact(
    source_root: Path,
    artifact: _MlflowArtifact,
    destination: Path,
) -> int:
    """Copy one local artifact without writing more than its preflight size."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    copied_size = 0
    source_fd: int | None = None
    try:
        source_fd = _open_local_mlflow_artifact(source_root, artifact.source_path or artifact.path)
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("artifact source path is not a regular file")
        if source_stat.st_size != artifact.size:
            raise _MlflowArtifactSizeChangedError(source_stat.st_size)

        with destination.open("xb") as output:
            while copied_size < artifact.size:
                chunk = os.read(source_fd, min(_MLFLOW_COPY_CHUNK_SIZE, artifact.size - copied_size))
                if not chunk:
                    break
                output.write(chunk)
                copied_size += len(chunk)

            extra_byte = os.read(source_fd, 1)
            final_source_size = os.fstat(source_fd).st_size
            if copied_size != artifact.size or extra_byte or final_source_size != artifact.size:
                actual_size = final_source_size
                if actual_size == artifact.size:
                    actual_size = copied_size + len(extra_byte)
                raise _MlflowArtifactSizeChangedError(actual_size)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if source_fd is not None:
            os.close(source_fd)

    return copied_size


def _opened_local_mlflow_path(source_fd: int) -> Path | None:
    """Return the path of the opened file handle when the platform exposes it."""
    if _IS_WINDOWS:
        try:
            import ctypes
            import ctypes.wintypes
            import msvcrt

            win_dll = getattr(ctypes, "WinDLL", None)
            get_osfhandle = getattr(msvcrt, "get_osfhandle", None)
            if not callable(win_dll) or not callable(get_osfhandle):
                return None
            kernel32: Any = win_dll("kernel32", use_last_error=True)
            get_final_path = kernel32.GetFinalPathNameByHandleW
            get_final_path.argtypes = (
                ctypes.wintypes.HANDLE,
                ctypes.wintypes.LPWSTR,
                ctypes.wintypes.DWORD,
                ctypes.wintypes.DWORD,
            )
            get_final_path.restype = ctypes.wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            handle_value = get_osfhandle(source_fd)
            if handle_value == -1:
                return None
            length = int(get_final_path(ctypes.wintypes.HANDLE(handle_value), buffer, len(buffer), 0))
            if length <= 0 or length >= len(buffer):
                return None
            opened_path = buffer.value
            if opened_path.startswith("\\\\?\\UNC\\"):
                opened_path = f"\\\\{opened_path[8:]}"
            elif opened_path.startswith("\\\\?\\"):
                opened_path = opened_path[4:]
            return Path(opened_path)
        except (AttributeError, ImportError, OSError, OverflowError, TypeError, ValueError):
            return None

    try:
        return Path(os.readlink(f"/proc/self/fd/{source_fd}"))
    except OSError:
        return None


def _opened_path_is_within_root(opened_path: Path, source_root: Path) -> bool:
    try:
        normalized_root = os.path.normcase(os.path.abspath(source_root))
        normalized_path = os.path.normcase(os.path.abspath(opened_path))
        return os.path.commonpath((normalized_root, normalized_path)) == normalized_root
    except (OSError, ValueError):
        return False


def _open_local_mlflow_artifact(source_root: Path, artifact_path: str) -> int:
    """Open a repository file without following replaceable path components."""
    parts = PurePosixPath(artifact_path).parts
    if not parts:
        raise ValueError("artifact source path is empty")

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    supports_secure_walk = nofollow and _OS_OPEN_SUPPORTS_DIR_FD

    if supports_secure_walk:
        current_fd = os.open(source_root, os.O_RDONLY | directory | nofollow | cloexec)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | directory | nofollow | cloexec, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            return os.open(parts[-1], os.O_RDONLY | nofollow | nonblock | cloexec, dir_fd=current_fd)
        finally:
            os.close(current_fd)

    source_path = source_root
    for part in parts:
        source_path /= part
        if source_path.is_symlink():
            raise ValueError("artifact source path contains a symbolic link")
    resolved_source = source_path.resolve(strict=True)
    if not resolved_source.is_relative_to(source_root):
        raise ValueError("artifact source path escaped the repository root")
    source_fd = os.open(resolved_source, os.O_RDONLY | nofollow | nonblock | cloexec)
    try:
        opened_path = _opened_local_mlflow_path(source_fd)
        if opened_path is None:
            raise ValueError("platform cannot verify the opened artifact path")
        if not _opened_path_is_within_root(opened_path, source_root):
            raise ValueError("opened artifact path escaped the repository root")
        path_stat = resolved_source.stat(follow_symlinks=False)
        opened_stat = os.fstat(source_fd)
        if (path_stat.st_dev, path_stat.st_ino) != (opened_stat.st_dev, opened_stat.st_ino):
            raise ValueError("artifact source path changed while opening")
    except Exception:
        os.close(source_fd)
        raise
    return source_fd


def _snapshot_local_mlflow_artifacts(
    source_root: Path,
    artifact_path: str | None,
    max_artifact_entries: int,
) -> tuple[dict[str, int], int]:
    """Return the regular files currently present under the requested local artifact."""
    requested_parts = PurePosixPath(artifact_path).parts if artifact_path else ()
    requested_path = source_root.joinpath(*requested_parts)
    if requested_path.is_symlink():
        raise ValueError("artifact source path contains a symbolic link")
    resolved_requested_path = requested_path.resolve(strict=True)
    if not resolved_requested_path.is_relative_to(source_root):
        raise ValueError("artifact source path escaped the repository root")

    requested_stat = resolved_requested_path.stat(follow_symlinks=False)
    if stat.S_ISREG(requested_stat.st_mode):
        if artifact_path is None:
            raise ValueError("artifact repository root is not a directory")
        if max_artifact_entries < 1:
            raise _MlflowArtifactListingExceededError
        return {artifact_path: requested_stat.st_size}, 1
    if not stat.S_ISDIR(requested_stat.st_mode):
        raise ValueError("artifact source path is not a regular file or directory")

    snapshot: dict[str, int] = {}
    entry_count = 0
    pending_dirs = [resolved_requested_path]
    while pending_dirs:
        current_dir = pending_dirs.pop()
        with os.scandir(current_dir) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > max_artifact_entries:
                    raise _MlflowArtifactListingExceededError
                if entry.is_symlink():
                    raise ValueError("artifact source path contains a symbolic link")
                entry_stat = entry.stat(follow_symlinks=False)
                entry_path = Path(entry.path)
                relative_path = entry_path.relative_to(source_root).as_posix()
                if stat.S_ISDIR(entry_stat.st_mode):
                    pending_dirs.append(entry_path)
                elif stat.S_ISREG(entry_stat.st_mode):
                    snapshot[relative_path] = entry_stat.st_size
                else:
                    raise ValueError(f"artifact source path is not a regular file: {relative_path}")
    return snapshot, entry_count


def _map_local_source_path(source: _MlflowLocalSource, source_path: str) -> str:
    if source.artifact_path is None:
        suffix = source_path
    elif source_path == source.artifact_path:
        suffix = ""
    elif source_path.startswith(f"{source.artifact_path}/"):
        suffix = source_path[len(source.artifact_path) + 1 :]
    else:
        raise ValueError(f"Artifact entry path escaped requested source: {source_path}")

    if source.destination_path:
        return posixpath.join(source.destination_path, suffix) if suffix else source.destination_path
    if suffix:
        return suffix
    return posixpath.basename(source_path)


def _snapshot_local_mlflow_sources(
    sources: tuple[_MlflowLocalSource, ...],
    max_artifact_entries: int,
) -> tuple[dict[str, _MlflowArtifact], int]:
    """Snapshot local sources using MLflow's model-over-run overlay order."""
    artifacts: dict[str, _MlflowArtifact] = {}
    entry_count = 0
    source_found = False
    for source in sources:
        try:
            snapshot, source_entry_count = _snapshot_local_mlflow_artifacts(
                source.root,
                source.artifact_path,
                max_artifact_entries - entry_count,
            )
        except (FileNotFoundError, NotADirectoryError):
            continue
        source_found = True
        entry_count += source_entry_count
        for source_path, size in snapshot.items():
            artifact_path = _normalize_mlflow_artifact_path(_map_local_source_path(source, source_path))
            artifacts[artifact_path] = _MlflowArtifact(
                path=artifact_path,
                size=size,
                source_root=source.root,
                source_path=source_path,
            )

    if not source_found:
        raise FileNotFoundError("requested artifact was not present in any local MLflow source")

    artifact_paths = set(artifacts)
    for artifact_path in artifact_paths:
        parent = posixpath.dirname(artifact_path)
        while parent:
            if parent in artifact_paths:
                raise ValueError(f"Artifact overlay contains a file and directory at {parent}")
            parent = posixpath.dirname(parent)
    return artifacts, entry_count


def _verify_local_mlflow_artifact_set(plan: _MlflowDownloadPlan) -> None:
    if plan.local_sources:
        current_plan, _ = _snapshot_local_mlflow_sources(plan.local_sources, plan.max_artifact_entries)
        current_artifacts = {artifact.path: artifact.size for artifact in current_plan.values()}
    else:
        current_artifacts, _ = _snapshot_local_mlflow_artifacts(
            plan.local_artifact_root,
            plan.artifact_path,
            plan.max_artifact_entries,
        )
    expected_artifacts = {artifact.path: artifact.size for artifact in plan.artifacts}
    added_paths = current_artifacts.keys() - expected_artifacts.keys()
    removed_paths = expected_artifacts.keys() - current_artifacts.keys()
    if added_paths or removed_paths:
        raise _MlflowArtifactSetChangedError(set(added_paths), set(removed_paths))
    for artifact_path, expected_size in expected_artifacts.items():
        actual_size = current_artifacts[artifact_path]
        if actual_size != expected_size:
            raise _MlflowArtifactSizeChangedError(
                actual_size,
                artifact_path=artifact_path,
                expected_size=expected_size,
            )


def _bounded_artifact_listing(
    list_artifacts: Any,
    artifact_path: str | None,
    remaining_entries: int,
) -> tuple[list[Any], bool]:
    """Bound local listing consumption after the repository returns each response.

    Standard MLflow repositories return a materialized sequence, so their own
    pagination and response allocation cannot be interrupted through this API.
    Iterable repository plugins are consumed lazily here.
    """
    artifact_infos = list_artifacts(artifact_path)
    if artifact_infos is None:
        raise ValueError(f"Artifact listing returned no size information for {artifact_path or '<root>'}")

    if isinstance(artifact_infos, Sequence):
        return list(artifact_infos[: remaining_entries + 1]), len(artifact_infos) > remaining_entries

    bounded_infos = list(islice(iter(artifact_infos), remaining_entries + 1))
    return bounded_infos, len(bounded_infos) > remaining_entries


def _artifact_path_matches(artifact_path: str | None, requested_path: str) -> bool:
    if artifact_path == requested_path:
        return True
    return artifact_path == posixpath.basename(requested_path)


def _normalize_mlflow_artifact_path(artifact_path: object) -> str:
    if not isinstance(artifact_path, str) or not artifact_path or "\x00" in artifact_path:
        raise ValueError("Artifact entry did not include a valid path")
    if (
        "\\" in artifact_path
        or (_IS_WINDOWS and ":" in artifact_path)
        or posixpath.isabs(artifact_path)
        or ntpath.isabs(artifact_path)
    ):
        raise ValueError(f"Artifact entry path is not relative: {artifact_path}")
    if any(segment in {".", ".."} for segment in artifact_path.split("/")):
        raise ValueError(f"Artifact entry path escapes the repository root: {artifact_path}")
    normalized = posixpath.normpath(artifact_path)
    if normalized in {"", ".", ".."} or normalized.startswith("../") or ntpath.splitdrive(normalized)[0]:
        raise ValueError(f"Artifact entry path escapes the repository root: {artifact_path}")
    return normalized


def _artifact_path_is_within(path: str, parent: str | None) -> bool:
    if parent is None:
        return True
    return path == parent or path.startswith(f"{parent}/")


def _find_single_file_artifact_info(
    list_artifacts: Any,
    requested_path: str,
    remaining_entries: int,
) -> tuple[Any | None, int, bool]:
    parent_path = posixpath.dirname(requested_path) or None
    artifact_infos, listing_exceeded = _bounded_artifact_listing(list_artifacts, parent_path, remaining_entries)
    for artifact_info in artifact_infos:
        artifact_path = getattr(artifact_info, "path", None)
        if not getattr(artifact_info, "is_dir", False) and _artifact_path_matches(artifact_path, requested_path):
            return artifact_info, len(artifact_infos), listing_exceeded
    return None, len(artifact_infos), listing_exceeded


def _preflight_local_mlflow_sources(
    model_uri: str,
    root_uri: str,
    sources: tuple[_MlflowLocalSource, ...],
    details: dict[str, Any],
    *,
    max_file_size: int,
    max_total_size: int,
    max_artifact_entries: int,
) -> _MlflowDownloadPlan | ModelAuditResultModel:
    try:
        planned_artifacts, entry_count = _snapshot_local_mlflow_sources(sources, max_artifact_entries)
    except _MlflowArtifactListingExceededError:
        details.update(
            {
                "reason": "artifact_listing_budget_exceeded",
                "artifact_entry_count": max_artifact_entries + 1,
            }
        )
        return _mlflow_budget_failure_result(
            model_uri,
            f"MLflow artifact listing exceeded {max_artifact_entries} entries before download",
            details,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        details.update(
            {
                "reason": "artifact_size_unavailable",
                "error": _redact_mlflow_error_for_display(exc),
            }
        )
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to determine MLflow artifact size before download",
            details,
        )

    total_size = 0
    for artifact in planned_artifacts.values():
        total_size += artifact.size
        if max_file_size > 0 and artifact.size > max_file_size:
            details.update(
                {
                    "reason": "artifact_file_size_exceeded",
                    "artifact_path": artifact.path,
                    "artifact_file_size": artifact.size,
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                f"MLflow artifact file too large to download: {artifact.size} bytes (max: {max_file_size})",
                details,
            )
        if max_total_size > 0 and total_size > max_total_size:
            details.update(
                {
                    "reason": "artifact_total_size_exceeded",
                    "artifact_total_size": total_size,
                    "artifact_file_count": len(planned_artifacts),
                    "artifact_entry_count": entry_count,
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                f"MLflow artifact total size too large to download: {total_size} bytes (max: {max_total_size})",
                details,
            )

    primary_source = sources[0]
    return _MlflowDownloadPlan(
        artifacts=tuple(planned_artifacts.values()),
        root_uri=root_uri,
        local_artifact_root=primary_source.root,
        artifact_path=primary_source.artifact_path,
        max_artifact_entries=max_artifact_entries,
        local_sources=sources,
    )


def _preflight_mlflow_download_budget(
    mlflow_module: Any,
    model_uri: str,
    *,
    max_file_size: int,
    max_total_size: int,
    max_artifact_entries: int,
) -> _MlflowDownloadPlan | _MlflowDelegatedDownloadPlan | ModelAuditResultModel:
    has_finite_budget = _finite_budget(max_file_size, max_total_size)
    root_uri, initial_artifact_path = _split_mlflow_artifact_uri(mlflow_module, model_uri)
    details: dict[str, Any] = {
        "model_uri": model_uri,
        "root_uri": root_uri,
        "artifact_path": initial_artifact_path,
        "max_file_size": max_file_size,
        "max_total_size": max_total_size,
        "max_artifact_entries": max_artifact_entries,
    }
    try:
        artifact_repository = mlflow_module.artifacts.get_artifact_repository(root_uri)
        artifact_repository = _terminal_mlflow_artifact_repository(artifact_repository)
        if artifact_repository is None:
            raise ValueError("Artifact repository wrapper chain could not be resolved")
    except Exception as e:
        details["reason"] = "artifact_size_unavailable"
        details["error"] = _redact_mlflow_error_for_display(e)
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to determine MLflow artifact size before download",
            details,
        )

    if _is_runs_mlflow_artifact_repository(artifact_repository):
        try:
            local_sources = _local_runs_mlflow_sources(artifact_repository, initial_artifact_path)
        except Exception as exc:
            details.update(
                {
                    "reason": "artifact_size_unavailable",
                    "error": _redact_mlflow_error_for_display(exc),
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                "Unable to determine MLflow artifact size before download",
                details,
            )
        if local_sources is None:
            if not has_finite_budget:
                return _trusted_mlflow_delegated_download_plan(
                    model_uri,
                    root_uri,
                    details,
                    artifact_repository,
                    max_file_size=max_file_size,
                    max_total_size=max_total_size,
                    max_artifact_entries=max_artifact_entries,
                )
            details["reason"] = "artifact_streaming_budget_unavailable"
            return _mlflow_budget_failure_result(
                model_uri,
                "MLflow artifact repository cannot enforce the configured download budget",
                details,
            )
        return _preflight_local_mlflow_sources(
            model_uri,
            root_uri,
            local_sources,
            details,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            max_artifact_entries=max_artifact_entries,
        )

    local_artifact_root = _local_mlflow_artifact_root(artifact_repository)
    if local_artifact_root is None:
        if not has_finite_budget:
            return _trusted_mlflow_delegated_download_plan(
                model_uri,
                root_uri,
                details,
                artifact_repository,
                max_file_size=max_file_size,
                max_total_size=max_total_size,
                max_artifact_entries=max_artifact_entries,
            )
        details["reason"] = "artifact_streaming_budget_unavailable"
        return _mlflow_budget_failure_result(
            model_uri,
            "MLflow artifact repository cannot enforce the configured download budget",
            details,
        )

    if _is_local_mlflow_artifact_repository(artifact_repository):
        return _preflight_local_mlflow_sources(
            model_uri,
            root_uri,
            (
                _MlflowLocalSource(
                    local_artifact_root,
                    initial_artifact_path,
                    initial_artifact_path,
                ),
            ),
            details,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            max_artifact_entries=max_artifact_entries,
        )

    list_artifacts = artifact_repository.list_artifacts
    total_size = 0
    file_count = 0
    entry_count = 0
    normalized_initial_path: str | None = None
    pending_dirs: list[str | None] = []
    visited_dirs: set[str | None] = set()
    planned_artifacts: dict[str, _MlflowArtifact] = {}
    try:
        normalized_initial_path = (
            _normalize_mlflow_artifact_path(initial_artifact_path) if initial_artifact_path is not None else None
        )
        pending_dirs.append(normalized_initial_path)
        while pending_dirs:
            current_path = pending_dirs.pop()
            if current_path in visited_dirs:
                continue
            visited_dirs.add(current_path)
            artifact_infos, listing_exceeded = _bounded_artifact_listing(
                list_artifacts,
                current_path,
                max_artifact_entries - entry_count,
            )
            if listing_exceeded:
                details.update(
                    {
                        "reason": "artifact_listing_budget_exceeded",
                        "artifact_entry_count": max_artifact_entries + 1,
                    }
                )
                return _mlflow_budget_failure_result(
                    model_uri,
                    f"MLflow artifact listing exceeded {max_artifact_entries} entries before download",
                    details,
                )

            artifact_infos_already_counted = False
            if not artifact_infos and current_path == normalized_initial_path and current_path:
                artifact_info, parent_entry_count, parent_listing_exceeded = _find_single_file_artifact_info(
                    list_artifacts,
                    current_path,
                    max_artifact_entries - entry_count,
                )
                if parent_listing_exceeded:
                    details.update(
                        {
                            "reason": "artifact_listing_budget_exceeded",
                            "artifact_entry_count": max_artifact_entries + 1,
                        }
                    )
                    return _mlflow_budget_failure_result(
                        model_uri,
                        f"MLflow artifact listing exceeded {max_artifact_entries} entries before download",
                        details,
                    )
                entry_count += parent_entry_count
                artifact_infos = [artifact_info] if artifact_info is not None else []
                artifact_infos_already_counted = artifact_info is not None

            for artifact_info in artifact_infos:
                if not artifact_infos_already_counted:
                    entry_count += 1
                    if entry_count > max_artifact_entries:
                        details.update(
                            {
                                "reason": "artifact_listing_budget_exceeded",
                                "artifact_entry_count": entry_count,
                            }
                        )
                        return _mlflow_budget_failure_result(
                            model_uri,
                            f"MLflow artifact listing exceeded {max_artifact_entries} entries before download",
                            details,
                        )

                raw_artifact_path = getattr(artifact_info, "path", None)
                artifact_path = (
                    current_path
                    if artifact_infos_already_counted and current_path is not None
                    else _normalize_mlflow_artifact_path(raw_artifact_path)
                )
                if not _artifact_path_is_within(artifact_path, current_path):
                    raise ValueError(f"Artifact entry path escaped listed directory: {artifact_path}")
                if getattr(artifact_info, "is_dir", False):
                    pending_dirs.append(artifact_path)
                    continue

                file_size = getattr(artifact_info, "file_size", None)
                if not isinstance(file_size, int) or isinstance(file_size, bool) or file_size < 0:
                    raise ValueError(f"Artifact file size unavailable for {artifact_path or '<unknown>'}")
                if artifact_path in planned_artifacts:
                    raise ValueError(f"Artifact listing returned a duplicate file path: {artifact_path}")

                file_count += 1
                total_size += file_size
                planned_artifacts[artifact_path] = _MlflowArtifact(path=artifact_path, size=file_size)
                if max_file_size > 0 and file_size > max_file_size:
                    details.update(
                        {
                            "reason": "artifact_file_size_exceeded",
                            "artifact_path": artifact_path,
                            "artifact_file_size": file_size,
                        }
                    )
                    return _mlflow_budget_failure_result(
                        model_uri,
                        f"MLflow artifact file too large to download: {file_size} bytes (max: {max_file_size})",
                        details,
                    )
                if max_total_size > 0 and total_size > max_total_size:
                    details.update(
                        {
                            "reason": "artifact_total_size_exceeded",
                            "artifact_total_size": total_size,
                            "artifact_file_count": file_count,
                            "artifact_entry_count": entry_count,
                        }
                    )
                    return _mlflow_budget_failure_result(
                        model_uri,
                        f"MLflow artifact total size too large to download: {total_size} bytes (max: {max_total_size})",
                        details,
                    )
    except Exception as e:
        details["reason"] = "artifact_size_unavailable"
        details["error"] = _redact_mlflow_error_for_display(e)
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to determine MLflow artifact size before download",
            details,
        )

    if file_count == 0:
        try:
            current_artifacts, _ = _snapshot_local_mlflow_artifacts(
                local_artifact_root,
                normalized_initial_path,
                max_artifact_entries,
            )
        except _MlflowArtifactListingExceededError:
            details.update(
                {
                    "reason": "artifact_listing_budget_exceeded",
                    "artifact_entry_count": max_artifact_entries + 1,
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                f"MLflow artifact listing exceeded {max_artifact_entries} entries before download",
                details,
            )
        except (OSError, ValueError) as exc:
            details.update(
                {
                    "reason": "artifact_size_unavailable",
                    "artifact_file_count": 0,
                    "error": _redact_mlflow_error_for_display(exc),
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                "Unable to determine MLflow artifact size before download",
                details,
            )
        if current_artifacts:
            details.update(
                {
                    "reason": "artifact_size_unavailable",
                    "artifact_file_count": 0,
                    "error": "Artifact listing omitted files present in the local repository",
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                "Unable to determine MLflow artifact size before download",
                details,
            )

    return _MlflowDownloadPlan(
        artifacts=tuple(planned_artifacts.values()),
        root_uri=root_uri,
        local_artifact_root=local_artifact_root,
        artifact_path=normalized_initial_path,
        max_artifact_entries=max_artifact_entries,
    )


def _download_preflighted_mlflow_artifacts(
    plan: _MlflowDownloadPlan,
    model_uri: str,
    download_dir: str,
    *,
    max_file_size: int,
    max_total_size: int,
) -> str | ModelAuditResultModel:
    details: dict[str, Any] = {
        "model_uri": model_uri,
        "root_uri": plan.root_uri,
        "max_file_size": max_file_size,
        "max_total_size": max_total_size,
        "artifact_file_count": len(plan.artifacts),
    }

    download_root = Path(download_dir).resolve()
    actual_total_size = 0
    try:
        _verify_local_mlflow_artifact_set(plan)
    except _MlflowArtifactListingExceededError:
        details.update(
            {
                "reason": "artifact_listing_budget_exceeded",
                "artifact_entry_count": plan.max_artifact_entries + 1,
                "max_artifact_entries": plan.max_artifact_entries,
            }
        )
        return _mlflow_budget_failure_result(
            model_uri,
            f"MLflow artifact listing exceeded {plan.max_artifact_entries} entries before download",
            details,
        )
    except _MlflowArtifactSetChangedError as exc:
        details.update(
            {
                "reason": "artifact_download_set_changed",
                "added_artifact_paths": sorted(exc.added_paths)[:10],
                "removed_artifact_paths": sorted(exc.removed_paths)[:10],
            }
        )
        return _mlflow_budget_failure_result(
            model_uri,
            "MLflow artifact file set changed after preflight",
            details,
        )
    except _MlflowArtifactSizeChangedError as exc:
        details.update(
            {
                "reason": "artifact_download_size_changed",
                "artifact_path": exc.artifact_path,
                "expected_artifact_size": exc.expected_size,
                "downloaded_artifact_size": exc.actual_size,
            }
        )
        return _mlflow_budget_failure_result(
            model_uri,
            "MLflow artifact size changed after preflight",
            details,
        )
    except (OSError, ValueError) as exc:
        details.update(
            {
                "reason": "artifact_download_verification_failed",
                "error": _redact_mlflow_error_for_display(exc),
            }
        )
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to verify downloaded MLflow artifact",
            details,
        )

    for artifact in plan.artifacts:
        local_path = download_root.joinpath(*PurePosixPath(artifact.path).parts)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        if not local_path.parent.resolve().is_relative_to(download_root):
            details.update({"reason": "artifact_path_escape", "artifact_path": artifact.path})
            return _mlflow_budget_failure_result(
                model_uri,
                "MLflow artifact path escaped the download directory",
                details,
            )

        try:
            actual_size = _copy_local_mlflow_artifact(
                artifact.source_root or plan.local_artifact_root,
                artifact,
                local_path,
            )
            if local_path.is_symlink() or not local_path.is_file():
                raise ValueError("downloaded path is not a regular file")
            if not local_path.resolve().is_relative_to(download_root):
                raise ValueError("downloaded path escaped the download directory")
        except _MlflowArtifactSizeChangedError as exc:
            details.update(
                {
                    "reason": "artifact_download_size_changed",
                    "artifact_path": artifact.path,
                    "expected_artifact_size": artifact.size,
                    "downloaded_artifact_size": exc.actual_size,
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                "MLflow artifact size changed after preflight",
                details,
            )
        except OSError as exc:
            details.update(
                {
                    "reason": "artifact_download_verification_failed",
                    "artifact_path": artifact.path,
                    "error": _redact_mlflow_error_for_display(exc),
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                "Unable to verify downloaded MLflow artifact",
                details,
            )
        except ValueError as exc:
            details.update(
                {
                    "reason": "artifact_download_verification_failed",
                    "artifact_path": artifact.path,
                    "error": str(exc),
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                "Unable to verify downloaded MLflow artifact",
                details,
            )

        actual_total_size += actual_size
        if max_file_size > 0 and actual_size > max_file_size:
            details.update(
                {
                    "reason": "artifact_file_size_exceeded",
                    "artifact_path": artifact.path,
                    "artifact_file_size": actual_size,
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                f"Downloaded MLflow artifact exceeds the file size budget: {actual_size} bytes (max: {max_file_size})",
                details,
            )
        if max_total_size > 0 and actual_total_size > max_total_size:
            details.update(
                {
                    "reason": "artifact_total_size_exceeded",
                    "artifact_total_size": actual_total_size,
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                f"Downloaded MLflow artifacts exceed the total size budget: {actual_total_size} bytes "
                f"(max: {max_total_size})",
                details,
            )

    try:
        _verify_local_mlflow_artifact_set(plan)
    except (_MlflowArtifactListingExceededError, _MlflowArtifactSetChangedError, _MlflowArtifactSizeChangedError):
        details["reason"] = "artifact_download_set_changed"
        return _mlflow_budget_failure_result(
            model_uri,
            "MLflow artifact file set changed during download",
            details,
        )
    except (OSError, ValueError) as exc:
        details.update(
            {
                "reason": "artifact_download_verification_failed",
                "error": _redact_mlflow_error_for_display(exc),
            }
        )
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to verify downloaded MLflow artifact",
            details,
        )

    return str(download_root)


def _prepare_download_dir(model_uri: str, cache_dir: str | None) -> tuple[str, bool]:
    """Return an ephemeral per-run staging directory under the configured cache root."""
    if not cache_dir:
        return tempfile.mkdtemp(prefix="modelaudit_mlflow_"), True

    cache_key = hashlib.sha256(model_uri.encode("utf-8")).hexdigest()[:16]
    download_root = Path(cache_dir).expanduser() / "mlflow"
    download_root.mkdir(parents=True, exist_ok=True)
    # Use a unique staging directory for this run. ``cache_dir`` controls where
    # temporary downloads live, while scan-result caching is still handled by core.
    return tempfile.mkdtemp(prefix=f"{cache_key}-", dir=str(download_root)), True


def _is_missing_mlflow_artifact_error(error: Exception) -> bool:
    try:
        from mlflow.exceptions import MlflowException
    except Exception:
        return False
    return isinstance(error, MlflowException) and error.error_code == _MLFLOW_RESOURCE_DOES_NOT_EXIST


def _validate_mlflow_delegated_artifact_listing(
    artifact_repository: Any,
    artifact_path: str | None,
    max_artifact_entries: int,
) -> tuple[str, ...]:
    """Reject unsafe remote artifact names before MLflow creates destination paths."""
    list_artifacts = getattr(artifact_repository, "list_artifacts", None)
    if not callable(list_artifacts):
        raise ValueError("MLflow artifact repository does not expose a safe listing API")

    normalized_initial_path = _normalize_mlflow_artifact_path(artifact_path) if artifact_path else None
    pending_directories: list[str | None] = [normalized_initial_path]
    visited_directories: set[str | None] = set()
    entry_count = 0
    artifact_paths: list[str] = []

    while pending_directories:
        current_path = pending_directories.pop()
        if current_path in visited_directories:
            continue
        visited_directories.add(current_path)
        artifact_infos, listing_exceeded = _bounded_artifact_listing(
            list_artifacts,
            current_path,
            max_artifact_entries - entry_count,
        )
        if listing_exceeded:
            raise _MlflowArtifactListingExceededError

        single_file = False
        if not artifact_infos and current_path:
            artifact_info, parent_entry_count, parent_listing_exceeded = _find_single_file_artifact_info(
                list_artifacts,
                current_path,
                max_artifact_entries - entry_count,
            )
            if parent_listing_exceeded:
                raise _MlflowArtifactListingExceededError
            entry_count += parent_entry_count
            artifact_infos = [artifact_info] if artifact_info is not None else []
            single_file = artifact_info is not None

        for artifact_info in artifact_infos:
            if not single_file:
                entry_count += 1
                if entry_count > max_artifact_entries:
                    raise _MlflowArtifactListingExceededError
            listed_path = (
                current_path
                if single_file and current_path is not None
                else _normalize_mlflow_artifact_path(getattr(artifact_info, "path", None))
            )
            if not _artifact_path_is_within(listed_path, current_path):
                raise ValueError(f"Artifact entry path escaped listed directory: {listed_path}")
            if getattr(artifact_info, "is_dir", False):
                pending_directories.append(listed_path)
            else:
                artifact_paths.append(listed_path)
    return tuple(artifact_paths)


def _is_standard_mlflow_artifact_repository(artifact_repository: Any) -> bool:
    try:
        from mlflow.store.artifact.artifact_repo import ArtifactRepository
    except Exception:
        return False
    return isinstance(artifact_repository, ArtifactRepository)


def _download_validated_mlflow_files(
    artifact_repository: Any,
    artifact_paths: tuple[str, ...],
    target_download_dir: Path,
    model_uri: str,
    download_dir: str,
    max_artifact_entries: int,
    expected_download_root: _MlflowDownloadRoot,
) -> str | ModelAuditResultModel:
    download_file = getattr(artifact_repository, "_download_file", None)
    if not callable(download_file):
        return _mlflow_artifact_trust_failure_result(
            model_uri,
            "MLflow artifact repository cannot perform guarded file downloads",
            {"reason": "artifact_guarded_download_unavailable"},
        )

    for artifact_path in artifact_paths:
        local_path = target_download_dir.joinpath(*PurePosixPath(artifact_path).parts)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        parent_check = _resolve_mlflow_download_path(
            model_uri,
            str(local_path.parent),
            download_dir,
            max_artifact_entries,
            expected_download_root,
        )
        if isinstance(parent_check, ModelAuditResultModel):
            return parent_check
        download_file(remote_file_path=artifact_path, local_path=str(local_path))
        file_check = _resolve_mlflow_download_path(
            model_uri,
            str(local_path),
            download_dir,
            max_artifact_entries,
            expected_download_root,
        )
        if isinstance(file_check, ModelAuditResultModel):
            return file_check
    return str(target_download_dir)


def _download_trusted_mlflow_artifacts(
    plan: _MlflowDelegatedDownloadPlan,
    model_uri: str,
    download_dir: str,
    max_artifact_entries: int,
    expected_download_root: _MlflowDownloadRoot,
) -> str | ModelAuditResultModel:
    downloaded_paths: list[str] = []
    for target in plan.targets:
        try:
            artifact_paths = _validate_mlflow_delegated_artifact_listing(
                target.artifact_repository,
                target.artifact_path,
                max_artifact_entries,
            )
        except _MlflowArtifactListingExceededError:
            return _mlflow_budget_failure_result(
                model_uri,
                f"MLflow artifact listing exceeded {max_artifact_entries} entries before download",
                {
                    "reason": "artifact_listing_budget_exceeded",
                    "max_artifact_entries": max_artifact_entries,
                },
            )
        except (TypeError, ValueError) as exc:
            return _mlflow_artifact_trust_failure_result(
                model_uri,
                "MLflow artifact repository returned an unsafe artifact listing",
                {
                    "reason": "artifact_listing_unsafe",
                    "error": _redact_mlflow_error_for_display(exc),
                },
            )
        if target.optional_when_missing and not artifact_paths:
            continue
        target_download_dir = Path(download_dir)
        if target.destination_subdirectory:
            target_download_dir /= target.destination_subdirectory
            target_download_dir.mkdir(parents=True, exist_ok=True)
        destination_check = _resolve_mlflow_download_path(
            model_uri,
            str(target_download_dir),
            download_dir,
            max_artifact_entries,
            expected_download_root,
        )
        if isinstance(destination_check, ModelAuditResultModel):
            return destination_check
        try:
            if _is_standard_mlflow_artifact_repository(target.artifact_repository):
                downloaded_path = _download_validated_mlflow_files(
                    target.artifact_repository,
                    artifact_paths,
                    target_download_dir,
                    model_uri,
                    download_dir,
                    max_artifact_entries,
                    expected_download_root,
                )
                if isinstance(downloaded_path, ModelAuditResultModel):
                    return downloaded_path
            else:
                downloaded_path = target.artifact_repository.download_artifacts(
                    artifact_path=target.artifact_path or "",
                    dst_path=str(target_download_dir),
                )
        except Exception as exc:
            if target.optional_when_missing and _is_missing_mlflow_artifact_error(exc):
                continue
            raise
        if not isinstance(downloaded_path, str) or not downloaded_path:
            raise RuntimeError("MLflow artifact repository did not return a download path")
        download_check = _resolve_mlflow_download_path(
            model_uri,
            downloaded_path,
            download_dir,
            max_artifact_entries,
            expected_download_root,
        )
        if isinstance(download_check, ModelAuditResultModel):
            return download_check
        downloaded_paths.append(downloaded_path)

    if len(downloaded_paths) > 1:
        return download_dir
    if downloaded_paths:
        return downloaded_paths[0]
    raise RuntimeError("MLflow artifact repositories did not return a download path")


def _mlflow_entry_is_reparse_point(path: Path, path_stat: os.stat_result) -> bool:
    """Return whether an entry is a symlink, junction, or other Windows reparse point."""
    if stat.S_ISLNK(path_stat.st_mode):
        return True

    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(path_stat, "st_file_attributes", 0) or 0
    return bool(reparse_flag and file_attributes & reparse_flag)


def _capture_mlflow_download_root(
    model_uri: str,
    download_dir: str,
) -> _MlflowDownloadRoot | ModelAuditResultModel:
    """Capture the private staging directory identity before backend code runs."""
    root_file_descriptor: int | None = None
    try:
        download_dir_path = Path(download_dir).expanduser()
        download_dir_stat = download_dir_path.stat(follow_symlinks=False)
        download_root = download_dir_path.resolve(strict=True)
        download_root_stat = download_root.stat(follow_symlinks=False)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return _mlflow_download_safety_failure_result(
            model_uri,
            "Unable to establish the MLflow staging directory",
            {
                "reason": "artifact_download_root_unavailable",
                "error": _redact_mlflow_error_for_display(exc),
            },
        )

    if (
        not stat.S_ISDIR(download_dir_stat.st_mode)
        or not stat.S_ISDIR(download_root_stat.st_mode)
        or _mlflow_entry_is_reparse_point(download_dir_path, download_dir_stat)
        or _mlflow_entry_is_reparse_point(download_root, download_root_stat)
        or not os.path.samestat(download_dir_stat, download_root_stat)
    ):
        return _mlflow_download_safety_failure_result(
            model_uri,
            "MLflow staging directory is not a stable private directory",
            {"reason": "artifact_download_root_unsupported"},
        )

    try:
        if os.name != "nt":
            open_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
            root_file_descriptor = os.open(download_root, open_flags)
            held_root_stat = os.fstat(root_file_descriptor)
            if not stat.S_ISDIR(held_root_stat.st_mode) or not os.path.samestat(held_root_stat, download_root_stat):
                raise OSError("MLflow staging directory changed while its identity was captured")
            download_root_stat = held_root_stat
    except OSError as exc:
        if root_file_descriptor is not None:
            os.close(root_file_descriptor)
        return _mlflow_download_safety_failure_result(
            model_uri,
            "Unable to hold the MLflow staging directory open",
            {
                "reason": "artifact_download_root_unavailable",
                "error": _redact_mlflow_error_for_display(exc),
            },
        )

    creation_time_ns = getattr(download_root_stat, "st_birthtime_ns", None)
    if creation_time_ns is None and os.name == "nt":
        creation_time_ns = download_root_stat.st_ctime_ns
    return _MlflowDownloadRoot(download_root, download_root_stat, root_file_descriptor, creation_time_ns)


def _validate_mlflow_download_tree(
    model_uri: str,
    download_root: Path,
    max_artifact_entries: int,
) -> ModelAuditResultModel | None:
    """Fail closed on staged entries that core cannot safely and completely scan."""
    pending_directories = [download_root]
    hardlink_counts: dict[tuple[int, int], int] = {}
    hardlink_totals: dict[tuple[int, int], int] = {}
    entry_count = 0

    while pending_directories:
        current_directory = pending_directories.pop()
        try:
            with os.scandir(current_directory) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > max_artifact_entries:
                        return _mlflow_download_safety_failure_result(
                            model_uri,
                            "MLflow staging validation exceeded the artifact entry budget",
                            {
                                "reason": "artifact_download_path_entry_limit",
                                "max_artifact_entries": max_artifact_entries,
                            },
                        )

                    entry_path = Path(entry.path)
                    relative_path = entry_path.relative_to(download_root).as_posix()
                    entry_stat = entry.stat(follow_symlinks=False)

                    if stat.S_ISLNK(entry_stat.st_mode):
                        resolved_target = entry_path.resolve(strict=True)
                        if not resolved_target.is_relative_to(download_root):
                            return _mlflow_download_safety_failure_result(
                                model_uri,
                                "MLflow staging contains a link outside the staging directory",
                                {
                                    "reason": "artifact_download_path_escape",
                                    "artifact_path": relative_path,
                                },
                            )
                        target_stat = resolved_target.stat(follow_symlinks=False)
                        if _mlflow_entry_is_reparse_point(resolved_target, target_stat):
                            return _mlflow_download_safety_failure_result(
                                model_uri,
                                "MLflow staging contains a link to an unsupported reparse point",
                                {
                                    "reason": "artifact_download_path_unsupported",
                                    "artifact_path": relative_path,
                                },
                            )
                        if stat.S_ISDIR(target_stat.st_mode):
                            return _mlflow_download_safety_failure_result(
                                model_uri,
                                "MLflow staging contains a directory link that would not be scanned",
                                {
                                    "reason": "artifact_download_directory_link_unsupported",
                                    "artifact_path": relative_path,
                                },
                            )
                        if not stat.S_ISREG(target_stat.st_mode):
                            return _mlflow_download_safety_failure_result(
                                model_uri,
                                "MLflow staging contains a link to an unsupported filesystem object",
                                {
                                    "reason": "artifact_download_path_unsupported",
                                    "artifact_path": relative_path,
                                },
                            )
                        continue

                    if stat.S_ISDIR(entry_stat.st_mode):
                        if _mlflow_entry_is_reparse_point(entry_path, entry_stat):
                            return _mlflow_download_safety_failure_result(
                                model_uri,
                                "MLflow staging contains a directory link that would not be scanned",
                                {
                                    "reason": "artifact_download_directory_link_unsupported",
                                    "artifact_path": relative_path,
                                },
                            )
                        pending_directories.append(entry_path)
                        continue

                    if _mlflow_entry_is_reparse_point(entry_path, entry_stat):
                        return _mlflow_download_safety_failure_result(
                            model_uri,
                            "MLflow staging contains an unsupported reparse point",
                            {
                                "reason": "artifact_download_path_unsupported",
                                "artifact_path": relative_path,
                            },
                        )

                    if not stat.S_ISREG(entry_stat.st_mode):
                        return _mlflow_download_safety_failure_result(
                            model_uri,
                            "MLflow staging contains an unsupported filesystem object",
                            {
                                "reason": "artifact_download_path_unsupported",
                                "artifact_path": relative_path,
                            },
                        )

                    link_count = int(getattr(entry_stat, "st_nlink", 1))
                    if link_count > 1:
                        inode_key = (entry_stat.st_dev, entry_stat.st_ino)
                        hardlink_counts[inode_key] = hardlink_counts.get(inode_key, 0) + 1
                        previous_total = hardlink_totals.setdefault(inode_key, link_count)
                        if previous_total != link_count:
                            raise OSError("staged hardlink count changed during validation")
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            return _mlflow_download_safety_failure_result(
                model_uri,
                "Unable to validate the MLflow staging directory",
                {
                    "reason": "artifact_download_path_unavailable",
                    "error": _redact_mlflow_error_for_display(exc),
                },
            )

    if any(hardlink_counts[inode_key] != link_total for inode_key, link_total in hardlink_totals.items()):
        return _mlflow_download_safety_failure_result(
            model_uri,
            "MLflow staging contains a file with hardlink aliases outside the staging directory",
            {"reason": "artifact_download_hardlink_escape"},
        )
    return None


def _resolve_mlflow_download_path(
    model_uri: str,
    local_path: str,
    download_dir: str,
    max_artifact_entries: int,
    expected_download_root: _MlflowDownloadRoot,
) -> str | ModelAuditResultModel:
    try:
        download_dir_path = Path(download_dir).expanduser()
        current_download_dir_stat = download_dir_path.stat(follow_symlinks=False)
        download_root = download_dir_path.resolve(strict=True)
        current_download_root_stat = download_root.stat(follow_symlinks=False)
        returned_path = Path(local_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return _mlflow_download_safety_failure_result(
            model_uri,
            "Unable to verify MLflow artifact download path",
            {
                "reason": "artifact_download_path_unavailable",
                "error": _redact_mlflow_error_for_display(exc),
            },
        )

    try:
        held_download_root_stat = (
            os.fstat(expected_download_root.file_descriptor)
            if expected_download_root.file_descriptor is not None
            else expected_download_root.stat
        )
    except OSError as exc:
        return _mlflow_download_safety_failure_result(
            model_uri,
            "Unable to verify the MLflow staging directory identity",
            {
                "reason": "artifact_download_root_unavailable",
                "error": _redact_mlflow_error_for_display(exc),
            },
        )

    current_creation_time_ns = getattr(current_download_root_stat, "st_birthtime_ns", None)
    if current_creation_time_ns is None and os.name == "nt":
        current_creation_time_ns = current_download_root_stat.st_ctime_ns

    if (
        download_root != expected_download_root.path
        or not stat.S_ISDIR(current_download_dir_stat.st_mode)
        or not stat.S_ISDIR(current_download_root_stat.st_mode)
        or _mlflow_entry_is_reparse_point(download_dir_path, current_download_dir_stat)
        or _mlflow_entry_is_reparse_point(download_root, current_download_root_stat)
        or not os.path.samestat(current_download_dir_stat, held_download_root_stat)
        or not os.path.samestat(current_download_root_stat, held_download_root_stat)
        or (
            expected_download_root.file_descriptor is None
            and current_creation_time_ns != expected_download_root.creation_time_ns
        )
    ):
        return _mlflow_download_safety_failure_result(
            model_uri,
            "MLflow staging directory changed during artifact download",
            {"reason": "artifact_download_root_changed"},
        )

    if not returned_path.is_relative_to(download_root):
        return _mlflow_download_safety_failure_result(
            model_uri,
            "MLflow artifact download returned a path outside the staging directory",
            {"reason": "artifact_download_path_escape"},
        )

    try:
        returned_stat = returned_path.stat(follow_symlinks=False)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return _mlflow_download_safety_failure_result(
            model_uri,
            "Unable to inspect MLflow artifact download path",
            {
                "reason": "artifact_download_path_unavailable",
                "error": _redact_mlflow_error_for_display(exc),
            },
        )

    if stat.S_ISREG(returned_stat.st_mode):
        scan_path = returned_path.parent
    elif stat.S_ISDIR(returned_stat.st_mode):
        scan_path = returned_path
    else:
        return _mlflow_download_safety_failure_result(
            model_uri,
            "MLflow artifact download returned an unsupported filesystem object",
            {"reason": "artifact_download_path_unsupported"},
        )

    if not scan_path.is_relative_to(download_root):
        return _mlflow_download_safety_failure_result(
            model_uri,
            "MLflow artifact download resolved outside the staging directory",
            {"reason": "artifact_download_scan_path_escape"},
        )
    staging_failure = _validate_mlflow_download_tree(model_uri, download_root, max_artifact_entries)
    if staging_failure is not None:
        return staging_failure
    return str(scan_path)


def scan_mlflow_model(
    model_uri: str,
    *,
    registry_uri: str | None = None,
    timeout: int = 3600,
    blacklist_patterns: list[str] | None = None,
    max_file_size: int = 0,
    max_total_size: int = 0,
    **kwargs: Any,
) -> ModelAuditResultModel:
    """Download and scan a model from the MLflow model registry.

    Parameters
    ----------
    model_uri:
        URI of the model in MLflow, e.g. ``"models:/MyModel/1"`` or
        ``"models:/MyModel/Production"``.
    registry_uri:
        Optional MLflow registry URI. If provided, ``mlflow.set_registry_uri`` is
        called before downloading the model.
    timeout:
        Maximum time in seconds to spend scanning.
    blacklist_patterns:
        Optional list of blacklist patterns to check against model names.
    max_file_size:
        Maximum artifact file size to download and scan in bytes (0 = unlimited).
    max_total_size:
        Maximum total artifact bytes to download and scan (0 = unlimited).
    **kwargs:
        Additional arguments passed to :func:`scan_model_directory_or_file`.

    Returns
    -------
    ModelAuditResultModel
        Scan results as returned by
        :func:`scan_model_directory_or_file`.

    Raises
    ------
    ImportError
        If the ``mlflow`` package is not installed.
    """
    try:
        import mlflow
    except Exception as e:  # pragma: no cover - handled in tests
        raise ImportError("mlflow is not installed, cannot scan MLflow models") from e

    if registry_uri:
        mlflow.set_registry_uri(registry_uri)  # type: ignore[possibly-unbound-attribute]

    scan_kwargs = kwargs.copy()
    cache_enabled = scan_kwargs.pop("cache_enabled", True)
    raw_cache_dir = scan_kwargs.pop("cache_dir", None)
    max_artifact_entries = _normalize_max_artifact_entries(
        scan_kwargs.pop("max_mlflow_artifact_entries", _DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES)
    )
    scan_cache_dir = str(Path(raw_cache_dir).expanduser()) if cache_enabled and raw_cache_dir else None

    download_plan = _preflight_mlflow_download_budget(
        mlflow,
        model_uri,
        max_file_size=max_file_size,
        max_total_size=max_total_size,
        max_artifact_entries=max_artifact_entries,
    )
    if isinstance(download_plan, ModelAuditResultModel):
        return download_plan

    download_dir, cleanup_download_dir = _prepare_download_dir(model_uri, scan_cache_dir)
    download_root_identity: _MlflowDownloadRoot | None = None

    try:
        captured_download_root = _capture_mlflow_download_root(model_uri, download_dir)
        if isinstance(captured_download_root, ModelAuditResultModel):
            return captured_download_root
        download_root_identity = captured_download_root

        logger.debug(f"Downloading MLflow model {_redact_mlflow_error_for_display(model_uri)} to {download_dir}")
        local_path: str | None
        if isinstance(download_plan, _MlflowDownloadPlan):
            download_result = _download_preflighted_mlflow_artifacts(
                download_plan,
                model_uri,
                download_dir,
                max_file_size=max_file_size,
                max_total_size=max_total_size,
            )
            if isinstance(download_result, ModelAuditResultModel):
                return download_result
            local_path = download_result
        else:
            local_path = None
            if download_plan.local_plan is not None:
                local_download_result = _download_preflighted_mlflow_artifacts(
                    download_plan.local_plan,
                    model_uri,
                    download_dir,
                    max_file_size=max_file_size,
                    max_total_size=max_total_size,
                )
                if isinstance(local_download_result, ModelAuditResultModel):
                    return local_download_result
                local_path = local_download_result
            if download_plan.targets:
                delegated_path = _download_trusted_mlflow_artifacts(
                    download_plan,
                    model_uri,
                    download_dir,
                    max_artifact_entries,
                    download_root_identity,
                )
                if isinstance(delegated_path, ModelAuditResultModel):
                    return delegated_path
                local_path = download_dir if local_path is not None else delegated_path
            if local_path is None:
                raise RuntimeError("MLflow artifact download plan did not contain any targets")
        download_path = _resolve_mlflow_download_path(
            model_uri,
            local_path,
            download_dir,
            max_artifact_entries,
            download_root_identity,
        )
        if isinstance(download_path, ModelAuditResultModel):
            return download_path
        cache_config = {"cache_enabled": cache_enabled, "cache_dir": scan_cache_dir}

        # Import here to avoid circular dependency
        from ..core import scan_model_directory_or_file

        return scan_model_directory_or_file(
            download_path,
            timeout=timeout,
            blacklist_patterns=blacklist_patterns,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            **cache_config,
            **scan_kwargs,
        )
    finally:
        if download_root_identity is not None and download_root_identity.file_descriptor is not None:
            os.close(download_root_identity.file_descriptor)
        if cleanup_download_dir:
            shutil.rmtree(download_dir, ignore_errors=True)
