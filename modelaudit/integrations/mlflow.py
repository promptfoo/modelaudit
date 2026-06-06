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

from ..detectors.network_comm import _redact_urls_in_text
from ..models import Check, CheckStatus, Issue, IssueSeverity, ModelAuditResultModel, create_initial_audit_result
from ..scanners._evidence_redaction import redact_evidence_string, redact_evidence_value
from ..utils.sources.cloud_storage import redact_cloud_error_for_display

logger = logging.getLogger(__name__)

_MLFLOW_DOWNLOAD_BUDGET_CHECK = "MLflow Download Size Check"
_DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES = 10000
_MAX_MLFLOW_ERROR_DISPLAY_CHARS = 512
_MLFLOW_COPY_CHUNK_SIZE = 1024 * 1024
_OS_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_IS_WINDOWS = os.name == "nt"
_MLFLOW_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?<![\w-])[\"']?"
    r"(?:authorization|proxy-authorization|access[_-]?key|access[_-]?token|api[_-]?key|credential|password|secret|token)"
    r"[\"']?\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|(?:(?:bearer|basic|token)\s+)?[^\s,;}\]]+)"
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
    safe_model_uri = redact_evidence_string(model_uri, max_chars=_MAX_MLFLOW_ERROR_DISPLAY_CHARS)
    safe_details = redact_evidence_value(details, max_string_chars=_MAX_MLFLOW_ERROR_DISPLAY_CHARS)

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


def _redact_mlflow_error_for_display(error: object) -> str:
    redacted = redact_cloud_error_for_display(_redact_urls_in_text(str(error)))

    def _replace_sensitive_value(match: re.Match[str]) -> str:
        value = match.group("value")
        quote = value[0] if value[:1] in {'"', "'"} else ""
        return f"{match.group('prefix')}{quote}<redacted>{quote}"

    redacted = _MLFLOW_SENSITIVE_ASSIGNMENT_RE.sub(_replace_sensitive_value, redacted)
    if len(redacted) <= _MAX_MLFLOW_ERROR_DISPLAY_CHARS:
        return redacted
    return f"{redacted[: _MAX_MLFLOW_ERROR_DISPLAY_CHARS - 3]}..."


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

    try:
        artifact_root = Path(repository.artifact_dir).expanduser().resolve(strict=True)
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
        logger.debug("MLflow logged-model lookup failed; continuing with bounded local run artifacts")
        return tuple(sources)
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
    except (OSError, TypeError, ValueError) as exc:
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
) -> _MlflowDownloadPlan | ModelAuditResultModel | None:
    if not _finite_budget(max_file_size, max_total_size):
        return None

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

    try:
        logger.debug(f"Downloading MLflow model {model_uri} to {download_dir}")
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
            local_path = mlflow.artifacts.download_artifacts(artifact_uri=model_uri, dst_path=download_dir)  # type: ignore[possibly-unbound-attribute]
        # mlflow may return a file within the download directory; ensure directory path
        download_path = os.path.dirname(local_path) if os.path.isfile(local_path) else local_path
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
        if cleanup_download_dir:
            shutil.rmtree(download_dir, ignore_errors=True)
