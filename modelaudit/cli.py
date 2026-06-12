"""Command-line interface for ModelAudit security scanner."""

import contextlib
import errno
import json
import logging
import os
import platform
import re
import secrets
import shutil
import stat
import sys
import time
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any, NoReturn, cast

import click
from pydantic import TypeAdapter
from yaspin import yaspin
from yaspin.spinners import Spinners

from . import __version__
from .auth.client import auth_client
from .auth.config import (
    cloud_config,
    config,
    get_config_directory_path,
    get_user_email,
    get_user_id,
    is_delegated_from_promptfoo,
    set_user_email,
)
from .cache.trusted_config_store import TrustedConfigStore
from .config import ModelAuditConfig, set_config
from .config.local_config import find_local_config_for_paths
from .core import (
    DVC_EXTERNAL_COVERED_DIRECTORIES_CONFIG_KEY,
    DVC_EXTERNAL_COVERED_PATHS_CONFIG_KEY,
    _make_trusted_stream_shard_root,
    _reconcile_cross_directory_shard_coverage,
    _snapshot_validated_shard_target,
    determine_exit_code,
    scan_model_directory_or_file,
)
from .core_results import (
    details_have_incomplete_coverage,
    details_match_shard_family_paths,
    metadata_has_incomplete_coverage,
    records_have_incomplete_coverage_for_path,
    results_have_incomplete_coverage_under_directory,
    results_have_inconclusive_outcome,
)
from .integrations.jfrog import scan_jfrog_artifact
from .integrations.sarif_formatter import format_sarif_output
from .integrations.source_redaction import redact_source_value
from .models import FileMetadataModel, ModelAuditResultModel
from .rules import Rule, RuleRegistry, Severity
from .scanner_results import (
    INCONCLUSIVE_SCAN_OUTCOME,
    SCAN_OUTCOME_METADATA_KEY,
    SCAN_OUTCOME_REASONS_METADATA_KEY,
    Issue,
    IssueSeverity,
)
from .scanner_selection import (
    SCANNER_SELECTION_CONFIG_KEY,
    collect_suppressed_preferred_scanners,
    policy_from_config,
    scanner_catalog,
    scanner_selection_config_from_inputs,
    selected_scanner_extensions,
    selected_scanner_filenames,
)
from .scanners.base import make_trusted_source_provenance
from .telemetry import (
    flush_telemetry,
    record_command_used,
    record_download_completed,
    record_download_started,
    record_feature_used,
    record_scan_completed,
    record_scan_failed,
    record_scan_started,
)
from .utils import resolve_dvc_file_with_metadata, should_skip_file
from .utils.file.handlers import ShardedModelDetector, ValidatedShardTargets
from .utils.helpers.auto_defaults import (
    apply_auto_overrides,
    detect_ci_environment,
    generate_auto_defaults,
    parse_size_string,
)
from .utils.helpers.interrupt_handler import interruptible_scan
from .utils.repository_context import (
    REPOSITORY_CURRENT_FILE_CONFIG_KEY,
    REPOSITORY_FILE_INVENTORY_CONFIG_KEY,
    REPOSITORY_SCAN_ROOT_CONFIG_KEY,
)
from .utils.sources.cloud_storage import (
    download_from_cloud,
    is_cleartext_cloud_url,
    is_cloud_url,
    is_stream_url,
    redact_cloud_error_for_display,
    redact_stream_error_for_display,
    redact_stream_url_for_display,
    redact_url_for_display,
)
from .utils.sources.huggingface import (
    download_file_from_hf,
    download_model,
    extract_model_id_from_path,
    get_model_info,
    is_huggingface_file_url,
    is_huggingface_url,
    parse_huggingface_file_url,
    parse_huggingface_url_with_revision,
    redact_huggingface_url_for_display,
    redact_huggingface_urls_in_text,
)
from .utils.sources.jfrog import (
    is_jfrog_url,
    is_jfrog_url_like,
    redact_jfrog_error_for_display,
    redact_jfrog_url_for_display,
)
from .utils.sources.pytorch_hub import (
    download_pytorch_hub_model,
    is_cleartext_pytorch_hub_url,
    is_pytorch_hub_url,
)

logger = logging.getLogger("modelaudit")
_JSON_VALUE_ADAPTER = TypeAdapter(Any)


def _display_path(path: str) -> str:
    """Return a path safe for user-facing CLI output."""
    return _escape_terminal_text(_display_scan_path(path))


def _display_scan_path(path: str) -> str:
    """Return an exact local path or a credential-redacted remote identifier."""
    if path.startswith("models:/"):
        from .integrations.mlflow import _redact_mlflow_error_for_display

        return _redact_mlflow_error_for_display(path)
    if is_stream_url(path):
        return f"stream://{redact_stream_url_for_display(path[9:])}"
    if (
        is_cloud_url(path)
        or is_cleartext_cloud_url(path)
        or is_pytorch_hub_url(path)
        or is_cleartext_pytorch_hub_url(path)
    ):
        return redact_url_for_display(path)
    if is_jfrog_url_like(path):
        return redact_jfrog_url_for_display(path)
    return redact_huggingface_url_for_display(path)


def _display_error(error: object, path: str) -> str:
    """Return an error safe for user-facing CLI output."""
    if is_stream_url(path):
        display_error = redact_stream_error_for_display(error, path[9:])
    elif is_huggingface_url(path) or is_huggingface_file_url(path):
        display_error = redact_huggingface_urls_in_text(str(error))
    elif is_jfrog_url_like(path):
        display_error = redact_jfrog_error_for_display(error, path)
    elif is_mlflow_uri(path):
        from .integrations.mlflow import _redact_mlflow_error_for_display

        display_error = _redact_mlflow_error_for_display(error)
    else:
        display_error = (
            redact_cloud_error_for_display(error, path)
            if is_cloud_url(path)
            or is_cleartext_cloud_url(path)
            or is_pytorch_hub_url(path)
            or is_cleartext_pytorch_hub_url(path)
            else str(error)
        )
    return _escape_terminal_text(display_error)


class _OutputWriteError(click.ClickException):
    """Report output failures using the scan command's documented error code."""

    exit_code = 2


def _absolute_output_path(output_path: str) -> Path:
    """Build an absolute path without collapsing symlink-sensitive ``..`` parts."""
    if os.name == "nt":
        windows_path = PureWindowsPath(output_path)
        path_parts = windows_path.parts[1:] if windows_path.anchor else windows_path.parts
        if any(":" in part for part in path_parts):
            raise _OutputWriteError(f"Refusing alternate data stream output path: {_display_path(output_path)}")
    separators = tuple(separator for separator in (os.sep, os.altsep) if separator)
    if output_path.endswith(separators):
        raise _OutputWriteError(f"Refusing output path with trailing separator: {_display_path(output_path)}")
    if output_path == "." or any(output_path.endswith(f"{separator}.") for separator in separators):
        raise _OutputWriteError(f"Refusing output path with final dot component: {_display_path(output_path)}")
    path = Path(output_path)
    if path.is_absolute():
        return path
    if path.drive:
        raise _OutputWriteError(f"Refusing drive-relative output path: {_display_path(output_path)}")
    return Path.cwd() / path


def _is_link_like_path(path: Path) -> bool:
    """Return whether an existing path is a symlink or Windows reparse point."""
    try:
        path_stat = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return False

    if stat.S_ISLNK(path_stat.st_mode):
        return True

    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(path_stat, "st_file_attributes", 0)
    if not reparse_attribute or not file_attributes & reparse_attribute:
        return False

    reparse_tag = getattr(path_stat, "st_reparse_tag", 0)
    name_surrogate_flag = 0x20000000
    return not reparse_tag or bool(reparse_tag & name_surrogate_flag)


def _darwin_fd_has_extended_acl(fd: int) -> bool:
    """Return whether a macOS descriptor has an extended ACL."""
    if platform.system() != "Darwin":
        return False

    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    acl_extended_fd = libc.acl_extended_fd_np
    acl_extended_fd.argtypes = (ctypes.c_int,)
    acl_extended_fd.restype = ctypes.c_int
    result = acl_extended_fd(fd)
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return bool(result)


def _directory_can_replace_entries(path: Path) -> bool:
    """Return whether an untrusted user could replace names in a directory."""
    try:
        path_stat = path.stat()
    except OSError:
        return True

    if os.name != "posix":
        return True
    if platform.system() == "Darwin":
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(path, directory_flags)
            try:
                if _darwin_fd_has_extended_acl(directory_fd):
                    return True
            finally:
                os.close(directory_fd)
        except OSError:
            return True
    elif hasattr(os, "listxattr"):
        try:
            if "system.posix_acl_access" in os.listxattr(path):
                return True
        except OSError as exc:
            if exc.errno not in {errno.ENOTSUP, errno.EOPNOTSUPP}:
                return True

    writable_by_others = bool(path_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    if path_stat.st_uid != 0 or writable_by_others:
        return True

    get_effective_uid = getattr(os, "geteuid", None)
    if get_effective_uid is None or get_effective_uid() == 0:
        return False

    access_kwargs = {"effective_ids": True} if os.access in os.supports_effective_ids else {}
    return os.access(path, os.W_OK, **access_kwargs)


def _posix_fd_has_extended_acl(output_path: str, fd: int) -> bool:
    """Return whether a macOS file has an ACL that this writer cannot preserve."""
    try:
        return _darwin_fd_has_extended_acl(fd)
    except OSError as exc:
        raise _OutputWriteError(
            f"Unable to inspect output ACL for {_display_path(output_path)}: {exc.strerror or exc}"
        ) from exc


def _open_windows_output_parent_guard(output_path: str, absolute_path: Path) -> int:
    """Pin a Windows output parent so path-based replacement cannot be redirected."""
    import ctypes
    import ctypes.wintypes as wintypes

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("file_attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD)]

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE

    file_traverse = 0x0020
    file_read_attributes = 0x0080
    file_share_read = 0x00000001
    file_share_write = 0x00000002
    open_existing = 3
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    handle = create_file(
        str(absolute_path.parent),
        file_traverse | file_read_attributes,
        file_share_read | file_share_write,
        None,
        open_existing,
        file_flag_backup_semantics | file_flag_open_reparse_point,
        None,
    )
    invalid_handle_value = ctypes.c_void_p(-1).value
    if handle in (None, invalid_handle_value):
        error = ctypes_windows.get_last_error()
        raise _OutputWriteError(
            f"Unable to secure output parent for {_display_path(output_path)}: {ctypes_windows.WinError(error)}"
        )

    handle_value = handle if isinstance(handle, int) else int(handle.value)
    try:
        get_file_information = kernel32.GetFileInformationByHandleEx
        get_file_information.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
        get_file_information.restype = wintypes.BOOL
        file_attribute_tag_info_class = 9
        tag_info = FileAttributeTagInfo()
        if not get_file_information(
            handle,
            file_attribute_tag_info_class,
            ctypes.byref(tag_info),
            ctypes.sizeof(tag_info),
        ):
            error = ctypes_windows.get_last_error()
            raise _OutputWriteError(
                f"Unable to validate output parent for {_display_path(output_path)}: {ctypes_windows.WinError(error)}"
            )

        reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
        name_surrogate_flag = 0x20000000
        if tag_info.file_attributes & reparse_attribute and (
            not tag_info.reparse_tag or tag_info.reparse_tag & name_surrogate_flag
        ):
            raise _OutputWriteError(
                f"Refusing to write output through symlink or reparse point: {_display_path(output_path)}"
            )

        if _validated_absolute_output_path(output_path) != absolute_path:
            raise _OutputWriteError(f"Refusing to write output because its path changed: {_display_path(output_path)}")
        return handle_value
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def _close_windows_handle(handle: int) -> None:
    """Close a native Windows handle acquired for output-path protection."""
    import ctypes
    import ctypes.wintypes as wintypes

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    close_handle(handle)


def _windows_handle_identity(output_path: str, handle: int) -> tuple[int, int, int]:
    """Return a stable volume and file identifier for a Windows handle."""
    import ctypes
    import ctypes.wintypes as wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    get_file_information = kernel32.GetFileInformationByHandle
    get_file_information.argtypes = (wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation))
    get_file_information.restype = wintypes.BOOL
    information = ByHandleFileInformation()
    if not get_file_information(handle, ctypes.byref(information)):
        error = ctypes_windows.get_last_error()
        raise _OutputWriteError(
            f"Unable to identify output parent for {_display_path(output_path)}: {ctypes_windows.WinError(error)}"
        )
    return information.volume_serial_number, information.file_index_high, information.file_index_low


def _open_windows_output_parent_lock(output_path: str, absolute_path: Path, parent_handle: int) -> int:
    """Open a delete-on-close child that locks the validated Windows parent hierarchy."""
    import ctypes
    import ctypes.wintypes as wintypes

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE

    delete_access = 0x00010000
    file_read_attributes = 0x0080
    file_share_read = 0x00000001
    file_share_write = 0x00000002
    create_new = 1
    file_attribute_temporary = 0x00000100
    file_flag_delete_on_close = 0x04000000
    lock_path = absolute_path.parent / f".modelaudit-output-{secrets.token_hex(12)}.lock"
    lock_handle = create_file(
        str(lock_path),
        delete_access | file_read_attributes,
        file_share_read | file_share_write,
        None,
        create_new,
        file_attribute_temporary | file_flag_delete_on_close,
        None,
    )
    invalid_handle_value = ctypes.c_void_p(-1).value
    if lock_handle in (None, invalid_handle_value):
        error = ctypes_windows.get_last_error()
        raise _OutputWriteError(
            f"Unable to lock output parent for {_display_path(output_path)}: {ctypes_windows.WinError(error)}"
        )

    lock_handle_value = lock_handle if isinstance(lock_handle, int) else int(lock_handle.value)
    verification_handle: int | None = None
    try:
        verification_handle = _open_windows_output_parent_guard(output_path, absolute_path)
        if _windows_handle_identity(output_path, parent_handle) != _windows_handle_identity(
            output_path,
            verification_handle,
        ):
            raise _OutputWriteError(
                f"Refusing to write output because its parent changed: {_display_path(output_path)}"
            )
        return lock_handle_value
    except Exception:
        _close_windows_handle(lock_handle_value)
        raise
    finally:
        if verification_handle is not None:
            _close_windows_handle(verification_handle)


def _windows_output_is_encrypted(fd: int) -> bool:
    """Return whether a pinned Windows output handle uses EFS encryption."""
    file_attribute_encrypted = getattr(stat, "FILE_ATTRIBUTE_ENCRYPTED", 0x00004000)
    return bool(getattr(os.fstat(fd), "st_file_attributes", 0) & file_attribute_encrypted)


def _reject_windows_encrypted_output(output_path: str, fd: int) -> None:
    """Fail closed when atomic replacement cannot preserve EFS recipients."""
    if _windows_output_is_encrypted(fd):
        raise _OutputWriteError(
            f"Refusing to replace encrypted output because its EFS protection cannot be preserved: "
            f"{_display_path(output_path)}"
        )


def _open_windows_output_temp_file(
    output_path: str,
    absolute_path: Path,
    temp_name: str,
    *,
    preserve_security: bool,
) -> tuple[int, Path]:
    """Create a writable Windows temp file whose handle can be renamed securely."""
    import ctypes
    import ctypes.wintypes as wintypes
    import msvcrt

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE

    generic_write = 0x40000000
    delete_access = 0x00010000
    file_read_attributes = 0x0080
    write_dac = 0x00040000
    write_owner = 0x00080000
    create_new = 1
    file_attribute_normal = 0x00000080
    temp_path = absolute_path.parent / temp_name
    desired_access = generic_write | delete_access | file_read_attributes
    if preserve_security:
        desired_access |= write_dac | write_owner
    temp_handle = create_file(
        str(temp_path),
        desired_access,
        0,
        None,
        create_new,
        file_attribute_normal,
        None,
    )
    invalid_handle_value = ctypes.c_void_p(-1).value
    if temp_handle in (None, invalid_handle_value):
        error = ctypes_windows.get_last_error()
        raise _OutputWriteError(
            f"Unable to create output temporary file for {_display_path(output_path)}: {ctypes_windows.WinError(error)}"
        )

    temp_handle_value = temp_handle if isinstance(temp_handle, int) else int(temp_handle.value)
    try:
        msvcrt_windows: Any = msvcrt
        temp_fd = msvcrt_windows.open_osfhandle(temp_handle_value, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    except Exception:
        _close_windows_handle(temp_handle_value)
        raise
    return temp_fd, temp_path


def _open_windows_existing_output_file(output_path: str, absolute_path: Path) -> int:
    """Open a Windows output with DACL-enforced write and replacement access."""
    import ctypes
    import ctypes.wintypes as wintypes
    import msvcrt

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE

    file_write_data = 0x0002
    file_read_attributes = 0x0080
    read_control = 0x00020000
    delete_access = 0x00010000
    file_share_read = 0x00000001
    file_share_write = 0x00000002
    file_share_delete = 0x00000004
    open_existing = 3
    file_flag_open_reparse_point = 0x00200000
    handle = create_file(
        str(absolute_path),
        file_write_data | file_read_attributes | read_control | delete_access,
        file_share_read | file_share_write | file_share_delete,
        None,
        open_existing,
        file_flag_open_reparse_point,
        None,
    )
    invalid_handle_value = ctypes.c_void_p(-1).value
    if handle in (None, invalid_handle_value):
        error = ctypes_windows.get_last_error()
        raise _OutputWriteError(
            f"Unable to write output {_display_path(output_path)}: {ctypes_windows.WinError(error)}"
        )

    handle_value = handle if isinstance(handle, int) else int(handle.value)
    try:
        msvcrt_windows: Any = msvcrt
        return int(msvcrt_windows.open_osfhandle(handle_value, os.O_WRONLY | getattr(os, "O_BINARY", 0)))
    except Exception:
        _close_windows_handle(handle_value)
        raise


def _copy_windows_output_security(output_path: str, source_fd: int, target_fd: int) -> None:
    """Copy ownership and the DACL from a validated Windows output handle."""
    import ctypes
    import ctypes.wintypes as wintypes
    import msvcrt

    ctypes_windows: Any = ctypes
    advapi32 = ctypes_windows.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    get_security_info = advapi32.GetSecurityInfo
    get_security_info.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    )
    get_security_info.restype = wintypes.DWORD
    set_security_info = advapi32.SetSecurityInfo
    set_security_info.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    )
    set_security_info.restype = wintypes.DWORD
    get_security_descriptor_control = advapi32.GetSecurityDescriptorControl
    get_security_descriptor_control.argtypes = (
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    )
    get_security_descriptor_control.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = (wintypes.HLOCAL,)
    local_free.restype = wintypes.HLOCAL

    msvcrt_windows: Any = msvcrt
    source_handle = msvcrt_windows.get_osfhandle(source_fd)
    target_handle = msvcrt_windows.get_osfhandle(target_fd)
    owner = wintypes.LPVOID()
    group = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    security_descriptor = wintypes.LPVOID()
    se_file_object = 1
    owner_security_information = 0x00000001
    group_security_information = 0x00000002
    dacl_security_information = 0x00000004
    security_information = owner_security_information | group_security_information | dacl_security_information
    result = get_security_info(
        source_handle,
        se_file_object,
        security_information,
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if result:
        raise _OutputWriteError(
            f"Unable to preserve output security for {_display_path(output_path)}: {ctypes_windows.WinError(result)}"
        )

    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not get_security_descriptor_control(
            security_descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            error = ctypes_windows.get_last_error()
            raise _OutputWriteError(
                f"Unable to preserve output security for {_display_path(output_path)}: {ctypes_windows.WinError(error)}"
            )
        se_dacl_protected = 0x1000
        security_information |= 0x80000000 if control.value & se_dacl_protected else 0x20000000
        result = set_security_info(
            target_handle,
            se_file_object,
            security_information,
            owner,
            group,
            dacl,
            None,
        )
        if result:
            raise _OutputWriteError(
                f"Unable to preserve output security for {_display_path(output_path)}: "
                f"{ctypes_windows.WinError(result)}"
            )
    finally:
        if security_descriptor:
            local_free(security_descriptor)


def _replace_windows_output_file(
    output_path: str,
    temp_fd: int,
    destination_path: Path,
    *,
    replace_existing: bool,
) -> None:
    """Atomically rename an open Windows temp file within its pinned parent."""
    import ctypes
    import ctypes.wintypes as wintypes
    import msvcrt

    class FileRenameInfo(ctypes.Structure):
        _fields_ = [
            ("flags", wintypes.DWORD),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            ("file_name", wintypes.WCHAR * 1),
        ]

    encoded_name = str(destination_path).encode("utf-16-le")
    file_name_offset = FileRenameInfo.file_name.offset
    buffer_size = ctypes.sizeof(FileRenameInfo) + len(encoded_name)
    rename_buffer = ctypes.create_string_buffer(buffer_size)
    rename_info = ctypes.cast(rename_buffer, ctypes.POINTER(FileRenameInfo)).contents
    file_rename_replace_if_exists = 0x00000001
    file_rename_posix_semantics = 0x00000002
    rename_info.flags = file_rename_replace_if_exists | file_rename_posix_semantics if replace_existing else 0
    rename_info.root_directory = None
    rename_info.file_name_length = len(encoded_name)
    ctypes.memmove(ctypes.addressof(rename_buffer) + file_name_offset, encoded_name, len(encoded_name))

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    set_file_information = kernel32.SetFileInformationByHandle
    set_file_information.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    set_file_information.restype = wintypes.BOOL
    file_rename_info_ex_class = 22
    msvcrt_windows: Any = msvcrt
    temp_handle = msvcrt_windows.get_osfhandle(temp_fd)
    if not set_file_information(temp_handle, file_rename_info_ex_class, rename_buffer, buffer_size):
        error = ctypes_windows.get_last_error()
        raise _OutputWriteError(
            f"Unable to write output {_display_path(output_path)}: {ctypes_windows.WinError(error)}"
        )


def _validated_absolute_output_path(output_path: str) -> Path:
    """Resolve protected parent links and reject attacker-replaceable ones."""
    absolute_path = _absolute_output_path(output_path)
    current_path = Path(absolute_path.anchor)
    path_parts = absolute_path.parts[1:]
    for index, part in enumerate(path_parts):
        if part == ".." and os.name == "nt":
            if _is_link_like_path(current_path):
                raise _OutputWriteError(
                    f"Refusing to write output through symlink or reparse point: {_display_path(output_path)}"
                )
            try:
                component_stat = current_path.lstat()
            except OSError as exc:
                raise _OutputWriteError(
                    f"Refusing output path through invalid parent component: {_display_path(output_path)}"
                ) from exc
            if not stat.S_ISDIR(component_stat.st_mode):
                raise _OutputWriteError(
                    f"Refusing output path through non-directory component: {_display_path(output_path)}"
                )

        candidate_path = current_path / part
        if not _is_link_like_path(candidate_path):
            current_path = candidate_path
            continue

        if index == len(path_parts) - 1 or _directory_can_replace_entries(current_path):
            raise _OutputWriteError(
                f"Refusing to write output through symlink or reparse point: {_display_path(output_path)}"
            )
        current_path = candidate_path.resolve(strict=True)

    return current_path


def _open_output_parent_directory(output_path: str) -> tuple[Path, int | None, int | None]:
    """Open the validated output parent without following replaceable links."""
    absolute_path = _validated_absolute_output_path(output_path)
    if os.name == "nt":
        return absolute_path, None, _open_windows_output_parent_guard(output_path, absolute_path)

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    directory_access = getattr(os, "O_PATH", 0) or getattr(os, "O_SEARCH", 0)
    dir_fd_functions = (os.open, os.stat, os.link, os.rename, os.unlink, os.mkdir, os.rmdir)
    if (
        os.name != "posix"
        or not nofollow
        or not directory
        or any(function not in os.supports_dir_fd for function in dir_fd_functions)
    ):
        raise _OutputWriteError(f"Secure output writes are unsupported on this platform: {_display_path(output_path)}")

    directory_flags = directory_access | directory | nofollow
    directory_fds: list[int] = []
    try:
        root_fd = os.open(absolute_path.anchor, directory_flags)
        try:
            directory_fds.append(root_fd)
        except BaseException:
            os.close(root_fd)
            raise
        for part in absolute_path.parts[1:-1]:
            if part == "..":
                if len(directory_fds) > 1:
                    os.close(directory_fds.pop())
                continue
            if part in {"", "."}:
                continue
            child_fd = os.open(part, directory_flags, dir_fd=directory_fds[-1])
            try:
                directory_fds.append(child_fd)
            except BaseException:
                os.close(child_fd)
                raise
        output_parent_fd = directory_fds.pop()
        for directory_fd in directory_fds:
            os.close(directory_fd)
        return absolute_path, output_parent_fd, None
    except Exception:
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)
        raise


def _validate_existing_output_path(
    output_path: str,
    absolute_path: Path,
    *,
    parent_fd: int | None,
) -> os.stat_result | None:
    """Reject unsafe existing outputs before opening devices or special files."""
    try:
        if parent_fd is None:
            path_stat = absolute_path.lstat()
        else:
            path_stat = os.stat(absolute_path.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None

    output_display = _display_path(output_path)
    if not stat.S_ISREG(path_stat.st_mode):
        raise _OutputWriteError(f"Refusing to write output to non-regular file: {output_display}")
    access_kwargs: dict[str, Any] = {}
    if os.access in os.supports_effective_ids:
        access_kwargs["effective_ids"] = True
    access_path: str | Path = absolute_path
    if parent_fd is not None and os.access in os.supports_dir_fd:
        access_path = absolute_path.name
        access_kwargs["dir_fd"] = parent_fd
        if os.access in os.supports_follow_symlinks:
            access_kwargs["follow_symlinks"] = False
    if not os.access(access_path, os.W_OK, **access_kwargs):
        raise _OutputWriteError(f"Unable to write output {output_display}: Permission denied")
    return path_stat


def _validate_fallback_temporary_file(
    output_path: str,
    absolute_path: Path,
    temp_path: Path,
    temp_fd: int,
) -> None:
    """Ensure fallback path resolution did not redirect temporary-file creation."""
    output_display = _display_path(output_path)
    if _validated_absolute_output_path(output_path) != absolute_path:
        raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}")

    opened_stat = os.fstat(temp_fd)
    if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_nlink != 1:
        raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}")
    if os.name == "nt":
        return

    try:
        path_stat = temp_path.lstat()
    except OSError as exc:
        raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}") from exc

    if not os.path.samestat(opened_stat, path_stat):
        raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}")


def _open_existing_output_file(
    output_path: str,
    absolute_path: Path,
    initial_stat: os.stat_result,
    *,
    parent_fd: int | None,
) -> int:
    """Open an existing validated output without truncating or following a replacement link."""
    if os.name == "nt":
        output_fd = _open_windows_existing_output_file(output_path, absolute_path)
    else:
        flags = os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow
        if parent_fd is None:
            output_fd = os.open(absolute_path, flags)
        else:
            output_fd = os.open(absolute_path.name, flags, dir_fd=parent_fd)

    try:
        opened_stat = os.fstat(output_fd)
        if not stat.S_ISREG(opened_stat.st_mode) or not os.path.samestat(initial_stat, opened_stat):
            raise _OutputWriteError(f"Refusing to write output because its path changed: {_display_path(output_path)}")
        return output_fd
    except Exception:
        os.close(output_fd)
        raise


def _open_posix_output_staging_directory(output_path: str, parent_fd: int, staging_name: str) -> int:
    """Create and pin a private staging directory inside the validated output parent."""
    directory_flags = (
        (getattr(os, "O_PATH", 0) or getattr(os, "O_SEARCH", 0))
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    os.mkdir(staging_name, 0o700, dir_fd=parent_fd)
    staging_fd: int | None = None
    try:
        staging_fd = os.open(staging_name, directory_flags, dir_fd=parent_fd)
        opened_stat = os.fstat(staging_fd)
        named_stat = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
        effective_uid = getattr(os, "geteuid", lambda: opened_stat.st_uid)()
        if (
            not stat.S_ISDIR(opened_stat.st_mode)
            or opened_stat.st_uid != effective_uid
            or stat.S_IMODE(opened_stat.st_mode) & 0o077
            or not os.path.samestat(opened_stat, named_stat)
        ):
            raise _OutputWriteError(
                f"Refusing to write output because its staging path changed: {_display_path(output_path)}"
            )
        return staging_fd
    except Exception:
        if staging_fd is not None:
            os.close(staging_fd)
        with contextlib.suppress(OSError):
            os.rmdir(staging_name, dir_fd=parent_fd)
        raise


def _copy_posix_output_metadata(output_path: str, source_fd: int, target_fd: int) -> None:
    """Copy ownership, mode, ACL, and user xattrs to a staged replacement."""
    source_stat = os.fstat(source_fd)
    target_stat = os.fstat(target_fd)
    try:
        if _posix_fd_has_extended_acl(output_path, source_fd):
            raise _OutputWriteError(f"Unable to preserve extended output ACL for {_display_path(output_path)}")
        if (source_stat.st_uid, source_stat.st_gid) != (target_stat.st_uid, target_stat.st_gid):
            os.fchown(target_fd, source_stat.st_uid, source_stat.st_gid)
        os.fchmod(target_fd, stat.S_IMODE(source_stat.st_mode))
        if all(hasattr(os, name) for name in ("listxattr", "getxattr", "setxattr")):
            try:
                attribute_names = os.listxattr(source_fd)
            except OSError as exc:
                if exc.errno not in {errno.ENOTSUP, errno.EOPNOTSUPP}:
                    raise
                attribute_names = []
            for name in attribute_names:
                os.setxattr(target_fd, name, os.getxattr(source_fd, name))
    except OSError as exc:
        raise _OutputWriteError(
            f"Unable to preserve output metadata for {_display_path(output_path)}: {exc.strerror or exc}"
        ) from exc


def _open_posix_output_parent_sync_fd(output_path: str, parent_fd: int) -> int:
    """Open the pinned parent for fsync before publishing a report entry."""
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(".", directory_flags, dir_fd=parent_fd)
    except OSError as exc:
        raise _OutputWriteError(
            f"Unable to secure output persistence for {_display_path(output_path)}: {exc.strerror or exc}"
        ) from exc


def _validate_posix_output_replacement_permission(
    output_path: str,
    parent_fd: int,
    output_stat: os.stat_result,
) -> None:
    """Reject replacements forbidden by sticky-directory ownership rules."""
    parent_stat = os.fstat(parent_fd)
    if not parent_stat.st_mode & stat.S_ISVTX:
        return

    get_effective_uid = getattr(os, "geteuid", None)
    if get_effective_uid is None:
        raise _OutputWriteError(
            f"Unable to verify sticky-directory replacement permission for {_display_path(output_path)}"
        )
    effective_uid = get_effective_uid()
    if effective_uid == 0 or effective_uid in {parent_stat.st_uid, output_stat.st_uid}:
        return
    raise _OutputWriteError(
        f"Unable to replace output in sticky directory {_display_path(output_path)}: Permission denied"
    )


def _probe_posix_hard_link_support(output_path: str, staging_fd: int, parent_fd: int, temp_name: str) -> None:
    """Verify the no-overwrite install primitive before a model scan begins."""
    probe_name = f".modelaudit-output-{secrets.token_hex(12)}.probe"
    linked = False
    try:
        os.link(temp_name, probe_name, src_dir_fd=staging_fd, dst_dir_fd=parent_fd)
        linked = True
        os.unlink(probe_name, dir_fd=parent_fd)
        linked = False
    except OSError as exc:
        raise _OutputWriteError(
            f"Unable to prepare atomic output installation for {_display_path(output_path)}: {exc.strerror or exc}"
        ) from exc
    finally:
        if linked:
            with contextlib.suppress(OSError):
                os.unlink(probe_name, dir_fd=parent_fd)


def _fsync_posix_output_parent(output_path: str, parent_sync_fd: int) -> None:
    """Persist a published POSIX report directory entry before reporting success."""
    try:
        os.fsync(parent_sync_fd)
    except OSError as exc:
        raise _OutputWriteError(
            f"Unable to persist output {_display_path(output_path)}: {exc.strerror or exc}"
        ) from exc


def _preflight_output_text_file(output_path: str) -> None:
    """Reject unsupported output destinations before a model scan begins."""
    absolute_path: Path | None = None
    parent_fd: int | None = None
    parent_guard: int | None = None
    parent_lock: int | None = None
    existing_fd: int | None = None
    parent_sync_fd: int | None = None
    staging_fd: int | None = None
    staging_name = ""
    temp_fd: int | None = None
    temp_path: Path | None = None
    temp_name = ""
    try:
        absolute_path, parent_fd, parent_guard = _open_output_parent_directory(output_path)
        if os.name == "nt":
            assert parent_guard is not None
            parent_lock = _open_windows_output_parent_lock(output_path, absolute_path, parent_guard)
        initial_stat = _validate_existing_output_path(output_path, absolute_path, parent_fd=parent_fd)
        if initial_stat is not None:
            if os.name == "posix" and parent_fd is not None:
                _validate_posix_output_replacement_permission(output_path, parent_fd, initial_stat)
            existing_fd = _open_existing_output_file(
                output_path,
                absolute_path,
                initial_stat,
                parent_fd=parent_fd,
            )
            if os.name == "nt":
                _reject_windows_encrypted_output(output_path, existing_fd)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow

        if os.name == "nt":
            temp_name = f".modelaudit-output-{secrets.token_hex(12)}.tmp"
            temp_fd, temp_path = _open_windows_output_temp_file(
                output_path,
                absolute_path,
                temp_name,
                preserve_security=initial_stat is not None,
            )
            _validate_fallback_temporary_file(output_path, absolute_path, temp_path, temp_fd)
        elif parent_fd is not None:
            parent_sync_fd = _open_posix_output_parent_sync_fd(output_path, parent_fd)
            staging_name = f".modelaudit-output-{secrets.token_hex(12)}.tmp"
            staging_fd = _open_posix_output_staging_directory(output_path, parent_fd, staging_name)
            temp_name = "output.tmp"
            temp_fd = os.open(temp_name, flags, 0o666, dir_fd=staging_fd)
            if initial_stat is None:
                _probe_posix_hard_link_support(output_path, staging_fd, parent_fd, temp_name)
        else:
            return

        if initial_stat is not None:
            assert existing_fd is not None
            assert temp_fd is not None
            if os.name == "nt":
                _copy_windows_output_security(output_path, existing_fd, temp_fd)
                if hasattr(os, "fchmod"):
                    os.fchmod(temp_fd, stat.S_IMODE(initial_stat.st_mode))
            else:
                _copy_posix_output_metadata(output_path, existing_fd, temp_fd)
    except _OutputWriteError:
        raise
    except OSError as exc:
        raise _OutputWriteError(
            f"Unable to prepare output {_display_path(output_path)}: {exc.strerror or exc}"
        ) from exc
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if staging_fd is not None:
            if temp_name:
                with contextlib.suppress(OSError):
                    os.unlink(temp_name, dir_fd=staging_fd)
            staging_stat: os.stat_result | None = None
            with contextlib.suppress(OSError):
                staging_stat = os.fstat(staging_fd)
            os.close(staging_fd)
            if parent_fd is not None and staging_name and staging_stat is not None:
                with contextlib.suppress(OSError):
                    named_stat = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
                    if os.path.samestat(staging_stat, named_stat):
                        os.rmdir(staging_name, dir_fd=parent_fd)
        if parent_sync_fd is not None:
            os.close(parent_sync_fd)
        if existing_fd is not None:
            os.close(existing_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        elif temp_path is not None:
            with contextlib.suppress(OSError):
                temp_path.unlink()
        if parent_lock is not None:
            _close_windows_handle(parent_lock)
        if parent_guard is not None:
            _close_windows_handle(parent_guard)


def _write_output_text_file(output_path: str, output_text: str, *, trailing_newline: bool = False) -> None:
    """Write CLI output without following attacker-controlled path entries."""
    output_display = _display_path(output_path)
    try:
        output_bytes = output_text.encode("utf-8") + (b"\n" if trailing_newline else b"")
    except UnicodeError as exc:
        raise _OutputWriteError(f"Unable to encode output {output_display}: {exc}") from exc
    absolute_path: Path | None = None
    parent_fd: int | None = None
    parent_guard: int | None = None
    parent_lock: int | None = None
    existing_fd: int | None = None
    parent_sync_fd: int | None = None
    staging_fd: int | None = None
    staging_name = ""
    temp_fd: int | None = None
    temp_path: Path | None = None
    temp_name = ""
    try:
        absolute_path, parent_fd, parent_guard = _open_output_parent_directory(output_path)
        if os.name == "nt":
            assert parent_guard is not None
            parent_lock = _open_windows_output_parent_lock(output_path, absolute_path, parent_guard)
        if parent_fd is None and _validated_absolute_output_path(output_path) != absolute_path:
            raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}")
        initial_stat = _validate_existing_output_path(output_path, absolute_path, parent_fd=parent_fd)

        if initial_stat is not None:
            if os.name == "posix" and parent_fd is not None:
                _validate_posix_output_replacement_permission(output_path, parent_fd, initial_stat)
            existing_fd = _open_existing_output_file(
                output_path,
                absolute_path,
                initial_stat,
                parent_fd=parent_fd,
            )
            if os.name == "nt":
                _reject_windows_encrypted_output(output_path, existing_fd)
            current_stat = _validate_existing_output_path(output_path, absolute_path, parent_fd=parent_fd)
            if current_stat is None or not os.path.samestat(initial_stat, current_stat):
                raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}")
            if parent_fd is None and _validated_absolute_output_path(output_path) != absolute_path:
                raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}")
        if parent_fd is not None:
            parent_sync_fd = _open_posix_output_parent_sync_fd(output_path, parent_fd)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow

        if os.name == "nt":
            temp_name = f".modelaudit-output-{secrets.token_hex(12)}.tmp"
            temp_fd, temp_path = _open_windows_output_temp_file(
                output_path,
                absolute_path,
                temp_name,
                preserve_security=initial_stat is not None,
            )
            _validate_fallback_temporary_file(output_path, absolute_path, temp_path, temp_fd)
        elif parent_fd is None:
            temp_name = f".modelaudit-output-{secrets.token_hex(12)}.tmp"
            temp_path = absolute_path.parent / temp_name
            temp_fd = os.open(temp_path, flags, 0o666)
            _validate_fallback_temporary_file(output_path, absolute_path, temp_path, temp_fd)
        else:
            staging_name = f".modelaudit-output-{secrets.token_hex(12)}.tmp"
            staging_fd = _open_posix_output_staging_directory(output_path, parent_fd, staging_name)
            temp_name = "output.tmp"
            temp_fd = os.open(temp_name, flags, 0o666, dir_fd=staging_fd)

        if os.name == "nt":
            if initial_stat is not None:
                assert existing_fd is not None
                _copy_windows_output_security(output_path, existing_fd, temp_fd)
                if hasattr(os, "fchmod"):
                    os.fchmod(temp_fd, stat.S_IMODE(initial_stat.st_mode))
            with os.fdopen(temp_fd, "wb", closefd=False) as output_file:
                output_file.write(output_bytes)
        else:
            if initial_stat is not None:
                assert existing_fd is not None
                _copy_posix_output_metadata(output_path, existing_fd, temp_fd)
            with os.fdopen(temp_fd, "wb", closefd=False) as output_file:
                output_file.write(output_bytes)
        os.fsync(temp_fd)

        if parent_fd is None:
            current_path = _validated_absolute_output_path(output_path)
            if current_path != absolute_path:
                raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}")
        current_stat = _validate_existing_output_path(output_path, absolute_path, parent_fd=parent_fd)
        if initial_stat is None:
            if current_stat is not None:
                raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}")
        elif current_stat is None or not os.path.samestat(initial_stat, current_stat):
            raise _OutputWriteError(f"Refusing to write output because its path changed: {output_display}")

        if os.name == "nt":
            assert parent_guard is not None
            assert temp_fd is not None
            _replace_windows_output_file(
                output_path,
                temp_fd,
                absolute_path,
                replace_existing=initial_stat is not None,
            )
            temp_path = None
            temp_name = ""
        elif parent_fd is None:
            assert temp_path is not None
            os.replace(temp_path, absolute_path)
            temp_path = None
        else:
            assert staging_fd is not None
            if initial_stat is None:
                os.link(temp_name, absolute_path.name, src_dir_fd=staging_fd, dst_dir_fd=parent_fd)
                os.unlink(temp_name, dir_fd=staging_fd)
            else:
                _validate_posix_output_replacement_permission(output_path, parent_fd, initial_stat)
                os.rename(temp_name, absolute_path.name, src_dir_fd=staging_fd, dst_dir_fd=parent_fd)
            temp_name = ""
            assert parent_sync_fd is not None
            _fsync_posix_output_parent(output_path, parent_sync_fd)
    except _OutputWriteError:
        raise
    except OSError as exc:
        raise _OutputWriteError(f"Unable to write output {output_display}: {exc.strerror or exc}") from exc
    finally:
        if existing_fd is not None:
            os.close(existing_fd)
        if temp_fd is not None:
            os.close(temp_fd)
        staging_stat: os.stat_result | None = None
        if staging_fd is not None:
            if temp_name:
                with contextlib.suppress(OSError):
                    os.unlink(temp_name, dir_fd=staging_fd)
            with contextlib.suppress(OSError):
                staging_stat = os.fstat(staging_fd)
            os.close(staging_fd)
        if parent_fd is not None:
            if temp_name and staging_fd is None:
                with contextlib.suppress(OSError):
                    os.unlink(temp_name, dir_fd=parent_fd)
            if staging_name and staging_stat is not None:
                with contextlib.suppress(OSError):
                    named_stat = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
                    if os.path.samestat(staging_stat, named_stat):
                        os.rmdir(staging_name, dir_fd=parent_fd)
            if parent_sync_fd is not None:
                os.close(parent_sync_fd)
            os.close(parent_fd)
        elif temp_path is not None:
            with contextlib.suppress(OSError):
                temp_path.unlink()
        if parent_lock is not None:
            _close_windows_handle(parent_lock)
        if parent_guard is not None:
            _close_windows_handle(parent_guard)


@dataclass
class _ScanRuntimeConfig:
    """Resolved scan settings used by source dispatch and scan execution."""

    config: dict[str, Any]
    timeout: int
    show_progress: bool
    cache_enabled: bool
    cache_dir: str | None
    output_format: str
    show_styled_output: bool
    selective_download: bool
    stream_analysis: bool
    scan_and_delete: bool
    max_file_size: int
    max_total_size: int
    skip_non_model_files: bool
    strict_license: bool
    use_hf_whitelist: bool
    max_download_bytes: int | None
    explicit_max_download_bytes: int | None
    jfrog_api_token: str | None
    jfrog_access_token: str | None
    mlflow_registry_uri: str | None
    scanner_selection: dict[str, Any] | None
    scanner_selection_metadata: dict[str, Any] | None
    scannable_extensions: frozenset[str] | None
    pytorch_hub_scannable_extensions: frozenset[str] | None
    scannable_filenames: frozenset[str] | None
    scannable_scanner_ids: frozenset[str] | None
    hf_stream_include_all_files: bool


@dataclass
class _SourceDispatchResult:
    """Result of source resolution for one path."""

    actual_path: str
    local_scan_required: bool = True
    temp_path: str | None = None
    source_model_id: str | None = None
    source_model_source: str | None = None
    repository_file_inventory: tuple[str, ...] = ()
    repository_current_file: str | None = None


@dataclass
class _ScanPathState:
    """Bookkeeping for scanned artifacts and deferred cleanup."""

    collect_dvc_coverage: bool = False
    scanned_paths: list[str] = field(default_factory=list)
    temp_cleanup_entries: list[tuple[str, bool]] = field(default_factory=list)
    sbom_paths_resolved: bool = False
    dvc_covered_paths: set[str] = field(default_factory=set)
    dvc_covered_directories: set[str] = field(default_factory=set)
    validated_shard_targets: ValidatedShardTargets = field(default_factory=dict)
    explicit_shard_family_groups: dict[str, str] = field(default_factory=dict)
    has_errors_outside_reconciled_shards: bool = False

    def mark_non_shard_error(self, audit_result: ModelAuditResultModel) -> None:
        """Record an aggregate error that shard reconciliation does not own."""
        self.has_errors_outside_reconciled_shards = True
        audit_result.has_errors = True

    def record_non_shard_result_errors(self, scan_result: ModelAuditResultModel) -> None:
        """Preserve errors from results that cannot join final CLI shard reconciliation."""
        if scan_result.has_errors:
            self.has_errors_outside_reconciled_shards = True

    def explicit_shard_family_group_for(self, path: str) -> str | None:
        """Return the opt-in family group only for an exact explicit file argument."""
        normalized_path = os.path.normcase(os.path.normpath(os.path.abspath(path)))
        return self.explicit_shard_family_groups.get(normalized_path)

    def record_validated_shard_targets(
        self,
        scan_result: ModelAuditResultModel,
        *,
        pre_scan_target: ValidatedShardTargets | None = None,
    ) -> None:
        """Record stable regular-file identities for shard assets that were scanned."""
        for asset in scan_result.assets:
            if not asset.path or asset.type == "error":
                continue
            metadata = scan_result.file_metadata.get(asset.path)
            if metadata is not None and metadata.get("operational_error") is True:
                continue
            explicit_family_group = self.explicit_shard_family_group_for(asset.path)
            post_scan_target = _snapshot_validated_shard_target(
                asset.path,
                family_group=explicit_family_group,
                family_group_policy="explicit" if explicit_family_group else None,
            )
            if not post_scan_target:
                continue
            if pre_scan_target:
                common_sources = pre_scan_target.keys() & post_scan_target.keys()
                if common_sources and any(
                    pre_scan_target[source_path] != post_scan_target[source_path] for source_path in common_sources
                ):
                    continue
            self.validated_shard_targets.update(post_scan_target)

    def track_streaming_paths_for_sbom(
        self,
        streaming_result: ModelAuditResultModel,
        fallback_path: str | None,
    ) -> None:
        """Track concrete streamed artifact paths so SBOM includes all scanned components."""
        self.sbom_paths_resolved = True
        added_path = False
        for asset in streaming_result.assets:
            if asset.path:
                self.scanned_paths.append(_display_scan_path(asset.path))
                added_path = True

        if not added_path and fallback_path is not None and not os.path.exists(fallback_path):
            self.scanned_paths.append(_display_scan_path(fallback_path))

    def track_directory_paths_for_sbom(self, scan_result: ModelAuditResultModel) -> None:
        """Track completed directory scan assets, including an authoritative empty set."""
        self.sbom_paths_resolved = True
        for asset in scan_result.assets:
            if asset.path:
                self.scanned_paths.append(_display_scan_path(asset.path))

    def defer_temp_cleanup(self, temp_path: str | None, *, cache_enabled: bool, verbose: bool) -> None:
        """Track temporary artifacts for post-SBOM cleanup."""
        if temp_path and os.path.exists(temp_path) and not cache_enabled:
            self.temp_cleanup_entries.append((temp_path, os.path.isdir(temp_path)))
            if verbose:
                logger.debug(f"Deferring cleanup of temporary artifact: {temp_path}")

    def record_dvc_coverage(
        self,
        scan_path: str,
        scan_result: ModelAuditResultModel,
        *,
        scanner_config: dict[str, Any] | None = None,
    ) -> None:
        """Record concrete artifacts and completed directory walks for later DVC pointers."""
        if not self.collect_dvc_coverage:
            return

        scanner_policy = policy_from_config(scanner_config)
        if scanner_policy.active:
            from modelaudit.scanners import get_scanner_for_file

        def resolve_coverage_path(file_path: str | None) -> Path | None:
            if not isinstance(file_path, str):
                return None
            try:
                return Path(file_path).resolve()
            except (OSError, RuntimeError, ValueError):
                return None

        def record_covered_file(file_path: str) -> None:
            if scanner_policy.active and get_scanner_for_file(file_path, config=scanner_config) is None:
                return
            resolved_path = resolve_coverage_path(file_path)
            if resolved_path is None:
                return
            if not resolved_path.is_file():
                return
            self.dvc_covered_paths.add(str(resolved_path))

        def path_matches_shard_family(candidate_path: str | None, shard_paths: set[Path]) -> bool:
            resolved_candidate = resolve_coverage_path(candidate_path)
            if resolved_candidate is None:
                return False
            if resolved_candidate in shard_paths:
                return True
            if resolved_candidate.is_dir():
                return any(shard_path.is_relative_to(resolved_candidate) for shard_path in shard_paths)
            return False

        def shard_family_has_incomplete_coverage(
            shard_paths: set[Path],
            *,
            only_detected_shard_family: bool,
        ) -> bool:
            for metadata_path, metadata in scan_result.file_metadata.items():
                if not (metadata.get("operational_error") is True or metadata_has_incomplete_coverage(metadata)):
                    continue
                if path_matches_shard_family(metadata_path, shard_paths):
                    return True

            incomplete_shard_checks = {
                "Shard Scan",
                "Sharded Model Coverage Check",
                "Sharded Model Membership Check",
            }
            records: tuple[Any, ...] = (*scan_result.checks, *scan_result.issues)
            for record in records:
                details = getattr(record, "details", None)
                details = details if isinstance(details, dict) else None
                if details is None:
                    continue
                if not (details.get("operational_error") is True or details_have_incomplete_coverage(details)):
                    continue
                if path_matches_shard_family(getattr(record, "location", None), shard_paths):
                    return True
                if details_match_shard_family_paths(
                    details,
                    lambda candidate: path_matches_shard_family(candidate, shard_paths),
                ):
                    return True
                if only_detected_shard_family and getattr(record, "name", None) in incomplete_shard_checks:
                    return True

            return False

        for asset in scan_result.assets:
            if not asset.path or asset.type == "error":
                continue
            metadata = scan_result.file_metadata.get(asset.path)
            if metadata is not None and (
                metadata.get("operational_error") is True or metadata_has_incomplete_coverage(metadata)
            ):
                continue
            if records_have_incomplete_coverage_for_path((*scan_result.checks, *scan_result.issues), asset.path):
                continue
            record_covered_file(asset.path)

        sharded_detection_families: list[tuple[list[Any], set[Path]]] = []
        for check in scan_result.checks:
            shard_paths = check.details.get("shards") if isinstance(check.details, dict) else None
            if check.name != "Sharded Model Detection" or not isinstance(shard_paths, list):
                continue
            resolved_shard_paths = {
                resolved_path
                for shard_path in shard_paths
                if isinstance(shard_path, str) and (resolved_path := resolve_coverage_path(shard_path)) is not None
            }
            sharded_detection_families.append((shard_paths, resolved_shard_paths))
        only_detected_shard_family = len(sharded_detection_families) <= 1
        for shard_paths, resolved_shard_paths in sharded_detection_families:
            if shard_family_has_incomplete_coverage(
                resolved_shard_paths,
                only_detected_shard_family=only_detected_shard_family,
            ):
                continue
            for shard_path in shard_paths:
                if isinstance(shard_path, str):
                    record_covered_file(shard_path)

        directory_roots: list[Path] = []
        scan_path_obj = Path(scan_path)
        if scan_path_obj.is_dir():
            directory_roots.append(scan_path_obj)
        elif scan_path.lower().endswith(".dvc"):
            directory_roots.extend(
                Path(target) for target in resolve_dvc_file_with_metadata(scan_path).targets if Path(target).is_dir()
            )

        for directory_root in directory_roots:
            try:
                resolved_root = directory_root.resolve()
            except OSError:
                continue
            if results_have_inconclusive_outcome(scan_result) or results_have_incomplete_coverage_under_directory(
                scan_result,
                str(resolved_root),
            ):
                continue
            walk_errors: list[OSError] = []
            walked_directories: set[str] = set()
            for root, _dirs, _files in os.walk(resolved_root, followlinks=False, onerror=walk_errors.append):
                try:
                    resolved_directory = Path(root).resolve()
                except OSError:
                    continue
                if resolved_directory.is_relative_to(resolved_root):
                    walked_directories.add(str(resolved_directory))
            if not walk_errors:
                self.dvc_covered_directories.update(walked_directories)


_HF_ACQUISITION_ERROR_REASON = "huggingface_acquisition_error"
_HF_ACQUISITION_BLOCKED_REASON = "huggingface_acquisition_blocked"
_HF_AUTH_BLOCKED_MARKERS = (
    "gatedrepoerror",
    "gated repo",
    "gated repository",
    "401",
    "403",
    "unauthorized",
    "forbidden",
    "repositorynotfounderror",
    "repository not found",
    "restricted",
)


class _HuggingFaceAcquisitionError(RuntimeError):
    """Marker for Hugging Face stream failures before the first artifact is yielded."""


class _HuggingFaceStreamInterruptedError(RuntimeError):
    """Marker for Hugging Face stream failures after artifact scanning may have started."""


def _track_huggingface_stream_acquisition(
    file_generator: Iterator[tuple[Path, bool]],
) -> Iterator[tuple[Path, bool]]:
    """Distinguish pre-yield acquisition failures from interrupted streamed scans."""
    yielded_artifact = False
    try:
        for file_path, is_last in file_generator:
            yielded_artifact = True
            yield file_path, is_last
    except Exception as exc:
        if yielded_artifact:
            raise _HuggingFaceStreamInterruptedError(str(exc)) from exc
        raise _HuggingFaceAcquisitionError(str(exc)) from exc


def _metadata_get_bool(metadata: Any, key: str) -> bool:
    if isinstance(metadata, dict):
        return bool(metadata.get(key))
    getter = getattr(metadata, "get", None)
    if callable(getter):
        try:
            return bool(getter(key))
        except Exception:
            return False
    return bool(getattr(metadata, key, False))


def _results_have_acquisition_error_metadata(results: ModelAuditResultModel | dict[str, Any]) -> bool:
    if isinstance(results, ModelAuditResultModel):
        return any(_metadata_get_bool(metadata, "acquisition_error") for metadata in results.file_metadata.values())
    raw_metadata = results.get("file_metadata", {})
    if not isinstance(raw_metadata, dict):
        return False
    return any(_metadata_get_bool(metadata, "acquisition_error") for metadata in raw_metadata.values())


def _results_have_blocked_acquisition_metadata(results: ModelAuditResultModel | dict[str, Any]) -> bool:
    if isinstance(results, ModelAuditResultModel):
        return any(_metadata_get_bool(metadata, "blocked") for metadata in results.file_metadata.values())
    raw_metadata = results.get("file_metadata", {})
    if not isinstance(raw_metadata, dict):
        return False
    return any(_metadata_get_bool(metadata, "blocked") for metadata in raw_metadata.values())


def _huggingface_requested_revision(path: str) -> str | None:
    try:
        if is_huggingface_file_url(path):
            _repo_id, file_revision, _filename = parse_huggingface_file_url(path)
            return file_revision
        if is_huggingface_url(path):
            _namespace, _repo_name, requested_revision = parse_huggingface_url_with_revision(path)
            return requested_revision
    except ValueError:
        return None
    return None


def _classify_huggingface_acquisition_error(error_msg: str) -> tuple[str, bool, str]:
    normalized = error_msg.lower()
    if any(marker in normalized for marker in _HF_AUTH_BLOCKED_MARKERS):
        return _HF_ACQUISITION_BLOCKED_REASON, True, "blocked"
    return _HF_ACQUISITION_ERROR_REASON, False, "acquisition_error"


def _huggingface_acquisition_source_key(path: str, requested_revision: str | None) -> str:
    display_path = _display_scan_path(path)
    if requested_revision and not is_huggingface_file_url(path):
        return f"{display_path}@{requested_revision}"
    return display_path


def _record_huggingface_acquisition_error(
    audit_result: ModelAuditResultModel,
    path_state: _ScanPathState,
    *,
    path: str,
    error_msg: str,
) -> None:
    """Record a Hugging Face source failure without claiming artifact coverage."""
    requested_revision = _huggingface_requested_revision(path)
    source_key = _huggingface_acquisition_source_key(path, requested_revision)
    reason, blocked, category = _classify_huggingface_acquisition_error(error_msg)
    issue_message = (
        f"Hugging Face acquisition blocked for {source_key}; no model artifacts were scanned."
        if blocked
        else f"Hugging Face acquisition failed for {source_key}; no model artifacts were scanned."
    )

    details: dict[str, Any] = {
        "source": "huggingface",
        "source_url": source_key,
        "acquisition_error": True,
        "blocked": blocked,
        "error_category": category,
        "error": error_msg,
        SCAN_OUTCOME_METADATA_KEY: INCONCLUSIVE_SCAN_OUTCOME,
        "scan_outcome_reason": reason,
        SCAN_OUTCOME_REASONS_METADATA_KEY: [reason],
    }
    if requested_revision is not None:
        details["requested_revision"] = requested_revision

    audit_result.issues.append(
        Issue(
            message=issue_message,
            severity=IssueSeverity.INFO,
            location=source_key,
            details=details,
            type="huggingface_acquisition_error",
        )
    )
    audit_result.file_metadata[source_key] = FileMetadataModel(
        source="huggingface",
        source_url=source_key,
        acquisition_error=True,
        blocked=blocked,
        error_category=category,
        operational_error=True,
        operational_error_reason=reason,
        scan_outcome=INCONCLUSIVE_SCAN_OUTCOME,
        scan_outcome_reason=reason,
        scan_outcome_reasons=[reason],
        requested_revision=requested_revision,
    )
    audit_result.has_errors = True
    audit_result.success = False
    path_state.mark_non_shard_error(audit_result)


def should_use_color() -> bool:
    """Check if colors should be used in output."""
    # Respect NO_COLOR environment variable
    if os.getenv("NO_COLOR"):
        return False
    # Only use colors if output is a TTY
    return sys.stdout.isatty()


def should_show_spinner() -> bool:
    """Check if spinners should be shown."""
    # Only show spinners if output is a TTY
    return sys.stdout.isatty()


def style_text(text: str, **kwargs: Any) -> str:
    """Style text only if colors are enabled."""
    if should_use_color():
        return click.style(text, **kwargs)
    return text


def _escape_terminal_text(value: Any) -> str:
    """Render control characters visibly before writing model-controlled text to terminals."""
    text = "" if value is None else str(value)

    def replace_control(char: str) -> str:
        if char == "\n":
            return "\\n"
        if char == "\r":
            return "\\r"
        if char == "\t":
            return "\\t"
        codepoint = ord(char)
        if codepoint <= 0xFF:
            return f"\\x{codepoint:02x}"
        if codepoint <= 0xFFFF:
            return f"\\u{codepoint:04x}"
        return f"\\U{codepoint:08x}"

    return "".join(
        replace_control(char) if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} else char for char in text
    )


def get_trusted_config_store() -> TrustedConfigStore:
    """Return the persistent store used for trusted local configs."""
    return TrustedConfigStore()


def can_use_trusted_local_config(output_format: str) -> bool:
    """Return True when the current scan mode supports trusted local configs."""
    return (
        output_format == "text"
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and not detect_ci_environment()
        and not is_delegated_from_promptfoo()
    )


def maybe_load_trusted_local_config(
    paths: list[str],
    output_format: str,
    *,
    quiet: bool,
) -> tuple[ModelAuditConfig | None, bool, Path | None]:
    """Load a trusted local config for interactive text scans when available."""
    if not can_use_trusted_local_config(output_format):
        return None, False, None

    candidate = find_local_config_for_paths(paths)
    if candidate is None:
        return None, False, None

    store = get_trusted_config_store()
    if store.is_trusted(candidate):
        return ModelAuditConfig.load(candidate.config_path), True, candidate.config_path

    if quiet:
        return None, False, None

    click.echo(style_text(f"Found local ModelAudit config at {candidate.config_path}", fg="cyan"))
    click.echo("It can suppress findings or change severities.")
    choice = click.prompt(
        "Use it? [y] once, [a] always, [n] no",
        type=click.Choice(["y", "a", "n"], case_sensitive=False),
        default="n",
        show_choices=False,
    ).lower()

    if choice == "n":
        return None, False, None

    if choice == "a":
        store.trust(candidate)

    return ModelAuditConfig.load(candidate.config_path), True, candidate.config_path


def build_scan_rule_config(
    paths: list[str],
    suppress: tuple[str, ...],
    severity_overrides: dict[str, str],
    *,
    output_format: str,
    quiet: bool,
) -> tuple[ModelAuditConfig, bool, Path | None]:
    """Build the effective scan rule config, including trusted local policy when enabled."""
    base_config, local_config_applied, local_config_path = maybe_load_trusted_local_config(
        paths,
        output_format,
        quiet=quiet,
    )
    cli_config = ModelAuditConfig.from_cli_args(
        suppress=list(suppress) if suppress else None,
        severity=severity_overrides if severity_overrides else None,
        base_config=base_config,
    )
    return cli_config, local_config_applied, local_config_path


def expand_paths(paths: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """Expand and validate input paths with type safety."""
    expanded: list[str] = []
    missing_globs: list[str] = []
    for path_str in paths:
        if "://" in path_str:
            expanded.append(path_str)
            continue

        # Handle glob patterns and resolve paths
        path = Path(path_str)
        is_remote_url = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", path_str))
        if ("*" in path_str or "?" in path_str) and not is_remote_url:
            # Handle glob patterns
            import glob

            matches = glob.glob(path_str, recursive=True)
            if matches:
                expanded.extend(matches)
            else:
                missing_globs.append(path_str)
        else:
            expanded.append(str(path.resolve()) if path.exists() else path_str)
    return expanded, missing_globs


def _explicit_local_shard_family_groups(paths: tuple[str, ...]) -> dict[str, str]:
    """Map exact local file arguments to conservative explicit-family groups."""
    grouped_paths: dict[tuple[str, int], list[tuple[str, Path, int]]] = {}
    seen_paths: set[str] = set()
    for path_str in paths:
        if "://" in path_str or "*" in path_str or "?" in path_str:
            continue
        path = Path(path_str)
        if not path.is_file():
            continue
        try:
            resolved_path = str(path.resolve(strict=True))
            parent_stat = os.stat(Path(resolved_path).parent, follow_symlinks=False)
        except (OSError, RuntimeError):
            continue
        if not stat.S_ISDIR(parent_stat.st_mode):
            continue
        if os.name != "nt":
            get_effective_uid = getattr(os, "geteuid", None)
            if callable(get_effective_uid) and parent_stat.st_uid != get_effective_uid():
                continue
            if stat.S_IMODE(parent_stat.st_mode) & 0o022:
                continue
        shard_match = ShardedModelDetector.match_shard_filename(Path(resolved_path).name)
        if shard_match is None:
            continue
        pattern = shard_match.get("pattern")
        shard_index = shard_match.get("current_shard_index")
        expected_total = shard_match.get("expected_total_shards")
        if (
            not isinstance(pattern, str)
            or not isinstance(shard_index, int)
            or not isinstance(expected_total, int)
            or expected_total <= 1
            or not 1 <= shard_index <= expected_total
        ):
            continue
        normalized_path = os.path.normcase(os.path.normpath(os.path.abspath(resolved_path)))
        if normalized_path in seen_paths:
            continue
        seen_paths.add(normalized_path)
        grouped_paths.setdefault((pattern, expected_total), []).append(
            (normalized_path, Path(resolved_path), shard_index)
        )

    groups: dict[str, str] = {}
    for (_pattern, expected_total), records in grouped_paths.items():
        targets_by_scope: dict[str, dict[int, list[str]]] = {}
        scopes_by_source: dict[str, set[str]] = {}
        for normalized_path, resolved_path_obj, shard_index in records:
            source_scopes = scopes_by_source.setdefault(normalized_path, set())
            for ancestor in (resolved_path_obj.parent, *resolved_path_obj.parent.parents):
                normalized_scope = os.path.normcase(os.path.normpath(str(ancestor)))
                source_scopes.add(normalized_scope)
                targets_by_scope.setdefault(normalized_scope, {}).setdefault(shard_index, []).append(normalized_path)

        complete_scopes = {
            scope
            for scope, targets_by_index in targets_by_scope.items()
            if len(targets_by_index) == expected_total
            and all(len(targets) == 1 for targets in targets_by_index.values())
        }
        for normalized_path, _resolved_path, _shard_index in records:
            matching_scopes = scopes_by_source[normalized_path] & complete_scopes
            if matching_scopes:
                family_scope = max(matching_scopes, key=lambda scope: len(Path(scope).parts))
                groups[normalized_path] = f"explicit-cli:{family_scope}"
    return groups


def parse_severity_overrides(values: tuple[str, ...]) -> dict[str, str]:
    """Parse CLI severity override arguments of the form CODE=LEVEL."""
    overrides: dict[str, str] = {}
    valid_levels = {severity.value for severity in Severity}
    for entry in values:
        if "=" not in entry:
            raise click.BadParameter("Severity overrides must use CODE=LEVEL format (e.g., S101=CRITICAL)")
        code, level = entry.split("=", 1)
        code = code.strip().upper()
        level = level.strip().upper()
        if not code or not level:
            raise click.BadParameter("Severity overrides must include both a rule code and a severity level")
        if RuleRegistry.get_rule(code) is None:
            raise click.BadParameter(f"Unknown rule code '{code}' in --severity override")
        if level not in valid_levels:
            allowed = ", ".join(sorted(valid_levels))
            raise click.BadParameter(f"Invalid severity level '{level}'. Allowed values: {allowed}")
        overrides[code] = level
    return overrides


def get_severity_color(severity: str) -> str:
    """Map severity string to a color for CLI display."""
    mapping = {
        "CRITICAL": "red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green",
    }
    return mapping.get(severity.upper(), "white")


def create_progress_callback_wrapper(progress_callback: Any | None, spinner: Any | None) -> Any | None:
    """Create a type-safe progress callback wrapper."""
    if not progress_callback:
        return None

    def wrapped_callback(message: str, percentage: float) -> None:
        """Wrapped progress callback with type safety."""
        try:
            progress_callback(message, percentage)
            if spinner and hasattr(spinner, "text"):
                spinner.text = _escape_terminal_text(message)
        except Exception as e:
            logger.warning(f"Progress callback error: {_escape_terminal_text(e)}")

    return wrapped_callback


def is_mlflow_uri(path: str) -> bool:
    """Check if a path is an MLflow model URI."""
    return path.startswith("models:/")


def _local_path_will_be_scanned(path: str, *, skip_non_model_files: bool) -> bool:
    """Return whether the local CLI prefilter will scan an explicit file path."""
    if not skip_non_model_files or not os.path.isfile(path):
        return True

    extension = Path(path).suffix.lower()
    if extension in {".py", ".js", ".html", ".css"}:
        return not should_skip_file(path)
    if extension != ".txt":
        return True

    from modelaudit.scanners import SCANNER_REGISTRY
    from modelaudit.scanners.zip_scanner import ZipScanner

    if ZipScanner.can_handle(path):
        return True

    return any(scanner_class().can_handle(path) for scanner_class in SCANNER_REGISTRY)


def _resolve_scan_paths(paths: tuple[str, ...], scan_start_time: float) -> list[str]:
    """Expand user paths and order capped DVC pointers after concrete sibling inputs."""
    expanded_paths, missing_globs = expand_paths(paths)
    dvc_resolutions = {
        path: resolve_dvc_file_with_metadata(path)
        for path in expanded_paths
        if os.path.isfile(path) and path.lower().endswith(".dvc")
    }
    ordered_paths: list[str] = []
    capped_dvc_paths: list[str] = []
    for path in expanded_paths:
        resolution = dvc_resolutions.get(path)
        if resolution is not None and resolution.omitted_output_count > 0:
            capped_dvc_paths.append(path)
        else:
            ordered_paths.append(path)

    if missing_globs:
        click.echo(
            style_text(
                f"Warning: glob pattern(s) did not match any files: {', '.join(missing_globs)}",
                fg="yellow",
            ),
            err=True,
        )
        click.echo("Note: glob expansion is only applied to local paths.", err=True)

    if not expanded_paths:
        click.echo(
            style_text(
                "No matching paths found. Check your paths or glob patterns.",
                fg="red",
                bold=True,
            ),
            err=True,
        )
        record_scan_failed(time.time() - scan_start_time, "No matching paths")
        flush_telemetry()
        sys.exit(2)

    return list(dict.fromkeys([*ordered_paths, *capped_dvc_paths]))


def _build_user_scan_overrides(
    *,
    format: str | None,
    timeout: int | None,
    max_size: str | None,
    cache_dir: str | None,
    progress: bool,
    no_cache: bool,
    no_whitelist: bool,
    stream: bool,
    strict: bool,
    verbose: bool,
    quiet: bool,
    scanners: tuple[str, ...],
    exclude_scanners: tuple[str, ...],
    scan_start_time: float,
) -> dict[str, Any]:
    """Normalize scan command flags into config overrides."""
    user_overrides: dict[str, Any] = {}
    if format is not None:
        user_overrides["format"] = format
    if timeout is not None:
        user_overrides["timeout"] = timeout
    if max_size is not None:
        try:
            user_overrides["max_file_size"] = parse_size_string(max_size)
            user_overrides["max_total_size"] = parse_size_string(max_size)
        except ValueError as exc:
            click.echo(f"Error parsing --max-size: {exc}", err=True)
            record_scan_failed(time.time() - scan_start_time, f"Invalid max-size: {exc}")
            flush_telemetry()
            sys.exit(2)

    if cache_dir is not None:
        user_overrides["cache_dir"] = str(Path(cache_dir).expanduser())
        user_overrides["use_cache"] = True

    if progress:
        user_overrides["show_progress"] = True
    if no_cache:
        user_overrides["use_cache"] = False
    if no_whitelist:
        user_overrides["use_hf_whitelist"] = False
    if stream:
        user_overrides["scan_and_delete"] = True
    if strict:
        user_overrides["skip_non_model_files"] = False
        user_overrides["selective_download"] = False
        user_overrides["strict_license"] = True
        user_overrides["use_cache"] = False
        user_overrides["use_hf_whitelist"] = False
    if verbose:
        user_overrides["verbose"] = True
    if quiet:
        user_overrides["verbose"] = False

    if scanners or exclude_scanners:
        try:
            user_overrides[SCANNER_SELECTION_CONFIG_KEY] = scanner_selection_config_from_inputs(
                scanners=scanners,
                exclude_scanners=exclude_scanners,
            )
        except ValueError as exc:
            click.echo(f"Error parsing scanner selection: {exc}", err=True)
            record_scan_failed(time.time() - scan_start_time, f"Invalid scanner selection: {exc}")
            flush_telemetry()
            sys.exit(2)

    return user_overrides


def _resolve_scan_runtime_config(
    expanded_paths: list[str],
    *,
    format: str | None,
    output: str | None,
    timeout: int | None,
    max_size: str | None,
    cache_dir: str | None,
    progress: bool,
    no_cache: bool,
    no_whitelist: bool,
    stream: bool,
    strict: bool,
    verbose: bool,
    quiet: bool,
    scanners: tuple[str, ...],
    exclude_scanners: tuple[str, ...],
    suppress: tuple[str, ...],
    severity: tuple[str, ...],
    scan_start_time: float,
) -> _ScanRuntimeConfig:
    """Build the effective scan runtime settings and apply rule config."""
    auto_defaults = generate_auto_defaults(expanded_paths)
    user_overrides = _build_user_scan_overrides(
        format=format,
        timeout=timeout,
        max_size=max_size,
        cache_dir=cache_dir,
        progress=progress,
        no_cache=no_cache,
        no_whitelist=no_whitelist,
        stream=stream,
        strict=strict,
        verbose=verbose,
        quiet=quiet,
        scanners=scanners,
        exclude_scanners=exclude_scanners,
        scan_start_time=scan_start_time,
    )
    config_values = apply_auto_overrides(user_overrides, auto_defaults)

    final_cache = config_values.get("use_cache", True)
    final_format = config_values.get("format", "text")
    final_cache_dir = config_values.get("cache_dir") if final_cache else None
    show_styled_output = final_format == "text" or bool(output)

    severity_overrides = parse_severity_overrides(severity)
    try:
        cli_config, local_config_applied, local_config_path = build_scan_rule_config(
            expanded_paths,
            suppress,
            severity_overrides,
            output_format=final_format,
            quiet=quiet,
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc
    set_config(cli_config)

    if local_config_applied:
        if final_cache:
            final_cache = False
            final_cache_dir = None
        if not quiet and show_styled_output and local_config_path is not None:
            click.echo(style_text(f"Using local ModelAudit config: {local_config_path}", fg="cyan"))
            click.echo(style_text("Scan result cache disabled for this run.", fg="yellow"))

    explicit_max_download_bytes = None
    max_download_bytes = None
    if max_size is not None:
        with contextlib.suppress(ValueError):
            explicit_max_download_bytes = parse_size_string(max_size)
            max_download_bytes = explicit_max_download_bytes
    else:
        configured_max_file_size = config_values.get("max_file_size", 0)
        if isinstance(configured_max_file_size, int) and configured_max_file_size > 0:
            max_download_bytes = configured_max_file_size

    scanner_selection = config_values.get(SCANNER_SELECTION_CONFIG_KEY)
    scanner_policy = policy_from_config(config_values)
    scannable_extensions = (
        selected_scanner_extensions(scanner_policy, conservative=True) if scanner_policy.active else None
    )
    pytorch_hub_scannable_extensions = scannable_extensions
    # Header-routed and generic container scanners must see every supported Hub
    # artifact; suffix filtering here would create selection-specific false negatives.
    if (
        scanner_policy.active
        and pytorch_hub_scannable_extensions is None
        and scanner_policy.exclude_scanner_ids
        and not scanner_policy.exact_scanner_ids
    ):
        pytorch_hub_scannable_extensions = selected_scanner_extensions(scanner_policy)
    scannable_filenames = (
        selected_scanner_filenames(scanner_policy, conservative=True) if scanner_policy.active else None
    )
    scannable_scanner_ids = scanner_policy.enabled_scanner_ids if scanner_policy.active else None
    hf_stream_include_all_files = not scanner_policy.active or scannable_extensions is None

    return _ScanRuntimeConfig(
        config=config_values,
        timeout=config_values.get("timeout", 3600),
        show_progress=config_values.get("show_progress", False),
        cache_enabled=final_cache,
        cache_dir=final_cache_dir,
        output_format=final_format,
        show_styled_output=show_styled_output,
        selective_download=config_values.get("selective_download", True),
        stream_analysis=config_values.get("stream_analysis", False),
        scan_and_delete=config_values.get("scan_and_delete", False),
        max_file_size=config_values.get("max_file_size", 0),
        max_total_size=config_values.get("max_total_size", 0),
        skip_non_model_files=config_values.get("skip_non_model_files", True),
        strict_license=config_values.get("strict_license", False),
        use_hf_whitelist=config_values.get("use_hf_whitelist", True),
        max_download_bytes=max_download_bytes,
        explicit_max_download_bytes=explicit_max_download_bytes,
        jfrog_api_token=os.getenv("JFROG_API_TOKEN"),
        jfrog_access_token=os.getenv("JFROG_ACCESS_TOKEN"),
        mlflow_registry_uri=os.getenv("MLFLOW_TRACKING_URI"),
        scanner_selection=scanner_selection if isinstance(scanner_selection, dict) else None,
        scanner_selection_metadata=scanner_policy.to_metadata() if scanner_policy.active else None,
        scannable_extensions=scannable_extensions,
        pytorch_hub_scannable_extensions=pytorch_hub_scannable_extensions,
        scannable_filenames=scannable_filenames,
        scannable_scanner_ids=scannable_scanner_ids,
        hf_stream_include_all_files=hf_stream_include_all_files,
    )


def _scanner_selection_overrides(runtime: _ScanRuntimeConfig) -> dict[str, Any]:
    """Return config kwargs needed to preserve scanner selection across scan paths."""
    if runtime.scanner_selection is None:
        return {}
    return {SCANNER_SELECTION_CONFIG_KEY: runtime.scanner_selection}


def _show_scan_runtime_defaults(
    runtime: _ScanRuntimeConfig,
    expanded_paths: list[str],
    blacklist: tuple[str, ...],
    *,
    quiet: bool,
    verbose: bool,
) -> None:
    """Emit resolved defaults and the scan header for text-friendly outputs."""
    if not quiet and runtime.show_styled_output:
        if verbose:
            click.echo(f"Defaults: {len(expanded_paths)} path(s) analyzed")
            for key, value in runtime.config.items():
                if key != "cache_dir":
                    click.echo(f"   • {key}: {value}")
        elif not runtime.config.get("colors", True):
            pass

    if runtime.show_styled_output and not quiet:
        delegation_note = ""
        if is_delegated_from_promptfoo():
            delegation_note = style_text(" (via promptfoo)", dim=True)

        header = [
            "─" * 80,
            style_text("ModelAudit Security Scanner", fg="blue", bold=True) + delegation_note,
            style_text(
                "Scanning for potential security issues in ML model files",
                fg="cyan",
            ),
            "─" * 80,
        ]
        click.echo("\n".join(header))
        display_paths = [_display_path(path) for path in expanded_paths]
        click.echo(f"Paths to scan: {style_text(', '.join(display_paths), fg='green')}")
        if blacklist:
            click.echo(
                f"Additional blacklist patterns: {style_text(', '.join(blacklist), fg='yellow')}",
            )
        click.echo("─" * 80)
        click.echo("")


def _configure_scan_logging(verbose: bool) -> None:
    """Set CLI logging verbosity and suppress noisy internals in normal mode."""
    if verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("modelaudit.core").setLevel(logging.DEBUG)
        return

    logging.getLogger("modelaudit.core").setLevel(logging.WARNING)
    logging.getLogger("modelaudit.utils.helpers.secure_hasher").setLevel(logging.WARNING)
    logging.getLogger("modelaudit.cache.cache_manager").setLevel(logging.WARNING)


def _initialize_progress_tracking(
    runtime: _ScanRuntimeConfig,
    expanded_paths: list[str],
    *,
    output: str | None,
    verbose: bool,
) -> tuple[Any | None, list[Any]]:
    """Create optional progress tracking/reporters for text stdout scans."""
    progress_tracker = None
    progress_reporters: list[Any] = []

    if not runtime.show_progress or not expanded_paths:
        return progress_tracker, progress_reporters

    try:
        from .progress import ConsoleProgressReporter, ProgressTracker

        progress_tracker = ProgressTracker(update_interval=2.0)

        if progress_tracker and runtime.output_format == "text" and not output:
            console_reporter = ConsoleProgressReporter(  # type: ignore[possibly-unresolved-reference]
                update_interval=2.0,
                disable_on_non_tty=True,
                show_bytes=True,
                show_items=True,
            )
            progress_reporters.append(console_reporter)
            progress_tracker.add_reporter(console_reporter)
    except (ImportError, RecursionError) as exc:
        if verbose:
            if isinstance(exc, RecursionError):
                click.echo("Progress tracking disabled due to import cycle", err=True)
            else:
                click.echo("Progress tracking not available (missing dependencies)", err=True)
        runtime.show_progress = False

    return progress_tracker, progress_reporters


def _complete_progress_tracking(progress_tracker: Any | None, *, verbose: bool) -> None:
    """Finalize progress tracker state after all paths have been processed."""
    if not progress_tracker:
        return

    try:
        from .progress import ProgressPhase

        progress_tracker.set_phase(ProgressPhase.FINALIZING, "Completing scan and generating report")
        progress_tracker.complete()
    except (ImportError, RecursionError):
        if verbose:
            click.echo("Progress tracking completion skipped due to import issues", err=True)
    except Exception as exc:
        logger.warning(f"Error completing progress tracking: {exc}")


def _cleanup_progress_reporters(progress_reporters: list[Any]) -> None:
    """Close progress reporters safely."""
    for reporter in progress_reporters:
        try:
            if hasattr(reporter, "cleanup"):
                reporter.cleanup()
            elif hasattr(reporter, "close"):
                reporter.close()
        except Exception as exc:
            logger.warning(f"Error cleaning up progress reporter: {exc}")


def _cleanup_temp_artifacts(temp_cleanup_entries: list[tuple[str, bool]], *, verbose: bool) -> None:
    """Delete deferred temporary files/directories after SBOM generation."""
    for temp_path, is_dir in temp_cleanup_entries:
        if os.path.exists(temp_path):
            try:
                if is_dir:
                    shutil.rmtree(temp_path)
                else:
                    os.remove(temp_path)
                if verbose:
                    logger.debug(f"Cleaned up temporary artifact: {temp_path}")
            except Exception as exc:
                logger.warning(f"Failed to clean up temporary artifact {temp_path}: {exc!s}")


def _write_scan_sbom(
    sbom: str | None,
    audit_result: ModelAuditResultModel,
    expanded_paths: list[str],
    path_state: _ScanPathState,
    *,
    scan_and_delete: bool,
) -> None:
    """Write CycloneDX SBOM output from the concrete paths that were scanned."""
    if not sbom:
        return

    from .integrations.sbom_generator import generate_sbom_pydantic

    asset_paths = list(
        dict.fromkeys(asset.path for asset in audit_result.assets if asset.path and asset.type != "skipped")
    )
    if asset_paths and (scan_and_delete or not path_state.sbom_paths_resolved):
        paths_for_sbom = [_display_scan_path(path) for path in asset_paths]
    elif path_state.sbom_paths_resolved:
        paths_for_sbom = path_state.scanned_paths
    else:
        paths_for_sbom = (
            path_state.scanned_paths
            if path_state.scanned_paths
            else [_display_scan_path(path) for path in expanded_paths]
        )

    sbom_text = generate_sbom_pydantic(paths_for_sbom, audit_result)
    _write_output_text_file(sbom, sbom_text)


def _format_scan_output(
    audit_result: ModelAuditResultModel,
    expanded_paths: list[str],
    *,
    output_format: str,
    verbose: bool,
) -> str:
    """Render scan results in the requested output format."""
    if output_format == "json":
        if not verbose:
            audit_result.issues = [issue for issue in audit_result.issues if issue.severity != IssueSeverity.DEBUG]
            audit_result.checks = [check for check in audit_result.checks if check.severity != IssueSeverity.DEBUG]
        redacted_result = redact_source_value(audit_result.model_dump(mode="python", exclude_none=True))
        return json.dumps(_JSON_VALUE_ADAPTER.dump_python(redacted_result, mode="json"), indent=2)

    if output_format == "sarif":
        return format_sarif_output(audit_result, expanded_paths, verbose)

    redacted_result = redact_source_value(audit_result.model_dump(mode="python"))
    return format_text_output(redacted_result if isinstance(redacted_result, dict) else {}, verbose)


def _emit_scan_output(
    output_text: str,
    audit_result: ModelAuditResultModel,
    *,
    output: str | None,
    output_format: str,
    verbose: bool,
) -> None:
    """Write rendered scan output to a file or stdout and preserve text-mode UX."""
    if output:
        _write_output_text_file(output, output_text)

        click.echo(f"Results written to {_display_path(output)}")

        if verbose:
            visible_issues = audit_result.issues
            if visible_issues:
                critical_count = len([issue for issue in visible_issues if issue.severity == IssueSeverity.CRITICAL])
                warning_count = len([issue for issue in visible_issues if issue.severity == IssueSeverity.WARNING])
                if critical_count > 0:
                    click.echo(f"Found {critical_count} critical issue(s), {warning_count} warning(s)")
                elif warning_count > 0:
                    click.echo(f"Found {warning_count} warning(s)")
                else:
                    click.echo(f"Found {len(visible_issues)} informational issue(s)")
            else:
                click.echo("No security issues found")
        return

    if output_format == "text":
        click.echo("\n" + "─" * 80)
    click.echo(output_text)


def _format_scanner_catalog(output_format: str) -> str:
    """Render registered scanners for CLI discovery."""
    scanners = scanner_catalog()
    if output_format == "json":
        return json.dumps({"scanners": scanners}, indent=2)

    lines = ["Registered scanners:"]
    for scanner in scanners:
        extensions = ", ".join(scanner["extensions"]) if scanner["extensions"] else "-"
        dependencies = ", ".join(scanner["dependencies"]) if scanner["dependencies"] else "-"
        lines.extend(
            [
                f"{scanner['id']} ({scanner['class']})",
                f"  extensions: {extensions}",
                f"  dependencies: {dependencies}",
                f"  {scanner['description']}",
            ]
        )
    return "\n".join(lines)


def _emit_scanner_catalog(*, output_format: str, output: str | None) -> None:
    """Write scanner discovery output to a file or stdout."""
    if output_format == "sarif":
        click.echo("Error: --list-scanners supports text or json output, not sarif", err=True)
        sys.exit(2)

    output_text = _format_scanner_catalog(output_format)
    if output:
        _write_output_text_file(output, output_text, trailing_newline=True)
        return
    click.echo(output_text)


def _announce_suppressed_preferred_scanners(suppressions: list[dict[str, Any]]) -> None:
    """Print a stderr warning summarizing preferred scanners suppressed by selection."""
    suppressed_ids = sorted({entry["scanner_id"] for entry in suppressions})
    click.echo(
        "Warning: scanner selection suppressed the preferred scanner(s) for "
        f"{len(suppressions)} file(s): {', '.join(suppressed_ids)}. "
        "These files were not analyzed by the scanner that routing would normally pick; "
        "rerun without --scanners/--exclude-scanner or widen the selection to close the gap.",
        err=True,
    )
    for entry in suppressions[:5]:
        location = _escape_terminal_text(entry["location"])
        scanner_id = _escape_terminal_text(entry["scanner_id"])
        click.echo(f"  - {location} (would have used: {scanner_id})", err=True)
    if len(suppressions) > 5:
        click.echo(f"  … and {len(suppressions) - 5} more", err=True)


def _record_suppressed_preferred_scanners(audit_result: ModelAuditResultModel) -> list[dict[str, Any]]:
    """Populate audit metadata with preferred-scanner suppressions and return them."""
    suppressions = collect_suppressed_preferred_scanners(audit_result.checks or [])
    if not suppressions:
        return suppressions

    if audit_result.scanner_selection is None:
        audit_result.scanner_selection = {}
    audit_result.scanner_selection["suppressed_preferred_scanner_ids"] = sorted(
        {entry["scanner_id"] for entry in suppressions}
    )
    return suppressions


def _record_scan_end_and_exit(audit_result: ModelAuditResultModel, scan_start_time: float) -> NoReturn:
    """Record final telemetry and exit with the scan result's status code."""
    scan_duration = time.time() - scan_start_time
    try:
        if audit_result.has_errors:
            failure_reason = (
                "Model acquisition failed"
                if _results_have_acquisition_error_metadata(audit_result)
                else "Scan completed with errors"
            )
            record_scan_failed(scan_duration, failure_reason)
        else:
            record_scan_completed(scan_duration, audit_result.model_dump())
    finally:
        flush_telemetry()

    sys.exit(determine_exit_code(audit_result))


def _should_skip_non_model_file(scan_path: str, runtime: _ScanRuntimeConfig, *, verbose: bool) -> bool:
    """Return True when the local scan prefilter should skip a non-model file."""
    if _local_path_will_be_scanned(scan_path, skip_non_model_files=runtime.skip_non_model_files):
        return False

    _, ext = os.path.splitext(scan_path)
    ext = ext.lower()
    display_path = _display_path(scan_path)
    if ext in (".py", ".js", ".html", ".css"):
        if verbose:
            logger.debug(f"Skipped: {display_path} (non-model file)")
        if runtime.show_styled_output:
            click.echo(f"Skipping non-model file: {display_path}")
        return True

    if verbose:
        logger.debug(f"Skipped: {display_path} (non-model .txt file)")
    if runtime.show_styled_output:
        click.echo(f"Skipping non-model file: {display_path}")
    return True


def _create_path_progress_callback(
    *,
    spinner: Any | None,
    progress_tracker: Any | None,
    actual_path: str,
) -> Any | None:
    """Build the legacy spinner callback or enhanced tracker callback for one path."""
    progress_callback = None
    if spinner and not progress_tracker:

        def update_progress(message: str, percentage: float, spinner_bound: Any = spinner) -> None:
            spinner_bound.text = f"{_escape_terminal_text(message)} ({percentage:.1f}%)"

        return update_progress

    if not progress_tracker:
        return progress_callback

    try:
        from .progress import ProgressPhase

        if os.path.isfile(actual_path):
            total_bytes = os.path.getsize(actual_path)
            total_items = 1
        elif os.path.isdir(actual_path):
            total_bytes, total_items = _summarize_progress_tree(actual_path)
        else:
            total_bytes = 0
            total_items = 1

        progress_tracker.stats.total_bytes = total_bytes
        progress_tracker.stats.total_items = total_items
        progress_tracker.set_phase(ProgressPhase.INITIALIZING, f"Starting scan: {_display_path(actual_path)}")
    except (ImportError, RecursionError):
        return None

    def enhanced_progress_callback(message: str, percentage: float) -> None:
        display_message = _escape_terminal_text(message)
        if progress_tracker:
            bytes_processed = int((percentage / 100.0) * total_bytes) if total_bytes > 0 else 0
            progress_tracker.update_bytes(bytes_processed, display_message)

            message_lower = message.lower()
            if "loading" in message_lower:
                progress_tracker.set_phase(ProgressPhase.LOADING, display_message)
            elif "analyzing" in message_lower or "scanning" in message_lower:
                progress_tracker.set_phase(ProgressPhase.ANALYZING, display_message)
            elif "checking" in message_lower:
                progress_tracker.set_phase(ProgressPhase.CHECKING, display_message)

        if spinner:
            spinner.text = f"{display_message} ({percentage:.1f}%)"

    return enhanced_progress_callback


def _summarize_progress_tree(path: str) -> tuple[int, int]:
    """Return total file bytes and total descendant items with one tree walk."""
    total_bytes = 0
    total_items = 0
    for item in Path(path).rglob("*"):
        total_items += 1
        if item.is_file():
            total_bytes += item.stat().st_size
    return total_bytes, total_items


def _scan_local_or_downloaded_path(
    path: str,
    source_result: _SourceDispatchResult,
    audit_result: ModelAuditResultModel,
    path_state: _ScanPathState,
    runtime: _ScanRuntimeConfig,
    progress_tracker: Any | None,
    blacklist: tuple[str, ...],
    *,
    verbose: bool,
) -> None:
    """Scan a local artifact or a downloaded path resolved by source dispatch."""
    actual_path = source_result.actual_path
    display_path = _display_path(path)
    explicit_family_group = path_state.explicit_shard_family_group_for(actual_path)
    pre_scan_shard_target = (
        _snapshot_validated_shard_target(
            actual_path,
            family_group=explicit_family_group,
            family_group_policy="explicit" if explicit_family_group else None,
        )
        if os.path.isfile(actual_path)
        else {}
    )
    if _should_skip_non_model_file(actual_path, runtime, verbose=verbose):
        return

    spinner = None
    if runtime.show_styled_output and should_show_spinner():
        spinner_text = f"Scanning {style_text(display_path, fg='cyan')}"
        spinner = yaspin(Spinners.dots, text=spinner_text)
        spinner.start()
    elif runtime.show_styled_output:
        click.echo(f"Scanning {display_path}...")

    try:
        progress_callback = _create_path_progress_callback(
            spinner=spinner,
            progress_tracker=progress_tracker,
            actual_path=actual_path,
        )

        if runtime.scan_and_delete and os.path.isdir(actual_path):
            from .core import scan_model_streaming
            from .utils.helpers.file_iterator import iterate_files_streaming

            if spinner:
                spinner.text = "Starting streaming scan of directory..."
            elif runtime.show_styled_output:
                click.echo(style_text("🔄 Starting streaming scan of directory...", fg="cyan"))

            file_generator = iterate_files_streaming(actual_path)
            streaming_result = scan_model_streaming(
                file_generator=file_generator,
                timeout=runtime.timeout,
                delete_after_scan=False,
                scan_root=actual_path,
                progress_callback=progress_callback,
                blacklist_patterns=list(blacklist) if blacklist else None,
                max_file_size=runtime.max_file_size,
                max_total_size=runtime.max_total_size,
                strict_license=runtime.strict_license,
                skip_file_types=runtime.skip_non_model_files,
                use_hf_whitelist=runtime.use_hf_whitelist,
                cache_enabled=runtime.cache_enabled,
                cache_dir=runtime.cache_dir,
                **_scanner_selection_overrides(runtime),
            )
            path_state.record_non_shard_result_errors(streaming_result)
            audit_result.aggregate_scan_result(streaming_result.model_dump())
            path_state.record_dvc_coverage(actual_path, streaming_result, scanner_config=runtime.config)
            path_state.track_streaming_paths_for_sbom(streaming_result, actual_path)

            if spinner:
                spinner.ok(style_text("✅ Streaming scan complete", fg="green", bold=True))
            elif runtime.show_styled_output:
                click.echo(style_text("✅ Streaming scan complete", fg="green", bold=True))
            return

        config_overrides: dict[str, Any] = {
            "enable_progress": bool(progress_tracker),
            "progress_update_interval": 2.0,
            "cache_enabled": runtime.cache_enabled,
            "cache_dir": runtime.cache_dir,
            **_scanner_selection_overrides(runtime),
        }
        is_dvc_pointer = actual_path.lower().endswith(".dvc")
        has_prior_dvc_coverage = bool(path_state.dvc_covered_paths or path_state.dvc_covered_directories)
        if is_dvc_pointer:
            config_overrides[DVC_EXTERNAL_COVERED_PATHS_CONFIG_KEY] = tuple(path_state.dvc_covered_paths)
            config_overrides[DVC_EXTERNAL_COVERED_DIRECTORIES_CONFIG_KEY] = tuple(path_state.dvc_covered_directories)
        if source_result.source_model_id and source_result.source_model_source == "huggingface":
            config_overrides["_trusted_source_provenance"] = make_trusted_source_provenance(
                source_result.source_model_id,
                source_result.source_model_source,
            )
        if source_result.repository_file_inventory:
            config_overrides[REPOSITORY_FILE_INVENTORY_CONFIG_KEY] = source_result.repository_file_inventory
        if source_result.repository_current_file:
            config_overrides[REPOSITORY_CURRENT_FILE_CONFIG_KEY] = source_result.repository_current_file

        if runtime.max_file_size > 0 or runtime.max_total_size > 0:
            record_feature_used(
                "large_model_support",
                max_file_size=runtime.max_file_size,
                max_total_size=runtime.max_total_size,
            )

        scan_results: ModelAuditResultModel = scan_model_directory_or_file(
            actual_path,
            blacklist_patterns=list(blacklist) if blacklist else None,
            timeout=runtime.timeout,
            max_file_size=runtime.max_file_size,
            max_total_size=runtime.max_total_size,
            strict_license=runtime.strict_license,
            progress_callback=progress_callback,
            skip_file_types=runtime.skip_non_model_files,
            use_hf_whitelist=runtime.use_hf_whitelist,
            **config_overrides,
        )
        path_state.record_validated_shard_targets(
            scan_results,
            pre_scan_target=pre_scan_shard_target,
        )
        audit_result.aggregate_scan_result(scan_results.model_dump())
        if is_dvc_pointer and has_prior_dvc_coverage:
            audit_result.content_hash = None
        path_state.record_dvc_coverage(actual_path, scan_results, scanner_config=runtime.config)
        if is_dvc_pointer:
            path_state.track_streaming_paths_for_sbom(scan_results, None)
        elif os.path.isdir(actual_path):
            path_state.track_directory_paths_for_sbom(scan_results)
        else:
            path_state.scanned_paths.append(_display_scan_path(actual_path))

        visible_issues = [
            issue for issue in list(scan_results.issues) if verbose or issue.severity != IssueSeverity.DEBUG
        ]
        issue_count = len(visible_issues)
        has_critical = any(issue.severity == IssueSeverity.CRITICAL for issue in visible_issues)
        has_incomplete_coverage = results_have_inconclusive_outcome(scan_results)

        if spinner:
            spinner.text = f"Scanned {style_text(display_path, fg='cyan')}"
            if issue_count == 0 and has_incomplete_coverage:
                spinner.ok(style_text("⚠️  Coverage incomplete", fg="yellow", bold=True))
            elif issue_count == 0:
                spinner.ok(style_text("✅ Clean", fg="green", bold=True))
            elif has_critical:
                status = f"🚨 Found {issue_count} issue{'s' if issue_count > 1 else ''} (CRITICAL)"
                if has_incomplete_coverage:
                    status += ", coverage incomplete"
                spinner.fail(
                    style_text(
                        status,
                        fg="red",
                        bold=True,
                    ),
                )
            else:
                status = f"⚠️  Found {issue_count} issue{'s' if issue_count > 1 else ''}"
                if has_incomplete_coverage:
                    status += " (coverage incomplete)"
                spinner.ok(
                    style_text(
                        status,
                        fg="yellow",
                        bold=True,
                    ),
                )
        elif runtime.show_styled_output:
            if issue_count == 0 and has_incomplete_coverage:
                click.echo(f"Scanned {display_path}: Coverage incomplete")
            elif issue_count == 0:
                click.echo(f"Scanned {display_path}: Clean")
            else:
                issues_str = "issue" if issue_count == 1 else "issues"
                if has_critical:
                    status = f"Scanned {display_path}: Found {issue_count} {issues_str} (CRITICAL)"
                else:
                    status = f"Scanned {display_path}: Found {issue_count} {issues_str}"
                if has_incomplete_coverage:
                    status += ", coverage incomplete"
                click.echo(status)
    except Exception as exc:
        display_error = _display_error(exc, path)
        if spinner:
            spinner.text = f"Error scanning {style_text(display_path, fg='cyan')}"
            spinner.fail(style_text("❌ Error", fg="red", bold=True))
        elif runtime.show_styled_output:
            click.echo(f"Error scanning {display_path}")

        logger.error(f"Error during scan of {display_path}: {display_error}")
        click.echo(f"Error scanning {display_path}: {display_error}", err=True)
        path_state.mark_non_shard_error(audit_result)
        path_state.scanned_paths.append(_display_scan_path(actual_path))

        if progress_tracker:
            progress_tracker.report_error(Exception(display_error))


def _resolve_scan_source_for_path(
    path: str,
    audit_result: ModelAuditResultModel,
    path_state: _ScanPathState,
    runtime: _ScanRuntimeConfig,
    blacklist: tuple[str, ...],
    *,
    verbose: bool,
    dry_run: bool,
) -> _SourceDispatchResult | None:
    """Resolve one source path and execute source-native scans when they should bypass local scanning."""
    if is_cleartext_cloud_url(path):
        click.echo(f"Error: Cleartext cloud storage URL is not supported: {_display_path(path)}", err=True)
        path_state.mark_non_shard_error(audit_result)
        return None

    if is_cleartext_pytorch_hub_url(path):
        click.echo(f"Error: Cleartext PyTorch Hub URL is not supported: {_display_path(path)}", err=True)
        path_state.mark_non_shard_error(audit_result)
        return None

    if is_huggingface_file_url(path):
        display_path = _display_path(path)
        if dry_run:
            try:
                repo_id, revision, filename = parse_huggingface_file_url(path)
                if runtime.show_styled_output:
                    click.echo(f"\n📊 Preview for {style_text(display_path, fg='cyan')}:")
                    click.echo("   Type: HuggingFace file")
                    click.echo(f"   Repository: {_escape_terminal_text(repo_id)}")
                    click.echo(f"   Revision: {_escape_terminal_text(revision)}")
                    click.echo(f"   File: {_escape_terminal_text(filename)}")
                return _SourceDispatchResult(actual_path=path, local_scan_required=False)
            except Exception as exc:
                error_msg = _display_error(exc, path)
                click.echo(f"Error analyzing {display_path}: {error_msg}", err=True)
                path_state.mark_non_shard_error(audit_result)
                return None

        download_spinner = None
        temp_dir = None
        if runtime.show_styled_output and should_show_spinner():
            download_spinner = yaspin(
                Spinners.dots, text=f"Downloading file from {style_text(display_path, fg='cyan')}"
            )
            download_spinner.start()
        elif runtime.show_styled_output:
            click.echo(f"Downloading file from {display_path}...")

        try:
            if runtime.cache_enabled and runtime.cache_dir:
                hf_cache_dir = Path(runtime.cache_dir) / "huggingface"
            elif runtime.cache_enabled:
                hf_cache_dir = Path.home() / ".modelaudit" / "cache" / "huggingface"
            else:
                import tempfile

                hf_cache_dir = Path(tempfile.mkdtemp(prefix="modelaudit_hf_"))
                temp_dir = str(hf_cache_dir)

            _repo_id, _revision, repository_current_file = parse_huggingface_file_url(path)
            direct_repository_file_inventory: list[str] = []
            download_path = download_file_from_hf(
                path,
                cache_dir=hf_cache_dir,
                max_size=runtime.max_download_bytes,
                repository_file_inventory=direct_repository_file_inventory,
                timeout_seconds=runtime.timeout,
            )
            source_model_id, source_model_source = extract_model_id_from_path(path)

            if not runtime.cache_enabled and temp_dir is None:
                temp_dir = str(hf_cache_dir)

            if download_spinner:
                download_spinner.ok(style_text("✅ Downloaded", fg="green", bold=True))
            elif runtime.show_styled_output:
                click.echo(style_text("✅ Download complete", fg="green", bold=True))

            return _SourceDispatchResult(
                actual_path=str(download_path),
                temp_path=temp_dir,
                source_model_id=source_model_id,
                source_model_source=source_model_source,
                repository_file_inventory=tuple(direct_repository_file_inventory),
                repository_current_file=repository_current_file,
            )
        except Exception as exc:
            if download_spinner:
                download_spinner.fail(style_text("❌ Download failed", fg="red", bold=True))
            elif runtime.show_styled_output:
                click.echo(style_text("❌ Download failed", fg="red", bold=True))

            error_msg = _display_error(exc, path)
            logger.error(f"Failed to download file from {display_path}: {error_msg}")
            click.echo(f"Error downloading file from {display_path}: {error_msg}", err=True)
            _record_huggingface_acquisition_error(
                audit_result,
                path_state,
                path=path,
                error_msg=error_msg,
            )
            path_state.defer_temp_cleanup(
                temp_dir,
                cache_enabled=runtime.cache_enabled,
                verbose=verbose,
            )
            return None

    if is_huggingface_url(path):
        display_path = _display_path(path)
        hf_stream_kwargs: dict[str, Any] = {}
        if runtime.scan_and_delete:
            if runtime.scannable_extensions is not None:
                hf_stream_kwargs["scannable_extensions"] = runtime.scannable_extensions
            if runtime.scannable_filenames is not None:
                hf_stream_kwargs["scannable_filenames"] = runtime.scannable_filenames
            if runtime.scannable_scanner_ids is not None:
                hf_stream_kwargs["scannable_scanner_ids"] = runtime.scannable_scanner_ids
            if runtime.hf_stream_include_all_files:
                hf_stream_kwargs["include_all_files"] = True
        hf_preview_kwargs: dict[str, Any] = {"timeout_seconds": runtime.timeout}
        if runtime.scan_and_delete:
            hf_preview_kwargs.update(hf_stream_kwargs)
            hf_preview_kwargs["streaming_selection"] = True
            hf_preview_kwargs.setdefault("include_all_files", False)
        if dry_run:
            try:
                model_info = get_model_info(path, **hf_preview_kwargs)
                size_bytes = int(model_info.get("total_size") or 0)
                inaccessible_gated_file_count = int(model_info.get("inaccessible_gated_file_count") or 0)
                unknown_size_count = int(model_info.get("unknown_size_count") or 0)
                if size_bytes == 0 and unknown_size_count:
                    size_str = "Unknown size"
                elif size_bytes >= 1024 * 1024 * 1024:
                    size_str = f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
                elif size_bytes >= 1024 * 1024:
                    size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
                else:
                    size_str = f"{size_bytes / 1024:.2f} KB"
                if size_bytes > 0 and unknown_size_count:
                    size_str = f"At least {size_str}"

                if runtime.show_styled_output:
                    click.echo(f"\n📊 Preview for {style_text(display_path, fg='cyan')}:")
                    click.echo("   Type: HuggingFace model")
                    click.echo(f"   Model: {_escape_terminal_text(str(model_info['model_id']))}")
                    click.echo(f"   Size: {size_str} ({_escape_terminal_text(str(model_info['file_count']))} files)")
                    if inaccessible_gated_file_count:
                        gated_file_count = _escape_terminal_text(str(inaccessible_gated_file_count))
                        click.echo(f"   Access: {gated_file_count} selected file(s) are gated/inaccessible")
                    if unknown_size_count:
                        click.echo(
                            f"   Access: {_escape_terminal_text(str(unknown_size_count))} "
                            "selected file size(s) unavailable"
                        )
                    if runtime.scan_and_delete:
                        click.echo(style_text("   Mode: Streaming (scan and delete to save disk)", fg="cyan"))
                return _SourceDispatchResult(actual_path=path, local_scan_required=False)
            except Exception as exc:
                error_msg = _display_error(exc, path)
                click.echo(f"Error analyzing {display_path}: {error_msg}", err=True)
                path_state.mark_non_shard_error(audit_result)
                return None

        if runtime.show_styled_output:
            click.echo(f"\n📥 Preparing to download from {style_text(display_path, fg='cyan')}")

            try:
                model_info = get_model_info(path, **hf_preview_kwargs)
                size_bytes = int(model_info.get("total_size") or 0)
                inaccessible_gated_file_count = int(model_info.get("inaccessible_gated_file_count") or 0)
                unknown_size_count = int(model_info.get("unknown_size_count") or 0)
                if size_bytes == 0 and unknown_size_count:
                    size_str = "Unknown size"
                elif size_bytes >= 1024 * 1024 * 1024:
                    size_str = f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
                elif size_bytes >= 1024 * 1024:
                    size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
                else:
                    size_str = f"{size_bytes / 1024:.2f} KB"
                if size_bytes > 0 and unknown_size_count:
                    size_str = f"At least {size_str}"

                model_id = _escape_terminal_text(str(model_info["model_id"]))
                file_count = _escape_terminal_text(str(model_info["file_count"]))
                click.echo(f"   Model: {model_id}")
                click.echo(f"   Size: {size_str} ({file_count} files)")
                if inaccessible_gated_file_count:
                    gated_file_count = _escape_terminal_text(str(inaccessible_gated_file_count))
                    click.echo(f"   Access: {gated_file_count} selected file(s) are gated/inaccessible")
                if unknown_size_count:
                    click.echo(
                        f"   Access: {_escape_terminal_text(str(unknown_size_count))} selected file size(s) unavailable"
                    )

                if runtime.scan_and_delete:
                    click.echo(style_text("   Mode: Streaming (scan and delete to save disk)", fg="cyan"))
            except Exception as exc:
                logger.debug(
                    "Unable to display HuggingFace model metadata for %s: %s",
                    display_path,
                    _display_error(exc, path),
                )

        temp_dir = None
        try:
            source_model_id, source_model_source = extract_model_id_from_path(path)
            if runtime.cache_enabled and runtime.cache_dir:
                hf_cache_dir = Path(runtime.cache_dir)
            elif runtime.cache_enabled:
                hf_cache_dir = Path.home() / ".modelaudit" / "cache"
            else:
                import tempfile

                hf_cache_dir = Path(tempfile.mkdtemp(prefix="modelaudit_hf_"))
                temp_dir = str(hf_cache_dir)

            record_download_started("huggingface", display_path)
            record_feature_used("huggingface_download", cache_enabled=runtime.cache_enabled)
            download_start = time.time()
            trusted_source_provenance = None
            if source_model_id and source_model_source == "huggingface":
                trusted_source_provenance = make_trusted_source_provenance(
                    source_model_id,
                    source_model_source,
                )

            if runtime.scan_and_delete:
                from .core import scan_model_streaming
                from .utils.sources.huggingface import download_model_streaming

                if runtime.show_styled_output:
                    click.echo(style_text("🔄 Starting streaming scan...", fg="cyan"))

                stream_repository_file_inventory: list[str] = []
                stream_namespace, stream_repo_name, _stream_requested_revision = parse_huggingface_url_with_revision(
                    path
                )
                stream_hf_cache_root = hf_cache_dir / "huggingface"
                stream_repository_scan_root = stream_hf_cache_root / stream_namespace
                if stream_repo_name:
                    stream_repository_scan_root = stream_repository_scan_root / stream_repo_name
                file_generator = _track_huggingface_stream_acquisition(
                    download_model_streaming(
                        path,
                        cache_dir=hf_cache_dir,
                        show_progress=runtime.show_progress,
                        max_size=runtime.max_download_bytes,
                        timeout_seconds=runtime.timeout,
                        repository_file_inventory=stream_repository_file_inventory,
                        **hf_stream_kwargs,
                    )
                )

                streaming_kwargs: dict[str, Any] = {}
                if trusted_source_provenance is not None:
                    streaming_kwargs["_trusted_source_provenance"] = trusted_source_provenance
                streaming_kwargs[REPOSITORY_FILE_INVENTORY_CONFIG_KEY] = stream_repository_file_inventory
                streaming_kwargs[REPOSITORY_SCAN_ROOT_CONFIG_KEY] = str(stream_repository_scan_root)
                streaming_kwargs.update(_scanner_selection_overrides(runtime))

                try:
                    streaming_result = scan_model_streaming(
                        file_generator=file_generator,
                        shard_family_group=f"stream-invocation:{id(file_generator):x}",
                        _trusted_shard_family_root=(
                            _make_trusted_stream_shard_root(str(hf_cache_dir / "huggingface"))
                            if runtime.cache_enabled and trusted_source_provenance is not None
                            else None
                        ),
                        timeout=runtime.timeout,
                        delete_after_scan=True,
                        scan_root=str(stream_hf_cache_root),
                        blacklist_patterns=list(blacklist) if blacklist else None,
                        max_file_size=runtime.max_file_size,
                        max_total_size=runtime.max_total_size,
                        strict_license=runtime.strict_license,
                        skip_file_types=runtime.skip_non_model_files,
                        use_hf_whitelist=runtime.use_hf_whitelist,
                        cache_enabled=runtime.cache_enabled,
                        cache_dir=runtime.cache_dir,
                        **streaming_kwargs,
                    )
                except _HuggingFaceAcquisitionError:
                    raise
                except Exception as exc:
                    raise _HuggingFaceStreamInterruptedError(str(exc)) from exc

                path_state.record_non_shard_result_errors(streaming_result)
                audit_result.aggregate_scan_result(streaming_result.model_dump())
                path_state.track_streaming_paths_for_sbom(streaming_result, path)

                download_duration = time.time() - download_start
                record_download_completed("huggingface", download_duration, 0, display_path)

                if runtime.show_styled_output:
                    if streaming_result.has_errors or not streaming_result.success:
                        click.echo(style_text("❌ Streaming scan incomplete", fg="red", bold=True))
                    else:
                        click.echo(style_text("✅ Streaming scan complete", fg="green", bold=True))

                return _SourceDispatchResult(
                    actual_path=path,
                    local_scan_required=False,
                    temp_path=temp_dir,
                    source_model_id=source_model_id,
                    source_model_source=source_model_source,
                )

            download_spinner = None
            if runtime.show_styled_output and should_show_spinner():
                download_spinner = yaspin(Spinners.dots, text="Downloading model files...")
                download_spinner.start()

            show_progress = runtime.show_styled_output and should_show_spinner()
            download_repository_file_inventory: list[str] = []
            download_path = download_model(
                path,
                cache_dir=hf_cache_dir,
                show_progress=show_progress,
                max_size=runtime.max_download_bytes,
                timeout_seconds=runtime.timeout,
                repository_file_inventory=download_repository_file_inventory,
            )
            download_duration = time.time() - download_start
            try:
                download_size = sum(
                    file_path.stat().st_size for file_path in Path(download_path).rglob("*") if file_path.is_file()
                )
                record_download_completed("huggingface", download_duration, download_size, display_path)
            except Exception:
                record_download_completed("huggingface", download_duration, 0, display_path)

            if download_spinner:
                download_spinner.ok(style_text("✅ Downloaded", fg="green", bold=True))
            elif runtime.show_styled_output:
                click.echo(style_text("✅ Download complete", fg="green", bold=True))

            return _SourceDispatchResult(
                actual_path=str(download_path),
                temp_path=temp_dir,
                source_model_id=source_model_id,
                source_model_source=source_model_source,
                repository_file_inventory=tuple(download_repository_file_inventory),
            )
        except _HuggingFaceStreamInterruptedError as exc:
            if runtime.show_styled_output:
                click.echo(style_text("❌ Download/scan failed", fg="red", bold=True))

            error_msg = _display_error(exc, path)
            logger.error(f"Streaming scan interrupted for {display_path}: {error_msg}")
            click.echo(f"Error processing model from {display_path}: {error_msg}", err=True)
            path_state.mark_non_shard_error(audit_result)
            audit_result.success = False
            path_state.defer_temp_cleanup(
                temp_dir,
                cache_enabled=runtime.cache_enabled,
                verbose=verbose,
            )
            return None
        except Exception as exc:
            if runtime.show_styled_output:
                click.echo(style_text("❌ Download/scan failed", fg="red", bold=True))

            error_msg = _display_error(exc, path)
            if "insufficient disk space" in error_msg.lower():
                logger.error(f"Disk space error for {display_path}: {error_msg}")
                click.echo(style_text(f"\n⚠️  {error_msg}", fg="yellow"), err=True)
                click.echo(
                    style_text(
                        "💡 Tip: Use --stream to minimize disk usage, or use "
                        "--cache-dir to specify a directory with more space",
                        fg="cyan",
                    ),
                    err=True,
                )
            else:
                logger.error(f"Failed to process model from {display_path}: {error_msg}")
                click.echo(f"Error processing model from {display_path}: {error_msg}", err=True)

            _record_huggingface_acquisition_error(
                audit_result,
                path_state,
                path=path,
                error_msg=error_msg,
            )
            path_state.defer_temp_cleanup(
                temp_dir,
                cache_enabled=runtime.cache_enabled,
                verbose=verbose,
            )
            return None

    if is_pytorch_hub_url(path):
        display_path = _display_path(path)
        download_spinner = None
        try:
            record_download_started("pytorch_hub", path)
            record_feature_used("pytorch_hub_download", cache_enabled=runtime.cache_enabled)
            download_start = time.time()

            if runtime.scan_and_delete:
                from .core import scan_model_streaming
                from .utils.sources.pytorch_hub import download_pytorch_hub_model_streaming

                if runtime.show_styled_output:
                    click.echo(style_text("🔄 Starting streaming scan...", fg="cyan"))

                file_generator = download_pytorch_hub_model_streaming(
                    path,
                    show_progress=runtime.show_progress,
                    max_size=runtime.max_download_bytes,
                    scannable_extensions=runtime.pytorch_hub_scannable_extensions,
                    timeout=runtime.timeout,
                )
                streaming_result = scan_model_streaming(
                    file_generator=file_generator,
                    shard_family_group=f"stream-invocation:{id(file_generator):x}",
                    timeout=runtime.timeout,
                    delete_after_scan=True,
                    blacklist_patterns=list(blacklist) if blacklist else None,
                    max_file_size=runtime.max_file_size,
                    max_total_size=runtime.max_total_size,
                    strict_license=runtime.strict_license,
                    skip_file_types=runtime.skip_non_model_files,
                    use_hf_whitelist=runtime.use_hf_whitelist,
                    cache_enabled=runtime.cache_enabled,
                    cache_dir=runtime.cache_dir,
                    **_scanner_selection_overrides(runtime),
                )
                path_state.track_streaming_paths_for_sbom(streaming_result, path)
                path_state.record_non_shard_result_errors(streaming_result)
                audit_result.aggregate_scan_result(streaming_result.model_dump())
                record_download_completed("pytorch_hub", time.time() - download_start, 0, path)

                if runtime.show_styled_output:
                    click.echo(style_text("✅ Streaming scan complete", fg="green", bold=True))

                return _SourceDispatchResult(actual_path=path, local_scan_required=False)

            if runtime.show_styled_output and should_show_spinner():
                spinner_text = f"Downloading from {style_text(display_path, fg='cyan')}"
                download_spinner = yaspin(Spinners.dots, text=spinner_text)
                download_spinner.start()
            elif runtime.show_styled_output:
                click.echo(f"Downloading from {display_path}...")

            download_path = download_pytorch_hub_model(
                path,
                cache_dir=Path(runtime.cache_dir) if runtime.cache_dir else None,
                max_size=runtime.max_download_bytes,
                scannable_extensions=runtime.pytorch_hub_scannable_extensions,
            )
            download_duration = time.time() - download_start
            try:
                download_size = sum(
                    file_path.stat().st_size for file_path in Path(download_path).rglob("*") if file_path.is_file()
                )
                record_download_completed("pytorch_hub", download_duration, download_size, path)
            except Exception:
                record_download_completed("pytorch_hub", download_duration, 0, path)

            if download_spinner:
                download_spinner.ok(style_text("✅ Downloaded", fg="green", bold=True))
            elif runtime.show_styled_output:
                click.echo("Downloaded successfully")

            return _SourceDispatchResult(actual_path=str(download_path), temp_path=str(download_path))
        except Exception as exc:
            if download_spinner:
                download_spinner.fail(style_text("❌ Download failed", fg="red", bold=True))
            elif runtime.show_styled_output:
                click.echo("Download failed")

            error_msg = _display_error(exc, path)
            if "insufficient disk space" in error_msg.lower():
                logger.error(f"Disk space error for {display_path}: {error_msg}")
                click.echo(style_text(f"\n⚠️  {error_msg}", fg="yellow"), err=True)
                click.echo(
                    style_text(
                        "💡 Tip: Free up disk space or use --cache-dir to specify a directory with more space",
                        fg="cyan",
                    ),
                    err=True,
                )
            else:
                logger.error(f"Failed to download model from {display_path}: {error_msg}")
                click.echo(f"Error downloading model from {display_path}: {error_msg}", err=True)

            path_state.mark_non_shard_error(audit_result)
            return None

    if is_cloud_url(path):
        display_path = _display_path(path)
        if dry_run:
            import asyncio

            from .utils.sources.cloud_storage import analyze_cloud_target

            try:
                metadata = asyncio.run(analyze_cloud_target(path))
                click.echo(f"\n📊 Preview for {style_text(display_path, fg='cyan')}:")
                click.echo(f"   Type: {metadata['type']}")

                if metadata["type"] == "file":
                    click.echo(f"   Size: {metadata.get('human_size', 'unknown')}")
                    click.echo(f"   Estimated download time: {metadata.get('estimated_time', 'unknown')}")
                elif metadata["type"] == "directory":
                    click.echo(f"   Files: {metadata.get('file_count', 0)}")
                    click.echo(f"   Total size: {metadata.get('human_size', 'unknown')}")
                    click.echo(f"   Estimated download time: {metadata.get('estimated_time', 'unknown')}")

                    if runtime.selective_download:
                        from .utils.sources.cloud_storage import filter_scannable_files

                        scannable = filter_scannable_files(
                            metadata.get("files", []),
                            scannable_extensions=runtime.scannable_extensions,
                            scannable_filenames=runtime.scannable_filenames,
                        )
                        click.echo(f"   Scannable files: {len(scannable)} of {metadata.get('file_count', 0)}")

                return _SourceDispatchResult(actual_path=path, local_scan_required=False)
            except Exception as exc:
                error_msg = _display_error(exc, path)
                click.echo(f"Error analyzing {display_path}: {error_msg}", err=True)
                path_state.mark_non_shard_error(audit_result)
                return None

        download_spinner = None
        try:
            record_download_started("cloud_storage", path)
            record_feature_used("cloud_storage_download", cache_enabled=runtime.cache_enabled)
            download_start = time.time()

            if runtime.scan_and_delete:
                from .core import scan_model_streaming
                from .utils.sources.cloud_storage import download_from_cloud_streaming

                if runtime.show_styled_output:
                    click.echo(style_text("🔄 Starting streaming scan from cloud storage...", fg="cyan"))

                cloud_stream_kwargs: dict[str, Any] = {}
                if runtime.scannable_extensions is not None:
                    cloud_stream_kwargs["scannable_extensions"] = runtime.scannable_extensions
                if runtime.scannable_filenames is not None:
                    cloud_stream_kwargs["scannable_filenames"] = runtime.scannable_filenames
                if runtime.scanner_selection is not None:
                    cloud_stream_kwargs["scanner_selection"] = runtime.scanner_selection
                file_generator = download_from_cloud_streaming(
                    path,
                    cache_dir=Path(runtime.cache_dir) if runtime.cache_dir else None,
                    max_size=runtime.max_download_bytes,
                    show_progress=runtime.show_progress,
                    selective=runtime.selective_download,
                    **cloud_stream_kwargs,
                )
                streaming_result = scan_model_streaming(
                    file_generator=file_generator,
                    shard_family_group=f"stream-invocation:{id(file_generator):x}",
                    timeout=runtime.timeout,
                    delete_after_scan=True,
                    blacklist_patterns=list(blacklist) if blacklist else None,
                    max_file_size=runtime.max_file_size,
                    max_total_size=runtime.max_total_size,
                    strict_license=runtime.strict_license,
                    skip_file_types=runtime.skip_non_model_files,
                    use_hf_whitelist=runtime.use_hf_whitelist,
                    cache_enabled=runtime.cache_enabled,
                    cache_dir=runtime.cache_dir,
                    **_scanner_selection_overrides(runtime),
                )
                path_state.track_streaming_paths_for_sbom(streaming_result, path)
                path_state.record_non_shard_result_errors(streaming_result)
                audit_result.aggregate_scan_result(streaming_result.model_dump())
                record_download_completed("cloud_storage", time.time() - download_start, 0, path)

                if runtime.show_styled_output:
                    click.echo(style_text("✅ Streaming scan complete", fg="green", bold=True))

                return _SourceDispatchResult(actual_path=path, local_scan_required=False)

            if runtime.show_styled_output and should_show_spinner():
                spinner_text = f"Downloading from {style_text(display_path, fg='cyan')}"
                download_spinner = yaspin(Spinners.dots, text=spinner_text)
                download_spinner.start()
            elif runtime.show_styled_output:
                click.echo(f"Downloading from {display_path}...")

            cloud_download_kwargs: dict[str, Any] = {}
            if runtime.scannable_extensions is not None:
                cloud_download_kwargs["scannable_extensions"] = runtime.scannable_extensions
            if runtime.scannable_filenames is not None:
                cloud_download_kwargs["scannable_filenames"] = runtime.scannable_filenames
            if runtime.scanner_selection is not None:
                cloud_download_kwargs["scanner_selection"] = runtime.scanner_selection
            download_path = download_from_cloud(  # type: ignore[assignment]
                path,
                cache_dir=Path(runtime.cache_dir) if runtime.cache_dir else None,
                max_size=runtime.max_download_bytes,
                use_cache=runtime.cache_enabled,
                show_progress=verbose,
                selective=runtime.selective_download,
                stream_analyze=runtime.stream_analysis,
                **cloud_download_kwargs,
            )
            download_duration = time.time() - download_start
            try:
                download_size = sum(
                    file_path.stat().st_size for file_path in Path(download_path).rglob("*") if file_path.is_file()
                )
                record_download_completed("cloud_storage", download_duration, download_size, path)
            except Exception:
                record_download_completed("cloud_storage", download_duration, 0, path)

            if download_spinner:
                download_spinner.ok(style_text("✅ Downloaded", fg="green", bold=True))
            elif runtime.show_styled_output:
                click.echo("Downloaded successfully")

            return _SourceDispatchResult(
                actual_path=str(download_path),
                temp_path=str(download_path) if not runtime.cache_enabled else None,
            )
        except Exception as exc:
            if download_spinner:
                download_spinner.fail(style_text("❌ Download failed", fg="red", bold=True))
            elif runtime.show_styled_output:
                click.echo("Download failed")

            error_msg = _display_error(exc, path)
            if "insufficient disk space" in error_msg.lower():
                logger.error(f"Disk space error for {display_path}: {error_msg}")
                click.echo(style_text(f"\n⚠️  {error_msg}", fg="yellow"), err=True)
                click.echo(
                    style_text(
                        "💡 Tip: Free up disk space or use --cache-dir to specify a directory with more space",
                        fg="cyan",
                    ),
                    err=True,
                )
            else:
                logger.error(f"Failed to download from {display_path}: {error_msg}")
                click.echo(f"Error downloading from {display_path}: {error_msg}", err=True)

            path_state.mark_non_shard_error(audit_result)
            return None

    if is_mlflow_uri(path):
        display_path = _display_path(path)
        download_spinner = None
        if runtime.show_styled_output and should_show_spinner():
            download_spinner = yaspin(Spinners.dots, text=f"Downloading from {style_text(display_path, fg='cyan')}")
            download_spinner.start()
        elif runtime.show_styled_output:
            click.echo(f"Downloading from {display_path}...")

        try:
            record_download_started("mlflow", path)
            record_feature_used("mlflow_download")
            download_start = time.time()

            from .integrations.mlflow import scan_mlflow_model

            results: ModelAuditResultModel = scan_mlflow_model(
                path,
                registry_uri=runtime.mlflow_registry_uri,
                timeout=runtime.timeout,
                blacklist_patterns=list(blacklist) if blacklist else None,
                max_file_size=runtime.max_file_size,
                max_total_size=runtime.max_total_size,
                cache_enabled=runtime.cache_enabled,
                cache_dir=runtime.cache_dir,
                use_hf_whitelist=runtime.use_hf_whitelist,
                **_scanner_selection_overrides(runtime),
            )

            path_state.record_non_shard_result_errors(results)
            audit_result.aggregate_scan_result(results.model_dump())
            download_refusal_type = next(
                (
                    issue_type
                    for issue in results.issues
                    if isinstance((issue_type := getattr(issue, "type", None)), str)
                    and (issue_type.startswith("mlflow_download_") or issue_type == "mlflow_artifact_trust")
                ),
                None,
            )
            if download_refusal_type is not None:
                if download_spinner:
                    download_spinner.fail(style_text("❌ Download refused", fg="red", bold=True))
                elif runtime.show_styled_output:
                    refusal_reason = (
                        "configured size budget"
                        if download_refusal_type == "mlflow_download_budget"
                        else (
                            "MLflow artifact trust policy"
                            if download_refusal_type == "mlflow_artifact_trust"
                            else "MLflow staging safety checks"
                        )
                    )
                    click.echo(f"Download refused by {refusal_reason}")
            else:
                record_download_completed("mlflow", time.time() - download_start, results.bytes_scanned, path)
                if download_spinner:
                    download_spinner.ok(style_text("✅ Downloaded & Scanned", fg="green", bold=True))
                elif runtime.show_styled_output:
                    click.echo("Downloaded and scanned successfully")
            return _SourceDispatchResult(actual_path=path, local_scan_required=False)
        except Exception as exc:
            if download_spinner:
                download_spinner.fail(style_text("❌ Download failed", fg="red", bold=True))
            elif runtime.show_styled_output:
                click.echo("Download failed")

            error_msg = _display_error(exc, path)
            logger.error(f"Failed to download model from {display_path}: {error_msg}")
            click.echo(f"Error downloading model from {display_path}: {error_msg}", err=True)
            path_state.mark_non_shard_error(audit_result)
            return None

    if is_jfrog_url(path):
        display_path = _display_path(path)
        download_spinner = None
        if runtime.show_styled_output and should_show_spinner():
            download_spinner = yaspin(
                Spinners.dots,
                text=f"Downloading and scanning from {style_text(display_path, fg='cyan')}",
            )
            download_spinner.start()
        elif runtime.show_styled_output:
            click.echo(f"Downloading and scanning from {display_path}...")

        try:
            record_download_started("jfrog", path)
            record_feature_used("jfrog_download")
            download_start = time.time()

            jfrog_scan_kwargs: dict[str, Any] = {}
            if runtime.scannable_extensions is not None:
                jfrog_scan_kwargs["scannable_extensions"] = runtime.scannable_extensions
            if runtime.scannable_filenames is not None:
                jfrog_scan_kwargs["scannable_filenames"] = runtime.scannable_filenames
            if runtime.explicit_max_download_bytes is not None:
                jfrog_scan_kwargs["max_download_size"] = runtime.explicit_max_download_bytes
            jfrog_results: ModelAuditResultModel = scan_jfrog_artifact(
                path,
                api_token=runtime.jfrog_api_token,
                access_token=runtime.jfrog_access_token,
                timeout=runtime.timeout,
                blacklist_patterns=list(blacklist) if blacklist else None,
                max_file_size=runtime.max_file_size,
                max_total_size=runtime.max_total_size,
                strict_license=runtime.strict_license,
                skip_file_types=runtime.skip_non_model_files,
                cache_enabled=runtime.cache_enabled,
                cache_dir=runtime.cache_dir,
                selective_download=runtime.selective_download,
                use_hf_whitelist=runtime.use_hf_whitelist,
                **jfrog_scan_kwargs,
                **_scanner_selection_overrides(runtime),
            )

            if download_spinner:
                download_spinner.ok(style_text("✅ Downloaded and scanned", fg="green", bold=True))
            elif runtime.show_styled_output:
                click.echo("Downloaded and scanned successfully")

            path_state.record_non_shard_result_errors(jfrog_results)
            audit_result.aggregate_scan_result(jfrog_results.model_dump())
            record_download_completed("jfrog", time.time() - download_start, jfrog_results.bytes_scanned, path)
            return _SourceDispatchResult(actual_path=path, local_scan_required=False)
        except Exception as exc:
            if download_spinner:
                download_spinner.fail(style_text("❌ Download/scan failed", fg="red", bold=True))
            elif runtime.show_styled_output:
                click.echo("Download/scan failed")

            error_msg = _display_error(exc, path)
            logger.error(f"Failed to download/scan model from {display_path}: {error_msg}")
            click.echo(f"Error downloading/scanning model from {display_path}: {error_msg}", err=True)
            path_state.mark_non_shard_error(audit_result)
            return None

    if not os.path.exists(path):
        click.echo(f"Error: Path does not exist: {_display_path(path)}", err=True)
        path_state.mark_non_shard_error(audit_result)
        return None

    return _SourceDispatchResult(actual_path=path)


class DefaultCommandGroup(click.Group):
    """Custom group that makes 'scan' the default command"""

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """Get command by name, return None if not found"""
        # Simply delegate to parent's get_command - no default logic here
        return click.Group.get_command(self, ctx, cmd_name)

    def resolve_command(  # type: ignore[override]
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """Resolve command, using 'scan' as default when paths are provided"""
        # If we have args and the first arg is not a known command, use 'scan' as default
        if args and args[0] not in self.list_commands(ctx):
            # Insert 'scan' at the beginning
            args = ["scan", *list(args)]

        return super().resolve_command(ctx, args)

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Show help with both commands but emphasize scan as primary"""
        formatter.write_text("ModelAudit - Security scanner for ML model files")
        formatter.write_paragraph()

        formatter.write_text("Usage:")
        with formatter.indentation():
            formatter.write_text("modelaudit [OPTIONS] PATHS...  # Scan files (default command)")
            formatter.write_text("modelaudit scan [OPTIONS] PATHS...  # Explicit scan command")

        formatter.write_paragraph()
        formatter.write_text("Examples:")
        with formatter.indentation():
            formatter.write_text("modelaudit model.pkl")
            formatter.write_text("modelaudit /path/to/models/")
            formatter.write_text("modelaudit https://huggingface.co/user/model")
            formatter.write_text("modelaudit https://pytorch.org/hub/pytorch_vision_resnet/")

        formatter.write_paragraph()
        formatter.write_text("Other commands:")
        with formatter.indentation():
            formatter.write_text("modelaudit doctor       # Diagnose scanner compatibility")
            formatter.write_text("modelaudit cache clear  # Clear scan results cache")
            formatter.write_text("modelaudit cache stats  # Show cache statistics")

        formatter.write_paragraph()
        formatter.write_text("For detailed help on scanning:")
        with formatter.indentation():
            formatter.write_text("modelaudit scan --help")

        formatter.write_paragraph()
        formatter.write_text("Options:")
        self.format_options(ctx, formatter)


@click.group(cls=DefaultCommandGroup)
@click.version_option(__version__)
def cli() -> None:
    """Static scanner for ML models"""


@cli.group()
def auth() -> None:
    """Manage authentication"""


@auth.command()
@click.option("-o", "--org", "org_id", help="The organization id to login to.")
@click.option(
    "-h",
    "--host",
    help=(
        "The API URL of the Promptfoo instance. Custom domains must also be configured through "
        "MODELAUDIT_API_ALLOWED_HOSTS (a comma-separated hostname or URL list), MODELAUDIT_API_HOST, or API_HOST."
    ),
)
@click.option("-k", "--api-key", help="Login using an API key.")
def login(org_id: str | None, host: str | None, api_key: str | None) -> None:
    """Login"""
    import time

    start_time = time.time()
    try:
        token = None
        api_host = host or config.get_api_host()

        # Record telemetry (stub for now)
        # telemetry.record('command_used', {'name': 'auth login'})

        if api_key:
            token = api_key
            result = auth_client.validate_and_set_api_token(token, api_host)
            user = result["user"]

            # Store token in global config and handle email sync
            existing_email = get_user_email()
            if existing_email and existing_email != user.email:
                click.echo(
                    style_text(f"Updating local email configuration from {existing_email} to {user.email}", fg="yellow")
                )
            set_user_email(user.email)
            record_command_used("auth_login", duration=time.time() - start_time, success=True, api_key_login=True)
            click.echo(style_text("Successfully logged in", fg="green"))
            return
        else:
            click.echo(
                f"Please login or sign up at {style_text('https://promptfoo.app', fg='green')} to get an API key."
            )
            click.echo(
                f"After logging in, you can get your api token at "
                f"{style_text('https://promptfoo.app/welcome', fg='green')}"
            )
            record_command_used("auth_login", duration=time.time() - start_time, success=False, api_key_login=False)

        return

    except Exception as error:
        error_message = str(error)
        record_command_used(
            "auth_login",
            duration=time.time() - start_time,
            success=False,
            error_type=type(error).__name__,
        )
        click.echo(f"Authentication failed: {error_message}", err=True)
        sys.exit(1)


@auth.command()
def logout() -> None:
    """Logout"""
    import time

    start_time = time.time()
    email = get_user_email()
    api_key = cloud_config.get_api_key()

    if not email and not api_key:
        record_command_used("auth_logout", duration=time.time() - start_time, success=True, was_logged_in=False)
        click.echo(style_text("You're already logged out - no active session to terminate", fg="yellow"))
        return

    cloud_config.delete()
    # Always unset email on logout
    set_user_email("")
    record_command_used("auth_logout", duration=time.time() - start_time, success=True, was_logged_in=True)
    click.echo(style_text("Successfully logged out", fg="green"))
    return


@auth.command()
def whoami() -> None:
    """Show current user information"""
    import time

    start_time = time.time()
    try:
        email = get_user_email()
        api_key = cloud_config.get_api_key()

        if not email or not api_key:
            record_command_used("auth_whoami", duration=time.time() - start_time, success=False, logged_in=False)
            click.echo(f"Not logged in. Run {style_text('modelaudit auth login', bold=True)} to login.")
            return

        user_info = auth_client.get_user_info()
        user = user_info.get("user", {})
        organization = user_info.get("organization", {})

        click.echo(style_text("Currently logged in as:", fg="green", bold=True))
        click.echo(f"User: {style_text(user.get('email', 'Unknown'), fg='cyan')}")
        click.echo(f"Organization: {style_text(organization.get('name', 'Unknown'), fg='cyan')}")
        click.echo(f"App URL: {style_text(cloud_config.get_app_url(), fg='cyan')}")

        # Record telemetry (stub for now)
        # telemetry.record('command_used', {'name': 'auth whoami'})
        record_command_used("auth_whoami", duration=time.time() - start_time, success=True, logged_in=True)

    except Exception as error:
        error_message = str(error)
        record_command_used(
            "auth_whoami",
            duration=time.time() - start_time,
            success=False,
            error_type=type(error).__name__,
        )
        click.echo(f"Failed to get user info: {error_message}", err=True)
        sys.exit(1)


@cli.group()
def cache() -> None:
    """Manage scan results cache"""


@cache.command()
@click.option("--cache-dir", type=click.Path(), help="Cache directory path [default: ~/.modelaudit/cache/scan_results]")
@click.option("--dry-run", is_flag=True, help="Show what would be cleared without actually clearing")
def clear(cache_dir: str | None, dry_run: bool) -> None:
    """Clear the entire scan results cache"""
    import time

    start_time = time.time()
    from .cache import get_cache_manager

    try:
        cache_manager = get_cache_manager(cache_dir, enabled=True)

        if dry_run:
            stats = cache_manager.get_stats()
            total_entries = stats.get("total_entries", 0)
            total_size_mb = stats.get("total_size_mb", 0.0)

            record_command_used(
                "cache_clear",
                duration=time.time() - start_time,
                success=True,
                dry_run=True,
                entries=total_entries,
            )
            click.echo(f"Would clear {total_entries} cache entries ({total_size_mb:.1f}MB)")
            return

        # Get stats before clearing for reporting
        stats = cache_manager.get_stats()
        total_entries = stats.get("total_entries", 0)
        total_size_mb = stats.get("total_size_mb", 0.0)

        # Clear the cache
        try:
            cache_manager.clear()
            success_msg = f"Cleared {total_entries} cache entries ({total_size_mb:.1f}MB)"
            record_command_used(
                "cache_clear",
                duration=time.time() - start_time,
                success=True,
                dry_run=False,
                entries=total_entries,
            )
            click.echo(style_text(success_msg, fg="green"))
        except PermissionError as e:
            error_msg = f"Permission denied while clearing cache: {e}"
            record_command_used(
                "cache_clear",
                duration=time.time() - start_time,
                success=False,
                dry_run=False,
                error_type=type(e).__name__,
            )
            click.echo(style_text(error_msg, fg="red"), err=True)
            click.echo("Try running with elevated permissions or check cache directory permissions.", err=True)
            sys.exit(1)
        except OSError as e:
            error_msg = f"File system error while clearing cache: {e}"
            record_command_used(
                "cache_clear",
                duration=time.time() - start_time,
                success=False,
                dry_run=False,
                error_type=type(e).__name__,
            )
            click.echo(style_text(error_msg, fg="red"), err=True)
            sys.exit(1)

    except Exception as e:
        error_msg = f"Failed to clear cache: {e}"
        record_command_used(
            "cache_clear",
            duration=time.time() - start_time,
            success=False,
            dry_run=dry_run,
            error_type=type(e).__name__,
        )
        click.echo(style_text(error_msg, fg="red"), err=True)
        sys.exit(1)


@cache.command()
@click.option("--cache-dir", type=click.Path(), help="Cache directory path [default: ~/.modelaudit/cache/scan_results]")
@click.option("--max-age", type=int, default=30, help="Maximum age of entries to keep in days [default: 30]")
@click.option("--dry-run", is_flag=True, help="Show what would be cleaned without actually cleaning")
def cleanup(cache_dir: str | None, max_age: int, dry_run: bool) -> None:
    """Clean up old cache entries"""
    import time

    start_time = time.time()
    from .cache import get_cache_manager

    try:
        cache_manager = get_cache_manager(cache_dir, enabled=True)

        if dry_run:
            # For dry run, we'd need to implement a preview method
            # For now, just show current stats
            stats = cache_manager.get_stats()
            total_entries = stats.get("total_entries", 0)
            total_size_mb = stats.get("total_size_mb", 0.0)

            record_command_used(
                "cache_cleanup",
                duration=time.time() - start_time,
                success=True,
                dry_run=True,
                max_age=max_age,
                entries=total_entries,
            )
            click.echo(f"Would cleanup cache entries older than {max_age} days")
            click.echo(f"Current cache: {total_entries} entries ({total_size_mb:.1f}MB)")
            return

        # Clean up old entries
        removed_count = cache_manager.cleanup(max_age)
        record_command_used(
            "cache_cleanup",
            duration=time.time() - start_time,
            success=True,
            dry_run=False,
            max_age=max_age,
            removed_count=removed_count,
        )

        if removed_count > 0:
            success_msg = f"Removed {removed_count} old cache entries (>{max_age} days old)"
            click.echo(style_text(success_msg, fg="green"))
        else:
            click.echo("No old cache entries found to remove")

    except Exception as e:
        error_msg = f"Failed to cleanup cache: {e}"
        record_command_used(
            "cache_cleanup",
            duration=time.time() - start_time,
            success=False,
            dry_run=dry_run,
            max_age=max_age,
            error_type=type(e).__name__,
        )
        click.echo(style_text(error_msg, fg="red"), err=True)
        sys.exit(1)


@cache.command()
@click.option("--cache-dir", type=click.Path(), help="Cache directory path [default: ~/.modelaudit/cache/scan_results]")
def stats(cache_dir: str | None) -> None:
    """Show cache statistics"""
    import time

    start_time = time.time()
    from .cache import get_cache_manager

    try:
        cache_manager = get_cache_manager(cache_dir, enabled=True)
        stats = cache_manager.get_stats()

        click.echo("Cache Statistics")
        click.echo("=" * 20)

        enabled = stats.get("enabled", False)
        if not enabled:
            record_command_used("cache_stats", duration=time.time() - start_time, success=True, enabled=False)
            click.echo(style_text("Cache is disabled", fg="yellow"))
            return

        total_entries = stats.get("total_entries", 0)
        total_size_mb = stats.get("total_size_mb", 0.0)
        cache_hits = stats.get("cache_hits", 0)
        cache_misses = stats.get("cache_misses", 0)
        hit_rate = stats.get("hit_rate", 0.0)

        click.echo(f"Total entries: {total_entries}")
        click.echo(f"Total size: {total_size_mb:.1f}MB")
        click.echo(f"Cache hits: {cache_hits}")
        click.echo(f"Cache misses: {cache_misses}")
        click.echo(f"Hit rate: {hit_rate:.1%}")

        if total_entries > 0:
            avg_size_kb = (total_size_mb * 1024) / total_entries
            click.echo(f"Average entry size: {avg_size_kb:.1f}KB")

        record_command_used(
            "cache_stats",
            duration=time.time() - start_time,
            success=True,
            enabled=True,
            entries=total_entries,
        )

    except Exception as e:
        error_msg = f"Failed to get cache stats: {e}"
        record_command_used(
            "cache_stats", duration=time.time() - start_time, success=False, error_type=type(e).__name__
        )
        click.echo(style_text(error_msg, fg="red"), err=True)
        sys.exit(1)


@cli.command("delegate-info", hidden=True)
def delegate_info() -> None:
    """Internal command to show delegation status"""

    from .auth.config import config

    is_delegated = config.is_delegated()
    auth_source = config.get_auth_source()
    api_key_available = config.is_authenticated()

    info = {"delegated": is_delegated, "auth_source": auth_source, "api_key_available": api_key_available}

    click.echo(json.dumps(info, indent=2))


@cli.command("scan")
@click.argument("paths", nargs=-1, type=str, required=False)
# Core output control (4 flags)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["text", "json", "sarif"]),
    help="Output format (text, json, or sarif) [default: auto-detected]",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path (prints to stdout if not specified)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Silence detection messages")
# Security behavior (2 flags)
@click.option(
    "--blacklist",
    "-b",
    multiple=True,
    help="Additional blacklist patterns to check against model names",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Strict mode: imply --no-whitelist and --no-cache, scan all file types, strict license validation",
)
@click.option(
    "--no-whitelist",
    is_flag=True,
    help="Disable HuggingFace whitelist severity downgrading",
)
@click.option(
    "--suppress",
    "-s",
    multiple=True,
    help="Suppress specific rule codes (e.g., -s S101). Can be specified multiple times.",
)
@click.option(
    "--severity",
    "-S",
    multiple=True,
    help="Override rule severities, format CODE=LEVEL (e.g., S101=CRITICAL). Can be specified multiple times.",
)
@click.option(
    "--scanners",
    multiple=True,
    help="Only run the selected scanners (comma-separated or repeat the flag). Accepts scanner IDs or class names.",
)
@click.option(
    "--exclude-scanner",
    "exclude_scanners",
    multiple=True,
    help="Exclude scanners from the active scanner set (comma-separated or repeat the flag).",
)
@click.option(
    "--list-scanners",
    is_flag=True,
    help="List registered scanner IDs, class names, extensions, and dependencies, then exit.",
)
# Progress & reporting (2 flags)
@click.option(
    "--progress",
    is_flag=True,
    help="Force enable progress reporting (auto-detected by default)",
)
@click.option(
    "--sbom",
    type=click.Path(),
    help="Write CycloneDX SBOM to the specified file",
)
# Override defaults (2 flags)
@click.option(
    "--timeout",
    "-t",
    type=int,
    help="Override auto-detected timeout in seconds",
)
@click.option(
    "--max-size",
    type=str,
    help="Override auto-detected size limits (e.g., 10GB, 500MB)",
)
# Preview/debugging (2 flags)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Preview what would be scanned/downloaded without actually doing it",
)
@click.option(
    "--no-cache",
    is_flag=True,
    help="Force disable caching (overrides defaults)",
)
@click.option(
    "--cache-dir",
    type=click.Path(),
    help="Cache directory path (overrides default cache location)",
)
@click.option(
    "--stream",
    is_flag=True,
    help="Stream scan: download files one-by-one, scan immediately, then delete to save disk space",
)
@click.option(
    "--assume-shard-family",
    is_flag=True,
    help="Treat explicitly provided cross-directory shard paths as one model family",
)
def scan_command(
    paths: tuple[str, ...],
    format: str | None,
    output: str | None,
    verbose: bool,
    quiet: bool,
    blacklist: tuple[str, ...],
    strict: bool,
    no_whitelist: bool,
    suppress: tuple[str, ...],
    severity: tuple[str, ...],
    scanners: tuple[str, ...],
    exclude_scanners: tuple[str, ...],
    list_scanners: bool,
    progress: bool,
    sbom: str | None,
    timeout: int | None,
    max_size: str | None,
    dry_run: bool,
    no_cache: bool,
    cache_dir: str | None,
    stream: bool,
    assume_shard_family: bool,
) -> None:
    """Scan files, directories, HuggingFace models, MLflow models, cloud storage,
    or JFrog artifacts for security issues.

    Uses defaults based on input type.

    \b
    Examples:
        modelaudit scan model.pkl                    # Local file - fast scan
        modelaudit scan s3://bucket/models/          # Cloud - auto caching + progress
        modelaudit scan hf://user/llama              # HuggingFace - selective download
        modelaudit scan models:/model/v1             # MLflow - registry integration

        # Override defaults when needed
        modelaudit scan large-model.pt --max-size 20GB --timeout 7200

        # Strict mode for security-critical scans
        modelaudit scan model.pkl --strict --format json --output report.json

    \b
    Defaults:
        • Input type (local/cloud/registry) → optimal download & caching
        • File size (>1GB) → large model optimizations + progress bars
        • Terminal type (TTY/CI) → appropriate UI (progress vs quiet)
        • Cloud operations → automatic caching, size limits, timeouts

    \b
    Authentication:
        • JFrog: Set JFROG_API_TOKEN or JFROG_ACCESS_TOKEN environment variables
        • MLflow: Set MLFLOW_TRACKING_URI environment variable

    \b
    Exit codes:
        0 - Success, no security issues found
        1 - Security issues found (scan completed successfully)
        2 - Errors occurred during scanning
    """
    scan_start_time = time.time()
    if list_scanners:
        output_format = format or "text"
        _emit_scanner_catalog(output_format=output_format, output=output)
        record_command_used("scan", duration=time.time() - scan_start_time, list_scanners=True, format=output_format)
        flush_telemetry()
        return

    if not paths:
        click.echo("Error: Missing argument 'PATHS...'.", err=True)
        record_scan_failed(time.time() - scan_start_time, "No paths provided")
        flush_telemetry()
        sys.exit(2)

    # Telemetry options - only include non-sensitive data
    # DO NOT include actual blacklist patterns or file paths - only counts
    telemetry_options = {
        "format": format,
        "timeout": timeout,
        "has_max_file_size": bool(max_size),
        "has_blacklist": bool(blacklist),
        "num_blacklist_patterns": len(blacklist) if blacklist else 0,
        "progress": progress,
        "has_output_file": bool(output),
        "has_sbom": bool(sbom),
        "verbose": verbose,
        "cache_enabled": not no_cache,
        "strict": strict,
        "no_whitelist": no_whitelist,
        "dry_run": dry_run,
        "assume_shard_family": assume_shard_family,
        "has_scanner_selection": bool(scanners or exclude_scanners),
        "num_paths": len(paths),
    }

    try:
        for output_path in dict.fromkeys(path for path in (output, sbom) if path is not None):
            _preflight_output_text_file(output_path)
    except _OutputWriteError:
        record_scan_failed(time.time() - scan_start_time, "Unable to prepare scan output")
        flush_telemetry()
        raise

    record_command_used("scan", duration=None, **telemetry_options)
    record_scan_started(list(paths), telemetry_options)

    expanded_paths = _resolve_scan_paths(paths, scan_start_time)
    runtime = _resolve_scan_runtime_config(
        expanded_paths,
        format=format,
        output=output,
        timeout=timeout,
        max_size=max_size,
        cache_dir=cache_dir,
        progress=progress,
        no_cache=no_cache,
        no_whitelist=no_whitelist,
        stream=stream,
        strict=strict,
        verbose=verbose,
        quiet=quiet,
        scanners=scanners,
        exclude_scanners=exclude_scanners,
        suppress=suppress,
        severity=severity,
        scan_start_time=scan_start_time,
    )
    _show_scan_runtime_defaults(
        runtime,
        expanded_paths,
        blacklist,
        quiet=quiet,
        verbose=verbose,
    )
    _configure_scan_logging(verbose)
    progress_tracker, progress_reporters = _initialize_progress_tracking(
        runtime,
        expanded_paths,
        output=output,
        verbose=verbose,
    )

    # Aggregated results using Pydantic model from the start
    from .models import create_initial_audit_result

    audit_result = create_initial_audit_result()
    if dry_run:
        cast(Any, audit_result).dry_run = True
    if runtime.scanner_selection_metadata is not None:
        audit_result.scanner_selection = dict(runtime.scanner_selection_metadata)
    path_state = _ScanPathState(
        collect_dvc_coverage=any(os.path.isfile(path) and path.lower().endswith(".dvc") for path in expanded_paths),
        explicit_shard_family_groups=_explicit_local_shard_family_groups(paths) if assume_shard_family else {},
    )

    # Scan each path with interrupt handling
    with interruptible_scan() as interrupt_handler:
        for path in expanded_paths:
            source_result = _SourceDispatchResult(actual_path=path)
            should_break = False

            try:
                resolved_source = _resolve_scan_source_for_path(
                    path,
                    audit_result,
                    path_state,
                    runtime,
                    blacklist,
                    verbose=verbose,
                    dry_run=dry_run,
                )
                if resolved_source is None:
                    continue

                source_result = resolved_source
                if source_result.local_scan_required:
                    _scan_local_or_downloaded_path(
                        path,
                        source_result,
                        audit_result,
                        path_state,
                        runtime,
                        progress_tracker,
                        blacklist,
                        verbose=verbose,
                    )

            except Exception as exc:
                display_path = _display_path(path)
                display_error = _display_error(exc, path)
                logger.error(f"Unexpected error processing {display_path}: {display_error}")
                click.echo(f"Unexpected error processing {display_path}: {display_error}", err=True)
                path_state.scanned_paths.append(_display_scan_path(source_result.actual_path))
                path_state.mark_non_shard_error(audit_result)

                if progress_tracker:
                    progress_tracker.report_error(Exception(display_error))

            finally:
                path_state.defer_temp_cleanup(
                    source_result.temp_path,
                    cache_enabled=runtime.cache_enabled,
                    verbose=verbose,
                )

                if interrupt_handler.is_interrupted():
                    logger.debug("Scan interrupted by user")
                    if not any(issue.message == "Scan interrupted by user" for issue in audit_result.issues):
                        from .scanner_results import Issue

                        interruption_issue = Issue(
                            message="Scan interrupted by user",
                            severity=IssueSeverity.INFO,
                            location=None,
                            details={"interrupted": True},
                            timestamp=time.time(),
                            why=None,
                            type=None,
                        )
                        audit_result.issues.append(interruption_issue)
                    should_break = True

            if should_break:
                break

    _complete_progress_tracking(progress_tracker, verbose=verbose)
    _cleanup_progress_reporters(progress_reporters)
    _reconcile_cross_directory_shard_coverage(
        audit_result,
        path_state.validated_shard_targets,
        missing_shard_errors_only=not path_state.has_errors_outside_reconciled_shards,
    )
    audit_result.finalize_statistics()
    audit_result.deduplicate_issues()

    try:
        try:
            _write_scan_sbom(
                sbom,
                audit_result,
                expanded_paths,
                path_state,
                scan_and_delete=runtime.scan_and_delete,
            )
        finally:
            _cleanup_temp_artifacts(path_state.temp_cleanup_entries, verbose=verbose)

        suppressions = _record_suppressed_preferred_scanners(audit_result)
        if suppressions:
            _announce_suppressed_preferred_scanners(suppressions)
        output_text = _format_scan_output(
            audit_result,
            expanded_paths,
            output_format=runtime.output_format,
            verbose=verbose,
        )
        _emit_scan_output(
            output_text,
            audit_result,
            output=output,
            output_format=runtime.output_format,
            verbose=verbose,
        )
    except _OutputWriteError:
        record_scan_failed(time.time() - scan_start_time, "Unable to write scan output")
        flush_telemetry()
        raise

    _record_scan_end_and_exit(audit_result, scan_start_time)


def format_text_output(results: dict[str, Any], verbose: bool = False) -> str:
    """Format scan results as human-readable text with colors"""
    output_lines = []
    has_incomplete_coverage = _results_have_incomplete_coverage(results)

    # Add scan summary header
    output_lines.append(style_text("\n📊 SCAN SUMMARY", fg="white", bold=True))
    output_lines.append("" + "─" * 60)

    # Add scan metrics in a grid format
    metrics = []

    # Scanner info
    if results.get("scanner_names"):
        scanner_names = results["scanner_names"]
        if len(scanner_names) == 1:
            metrics.append(("Scanner", scanner_names[0], "blue"))
        else:
            metrics.append(("Scanners", ", ".join(scanner_names), "blue"))

    # Duration
    if "duration" in results:
        duration = results["duration"]
        duration_str = f"{duration:.3f}s" if duration < 0.01 else f"{duration:.2f}s"
        metrics.append(("Duration", duration_str, "cyan"))

    # Files scanned
    if "files_scanned" in results:
        metrics.append(("Files", str(results["files_scanned"]), "cyan"))

    # Data size
    if "bytes_scanned" in results:
        bytes_scanned = results["bytes_scanned"]
        if bytes_scanned >= 1024 * 1024 * 1024:
            size_str = f"{bytes_scanned / (1024 * 1024 * 1024):.2f} GB"
        elif bytes_scanned >= 1024 * 1024:
            size_str = f"{bytes_scanned / (1024 * 1024):.2f} MB"
        elif bytes_scanned >= 1024:
            size_str = f"{bytes_scanned / 1024:.2f} KB"
        else:
            size_str = f"{bytes_scanned} bytes"
        metrics.append(("Size", size_str, "cyan"))

    # Display metrics in a formatted grid
    for label, value, color in metrics:
        label_str = style_text(f"  {label}:", fg="bright_black")
        value_str = style_text(_escape_terminal_text(value), fg=color, bold=True)
        output_lines.append(f"{label_str} {value_str}")

    # Add authentication status (inspired by semgrep's approach)
    from .scanners import _registry

    available_scanners = _registry.get_available_scanners()
    total_scanners = len(_registry.get_scanner_classes())  # Total possible scanners
    authenticated = config.is_authenticated()

    if authenticated:
        auth_label = style_text("  Promptfoo Cloud:", fg="bright_black")
        auth_value = style_text("Logged in", fg="green", bold=True)
        output_lines.append(f"{auth_label} {auth_value}")
        # Show enhanced scanner count for authenticated users
        scanner_label = style_text("  Enhanced Scanners:", fg="bright_black")
        scanner_value = style_text(f"{len(available_scanners)}/{total_scanners}", fg="green", bold=True)
        output_lines.append(f"{scanner_label} {scanner_value}")
    else:
        auth_label = style_text("  Promptfoo Cloud:", fg="bright_black")
        auth_value = style_text("Not logged in", fg="yellow", bold=True)
        output_lines.append(f"{auth_label} {auth_value}")
        # Show limited scanner info for unauthenticated users
        scanner_label = style_text("  Basic Scanners:", fg="bright_black")
        scanner_value = style_text(f"{len(available_scanners)}/{total_scanners}", fg="yellow", bold=True)
        output_lines.append(f"{scanner_label} {scanner_value}")

        # Add gentle encouragement to login (only if we have failures or limited functionality)
        if len(available_scanners) < total_scanners:
            output_lines.append("")
            tip_icon = "💡"
            tip_text = "Login for enhanced scanning with cloud models and fewer false positives"
            login_cmd = style_text("modelaudit auth login", fg="cyan", bold=True)
            output_lines.append(f"  {tip_icon} {tip_text}")
            output_lines.append(f"     Run {login_cmd} to get started")

    # Add model information if available
    if "file_metadata" in results:
        for _file_path, metadata in results["file_metadata"].items():
            if metadata.get("model_info"):
                model_info = metadata["model_info"]
                output_lines.append("")
                output_lines.append(style_text("  Model Information:", fg="bright_black"))

                if "model_type" in model_info:
                    model_type = _escape_terminal_text(model_info["model_type"])
                    output_lines.append(f"  • Type: {style_text(model_type, fg='cyan')}")
                if "architectures" in model_info:
                    arch_str = (
                        ", ".join(_escape_terminal_text(architecture) for architecture in model_info["architectures"])
                        if isinstance(model_info["architectures"], list)
                        else _escape_terminal_text(model_info["architectures"])
                    )
                    output_lines.append(f"  • Architecture: {style_text(arch_str, fg='cyan')}")
                if "num_layers" in model_info:
                    num_layers = _escape_terminal_text(model_info["num_layers"])
                    output_lines.append(f"  • Layers: {style_text(num_layers, fg='cyan')}")
                if "hidden_size" in model_info:
                    hidden_size = _escape_terminal_text(model_info["hidden_size"])
                    output_lines.append(f"  • Hidden Size: {style_text(hidden_size, fg='cyan')}")
                if "vocab_size" in model_info:
                    vocab_size = model_info["vocab_size"]
                    vocab_str = (
                        f"{vocab_size:,}"
                        if isinstance(vocab_size, (int, float)) and not isinstance(vocab_size, bool)
                        else _escape_terminal_text(vocab_size)
                    )
                    output_lines.append(f"  • Vocab Size: {style_text(vocab_str, fg='cyan')}")
                if "framework_version" in model_info:
                    framework_version = _escape_terminal_text(model_info["framework_version"])
                    output_lines.append(f"  • Framework: {style_text(framework_version, fg='cyan')}")
                break  # Only show the first model info found

    # Add security check statistics
    if "total_checks" in results and results["total_checks"] > 0:
        total = results["total_checks"]
        passed = results.get("passed_checks", 0)
        failed = results.get("failed_checks", 0)
        success_rate = (passed / total * 100) if total > 0 else 0

        output_lines.append("")
        output_lines.append(style_text("  Security Checks:", fg="bright_black"))

        # Show check counts with visual indicator
        check_str = f"  ✅ {passed} passed / "
        if failed > 0:
            check_str += style_text(f"❌ {failed} failed", fg="red")
        else:
            check_str += style_text(f"✅ {failed} failed", fg="green")
        check_str += f" (Total: {total})"
        output_lines.append(check_str)

        # Show success rate with color coding
        if success_rate >= 95:
            rate_color = "green"
            rate_icon = "✅"
        elif success_rate >= 80:
            rate_color = "yellow"
            rate_icon = "⚠️"
        else:
            rate_color = "red"
            rate_icon = "🚨"

        rate_str = style_text(f"  {rate_icon} Success Rate: {success_rate:.1f}%", fg=rate_color, bold=True)
        output_lines.append(rate_str)

    # Show failed checks if any exist
    failed_checks_list = [c for c in results.get("checks", []) if c.get("status") == "failed"]
    if failed_checks_list:
        output_lines.append("")
        output_lines.append(style_text("  Failed Checks (non-critical):", fg="yellow"))
        # Group failed checks by name to avoid repetition
        check_groups: dict[str, list[str]] = {}
        for check in failed_checks_list:
            check_name = _escape_terminal_text(check.get("name", "Unknown check"))
            if check_name not in check_groups:
                check_groups[check_name] = []
            check_groups[check_name].append(_escape_terminal_text(check.get("message", "")))

        # Show unique failed check types
        for check_name, messages in list(check_groups.items())[:5]:  # Show first 5 types
            unique_msg = messages[0] if messages else ""
            if len(messages) > 1:
                output_lines.append(f"    • {check_name} ({len(messages)} occurrences)")
            else:
                output_lines.append(f"    • {check_name}: {unique_msg}")
        if len(check_groups) > 5:
            output_lines.append(f"    ... and {len(check_groups) - 5} more check types")

    if has_incomplete_coverage:
        incomplete_summaries = _incomplete_coverage_summaries(results)
        output_lines.append("")
        output_lines.append(style_text("  Scan Coverage:", fg="bright_black"))
        output_lines.append(
            "  " + style_text("⚠️  Incomplete security coverage", fg="yellow", bold=True),
        )
        for file_path, reason in incomplete_summaries[:5]:
            output_lines.append(f"    • {_escape_terminal_text(file_path)}: {_escape_terminal_text(reason)}")
        incomplete_count = len(incomplete_summaries)
        if incomplete_count > 5:
            output_lines.append(f"    ... and {incomplete_count - 5} more incomplete files")

    # Add issue summary
    issues = results.get("issues", [])
    # Filter out DEBUG severity issues when not in verbose mode
    visible_issues = [issue for issue in issues if verbose or _get_issue_attr(issue, "severity") != "debug"]

    # Count issues by severity
    severity_counts = {
        "critical": 0,
        "warning": 0,
        "info": 0,
        "debug": 0,
    }

    for issue in issues:
        severity = _get_issue_attr(issue, "severity", "warning")
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Display issue summary
    output_lines.append("")
    output_lines.append(style_text("\n🔍 SECURITY FINDINGS", fg="white", bold=True))
    output_lines.append("" + "─" * 60)

    if visible_issues:
        # Show issue counts with icons
        summary_parts = []
        if severity_counts["critical"] > 0:
            summary_parts.append(
                "  "
                + style_text(
                    f"🚨 {severity_counts['critical']} Critical",
                    fg="red",
                    bold=True,
                ),
            )
        if severity_counts["warning"] > 0:
            summary_parts.append(
                "  "
                + style_text(
                    f"⚠️  {severity_counts['warning']} Warning{'s' if severity_counts['warning'] > 1 else ''}",
                    fg="yellow",
                ),
            )
        if severity_counts["info"] > 0:
            summary_parts.append(
                "  " + style_text(f"[i] {severity_counts['info']} Info", fg="blue"),
            )
        if verbose and severity_counts["debug"] > 0:
            summary_parts.append(
                "  " + style_text(f"🐛 {severity_counts['debug']} Debug", fg="cyan"),
            )

        output_lines.extend(summary_parts)

        # Group issues by severity for better organization
        output_lines.append("")

        # Display critical issues first
        critical_issues = [issue for issue in visible_issues if _get_issue_attr(issue, "severity") == "critical"]
        if critical_issues:
            output_lines.append(
                style_text("  🚨 Critical Issues", fg="red", bold=True),
            )
            output_lines.append("  " + "─" * 40)
            for issue in critical_issues:
                _format_issue(issue, output_lines, "critical")
                output_lines.append("")

        # Display warnings
        warning_issues = [issue for issue in visible_issues if _get_issue_attr(issue, "severity") == "warning"]
        if warning_issues:
            if critical_issues:
                output_lines.append("")
            output_lines.append(style_text("  ⚠️  Warnings", fg="yellow", bold=True))
            output_lines.append("  " + "─" * 40)
            for issue in warning_issues:
                _format_issue(issue, output_lines, "warning")
                output_lines.append("")

        # Display info issues
        info_issues = [issue for issue in visible_issues if _get_issue_attr(issue, "severity") == "info"]
        if info_issues:
            if critical_issues or warning_issues:
                output_lines.append("")
            output_lines.append(style_text("  [i] Information", fg="blue", bold=True))
            output_lines.append("  " + "─" * 40)
            for issue in info_issues:
                _format_issue(issue, output_lines, "info")
                output_lines.append("")

        # Display debug issues if verbose
        if verbose:
            debug_issues = [issue for issue in visible_issues if _get_issue_attr(issue, "severity") == "debug"]
            if debug_issues:
                if critical_issues or warning_issues or info_issues:
                    output_lines.append("")
                output_lines.append(style_text("  🐛 Debug", fg="cyan", bold=True))
                output_lines.append("  " + "─" * 40)
                for issue in debug_issues:
                    _format_issue(issue, output_lines, "debug")
                    output_lines.append("")
    else:
        # Check if no files were scanned to show appropriate message
        files_scanned = results.get("files_scanned", 0)
        if results.get("dry_run"):
            output_lines.append(
                "  " + style_text("✅ Dry-run preview complete; no files were scanned", fg="green", bold=True),
            )
        elif files_scanned == 0:
            output_lines.append(
                "  " + style_text("⚠️  No model files found to scan", fg="yellow", bold=True),
            )
        elif has_incomplete_coverage:
            output_lines.append(
                "  " + style_text("⚠️  Security coverage incomplete", fg="yellow", bold=True),
            )
        else:
            output_lines.append(
                "  " + style_text("✅ No security issues detected", fg="green", bold=True),
            )
        output_lines.append("")

    # Add a footer with final status
    output_lines.append("")
    output_lines.append("═" * 80)

    # Check if scan had operational errors first (highest priority in exit code)
    has_operational_errors = bool(results.get("has_errors"))
    has_acquisition_errors = _results_have_acquisition_error_metadata(results)
    has_blocked_acquisition = _results_have_blocked_acquisition_metadata(results)
    files_scanned = results.get("files_scanned", 0)
    is_dry_run = bool(results.get("dry_run"))
    has_critical_findings = any(_get_issue_attr(issue, "severity") == "critical" for issue in visible_issues)
    has_warning_findings = any(_get_issue_attr(issue, "severity") == "warning" for issue in visible_issues)
    has_security_findings = has_critical_findings or has_warning_findings
    if has_operational_errors:
        status_icon = "❌"
        if has_acquisition_errors:
            status_msg = "MODEL ACQUISITION BLOCKED" if has_blocked_acquisition else "MODEL ACQUISITION FAILED"
        else:
            status_msg = "SCAN COMPLETED WITH OPERATIONAL ERRORS"
        status_color = "red"
        output_lines.append(f"  {style_text(f'{status_icon} {status_msg}', fg=status_color, bold=True)}")
        if has_acquisition_errors:
            guidance = (
                "No model artifacts were scanned for blocked Hugging Face source(s)."
                if has_blocked_acquisition
                else "No model artifacts were scanned for failed Hugging Face source(s)."
            )
        else:
            guidance = "Review warnings above and use --verbose for troubleshooting details."
        output_lines.append(f"  {style_text(guidance, fg='yellow')}")
    # Determine overall status
    elif has_security_findings:
        if has_critical_findings:
            status_icon = "❌"
            status_msg = "CRITICAL SECURITY ISSUES FOUND"
            status_color = "red"
        elif has_warning_findings:
            status_icon = "⚠️"
            status_msg = "WARNINGS DETECTED"
            status_color = "yellow"
        if has_incomplete_coverage:
            status_msg += "; COVERAGE INCOMPLETE"
        status_line = style_text(f"{status_icon} {status_msg}", fg=status_color, bold=True)
        output_lines.append(f"  {status_line}")
    elif is_dry_run:
        output_lines.append(f"  {style_text('✅ DRY RUN PREVIEW COMPLETE', fg='green', bold=True)}")
    # Check if no files were scanned
    elif files_scanned == 0:
        status_icon = "❌"
        status_msg = "NO FILES SCANNED"
        status_color = "red"
        output_lines.append(f"  {style_text(f'{status_icon} {status_msg}', fg=status_color, bold=True)}")
        output_lines.append(
            f"  {style_text('Warning: No model files were found at the specified location.', fg='yellow')}"
        )
    elif has_incomplete_coverage:
        status_icon = "⚠️"
        status_msg = "SCAN COVERAGE INCOMPLETE"
        status_color = "yellow"
        output_lines.append(f"  {style_text(f'{status_icon} {status_msg}', fg=status_color, bold=True)}")
        output_lines.append(f"  {style_text('Some selected files could not be fully analyzed.', fg='yellow')}")
    elif visible_issues:
        if has_critical_findings:
            status_icon = "❌"
            status_msg = "CRITICAL SECURITY ISSUES FOUND"
            status_color = "red"
        elif has_warning_findings:
            status_icon = "⚠️"
            status_msg = "WARNINGS DETECTED"
            status_color = "yellow"
        else:
            # Only info/debug issues
            status_icon = "[i]"
            status_msg = "INFORMATIONAL FINDINGS"
            status_color = "blue"
        status_line = style_text(f"{status_icon} {status_msg}", fg=status_color, bold=True)
        output_lines.append(f"  {status_line}")
    else:
        status_icon = "✅"
        status_msg = "NO ISSUES FOUND"
        status_color = "green"
        status_line = style_text(f"{status_icon} {status_msg}", fg=status_color, bold=True)
        output_lines.append(f"  {status_line}")

    output_lines.append("═" * 80)

    # Add encouragement message for unauthenticated users after successful scans
    # (similar to promptfoo's approach)
    if not config.is_authenticated() and not visible_issues:
        output_lines.append("")
        encouragement_msg = "» Want enhanced scanning with cloud models and team sharing?"
        signup_link = style_text("https://promptfoo.app", fg="green", bold=True)
        encouragement_line = f"  {encouragement_msg} Sign up at {signup_link}"
        output_lines.append(encouragement_line)

    return "\n".join(output_lines)


def _results_have_incomplete_coverage(results: dict[str, Any]) -> bool:
    return bool(_incomplete_coverage_summaries(results))


def _incomplete_coverage_summaries(results: dict[str, Any]) -> list[tuple[str, str]]:
    summaries: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    file_metadata = results.get("file_metadata")
    if isinstance(file_metadata, dict):
        for file_path, metadata in file_metadata.items():
            if metadata_has_incomplete_coverage(metadata):
                _append_incomplete_coverage_summary(
                    summaries,
                    seen,
                    str(file_path),
                    _incomplete_coverage_reason(metadata),
                )

    for collection_name in ("issues", "checks"):
        records = results.get(collection_name)
        if not isinstance(records, list):
            continue
        fallback_location = collection_name[:-1]
        for record in records:
            details = _get_issue_attr(record, "details", {})
            if not details_have_incomplete_coverage(details):
                continue
            location = (
                _get_issue_attr(record, "location")
                or _get_issue_attr(record, "name")
                or _get_issue_attr(record, "type")
                or fallback_location
            )
            _append_incomplete_coverage_summary(
                summaries,
                seen,
                str(location),
                _incomplete_coverage_reason(details),
            )

    return summaries


def _append_incomplete_coverage_summary(
    summaries: list[tuple[str, str]],
    seen: set[tuple[str, str]],
    location: str,
    reason: str,
) -> None:
    summary = (location, reason)
    if summary in seen:
        return
    seen.add(summary)
    summaries.append(summary)


def _incomplete_coverage_reason(metadata: Any, *, _depth: int = 0) -> str:
    if not isinstance(metadata, dict):
        return "incomplete coverage"

    reason = metadata.get("scan_outcome_reason")
    if isinstance(reason, str) and reason:
        return reason

    reason = metadata.get("reason")
    if isinstance(reason, str) and reason:
        return reason

    reason = metadata.get("incomplete_reason")
    if isinstance(reason, str) and reason:
        return reason

    reasons = metadata.get("scan_outcome_reasons")
    if isinstance(reasons, str) and reasons:
        return reasons
    if isinstance(reasons, (list, tuple, set, frozenset)):
        joined_reasons = ", ".join(str(reason) for reason in reasons if reason)
        if joined_reasons:
            return joined_reasons

    if metadata.get("analysis_incomplete") is True:
        return "analysis_incomplete"
    if metadata.get("scan_outcome") == "inconclusive":
        return "inconclusive"

    if _depth < 4:
        findings = metadata.get("findings")
        if isinstance(findings, dict) and details_have_incomplete_coverage(findings):
            return _incomplete_coverage_reason(findings, _depth=_depth + 1)
        if isinstance(findings, (list, tuple, set, frozenset)):
            for finding in findings:
                if details_have_incomplete_coverage(finding):
                    return _incomplete_coverage_reason(finding, _depth=_depth + 1)

    return "incomplete coverage"


def _get_issue_attr(issue: dict[str, Any] | Any, attr: str, default: Any = None) -> Any:
    """Safely get an attribute from an issue whether it's a dict or Pydantic object."""
    if isinstance(issue, dict):
        return issue.get(attr, default)
    else:
        # Assume it's a Pydantic object
        return getattr(issue, attr, default)


def _format_issue(
    issue: dict[str, Any] | Any,
    output_lines: list[str],
    severity: str,
) -> None:
    """Format a single issue with proper indentation and styling"""
    message = _escape_terminal_text(_get_issue_attr(issue, "message", "Unknown issue"))
    location = _escape_terminal_text(_get_issue_attr(issue, "location", ""))

    # Icon based on severity
    icons = {
        "critical": "    └─ 🚨",
        "warning": "    └─ ⚠️ ",
        "info": "    └─ [i] ",
        "debug": "    └─ 🐛",
    }

    # Build the issue line
    icon = icons.get(severity, "    └─ ")

    if location:
        location_str = style_text(f"[{location}]", fg="cyan", bold=True)
        output_lines.append(f"{icon} {location_str}")
        output_lines.append(f"       {style_text(message, fg='bright_white')}")
    else:
        output_lines.append(f"{icon} {style_text(message, fg='bright_white')}")

    # Add "Why" explanation if available
    why = _get_issue_attr(issue, "why")
    if why:
        why_label = style_text("Why:", fg="magenta", bold=True)
        why_text = _escape_terminal_text(why)
        # Wrap long explanations
        import textwrap

        wrapped_why = textwrap.fill(
            why_text,
            width=65,
            initial_indent="",
            subsequent_indent="           ",
        )
        output_lines.append(f"       {why_label} {wrapped_why}")

    # Add details if available
    details = _get_issue_attr(issue, "details", {})
    if details:
        for key, value in details.items():
            if value:  # Only show non-empty values
                detail_label = style_text(f"{_escape_terminal_text(key)}:", fg="bright_black")
                detail_value = style_text(_escape_terminal_text(value), fg="bright_white")
                output_lines.append(f"       {detail_label} {detail_value}")


def _display_failure_details(summary: dict[str, Any]) -> None:
    """Display categorized failure information from scanner summary."""
    # Show dependency errors with install commands
    if summary["dependency_errors"]:
        click.echo("\nMissing Dependencies:")
        for scanner_id, info in summary["dependency_errors"].items():
            click.secho(f"  ❌ {scanner_id}", fg="red")
            click.echo(f"     Dependencies: {', '.join(info['dependencies'])}")
            click.echo(f"     Install: {info['install_command']}")

    # Show NumPy compatibility errors separately
    if summary["numpy_errors"]:
        click.echo("\nNumPy Compatibility Issues:")
        for scanner_id, error in summary["numpy_errors"].items():
            click.secho(f"  ⚠️  {scanner_id}", fg="yellow")
            click.echo(f"     {error}")

    # Show other errors
    other_errors = {
        k: v
        for k, v in summary["failed_scanner_details"].items()
        if k not in summary["dependency_errors"] and k not in summary["numpy_errors"]
    }
    if other_errors:
        click.echo("\nOther Issues:")
        for scanner_id, error_msg in other_errors.items():
            click.secho(f"  ❌ {scanner_id}", fg="red")
            click.echo(f"     {error_msg}")


@cli.command("metadata")
@click.argument("path", type=click.Path(exists=True, readable=True, dir_okay=True, file_okay=True))
@click.option(
    "--format", "output_format", type=click.Choice(["json", "yaml", "table"]), default="table", help="Output format"
)
@click.option("--output", type=click.Path(), help="Output file path")
@click.option("--security-only", is_flag=True, help="Show only security-relevant metadata")
@click.option(
    "--trust-loaders",
    is_flag=True,
    help="Allow metadata extraction to deserialize models (unsafe on untrusted inputs; defaults to off)",
)
def metadata(path: str, output_format: str, output: str | None, security_only: bool, trust_loaders: bool) -> None:
    """Extract and display model metadata."""
    import time

    start_time = time.time()
    from .metadata_extractor import ModelMetadataExtractor

    try:
        extractor = ModelMetadataExtractor()
        metadata = extractor.extract(path, security_only=security_only, allow_deserialization=trust_loaders)

        if output_format == "json":
            output_text = json.dumps(metadata, indent=2)
        elif output_format == "yaml":
            try:
                import yaml

                output_text = yaml.dump(metadata, default_flow_style=False, sort_keys=False)
            except ImportError:
                click.secho("Warning: PyYAML not installed, falling back to JSON", fg="yellow")
                output_text = json.dumps(metadata, indent=2)
        else:  # table format
            output_text = _format_metadata_table(metadata)

        if output:
            _write_output_text_file(output, output_text)
            click.secho(f"Metadata written to {_display_path(output)}", fg="green")
        else:
            click.echo(output_text)

        record_command_used(
            "metadata",
            duration=time.time() - start_time,
            success=True,
            format=output_format,
            security_only=security_only,
            trust_loaders=trust_loaders,
            output_file=bool(output),
        )

    except _OutputWriteError as e:
        record_command_used(
            "metadata",
            duration=time.time() - start_time,
            success=False,
            format=output_format,
            error_type=type(e).__name__,
        )
        raise
    except Exception as e:
        record_command_used(
            "metadata",
            duration=time.time() - start_time,
            success=False,
            format=output_format,
            error_type=type(e).__name__,
        )
        click.secho(f"Error extracting metadata: {_display_error(e, path)}", fg="red")
        sys.exit(1)


def _format_metadata_table(metadata: dict[str, Any]) -> str:
    """Format metadata as a readable table."""
    output = []

    if "directory" in metadata:
        # Directory summary
        output.append(f"Directory: {_escape_terminal_text(metadata['directory'])}")
        output.append(f"Total Files: {_escape_terminal_text(metadata['summary']['total_files'])}")
        if metadata.get("analysis_incomplete"):
            output.append("\nWarning: Metadata extraction is incomplete")
            for event in metadata.get("budget_events", []):
                output.append(f"  Budget exceeded: {_escape_terminal_text(event.get('limit', 'unknown'))}")
        output.append("\nFormats:")
        for fmt, count in metadata["summary"]["formats"].items():
            output.append(f"  {_escape_terminal_text(fmt)}: {_escape_terminal_text(count)}")
        output.append("\nFiles:")
        for file_meta in metadata["files"][:10]:  # Show first 10 files
            file_name = _escape_terminal_text(file_meta.get("file", "unknown"))
            if error := file_meta.get("error"):
                output.append(f"  {file_name} (error: {_escape_terminal_text(error)})")
            else:
                file_format = _escape_terminal_text(file_meta.get("format", "unknown"))
                output.append(f"  {file_name} ({file_format})")
                for key in (
                    "has_custom_metadata",
                    "custom_metadata_entry_count",
                    "custom_metadata_valid",
                    "custom_metadata_type",
                    "custom_metadata_invalid_value_count",
                    "custom_metadata_security_flags",
                ):
                    if key not in file_meta:
                        continue
                    value = file_meta[key]
                    if isinstance(value, list):
                        value = ", ".join(_escape_terminal_text(item) for item in value) if value else "none"
                    output.append(f"    {key.replace('_', ' ').title()}: {_escape_terminal_text(value)}")
        if len(metadata["files"]) > 10:
            output.append(f"  ... and {len(metadata['files']) - 10} more")
    else:
        # Single file
        output.append(f"File: {_escape_terminal_text(metadata.get('file', 'unknown'))}")
        output.append(f"Format: {_escape_terminal_text(metadata.get('format', 'unknown'))}")
        file_size = metadata.get("file_size", 0)
        size_text = (
            f"{file_size:,}"
            if isinstance(file_size, (int, float)) and not isinstance(file_size, bool)
            else _escape_terminal_text(file_size)
        )
        output.append(f"Size: {size_text} bytes")

        # Show key metadata fields
        for key, value in metadata.items():
            if key not in ["file", "path", "format", "file_size"]:
                label = _escape_terminal_text(str(key).replace("_", " ").title())
                if isinstance(value, str | int | float | bool):
                    output.append(f"{label}: {_escape_terminal_text(value)}")
                elif isinstance(value, dict) and len(value) <= 5:
                    output.append(f"{label}:")
                    for k, v in value.items():
                        output.append(f"  {_escape_terminal_text(k)}: {_escape_terminal_text(v)}")
                elif isinstance(value, list) and len(value) <= 10:
                    values = ", ".join(_escape_terminal_text(item) for item in value)
                    output.append(f"{label}: {values}")

    return "\n".join(output)


@cli.command()
@click.option(
    "--show-failed",
    is_flag=True,
    help="Show detailed information about failed scanners",
)
def doctor(show_failed: bool) -> None:
    """Diagnose scanner availability and dependencies"""
    import sys
    import time

    from .scanners import _registry

    start_time = time.time()
    click.echo("ModelAudit Scanner Diagnostic Report")
    click.echo("=" * 40)

    # System information
    click.echo(f"Python version: {sys.version.split()[0]}")

    # NumPy status
    numpy_compatible, numpy_status = _registry.get_numpy_status()
    numpy_color = "green" if numpy_compatible else "yellow"
    click.echo("NumPy status: ", nl=False)
    click.secho(numpy_status, fg=numpy_color)

    # Get comprehensive summary
    summary = _registry.get_available_scanners_summary()

    click.echo(f"\nTotal scanners: {summary['total_scanners']}")
    click.echo(f"Loaded successfully: {summary['loaded_scanners']}")
    click.echo(f"Failed to load: {summary['failed_scanners']}")

    # Show success rate with color coding
    success_rate = summary.get("success_rate", 0.0)
    if success_rate < 100.0:
        if success_rate >= 80.0:
            rate_color = "yellow"
        elif success_rate >= 60.0:
            rate_color = "red"
        else:
            rate_color = "bright_red"
        click.echo("Success rate: ", nl=False)
        click.secho(f"{success_rate}%", fg=rate_color)

    # Show detailed failure information if requested
    if show_failed and summary["failed_scanners"] > 0:
        _display_failure_details(summary)

    if summary["loaded_scanner_list"]:
        click.echo("\n" + style_text("Available Scanners:", fg="green"))
        for scanner in summary["loaded_scanner_list"]:
            click.echo(f"  ✅ {scanner}")

    # Enhanced recommendations
    if summary["failed_scanners"] > 0:
        click.echo("\n" + style_text("Recommendations:", fg="blue"))

        # Check for NumPy compatibility issues
        if summary.get("numpy_errors"):
            click.echo("• NumPy compatibility issues detected:")
            click.echo("  For NumPy 1.x compatibility: pip install 'numpy<2.0'")
            click.echo("  Then reinstall ML frameworks: pip install --force-reinstall tensorflow torch h5py")

        # Aggregate missing dependencies with grouped installation command
        all_missing_deps = set()
        for dep_info in summary.get("dependency_errors", {}).values():
            all_missing_deps.update(dep_info.get("dependencies", []))

        if all_missing_deps:
            click.echo(f"• Install missing dependencies: pip install modelaudit[{','.join(sorted(all_missing_deps))}]")

        click.echo("• Core functionality works even with missing optional dependencies")
        click.echo("• Run 'modelaudit doctor --show-failed' for detailed error messages")
    else:
        click.secho("\n✓ All scanners loaded successfully!", fg="green")

    record_command_used(
        "doctor",
        duration=time.time() - start_time,
        success=True,
        show_failed=show_failed,
        failed_scanners=summary["failed_scanners"],
    )


def display_rules(rules: dict[str, Rule], output_format: str) -> None:
    """Display rules in requested format."""
    if output_format == "json":
        rules_list = [
            {
                "code": code,
                "name": rule.name,
                "severity": rule.default_severity.value,
                "description": rule.description,
            }
            for code, rule in sorted(rules.items())
        ]
        click.echo(json.dumps(rules_list, indent=2))
    else:
        click.echo(style_text("Code   Severity   Name", bold=True))
        click.echo(style_text("----   --------   ----", bold=True))
        for code, rule in sorted(rules.items()):
            severity_text = style_text(rule.default_severity.value, fg=get_severity_color(rule.default_severity.value))
            click.echo(f"{code:<6} {severity_text:<10} {rule.name}")


@cli.command("rules")
@click.argument("rule_code", required=False)
@click.option("--list", "list_rules", is_flag=True, help="List all rules")
@click.option("--category", help="Show rules in a category range (e.g., 100-199)")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def rules_command(rule_code: str | None, list_rules: bool, category: str | None, output_format: str) -> None:
    """View and explain security rules."""
    RuleRegistry.initialize()

    if rule_code:
        rule = RuleRegistry.get_rule(rule_code.upper())
        if not rule:
            click.echo(f"Rule {rule_code} not found", err=True)
            sys.exit(1)

        if output_format == "json":
            click.echo(
                json.dumps(
                    {
                        "code": rule.code,
                        "name": rule.name,
                        "severity": rule.default_severity.value,
                        "description": rule.description,
                    },
                    indent=2,
                )
            )
        else:
            click.echo(f"Code: {style_text(rule.code, bold=True)}")
            click.echo(f"Name: {rule.name}")
            severity_text = style_text(rule.default_severity.value, fg=get_severity_color(rule.default_severity.value))
            click.echo(f"Default Severity: {severity_text}")
            click.echo(f"Description: {rule.description}")
    elif category:
        try:
            if "-" in category:
                start_str, end_str = category.split("-")
                start = int(start_str)
                end = int(end_str)
            else:
                start = int(category)
                end = start + 99

            rules = RuleRegistry.get_rules_by_range(start, end)
            if not rules:
                click.echo(f"No rules found in range S{start}-S{end}", err=True)
                sys.exit(1)

            display_rules(rules, output_format)
        except ValueError:
            click.echo(f"Invalid category format: {category}", err=True)
            sys.exit(1)
    else:
        rules = RuleRegistry.get_all_rules()
        display_rules(rules, output_format)


def _get_platform_info() -> dict[str, Any]:
    """Get platform information for debug output."""
    import platform

    return {
        "os": sys.platform,
        "release": platform.release(),
        "arch": platform.machine(),
        "pythonVersion": platform.python_version(),
        "pythonExecutable": sys.executable,
        "pythonRecursionLimit": sys.getrecursionlimit(),
    }


def _get_install_info() -> dict[str, Any]:
    """Get ModelAudit installation information for debug output."""
    from importlib.metadata import PackageNotFoundError

    info: dict[str, Any] = {}

    # Check if editable install
    try:
        from importlib.metadata import distribution

        dist = distribution("modelaudit")

        # Get install location using public API (locate_file returns install root)
        with contextlib.suppress(Exception):
            install_root = dist.locate_file("")
            install_path = str(install_root)
            home = str(Path.home())
            if install_path.startswith(home):
                install_path = "~" + install_path[len(home) :]
            info["location"] = install_path

        # Check for editable install via direct_url.json
        direct_url_text = dist.read_text("direct_url.json")
        if direct_url_text:
            direct_url = json.loads(direct_url_text)
            if direct_url.get("dir_info", {}).get("editable", False):
                info["editable"] = True
            else:
                info["editable"] = False
        else:
            info["editable"] = False

    except PackageNotFoundError:
        info["editable"] = None
        info["location"] = "not installed as package"
    except Exception:
        info["editable"] = None

    return info


def _redact_proxy_url(proxy_url: str | None) -> str | None:
    """Redact credentials from proxy URLs while preserving host/port for debugging.

    Proxy URLs often contain credentials (http://user:pass@host:port).
    Since debug output is meant to be pasted in bug reports, we must redact
    the credentials while keeping the scheme/host/port for troubleshooting.
    """
    if not proxy_url:
        return None
    try:
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(proxy_url)
        if parts.username or parts.password:
            # Rebuild URL without credentials
            netloc = parts.hostname or ""
            if parts.port:
                netloc += f":{parts.port}"
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        # If parsing fails, return a safe indicator rather than the raw URL
        return "<proxy configured>"
    return proxy_url


def _get_env_info() -> dict[str, Any]:
    """Get environment variable information for debug output."""
    from .telemetry import is_telemetry_enabled

    return {
        "telemetryDisabled": not is_telemetry_enabled(),
        "noColor": bool(os.getenv("NO_COLOR")),
        "ciEnvironment": bool(os.getenv("CI")),
        "jfrogConfigured": bool(os.getenv("JFROG_API_TOKEN") or os.getenv("JFROG_ACCESS_TOKEN")),
        "mlflowConfigured": bool(os.getenv("MLFLOW_TRACKING_URI")),
        "httpProxy": _redact_proxy_url(os.getenv("HTTP_PROXY") or os.getenv("http_proxy")),
        "httpsProxy": _redact_proxy_url(os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")),
        "noProxy": os.getenv("NO_PROXY") or os.getenv("no_proxy") or None,
    }


def _get_dependency_versions() -> dict[str, Any]:
    """Get versions of key dependencies for debug output.

    Uses importlib.metadata to get versions WITHOUT importing modules.
    This avoids mutex/threading issues from ML framework initialization.
    """
    from importlib.metadata import PackageNotFoundError, version

    def _get_version(package_name: str) -> str | None:
        """Get package version from metadata without importing the module."""
        try:
            return version(package_name)
        except PackageNotFoundError:
            return None
        except Exception:
            return None

    # Core dependencies (should always be installed)
    core = {
        "click": _get_version("click"),
        "pyyaml": _get_version("pyyaml"),
        "requests": _get_version("requests"),
        "platformdirs": _get_version("platformdirs"),
    }

    # ML framework dependencies (optional, scanner-specific)
    ml_frameworks = {
        "numpy": _get_version("numpy"),
        "torch": _get_version("torch"),
        "tensorflow": _get_version("tensorflow"),
        "onnx": _get_version("onnx"),
        "jax": _get_version("jax"),
        "flax": _get_version("flax"),
    }

    # Format/serialization dependencies (optional)
    serialization = {
        "h5py": _get_version("h5py"),
        "safetensors": _get_version("safetensors"),
        "msgpack": _get_version("msgpack"),
        "joblib": _get_version("joblib"),
    }

    # Utility dependencies (optional)
    utilities = {
        "huggingface_hub": _get_version("huggingface-hub"),
        "posthog": _get_version("posthog"),
        "jinja2": _get_version("jinja2"),
        "py7zr": _get_version("py7zr"),
        "xgboost": _get_version("xgboost"),
    }

    # Filter out None values for cleaner output
    def filter_installed(deps: dict[str, str | None]) -> dict[str, str]:
        return {k: v for k, v in deps.items() if v is not None}

    result: dict[str, Any] = {
        "core": filter_installed(core),
        "mlFrameworks": filter_installed(ml_frameworks),
        "serialization": filter_installed(serialization),
        "utilities": filter_installed(utilities),
    }

    return result


def _get_auth_info() -> dict[str, Any]:
    """Get authentication information for debug output."""
    return {
        "authenticated": config.is_authenticated(),
        "authSource": config.get_auth_source() if config.is_authenticated() else None,
        "delegatedFromPromptfoo": is_delegated_from_promptfoo(),
    }


def _get_scanner_info(verbose: bool = False) -> dict[str, Any]:
    """Get scanner information for debug output."""
    from .scanners import _registry

    summary = _registry.get_available_scanners_summary()

    info: dict[str, Any] = {
        "total": summary["total_scanners"],
        "available": summary["loaded_scanners"],
        "failed": summary["failed_scanners"],
        "successRate": summary["success_rate"],
        "availableList": summary.get("loaded_scanner_list", []),
    }

    # Only include failure details if there are failures
    if summary["failed_scanners"] > 0:
        info["failedList"] = list(summary["failed_scanner_details"].keys())

        if verbose:
            info["failedDetails"] = summary["failed_scanner_details"]
            if summary["dependency_errors"]:
                info["dependencyErrors"] = summary["dependency_errors"]
            if summary["numpy_errors"]:
                info["numpyErrors"] = summary["numpy_errors"]

    return info


def _sanitize_debug_path(path: str) -> str:
    """Sanitize filesystem paths for debug output."""
    home = str(Path.home())
    if path.startswith(home):
        return "~" + path[len(home) :]
    if os.path.isabs(path):
        return "<outside-home path redacted>"
    return path


def _get_cache_info() -> dict[str, Any]:
    """Get cache information for debug output."""
    try:
        from .cache import get_cache_manager

        cache_manager = get_cache_manager(enabled=True)
        stats = cache_manager.get_stats()

        # Get cache directory path with ~ expansion for privacy
        cache_dir_path: str | None = None
        if cache_manager.cache is not None:
            cache_dir_path = _sanitize_debug_path(str(cache_manager.cache.cache_dir))

        return {
            "enabled": True,
            "directory": cache_dir_path,
            "entries": stats.get("total_entries", 0),
            "sizeMb": round(stats.get("total_size_mb", 0.0), 2),
            "hitRate": round(stats.get("hit_rate", 0.0), 4),
        }
    except Exception as e:
        return {
            "enabled": False,
            "error": str(e)[:100],
        }


def _get_config_info() -> dict[str, Any]:
    """Get configuration information for debug output."""
    # Shared config with promptfoo
    shared_config_dir = get_config_directory_path()
    shared_config_path = os.path.join(shared_config_dir, "promptfoo.yaml")
    shared_display_path = _sanitize_debug_path(shared_config_path)

    # ModelAudit-specific config
    home = str(Path.home())
    modelaudit_config_path = os.path.join(home, ".modelaudit", "user_config.json")
    modelaudit_display_path = "~/.modelaudit/user_config.json"

    return {
        "sharedConfigPath": shared_display_path,
        "sharedConfigExists": os.path.exists(shared_config_path),
        "modelauditConfigPath": modelaudit_display_path,
        "modelauditConfigExists": os.path.exists(modelaudit_config_path),
        "userIdGenerated": bool(get_user_id()),
    }


def _safe_get_section(func: Any, section_name: str) -> dict[str, Any]:
    """Safely execute a debug info function, returning error on failure."""
    try:
        result = func()
        return result if isinstance(result, dict) else {"value": result}
    except Exception as e:
        return {"error": f"Failed to retrieve {section_name}: {str(e)[:100]}"}


def _format_debug_output(debug_info: dict[str, Any], verbose: bool) -> str:
    """Format debug info as pretty-printed output with quick diagnosis."""
    lines = []

    # Header
    border = "═" * 80
    lines.append(border)
    lines.append(style_text("ModelAudit Debug Information", fg="blue", bold=True))
    lines.append(border)

    # JSON output
    lines.append(json.dumps(debug_info, indent=2, default=str))

    lines.append(border)
    lines.append(
        style_text(
            "Please include this output when reporting issues:",
            fg="yellow",
        )
    )
    lines.append(style_text("https://github.com/promptfoo/modelaudit/issues", fg="cyan"))
    lines.append("")

    # Quick diagnosis section
    lines.append(style_text("Quick diagnosis:", fg="white", bold=True))

    # Platform status
    platform_info = debug_info.get("platform", {})
    python_ver = platform_info.get("pythonVersion", "unknown")
    os_name = platform_info.get("os", "unknown")
    arch = platform_info.get("arch", "unknown")
    lines.append(f"  ✅ Python {python_ver} on {os_name} ({arch})")

    # Dependencies summary
    deps_info = debug_info.get("dependencies", {})
    ml_frameworks = deps_info.get("mlFrameworks", {})
    ml_installed = [k for k in ["torch", "tensorflow", "onnx", "jax"] if k in ml_frameworks]
    if ml_installed:
        lines.append(f"  ✅ ML frameworks: {', '.join(ml_installed)}")
    else:
        lines.append(style_text("  ⚠️  No ML frameworks installed (torch, tensorflow, onnx, jax)", fg="yellow"))

    # Scanner status
    scanner_info = debug_info.get("scanners", {})
    available = scanner_info.get("available", 0)
    total = scanner_info.get("total", 0)
    failed = scanner_info.get("failed", 0)

    if failed == 0:
        lines.append(f"  ✅ {available}/{total} scanners available")
    else:
        lines.append(style_text(f"  ⚠️  {available}/{total} scanners available ({failed} unavailable)", fg="yellow"))
        if not verbose:
            lines.append(style_text("     Run with --verbose for failure details", dim=True))

    # NumPy status (get from dependencies)
    numpy_version = ml_frameworks.get("numpy")
    if numpy_version:
        # NumPy 2.x may have compatibility issues with some ML frameworks
        major_version = int(numpy_version.split(".")[0]) if numpy_version else 0
        if major_version >= 2:
            lines.append(style_text(f"  ⚠️  NumPy {numpy_version} (v2 may have ML framework issues)", fg="yellow"))
        else:
            lines.append(f"  ✅ NumPy {numpy_version}")
    else:
        lines.append(style_text("  ⚠️  NumPy not installed", fg="yellow"))

    # Cache status
    cache_info = debug_info.get("cache", {})
    if cache_info.get("enabled"):
        entries = cache_info.get("entries", 0)
        size_mb = cache_info.get("sizeMb", 0)
        lines.append(f"  ✅ Cache enabled ({entries} entries, {size_mb} MB)")
    else:
        cache_error = cache_info.get("error", "disabled")
        lines.append(style_text(f"  ⚠️  Cache: {cache_error}", fg="yellow"))

    # Auth status
    auth_info = debug_info.get("auth", {})
    if auth_info.get("authenticated"):
        source = auth_info.get("authSource", "unknown")
        lines.append(f"  ✅ Authenticated via {source}")
    else:
        lines.append(style_text("  ⚠️  Not authenticated (enhanced scanning unavailable)", fg="yellow"))

    # Telemetry status
    env_info = debug_info.get("env", {})
    if env_info.get("telemetryDisabled"):
        lines.append("  [i] Telemetry disabled")

    lines.append(border)

    return "\n".join(lines)


@cli.command()
@click.option("--json", "output_json", is_flag=True, help="Output raw JSON without formatting")
@click.option("--verbose", "-v", is_flag=True, help="Include additional diagnostic details")
def debug(output_json: bool, verbose: bool) -> None:
    """Display debug information for troubleshooting.

    Outputs comprehensive diagnostic information useful for:

    \b
    - Filing bug reports on GitHub
    - Troubleshooting scanner issues
    - Verifying configuration and authentication
    - Checking environment setup

    \b
    Examples:
        modelaudit debug                    # Pretty-printed output
        modelaudit debug --json             # Raw JSON for scripting
        modelaudit debug --verbose          # Include detailed scanner errors
    """
    import time

    start_time = time.time()
    # Build debug info dictionary
    debug_info: dict[str, Any] = {
        "version": __version__,
        "platform": _safe_get_section(_get_platform_info, "platform"),
        "install": _safe_get_section(_get_install_info, "install"),
        "dependencies": _safe_get_section(_get_dependency_versions, "dependencies"),
        "env": _safe_get_section(_get_env_info, "env"),
        "auth": _safe_get_section(_get_auth_info, "auth"),
        "scanners": _safe_get_section(lambda: _get_scanner_info(verbose), "scanners"),
        "cache": _safe_get_section(_get_cache_info, "cache"),
        "config": _safe_get_section(_get_config_info, "config"),
    }

    if output_json:
        # Raw JSON output for scripting
        click.echo(json.dumps(debug_info, indent=2, default=str))
    else:
        # Pretty-printed output with quick diagnosis
        click.echo(_format_debug_output(debug_info, verbose))

    record_command_used(
        "debug", duration=time.time() - start_time, success=True, output_json=output_json, verbose=verbose
    )


def main() -> None:
    if sys.version_info < (3, 10):  # noqa: UP036 — intentional safety net for bypassed requires-python
        click.echo(
            click.style(
                f"WARNING: modelaudit requires Python 3.10+, but you are running "
                f"Python {sys.version_info[0]}.{sys.version_info[1]}. "
                f"Please upgrade: https://www.promptfoo.dev/docs/model-audit/",
                fg="yellow",
            ),
            err=True,
        )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    cli()


if __name__ == "__main__":
    main()
