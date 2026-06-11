"""Scanner for tar-archived model files (.tar, .tar.gz, .tgz)."""

from __future__ import annotations

import errno
import os
import re
import tarfile
import tempfile
from typing import Any, ClassVar

from ..utils import is_absolute_archive_path, is_critical_system_path, sanitize_archive_path
from ..utils.helpers.assets import asset_from_scan_result
from ._archive_locations import rewrite_extracted_member_location
from ._archive_outcomes import mark_archive_scan_incomplete, member_scan_incomplete
from .archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY, scan_nested_file
from .archive_member_security import scan_archive_member_for_known_risks
from .base import BaseScanner, IssueSeverity, ScanResult

CRITICAL_SYSTEM_PATHS = [
    "/etc",
    "/bin",
    "/usr",
    "/var",
    "/lib",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/sbin",
    "C:\\Windows",
]

DEFAULT_MAX_TAR_ENTRY_SIZE = 1024 * 1024 * 1024
DEFAULT_MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_DECOMPRESSION_RATIO = 250.0
ARCHIVE_MEMBER_COPY_CHUNK_BYTES = 64 * 1024
MAX_TAR_PYTHON_ANALYSIS_BYTES = 10 * 1024 * 1024
TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY = "_tar_security_only_nested_member_entries"

_GZIP_MAGIC = b"\x1f\x8b"
_BZIP2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"


class _TarEntryExtractionIncomplete(ValueError):
    """Raised when a TAR member cannot be inspected within extraction policy."""


class TarScanner(BaseScanner):
    """Scanner for TAR archive files."""

    name = "tar"
    description = "Scans TAR archive files and their contents recursively"
    supported_extensions: ClassVar[list[str]] = [
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.bz2",
        ".tbz2",
        ".tar.xz",
        ".txz",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.max_depth = self.config.get("max_tar_depth", 5)
        self.max_entries = self.config.get("max_tar_entries", 10000)
        self.max_decompressed_bytes = self._normalize_positive_int_config(
            self.config.get("compressed_max_decompressed_bytes"),
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        self.max_decompression_ratio = self._normalize_positive_float_config(
            self.config.get("compressed_max_decompression_ratio"),
            DEFAULT_MAX_DECOMPRESSION_RATIO,
        )

    @staticmethod
    def _normalize_positive_float_config(value: Any, default: float) -> float:
        """Return a positive float config value, or default for invalid input."""
        if isinstance(value, bool):
            return default
        try:
            normalized_value = float(value)
        except (TypeError, ValueError):
            return default
        return normalized_value if normalized_value > 0 else default

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        try:
            return tarfile.is_tarfile(path)
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        path_check = self._check_path(path)
        if path_check:
            return path_check

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        result.metadata["file_size"] = self.get_file_size(path)

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            self.current_file_path = path
            try:
                archive_depth = int(self.config.get("_archive_depth", 0))
            except (TypeError, ValueError):
                archive_depth = 0

            scan_result = self._scan_tar_file(path, depth=max(archive_depth, 0))
            result.merge(scan_result)
        except tarfile.TarError:
            result.add_check(
                name="TAR File Format Validation",
                passed=False,
                message=f"Not a valid tar file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
                rule_code="S902",
            )
            mark_archive_scan_incomplete(result, "tar_analysis_incomplete")
            result.finish(success=False)
            return result
        except Exception as e:
            self._record_incomplete_tar_scan(result, path, e)
            result.finish(success=False)
            return result

        result.finish(success=scan_result.success and not result.has_errors)
        result.metadata["contents"] = scan_result.metadata.get("contents", [])
        return result

    def _get_max_entry_size(self) -> int:
        """Return the per-entry extraction limit used for TAR members."""
        configured_file_limit = self.config.get("max_file_size")
        configured_entry_limit = self.config.get("max_entry_size")

        # The top-level scan cap is the operator-facing hard stop (for example
        # CLI --max-size), so it must win when explicitly set.
        if configured_file_limit is not None and configured_file_limit != 0:
            return self._normalize_positive_int_config(
                configured_file_limit,
                DEFAULT_MAX_TAR_ENTRY_SIZE,
            )

        if configured_entry_limit is not None:
            if configured_entry_limit == 0:
                return 1024 * 1024 * 1024 * 1024
            return self._normalize_positive_int_config(
                configured_entry_limit,
                DEFAULT_MAX_TAR_ENTRY_SIZE,
            )

        if configured_file_limit == 0:
            return DEFAULT_MAX_TAR_ENTRY_SIZE

        return DEFAULT_MAX_TAR_ENTRY_SIZE

    def _rewrite_nested_result_context(
        self,
        scan_result: ScanResult,
        tmp_path: str,
        archive_path: str,
        entry_name: str,
    ) -> None:
        """Rewrite nested result locations so archive members, not temp files, are reported."""
        archive_location = f"{archive_path}:{entry_name}"

        for issue in scan_result.issues:
            issue.location = self._rewrite_archive_location(issue.location, tmp_path, archive_location)

            existing_issue_entry = issue.details.get("tar_entry")
            issue.details["tar_entry"] = (
                f"{entry_name}:{existing_issue_entry}"
                if isinstance(existing_issue_entry, str) and existing_issue_entry
                else entry_name
            )

        for check in scan_result.checks:
            check.location = self._rewrite_archive_location(check.location, tmp_path, archive_location)

            existing_check_entry = check.details.get("tar_entry")
            check.details["tar_entry"] = (
                f"{entry_name}:{existing_check_entry}"
                if isinstance(existing_check_entry, str) and existing_check_entry
                else entry_name
            )

    def _scan_nested_archive_entry(self, path: str, nested_config: dict[str, Any]) -> ScanResult:
        """Dispatch a nested archive member through an injected callback or registry fallback."""
        nested_scan_callback = self.config.get(NESTED_SCAN_CALLBACK_CONFIG_KEY)
        if callable(nested_scan_callback):
            return nested_scan_callback(path, nested_config)
        return scan_nested_file(path, nested_config)

    @staticmethod
    def _rewrite_archive_location(location: str | None, tmp_path: str, archive_location: str) -> str:
        return rewrite_extracted_member_location(
            location,
            tmp_path,
            archive_location,
            preserve_non_delimited_suffix=False,
        )

    @staticmethod
    def _resolve_link_target(
        target: str,
        *,
        resolved_member_name: str,
        extraction_root: str,
        is_symlink: bool,
    ) -> tuple[str, bool]:
        """Resolve TAR symlinks from their parent and hardlinks from the archive root."""
        if not is_symlink:
            return sanitize_archive_path(target, extraction_root)
        if is_absolute_archive_path(target):
            return sanitize_archive_path(target, extraction_root)

        normalized_target = target.replace("\\", os.sep).replace("/", os.sep)
        target_base = os.path.dirname(resolved_member_name)
        target_resolved = os.path.normpath(os.path.join(target_base, normalized_target))
        try:
            target_from_root = os.path.relpath(target_resolved, extraction_root)
        except ValueError:
            return target_resolved, False
        return sanitize_archive_path(target_from_root, extraction_root)

    def _extract_member_to_tempfile(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        *,
        suffix: str,
    ) -> tuple[str, int]:
        """Stream a TAR member to disk while enforcing the configured size limit."""
        max_entry_size = self._get_max_entry_size()
        if member.size > max_entry_size:
            raise _TarEntryExtractionIncomplete(
                f"TAR entry {member.name} exceeds maximum size of {max_entry_size} bytes"
            )
        fileobj = tar.extractfile(member)
        if fileobj is None:
            raise _TarEntryExtractionIncomplete(f"Unable to extract TAR entry: {member.name}")

        total_size = 0
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp_path = tmp.name
                while True:
                    chunk = fileobj.read(ARCHIVE_MEMBER_COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    total_size += len(chunk)
                    if total_size > max_entry_size:
                        raise _TarEntryExtractionIncomplete(
                            f"TAR entry {member.name} exceeds maximum size of {max_entry_size} bytes"
                        )
                    tmp.write(chunk)
        except Exception:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        finally:
            fileobj.close()

        assert tmp_path is not None
        return tmp_path, total_size

    @staticmethod
    def _detect_compressed_tar_wrapper(path: str) -> str | None:
        """Detect compressed TAR wrappers by content, not by filename suffix."""
        with open(path, "rb") as file_obj:
            header = file_obj.read(6)

        if header.startswith(_GZIP_MAGIC):
            return "gzip"
        if header.startswith(_BZIP2_MAGIC):
            return "bzip2"
        if header.startswith(_XZ_MAGIC):
            return "xz"
        return None

    @staticmethod
    def _finalize_tar_stream_size(consumed_size: int) -> int:
        """Return the minimum TAR stream size after EOF blocks and record padding."""
        total_size = max(consumed_size + (2 * tarfile.BLOCKSIZE), tarfile.RECORDSIZE)
        return ((total_size + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE

    @staticmethod
    def _is_empty_tar_archive(path: str) -> bool:
        """Detect standard empty TAR archives that some Python 3.10 builds reject on ``next()``."""
        max_read_size = 10 * 1024 * 1024
        try:
            file_size = os.path.getsize(path)
            if file_size < 2 * tarfile.BLOCKSIZE or file_size % tarfile.BLOCKSIZE != 0:
                return False
            if file_size > max_read_size:
                return False

            with open(path, "rb") as file_obj:
                empty_data = file_obj.read(file_size)
                return len(empty_data) == file_size and empty_data == b"\0" * file_size
        except OSError:
            return False

    def _add_compressed_wrapper_limit_check(
        self,
        result: ScanResult,
        *,
        passed: bool,
        path: str,
        message: str,
        decompressed_size: int,
        compressed_size: int,
        compression_codec: str,
        actual_ratio: float | None = None,
    ) -> None:
        """Record compressed-wrapper policy checks with consistent details."""
        details: dict[str, Any] = {
            "decompressed_size": decompressed_size,
            "compressed_size": compressed_size,
            "max_decompressed_size": self.max_decompressed_bytes,
            "max_ratio": self.max_decompression_ratio,
            "compression": compression_codec,
        }
        if actual_ratio is not None:
            details["actual_ratio"] = actual_ratio

        result.add_check(
            name="Compressed Wrapper Decompression Limits",
            passed=passed,
            message=message,
            severity=None if passed else IssueSeverity.WARNING,
            location=path,
            details=details,
            rule_code=None if passed else "S902",
        )

    def _preflight_tar_archive(self, path: str, result: ScanResult) -> bool:
        """Stream TAR headers once to enforce entry-count and wrapper-size limits before extraction."""
        entry_count = 0
        compressed_size = os.path.getsize(path)
        compression_codec = self._detect_compressed_tar_wrapper(path)
        consumed_size = 0

        with tarfile.open(path, "r:*") as tar:
            while True:
                try:
                    member = tar.next()
                except OSError as exc:
                    if entry_count == 0 and exc.errno == errno.EINVAL and self._is_empty_tar_archive(path):
                        break
                    raise

                if member is None:
                    break

                entry_count += 1
                if entry_count > self.max_entries:
                    result.add_check(
                        name="Entry Count Limit Check",
                        passed=False,
                        message=f"TAR file contains too many entries ({entry_count} > {self.max_entries})",
                        rule_code="S902",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"entries": entry_count, "max_entries": self.max_entries},
                    )
                    return False

                if compression_codec is not None:
                    consumed_size = max(consumed_size, tar.offset)
                    estimated_stream_size = self._finalize_tar_stream_size(consumed_size)
                    actual_ratio = (estimated_stream_size / compressed_size) if compressed_size > 0 else 0.0

                    if estimated_stream_size > self.max_decompressed_bytes:
                        self._add_compressed_wrapper_limit_check(
                            result,
                            passed=False,
                            path=path,
                            message=(
                                f"Decompressed size exceeded limit "
                                f"({estimated_stream_size} > {self.max_decompressed_bytes})"
                            ),
                            decompressed_size=estimated_stream_size,
                            compressed_size=compressed_size,
                            compression_codec=compression_codec,
                            actual_ratio=actual_ratio,
                        )
                        return False

                    if compressed_size > 0 and actual_ratio > self.max_decompression_ratio:
                        self._add_compressed_wrapper_limit_check(
                            result,
                            passed=False,
                            path=path,
                            message=(
                                "Decompression ratio exceeded limit "
                                f"({actual_ratio:.1f}x > {self.max_decompression_ratio:.1f}x)"
                            ),
                            decompressed_size=estimated_stream_size,
                            compressed_size=compressed_size,
                            compression_codec=compression_codec,
                            actual_ratio=actual_ratio,
                        )
                        return False

            result.add_check(
                name="Entry Count Limit Check",
                passed=True,
                message=f"Entry count ({entry_count}) is within limits",
                location=path,
                details={"entries": entry_count, "max_entries": self.max_entries},
                rule_code=None,
            )

            if compression_codec is not None:
                final_stream_size = self._finalize_tar_stream_size(max(consumed_size, tar.offset))
                actual_ratio = (final_stream_size / compressed_size) if compressed_size > 0 else 0.0

                if final_stream_size > self.max_decompressed_bytes:
                    self._add_compressed_wrapper_limit_check(
                        result,
                        passed=False,
                        path=path,
                        message=(
                            f"Decompressed size exceeded limit ({final_stream_size} > {self.max_decompressed_bytes})"
                        ),
                        decompressed_size=final_stream_size,
                        compressed_size=compressed_size,
                        compression_codec=compression_codec,
                        actual_ratio=actual_ratio,
                    )
                    return False

                if compressed_size > 0 and actual_ratio > self.max_decompression_ratio:
                    self._add_compressed_wrapper_limit_check(
                        result,
                        passed=False,
                        path=path,
                        message=(
                            "Decompression ratio exceeded limit "
                            f"({actual_ratio:.1f}x > {self.max_decompression_ratio:.1f}x)"
                        ),
                        decompressed_size=final_stream_size,
                        compressed_size=compressed_size,
                        compression_codec=compression_codec,
                        actual_ratio=actual_ratio,
                    )
                    return False

                self._add_compressed_wrapper_limit_check(
                    result,
                    passed=True,
                    path=path,
                    message=(
                        f"Decompressed size/ratio are within limits ({final_stream_size} bytes, {actual_ratio:.1f}x)"
                    ),
                    decompressed_size=final_stream_size,
                    compressed_size=compressed_size,
                    compression_codec=compression_codec,
                    actual_ratio=actual_ratio,
                )

        return True

    @staticmethod
    def _record_incomplete_tar_scan(result: ScanResult, path: str, exc: Exception) -> None:
        """Record unavailable TAR traversal without discarding findings already collected."""
        mark_archive_scan_incomplete(result, "tar_scan_incomplete")
        result.add_check(
            name="TAR File Scan",
            passed=False,
            message=f"Error scanning tar file: {exc!s}",
            severity=IssueSeverity.INFO,
            rule_code="S902",
            location=path,
            details={
                "exception": str(exc),
                "exception_type": type(exc).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "tar_scan_incomplete",
            },
        )

    def _scan_tar_file(self, path: str, depth: int = 0) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        contents: list[dict[str, Any]] = []
        scan_complete = True

        if depth >= self.max_depth:
            mark_archive_scan_incomplete(result, "tar_depth_limit")
            result.add_check(
                name="TAR Depth Bomb Protection",
                passed=False,
                message=f"Maximum TAR nesting depth ({self.max_depth}) exceeded",
                rule_code="S902",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "depth": depth,
                    "max_depth": self.max_depth,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "tar_depth_limit",
                },
            )
            result.finish(success=False)
            return result
        else:
            result.add_check(
                name="TAR Depth Bomb Protection",
                passed=True,
                message="TAR nesting depth is within safe limits",
                location=path,
                details={"depth": depth, "max_depth": self.max_depth},
                rule_code=None,  # Passing check
            )

        if not self._preflight_tar_archive(path, result):
            result.metadata["contents"] = contents
            result.metadata["file_size"] = os.path.getsize(path)
            mark_archive_scan_incomplete(result, "tar_analysis_incomplete")
            result.finish(success=False)
            return result

        with tarfile.open(path, "r:*") as tar:
            security_only_nested_entries = self.config.get(TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY)
            if not isinstance(security_only_nested_entries, set):
                security_only_nested_entries = set()
            while True:
                try:
                    member = tar.next()
                except OSError as exc:
                    if not contents and exc.errno == errno.EINVAL and self._is_empty_tar_archive(path):
                        break
                    scan_complete = False
                    self._record_incomplete_tar_scan(result, path, exc)
                    break
                except tarfile.TarError:
                    raise
                except Exception as exc:
                    scan_complete = False
                    self._record_incomplete_tar_scan(result, path, exc)
                    break

                if member is None:
                    break

                name = member.name
                temp_base = os.path.join(tempfile.gettempdir(), "extract_tar")
                resolved_name, is_safe = sanitize_archive_path(name, temp_base)
                if not is_safe:
                    result.add_check(
                        name="Path Traversal Protection",
                        passed=False,
                        message=f"Archive entry {name} attempted path traversal outside the archive",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{path}:{name}",
                        details={"entry": name},
                        rule_code="S405",
                    )
                    continue

                if member.issym() or member.islnk():
                    target = member.linkname
                    link_kind = "Symlink" if member.issym() else "Hard link"
                    if target:
                        _target_resolved, target_safe = self._resolve_link_target(
                            target,
                            resolved_member_name=resolved_name,
                            extraction_root=temp_base,
                            is_symlink=member.issym(),
                        )
                    else:
                        target_safe = False
                    if not target_safe:
                        # Check if it's specifically a critical system path
                        if is_absolute_archive_path(target) and is_critical_system_path(target, CRITICAL_SYSTEM_PATHS):
                            message = f"{link_kind} {name} points to critical system path: {target}"
                        elif not target:
                            message = f"{link_kind} {name} has an empty target"
                        else:
                            message = f"{link_kind} {name} resolves outside extraction directory"
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=False,
                            message=message,
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"target": target, "entry": name},
                            rule_code="S406",
                        )
                    elif is_absolute_archive_path(target) and is_critical_system_path(target, CRITICAL_SYSTEM_PATHS):
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=False,
                            message=f"{link_kind} {name} points to critical system path: {target}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"target": target, "entry": name},
                            rule_code="S406",
                        )
                    continue

                if member.isdir():
                    continue

                if not member.isfile():
                    continue

                try:
                    # Check for compound extensions like .tar.gz
                    name_lower = name.lower()
                    is_tar_extension = any(name_lower.endswith(ext) for ext in self.supported_extensions)
                    if is_tar_extension:
                        # Extract the full extension for the temp file
                        for ext in self.supported_extensions:
                            if name_lower.endswith(ext):
                                suffix = ext
                                break
                        else:
                            suffix = ".tar"  # fallback
                    else:
                        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", os.path.basename(name))
                        suffix = f"_{safe_name}"

                    tmp_path, total_size = self._extract_member_to_tempfile(tar, member, suffix=suffix)
                    try:
                        if is_tar_extension and tarfile.is_tarfile(tmp_path):
                            nested_config = dict(self.config)
                            nested_config.pop(TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY, None)
                            # Extracted members are deleted below, so temporary paths
                            # cannot serve as reusable cache keys.
                            nested_config["cache_enabled"] = False
                            nested_config["_archive_depth"] = depth + 1
                            nested_result = self._scan_nested_archive_entry(tmp_path, nested_config)
                            if member_scan_incomplete(nested_result):
                                scan_complete = False

                            self._rewrite_nested_result_context(nested_result, tmp_path, path, name)
                            result.merge_member_result(nested_result, name)
                            asset_entry = asset_from_scan_result(f"{path}:{name}", nested_result)
                        else:
                            scan_archive_member_for_known_risks(
                                archive_kind="TAR",
                                archive_path=path,
                                member_name=name,
                                tmp_path=tmp_path,
                                total_size=total_size,
                                result=result,
                                max_python_analysis_bytes=MAX_TAR_PYTHON_ANALYSIS_BYTES,
                                python_analysis_incomplete_reason="tar_python_member_analysis_incomplete",
                                executable_analysis_incomplete_reason="tar_executable_member_analysis_incomplete",
                            )

                            if name in security_only_nested_entries:
                                result.bytes_scanned += total_size
                                asset_entry = {"path": f"{path}:{name}", "type": "nemo_managed"}
                            else:
                                nested_config = dict(self.config)
                                nested_config.pop(TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY, None)
                                # Extracted members are deleted below, so temporary paths
                                # cannot serve as reusable cache keys.
                                nested_config["cache_enabled"] = False
                                nested_config["_archive_depth"] = depth + 1
                                file_result = self._scan_nested_archive_entry(tmp_path, nested_config)
                                self._rewrite_nested_result_context(file_result, tmp_path, path, name)
                                if member_scan_incomplete(file_result):
                                    scan_complete = False

                                result.merge_member_result(file_result, name)
                                asset_entry = asset_from_scan_result(f"{path}:{name}", file_result)

                                if file_result.scanner_name == "unknown":
                                    result.bytes_scanned += total_size

                        asset_entry.setdefault("size", member.size)
                        contents.append(asset_entry)
                    finally:
                        os.unlink(tmp_path)
                except _TarEntryExtractionIncomplete as exc:
                    scan_complete = False
                    mark_archive_scan_incomplete(result, "tar_entry_extraction_incomplete")
                    result.add_check(
                        name="TAR Entry Scan",
                        passed=False,
                        message=f"Unable to fully inspect TAR entry {name}: {exc!s}",
                        severity=IssueSeverity.INFO,
                        rule_code="S902",
                        location=f"{path}:{name}",
                        details={
                            "entry": name,
                            "exception": str(exc),
                            "exception_type": type(exc).__name__,
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "tar_entry_extraction_incomplete",
                        },
                    )
                except Exception as exc:
                    scan_complete = False
                    mark_archive_scan_incomplete(result, "tar_entry_scan_incomplete")
                    result.add_check(
                        name="TAR Entry Scan",
                        passed=False,
                        message=f"Error scanning TAR entry {name}: {exc!s}",
                        severity=IssueSeverity.INFO,
                        rule_code="S902",
                        location=f"{path}:{name}",
                        details={
                            "entry": name,
                            "exception": str(exc),
                            "exception_type": type(exc).__name__,
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "tar_entry_scan_incomplete",
                        },
                    )

        result.metadata["contents"] = contents
        result.metadata["file_size"] = os.path.getsize(path)
        if not scan_complete:
            mark_archive_scan_incomplete(result, "tar_analysis_incomplete")
        result.finish(success=scan_complete and not member_scan_incomplete(result) and not result.has_errors)
        return result
