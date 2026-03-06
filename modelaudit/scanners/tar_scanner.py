"""Scanner for tar-archived model files (.tar, .tar.gz, .tgz)."""

from __future__ import annotations

import os
import re
import tarfile
import tempfile
from typing import Any, ClassVar

from .. import core
from ..utils import is_absolute_archive_path, is_critical_system_path, sanitize_archive_path
from ..utils.helpers.assets import asset_from_scan_result
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

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        # Check for compound extensions like .tar.gz
        path_lower = path.lower()
        if not any(path_lower.endswith(ext) for ext in cls.supported_extensions):
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
            scan_result = self._scan_tar_file(path, depth=0)
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
            result.finish(success=False)
            return result
        except Exception as e:
            result.add_check(
                name="TAR File Scan",
                passed=False,
                message=f"Error scanning tar file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        result.metadata["contents"] = scan_result.metadata.get("contents", [])
        return result

    def _get_max_entry_size(self) -> int:
        """Return the per-entry extraction limit used for TAR members."""
        max_entry_size = self.config.get("max_file_size", self.config.get("max_entry_size", 10 * 1024 * 1024 * 1024))
        if max_entry_size == 0:
            return 1024 * 1024 * 1024 * 1024
        return int(max_entry_size)

    def _extract_member_to_tempfile(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        *,
        suffix: str,
    ) -> tuple[str, int]:
        """Stream a TAR member to disk while enforcing the configured size limit."""
        max_entry_size = self._get_max_entry_size()
        fileobj = tar.extractfile(member)
        if fileobj is None:
            raise ValueError(f"Unable to extract TAR entry: {member.name}")

        total_size = 0
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp_path = tmp.name
                while True:
                    chunk = fileobj.read(4096)
                    if not chunk:
                        break
                    total_size += len(chunk)
                    if total_size > max_entry_size:
                        raise ValueError(f"TAR entry {member.name} exceeds maximum size of {max_entry_size} bytes")
                    tmp.write(chunk)
        except Exception:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        finally:
            fileobj.close()

        assert tmp_path is not None
        return tmp_path, total_size

    def _scan_tar_file(self, path: str, depth: int = 0) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        contents: list[dict[str, Any]] = []

        if depth >= self.max_depth:
            result.add_check(
                name="TAR Depth Bomb Protection",
                passed=False,
                message=f"Maximum TAR nesting depth ({self.max_depth}) exceeded",
                rule_code="S902",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"depth": depth, "max_depth": self.max_depth},
            )
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

        with tarfile.open(path, "r:*") as tar:
            members = tar.getmembers()
            if len(members) > self.max_entries:
                result.add_check(
                    name="Entry Count Limit Check",
                    passed=False,
                    message=f"TAR file contains too many entries ({len(members)} > {self.max_entries})",
                    rule_code="S902",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"entries": len(members), "max_entries": self.max_entries},
                )
                return result
            else:
                result.add_check(
                    name="Entry Count Limit Check",
                    passed=True,
                    message=f"Entry count ({len(members)}) is within limits",
                    location=path,
                    details={"entries": len(members), "max_entries": self.max_entries},
                    rule_code=None,  # Passing check
                )

            for member in members:
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
                    target_base = os.path.dirname(resolved_name)
                    _target_resolved, target_safe = sanitize_archive_path(target, target_base)
                    if not target_safe:
                        # Check if it's specifically a critical system path
                        if is_absolute_archive_path(target) and is_critical_system_path(target, CRITICAL_SYSTEM_PATHS):
                            message = f"Symlink {name} points to critical system path: {target}"
                        else:
                            message = f"Symlink {name} resolves outside extraction directory"
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=False,
                            message=message,
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"target": target},
                            rule_code="S902",
                        )
                    elif is_absolute_archive_path(target) and is_critical_system_path(target, CRITICAL_SYSTEM_PATHS):
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=False,
                            message=f"Symlink {name} points to critical system path: {target}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"target": target},
                            rule_code="S406",
                        )
                    else:
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=True,
                            message=f"Symlink {name} is safe",
                            location=f"{path}:{name}",
                            details={"target": target, "entry": name},
                            rule_code=None,  # Passing check
                        )
                    continue

                if member.isdir():
                    continue

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
                    tmp_path, total_size = self._extract_member_to_tempfile(tar, member, suffix=suffix)
                    try:
                        if tarfile.is_tarfile(tmp_path):
                            nested_result = self._scan_tar_file(tmp_path, depth + 1)
                            for issue in nested_result.issues:
                                if issue.location and issue.location.startswith(tmp_path):
                                    issue.location = issue.location.replace(tmp_path, f"{path}:{name}", 1)
                            result.merge(nested_result)
                            asset_entry = asset_from_scan_result(f"{path}:{name}", nested_result)
                            asset_entry.setdefault("size", member.size)
                            contents.append(asset_entry)
                        else:
                            file_result = core.scan_file(tmp_path, self.config)
                            for issue in file_result.issues:
                                if issue.location:
                                    if issue.location.startswith(tmp_path):
                                        issue.location = issue.location.replace(tmp_path, f"{path}:{name}", 1)
                                    else:
                                        issue.location = f"{path}:{name} {issue.location}"
                                else:
                                    issue.location = f"{path}:{name}"

                                if issue.details:
                                    issue.details["tar_entry"] = name
                                else:
                                    issue.details = {"tar_entry": name}

                            result.merge(file_result)

                            asset_entry = asset_from_scan_result(f"{path}:{name}", file_result)
                            asset_entry.setdefault("size", member.size)
                            contents.append(asset_entry)

                            if file_result.scanner_name == "unknown":
                                result.bytes_scanned += total_size
                    finally:
                        os.unlink(tmp_path)
                else:
                    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", os.path.basename(name))
                    tmp_path, total_size = self._extract_member_to_tempfile(tar, member, suffix=f"_{safe_name}")
                    try:
                        file_result = core.scan_file(tmp_path, self.config)
                        for issue in file_result.issues:
                            if issue.location:
                                if issue.location.startswith(tmp_path):
                                    issue.location = issue.location.replace(tmp_path, f"{path}:{name}", 1)
                                else:
                                    issue.location = f"{path}:{name} {issue.location}"
                            else:
                                issue.location = f"{path}:{name}"

                            if issue.details:
                                issue.details["tar_entry"] = name
                            else:
                                issue.details = {"tar_entry": name}

                        result.merge(file_result)

                        asset_entry = asset_from_scan_result(f"{path}:{name}", file_result)
                        asset_entry.setdefault("size", member.size)
                        contents.append(asset_entry)

                        if file_result.scanner_name == "unknown":
                            result.bytes_scanned += total_size
                    finally:
                        os.unlink(tmp_path)

        result.metadata["contents"] = contents
        result.metadata["file_size"] = os.path.getsize(path)
        result.finish(success=not result.has_errors)
        return result
