"""Archive member helpers for PyTorch ZIP scanner."""

import contextlib
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Any

from ..base import IssueSeverity, ScanResult


def read_zip_header(path: str, length: int = 4) -> bytes:
    """Return the first few bytes of a file."""
    try:
        with open(path, "rb") as f:
            return f.read(length)
    except Exception:
        return b""


def get_zip_member_name(name: str | zipfile.ZipInfo) -> str:
    """Return the archive member name for a string or ZipInfo."""
    return name.filename if isinstance(name, zipfile.ZipInfo) else name


def get_zip_member_names(entries: list[zipfile.ZipInfo]) -> list[str]:
    """Return archive member names while preserving duplicate entries."""
    return [get_zip_member_name(entry) for entry in entries]


def find_zip_entry(entries: list[zipfile.ZipInfo], member_name: str) -> zipfile.ZipInfo | None:
    """Return the first matching ZipInfo entry for a member name, or None."""
    for entry in entries:
        if entry.filename == member_name:
            return entry
    return None


def _is_crc_mismatch_error(error: Exception) -> bool:
    """Return True when the error indicates a ZIP member CRC mismatch."""
    return isinstance(error, zipfile.BadZipFile) and "Bad CRC-32" in str(error)


def _open_zip_member(
    zip_file: zipfile.ZipFile,
    name: str | zipfile.ZipInfo,
    *,
    relaxed_crc: bool = False,
) -> Any:
    """Open a ZIP member, optionally disabling CRC enforcement on the stream."""
    handle: Any = zip_file.open(name, "r")
    if relaxed_crc and hasattr(handle, "_expected_crc"):
        # PyTorch-generated archives can have incorrect member CRCs. Disable
        # per-member CRC enforcement only after a strict read failed so the
        # scanner can still inspect the payload.
        handle._expected_crc = None
    return handle


@dataclass
class RelaxedZipCrcTracker:
    """Track members that require relaxed CRC reads during scanning."""

    reads: dict[str, set[str]] = field(default_factory=dict)
    check_indices: dict[str, tuple[int, int]] = field(default_factory=dict)

    def reset(self) -> None:
        """Clear all recorded relaxed-CRC state."""
        self.reads = {}
        self.check_indices = {}

    def has_member(self, member_name: str) -> bool:
        """Return True when the member has already needed relaxed CRC reads."""
        return member_name in self.reads

    def record_usage(
        self,
        member_name: str,
        phase: str,
        result: ScanResult,
        *,
        archive_path: str,
        error: Exception | None = None,
    ) -> None:
        """Record that a member needed relaxed CRC handling during scanning."""
        is_new_member = member_name not in self.reads
        phases = self.reads.setdefault(member_name, set())
        phases.add(phase)
        phase_list = sorted(phases)
        result.metadata["relaxed_crc_members"] = {
            name: sorted(recorded_phases) for name, recorded_phases in self.reads.items()
        }
        result.metadata["relaxed_crc_used"] = True

        existing_indices = self.check_indices.get(member_name)
        if existing_indices is not None:
            check_index, issue_index = existing_indices
            for details_dict in (
                result.checks[check_index].details,
                result.issues[issue_index].details,
            ):
                details_dict["scan_phases"] = phase_list

        if not is_new_member:
            return

        result.add_check(
            name="PyTorch ZIP CRC Handling",
            passed=False,
            message=(
                f"CRC validation failed for archive member {member_name}; "
                "continuing scan with relaxed CRC handling for content analysis"
            ),
            severity=IssueSeverity.WARNING,
            location=f"{archive_path}:{member_name}",
            details={
                "zip_entry": member_name,
                "scan_phases": phase_list,
                "relaxed_crc": True,
                "exception": str(error) if error else None,
                "exception_type": type(error).__name__ if error else None,
            },
            why=(
                "Some PyTorch ZIP archives contain member-level CRC mismatches. "
                "The scanner retries those member reads with CRC enforcement "
                "relaxed so payload analysis can continue, but surfaces the "
                "integrity anomaly for review."
            ),
        )
        self.check_indices[member_name] = (len(result.checks) - 1, len(result.issues) - 1)


def _resolve_member_info(zip_file: zipfile.ZipFile, name: str | zipfile.ZipInfo) -> tuple[str, zipfile.ZipInfo]:
    member_name = get_zip_member_name(name)
    member_info = name if isinstance(name, zipfile.ZipInfo) else zip_file.getinfo(name)
    return member_name, member_info


def read_member_prefix(
    zip_file: zipfile.ZipFile,
    name: str | zipfile.ZipInfo,
    limit: int,
    *,
    phase: str,
    result: ScanResult,
    archive_path: str,
    crc_tracker: RelaxedZipCrcTracker,
) -> bytes:
    """Read up to ``limit`` bytes from a ZIP member with guarded CRC fallback."""
    member_name = get_zip_member_name(name)
    relaxed_crc = crc_tracker.has_member(member_name)
    if relaxed_crc:
        crc_tracker.record_usage(member_name, phase, result, archive_path=archive_path)

    try:
        with _open_zip_member(zip_file, name, relaxed_crc=relaxed_crc) as handle:
            return handle.read(limit)
    except zipfile.BadZipFile as exc:
        if relaxed_crc or not _is_crc_mismatch_error(exc):
            raise
        crc_tracker.record_usage(member_name, phase, result, archive_path=archive_path, error=exc)
    with _open_zip_member(zip_file, name, relaxed_crc=True) as handle:
        return handle.read(limit)


def read_member_bytes(
    zip_file: zipfile.ZipFile,
    name: str | zipfile.ZipInfo,
    *,
    phase: str,
    result: ScanResult,
    archive_path: str,
    crc_tracker: RelaxedZipCrcTracker,
    max_bytes: int | None = None,
) -> bytes:
    """Read an entire ZIP member with optional bounded size and guarded CRC fallback."""
    member_name, member_info = _resolve_member_info(zip_file, name)
    if max_bytes is not None and member_info.file_size > max_bytes:
        raise ValueError(
            f"Archive member {member_name} exceeds bounded read limit ({member_info.file_size} > {max_bytes})",
        )

    def read_all(*, relaxed_crc: bool) -> bytes:
        with _open_zip_member(zip_file, member_info, relaxed_crc=relaxed_crc) as handle:
            data = bytearray()
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                data.extend(chunk)
                if max_bytes is not None and len(data) > max_bytes:
                    raise ValueError(f"Archive member {member_name} exceeded bounded read limit ({max_bytes})")
            return bytes(data)

    relaxed_crc = crc_tracker.has_member(member_name)
    if relaxed_crc:
        crc_tracker.record_usage(member_name, phase, result, archive_path=archive_path)
    try:
        return read_all(relaxed_crc=relaxed_crc)
    except zipfile.BadZipFile as exc:
        if relaxed_crc or not _is_crc_mismatch_error(exc):
            raise
        crc_tracker.record_usage(member_name, phase, result, archive_path=archive_path, error=exc)
    return read_all(relaxed_crc=True)


def read_member_to_spooled_file(
    zip_file: zipfile.ZipFile,
    name: str | zipfile.ZipInfo,
    *,
    phase: str,
    result: ScanResult,
    archive_path: str,
    crc_tracker: RelaxedZipCrcTracker,
    max_size: int,
    max_bytes: int | None = None,
) -> tuple[Any, int]:
    """Copy a ZIP member into a spooled temp file with guarded CRC fallback."""
    member_name, member_info = _resolve_member_info(zip_file, name)
    if max_bytes is not None and member_info.file_size > max_bytes:
        raise ValueError(
            f"Archive member {member_name} exceeds bounded read limit ({member_info.file_size} > {max_bytes})",
        )

    def copy_to_spool(*, relaxed_crc: bool) -> tuple[Any, int]:
        with contextlib.ExitStack() as stack:
            spool = stack.enter_context(tempfile.SpooledTemporaryFile(max_size=max_size))
            total_bytes = 0
            with _open_zip_member(zip_file, member_info, relaxed_crc=relaxed_crc) as handle:
                while True:
                    chunk = handle.read(64 * 1024)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if max_bytes is not None and total_bytes > max_bytes:
                        raise ValueError(
                            f"Archive member {member_name} exceeded bounded read limit ({max_bytes})",
                        )
                    spool.write(chunk)
            spool.seek(0)
            stack.pop_all()
            return spool, total_bytes

    relaxed_crc = crc_tracker.has_member(member_name)
    if relaxed_crc:
        crc_tracker.record_usage(member_name, phase, result, archive_path=archive_path)
    try:
        return copy_to_spool(relaxed_crc=relaxed_crc)
    except zipfile.BadZipFile as exc:
        if relaxed_crc or not _is_crc_mismatch_error(exc):
            raise
        crc_tracker.record_usage(member_name, phase, result, archive_path=archive_path, error=exc)
    return copy_to_spool(relaxed_crc=True)
