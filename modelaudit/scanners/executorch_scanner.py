"""Scanner for ExecuTorch model files (.pte)."""

import os
import pickletools
import tempfile
import zipfile
from typing import Any, BinaryIO, ClassVar, cast

from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ..scanner_selection import add_scanner_selection_skip_check, embedded_pickle_scanner
from ..utils import sanitize_archive_path
from ..utils.file.detection import (
    PROTO0_1_START_BYTES,
    _is_executorch_binary_signature,
    _is_valid_executorch_binary,
    _looks_like_proto0_or_1_pickle,
    is_executorch_archive,
)
from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner
from .picklescan_adapter import (
    apply_pickle_member_context,
)

CONTENT_ROUTE_BLOCKED_EXTENSIONS = frozenset({".bin", ".meta", ".pb"})
_PICKLE_BINARY_PROTOCOL_PREFIXES: tuple[bytes, ...] = (
    b"\x80\x01",
    b"\x80\x02",
    b"\x80\x03",
    b"\x80\x04",
    b"\x80\x05",
)
_PICKLE_PROTOCOLLESS_BINARY_START_BYTES = frozenset(
    ord(opcode.code) for opcode in pickletools.opcodes if opcode.proto >= 1 and opcode.name != "PROTO"
)
_PICKLE_DISCOVERY_SHORT_PROBE_BYTES = 16
_PICKLE_DISCOVERY_MAX_ENTRIES = 10_000
_PICKLE_DISCOVERY_MAX_PROBE_BYTES = 4 * 1024 * 1024
_PICKLE_DISCOVERY_MAX_FAILURE_SAMPLES = 20
_PICKLE_DISCOVERY_MAX_DIAGNOSTIC_CHARS = 512
_PICKLE_DISCOVERY_INCOMPLETE_REASON = "executorch_pickle_discovery_incomplete"
_PICKLE_MEMBER_SCAN_INCOMPLETE_REASON = "executorch_pickle_member_scan_incomplete"


class _PickleDiscoveryBudgetExceeded(ValueError):
    """Raised when hidden-pickle discovery cannot inspect another candidate safely."""


class ExecuTorchScanner(BaseScanner):
    """Scanner for PyTorch Mobile/ExecuTorch archives (.ptl, .pte)."""

    name = "executorch"
    description = "Scans ExecuTorch mobile model files for suspicious content"
    supported_extensions: ClassVar[list[str]] = [".ptl", ".pte"]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.pickle_scanner, self.scanner_selection = embedded_pickle_scanner(self.config, PickleScanner)
        self.max_pickle_discovery_entries = self._normalize_positive_int_config(
            self.config.get("max_executorch_pickle_discovery_entries"),
            _PICKLE_DISCOVERY_MAX_ENTRIES,
        )
        self.max_pickle_discovery_probe_bytes = self._normalize_positive_int_config(
            self.config.get("max_executorch_pickle_discovery_probe_bytes"),
            _PICKLE_DISCOVERY_MAX_PROBE_BYTES,
        )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            return True
        if ext in CONTENT_ROUTE_BLOCKED_EXTENSIONS:
            return False
        try:
            header = cls._read_header(path, length=8)
        except OSError:
            return False
        return (_is_executorch_binary_signature(header) and _is_valid_executorch_binary(path)) or is_executorch_archive(
            path
        )

    @staticmethod
    def _read_header(path: str, length: int = 4) -> bytes:
        with open(path, "rb") as f:
            return f.read(length)

    @staticmethod
    def _bounded_discovery_text(value: object) -> str:
        text = str(value)
        if len(text) <= _PICKLE_DISCOVERY_MAX_DIAGNOSTIC_CHARS:
            return text
        return f"{text[: _PICKLE_DISCOVERY_MAX_DIAGNOSTIC_CHARS - 3]}..."

    @staticmethod
    def _looks_like_binary_pickle_prefix(
        sample: bytes,
        *,
        sample_is_prefix: bool,
        allow_protocolless: bool = False,
    ) -> bool:
        has_protocol = any(sample.startswith(magic) for magic in _PICKLE_BINARY_PROTOCOL_PREFIXES)
        if not has_protocol and not (
            allow_protocolless and sample and sample[0] in _PICKLE_PROTOCOLLESS_BINARY_START_BYTES
        ):
            return False

        op_count = 0
        try:
            for opcode, _arg, _pos in pickletools.genops(sample):
                op_count += 1
                if opcode.name == "STOP":
                    return True
                if sample_is_prefix and op_count >= 4:
                    return True
        except ValueError as exc:
            message = str(exc).lower()
            return (
                sample_is_prefix
                and op_count >= 1
                and ("exhausted before seeing stop" in message or "not enough data" in message or "expected" in message)
            )

        return sample_is_prefix and op_count >= 2

    def _entry_looks_like_pickle(
        self,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        probe_bytes_remaining: list[int],
    ) -> bool:
        if entry.file_size <= 0:
            return False
        if probe_bytes_remaining[0] <= 0:
            raise _PickleDiscoveryBudgetExceeded("aggregate hidden-pickle probe byte budget exhausted")

        with zip_file.open(entry, "r") as member_file:
            initial_read_size = min(
                entry.file_size,
                _PICKLE_DISCOVERY_SHORT_PROBE_BYTES,
                probe_bytes_remaining[0],
            )
            data_start = member_file.read(initial_read_size)
            probe_bytes_remaining[0] -= len(data_start)

            if not data_start:
                return False

            incomplete_protocol_prefix = data_start == b"\x80" and entry.file_size > len(data_start)
            has_binary_protocol = any(data_start.startswith(magic) for magic in _PICKLE_BINARY_PROTOCOL_PREFIXES)
            has_protocolless_binary_start = data_start[0] in _PICKLE_PROTOCOLLESS_BINARY_START_BYTES
            has_proto0_or_1_start = data_start[0] in PROTO0_1_START_BYTES
            if not (
                incomplete_protocol_prefix
                or has_binary_protocol
                or has_protocolless_binary_start
                or has_proto0_or_1_start
            ):
                return False

            remaining_entry_bytes = entry.file_size - len(data_start)
            extra_read_size = min(remaining_entry_bytes, probe_bytes_remaining[0])
            sample = data_start + member_file.read(extra_read_size)
            probe_bytes_remaining[0] -= len(sample) - len(data_start)

        sample_is_prefix = entry.file_size > len(sample)
        if incomplete_protocol_prefix:
            raise _PickleDiscoveryBudgetExceeded("hidden-pickle protocol prefix exceeds aggregate probe byte budget")

        if has_binary_protocol or has_protocolless_binary_start:
            is_pickle = self._looks_like_binary_pickle_prefix(
                sample,
                sample_is_prefix=sample_is_prefix,
                allow_protocolless=has_protocolless_binary_start,
            )
        else:
            is_pickle = _looks_like_proto0_or_1_pickle(sample, sample_is_prefix=sample_is_prefix)

        if is_pickle:
            return True
        if sample_is_prefix and probe_bytes_remaining[0] <= 0:
            raise _PickleDiscoveryBudgetExceeded("hidden-pickle structure exceeds aggregate probe byte budget")
        return False

    def _discover_pickle_entries(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> list[zipfile.ZipInfo]:
        pickle_entries: list[zipfile.ZipInfo] = []
        seen_entries: set[int] = set()

        def add_entry(entry: zipfile.ZipInfo) -> None:
            entry_key = id(entry)
            if entry_key in seen_entries:
                return
            pickle_entries.append(entry)
            seen_entries.add(entry_key)

        for entry in safe_entries:
            if entry.filename.casefold().endswith(".pkl"):
                add_entry(entry)

        candidates = [entry for entry in safe_entries if id(entry) not in seen_entries and not entry.is_dir()]
        entries_to_probe = candidates[: self.max_pickle_discovery_entries]
        failed_count = len(candidates) - len(entries_to_probe)
        probe_failures: list[dict[str, Any]] = []
        if failed_count:
            probe_failures.append(
                {
                    "exception": "hidden-pickle candidate entry limit exceeded",
                    "exception_type": _PickleDiscoveryBudgetExceeded.__name__,
                    "location": self.current_file_path,
                }
            )

        probe_bytes_remaining = [self.max_pickle_discovery_probe_bytes]
        for entry in entries_to_probe:
            try:
                if self._entry_looks_like_pickle(zip_file, entry, probe_bytes_remaining):
                    add_entry(entry)
            except Exception as exc:
                failed_count += 1
                if len(probe_failures) < _PICKLE_DISCOVERY_MAX_FAILURE_SAMPLES:
                    safe_name = self._bounded_discovery_text(entry.filename)
                    probe_failures.append(
                        {
                            "zip_entry": safe_name,
                            "exception": self._bounded_discovery_text(exc),
                            "exception_type": type(exc).__name__,
                            "location": self._bounded_discovery_text(f"{self.current_file_path}:{safe_name}"),
                        }
                    )

        if failed_count:
            mark_inconclusive_scan_result(result, _PICKLE_DISCOVERY_INCOMPLETE_REASON)
            count = failed_count
            noun = "member" if count == 1 else "members"
            result.add_check(
                name="Pickle Discovery",
                passed=False,
                message=f"{count} ExecuTorch ZIP {noun} could not be inspected for hidden pickle payloads",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "zip_entries": [failure["zip_entry"] for failure in probe_failures if "zip_entry" in failure],
                    "entries": probe_failures,
                    "failed_count": count,
                    "reported_failure_count": len(probe_failures),
                    "analysis_incomplete": True,
                    "scan_outcome_reason": _PICKLE_DISCOVERY_INCOMPLETE_REASON,
                },
            )

        return pickle_entries

    @staticmethod
    def _finish_read_failure(result: ScanResult, path: str, exc: OSError) -> ScanResult:
        mark_inconclusive_scan_result(result, "executorch_read_failed")
        result.add_check(
            name="ExecuTorch File Read",
            passed=False,
            message=f"Unable to read ExecuTorch content: {exc!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(exc),
                "exception_type": type(exc).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "executorch_read_failed",
            },
            rule_code="S902",
        )
        result.finish(success=False)
        return result

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            header = self._read_header(path, length=8)
            valid_binary_program = _is_executorch_binary_signature(header) and _is_valid_executorch_binary(
                path,
                propagate_io_errors=True,
            )
        except OSError as exc:
            return self._finish_read_failure(result, path, exc)
        if valid_binary_program:
            result.add_check(
                name="ExecuTorch Binary Format Validation",
                passed=True,
                message="Valid ExecuTorch binary program format detected",
                location=path,
                details={"path": path, "format": "executorch_binary"},
            )

        should_scan_archive = header.startswith(b"PK")
        if not should_scan_archive:
            try:
                should_scan_archive = zipfile.is_zipfile(path)
            except OSError as exc:
                return self._finish_read_failure(result, path, exc)

        if valid_binary_program and not should_scan_archive:
            result.bytes_scanned = file_size
            result.finish(success=True)
            return result

        if not should_scan_archive:
            result.add_check(
                name="ExecuTorch Archive Format Validation",
                passed=False,
                message=f"Not a valid ExecuTorch archive: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
                rule_code="S104",
            )
            result.finish(success=False)
            return result

        try:
            self.current_file_path = path
            with zipfile.ZipFile(path, "r") as z:
                safe_entries: list[zipfile.ZipInfo] = []
                for entry in z.infolist():
                    name = entry.filename
                    temp_base = os.path.join(tempfile.gettempdir(), "extract")
                    _, is_safe = sanitize_archive_path(name, temp_base)
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
                    safe_entries.append(entry)

                pickle_entries = self._discover_pickle_entries(z, safe_entries, result)
                pickle_files = [entry.filename for entry in pickle_entries]
                result.metadata["pickle_files"] = pickle_files
                bytes_scanned = 0
                pickle_member_failure_count = 0
                pickle_member_failures: list[dict[str, Any]] = []

                for member_info in pickle_entries:
                    name = member_info.filename
                    bytes_scanned += member_info.file_size
                    if self.pickle_scanner is None:
                        add_scanner_selection_skip_check(
                            result,
                            f"{path}:{name}",
                            "pickle",
                            self.scanner_selection,
                            context="embedded ExecuTorch pickle analysis",
                        )
                        continue

                    try:
                        with z.open(member_info, "r") as file_like:
                            sub_result = self.pickle_scanner.scan_stream(
                                cast(BinaryIO, file_like),
                                member_info.file_size,
                                source=f"{path}:{name}",
                            )
                    except Exception as exc:
                        pickle_member_failure_count += 1
                        if len(pickle_member_failures) < _PICKLE_DISCOVERY_MAX_FAILURE_SAMPLES:
                            safe_name = self._bounded_discovery_text(name)
                            pickle_member_failures.append(
                                {
                                    "zip_entry": safe_name,
                                    "exception": self._bounded_discovery_text(exc),
                                    "exception_type": type(exc).__name__,
                                    "location": self._bounded_discovery_text(f"{path}:{safe_name}"),
                                }
                            )
                        continue
                    apply_pickle_member_context(sub_result, archive_path=path, member_name=name)
                    result.merge(sub_result)

                if pickle_member_failure_count:
                    mark_inconclusive_scan_result(result, _PICKLE_MEMBER_SCAN_INCOMPLETE_REASON)
                    noun = "member" if pickle_member_failure_count == 1 else "members"
                    result.add_check(
                        name="Embedded Pickle Scan",
                        passed=False,
                        message=(f"Unable to scan {pickle_member_failure_count} embedded ExecuTorch pickle {noun}"),
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "entries": pickle_member_failures,
                            "failed_count": pickle_member_failure_count,
                            "reported_failure_count": len(pickle_member_failures),
                            "analysis_incomplete": True,
                            "scan_outcome_reason": _PICKLE_MEMBER_SCAN_INCOMPLETE_REASON,
                        },
                    )

                for entry in safe_entries:
                    name = entry.filename
                    if name.casefold().endswith(".py"):
                        result.add_check(
                            name="Python File Detection",
                            passed=False,
                            message=f"Python code file found in ExecuTorch model: {name}",
                            severity=IssueSeverity.INFO,
                            location=f"{path}:{name}",
                            details={"file": name},
                            rule_code="S507",  # Python embedded code
                        )
                        result.add_check(
                            name="Executable File Detection",
                            passed=False,
                            message=f"Executable file found in ExecuTorch model: {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"file": name},
                            rule_code="S104",
                        )

                result.bytes_scanned = bytes_scanned
        except zipfile.BadZipFile:
            result.add_check(
                name="ZIP File Format Validation",
                passed=False,
                message=f"Not a valid zip file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
                rule_code="S902",
            )
            result.finish(success=False)
            return result
        except OSError as exc:
            return self._finish_read_failure(result, path, exc)
        except Exception as e:  # pragma: no cover - unexpected errors
            result.add_check(
                name="ExecuTorch File Scan",
                passed=False,
                message=f"Error scanning ExecuTorch file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        result.finish(success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME)
        return result
