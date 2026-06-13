"""Scanner for ExecuTorch model files (.pte)."""

import io
import os
import pickle
import pickletools
import tempfile
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, Final, cast

from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ..scanner_selection import add_scanner_selection_skip_check, embedded_pickle_scanner
from ..utils import sanitize_archive_path
from ..utils.file.detection import (
    PROTO0_1_START_BYTES,
    _is_executorch_binary_signature,
    _is_valid_executorch_binary,
    _looks_like_binary_pickle_protocol,
    _looks_like_proto0_or_1_pickle,
    is_executorch_archive,
)
from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner
from .picklescan_adapter import (
    apply_pickle_member_context,
)
from .pytorch_binary_scanner import PyTorchBinaryScanner

CONTENT_ROUTE_BLOCKED_EXTENSIONS = frozenset({".bin", ".meta", ".pb"})
_PICKLE_PROTOCOLLESS_BINARY_START_BYTES = frozenset(
    ord(opcode.code) for opcode in pickletools.opcodes if opcode.proto >= 1 and opcode.name != "PROTO"
)
_PICKLE_DISCOVERY_SHORT_PROBE_BYTES = 16
_PICKLE_DISCOVERY_MAX_ENTRIES = 10_000
_PICKLE_DISCOVERY_MAX_PROBE_BYTES = 4 * 1024 * 1024
_PICKLE_DISCOVERY_MAX_FAILURE_SAMPLES = 20
_PICKLE_DISCOVERY_MAX_DIAGNOSTIC_CHARS = 512
_PICKLE_DISCOVERY_MAX_GLOBAL_COMMENT_TOKENS = 64
_PICKLE_DISCOVERY_INCOMPLETE_REASON = "executorch_pickle_discovery_incomplete"


class _PickleDiscoveryBudgetExceeded(ValueError):
    """Raised when hidden-pickle discovery cannot inspect another candidate safely."""


_ZIP_EOCD_SIGNATURE: Final[bytes] = b"PK\x05\x06"
_ZIP_EOCD_MIN_SIZE: Final[int] = 22
_ZIP_MAX_COMMENT_SIZE: Final[int] = 0xFFFF
_ZIP64_EOCD_LOCATOR_SIGNATURE: Final[bytes] = b"PK\x06\x07"
_ZIP64_EOCD_LOCATOR_SIZE: Final[int] = 20
_ZIP64_EOCD_SIGNATURE: Final[bytes] = b"PK\x06\x06"
_ZIP64_EOCD_MIN_SIZE: Final[int] = 56
_ZIP64_SENTINEL_ENTRY_COUNT: Final[int] = 0xFFFF
_ZIP_CENTRAL_DIRECTORY_SIGNATURE: Final[bytes] = b"PK\x01\x02"
_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE: Final[int] = 46
_ZIP_CENTRAL_DIRECTORY_DIGITAL_SIGNATURE: Final[bytes] = b"PK\x05\x05"
_ZIP_CENTRAL_DIRECTORY_DIGITAL_SIGNATURE_HEADER_SIZE: Final[int] = 6
_ZIP_PREAMBLE_SCAN_CHUNK_SIZE: Final[int] = 64 * 1024
_ZIP_MAX_PREAMBLE_EOCD_CANDIDATES: Final[int] = 64
_ZIP_SNAPSHOT_MEMORY_LIMIT: Final[int] = 8 * 1024 * 1024
_ZIP_SNAPSHOT_CHUNK_SIZE: Final[int] = 1024 * 1024
PYTORCH_BINARY_PRIMARY_SCANNED_CONFIG_KEY = "_pytorch_binary_primary_scanned"


class ExecuTorchScanner(BaseScanner):
    """Scanner for PyTorch Mobile/ExecuTorch archives (.ptl, .pte)."""

    name = "executorch"
    description = "Scans ExecuTorch mobile model files for suspicious content"
    supported_extensions: ClassVar[list[str]] = [".ptl", ".pte"]
    DEFAULT_MAX_ARCHIVE_ENTRIES: ClassVar[int] = 10000
    DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE: ClassVar[int] = 64 * 1024 * 1024
    DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE: ClassVar[int] = 10 * 1024 * 1024 * 1024
    MAX_COMPRESSION_RATIO: ClassVar[int] = 100
    MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE: ClassVar[int] = 1024 * 1024
    UNLIMITED_ARCHIVE_SIZE: ClassVar[int] = 1024 * 1024 * 1024 * 1024
    ZIP_ENTRY_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_entry_limit"
    ZIP_CENTRAL_DIRECTORY_INVALID_REASON: ClassVar[str] = "executorch_zip_central_directory_invalid"
    ZIP_CENTRAL_DIRECTORY_SIZE_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_central_directory_size_limit"
    ZIP_AGGREGATE_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_total_uncompressed_size_limit"
    ZIP_PICKLE_MEMBER_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_pickle_member_size_limit"
    ZIP_COMPRESSION_RATIO_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_compression_ratio_limit"
    ZIP_PICKLE_MEMBER_READ_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_pickle_member_read_failed"

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
        self.max_archive_entries = self._normalize_positive_int_config(
            self.config.get(
                "max_executorch_zip_entries",
                self.config.get("max_archive_entries", self.config.get("max_zip_entries")),
            ),
            self.DEFAULT_MAX_ARCHIVE_ENTRIES,
        )
        self.max_central_directory_size = self._normalize_positive_int_config(
            self.config.get("max_executorch_zip_central_directory_size"),
            self.DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE,
        )
        self.max_total_uncompressed_size = self._get_max_total_uncompressed_size()
        self.min_compression_bomb_uncompressed_size = self._normalize_positive_int_config(
            self.config.get("zip_min_compression_bomb_uncompressed_size"),
            self.MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE,
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

    @classmethod
    def _get_max_total_uncompressed_size_from_config(cls, config: dict[str, Any]) -> int:
        """Return the configured aggregate ExecuTorch ZIP budget."""
        positive_limits: list[int] = []
        configured_limit = config.get("max_executorch_zip_total_uncompressed_size")
        if configured_limit is None:
            configured_limit = config.get("max_zip_total_uncompressed_size")

        if configured_limit is not None:
            is_unlimited = (
                isinstance(configured_limit, int) and not isinstance(configured_limit, bool) and configured_limit == 0
            )
            if not is_unlimited:
                positive_limits.append(
                    cls._normalize_positive_int_config(configured_limit, cls.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE)
                )
        else:
            positive_limits.append(cls.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE)

        for config_key in ("max_total_size", "max_file_size"):
            configured_public_limit = config.get(config_key)
            if configured_public_limit is None or (
                isinstance(configured_public_limit, int)
                and not isinstance(configured_public_limit, bool)
                and configured_public_limit == 0
            ):
                continue
            positive_limits.append(
                cls._normalize_positive_int_config(configured_public_limit, cls.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE)
            )

        return min(positive_limits) if positive_limits else cls.UNLIMITED_ARCHIVE_SIZE

    def _get_max_total_uncompressed_size(self) -> int:
        return self._get_max_total_uncompressed_size_from_config(self.config)

    @staticmethod
    def _find_zip_eocd_index(tail: bytes) -> tuple[int, bool, tuple[int, ...]] | None:
        candidate_indexes: list[int] = []
        search_start = 0
        while True:
            candidate_index = tail.find(_ZIP_EOCD_SIGNATURE, search_start)
            if candidate_index < 0:
                break
            if candidate_index + _ZIP_EOCD_MIN_SIZE <= len(tail):
                candidate_indexes.append(candidate_index)
            search_start = candidate_index + 1

        if not candidate_indexes:
            return None

        exact_candidates = []
        for candidate_index in candidate_indexes:
            comment_length = int.from_bytes(tail[candidate_index + 20 : candidate_index + 22], "little")
            if candidate_index + _ZIP_EOCD_MIN_SIZE + comment_length == len(tail):
                exact_candidates.append(candidate_index)

        selected_index = candidate_indexes[-1]
        ambiguous = len(exact_candidates) > 1 or (len(exact_candidates) == 1 and exact_candidates[0] != selected_index)
        return selected_index, ambiguous, tuple(candidate_indexes)

    @staticmethod
    def _count_central_directory_entries(
        handle: BinaryIO,
        *,
        directory_start: int,
        directory_size: int,
        entry_limit: int,
        local_header_offsets: list[int] | None = None,
    ) -> tuple[int, bool]:
        """Count bounded central-directory records without constructing ZipInfo objects."""
        if directory_start < 0 or directory_size < 0:
            return 0, False

        handle.seek(directory_start)
        remaining = directory_size
        entry_count = 0
        while remaining > 0:
            signature = handle.read(4)
            if len(signature) != 4:
                return entry_count, False

            if signature == _ZIP_CENTRAL_DIRECTORY_DIGITAL_SIGNATURE:
                signature_size_bytes = handle.read(2)
                if len(signature_size_bytes) != 2:
                    return entry_count, False
                signature_size = int.from_bytes(signature_size_bytes, "little")
                record_size = _ZIP_CENTRAL_DIRECTORY_DIGITAL_SIGNATURE_HEADER_SIZE + signature_size
                if record_size != remaining:
                    return entry_count, False
                handle.seek(signature_size, os.SEEK_CUR)
                remaining -= record_size
                continue

            if signature != _ZIP_CENTRAL_DIRECTORY_SIGNATURE or remaining < _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE:
                return entry_count, False

            header_tail = handle.read(_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE - 4)
            if len(header_tail) != _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE - 4:
                return entry_count, False
            header = signature + header_tail

            filename_length = int.from_bytes(header[28:30], "little")
            extra_length = int.from_bytes(header[30:32], "little")
            comment_length = int.from_bytes(header[32:34], "little")
            if local_header_offsets is not None:
                local_header_offsets.append(int.from_bytes(header[42:46], "little"))
            record_size = _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE + filename_length + extra_length + comment_length
            if record_size > remaining:
                return entry_count, False

            entry_count += 1
            if entry_count > entry_limit:
                return entry_count, True
            handle.seek(record_size - _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE, os.SEEK_CUR)
            remaining -= record_size

        return entry_count, True

    @classmethod
    def _has_prior_valid_zip_in_preamble(
        cls,
        handle: BinaryIO,
        *,
        preamble_end: int,
        entry_limit: int,
        central_directory_size_limit: int,
    ) -> bool:
        """Detect a complete ZIP hidden before the selected archive's first member."""
        if preamble_end < _ZIP_EOCD_MIN_SIZE:
            return False

        overlap = b""
        position = 0
        last_candidate_offset = -1
        candidate_count = 0
        while position < preamble_end:
            handle.seek(position)
            chunk = handle.read(min(_ZIP_PREAMBLE_SCAN_CHUNK_SIZE, preamble_end - position))
            if not chunk:
                break
            window = overlap + chunk
            window_start = position - len(overlap)
            search_start = 0
            while True:
                candidate_index = window.find(_ZIP_EOCD_SIGNATURE, search_start)
                if candidate_index < 0:
                    break
                search_start = candidate_index + 1
                candidate_offset = window_start + candidate_index
                if candidate_offset <= last_candidate_offset:
                    continue
                last_candidate_offset = candidate_offset
                candidate_count += 1
                if candidate_count > _ZIP_MAX_PREAMBLE_EOCD_CANDIDATES:
                    return True

                handle.seek(candidate_offset)
                eocd = handle.read(_ZIP_EOCD_MIN_SIZE)
                if len(eocd) != _ZIP_EOCD_MIN_SIZE:
                    continue
                comment_length = int.from_bytes(eocd[20:22], "little")
                if candidate_offset + _ZIP_EOCD_MIN_SIZE + comment_length > preamble_end:
                    continue

                entry_count = int.from_bytes(eocd[10:12], "little")
                directory_size = int.from_bytes(eocd[12:16], "little")
                if cls._has_valid_prior_zip64_directory(
                    handle,
                    eocd_offset=candidate_offset,
                    entry_limit=entry_limit,
                    central_directory_size_limit=central_directory_size_limit,
                ):
                    return True
                if entry_count == _ZIP64_SENTINEL_ENTRY_COUNT:
                    continue
                if directory_size == 0:
                    continue

                directory_start = candidate_offset - directory_size
                if directory_start < 0:
                    continue
                if directory_size > central_directory_size_limit:
                    handle.seek(directory_start)
                    if handle.read(4) == _ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                        return True
                    continue
                parsed_count, parsed_completely = cls._count_central_directory_entries(
                    handle,
                    directory_start=directory_start,
                    directory_size=directory_size,
                    entry_limit=entry_limit,
                )
                if parsed_count > entry_limit or (parsed_completely and parsed_count > 0):
                    return True

            overlap = window[-(_ZIP_EOCD_MIN_SIZE - 1) :]
            position += len(chunk)
        return False

    @classmethod
    def _has_valid_prior_zip64_directory(
        cls,
        handle: BinaryIO,
        *,
        eocd_offset: int,
        entry_limit: int,
        central_directory_size_limit: int,
    ) -> bool:
        locator_offset = eocd_offset - _ZIP64_EOCD_LOCATOR_SIZE
        if locator_offset < 0:
            return False
        handle.seek(locator_offset)
        locator = handle.read(_ZIP64_EOCD_LOCATOR_SIZE)
        if len(locator) != _ZIP64_EOCD_LOCATOR_SIZE or not locator.startswith(_ZIP64_EOCD_LOCATOR_SIGNATURE):
            return False
        if int.from_bytes(locator[4:8], "little") != 0 or int.from_bytes(locator[16:20], "little") != 1:
            return False

        stored_record_offset = int.from_bytes(locator[8:16], "little")
        search_start = max(0, locator_offset - _ZIP_PREAMBLE_SCAN_CHUNK_SIZE)
        handle.seek(search_start)
        record_window = handle.read(locator_offset - search_start)
        candidate_offsets = [stored_record_offset]
        search_index = 0
        while True:
            record_index = record_window.find(_ZIP64_EOCD_SIGNATURE, search_index)
            if record_index < 0:
                break
            candidate_offsets.append(search_start + record_index)
            search_index = record_index + 1

        for record_offset in dict.fromkeys(candidate_offsets):
            if record_offset < 0 or record_offset >= locator_offset:
                continue
            handle.seek(record_offset)
            record = handle.read(_ZIP64_EOCD_MIN_SIZE)
            if len(record) != _ZIP64_EOCD_MIN_SIZE or not record.startswith(_ZIP64_EOCD_SIGNATURE):
                continue
            record_size = int.from_bytes(record[4:12], "little")
            if record_size < _ZIP64_EOCD_MIN_SIZE - 12 or record_offset + 12 + record_size != locator_offset:
                continue
            if int.from_bytes(record[16:20], "little") != 0 or int.from_bytes(record[20:24], "little") != 0:
                continue
            directory_size = int.from_bytes(record[40:48], "little")
            if directory_size == 0:
                continue
            directory_start = record_offset - directory_size
            if directory_start < 0:
                continue
            if directory_size > central_directory_size_limit:
                handle.seek(directory_start)
                if handle.read(4) == _ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                    return True
                continue
            parsed_count, parsed_completely = cls._count_central_directory_entries(
                handle,
                directory_start=directory_start,
                directory_size=directory_size,
                entry_limit=entry_limit,
            )
            if parsed_count > entry_limit or (parsed_completely and parsed_count > 0):
                return True
        return False

    @classmethod
    def _has_prior_valid_eocd_overlay(
        cls,
        handle: BinaryIO,
        *,
        tail: bytes,
        tail_start: int,
        selected_index: int,
        candidate_indexes: tuple[int, ...],
        entry_limit: int,
        central_directory_size_limit: int,
    ) -> bool:
        """Detect a complete ZIP archive hidden before a trailing EOCD overlay."""
        for candidate_index in candidate_indexes:
            if candidate_index >= selected_index:
                continue
            comment_length = int.from_bytes(tail[candidate_index + 20 : candidate_index + 22], "little")
            if candidate_index + _ZIP_EOCD_MIN_SIZE + comment_length > selected_index:
                continue

            entry_count = int.from_bytes(tail[candidate_index + 10 : candidate_index + 12], "little")
            directory_size = int.from_bytes(tail[candidate_index + 12 : candidate_index + 16], "little")
            if entry_count == 0 and directory_size == 0:
                continue

            candidate_absolute_index = tail_start + candidate_index
            if entry_count == _ZIP64_SENTINEL_ENTRY_COUNT:
                locator_offset = candidate_absolute_index - _ZIP64_EOCD_LOCATOR_SIZE
                if locator_offset >= 0:
                    handle.seek(locator_offset)
                    if handle.read(4) == _ZIP64_EOCD_LOCATOR_SIGNATURE:
                        return True
                continue

            directory_start = candidate_absolute_index - directory_size
            if directory_size == 0 or directory_start < 0:
                continue
            if directory_size > central_directory_size_limit:
                handle.seek(directory_start)
                if handle.read(4) == _ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                    return True
                continue

            parsed_count, parsed_completely = cls._count_central_directory_entries(
                handle,
                directory_start=directory_start,
                directory_size=directory_size,
                entry_limit=entry_limit,
            )
            if parsed_count > entry_limit or (parsed_completely and parsed_count > 0):
                return True
        return False

    @classmethod
    def _read_zip_entry_count(
        cls,
        handle: BinaryIO,
        file_size: int,
        entry_limit: int,
        central_directory_size_limit: int,
    ) -> tuple[int, int, bool] | None:
        """Read and validate bounded central-directory metadata without ZipInfo allocation."""
        if file_size < _ZIP_EOCD_MIN_SIZE:
            return None

        tail_size = min(file_size, _ZIP_EOCD_MIN_SIZE + _ZIP_MAX_COMMENT_SIZE)
        handle.seek(file_size - tail_size)
        tail = handle.read(tail_size)
        eocd_match = cls._find_zip_eocd_index(tail)
        if eocd_match is None:
            return None
        eocd_index, eocd_ambiguous, candidate_indexes = eocd_match

        entry_count = int.from_bytes(tail[eocd_index + 10 : eocd_index + 12], "little")
        central_directory_size = int.from_bytes(tail[eocd_index + 12 : eocd_index + 16], "little")
        central_directory_offset = int.from_bytes(tail[eocd_index + 16 : eocd_index + 20], "little")
        tail_start = file_size - tail_size
        if eocd_ambiguous or cls._has_prior_valid_eocd_overlay(
            handle,
            tail=tail,
            tail_start=tail_start,
            selected_index=eocd_index,
            candidate_indexes=candidate_indexes,
            entry_limit=entry_limit,
            central_directory_size_limit=central_directory_size_limit,
        ):
            return entry_count, central_directory_size, False

        central_directory_end = tail_start + eocd_index
        locator_offset = central_directory_end - _ZIP64_EOCD_LOCATOR_SIZE
        zip64_locator_found = False
        if locator_offset >= 0:
            handle.seek(locator_offset)
            locator = handle.read(_ZIP64_EOCD_LOCATOR_SIZE)
            if locator.startswith(_ZIP64_EOCD_LOCATOR_SIGNATURE):
                zip64_locator_found = True
                stored_zip64_eocd_offset = int.from_bytes(locator[8:16], "little")
                candidate_offsets = [stored_zip64_eocd_offset]
                physical_zip64_eocd_offset = locator_offset - _ZIP64_EOCD_MIN_SIZE
                if physical_zip64_eocd_offset != stored_zip64_eocd_offset:
                    candidate_offsets.append(physical_zip64_eocd_offset)

                zip64_eocd = b""
                for candidate_offset in candidate_offsets:
                    if candidate_offset < 0:
                        continue
                    handle.seek(candidate_offset)
                    candidate = handle.read(_ZIP64_EOCD_MIN_SIZE)
                    if len(candidate) >= _ZIP64_EOCD_MIN_SIZE and candidate.startswith(_ZIP64_EOCD_SIGNATURE):
                        zip64_eocd = candidate
                        central_directory_end = candidate_offset
                        break
                if not zip64_eocd:
                    return entry_count, central_directory_size, False

                entry_count = int.from_bytes(zip64_eocd[32:40], "little")
                central_directory_size = int.from_bytes(zip64_eocd[40:48], "little")
                central_directory_offset = int.from_bytes(zip64_eocd[48:56], "little")

        if entry_count == _ZIP64_SENTINEL_ENTRY_COUNT and not zip64_locator_found:
            return entry_count, central_directory_size, False
        if entry_count > entry_limit or central_directory_size > central_directory_size_limit:
            return entry_count, central_directory_size, True

        central_directory_start = central_directory_end - central_directory_size
        if central_directory_start < 0 or central_directory_offset > central_directory_start:
            return entry_count, central_directory_size, False

        local_header_offsets: list[int] = []
        parsed_entry_count, parsed_completely = cls._count_central_directory_entries(
            handle,
            directory_start=central_directory_start,
            directory_size=central_directory_size,
            entry_limit=entry_limit,
            local_header_offsets=local_header_offsets,
        )
        archive_prefix_size = central_directory_start - central_directory_offset
        finite_local_offsets = [offset for offset in local_header_offsets if offset != 0xFFFFFFFF]
        preamble_end = archive_prefix_size + min(finite_local_offsets, default=0)
        if preamble_end < 0 or preamble_end > central_directory_start:
            return max(entry_count, parsed_entry_count), central_directory_size, False
        if cls._has_prior_valid_zip_in_preamble(
            handle,
            preamble_end=preamble_end,
            entry_limit=entry_limit,
            central_directory_size_limit=central_directory_size_limit,
        ):
            return max(entry_count, parsed_entry_count), central_directory_size, False
        return (
            max(entry_count, parsed_entry_count),
            central_directory_size,
            parsed_completely and parsed_entry_count == entry_count,
        )

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
        has_protocol = _looks_like_binary_pickle_protocol(sample)
        if not has_protocol and not (
            allow_protocolless and sample and sample[0] in _PICKLE_PROTOCOLLESS_BINARY_START_BYTES
        ):
            return False

        parse_sample = sample
        if has_protocol and sample[1] > pickle.HIGHEST_PROTOCOL:
            parse_sample = sample[:1] + bytes([pickle.HIGHEST_PROTOCOL]) + sample[2:]

        op_count = 0
        try:
            for opcode, _arg, _pos in pickletools.genops(parse_sample):
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

    @staticmethod
    def _without_global_comment_tokens(sample: bytes) -> bytes | None:
        candidate = sample
        removed_token_count = 0

        while (token_index := candidate.find(b"#\n")) > 0:
            last_opcode_name: str | None = None
            try:
                for opcode, _arg, _pos in pickletools.genops(candidate[:token_index]):
                    last_opcode_name = opcode.name
            except ValueError as exc:
                if not str(exc).startswith("pickle exhausted before seeing STOP"):
                    return None
            except Exception:
                return None

            if last_opcode_name != "GLOBAL":
                return None

            token_end = token_index
            while candidate.startswith(b"#\n", token_end):
                removed_token_count += 1
                if removed_token_count > _PICKLE_DISCOVERY_MAX_GLOBAL_COMMENT_TOKENS:
                    raise _PickleDiscoveryBudgetExceeded("too many GLOBAL-adjacent pickle comment tokens")
                token_end += 2
            candidate = candidate[:token_index] + candidate[token_end:]

        return candidate if removed_token_count else None

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
            has_binary_protocol = _looks_like_binary_pickle_protocol(data_start)
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
            if not is_pickle:
                uncommented_sample = self._without_global_comment_tokens(sample)
                if uncommented_sample is not None:
                    is_pickle = _looks_like_proto0_or_1_pickle(
                        uncommented_sample,
                        sample_is_prefix=sample_is_prefix,
                    )

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

    def _check_opened_file_size_limit(
        self,
        result: ScanResult,
        path: str,
        archive_handle: BinaryIO,
    ) -> tuple[os.stat_result, ScanResult | None]:
        """Revalidate the archive size on the descriptor used for parsing."""
        opened_stat = os.fstat(archive_handle.fileno())
        opened_file_size = opened_stat.st_size
        result.checks = [check for check in result.checks if check.name != "File Size Limit"]
        result.metadata["file_size"] = opened_file_size

        if self.max_file_read_size > 0 and opened_file_size > self.max_file_read_size:
            mark_inconclusive_scan_result(result, "max_file_read_size_exceeded")
            result.add_check(
                name="File Size Limit",
                passed=False,
                message=f"File too large: {opened_file_size} bytes (max: {self.max_file_read_size})",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "file_size": opened_file_size,
                    "max_file_read_size": self.max_file_read_size,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "max_file_read_size_exceeded",
                },
            )
            result.finish(success=False)
            return opened_stat, result

        if self.max_file_read_size > 0:
            result.add_check(
                name="File Size Limit",
                passed=True,
                message="File size within limit",
                location=path,
                details={
                    "file_size": opened_file_size,
                    "max_file_read_size": self.max_file_read_size,
                },
            )
        return opened_stat, None

    @staticmethod
    def _stable_stat_identity(stat_result: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_size,
            stat_result.st_mtime_ns,
            stat_result.st_ctime_ns,
        )

    @classmethod
    def _snapshot_archive(
        cls,
        source_handle: BinaryIO,
        opened_stat: os.stat_result,
    ) -> BinaryIO:
        """Copy one stable archive view before parsing attacker-controlled metadata."""
        snapshot: BinaryIO
        if opened_stat.st_size <= _ZIP_SNAPSHOT_MEMORY_LIMIT:
            snapshot = io.BytesIO()
        else:
            snapshot = cast(BinaryIO, tempfile.TemporaryFile(mode="w+b"))  # noqa: SIM115
        try:
            source_handle.seek(0)
            remaining = opened_stat.st_size
            while remaining > 0:
                chunk = source_handle.read(min(_ZIP_SNAPSHOT_CHUNK_SIZE, remaining))
                if not chunk:
                    raise OSError("ExecuTorch archive changed while creating a private snapshot")
                snapshot.write(chunk)
                remaining -= len(chunk)
            if source_handle.read(1):
                raise OSError("ExecuTorch archive grew while creating a private snapshot")
            final_stat = os.fstat(source_handle.fileno())
            if cls._stable_stat_identity(final_stat) != cls._stable_stat_identity(opened_stat):
                raise OSError("ExecuTorch archive changed while creating a private snapshot")
            snapshot.seek(0)
            return snapshot
        except Exception:
            snapshot.close()
            raise

    @classmethod
    def _source_changed_after_snapshot(
        cls,
        source_handle: BinaryIO,
        opened_stat: os.stat_result,
        path: str,
    ) -> bool:
        try:
            descriptor_stat = os.fstat(source_handle.fileno())
            path_stat = os.stat(path)
        except OSError:
            return True
        expected = cls._stable_stat_identity(opened_stat)
        return (
            cls._stable_stat_identity(descriptor_stat) != expected or cls._stable_stat_identity(path_stat) != expected
        )

    @staticmethod
    def _add_source_changed_failure(result: ScanResult, path: str) -> None:
        reason = "executorch_file_changed_during_scan"
        mark_inconclusive_scan_result(result, reason)
        result.add_check(
            name="ExecuTorch File Stability",
            passed=False,
            message="ExecuTorch archive changed while it was being scanned; refusing a stale success result",
            severity=IssueSeverity.WARNING,
            location=path,
            details={
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )

    @classmethod
    def _add_zip_budget_failure(
        cls,
        result: ScanResult,
        path: str,
        *,
        check_name: str,
        message: str,
        details: dict[str, Any],
        reason: str,
        rule_code: str = "S410",
    ) -> None:
        mark_inconclusive_scan_result(result, reason)
        result.add_check(
            name=check_name,
            passed=False,
            message=message,
            severity=IssueSeverity.WARNING,
            location=path,
            details={
                **details,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code=rule_code,
        )

    @classmethod
    def _finish_zip_budget_failure(
        cls,
        result: ScanResult,
        path: str,
        *,
        check_name: str,
        message: str,
        details: dict[str, Any],
        reason: str,
        rule_code: str = "S410",
    ) -> ScanResult:
        cls._add_zip_budget_failure(
            result,
            path,
            check_name=check_name,
            message=message,
            details=details,
            reason=reason,
            rule_code=rule_code,
        )
        result.finish(success=False)
        return result

    def _check_zip_entry_count_preflight(
        self,
        result: ScanResult,
        path: str,
        archive_handle: BinaryIO,
        file_size: int,
    ) -> ScanResult | None:
        preflight = self._read_zip_entry_count(
            archive_handle,
            file_size,
            self.max_archive_entries,
            self.max_central_directory_size,
        )
        if preflight is None:
            return None
        entry_count, central_directory_size, central_directory_valid = preflight

        result.metadata["executorch_zip_entry_count"] = entry_count
        result.metadata["max_executorch_zip_entries"] = self.max_archive_entries
        result.metadata["executorch_zip_central_directory_size"] = central_directory_size
        result.metadata["max_executorch_zip_central_directory_size"] = self.max_central_directory_size

        if entry_count > self.max_archive_entries:
            return self._finish_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Entry Count Preflight",
                message=(
                    f"ExecuTorch ZIP contains too many entries before archive open "
                    f"({entry_count} > {self.max_archive_entries})"
                ),
                details={
                    "entry_count": entry_count,
                    "max_entries": self.max_archive_entries,
                    "phase": "pre_open",
                },
                reason=self.ZIP_ENTRY_LIMIT_INCONCLUSIVE_REASON,
            )

        if central_directory_size > self.max_central_directory_size:
            return self._finish_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Central Directory Size Preflight",
                message=(
                    f"ExecuTorch ZIP central directory exceeds the pre-open allocation limit "
                    f"({central_directory_size} > {self.max_central_directory_size} bytes)"
                ),
                details={
                    "central_directory_size": central_directory_size,
                    "max_central_directory_size": self.max_central_directory_size,
                    "phase": "pre_open",
                },
                reason=self.ZIP_CENTRAL_DIRECTORY_SIZE_LIMIT_INCONCLUSIVE_REASON,
            )

        if central_directory_valid:
            return None
        return self._finish_zip_budget_failure(
            result,
            path,
            check_name="ExecuTorch ZIP Central Directory Preflight",
            message="ExecuTorch ZIP central-directory metadata is inconsistent; refusing incomplete analysis",
            details={
                "entry_count": entry_count,
                "central_directory_size": central_directory_size,
                "phase": "pre_open",
            },
            reason=self.ZIP_CENTRAL_DIRECTORY_INVALID_REASON,
            rule_code="S902",
        )

    def _check_zip_entry_count(
        self, result: ScanResult, path: str, entries: list[zipfile.ZipInfo]
    ) -> ScanResult | None:
        entry_count = len(entries)
        result.metadata["executorch_zip_entry_count"] = entry_count
        result.metadata["max_executorch_zip_entries"] = self.max_archive_entries
        if entry_count > self.max_archive_entries:
            return self._finish_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Entry Count Limit",
                message=f"ExecuTorch ZIP contains too many entries ({entry_count} > {self.max_archive_entries})",
                details={
                    "entry_count": entry_count,
                    "max_entries": self.max_archive_entries,
                    "phase": "post_open",
                },
                reason=self.ZIP_ENTRY_LIMIT_INCONCLUSIVE_REASON,
            )

        result.add_check(
            name="ExecuTorch ZIP Entry Count Limit",
            passed=True,
            message=f"ExecuTorch ZIP entry count ({entry_count}) is within limits",
            location=path,
            details={
                "entry_count": entry_count,
                "max_entries": self.max_archive_entries,
            },
        )
        return None

    def _check_pickle_member_budgets(
        self,
        result: ScanResult,
        path: str,
        pickle_entries: list[zipfile.ZipInfo],
    ) -> tuple[list[zipfile.ZipInfo], bool]:
        small_high_ratio_uncompressed_size = 0
        small_high_ratio_compressed_size = 0
        small_high_ratio_entries: list[zipfile.ZipInfo] = []
        oversized_entries: list[zipfile.ZipInfo] = []
        large_high_ratio_entries: list[tuple[zipfile.ZipInfo, float | None]] = []
        blocked_entry_ids: set[int] = set()
        analysis_incomplete = False
        pickle_member_limit = self.pickle_scanner.max_file_read_size if self.pickle_scanner is not None else 0
        for entry in pickle_entries:
            if pickle_member_limit > 0 and entry.file_size > pickle_member_limit:
                oversized_entries.append(entry)
                blocked_entry_ids.add(id(entry))
                analysis_incomplete = True
                continue

            compression_ratio = entry.file_size / entry.compress_size if entry.compress_size > 0 else None
            exceeds_ratio = compression_ratio is None or compression_ratio > self.MAX_COMPRESSION_RATIO
            if not exceeds_ratio:
                continue

            if entry.file_size < self.min_compression_bomb_uncompressed_size:
                small_high_ratio_uncompressed_size += entry.file_size
                small_high_ratio_compressed_size += entry.compress_size
                small_high_ratio_entries.append(entry)
                continue

            large_high_ratio_entries.append((entry, compression_ratio))
            blocked_entry_ids.add(id(entry))
            analysis_incomplete = True

        if oversized_entries:
            first_entry = oversized_entries[0]
            self._add_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Pickle Member Size Limit",
                message=(
                    f"ExecuTorch pickle member {first_entry.filename} exceeds the pickle scan limit "
                    f"({first_entry.file_size} > {pickle_member_limit} bytes); skipping "
                    f"{len(oversized_entries)} oversized member content scan(s)"
                ),
                details={
                    "member": first_entry.filename,
                    "member_count": len(oversized_entries),
                    "uncompressed_size": first_entry.file_size,
                    "max_pickle_member_size": pickle_member_limit,
                },
                reason=self.ZIP_PICKLE_MEMBER_LIMIT_INCONCLUSIVE_REASON,
            )

        if large_high_ratio_entries:
            first_entry, first_ratio = large_high_ratio_entries[0]
            ratio_text = "infinite" if first_ratio is None else f"{first_ratio:.1f}x"
            self._add_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Pickle Compression Ratio Limit",
                message=(
                    f"ExecuTorch pickle member {first_entry.filename} has a suspicious compression ratio "
                    f"({ratio_text}); skipping {len(large_high_ratio_entries)} suspicious member content scan(s)"
                ),
                details={
                    "member": first_entry.filename,
                    "member_count": len(large_high_ratio_entries),
                    "compressed_size": first_entry.compress_size,
                    "uncompressed_size": first_entry.file_size,
                    "compression_ratio": first_ratio,
                    "max_compression_ratio": self.MAX_COMPRESSION_RATIO,
                    "min_uncompressed_size": self.min_compression_bomb_uncompressed_size,
                },
                reason=self.ZIP_COMPRESSION_RATIO_INCONCLUSIVE_REASON,
            )

        if small_high_ratio_uncompressed_size >= self.min_compression_bomb_uncompressed_size:
            aggregate_ratio = (
                small_high_ratio_uncompressed_size / small_high_ratio_compressed_size
                if small_high_ratio_compressed_size > 0
                else None
            )
            ratio_text = "infinite" if aggregate_ratio is None else f"{aggregate_ratio:.1f}x"
            self._add_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Pickle Compression Ratio Limit",
                message=(
                    "ExecuTorch ZIP contains multiple small pickle members with a suspicious aggregate "
                    f"compression ratio ({ratio_text}); skipping those member content scans"
                ),
                details={
                    "aggregate_small_member_check": True,
                    "member_count": len(small_high_ratio_entries),
                    "compressed_size": small_high_ratio_compressed_size,
                    "uncompressed_size": small_high_ratio_uncompressed_size,
                    "compression_ratio": aggregate_ratio,
                    "max_compression_ratio": self.MAX_COMPRESSION_RATIO,
                    "min_uncompressed_size": self.min_compression_bomb_uncompressed_size,
                },
                reason=self.ZIP_COMPRESSION_RATIO_INCONCLUSIVE_REASON,
            )
            blocked_entry_ids.update(id(entry) for entry in small_high_ratio_entries)
            analysis_incomplete = True

        scannable_entries = [entry for entry in pickle_entries if id(entry) not in blocked_entry_ids]
        return scannable_entries, analysis_incomplete

    def _check_zip_aggregate_size(
        self,
        result: ScanResult,
        path: str,
        *,
        all_entries: list[zipfile.ZipInfo],
        safe_entries: list[zipfile.ZipInfo],
    ) -> bool:
        declared_uncompressed_size = sum(entry.file_size for entry in all_entries if not entry.is_dir())
        safe_uncompressed_size = sum(entry.file_size for entry in safe_entries if not entry.is_dir())
        result.metadata["executorch_zip_declared_uncompressed_size"] = declared_uncompressed_size
        result.metadata["executorch_zip_uncompressed_size"] = safe_uncompressed_size
        result.metadata["max_executorch_zip_total_uncompressed_size"] = self.max_total_uncompressed_size
        if safe_uncompressed_size > self.max_total_uncompressed_size:
            self._add_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Aggregate Size Limit",
                message=(
                    f"ExecuTorch ZIP total uncompressed size exceeds limit "
                    f"({safe_uncompressed_size} > {self.max_total_uncompressed_size} bytes); "
                    "continuing only bounded pickle member scans"
                ),
                details={
                    "archive_uncompressed_size": safe_uncompressed_size,
                    "archive_declared_uncompressed_size": declared_uncompressed_size,
                    "max_total_uncompressed_size": self.max_total_uncompressed_size,
                },
                reason=self.ZIP_AGGREGATE_LIMIT_INCONCLUSIVE_REASON,
            )
            return True

        result.add_check(
            name="ExecuTorch ZIP Aggregate Size Limit",
            passed=True,
            message=(
                f"ExecuTorch ZIP total uncompressed size ({safe_uncompressed_size}) is within "
                f"limit ({self.max_total_uncompressed_size})"
            ),
            location=path,
            details={
                "archive_uncompressed_size": safe_uncompressed_size,
                "archive_declared_uncompressed_size": declared_uncompressed_size,
                "max_total_uncompressed_size": self.max_total_uncompressed_size,
            },
        )
        return False

    def _limit_pickle_entries_to_aggregate_budget(
        self,
        result: ScanResult,
        pickle_entries: list[zipfile.ZipInfo],
    ) -> tuple[list[zipfile.ZipInfo], bool]:
        """Keep pickle scanning bounded while preserving earlier detections."""
        selected_entries: list[zipfile.ZipInfo] = []
        skipped_entry_count = 0
        selected_uncompressed_size = 0
        for entry in pickle_entries:
            if entry.file_size > self.max_total_uncompressed_size - selected_uncompressed_size:
                skipped_entry_count += 1
                continue
            selected_entries.append(entry)
            selected_uncompressed_size += entry.file_size

        result.metadata["executorch_zip_pickle_scan_uncompressed_size"] = selected_uncompressed_size
        result.metadata["executorch_zip_pickle_aggregate_skipped_count"] = skipped_entry_count
        return selected_entries, skipped_entry_count > 0

    @staticmethod
    def _add_python_entry_checks(result: ScanResult, path: str, safe_entries: list[zipfile.ZipInfo]) -> None:
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

    @staticmethod
    def _supplemental_raw_binary_config(config: dict[str, Any]) -> dict[str, Any]:
        raw_config = dict(config)
        try:
            archive_depth = int(raw_config.get("_archive_depth", 0))
        except (TypeError, ValueError):
            archive_depth = 0
        raw_config["_archive_depth"] = max(archive_depth, 1)
        return raw_config

    def _merge_raw_binary_analysis(self, path: str, result: ScanResult, file_size: int) -> None:
        if self.config.get(PYTORCH_BINARY_PRIMARY_SCANNED_CONFIG_KEY) is True:
            result.bytes_scanned = max(result.bytes_scanned, file_size)
            return

        if not self.scanner_selection.allows("pytorch_binary"):
            add_scanner_selection_skip_check(
                result,
                path,
                "pytorch_binary",
                self.scanner_selection,
                context="supplemental ExecuTorch binary raw payload analysis",
            )
            result.bytes_scanned = max(result.bytes_scanned, file_size)
            return

        primary_bytes_scanned = result.bytes_scanned
        raw_result = PyTorchBinaryScanner(config=self._supplemental_raw_binary_config(self.config)).scan(path)
        result.merge(raw_result)
        result.bytes_scanned = max(primary_bytes_scanned, raw_result.bytes_scanned, file_size)
        supplemental_scanners = result.metadata.setdefault("supplemental_scanners", [])
        if isinstance(supplemental_scanners, list):
            supplemental_scanners.append("pytorch_binary")

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
        pickle_coverage_incomplete = False

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
            self._merge_raw_binary_analysis(path, result, file_size)
            result.finish(success=not result.has_errors)
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

        source_handle: BinaryIO | None = None
        archive_handle: BinaryIO | None = None
        opened_stat: os.stat_result | None = None
        try:
            source_handle = Path(path).open("rb")  # noqa: SIM115
            opened_stat, opened_size_result = self._check_opened_file_size_limit(
                result,
                path,
                source_handle,
            )
            if opened_size_result:
                return opened_size_result
            file_size = opened_stat.st_size
            archive_handle = self._snapshot_archive(source_handle, opened_stat)
            preflight_result = self._check_zip_entry_count_preflight(result, path, archive_handle, file_size)
            if preflight_result:
                return preflight_result

            archive_handle.seek(0)
            self.current_file_path = path
            with zipfile.ZipFile(archive_handle, "r") as z:
                archive_entries = z.infolist()
                entry_limit_result = self._check_zip_entry_count(result, path, archive_entries)
                if entry_limit_result:
                    return entry_limit_result

                safe_entries: list[zipfile.ZipInfo] = []
                for entry in archive_entries:
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

                self._add_python_entry_checks(result, path, safe_entries)
                aggregate_coverage_incomplete = self._check_zip_aggregate_size(
                    result,
                    path,
                    all_entries=archive_entries,
                    safe_entries=safe_entries,
                )

                pickle_entries = self._discover_pickle_entries(z, safe_entries, result)
                discovery_coverage_incomplete = _PICKLE_DISCOVERY_INCOMPLETE_REASON in result.metadata.get(
                    "scan_outcome_reasons", ()
                )
                pickle_files = [entry.filename for entry in pickle_entries]
                result.metadata["pickle_files"] = pickle_files
                pickle_entries, member_budget_incomplete = self._check_pickle_member_budgets(
                    result,
                    path,
                    pickle_entries,
                )
                pickle_entries, aggregate_pickle_budget_incomplete = self._limit_pickle_entries_to_aggregate_budget(
                    result,
                    pickle_entries,
                )
                pickle_coverage_incomplete = (
                    aggregate_coverage_incomplete
                    or discovery_coverage_incomplete
                    or member_budget_incomplete
                    or aggregate_pickle_budget_incomplete
                )
                bytes_scanned = 0
                pickle_member_failure_count = 0
                pickle_member_failures: list[dict[str, Any]] = []

                for member_info in pickle_entries:
                    name = member_info.filename
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
                    bytes_scanned += member_info.file_size
                    apply_pickle_member_context(sub_result, archive_path=path, member_name=name)
                    result.merge_member_result(sub_result, name)

                if pickle_member_failure_count:
                    mark_inconclusive_scan_result(result, self.ZIP_PICKLE_MEMBER_READ_INCONCLUSIVE_REASON)
                    pickle_coverage_incomplete = True
                    noun = "member" if pickle_member_failure_count == 1 else "members"
                    result.add_check(
                        name="ExecuTorch ZIP Pickle Member Read",
                        passed=False,
                        message=(f"Unable to scan {pickle_member_failure_count} embedded ExecuTorch pickle {noun}"),
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={
                            "entries": pickle_member_failures,
                            "failed_count": pickle_member_failure_count,
                            "reported_failure_count": len(pickle_member_failures),
                            "analysis_incomplete": True,
                            "scan_outcome_reason": self.ZIP_PICKLE_MEMBER_READ_INCONCLUSIVE_REASON,
                        },
                        rule_code="S902",
                    )
                result.bytes_scanned = bytes_scanned
            if self._source_changed_after_snapshot(source_handle, opened_stat, path):
                self._add_source_changed_failure(result, path)
                pickle_coverage_incomplete = True
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
        finally:
            if archive_handle is not None:
                archive_handle.close()
            if source_handle is not None:
                source_handle.close()

        if valid_binary_program or not header.startswith(b"PK"):
            self._merge_raw_binary_analysis(path, result, file_size)
        result.finish(
            success=(
                not pickle_coverage_incomplete and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
            )
        )
        return result
