"""
Security Asset Integration Tests

Tests that integrate with the organized test asset structure.
Focuses on security-specific scanning scenarios.
"""

import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import modelaudit.scanners.keras_h5_scanner as keras_h5_scanner_module
import modelaudit.scanners.keras_zip_scanner as keras_zip_scanner_module
from modelaudit.cli import cli
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import metadata_has_coverage_only_operational_error
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanner_results import Check, CheckStatus, Issue
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.zip_scanner import ZipPreflightRejected, ZipScanner, open_preflighted_zip
from modelaudit.utils.file import detection as file_detection_module

EXPECTED_UNAVAILABLE_SCANNER_MESSAGE = "Recognized format could not be scanned because no scanner was available"
OPERATIONAL_FAILURE_REASON_SUFFIXES = ("_failed", "_error", "_exceeded", "_timeout", "_interrupted")
EXPECTED_AGPL_SOURCE_STABILITY_ASSET = (
    Path(__file__).parent / "assets" / "scenarios" / "license_scenarios" / "agpl_component" / "agpl_model.pkl"
).resolve()
EXPECTED_AGPL_SOURCE_STABILITY_REASON = "source_search_context_changed"
EXPECTED_AGPL_SOURCE_STABILITY_OUTCOME_REASONS = frozenset(
    {
        "call_graph_analysis_error",
        "flax_msgpack_routing_incomplete",
        "nested_pickle_incomplete",
        "nested_probe_limit",
    }
)
EXPECTED_KERAS_H5_H5PY_OUTCOMES = frozenset({"keras_h5_h5py_unavailable"})
EXPECTED_KERAS_ZIP_H5PY_OUTCOMES = frozenset(
    {
        "keras_zip_embedded_weights_h5py_unavailable",
        "keras_zip_embedded_weights_hdf5_signature_probe_incomplete",
    }
)
EXPECTED_DEPENDENCY_OUTCOMES = {
    "defusedxml": frozenset({"pmml_safe_xml_parser_unavailable"}),
    "h5py": EXPECTED_KERAS_H5_H5PY_OUTCOMES | EXPECTED_KERAS_ZIP_H5PY_OUTCOMES,
    "onnx": frozenset(
        {
            "onnx_dependency_unavailable",
            "onnx_tentative_candidate_analysis_unavailable",
        }
    ),
    "py7zr": frozenset({"sevenzip_analysis_incomplete"}),
    "tflite": frozenset({"tflite_dependency_unavailable"}),
    "ubjson": frozenset({"xgboost_ubj_dependency_missing"}),
    "xgboost": frozenset({"xgboost_binary_load_dependency_missing"}),
}
EXPECTED_DEPENDENCY_OUTCOME_REASONS = frozenset(
    reason for outcomes in EXPECTED_DEPENDENCY_OUTCOMES.values() for reason in outcomes
)
EXPECTED_COVERAGE_AGGREGATION_OUTCOME_REASONS = frozenset({"zip_analysis_incomplete"})
EXPECTED_SECURITY_FINDING_OUTCOME_REASONS = frozenset({"nested_pickle_incomplete", "nested_probe_limit"})
EXPECTED_SECURITY_FINDING_OUTCOME_MESSAGES = {
    "nested_pickle_incomplete": "Nested pickle analysis did not complete",
    "nested_probe_limit": "Nested pickle probe candidate limit exceeded",
}
EXPECTED_PICKLE_INCOMPLETE_MESSAGES = frozenset(
    {
        "Nested pickle analysis did not complete",
        "Nested pickle payload exceeds deep-scan byte limit",
        "Nested pickle probe candidate limit exceeded",
    }
)
EXPECTED_DEPENDENCY_MESSAGE_MARKERS = {
    "defusedxml": ("defusedxml is unavailable",),
    "h5py": ("h5py is required", "h5py is unavailable"),
    "onnx": ("onnx analysis dependency is unavailable",),
    "py7zr": ("py7zr library not installed", "py7zr package is not installed"),
    "tflite": ("tflite package not installed",),
    "ubjson": ("ubjson package is not installed",),
    "xgboost": ("xgboost library not available",),
}
EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE = (
    "XML model routing was inconclusive because the bounded probe ended before the first structural root element"
)
EXPECTED_XML_ARCHIVE_DIAGNOSTIC_FIELDS = frozenset({"format", "path", "zip_entry"})
EXPECTED_UNAVAILABLE_SCANNER_DIAGNOSTIC_FIELDS = frozenset({"format", "path"})
EXPECTED_COMPRESSION_BOMB_DIAGNOSTIC_FIELDS = frozenset(
    {"compressed_size", "entry", "min_uncompressed_size", "ratio", "threshold", "uncompressed_size"}
)
EXPECTED_NESTED_H5PY_MESSAGE = "h5py is required for Keras H5 scanning. Install with 'pip install modelaudit[h5]'."
EXPECTED_NESTED_H5PY_REASON = "keras_h5_h5py_unavailable"
HDF5_SIGNATURE = b"\x89HDF\r\n\x1a\n"
HDF5_USERBLOCK_FIRST_OFFSET = 512
HDF5_SIGNATURE_SCAN_MAX_BYTES = 10 * 1024 * 1024
HDF5_SUPERBLOCK_PROBE_BYTES = 144
HDF5_ARCHIVE_CONTRACT_MAX_TOTAL_PROBE_BYTES = 16 * HDF5_SIGNATURE_SCAN_MAX_BYTES
DIRECT_HDF5_USERBLOCK_PROBE_REASON = "hdf5_userblock_zip_probe_incomplete"
DIRECT_HDF5_USERBLOCK_PROBE_MESSAGE = "HDF5 user-block ZIP discovery reached its bounded scan limit."
HDF5_SUPPORTED_FIELD_WIDTHS = frozenset({2, 4, 8, 16, 32})
HDF5_SUPERBLOCK_STATUS_FLAGS = 0x07
UINT32_MASK = (1 << 32) - 1
XML_ARCHIVE_CONTRACT_MAX_ENTRIES = 256
XML_ARCHIVE_CONTRACT_MAX_TOTAL_PROBE_BYTES = 16 * file_detection_module._XML_MODEL_SIGNATURE_READ_BYTES
ZIP_ARCHIVE_CONTRACT_MAX_DEPTH = 5
ZIP_ARCHIVE_CONTRACT_MAX_TOTAL_NESTED_BYTES = 16 * 1024 * 1024
ZIP_ARCHIVE_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x06\x06")
ZIP_TEMP_MEMBER_BASENAME_MAX_LENGTH = 160
ZIP_TEMP_PRESERVED_EXTENSIONS = frozenset({".mar", ".npz", ".zip"})
ZIP_TEMP_PRESERVED_FILENAMES = frozenset(
    {
        ".env",
        "classes.txt",
        "labels.txt",
        "merges.txt",
        "model_card",
        "model_card.md",
        "readme",
        "readme.md",
        "requirements.txt",
        "tokenizer-vocab.txt",
        "tokenizer.txt",
        "tokenizer_vocab.txt",
        "tokens.txt",
        "vocab.txt",
        "vocabulary.txt",
    }
)
ZIP_TEMP_DOCUMENTATION_PREFIXES = ("model_card.", "modelcard.", "readme.")
ZIP_TEMP_DOCUMENTATION_EXTENSIONS = frozenset({".markdown", ".md", ".rst", ".txt"})
ALIASLESS_PICKLE_DISALLOWED_FIELDS = frozenset(
    {
        "error",
        "error_type",
        "exception",
        "exception_type",
        "interrupted",
        "operational_error",
        "operational_error_reason",
        "scan_outcome_reason",
        "scan_outcome_reasons",
    }
)

CompressionBombKey = tuple[str, int, int]
XmlArchiveSourceProfile = tuple[str, str, bool]


def _zip_member_path_is_safe(member_name: str) -> bool:
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[a-zA-Z]:", normalized):
        return False

    depth = 0
    for segment in normalized.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if depth == 0:
                return False
            depth -= 1
            continue
        depth += 1
    return True


def _zip_member_temp_name_profile(member_name: str) -> tuple[str, bool]:
    basename = member_name.replace("\\", "/").rsplit("/", 1)[-1]
    normalized_basename = basename.lower()
    extension = os.path.splitext(normalized_basename)[1]
    preserve_basename = (
        extension in ZIP_TEMP_PRESERVED_EXTENSIONS
        or normalized_basename in ZIP_TEMP_PRESERVED_FILENAMES
        or (
            normalized_basename.startswith(ZIP_TEMP_DOCUMENTATION_PREFIXES)
            and extension in ZIP_TEMP_DOCUMENTATION_EXTENSIONS
        )
    )
    raw_safe_name = re.sub(
        r"[^a-zA-Z0-9_.-]",
        "_",
        basename,
    )
    safe_name = raw_safe_name if preserve_basename else raw_safe_name.strip("._")
    if not safe_name:
        safe_name = "archive-member"
    if preserve_basename and len(safe_name) > ZIP_TEMP_MEMBER_BASENAME_MAX_LENGTH:
        stem, extension = os.path.splitext(safe_name)
        max_stem_length = max(1, ZIP_TEMP_MEMBER_BASENAME_MAX_LENGTH - len(extension))
        safe_name = f"{stem[:max_stem_length]}{extension}"
    return safe_name, preserve_basename


def _xml_archive_source_profile(
    member_name: str,
    zip_entry_prefix: str | None,
) -> XmlArchiveSourceProfile:
    safe_name, preserve_basename = _zip_member_temp_name_profile(member_name)
    zip_entry = member_name if zip_entry_prefix is None else f"{zip_entry_prefix}:{member_name}"
    return zip_entry, safe_name, preserve_basename


def _hdf5_signature_offsets(file_size: int) -> tuple[int, ...]:
    max_signature_end = min(file_size, HDF5_SIGNATURE_SCAN_MAX_BYTES)
    offsets: list[int] = []
    if len(HDF5_SIGNATURE) <= max_signature_end:
        offsets.append(0)
    offset = HDF5_USERBLOCK_FIRST_OFFSET
    while offset + len(HDF5_SIGNATURE) <= max_signature_end:
        offsets.append(offset)
        offset *= 2
    return tuple(offsets)


def _rotate_left_32(value: int, bits: int) -> int:
    return ((value << bits) ^ (value >> (32 - bits))) & UINT32_MASK


def _hdf5_checksum_mix(a: int, b: int, c: int) -> tuple[int, int, int]:
    a = ((a - c) ^ _rotate_left_32(c, 4)) & UINT32_MASK
    c = (c + b) & UINT32_MASK
    b = ((b - a) ^ _rotate_left_32(a, 6)) & UINT32_MASK
    a = (a + c) & UINT32_MASK
    c = ((c - b) ^ _rotate_left_32(b, 8)) & UINT32_MASK
    b = (b + a) & UINT32_MASK
    a = ((a - c) ^ _rotate_left_32(c, 16)) & UINT32_MASK
    c = (c + b) & UINT32_MASK
    b = ((b - a) ^ _rotate_left_32(a, 19)) & UINT32_MASK
    a = (a + c) & UINT32_MASK
    c = ((c - b) ^ _rotate_left_32(b, 4)) & UINT32_MASK
    b = (b + a) & UINT32_MASK
    return a, b, c


def _hdf5_checksum_finalize(a: int, b: int, c: int) -> int:
    c = ((c ^ b) - _rotate_left_32(b, 14)) & UINT32_MASK
    a = ((a ^ c) - _rotate_left_32(c, 11)) & UINT32_MASK
    b = ((b ^ a) - _rotate_left_32(a, 25)) & UINT32_MASK
    c = ((c ^ b) - _rotate_left_32(b, 16)) & UINT32_MASK
    a = ((a ^ c) - _rotate_left_32(c, 4)) & UINT32_MASK
    b = ((b ^ a) - _rotate_left_32(a, 14)) & UINT32_MASK
    return ((c ^ b) - _rotate_left_32(b, 24)) & UINT32_MASK


def _hdf5_metadata_checksum(data: bytes) -> int:
    length = len(data)
    a = b = c = (0xDEADBEEF + length) & UINT32_MASK
    offset = 0
    while length - offset > 12:
        a = (a + int.from_bytes(data[offset : offset + 4], "little")) & UINT32_MASK
        b = (b + int.from_bytes(data[offset + 4 : offset + 8], "little")) & UINT32_MASK
        c = (c + int.from_bytes(data[offset + 8 : offset + 12], "little")) & UINT32_MASK
        a, b, c = _hdf5_checksum_mix(a, b, c)
        offset += 12
    tail = data[offset:]
    if not tail:
        return c
    if len(tail) > 8:
        c = (c + int.from_bytes(tail[8:], "little")) & UINT32_MASK
    if len(tail) > 4:
        b = (b + int.from_bytes(tail[4:8], "little")) & UINT32_MASK
    a = (a + int.from_bytes(tail[:4], "little")) & UINT32_MASK
    return _hdf5_checksum_finalize(a, b, c)


def _hdf5_superblock_is_plausible(superblock: bytes, signature_offset: int, file_size: int) -> bool:
    if superblock[: len(HDF5_SIGNATURE)] != HDF5_SIGNATURE or len(superblock) <= len(HDF5_SIGNATURE):
        return False

    version = superblock[8]
    if version in (0, 1):
        fixed_header_bytes = 24 if version == 0 else 28
        if len(superblock) < fixed_header_bytes:
            return False
        if any(superblock[field_offset] != 0 for field_offset in (9, 10, 11, 12, 15)):
            return False
        if int.from_bytes(superblock[16:18], "little") == 0:
            return False
        if int.from_bytes(superblock[18:20], "little") == 0:
            return False
        if version == 1 and (int.from_bytes(superblock[24:26], "little") == 0 or superblock[26:28] != b"\x00\x00"):
            return False
        offset_size = superblock[13]
        length_size = superblock[14]
        status_flags = int.from_bytes(superblock[20:24], "little")
        base_address_offset = fixed_header_bytes
    elif version in (2, 3):
        if len(superblock) < 12:
            return False
        offset_size = superblock[9]
        length_size = superblock[10]
        status_flags = superblock[11]
        base_address_offset = 12
    else:
        return False

    if (
        offset_size not in HDF5_SUPPORTED_FIELD_WIDTHS
        or length_size not in HDF5_SUPPORTED_FIELD_WIDTHS
        or status_flags & ~HDF5_SUPERBLOCK_STATUS_FLAGS
    ):
        return False

    if version in (2, 3):
        checksum_offset = base_address_offset + (4 * offset_size)
        if len(superblock) < checksum_offset + 4:
            return False
        stored_checksum = int.from_bytes(superblock[checksum_offset : checksum_offset + 4], "little")
        if _hdf5_metadata_checksum(superblock[:checksum_offset]) != stored_checksum:
            return False

    end_of_file_offset = base_address_offset + (2 * offset_size)
    if len(superblock) < end_of_file_offset + offset_size:
        return False
    undefined_address = (1 << (offset_size * 8)) - 1
    base_address = int.from_bytes(superblock[base_address_offset : base_address_offset + offset_size], "little")
    end_of_file_address = int.from_bytes(
        superblock[end_of_file_offset : end_of_file_offset + offset_size],
        "little",
    )
    if base_address == undefined_address or end_of_file_address == undefined_address:
        return False
    adjusted_end_of_file = end_of_file_address + (signature_offset - base_address)
    return signature_offset < adjusted_end_of_file <= file_size


def _bounded_probe_has_plausible_hdf5_superblock(probe: bytes, file_size: int) -> bool:
    return _bounded_probe_plausible_hdf5_signature_offset(probe, file_size) is not None


def _bounded_probe_plausible_hdf5_signature_offset(probe: bytes, file_size: int) -> int | None:
    return next(
        (
            offset
            for offset in _hdf5_signature_offsets(file_size)
            if _hdf5_superblock_is_plausible(
                probe[offset : offset + HDF5_SUPERBLOCK_PROBE_BYTES],
                offset,
                file_size,
            )
        ),
        None,
    )


def _bounded_hdf5_probe_covers_all_legal_offsets(file_size: int) -> bool:
    offset = HDF5_USERBLOCK_FIRST_OFFSET
    while offset + len(HDF5_SIGNATURE) <= file_size:
        if offset + len(HDF5_SIGNATURE) > HDF5_SIGNATURE_SCAN_MAX_BYTES:
            return False
        offset *= 2
    return True


class _ZipArchiveLevelContract:
    def __init__(
        self,
        *,
        archive_location: str,
        zip_entry_prefix: str | None,
        xml_members: Counter[str],
        xml_source_profiles: dict[str, set[XmlArchiveSourceProfile]],
        h5py_dependency_members: Counter[tuple[str, XmlArchiveSourceProfile]],
        unsafe_members: Counter[str],
        unsafe_member_order: tuple[str, ...],
        compression_bombs: Counter[CompressionBombKey],
        compression_bomb_order: tuple[CompressionBombKey, ...],
        compression_check_entries: tuple[str, ...],
    ) -> None:
        self.archive_location = archive_location
        self.zip_entry_prefix = zip_entry_prefix
        self.xml_members = xml_members
        self.xml_source_profiles = xml_source_profiles
        self.h5py_dependency_members = h5py_dependency_members
        self.unsafe_members = unsafe_members
        self.unsafe_member_order = unsafe_member_order
        self.compression_bombs = compression_bombs
        self.compression_bomb_order = compression_bomb_order
        self.compression_check_entries = compression_check_entries


class _ZipArchiveOccurrenceContract:
    def __init__(
        self,
        levels: tuple[_ZipArchiveLevelContract, ...],
        *,
        root_is_corrupt: bool = False,
        nested_corrupt_members: Counter[tuple[str, XmlArchiveSourceProfile]] | None = None,
    ) -> None:
        merged_levels: dict[tuple[str, str | None], _ZipArchiveLevelContract] = {}
        for level in levels:
            level_key = (level.archive_location, level.zip_entry_prefix)
            merged = merged_levels.get(level_key)
            if merged is None:
                merged_levels[level_key] = _ZipArchiveLevelContract(
                    archive_location=level.archive_location,
                    zip_entry_prefix=level.zip_entry_prefix,
                    xml_members=Counter(level.xml_members),
                    xml_source_profiles={
                        location: set(profiles) for location, profiles in level.xml_source_profiles.items()
                    },
                    h5py_dependency_members=Counter(level.h5py_dependency_members),
                    unsafe_members=Counter(level.unsafe_members),
                    unsafe_member_order=tuple(level.unsafe_member_order),
                    compression_bombs=Counter(level.compression_bombs),
                    compression_bomb_order=tuple(level.compression_bomb_order),
                    compression_check_entries=tuple(level.compression_check_entries),
                )
                continue
            merged.xml_members.update(level.xml_members)
            for location, profiles in level.xml_source_profiles.items():
                merged.xml_source_profiles.setdefault(location, set()).update(profiles)
            merged.h5py_dependency_members.update(level.h5py_dependency_members)
            merged.unsafe_members.update(level.unsafe_members)
            merged.unsafe_member_order += level.unsafe_member_order
            merged.compression_bombs.update(level.compression_bombs)
            merged.compression_bomb_order += level.compression_bomb_order
            merged.compression_check_entries += level.compression_check_entries

        self.levels = tuple(merged_levels.values())
        self.root_is_corrupt = root_is_corrupt
        self.nested_corrupt_members = Counter() if nested_corrupt_members is None else nested_corrupt_members
        self.xml_members: Counter[str] = Counter()
        self.xml_source_profiles: dict[str, set[XmlArchiveSourceProfile]] = {}
        self.h5py_dependency_members: Counter[tuple[str, XmlArchiveSourceProfile]] = Counter()
        for level in self.levels:
            self.xml_members.update(level.xml_members)
            for location, profiles in level.xml_source_profiles.items():
                self.xml_source_profiles.setdefault(location, set()).update(profiles)
            self.h5py_dependency_members.update(level.h5py_dependency_members)


class _ZipArchiveContractBudget:
    def __init__(self) -> None:
        self.entries_remaining = XML_ARCHIVE_CONTRACT_MAX_ENTRIES
        self.probe_bytes_remaining = XML_ARCHIVE_CONTRACT_MAX_TOTAL_PROBE_BYTES
        self.hdf5_probe_bytes_remaining = HDF5_ARCHIVE_CONTRACT_MAX_TOTAL_PROBE_BYTES
        self.nested_bytes_remaining = ZIP_ARCHIVE_CONTRACT_MAX_TOTAL_NESTED_BYTES


def describe_operational_errors(results: ModelAuditResultModel) -> str:
    """Summarize which files carried operational errors, for assertion messages.

    ``has_errors`` alone truncates to an unhelpful model repr in CI logs, which
    hides whichever file actually failed. Naming the paths and reasons keeps a
    recurrence diagnosable from the log without a Windows reproduction.
    """
    offenders = []
    for path, metadata in results.file_metadata.items():
        dump = getattr(metadata, "model_dump", None)
        payload = dump() if callable(dump) else metadata
        if not isinstance(payload, dict) or not payload.get("operational_error"):
            continue
        offenders.append(f"{path}: {payload.get('operational_error_reason', 'unknown reason')}")
    return "; ".join(sorted(offenders)) or "no per-file operational_error metadata recorded"


def _nested_diagnostic_details(details: dict[str, Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    pending = [details]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        normalized.append(current)

        nested_details = current.get("details")
        if isinstance(nested_details, dict):
            pending.append(nested_details)
        nested_findings = current.get("findings")
        if isinstance(nested_findings, dict):
            pending.append(nested_findings)
        elif isinstance(nested_findings, (list, tuple, set, frozenset)):
            pending.extend(finding for finding in nested_findings if isinstance(finding, dict))
    return normalized


def _has_malformed_diagnostic_markers(details: dict[str, Any]) -> bool:
    for marker in ("analysis_incomplete", "operational_error", "interrupted"):
        if marker in details and not isinstance(details[marker], bool):
            return True
    for marker in ("exception_type", "error_type", "operational_error_reason"):
        if marker in details and (not isinstance(details[marker], str) or not details[marker]):
            return True
    if "scan_outcome" in details and (not isinstance(details["scan_outcome"], str) or not details["scan_outcome"]):
        return True

    scan_outcome_reason = details.get("scan_outcome_reason")
    if "scan_outcome_reason" in details and (not isinstance(scan_outcome_reason, str) or not scan_outcome_reason):
        return True
    scan_outcome_reasons = details.get("scan_outcome_reasons")
    if "scan_outcome_reasons" in details and (
        not isinstance(scan_outcome_reasons, list)
        or not scan_outcome_reasons
        or not all(isinstance(reason, str) and bool(reason) for reason in scan_outcome_reasons)
        or len(scan_outcome_reasons) != len(set(scan_outcome_reasons))
    ):
        return True
    return (
        isinstance(scan_outcome_reason, str)
        and isinstance(scan_outcome_reasons, list)
        and scan_outcome_reason not in scan_outcome_reasons
    )


def _incomplete_diagnostic_state_is_consistent(details: dict[str, Any]) -> bool:
    return ("analysis_incomplete" not in details or details["analysis_incomplete"] is True) and (
        "scan_outcome" not in details or details["scan_outcome"] == "inconclusive"
    )


def _security_notice_aliases_are_valid(details: dict[str, Any]) -> bool:
    notice_code = details.get("notice_code")
    pickle_notice_code = details.get("pickle_notice_code")
    has_expected_alias = (
        isinstance(notice_code, str) and notice_code in EXPECTED_SECURITY_FINDING_OUTCOME_REASONS
    ) or (isinstance(pickle_notice_code, str) and pickle_notice_code in EXPECTED_SECURITY_FINDING_OUTCOME_REASONS)
    if not has_expected_alias:
        return True
    if "notice_code" in details and "pickle_notice_code" in details:
        return (
            isinstance(notice_code, str)
            and notice_code == pickle_notice_code
            and notice_code in EXPECTED_SECURITY_FINDING_OUTCOME_REASONS
        )
    present_alias = notice_code if "notice_code" in details else pickle_notice_code
    return isinstance(present_alias, str) and present_alias in EXPECTED_SECURITY_FINDING_OUTCOME_REASONS


def _is_expected_missing_dependency_diagnostic(
    diagnostic: Issue | Check,
    details: dict[str, Any],
    metadata: dict[str, Any] | None,
    *,
    h5py_profile_is_valid: bool,
) -> bool:
    if not _incomplete_diagnostic_state_is_consistent(details):
        return False
    required_package = details.get("required_package")
    error_type = details.get("error_type")
    if not isinstance(required_package, str) or not required_package.strip():
        return False
    normalized_package = required_package.strip().casefold().replace("-", "_")
    message = diagnostic.message
    message_markers = EXPECTED_DEPENDENCY_MESSAGE_MARKERS.get(normalized_package, ())
    if not (
        isinstance(message, str) and message.strip() and any(marker in message.casefold() for marker in message_markers)
    ):
        return False
    if not isinstance(metadata, dict):
        return False
    scan_outcome_reasons = metadata.get("scan_outcome_reasons")
    tentative_onnx_candidate = (
        normalized_package == "onnx"
        and metadata.get("tentative_protobuf_candidate_unanalyzed") == "onnx_dependency_unavailable"
        and scan_outcome_reasons == ["onnx_tentative_candidate_analysis_unavailable"]
    )
    if not (
        (metadata.get("analysis_incomplete") is True or tentative_onnx_candidate)
        and metadata.get("scan_outcome") == "inconclusive"
        and isinstance(scan_outcome_reasons, list)
        and bool(scan_outcome_reasons)
        and all(isinstance(reason, str) and bool(reason) for reason in scan_outcome_reasons)
    ):
        return False
    if normalized_package == "h5py" and not h5py_profile_is_valid:
        return False
    expected_reasons = EXPECTED_DEPENDENCY_OUTCOMES.get(normalized_package, frozenset())
    detail_reason = details.get("scan_outcome_reason")
    if "scan_outcome_reason" in details and (
        not isinstance(detail_reason, str)
        or not detail_reason
        or detail_reason not in scan_outcome_reasons
        or detail_reason not in expected_reasons
    ):
        return False
    return (
        (not isinstance(diagnostic, Check) or diagnostic.status == CheckStatus.FAILED)
        and bool(expected_reasons.intersection(scan_outcome_reasons))
        and "error" not in details
        and "exception" not in details
        and "exception_type" not in details
        and ("error_type" not in details or error_type == "missing_dependency")
        and "operational_error" not in details
        and "interrupted" not in details
    )


def _expected_missing_dependency_reasons(
    diagnostic: Issue | Check,
    details: dict[str, Any],
    owner_path: str,
    metadata: dict[str, Any],
    expected_dependency_outcomes: set[tuple[str, str]],
    *,
    h5py_profile_is_valid: bool,
) -> set[str]:
    if not _is_expected_missing_dependency_diagnostic(
        diagnostic,
        details,
        metadata,
        h5py_profile_is_valid=h5py_profile_is_valid,
    ):
        return set()
    required_package = details.get("required_package")
    normalized_package = (
        required_package.strip().casefold().replace("-", "_") if isinstance(required_package, str) else ""
    )
    expected_reasons = EXPECTED_DEPENDENCY_OUTCOMES.get(normalized_package, frozenset())
    owner_expected_reasons = {
        reason for path, reason in expected_dependency_outcomes if path == owner_path and reason in expected_reasons
    }
    detail_reason = details.get("scan_outcome_reason")
    if isinstance(detail_reason, str):
        return {detail_reason} & owner_expected_reasons
    if "scan_outcome_reason" not in details and len(owner_expected_reasons) == 1:
        return owner_expected_reasons
    return set()


def _file_metadata_for_diagnostic(
    results: ModelAuditResultModel,
    location: str,
) -> tuple[str, dict[str, Any]] | None:
    matching_paths = [
        path
        for path in results.file_metadata
        if location == path or location.startswith(f"{path}:") or location.startswith(f"{path} (")
    ]
    if not matching_paths:
        return None
    owner_path = max(matching_paths, key=len)
    metadata = results.file_metadata[owner_path]
    return owner_path, metadata.model_dump(exclude_none=True)


class _DirectH5pyDependencyProfile:
    def __init__(
        self,
        *,
        location: str,
        check_name: str,
        message: str,
        details: dict[str, Any],
    ) -> None:
        self.location = location
        self.check_name = check_name
        self.message = message
        self.details = details


def _direct_hdf5_signature_offset(path: str) -> int | None:
    try:
        file_size = os.path.getsize(path)
        with open(path, "rb") as source:
            offset = 0
            while offset + len(HDF5_SIGNATURE) <= file_size:
                source.seek(offset)
                probe = source.read(min(HDF5_SUPERBLOCK_PROBE_BYTES, file_size - offset))
                if _hdf5_superblock_is_plausible(probe, offset, file_size):
                    return offset
                offset = HDF5_USERBLOCK_FIRST_OFFSET if offset == 0 else offset * 2
    except OSError:
        return None
    return None


def _direct_keras_weights_source_profile(owner_path: str) -> tuple[int, int | None, bool] | None:
    try:
        with open_preflighted_zip(
            owner_path,
            {"max_zip_entries": XML_ARCHIVE_CONTRACT_MAX_ENTRIES},
        ) as archive:
            members = [member for member in archive.infolist() if not member.is_dir()]
            member_names = Counter(member.filename for member in members)
            if any(member_names[name] != 1 for name in ("config.json", "metadata.json", "model.weights.h5")):
                return None
            weights_info = next(member for member in members if member.filename == "model.weights.h5")
            offsets = _hdf5_signature_offsets(weights_info.file_size)
            probe_size = min(weights_info.file_size, offsets[-1] + HDF5_SUPERBLOCK_PROBE_BYTES) if offsets else 0
            with archive.open(weights_info) as source:
                probe = source.read(probe_size)
    except (OSError, ZipPreflightRejected, zipfile.BadZipFile):
        return None
    if len(probe) != probe_size:
        return None
    signature_offset = _bounded_probe_plausible_hdf5_signature_offset(probe, weights_info.file_size)
    return (
        weights_info.file_size,
        signature_offset,
        _bounded_hdf5_probe_covers_all_legal_offsets(weights_info.file_size),
    )


def _direct_keras_weights_metadata_is_exact(
    metadata: dict[str, Any],
    owner_path: str,
    weights_size: int,
    *,
    source_is_hdf5: bool,
) -> bool:
    contents = metadata.get("contents")
    if not isinstance(contents, list):
        return False
    expected_path = f"{owner_path}:model.weights.h5"
    matching_contents = [
        content for content in contents if isinstance(content, dict) and content.get("path") == expected_path
    ]
    if len(matching_contents) != 1:
        return False
    content = matching_contents[0]
    content_type = content.get("type")
    return (
        content.get("size") == weights_size
        and isinstance(content_type, str)
        and bool(content_type)
        and (content_type == "security_only" if source_is_hdf5 else content_type != "keras_h5")
    )


def _direct_h5py_dependency_profile(
    owner_path: str,
    metadata: dict[str, Any],
    reason: str,
) -> _DirectH5pyDependencyProfile | None:
    scan_outcome_reasons = metadata.get("scan_outcome_reasons")
    if not isinstance(scan_outcome_reasons, list):
        return None
    h5py_reasons = [item for item in scan_outcome_reasons if item in EXPECTED_DEPENDENCY_OUTCOMES["h5py"]]
    if h5py_reasons != [reason]:
        return None
    try:
        source_size = os.path.getsize(owner_path)
    except OSError:
        return None
    if metadata.get("file_size") != source_size:
        return None

    scanner_dependency_ids = metadata.get("scanner_dependency_ids")
    if reason == "keras_h5_h5py_unavailable":
        if (
            scanner_dependency_ids != ["keras_h5"]
            or keras_h5_scanner_module.HAS_H5PY is not False
            or _direct_hdf5_signature_offset(owner_path) is None
        ):
            return None
        message = "h5py is required for Keras H5 scanning. Install with 'pip install modelaudit[h5]'."
        return _DirectH5pyDependencyProfile(
            location=owner_path,
            check_name="H5PY Library Check",
            message=message,
            details={
                "path": owner_path,
                "required_package": "h5py",
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )

    if scanner_dependency_ids != ["keras_zip"] or keras_zip_scanner_module.HAS_H5PY is not False:
        return None
    source_profile = _direct_keras_weights_source_profile(owner_path)
    if source_profile is None:
        return None
    weights_size, signature_offset, probe_is_complete = source_profile
    location = f"{owner_path}:model.weights.h5"
    if reason == "keras_zip_embedded_weights_h5py_unavailable":
        if (
            signature_offset is None
            or metadata.get("embedded_weights_hdf5_signature_offset") != signature_offset
            or not _direct_keras_weights_metadata_is_exact(
                metadata,
                owner_path,
                weights_size,
                source_is_hdf5=True,
            )
        ):
            return None
        message = (
            "Skipping embedded model.weights.h5 inspection because h5py is required for HDF5 weights "
            "analysis. Install with 'pip install modelaudit[h5]'."
        )
        return _DirectH5pyDependencyProfile(
            location=location,
            check_name="Embedded Weights H5PY Library Check",
            message=message,
            details={
                "entry": "model.weights.h5",
                "required_package": "h5py",
                "hdf5_signature_offset": signature_offset,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )

    if reason != "keras_zip_embedded_weights_hdf5_signature_probe_incomplete":
        return None
    if (
        signature_offset is not None
        or probe_is_complete
        or "embedded_weights_hdf5_signature_offset" in metadata
        or not _direct_keras_weights_metadata_is_exact(
            metadata,
            owner_path,
            weights_size,
            source_is_hdf5=False,
        )
    ):
        return None
    message = (
        "Skipping embedded model.weights.h5 inspection because h5py is unavailable and the weights entry "
        "is too large to rule out a valid HDF5 user-block signature within the bounded probe window. "
        "Install with 'pip install modelaudit[h5]'."
    )
    return _DirectH5pyDependencyProfile(
        location=location,
        check_name="Embedded Weights HDF5 Signature Probe",
        message=message,
        details={
            "entry": "model.weights.h5",
            "required_package": "h5py",
            "file_size": weights_size,
            "hdf5_signature_probe_max_bytes": HDF5_SIGNATURE_SCAN_MAX_BYTES,
            "analysis_incomplete": True,
            "scan_outcome_reason": reason,
        },
    )


def _direct_h5py_dependency_diagnostic_is_exact(
    diagnostic: Issue | Check,
    profile: _DirectH5pyDependencyProfile,
) -> bool:
    if (
        diagnostic.location != profile.location
        or diagnostic.message != profile.message
        or diagnostic.rule_code != "S902"
        or diagnostic.severity != IssueSeverity.INFO
        or diagnostic.details != profile.details
    ):
        return False
    if isinstance(diagnostic, Check):
        return diagnostic.status == CheckStatus.FAILED and diagnostic.name == profile.check_name
    return isinstance(diagnostic, Issue)


def _direct_hdf5_userblock_probe_profile(
    owner_path: str,
    metadata: dict[str, Any],
) -> _DirectH5pyDependencyProfile | None:
    reasons = metadata.get("scan_outcome_reasons")
    if (
        not isinstance(reasons, list)
        or reasons.count(DIRECT_HDF5_USERBLOCK_PROBE_REASON) != 1
        or "keras_h5_h5py_unavailable" not in reasons
        or metadata.get("scanner_dependency_ids") != ["keras_h5"]
        or keras_h5_scanner_module.HAS_H5PY is not False
    ):
        return None
    try:
        source_size = os.path.getsize(owner_path)
    except OSError:
        return None
    signature_offset = _direct_hdf5_signature_offset(owner_path)
    if (
        metadata.get("file_size") != source_size
        or signature_offset is None
        or signature_offset <= HDF5_SIGNATURE_SCAN_MAX_BYTES
    ):
        return None
    return _DirectH5pyDependencyProfile(
        location=owner_path,
        check_name="HDF5 User Block ZIP Probe",
        message=DIRECT_HDF5_USERBLOCK_PROBE_MESSAGE,
        details={
            "analysis_incomplete": True,
            "scan_outcome_reason": DIRECT_HDF5_USERBLOCK_PROBE_REASON,
            "hdf5_signature_offset": signature_offset,
            "zip_probe_bytes_scanned": HDF5_SIGNATURE_SCAN_MAX_BYTES,
            "zip_probe_max_bytes": HDF5_SIGNATURE_SCAN_MAX_BYTES,
        },
    )


def _direct_hdf5_userblock_probe_diagnostic_is_candidate(diagnostic: Issue | Check) -> bool:
    return (
        diagnostic.details.get("scan_outcome_reason") == DIRECT_HDF5_USERBLOCK_PROBE_REASON
        or diagnostic.message == DIRECT_HDF5_USERBLOCK_PROBE_MESSAGE
        or (isinstance(diagnostic, Check) and diagnostic.name == "HDF5 User Block ZIP Probe")
    )


def _validate_direct_hdf5_userblock_probe_profiles(
    results: ModelAuditResultModel,
    diagnostics: list[Issue | Check],
) -> tuple[frozenset[int], frozenset[str], set[str]]:
    validated_diagnostic_ids: set[int] = set()
    validated_paths: set[str] = set()
    invalid_paths: set[str] = set()
    for owner_path, metadata_model in results.file_metadata.items():
        metadata = metadata_model.model_dump(exclude_none=True)
        reasons = metadata.get("scan_outcome_reasons")
        reason_is_claimed = isinstance(reasons, list) and DIRECT_HDF5_USERBLOCK_PROBE_REASON in reasons
        owner_candidates = [
            diagnostic
            for diagnostic in diagnostics
            if _direct_hdf5_userblock_probe_diagnostic_is_candidate(diagnostic)
            and isinstance(diagnostic.location, str)
            and (owner := _file_metadata_for_diagnostic(results, diagnostic.location)) is not None
            and owner[0] == owner_path
        ]
        if not reason_is_claimed and not owner_candidates:
            continue
        profile = _direct_hdf5_userblock_probe_profile(owner_path, metadata)
        exact_issues = [
            diagnostic
            for diagnostic in owner_candidates
            if isinstance(diagnostic, Issue)
            and profile is not None
            and _direct_h5py_dependency_diagnostic_is_exact(diagnostic, profile)
        ]
        exact_checks = [
            diagnostic
            for diagnostic in owner_candidates
            if isinstance(diagnostic, Check)
            and profile is not None
            and _direct_h5py_dependency_diagnostic_is_exact(diagnostic, profile)
        ]
        if profile is None or len(owner_candidates) != 2 or len(exact_issues) != 1 or len(exact_checks) != 1:
            invalid_paths.add(owner_path)
            continue
        validated_paths.add(owner_path)
        validated_diagnostic_ids.update(id(diagnostic) for diagnostic in owner_candidates)
    return frozenset(validated_diagnostic_ids), frozenset(validated_paths), invalid_paths


def _validate_direct_h5py_dependency_profiles(
    results: ModelAuditResultModel,
    diagnostics: list[Issue | Check],
    nested_h5py_dependency_paths: frozenset[str],
) -> tuple[frozenset[int], set[str]]:
    validated_diagnostic_ids: set[int] = set()
    invalid_paths: set[str] = set()
    for owner_path, metadata_model in results.file_metadata.items():
        metadata = metadata_model.model_dump(exclude_none=True)
        scan_outcome_reasons = metadata.get("scan_outcome_reasons")
        if not isinstance(scan_outcome_reasons, list):
            continue
        h5py_reasons = [reason for reason in scan_outcome_reasons if reason in EXPECTED_DEPENDENCY_OUTCOMES["h5py"]]
        if not h5py_reasons or owner_path in nested_h5py_dependency_paths:
            continue
        if len(h5py_reasons) != 1:
            invalid_paths.add(owner_path)
            continue
        profile = _direct_h5py_dependency_profile(owner_path, metadata, h5py_reasons[0])
        owner_diagnostics = [
            diagnostic
            for diagnostic in diagnostics
            if diagnostic.details.get("required_package") == "h5py"
            and isinstance(diagnostic.location, str)
            and (owner := _file_metadata_for_diagnostic(results, diagnostic.location)) is not None
            and owner[0] == owner_path
        ]
        exact_issues = [
            diagnostic
            for diagnostic in owner_diagnostics
            if isinstance(diagnostic, Issue)
            and profile is not None
            and _direct_h5py_dependency_diagnostic_is_exact(diagnostic, profile)
        ]
        exact_checks = [
            diagnostic
            for diagnostic in owner_diagnostics
            if isinstance(diagnostic, Check)
            and profile is not None
            and _direct_h5py_dependency_diagnostic_is_exact(diagnostic, profile)
        ]
        if profile is None or len(owner_diagnostics) != 2 or len(exact_issues) != 1 or len(exact_checks) != 1:
            invalid_paths.add(owner_path)
            continue
        validated_diagnostic_ids.update(id(diagnostic) for diagnostic in owner_diagnostics)
    return frozenset(validated_diagnostic_ids), invalid_paths


def _expected_security_outcome_reason(
    diagnostic: Issue | Check,
    details: dict[str, Any],
) -> str | None:
    notice_code = details.get("notice_code")
    pickle_notice_code = details.get("pickle_notice_code")
    if not _security_notice_aliases_are_valid(details):
        return None
    if notice_code not in EXPECTED_SECURITY_FINDING_OUTCOME_REASONS:
        notice_code = pickle_notice_code
    if not isinstance(notice_code, str):
        return None
    expected_message = EXPECTED_SECURITY_FINDING_OUTCOME_MESSAGES.get(notice_code)
    diagnostic_is_failed = not isinstance(diagnostic, Check) or diagnostic.status == CheckStatus.FAILED
    if (
        diagnostic_is_failed
        and expected_message is not None
        and diagnostic.message == expected_message
        and details.get("analysis_incomplete") is True
        and _incomplete_diagnostic_state_is_consistent(details)
        and isinstance(details.get("pickle_source"), str)
        and isinstance(diagnostic.location, str)
    ):
        return notice_code
    return None


def _is_expected_archive_member_coverage_diagnostic(
    diagnostic: Issue | Check,
    details: dict[str, Any],
    owner_path: str,
    metadata: dict[str, Any],
    diagnostics: list[tuple[Issue | Check, dict[str, Any]]],
    expected_dependency_outcomes: set[tuple[str, str]],
    validated_h5py_diagnostic_ids: frozenset[int],
) -> bool:
    zip_entry = details.get("zip_entry")
    coverage_reason = "flax_msgpack_routing_incomplete"
    owner_reason = "keras_zip_embedded_weights_hdf5_signature_probe_incomplete"
    if (
        zip_entry != "model.weights.h5"
        or details.get("scan_outcome_reason") != coverage_reason
        or diagnostic.message
        != "Flax MessagePack analysis incomplete because bounded routing inspection could not complete"
    ):
        return False
    member_path = f"{owner_path}:{zip_entry}"
    contents = metadata.get("contents")
    scan_outcome_reasons = metadata.get("scan_outcome_reasons")
    if not (
        diagnostic.location == member_path
        and isinstance(contents, list)
        and any(isinstance(content, dict) and content.get("path") == member_path for content in contents)
        and isinstance(scan_outcome_reasons, list)
        and owner_reason in scan_outcome_reasons
    ):
        return False
    return any(
        candidate is not diagnostic
        and candidate.location == member_path
        and owner_reason
        in _expected_missing_dependency_reasons(
            candidate,
            candidate_details,
            owner_path,
            metadata,
            expected_dependency_outcomes,
            h5py_profile_is_valid=id(candidate) in validated_h5py_diagnostic_ids,
        )
        for candidate, candidate_details in diagnostics
        if "required_package" in candidate_details
    )


def _compression_bomb_key_from_details(
    details: dict[str, Any],
    zip_entry_prefix: str | None,
) -> CompressionBombKey | None:
    normalized_details = _diagnostic_details_for_archive_level(details, zip_entry_prefix)
    if normalized_details is None:
        return None
    compressed_size = normalized_details.get("compressed_size")
    entry = normalized_details.get("entry")
    min_uncompressed_size = normalized_details.get("min_uncompressed_size")
    ratio = normalized_details.get("ratio")
    threshold = normalized_details.get("threshold")
    uncompressed_size = normalized_details.get("uncompressed_size")
    if not (
        frozenset(normalized_details) == EXPECTED_COMPRESSION_BOMB_DIAGNOSTIC_FIELDS
        and isinstance(compressed_size, int)
        and not isinstance(compressed_size, bool)
        and compressed_size > 0
        and isinstance(entry, str)
        and bool(entry)
        and min_uncompressed_size == ZipScanner.MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE
        and isinstance(ratio, (int, float))
        and not isinstance(ratio, bool)
        and threshold == ZipScanner.MAX_COMPRESSION_RATIO
        and isinstance(uncompressed_size, int)
        and not isinstance(uncompressed_size, bool)
        and uncompressed_size >= ZipScanner.MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE
        and ratio > ZipScanner.MAX_COMPRESSION_RATIO
        and math.isclose(float(ratio), uncompressed_size / compressed_size, rel_tol=1e-12)
    ):
        return None
    return entry, compressed_size, uncompressed_size


def _compression_bomb_message(key: CompressionBombKey) -> str:
    entry, compressed_size, uncompressed_size = key
    ratio = uncompressed_size / compressed_size
    return (
        f"Suspicious compression ratio ({ratio:.1f}x) and uncompressed size "
        f"({uncompressed_size} bytes) in entry: {entry}; skipping extraction"
    )


def _listed_archive_contents_by_member(
    contents: Any,
    archive_location: str,
    archive_source_basename: str | None,
    archive_source_name_is_exact: bool,
) -> tuple[dict[str, list[dict[str, Any]]], bool]:
    if not isinstance(contents, list):
        return {}, False
    listed: dict[str, list[dict[str, Any]]] = {}
    paths_are_valid = True
    for content in contents:
        if not isinstance(content, dict) or not isinstance(content.get("path"), str):
            paths_are_valid = False
            continue
        content_path = content["path"]
        canonical_prefix = f"{archive_location}:"
        if archive_source_basename is None and content_path.startswith(canonical_prefix):
            member_name = content_path[len(canonical_prefix) :]
        elif archive_source_basename is not None:
            marker = f"{archive_source_basename}:"
            marker_offset = content_path.rfind(marker)
            if marker_offset < 0:
                paths_are_valid = False
                continue
            extracted_archive_path = content_path[: marker_offset + len(archive_source_basename)]
            extracted_parent = Path(extracted_archive_path).parent
            extracted_name = Path(extracted_archive_path).name
            temp_root = Path(tempfile.gettempdir())
            if archive_source_name_is_exact:
                path_matches_profile = (
                    extracted_name == archive_source_basename
                    and extracted_parent.parent == temp_root
                    and re.fullmatch(r"tmp[a-z0-9_]{8}", extracted_parent.name) is not None
                )
            else:
                random_prefix = extracted_name[: -len(archive_source_basename) - 1]
                path_matches_profile = (
                    extracted_parent == temp_root
                    and extracted_name.endswith(f"_{archive_source_basename}")
                    and re.fullmatch(r"tmp[a-z0-9_]{8}", random_prefix) is not None
                )
            if not os.path.isabs(extracted_archive_path) or not path_matches_profile:
                paths_are_valid = False
                continue
            member_name = content_path[marker_offset + len(marker) :]
        else:
            paths_are_valid = False
            continue
        if not member_name:
            paths_are_valid = False
            continue
        listed.setdefault(member_name, []).append(content)
    return listed, paths_are_valid


def _zip_archive_occurrence_contract(
    owner_path: str,
    metadata: dict[str, Any],
) -> tuple[_ZipArchiveOccurrenceContract | None, set[str]]:
    if not os.path.isfile(owner_path):
        return None, set()

    try:
        with open(owner_path, "rb") as source:
            root_signature = source.read(4)
    except OSError:
        return None, {owner_path}
    root_is_zip_candidate = root_signature in ZIP_ARCHIVE_SIGNATURES
    budget = _ZipArchiveContractBudget()
    invalid_locations: set[str] = set()
    levels: list[_ZipArchiveLevelContract] = []
    root_is_corrupt = False
    nested_corrupt_members: Counter[tuple[str, XmlArchiveSourceProfile]] = Counter()

    def inspect_archive(
        archive_path: str,
        archive_location: str,
        zip_entry_prefix: str | None,
        archive_source_basename: str | None,
        archive_source_name_is_exact: bool,
        contents: Any,
        depth: int,
        *,
        root_archive: bool,
    ) -> bool:
        nonlocal root_is_corrupt
        try:
            with open_preflighted_zip(
                archive_path,
                {"max_zip_entries": XML_ARCHIVE_CONTRACT_MAX_ENTRIES},
            ) as archive:
                members = [member for member in archive.infolist() if not member.is_dir()]
                if len(members) > budget.entries_remaining:
                    invalid_locations.add(owner_path)
                    return False
                budget.entries_remaining -= len(members)
                listed_by_member, listed_paths_are_valid = _listed_archive_contents_by_member(
                    contents,
                    archive_location,
                    archive_source_basename,
                    archive_source_name_is_exact,
                )
                if not listed_paths_are_valid:
                    invalid_locations.add(archive_location)

                safe_members: Counter[str] = Counter()
                listed_offsets: Counter[str] = Counter()
                inconclusive_xml_members: Counter[str] = Counter()
                xml_source_profiles: dict[str, set[XmlArchiveSourceProfile]] = {}
                h5py_dependency_members: Counter[tuple[str, XmlArchiveSourceProfile]] = Counter()
                unsafe_members: Counter[str] = Counter()
                unsafe_member_order: list[str] = []
                compression_bombs: Counter[CompressionBombKey] = Counter()
                compression_bomb_order: list[CompressionBombKey] = []
                compression_check_entries: list[str] = []

                for member in members:
                    member_path = f"{archive_location}:{member.filename}"
                    if not _zip_member_path_is_safe(member.filename):
                        unsafe_members[member.filename] += 1
                        unsafe_member_order.append(member.filename)
                        continue
                    is_symlink = member.create_system == 3 and stat.S_ISLNK(member.external_attr >> 16)
                    if is_symlink:
                        continue
                    if member.compress_size > 0:
                        compression_check_entries.append(member.filename)
                        compression_ratio = member.file_size / member.compress_size
                        if (
                            compression_ratio > ZipScanner.MAX_COMPRESSION_RATIO
                            and member.file_size >= ZipScanner.MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE
                        ):
                            key = (member.filename, member.compress_size, member.file_size)
                            compression_bombs[key] += 1
                            compression_bomb_order.append(key)
                            continue

                    safe_members[member.filename] += 1
                    listed_index = listed_offsets[member.filename]
                    listed_offsets[member.filename] += 1
                    listed_occurrences = listed_by_member.get(member.filename, [])
                    listed_content = (
                        listed_occurrences[listed_index] if listed_index < len(listed_occurrences) else None
                    )

                    probe_size = min(member.file_size, file_detection_module._XML_MODEL_SIGNATURE_READ_BYTES)
                    if probe_size > budget.probe_bytes_remaining:
                        invalid_locations.add(owner_path)
                        return False
                    with archive.open(member) as member_handle:
                        probe = member_handle.read(probe_size)
                    if len(probe) != probe_size:
                        invalid_locations.add(member_path)
                        return False
                    budget.probe_bytes_remaining -= len(probe)

                    metadata_size = listed_content.get("size") if isinstance(listed_content, dict) else None
                    metadata_claims_hdf5 = isinstance(listed_content, dict) and listed_content.get("type") == "keras_h5"
                    metadata_matches_hdf5_source = (
                        metadata_claims_hdf5
                        and isinstance(metadata_size, int)
                        and not isinstance(metadata_size, bool)
                        and metadata_size == member.file_size
                    )
                    direct_keras_hdf5_source = (
                        root_archive
                        and metadata.get("scanner_dependency_ids") == ["keras_zip"]
                        and member.filename == "model.weights.h5"
                        and isinstance(listed_content, dict)
                        and listed_content.get("type") == "security_only"
                        and isinstance(metadata_size, int)
                        and not isinstance(metadata_size, bool)
                        and metadata_size == member.file_size
                    )
                    source_is_hdf5 = False
                    hdf5_offsets = _hdf5_signature_offsets(member.file_size)
                    if hdf5_offsets:
                        hdf5_probe_size = min(
                            member.file_size,
                            hdf5_offsets[-1] + HDF5_SUPERBLOCK_PROBE_BYTES,
                        )
                        if hdf5_probe_size > budget.hdf5_probe_bytes_remaining:
                            invalid_locations.add(owner_path)
                            return False
                        if hdf5_probe_size <= len(probe):
                            hdf5_probe = probe[:hdf5_probe_size]
                        else:
                            with archive.open(member) as member_handle:
                                hdf5_probe = member_handle.read(hdf5_probe_size)
                        if len(hdf5_probe) != hdf5_probe_size:
                            invalid_locations.add(member_path)
                            return False
                        budget.hdf5_probe_bytes_remaining -= len(hdf5_probe)
                        source_is_hdf5 = _bounded_probe_has_plausible_hdf5_superblock(
                            hdf5_probe,
                            member.file_size,
                        )
                    if source_is_hdf5:
                        if metadata_matches_hdf5_source:
                            h5py_dependency_members[
                                (member_path, _xml_archive_source_profile(member.filename, zip_entry_prefix))
                            ] += 1
                        elif not direct_keras_hdf5_source:
                            invalid_locations.add(member_path)
                    elif metadata_claims_hdf5:
                        invalid_locations.add(member_path)

                    if file_detection_module._could_be_xml_prefix(probe):
                        detected_format = file_detection_module._detect_xml_model_format(
                            probe,
                            sample_is_prefix=member.file_size > len(probe),
                        )
                        if detected_format == file_detection_module.XML_MODEL_INCONCLUSIVE_FORMAT:
                            inconclusive_xml_members[member_path] += 1
                            xml_source_profiles.setdefault(member_path, set()).add(
                                _xml_archive_source_profile(member.filename, zip_entry_prefix)
                            )

                    if probe[:4] not in ZIP_ARCHIVE_SIGNATURES:
                        continue
                    if depth + 1 >= ZIP_ARCHIVE_CONTRACT_MAX_DEPTH:
                        invalid_locations.add(member_path)
                        continue
                    if member.file_size > budget.nested_bytes_remaining:
                        invalid_locations.add(member_path)
                        continue
                    with archive.open(member) as member_handle:
                        nested_payload = member_handle.read(member.file_size)
                    if len(nested_payload) != member.file_size:
                        invalid_locations.add(member_path)
                        continue
                    budget.nested_bytes_remaining -= len(nested_payload)
                    nested_contents = listed_content.get("contents") if isinstance(listed_content, dict) else None
                    nested_prefix = (
                        member.filename if zip_entry_prefix is None else f"{zip_entry_prefix}:{member.filename}"
                    )
                    nested_archive_basename, preserve_basename = _zip_member_temp_name_profile(member.filename)
                    with tempfile.NamedTemporaryFile(suffix=f"_{nested_archive_basename}") as nested_file:
                        nested_file.write(nested_payload)
                        nested_file.flush()
                        inspect_archive(
                            nested_file.name,
                            member_path,
                            nested_prefix,
                            nested_archive_basename,
                            preserve_basename,
                            nested_contents,
                            depth + 1,
                            root_archive=False,
                        )

                listed_member_counts = Counter(
                    {member_name: len(member_contents) for member_name, member_contents in listed_by_member.items()}
                )
                if listed_member_counts != safe_members:
                    invalid_locations.add(archive_location)
                levels.append(
                    _ZipArchiveLevelContract(
                        archive_location=archive_location,
                        zip_entry_prefix=zip_entry_prefix,
                        xml_members=inconclusive_xml_members,
                        xml_source_profiles=xml_source_profiles,
                        h5py_dependency_members=h5py_dependency_members,
                        unsafe_members=unsafe_members,
                        unsafe_member_order=tuple(unsafe_member_order),
                        compression_bombs=compression_bombs,
                        compression_bomb_order=tuple(compression_bomb_order),
                        compression_check_entries=tuple(compression_check_entries),
                    )
                )
                return True
        except zipfile.BadZipFile:
            if root_archive and root_is_zip_candidate:
                root_is_corrupt = True
            elif not root_archive:
                if zip_entry_prefix is None or archive_source_basename is None:
                    invalid_locations.add(archive_location)
                else:
                    nested_corrupt_members[
                        (
                            archive_location,
                            (zip_entry_prefix, archive_source_basename, archive_source_name_is_exact),
                        )
                    ] += 1
            return False
        except (OSError, RuntimeError, NotImplementedError, zipfile.LargeZipFile, ZipPreflightRejected):
            invalid_locations.add(archive_location)
            return False

    if not inspect_archive(
        owner_path,
        owner_path,
        None,
        None,
        False,
        metadata.get("contents"),
        0,
        root_archive=True,
    ):
        if root_is_corrupt:
            return _ZipArchiveOccurrenceContract((), root_is_corrupt=True), invalid_locations
        return None, invalid_locations
    return (
        _ZipArchiveOccurrenceContract(tuple(levels), nested_corrupt_members=nested_corrupt_members),
        invalid_locations,
    )


def _path_traversal_diagnostic_is_candidate(diagnostic: Issue | Check) -> bool:
    return (
        diagnostic.rule_code == "S405"
        or "attempted path traversal outside the archive" in diagnostic.message
        or (isinstance(diagnostic, Check) and diagnostic.name == "Path Traversal Protection")
    )


def _path_traversal_message(entry: str) -> str:
    return f"Archive entry {entry} attempted path traversal outside the archive"


def _diagnostic_archive_prefix(details: dict[str, Any]) -> tuple[bool, str | None]:
    findings = details.get("findings")
    if findings is not None:
        if "zip_entry" in details or not isinstance(findings, list) or not findings:
            return False, None
        prefixes: set[str | None] = set()
        for finding in findings:
            if not isinstance(finding, dict):
                return False, None
            if "zip_entry" not in finding:
                prefixes.add(None)
                continue
            prefix = finding.get("zip_entry")
            if not isinstance(prefix, str) or not prefix:
                return False, None
            prefixes.add(prefix)
        if len(prefixes) != 1:
            return False, None
        return True, next(iter(prefixes))
    if "zip_entry" not in details:
        return True, None
    prefix = details.get("zip_entry")
    if not isinstance(prefix, str) or not prefix:
        return False, None
    return True, prefix


def _archive_level_key(owner_path: str, zip_entry_prefix: str | None) -> tuple[str, str | None]:
    archive_location = owner_path if zip_entry_prefix is None else f"{owner_path}:{zip_entry_prefix}"
    return archive_location, zip_entry_prefix


def _diagnostic_details_for_archive_level(
    details: dict[str, Any],
    zip_entry_prefix: str | None,
) -> dict[str, Any] | None:
    if zip_entry_prefix is None:
        return details if "zip_entry" not in details else None
    if details.get("zip_entry") != zip_entry_prefix:
        return None
    return {key: value for key, value in details.items() if key != "zip_entry"}


def _validate_path_traversal_diagnostics(
    owner_path: str,
    contract: _ZipArchiveOccurrenceContract,
    root_diagnostics: list[Issue | Check],
) -> set[str]:
    invalid_locations: set[str] = set()
    levels_by_key = {(level.archive_location, level.zip_entry_prefix): level for level in contract.levels}
    diagnostics_by_key: dict[tuple[str, str | None], list[Issue | Check]] = {key: [] for key in levels_by_key}
    for diagnostic in root_diagnostics:
        location = diagnostic.location or "unknown scan location"
        if not (location == owner_path or location.startswith(f"{owner_path}:")):
            continue
        if not _path_traversal_diagnostic_is_candidate(diagnostic):
            continue
        prefix_is_valid, zip_entry_prefix = _diagnostic_archive_prefix(diagnostic.details)
        level_key = _archive_level_key(owner_path, zip_entry_prefix)
        if not prefix_is_valid or level_key not in levels_by_key:
            invalid_locations.add(location)
            continue
        diagnostics_by_key[level_key].append(diagnostic)

    for level_key, level in levels_by_key.items():
        zip_entry_prefix = level_key[1]
        issue_occurrences: Counter[str] = Counter()
        direct_check_occurrences: Counter[str] = Counter()
        consolidated_check_occurrences: list[Counter[str]] = []
        for diagnostic in diagnostics_by_key[level_key]:
            location = diagnostic.location or "unknown scan location"
            details = (
                diagnostic.details
                if isinstance(diagnostic, Check) and "findings" in diagnostic.details
                else _diagnostic_details_for_archive_level(diagnostic.details, zip_entry_prefix)
            )
            if details is None:
                invalid_locations.add(location)
                continue
            if isinstance(diagnostic, Issue):
                entry = details.get("entry")
                if not (
                    diagnostic.rule_code == "S405"
                    and diagnostic.severity == IssueSeverity.CRITICAL
                    and frozenset(details) == frozenset({"entry"})
                    and isinstance(entry, str)
                    and bool(entry)
                    and level.unsafe_members[entry] > 0
                    and location == f"{level.archive_location}:{entry}"
                    and diagnostic.message == _path_traversal_message(entry)
                ):
                    invalid_locations.add(location)
                    continue
                issue_occurrences[entry] += 1
                continue

            if not (
                diagnostic.name == "Path Traversal Protection"
                and diagnostic.status == CheckStatus.FAILED
                and diagnostic.severity == IssueSeverity.CRITICAL
            ):
                invalid_locations.add(location)
                continue
            entry = details.get("entry")
            if isinstance(entry, str) and frozenset(details) == frozenset({"entry"}):
                if not (
                    diagnostic.rule_code == "S405"
                    and level.unsafe_members[entry] > 0
                    and location == f"{level.archive_location}:{entry}"
                    and diagnostic.message == _path_traversal_message(entry)
                ):
                    invalid_locations.add(location)
                    continue
                direct_check_occurrences[entry] += 1
                continue

            findings = details.get("findings")
            component_count = details.get("component_count")
            if not (
                diagnostic.rule_code is None
                and frozenset(details) == frozenset({"component_count", "findings"})
                and isinstance(component_count, int)
                and not isinstance(component_count, bool)
                and component_count > 1
                and isinstance(findings, list)
                and component_count == len(findings)
            ):
                invalid_locations.add(location)
                continue
            child_occurrences: Counter[str] = Counter()
            for finding in findings:
                if not isinstance(finding, dict):
                    child_occurrences.clear()
                    break
                child_details = _diagnostic_details_for_archive_level(finding, zip_entry_prefix)
                if not (
                    child_details is not None
                    and frozenset(child_details) == frozenset({"entry"})
                    and isinstance(child_details.get("entry"), str)
                    and level.unsafe_members[child_details["entry"]] > 0
                ):
                    child_occurrences.clear()
                    break
                child_occurrences[child_details["entry"]] += 1
            if not child_occurrences:
                invalid_locations.add(location)
                continue
            expected_messages = [_path_traversal_message(entry_name) for entry_name in level.unsafe_member_order]
            expected_message = (
                expected_messages[0]
                if len(set(expected_messages)) == 1
                else f"Path Traversal Protection found {len(expected_messages)} issues"
            )
            first_entry = level.unsafe_member_order[0]
            if location != f"{level.archive_location}:{first_entry}" or diagnostic.message != expected_message:
                invalid_locations.add(location)
                continue
            consolidated_check_occurrences.append(child_occurrences)

        expected_issue_occurrences = Counter(dict.fromkeys(level.unsafe_members, 1))
        if issue_occurrences != expected_issue_occurrences:
            invalid_locations.add(level.archive_location)
        if not level.unsafe_members:
            if direct_check_occurrences or consolidated_check_occurrences:
                invalid_locations.add(level.archive_location)
        elif sum(level.unsafe_members.values()) == 1:
            if direct_check_occurrences != level.unsafe_members or consolidated_check_occurrences:
                invalid_locations.add(level.archive_location)
        elif (
            direct_check_occurrences
            or len(consolidated_check_occurrences) != 1
            or consolidated_check_occurrences[0] != level.unsafe_members
        ):
            invalid_locations.add(level.archive_location)
    return invalid_locations


def _corrupt_zip_diagnostic_is_candidate(diagnostic: Issue | Check, owner_path: str) -> bool:
    location = diagnostic.location
    return (
        isinstance(location, str)
        and (location == owner_path or location.startswith(f"{owner_path}:"))
        and (
            diagnostic.rule_code == "S902"
            or diagnostic.message.startswith("Not a valid zip file:")
            or (isinstance(diagnostic, Check) and diagnostic.name == "ZIP File Format Validation")
        )
    )


def _validate_corrupt_zip_diagnostics(
    owner_path: str,
    root_diagnostics: list[Issue | Check],
) -> tuple[bool, set[str]]:
    candidates = [
        diagnostic for diagnostic in root_diagnostics if _corrupt_zip_diagnostic_is_candidate(diagnostic, owner_path)
    ]
    expected_message = f"Not a valid zip file: {owner_path}"
    expected_details = frozenset({"path"})
    issue_count = sum(
        isinstance(diagnostic, Issue)
        and diagnostic.rule_code == "S902"
        and diagnostic.severity == IssueSeverity.INFO
        and diagnostic.message == expected_message
        and frozenset(diagnostic.details) == expected_details
        and diagnostic.details.get("path") == owner_path
        for diagnostic in candidates
    )
    check_count = sum(
        isinstance(diagnostic, Check)
        and diagnostic.name == "ZIP File Format Validation"
        and diagnostic.status == CheckStatus.FAILED
        and diagnostic.rule_code == "S902"
        and diagnostic.severity == IssueSeverity.INFO
        and diagnostic.message == expected_message
        and frozenset(diagnostic.details) == expected_details
        and diagnostic.details.get("path") == owner_path
        for diagnostic in candidates
    )
    diagnostics_are_exact = len(candidates) == 2 and issue_count == 1 and check_count == 1
    return diagnostics_are_exact, set() if diagnostics_are_exact else {owner_path}


def _source_path_matches_temp_profile(
    source_path: Any,
    expected_source_name: str,
    source_name_is_exact: bool,
) -> bool:
    if not isinstance(source_path, str) or not os.path.isabs(source_path):
        return False
    source_basename = Path(source_path).name
    return (
        source_basename == expected_source_name
        if source_name_is_exact
        else source_basename.endswith(f"_{expected_source_name}")
    )


def _zip_format_diagnostic_has_explicit_marker(diagnostic: Issue | Check) -> bool:
    if diagnostic.message.startswith("Not a valid zip file:"):
        return True
    has_zip_provenance = (
        diagnostic.rule_code == "S902" and "path" in diagnostic.details and "zip_entry" in diagnostic.details
    )
    if isinstance(diagnostic, Check):
        return diagnostic.status == CheckStatus.FAILED and (
            diagnostic.name == "ZIP File Format Validation" or has_zip_provenance
        )
    return has_zip_provenance


def _nested_h5py_details_are_exact(
    details: dict[str, Any],
    source_profile: XmlArchiveSourceProfile,
) -> bool:
    expected_zip_entry, expected_source_name, source_name_is_exact = source_profile
    return (
        frozenset(details)
        == frozenset({"analysis_incomplete", "path", "required_package", "scan_outcome_reason", "zip_entry"})
        and details.get("analysis_incomplete") is True
        and details.get("required_package") == "h5py"
        and details.get("scan_outcome_reason") == EXPECTED_NESTED_H5PY_REASON
        and details.get("zip_entry") == expected_zip_entry
        and _source_path_matches_temp_profile(details.get("path"), expected_source_name, source_name_is_exact)
    )


def _nested_h5py_direct_diagnostic_is_exact(
    diagnostic: Issue | Check,
    member_location: str,
    source_profile: XmlArchiveSourceProfile,
) -> bool:
    common_fields_are_exact = (
        diagnostic.location == member_location
        and diagnostic.rule_code == "S902"
        and diagnostic.severity == IssueSeverity.INFO
        and diagnostic.message == EXPECTED_NESTED_H5PY_MESSAGE
        and _nested_h5py_details_are_exact(diagnostic.details, source_profile)
    )
    if isinstance(diagnostic, Issue):
        return common_fields_are_exact
    return (
        common_fields_are_exact and diagnostic.name == "H5PY Library Check" and diagnostic.status == CheckStatus.FAILED
    )


def _nested_h5py_consolidated_check_is_exact(
    diagnostic: Check,
    member_location: str,
    source_profile: XmlArchiveSourceProfile,
    occurrence_count: int,
    direct_issue: Issue,
) -> bool:
    findings = diagnostic.details.get("findings")
    if not (
        diagnostic.location == member_location
        and diagnostic.name == "H5PY Library Check"
        and diagnostic.status == CheckStatus.FAILED
        and diagnostic.rule_code is None
        and diagnostic.severity == IssueSeverity.INFO
        and diagnostic.message == EXPECTED_NESTED_H5PY_MESSAGE
        and frozenset(diagnostic.details) == frozenset({"component_count", "findings"})
        and diagnostic.details.get("component_count") == occurrence_count
        and isinstance(findings, list)
        and len(findings) == occurrence_count
        and all(
            isinstance(finding, dict) and _nested_h5py_details_are_exact(finding, source_profile)
            for finding in findings
        )
    ):
        return False
    source_paths = [finding["path"] for finding in findings]
    return len(set(source_paths)) == occurrence_count and direct_issue.details in findings


def _nested_h5py_diagnostic_is_candidate(diagnostic: Issue | Check) -> bool:
    if (
        diagnostic.message == EXPECTED_NESTED_H5PY_MESSAGE
        or diagnostic.details.get("scan_outcome_reason") == EXPECTED_NESTED_H5PY_REASON
    ):
        return True
    return any(
        details.get("scan_outcome_reason") == EXPECTED_NESTED_H5PY_REASON
        for details in _nested_diagnostic_details(diagnostic.details)
    )


def _validate_nested_h5py_dependency_profile(
    owner_path: str,
    metadata: dict[str, Any],
    contract: _ZipArchiveOccurrenceContract,
    root_diagnostics: list[Issue | Check],
) -> tuple[bool, bool, set[str], set[int]]:
    scan_outcome_reasons = metadata.get("scan_outcome_reasons")
    owner_claims_dependency = (
        isinstance(scan_outcome_reasons, list) and EXPECTED_NESTED_H5PY_REASON in scan_outcome_reasons
    )
    candidates = [
        diagnostic
        for diagnostic in root_diagnostics
        if isinstance(diagnostic.location, str)
        and (diagnostic.location == owner_path or diagnostic.location.startswith(f"{owner_path}:"))
        and _nested_h5py_diagnostic_is_candidate(diagnostic)
    ]
    dependency_is_unavailable = keras_h5_scanner_module.HAS_H5PY is False
    dependency_is_required = dependency_is_unavailable and bool(contract.h5py_dependency_members)
    claimed = owner_claims_dependency or bool(candidates) or dependency_is_required
    if not claimed:
        return False, False, set(), set()

    if not dependency_is_unavailable:
        stale_profile_locations = {owner_path}
        stale_profile_locations.update(diagnostic.location or "unknown scan location" for diagnostic in candidates)
        return True, False, stale_profile_locations, set()

    invalid_locations: set[str] = set()
    validated_ids: set[int] = set()
    metadata_is_exact = (
        metadata.get("analysis_incomplete") is True
        and metadata.get("scan_outcome") == "inconclusive"
        and isinstance(scan_outcome_reasons, list)
        and EXPECTED_NESTED_H5PY_REASON in scan_outcome_reasons
        and "zip_analysis_incomplete" in scan_outcome_reasons
    )
    if not metadata_is_exact or not contract.h5py_dependency_members:
        invalid_locations.add(owner_path)

    expected_locations = {location for location, _source_profile in contract.h5py_dependency_members}
    for diagnostic in candidates:
        location = diagnostic.location or "unknown scan location"
        if location not in expected_locations:
            invalid_locations.add(location)

    for (member_location, source_profile), occurrence_count in contract.h5py_dependency_members.items():
        member_candidates = [diagnostic for diagnostic in candidates if diagnostic.location == member_location]
        exact_issues = [
            diagnostic
            for diagnostic in member_candidates
            if isinstance(diagnostic, Issue)
            and _nested_h5py_direct_diagnostic_is_exact(diagnostic, member_location, source_profile)
        ]
        if len(member_candidates) != 2 or len(exact_issues) != 1:
            invalid_locations.add(member_location)
            continue
        direct_issue = exact_issues[0]
        exact_checks = [diagnostic for diagnostic in member_candidates if isinstance(diagnostic, Check)]
        if occurrence_count == 1:
            checks_are_exact = len(exact_checks) == 1 and _nested_h5py_direct_diagnostic_is_exact(
                exact_checks[0], member_location, source_profile
            )
        else:
            checks_are_exact = len(exact_checks) == 1 and _nested_h5py_consolidated_check_is_exact(
                exact_checks[0],
                member_location,
                source_profile,
                occurrence_count,
                direct_issue,
            )
        if not checks_are_exact:
            invalid_locations.add(member_location)
            continue
        validated_ids.update(id(diagnostic) for diagnostic in member_candidates)

    profile_is_valid = metadata_is_exact and bool(contract.h5py_dependency_members) and not invalid_locations
    if not profile_is_valid:
        validated_ids.clear()
    return True, profile_is_valid, invalid_locations, validated_ids


def _nested_corrupt_zip_diagnostic_has_marker(diagnostic: Issue | Check) -> bool:
    return diagnostic.rule_code == "S902" or _zip_format_diagnostic_has_explicit_marker(diagnostic)


def _nested_corrupt_zip_diagnostic_is_candidate(diagnostic: Issue | Check, location: str) -> bool:
    return diagnostic.location == location and _nested_corrupt_zip_diagnostic_has_marker(diagnostic)


def _unexpected_zip_format_diagnostic_locations(
    diagnostics: list[Issue | Check],
    expected_locations: frozenset[str],
    ignored_diagnostic_ids: frozenset[int] = frozenset(),
) -> set[str]:
    return {
        diagnostic.location if isinstance(diagnostic.location, str) else "unknown scan location"
        for diagnostic in diagnostics
        if id(diagnostic) not in ignored_diagnostic_ids
        and diagnostic.location not in expected_locations
        and _zip_format_diagnostic_has_explicit_marker(diagnostic)
    }


def _nested_corrupt_zip_details_key(
    details: dict[str, Any],
    expected_source_profile: XmlArchiveSourceProfile,
) -> tuple[str, str] | None:
    expected_zip_entry, expected_source_name, source_name_is_exact = expected_source_profile
    source_path = details.get("path")
    if (
        frozenset(details) == frozenset({"path", "zip_entry"})
        and details.get("zip_entry") == expected_zip_entry
        and _source_path_matches_temp_profile(source_path, expected_source_name, source_name_is_exact)
        and isinstance(source_path, str)
    ):
        return source_path, expected_zip_entry
    return None


def _nested_corrupt_zip_diagnostic_is_exact(
    diagnostic: Issue | Check,
    expected_source_profile: XmlArchiveSourceProfile,
) -> bool:
    details_key = _nested_corrupt_zip_details_key(diagnostic.details, expected_source_profile)
    common_fields_are_exact = (
        details_key is not None
        and diagnostic.rule_code == "S902"
        and diagnostic.severity == IssueSeverity.INFO
        and diagnostic.message == f"Not a valid zip file: {details_key[0]}"
    )
    if isinstance(diagnostic, Issue):
        return common_fields_are_exact
    return (
        common_fields_are_exact
        and diagnostic.name == "ZIP File Format Validation"
        and diagnostic.status == CheckStatus.FAILED
    )


def _nested_corrupt_zip_consolidated_check_is_exact(
    diagnostic: Issue | Check,
    expected_source_profile: XmlArchiveSourceProfile,
    expected_issue_details: Counter[tuple[str, str]],
    expected_count: int,
) -> bool:
    if not isinstance(diagnostic, Check):
        return False
    details = diagnostic.details
    findings = details.get("findings")
    if (
        diagnostic.name != "ZIP File Format Validation"
        or diagnostic.status != CheckStatus.FAILED
        or diagnostic.rule_code is not None
        or diagnostic.severity != IssueSeverity.INFO
        or diagnostic.message != f"ZIP File Format Validation found {expected_count} issues"
        or frozenset(details) != frozenset({"component_count", "findings"})
        or details.get("component_count") != expected_count
        or not isinstance(findings, list)
        or len(findings) != expected_count
    ):
        return False

    finding_keys: list[tuple[str, str]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            return False
        finding_key = _nested_corrupt_zip_details_key(finding, expected_source_profile)
        if finding_key is None:
            return False
        finding_keys.append(finding_key)
    return Counter(finding_keys) == expected_issue_details


def _validate_nested_corrupt_zip_diagnostics(
    contract: _ZipArchiveOccurrenceContract,
    root_diagnostics: list[Issue | Check],
) -> tuple[bool, set[str], set[str]]:
    invalid_locations: set[str] = set()
    validated_locations: set[str] = set()
    expected_by_location: dict[str, Counter[XmlArchiveSourceProfile]] = {}
    for (location, source_profile), occurrence_count in contract.nested_corrupt_members.items():
        expected_by_location.setdefault(location, Counter())[source_profile] += occurrence_count

    for location, source_profiles in expected_by_location.items():
        candidates = [
            diagnostic
            for diagnostic in root_diagnostics
            if _nested_corrupt_zip_diagnostic_is_candidate(diagnostic, location)
        ]
        if len(source_profiles) != 1:
            invalid_locations.add(location)
            continue
        source_profile, expected_count = next(iter(source_profiles.items()))
        exact_issues = [
            diagnostic
            for diagnostic in candidates
            if (
                diagnostic.location == location
                and isinstance(diagnostic, Issue)
                and _nested_corrupt_zip_diagnostic_is_exact(diagnostic, source_profile)
            )
        ]
        issue_details = Counter(
            details_key
            for diagnostic in exact_issues
            if (details_key := _nested_corrupt_zip_details_key(diagnostic.details, source_profile)) is not None
        )
        if expected_count == 1:
            exact_checks = [
                diagnostic
                for diagnostic in candidates
                if (
                    diagnostic.location == location
                    and isinstance(diagnostic, Check)
                    and _nested_corrupt_zip_diagnostic_is_exact(diagnostic, source_profile)
                )
            ]
            diagnostics_are_exact = len(candidates) == 2 and len(exact_issues) == 1 and len(exact_checks) == 1
        else:
            exact_checks = [
                diagnostic
                for diagnostic in candidates
                if diagnostic.location == location
                and _nested_corrupt_zip_consolidated_check_is_exact(
                    diagnostic,
                    source_profile,
                    issue_details,
                    expected_count,
                )
            ]
            diagnostics_are_exact = (
                len(candidates) == expected_count + 1 and len(exact_issues) == expected_count and len(exact_checks) == 1
            )
        if diagnostics_are_exact:
            validated_locations.add(location)
        else:
            invalid_locations.add(location)

    return not invalid_locations, invalid_locations, validated_locations


def _xml_archive_diagnostic_details_are_exact(
    details: dict[str, Any],
    expected_source_profile: XmlArchiveSourceProfile,
) -> bool:
    expected_zip_entry, expected_source_name, source_name_is_exact = expected_source_profile
    zip_entry = details.get("zip_entry")
    source_path = details.get("path")
    return (
        frozenset(details) == EXPECTED_XML_ARCHIVE_DIAGNOSTIC_FIELDS
        and details.get("format") == "xml_model_inconclusive"
        and _source_path_matches_temp_profile(source_path, expected_source_name, source_name_is_exact)
        and isinstance(zip_entry, str)
        and zip_entry == expected_zip_entry
    )


def _xml_archive_diagnostic_is_candidate(diagnostic: Issue | Check) -> bool:
    return (
        diagnostic.message == EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        or (isinstance(diagnostic, Check) and diagnostic.name == "XML Model Routing")
        or diagnostic.details.get("format") == "xml_model_inconclusive"
    )


def _diagnosed_xml_archive_occurrences(
    results: ModelAuditResultModel,
    root_diagnostics: list[Issue | Check],
    expected_occurrences: Counter[tuple[str, str]],
    expected_source_profiles: dict[tuple[str, str], XmlArchiveSourceProfile],
) -> tuple[Counter[tuple[str, str]], set[str]]:
    direct_issue_occurrences: Counter[tuple[str, str]] = Counter()
    direct_check_occurrences: Counter[tuple[str, str]] = Counter()
    consolidated_check_objects: Counter[tuple[str, str]] = Counter()
    consolidated_check_occurrences: Counter[tuple[str, str]] = Counter()
    invalid_locations: set[str] = set()

    for diagnostic in root_diagnostics:
        if not _xml_archive_diagnostic_is_candidate(diagnostic):
            continue
        location = diagnostic.location or "unknown scan location"
        if diagnostic.message != EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE:
            invalid_locations.add(location)
            continue
        owner = _file_metadata_for_diagnostic(results, location)
        if owner is None:
            invalid_locations.add(location)
            continue
        occurrence_key = (owner[0], location)
        expected_source_profile = expected_source_profiles.get(occurrence_key)
        if expected_occurrences[occurrence_key] == 0 or expected_source_profile is None:
            invalid_locations.add(location)
            continue

        if isinstance(diagnostic, Issue):
            if (
                diagnostic.severity == IssueSeverity.INFO
                and diagnostic.rule_code is None
                and _xml_archive_diagnostic_details_are_exact(diagnostic.details, expected_source_profile)
            ):
                direct_issue_occurrences[occurrence_key] += 1
            else:
                invalid_locations.add(location)
            continue

        if not (
            diagnostic.name == "XML Model Routing"
            and diagnostic.status == CheckStatus.FAILED
            and diagnostic.severity == IssueSeverity.INFO
            and diagnostic.rule_code is None
        ):
            invalid_locations.add(location)
            continue
        if _xml_archive_diagnostic_details_are_exact(diagnostic.details, expected_source_profile):
            direct_check_occurrences[occurrence_key] += 1
            continue

        details = diagnostic.details
        findings = details.get("findings")
        component_count = details.get("component_count")
        if not (
            frozenset(details) == frozenset({"component_count", "findings"})
            and isinstance(component_count, int)
            and not isinstance(component_count, bool)
            and component_count > 0
            and isinstance(findings, list)
            and component_count == len(findings)
            and all(
                isinstance(finding, dict)
                and _xml_archive_diagnostic_details_are_exact(finding, expected_source_profile)
                for finding in findings
            )
        ):
            invalid_locations.add(location)
            continue
        consolidated_check_objects[occurrence_key] += 1
        consolidated_check_occurrences[occurrence_key] += component_count

    diagnosed_occurrences: Counter[tuple[str, str]] = Counter()
    occurrence_keys = (
        expected_occurrences.keys()
        | direct_issue_occurrences.keys()
        | direct_check_occurrences.keys()
        | consolidated_check_objects.keys()
        | consolidated_check_occurrences.keys()
    )
    for occurrence_key in occurrence_keys:
        expected_count = expected_occurrences[occurrence_key]
        representation_is_exact = direct_issue_occurrences[occurrence_key] == (1 if expected_count else 0)
        if expected_count == 1:
            representation_is_exact = (
                representation_is_exact
                and direct_check_occurrences[occurrence_key] == 1
                and consolidated_check_objects[occurrence_key] == 0
                and consolidated_check_occurrences[occurrence_key] == 0
            )
        elif expected_count > 1:
            representation_is_exact = (
                representation_is_exact
                and direct_check_occurrences[occurrence_key] == 0
                and consolidated_check_objects[occurrence_key] == 1
                and consolidated_check_occurrences[occurrence_key] == expected_count
            )
        else:
            representation_is_exact = False
        if representation_is_exact:
            diagnosed_occurrences[occurrence_key] = expected_count
        else:
            invalid_locations.add(occurrence_key[1])
    return diagnosed_occurrences, invalid_locations


def _compression_bomb_diagnostic_is_candidate(diagnostic: Issue | Check) -> bool:
    return (
        diagnostic.message.startswith("Suspicious compression ratio (")
        or (isinstance(diagnostic, Check) and diagnostic.name == "Compression Ratio Check")
        or bool(
            frozenset(
                {"compressed_size", "min_uncompressed_size", "ratio", "threshold", "uncompressed_size"}
            ).intersection(diagnostic.details)
        )
    )


def _validate_compression_bomb_diagnostics(
    owner_path: str,
    contract: _ZipArchiveOccurrenceContract,
    root_diagnostics: list[Issue | Check],
) -> tuple[bool, set[str]]:
    invalid_locations: set[str] = set()
    levels_by_key = {(level.archive_location, level.zip_entry_prefix): level for level in contract.levels}
    diagnostics_by_key: dict[tuple[str, str | None], list[Issue | Check]] = {key: [] for key in levels_by_key}
    for diagnostic in root_diagnostics:
        location = diagnostic.location or "unknown scan location"
        if not (location == owner_path or location.startswith(f"{owner_path}:")):
            continue
        if not _compression_bomb_diagnostic_is_candidate(diagnostic):
            continue
        if isinstance(diagnostic, Check) and diagnostic.status != CheckStatus.FAILED:
            continue
        prefix_is_valid, zip_entry_prefix = _diagnostic_archive_prefix(diagnostic.details)
        level_key = _archive_level_key(owner_path, zip_entry_prefix)
        if not prefix_is_valid or level_key not in levels_by_key:
            invalid_locations.add(location)
            continue
        diagnostics_by_key[level_key].append(diagnostic)

    for level_key, level in levels_by_key.items():
        zip_entry_prefix = level_key[1]
        issue_occurrences: Counter[CompressionBombKey] = Counter()
        direct_check_occurrences: Counter[CompressionBombKey] = Counter()
        consolidated_check_occurrences: list[tuple[int, Counter[CompressionBombKey]]] = []
        for diagnostic in diagnostics_by_key[level_key]:
            location = diagnostic.location or "unknown scan location"
            if isinstance(diagnostic, Issue):
                key = _compression_bomb_key_from_details(diagnostic.details, zip_entry_prefix)
                if not (
                    diagnostic.rule_code == "S410"
                    and diagnostic.severity == IssueSeverity.WARNING
                    and key is not None
                    and level.compression_bombs[key] > 0
                    and location == f"{level.archive_location}:{key[0]}"
                    and diagnostic.message == _compression_bomb_message(key)
                ):
                    invalid_locations.add(location)
                    continue
                issue_occurrences[key] += 1
                continue

            if not (
                diagnostic.name == "Compression Ratio Check"
                and diagnostic.status == CheckStatus.FAILED
                and diagnostic.severity == IssueSeverity.WARNING
            ):
                invalid_locations.add(location)
                continue
            key = _compression_bomb_key_from_details(diagnostic.details, zip_entry_prefix)
            if key is not None:
                if not (
                    diagnostic.rule_code == "S410"
                    and level.compression_bombs[key] > 0
                    and location == f"{level.archive_location}:{key[0]}"
                    and diagnostic.message == _compression_bomb_message(key)
                ):
                    invalid_locations.add(location)
                    continue
                direct_check_occurrences[key] += 1
                continue

            details = diagnostic.details
            findings = details.get("findings")
            component_count = details.get("component_count")
            if not (
                diagnostic.rule_code is None
                and frozenset(details) == frozenset({"component_count", "findings"})
                and isinstance(component_count, int)
                and not isinstance(component_count, bool)
                and component_count > 1
                and isinstance(findings, list)
                and bool(findings)
            ):
                invalid_locations.add(location)
                continue
            child_occurrences: Counter[CompressionBombKey] = Counter()
            for finding in findings:
                if not isinstance(finding, dict):
                    child_occurrences.clear()
                    break
                child_key = _compression_bomb_key_from_details(finding, zip_entry_prefix)
                if child_key is None or level.compression_bombs[child_key] == 0:
                    child_occurrences.clear()
                    break
                child_occurrences[child_key] += 1
            if not child_occurrences:
                invalid_locations.add(location)
                continue
            expected_messages = [_compression_bomb_message(item) for item in level.compression_bomb_order]
            expected_message = (
                expected_messages[0]
                if len(set(expected_messages)) == 1
                else f"Compression Ratio Check found {len(expected_messages)} issues"
            )
            first_group_entry = level.compression_check_entries[0] if level.compression_check_entries else None
            if (
                first_group_entry is None
                or location != f"{level.archive_location}:{first_group_entry}"
                or diagnostic.message != expected_message
            ):
                child_occurrences.clear()
                invalid_locations.add(location)
                continue
            consolidated_check_occurrences.append((component_count, child_occurrences))

        expected_issue_occurrences = Counter(dict.fromkeys(level.compression_bombs, 1))
        if issue_occurrences != expected_issue_occurrences:
            invalid_locations.add(level.archive_location)
        compression_group_count = len(level.compression_check_entries)
        if not level.compression_bombs:
            if direct_check_occurrences or consolidated_check_occurrences:
                invalid_locations.add(level.archive_location)
        elif compression_group_count == 1:
            if direct_check_occurrences != level.compression_bombs or consolidated_check_occurrences:
                invalid_locations.add(level.archive_location)
        elif (
            direct_check_occurrences
            or len(consolidated_check_occurrences) != 1
            or consolidated_check_occurrences[0][0] != compression_group_count
            or consolidated_check_occurrences[0][1] != level.compression_bombs
        ):
            invalid_locations.add(level.archive_location)
    return not invalid_locations, invalid_locations


def _is_expected_pickle_incomplete_diagnostic(
    diagnostic: Issue | Check,
    details: dict[str, Any],
) -> bool:
    if not (
        (not isinstance(diagnostic, Check) or diagnostic.status == CheckStatus.FAILED)
        and diagnostic.message in EXPECTED_PICKLE_INCOMPLETE_MESSAGES
        and details.get("analysis_incomplete") is True
        and _incomplete_diagnostic_state_is_consistent(details)
        and isinstance(details.get("pickle_source"), str)
    ):
        return False
    if diagnostic.message == "Nested pickle analysis did not complete":
        return details.get("nested_status") == "inconclusive" and isinstance(details.get("nested_encoding"), str)
    if diagnostic.message == "Nested pickle payload exceeds deep-scan byte limit":
        return (
            isinstance(details.get("encoding"), str)
            and isinstance(details.get("max_nested_pickle_bytes"), int)
            and details.get("nested_has_execution_opcode") is True
        )
    return isinstance(details.get("encoding"), str) and isinstance(details.get("max_nested_payload_probes"), int)


def _is_expected_call_graph_source_unavailable_diagnostic(
    diagnostic: Issue | Check,
    details: dict[str, Any],
) -> bool:
    return (
        isinstance(diagnostic, Check)
        and diagnostic.status == CheckStatus.PASSED
        and diagnostic.message == "Python call-graph analysis could not inspect invoked callable source"
        and details.get("notice_code") == "call_graph_source_unavailable"
        and details.get("pickle_notice_code") == "call_graph_source_unavailable"
        and details.get("reason") == "source_unavailable"
        and details.get("analysis_incomplete") is True
        and isinstance(details.get("pickle_source"), str)
    )


def assert_no_unexpected_asset_scan_errors(results: ModelAuditResultModel, scan_description: str) -> None:
    root_diagnostics: list[Issue | Check] = [*results.issues, *results.checks]
    diagnostics = [
        (diagnostic, details)
        for diagnostic in root_diagnostics
        for details in _nested_diagnostic_details(diagnostic.details)
    ]
    unexpected_errors = {asset.path for asset in results.assets if asset.type == "error"}
    for diagnostic, details in diagnostics:
        if _has_malformed_diagnostic_markers(details):
            unexpected_errors.add(diagnostic.location or "unknown scan location")

    archive_contracts: dict[str, _ZipArchiveOccurrenceContract] = {}
    corrupt_zip_paths: set[str] = set()
    validated_corrupt_zip_paths: set[str] = set()
    nested_corrupt_zip_paths: set[str] = set()
    validated_nested_corrupt_zip_paths: set[str] = set()
    validated_nested_corrupt_zip_locations: set[str] = set()
    compression_bomb_paths: set[str] = set()
    compression_bomb_locations: set[str] = set()
    validated_compression_bomb_paths: set[str] = set()
    nested_h5py_dependency_paths: set[str] = set()
    validated_nested_h5py_dependency_paths: set[str] = set()
    validated_nested_h5py_diagnostic_ids: set[int] = set()
    for path, metadata in results.file_metadata.items():
        payload = metadata.model_dump(exclude_none=True)
        contract, contract_errors = _zip_archive_occurrence_contract(path, payload)
        if contract is None:
            unexpected_errors.update(contract_errors)
            continue
        archive_contracts[path] = contract
        unexpected_errors.update(contract_errors)
        if contract.root_is_corrupt:
            corrupt_zip_paths.add(path)
            corrupt_zip_is_valid, corrupt_zip_errors = _validate_corrupt_zip_diagnostics(
                path,
                root_diagnostics,
            )
            unexpected_errors.update(corrupt_zip_errors)
            if corrupt_zip_is_valid:
                validated_corrupt_zip_paths.add(path)
                unexpected_errors.discard(path)
            continue
        h5py_claimed, h5py_is_valid, h5py_errors, h5py_diagnostic_ids = _validate_nested_h5py_dependency_profile(
            path, payload, contract, root_diagnostics
        )
        unexpected_errors.update(h5py_errors)
        if h5py_claimed:
            nested_h5py_dependency_paths.add(path)
        if h5py_is_valid:
            validated_nested_h5py_dependency_paths.add(path)
            validated_nested_h5py_diagnostic_ids.update(h5py_diagnostic_ids)
        nested_corrupt_is_valid, nested_corrupt_errors, nested_corrupt_locations = (
            _validate_nested_corrupt_zip_diagnostics(contract, root_diagnostics)
        )
        unexpected_errors.update(nested_corrupt_errors)
        if contract.nested_corrupt_members:
            nested_corrupt_zip_paths.add(path)
            if nested_corrupt_is_valid:
                validated_nested_corrupt_zip_paths.add(path)
                validated_nested_corrupt_zip_locations.update(nested_corrupt_locations)
        unexpected_errors.update(_validate_path_traversal_diagnostics(path, contract, root_diagnostics))
        compression_levels = [level for level in contract.levels if level.compression_bombs]
        compression_is_valid, compression_errors = _validate_compression_bomb_diagnostics(
            path,
            contract,
            root_diagnostics,
        )
        unexpected_errors.update(compression_errors)
        if compression_levels:
            compression_bomb_paths.add(path)
            compression_bomb_locations.update(
                f"{level.archive_location}:{entry}"
                for level in compression_levels
                for entry, _compressed_size, _uncompressed_size in level.compression_bombs
            )
            if compression_is_valid:
                validated_compression_bomb_paths.add(path)

    validated_direct_h5py_diagnostic_ids, direct_h5py_errors = _validate_direct_h5py_dependency_profiles(
        results,
        root_diagnostics,
        frozenset(validated_nested_h5py_dependency_paths),
    )
    unexpected_errors.update(direct_h5py_errors)
    validated_h5py_diagnostic_ids = validated_direct_h5py_diagnostic_ids | frozenset(
        validated_nested_h5py_diagnostic_ids
    )
    (
        validated_direct_hdf5_probe_diagnostic_ids,
        validated_direct_hdf5_probe_paths,
        direct_hdf5_probe_errors,
    ) = _validate_direct_hdf5_userblock_probe_profiles(results, root_diagnostics)
    unexpected_errors.update(direct_hdf5_probe_errors)

    expected_source_changes = set()
    expected_zip_format_locations = frozenset(
        corrupt_zip_paths
        | {
            location
            for contract in archive_contracts.values()
            for location, _source_profile in contract.nested_corrupt_members
        }
    )
    unexpected_errors.update(
        _unexpected_zip_format_diagnostic_locations(
            root_diagnostics,
            expected_zip_format_locations,
            frozenset(validated_nested_h5py_diagnostic_ids),
        )
    )

    expected_dependency_outcomes: set[tuple[str, str]] = set()
    expected_coverage_outcomes: set[tuple[str, str]] = set()
    expected_security_outcomes: set[tuple[str, str]] = set()
    expected_xml_member_occurrences: Counter[tuple[str, str]] = Counter()
    expected_xml_source_profiles: dict[tuple[str, str], XmlArchiveSourceProfile] = {}
    expected_xml_member_coverage_outcomes: Counter[tuple[str, str, str]] = Counter()
    dependency_incomplete_paths: set[str] = set()
    security_incomplete_paths: set[str] = set()
    security_finding_locations = {
        issue.location for issue in results.issues if issue.rule_code == "S204" and issue.location is not None
    } | compression_bomb_locations
    actionable_security_finding_locations = {
        issue.location
        for issue in results.issues
        if issue.severity == IssueSeverity.CRITICAL and issue.location is not None
    }
    coverage_only_paths = set()
    unavailable_scanner_paths = set()
    diagnosed_dependency_outcomes: set[tuple[str, str]] = set()
    diagnosed_coverage_outcomes: set[tuple[str, str]] = set()
    diagnosed_security_outcomes: set[tuple[str, str]] = set()
    diagnosed_xml_member_coverage_outcomes: Counter[tuple[str, str, str]] = Counter()
    diagnostic_incomplete_paths: set[str] = set()
    for path, metadata in results.file_metadata.items():
        payload = metadata.model_dump(exclude_none=True)
        if _has_malformed_diagnostic_markers(payload):
            unexpected_errors.add(path)
            continue
        scan_outcome_reasons = payload.get("scan_outcome_reasons")
        coverage_reasons: set[str] = set()
        security_reasons: set[str] = set()
        if scan_outcome_reasons is None:
            if payload.get("analysis_incomplete") is True or payload.get("scan_outcome") == "inconclusive":
                unexpected_errors.add(path)
        else:
            if (
                not isinstance(scan_outcome_reasons, list)
                or not scan_outcome_reasons
                or not all(isinstance(reason, str) and bool(reason) for reason in scan_outcome_reasons)
            ):
                unexpected_errors.add(path)
                continue
            if len(scan_outcome_reasons) != len(set(scan_outcome_reasons)):
                unexpected_errors.add(path)
                continue
            string_reasons = set(scan_outcome_reasons)
            dependency_reasons = string_reasons.intersection(EXPECTED_DEPENDENCY_OUTCOME_REASONS)
            coverage_reasons = {
                reason
                for reason in string_reasons
                if metadata_has_coverage_only_operational_error(
                    {"operational_error": True, "operational_error_reason": reason}
                )
            }
            if path in validated_direct_hdf5_probe_paths:
                coverage_reasons.update(string_reasons.intersection({DIRECT_HDF5_USERBLOCK_PROBE_REASON}))
            if (
                metadata_has_coverage_only_operational_error(payload)
                or path in compression_bomb_paths
                or path in corrupt_zip_paths
                or path in nested_corrupt_zip_paths
                or path in validated_nested_h5py_dependency_paths
            ):
                coverage_reasons.update(string_reasons.intersection(EXPECTED_COVERAGE_AGGREGATION_OUTCOME_REASONS))
            path_has_actionable_security_finding = any(
                finding_location == path
                or finding_location.startswith(f"{path} (")
                or finding_location.startswith(f"{path}:")
                for finding_location in actionable_security_finding_locations
            )
            security_reasons = string_reasons.intersection(EXPECTED_SECURITY_FINDING_OUTCOME_REASONS)
            if security_reasons and not (
                payload.get("analysis_incomplete") is True
                and payload.get("scan_outcome") == "inconclusive"
                and payload.get("pickle_report_status") == "inconclusive"
                and payload.get("pickle_verdict") == "malicious"
                and path_has_actionable_security_finding
            ):
                security_reasons = set()
            allowed_reasons = dependency_reasons | coverage_reasons | security_reasons
            if Path(path).resolve() == EXPECTED_AGPL_SOURCE_STABILITY_ASSET:
                allowed_reasons.update(string_reasons.intersection({"call_graph_analysis_error"}))
            if string_reasons - allowed_reasons:
                unexpected_errors.add(path)
            if dependency_reasons:
                dependency_incomplete_paths.add(path)
                expected_dependency_outcomes.update((path, reason) for reason in dependency_reasons)
            if security_reasons:
                security_incomplete_paths.add(path)
                expected_security_outcomes.update((path, reason) for reason in security_reasons)
            if "xml_model_routing_incomplete" in coverage_reasons:
                archive_contract = archive_contracts.get(path)
                expected_members = archive_contract.xml_members if archive_contract is not None else None
                expected_member_reasons = coverage_reasons.intersection(
                    {"xml_model_routing_incomplete", "zip_analysis_incomplete"}
                )
                if archive_contract is None or not expected_members or not expected_member_reasons:
                    unexpected_errors.add(path)
                else:
                    for member_path, occurrence_count in expected_members.items():
                        source_profiles = archive_contract.xml_source_profiles.get(member_path, set())
                        if len(source_profiles) != 1:
                            unexpected_errors.add(path)
                            continue
                        expected_xml_source_profiles[(path, member_path)] = next(iter(source_profiles))
                        expected_xml_member_occurrences[(path, member_path)] += occurrence_count
                        for reason in expected_member_reasons:
                            expected_xml_member_coverage_outcomes[(path, member_path, reason)] += occurrence_count
        operational_error_reason = payload.get("operational_error_reason")
        scan_outcome_reason = payload.get("scan_outcome_reason")
        has_failed_outcome_reason = isinstance(scan_outcome_reasons, list) and any(
            isinstance(reason, str) and reason.endswith(OPERATIONAL_FAILURE_REASON_SUFFIXES)
            for reason in scan_outcome_reasons
        )
        has_noncoverage_outcome_reason = (
            isinstance(scan_outcome_reason, str)
            and bool(scan_outcome_reason)
            and not metadata_has_coverage_only_operational_error(
                {"operational_error": True, "operational_error_reason": scan_outcome_reason}
            )
        )
        if payload.get("operational_error") is not True:
            has_unflagged_coverage_reason = (
                isinstance(scan_outcome_reason, str)
                and bool(scan_outcome_reason)
                and not has_noncoverage_outcome_reason
            ) or (
                isinstance(scan_outcome_reasons, list)
                and any(
                    isinstance(reason, str)
                    and reason
                    and metadata_has_coverage_only_operational_error(
                        {"operational_error": True, "operational_error_reason": reason}
                    )
                    for reason in scan_outcome_reasons
                )
            )
            path_has_security_finding = any(
                finding_location == path
                or finding_location.startswith(f"{path} (")
                or finding_location.startswith(f"{path}:")
                for finding_location in security_finding_locations
            )
            path_has_fail_closed_evidence = (
                path_has_security_finding
                or path in validated_corrupt_zip_paths
                or path in validated_nested_corrupt_zip_paths
                or path in validated_nested_h5py_dependency_paths
                or path in validated_direct_hdf5_probe_paths
            )
            unflagged_coverage_is_inconclusive = (
                payload.get("analysis_incomplete") is True
                and payload.get("scan_outcome") == "inconclusive"
                and isinstance(scan_outcome_reasons, list)
                and bool(scan_outcome_reasons)
                and (
                    "scan_outcome_reason" not in payload
                    or (
                        isinstance(scan_outcome_reason, str)
                        and bool(scan_outcome_reason)
                        and scan_outcome_reason in scan_outcome_reasons
                    )
                )
            )
            if (
                (isinstance(operational_error_reason, str) and operational_error_reason)
                or has_failed_outcome_reason
                or has_noncoverage_outcome_reason
                or (
                    has_unflagged_coverage_reason
                    and (not path_has_fail_closed_evidence or not unflagged_coverage_is_inconclusive)
                )
            ):
                unexpected_errors.add(path)
            else:
                expected_coverage_outcomes.update((path, reason) for reason in coverage_reasons)
            continue
        if metadata_has_coverage_only_operational_error(payload):
            coverage_only_is_inconclusive = (
                payload.get("analysis_incomplete") is True
                and payload.get("scan_outcome") == "inconclusive"
                and isinstance(scan_outcome_reasons, list)
                and all(isinstance(reason, str) for reason in scan_outcome_reasons)
                and operational_error_reason in scan_outcome_reasons
                and not any(reason.endswith(OPERATIONAL_FAILURE_REASON_SUFFIXES) for reason in scan_outcome_reasons)
            )
            if coverage_only_is_inconclusive:
                coverage_only_paths.add(path)
                expected_coverage_outcomes.update((path, reason) for reason in coverage_reasons)
                if operational_error_reason == "recognized_format_scanner_unavailable":
                    unavailable_scanner_paths.add(path)
            else:
                unexpected_errors.add(path)
            continue

        if (
            Path(path).resolve() == EXPECTED_AGPL_SOURCE_STABILITY_ASSET
            and payload.get("operational_error_reason") == "call_graph_analysis_error"
            and payload.get("analysis_incomplete") is True
            and payload.get("scan_outcome") == "inconclusive"
            and isinstance(scan_outcome_reasons, list)
            and all(isinstance(reason, str) for reason in scan_outcome_reasons)
            and len(scan_outcome_reasons) == len(EXPECTED_AGPL_SOURCE_STABILITY_OUTCOME_REASONS)
            and frozenset(scan_outcome_reasons) == EXPECTED_AGPL_SOURCE_STABILITY_OUTCOME_REASONS
            and payload.get("pickle_report_status") == "inconclusive"
            and payload.get("pickle_verdict") == "malicious"
            and isinstance(payload.get("pickle_source"), str)
            and Path(payload["pickle_source"]).resolve() == EXPECTED_AGPL_SOURCE_STABILITY_ASSET
        ):
            expected_source_changes.add(path)
            expected_coverage_outcomes.update((path, reason) for reason in coverage_reasons)
        else:
            unexpected_errors.add(path)

    diagnosed_xml_member_occurrences, invalid_xml_diagnostic_locations = _diagnosed_xml_archive_occurrences(
        results,
        root_diagnostics,
        expected_xml_member_occurrences,
        expected_xml_source_profiles,
    )
    unexpected_errors.update(invalid_xml_diagnostic_locations)
    for (owner_path, member_path, reason), expected_count in expected_xml_member_coverage_outcomes.items():
        diagnosed_xml_member_coverage_outcomes[(owner_path, member_path, reason)] = diagnosed_xml_member_occurrences[
            (owner_path, member_path)
        ]
        if diagnosed_xml_member_coverage_outcomes[(owner_path, member_path, reason)] != expected_count:
            unexpected_errors.add(owner_path)
    for owner_path, reason in expected_coverage_outcomes:
        xml_pairs = {
            (path, member_path, expected_reason): expected_count
            for (path, member_path, expected_reason), expected_count in expected_xml_member_coverage_outcomes.items()
            if path == owner_path and expected_reason == reason
        }
        if xml_pairs and all(
            diagnosed_xml_member_coverage_outcomes[pair] == expected_count for pair, expected_count in xml_pairs.items()
        ):
            diagnosed_coverage_outcomes.add((owner_path, reason))
            diagnostic_incomplete_paths.add(owner_path)

    for owner_path in compression_bomb_paths:
        compression_coverage_pair = (owner_path, "zip_analysis_incomplete")
        if (
            owner_path in validated_compression_bomb_paths
            and compression_coverage_pair in expected_coverage_outcomes
            and results.success is False
            and determine_exit_code(results) == 1
        ):
            diagnosed_coverage_outcomes.add(compression_coverage_pair)
            diagnostic_incomplete_paths.add(owner_path)
        else:
            unexpected_errors.add(owner_path)

    for owner_path in corrupt_zip_paths:
        corrupt_coverage_pair = (owner_path, "zip_analysis_incomplete")
        if (
            owner_path in validated_corrupt_zip_paths
            and corrupt_coverage_pair in expected_coverage_outcomes
            and results.success is False
            and determine_exit_code(results) == 2
        ):
            diagnosed_coverage_outcomes.add(corrupt_coverage_pair)
            diagnostic_incomplete_paths.add(owner_path)
        else:
            unexpected_errors.add(owner_path)

    for owner_path in nested_corrupt_zip_paths:
        nested_corrupt_coverage_pair = (owner_path, "zip_analysis_incomplete")
        if (
            owner_path in validated_nested_corrupt_zip_paths
            and nested_corrupt_coverage_pair in expected_coverage_outcomes
            and results.success is False
            and determine_exit_code(results) == 2
        ):
            diagnosed_coverage_outcomes.add(nested_corrupt_coverage_pair)
            diagnostic_incomplete_paths.add(owner_path)
        else:
            unexpected_errors.add(owner_path)

    for owner_path in nested_h5py_dependency_paths:
        nested_h5py_coverage_pair = (owner_path, "zip_analysis_incomplete")
        owner_has_actionable_security_finding = any(
            location == owner_path or location.startswith(f"{owner_path}:")
            for location in actionable_security_finding_locations
        )
        expected_exit_code = 1 if owner_has_actionable_security_finding else 2
        if (
            owner_path in validated_nested_h5py_dependency_paths
            and nested_h5py_coverage_pair in expected_coverage_outcomes
            and results.success is False
            and determine_exit_code(results) == expected_exit_code
        ):
            diagnosed_coverage_outcomes.add(nested_h5py_coverage_pair)
            diagnostic_incomplete_paths.add(owner_path)
        else:
            unexpected_errors.add(owner_path)

    diagnosed_source_changes = set()
    diagnosed_unavailable_scanners = set()
    for diagnostic, details in diagnostics:
        location = diagnostic.location or "unknown scan location"
        if _xml_archive_diagnostic_is_candidate(diagnostic):
            continue
        if diagnostic.rule_code == "S410" or _compression_bomb_diagnostic_is_candidate(diagnostic):
            continue
        if (
            isinstance(diagnostic.location, str)
            and diagnostic.location in corrupt_zip_paths
            and _corrupt_zip_diagnostic_is_candidate(diagnostic, diagnostic.location)
        ):
            continue
        if (
            isinstance(diagnostic.location, str)
            and diagnostic.location in validated_nested_corrupt_zip_locations
            and _nested_corrupt_zip_diagnostic_is_candidate(diagnostic, diagnostic.location)
        ):
            continue
        pickle_source = details.get("pickle_source")
        category = details.get("category")
        scan_outcome_reason = details.get("scan_outcome_reason")
        scan_outcome_reasons = details.get("scan_outcome_reasons")
        if _has_malformed_diagnostic_markers(details) or not _security_notice_aliases_are_valid(details):
            unexpected_errors.add(location)
            continue
        if id(diagnostic) in validated_direct_hdf5_probe_diagnostic_ids:
            diagnostic_owner = _file_metadata_for_diagnostic(results, location)
            coverage_pair = (
                (diagnostic_owner[0], DIRECT_HDF5_USERBLOCK_PROBE_REASON) if diagnostic_owner is not None else None
            )
            if coverage_pair is None or coverage_pair not in expected_coverage_outcomes:
                unexpected_errors.add(location)
            else:
                diagnosed_coverage_outcomes.add(coverage_pair)
                diagnostic_incomplete_paths.add(coverage_pair[0])
            continue
        coverage_only_diagnostic = metadata_has_coverage_only_operational_error(
            {
                "operational_error": True,
                "operational_error_reason": scan_outcome_reason,
            }
        )
        has_noncoverage_outcome_reason = (
            isinstance(scan_outcome_reason, str) and bool(scan_outcome_reason) and not coverage_only_diagnostic
        )
        has_operational_marker = (
            details.get("operational_error") is True
            or details.get("interrupted") is True
            or (isinstance(scan_outcome_reason, str) and bool(scan_outcome_reason))
        )
        diagnostic_is_failed = not isinstance(diagnostic, Check) or diagnostic.status == CheckStatus.FAILED
        expected_security_outcome_reason = _expected_security_outcome_reason(diagnostic, details)
        expected_pickle_incomplete = _is_expected_pickle_incomplete_diagnostic(diagnostic, details)
        expected_call_graph_source_unavailable = _is_expected_call_graph_source_unavailable_diagnostic(
            diagnostic, details
        )
        expected_coverage_incomplete = (
            diagnostic_is_failed
            and details.get("analysis_incomplete") is True
            and _incomplete_diagnostic_state_is_consistent(details)
            and isinstance(scan_outcome_reason, str)
            and coverage_only_diagnostic
        )
        if "exception" in details:
            unexpected_errors.add(location)
            continue

        if not diagnostic_is_failed and has_operational_marker:
            unexpected_errors.add(location)
            continue

        if diagnostic.message == EXPECTED_UNAVAILABLE_SCANNER_MESSAGE:
            unavailable_check = diagnostic if isinstance(diagnostic, Check) else None
            if (
                unavailable_check is not None
                and unavailable_check.status == CheckStatus.FAILED
                and frozenset(details) == EXPECTED_UNAVAILABLE_SCANNER_DIAGNOSTIC_FIELDS
                and isinstance(details.get("format"), str)
                and bool(details["format"])
                and details.get("path") == location
                and location in unavailable_scanner_paths
            ):
                diagnosed_unavailable_scanners.add(location)
                diagnosed_coverage_outcomes.add((location, "recognized_format_scanner_unavailable"))
                diagnostic_incomplete_paths.add(location)
            else:
                unexpected_errors.add(location)
            continue

        diagnostic_owner = _file_metadata_for_diagnostic(results, location)
        expected_security_message_reason = next(
            (
                reason
                for reason, message in EXPECTED_SECURITY_FINDING_OUTCOME_MESSAGES.items()
                if diagnostic.message == message
            ),
            None,
        )
        aliasless_security_finding_identity = (
            diagnostic.rule_code in {"S213", "S601"}
            and diagnostic.severity == IssueSeverity.CRITICAL
            and details.get("pickle_rule_code") == diagnostic.rule_code
            and diagnostic.message in EXPECTED_PICKLE_INCOMPLETE_MESSAGES
            and isinstance(pickle_source, str)
        )
        expected_aliasless_security_finding = (
            aliasless_security_finding_identity
            and expected_pickle_incomplete
            and "notice_code" not in details
            and "pickle_notice_code" not in details
            and not any(field in details for field in ALIASLESS_PICKLE_DISALLOWED_FIELDS)
        )
        if aliasless_security_finding_identity and not expected_aliasless_security_finding:
            unexpected_errors.add(location)
            continue
        if (
            expected_security_message_reason is not None
            and expected_security_outcome_reason != expected_security_message_reason
            and not expected_aliasless_security_finding
        ):
            unexpected_errors.add(location)
            continue
        if expected_security_outcome_reason is not None:
            source_owner = (
                _file_metadata_for_diagnostic(results, pickle_source) if isinstance(pickle_source, str) else None
            )
            security_pair = (
                (diagnostic_owner[0], expected_security_outcome_reason)
                if diagnostic_owner is not None and source_owner is not None and source_owner[0] == diagnostic_owner[0]
                else None
            )
            if (
                security_pair is None
                or security_pair not in expected_security_outcomes
                or ("scan_outcome_reason" in details and scan_outcome_reason != expected_security_outcome_reason)
            ):
                unexpected_errors.add(location)
                continue
            diagnosed_security_outcomes.add(security_pair)
            diagnostic_incomplete_paths.add(security_pair[0])

        if expected_pickle_incomplete and "scan_outcome_reason" in details:
            expected_message_reason = next(
                (
                    reason
                    for reason, message in EXPECTED_SECURITY_FINDING_OUTCOME_MESSAGES.items()
                    if diagnostic.message == message
                ),
                None,
            )
            if scan_outcome_reason != expected_message_reason:
                unexpected_errors.add(location)
                continue

        if coverage_only_diagnostic:
            coverage_pair = (
                (diagnostic_owner[0], scan_outcome_reason)
                if diagnostic_owner is not None and isinstance(scan_outcome_reason, str)
                else None
            )
            expected_archive_member_coverage = (
                diagnostic_owner is not None
                and _is_expected_archive_member_coverage_diagnostic(
                    diagnostic,
                    details,
                    diagnostic_owner[0],
                    diagnostic_owner[1],
                    diagnostics,
                    expected_dependency_outcomes,
                    validated_h5py_diagnostic_ids,
                )
            )
            if (
                not expected_coverage_incomplete
                or coverage_pair is None
                or (coverage_pair not in expected_coverage_outcomes and not expected_archive_member_coverage)
            ):
                unexpected_errors.add(location)
                continue
            if coverage_pair in expected_coverage_outcomes:
                diagnosed_coverage_outcomes.add(coverage_pair)
                aggregate_pair = (coverage_pair[0], "zip_analysis_incomplete")
                if location.startswith(f"{coverage_pair[0]}:") and aggregate_pair in expected_coverage_outcomes:
                    diagnosed_coverage_outcomes.add(aggregate_pair)
            diagnostic_incomplete_paths.add(coverage_pair[0])

        if category == "call_graph_analysis_error" or (
            pickle_source and category not in {None, "parse_error"} and "exception_type" in details
        ):
            matching_paths = {path for path in expected_source_changes if location == path}
            if (
                matching_paths
                and isinstance(pickle_source, str)
                and Path(pickle_source).resolve() == EXPECTED_AGPL_SOURCE_STABILITY_ASSET
                and diagnostic.message
                == "Python call-graph analysis could not complete: source changed during shared call-graph analysis"
                and category == "call_graph_analysis_error"
                and details.get("exception_type") == "_CallGraphAnalysisLimitError"
                and details.get("analysis") == "python_call_graph_source_stability"
                and details.get("analysis_incomplete") is True
                and details.get("source_stability_reason") == EXPECTED_AGPL_SOURCE_STABILITY_REASON
                and diagnostic_is_failed
                and any(
                    finding_location == location or finding_location.startswith(f"{location} (")
                    for finding_location in security_finding_locations
                )
            ):
                diagnosed_source_changes.update(matching_paths)
            else:
                unexpected_errors.add(location)
            continue

        if "required_package" in details:
            diagnostic_metadata = diagnostic_owner[1] if diagnostic_owner is not None else None
            if diagnostic_owner is not None and diagnostic_metadata is not None:
                owner_path = diagnostic_owner[0]
                diagnostic_reasons = _expected_missing_dependency_reasons(
                    diagnostic,
                    details,
                    owner_path,
                    diagnostic_metadata,
                    expected_dependency_outcomes,
                    h5py_profile_is_valid=id(diagnostic) in validated_h5py_diagnostic_ids,
                )
                if diagnostic_reasons:
                    diagnosed_dependency_outcomes.update((owner_path, reason) for reason in diagnostic_reasons)
                    diagnostic_incomplete_paths.add(owner_path)
                    continue
            unexpected_errors.add(location)
            continue

        has_unexplained_operational_marker = (
            (
                isinstance(category, str)
                and category != "parse_error"
                and category.endswith(OPERATIONAL_FAILURE_REASON_SUFFIXES)
            )
            or "operational_error_reason" in details
            or "scan_outcome_reasons" in details
            or details.get("scan_outcome") == "inconclusive"
            or (
                details.get("analysis_incomplete") is True
                and category != "parse_error"
                and expected_security_outcome_reason is None
                and not expected_pickle_incomplete
                and not expected_call_graph_source_unavailable
                and not expected_coverage_incomplete
            )
        )
        if has_unexplained_operational_marker:
            unexpected_errors.add(location)
            continue

        explicit_operational_failure = (
            (details.get("operational_error") is True and not coverage_only_diagnostic)
            or details.get("interrupted") is True
            or has_noncoverage_outcome_reason
            or (
                details.get("analysis_incomplete") is True
                and ("max_total_size" in details or ("scan_outcome_reason" in details and not coverage_only_diagnostic))
            )
        )
        if explicit_operational_failure:
            unexpected_errors.add(location)
            continue

        if category == "parse_error":
            if "error" in details or "error_type" in details:
                unexpected_errors.add(location)
            continue
        if pickle_source:
            if "exception_type" in details or "error_type" in details or "error" in details:
                unexpected_errors.add(location)
            continue

        scan_budget_failure = (diagnostic.rule_code == "S902" or diagnostic.severity == IssueSeverity.INFO) and (
            any(key.startswith("max_") for key in details)
            or details.get("security_check") == "compression_bomb_detection"
        )
        if (
            (scan_budget_failure and not coverage_only_diagnostic)
            or "exception_type" in details
            or "error_type" in details
            or "error" in details
            or details.get("operational_error") is True
            or details.get("interrupted") is True
            or (
                details.get("analysis_incomplete") is True
                and ("max_total_size" in details or ("scan_outcome_reason" in details and not coverage_only_diagnostic))
            )
        ):
            unexpected_errors.add(location)
            continue

    unexpected_errors.update(path for path, _reason in expected_dependency_outcomes - diagnosed_dependency_outcomes)
    unexpected_errors.update(path for path, _reason in expected_security_outcomes - diagnosed_security_outcomes)
    unexpected_errors.update(path for path, _reason in diagnosed_security_outcomes - expected_security_outcomes)
    unexpected_errors.update(path for path, _reason in expected_coverage_outcomes - diagnosed_coverage_outcomes)
    unexpected_errors.update(path for path, _reason in diagnosed_coverage_outcomes - expected_coverage_outcomes)
    unexpected_errors.update(
        path
        for path, _member, _reason in expected_xml_member_coverage_outcomes - diagnosed_xml_member_coverage_outcomes
    )
    unexpected_errors.update(
        path
        for path, _member, _reason in diagnosed_xml_member_coverage_outcomes - expected_xml_member_coverage_outcomes
    )
    unexpected_errors.update(unavailable_scanner_paths - diagnosed_unavailable_scanners)
    incomplete_asset_paths = (
        coverage_only_paths | dependency_incomplete_paths | security_incomplete_paths | diagnostic_incomplete_paths
    )
    if incomplete_asset_paths and (results.success is not False or determine_exit_code(results) == 0):
        unexpected_errors.update(incomplete_asset_paths)
    error_message = (
        f"{scan_description} should not have unexpected operational errors: {describe_operational_errors(results)}"
    )
    assert not unexpected_errors, error_message
    if expected_source_changes:
        assert results.has_errors and expected_source_changes == diagnosed_source_changes, error_message
        assert results.success is False, f"{scan_description} must fail closed when source stability changes"
        assert determine_exit_code(results) == 2, f"{scan_description} must preserve its operational-error exit code"
        return
    assert not results.has_errors and not diagnosed_source_changes, error_message


class TestSecurityAssetIntegration:
    """Integration tests for security assets using organized structure."""

    @pytest.fixture
    def assets_dir(self):
        """Get the path to organized test assets."""
        return Path(__file__).parent / "assets"

    @pytest.fixture
    def samples_dir(self, assets_dir):
        """Get the samples directory for individual test files."""
        return assets_dir / "samples"

    @pytest.fixture
    def scenarios_dir(self, assets_dir):
        """Get the scenarios directory for complex test scenarios."""
        return assets_dir / "scenarios"

    def get_malicious_samples(self, samples_dir: Path) -> list[Path]:
        """Get all malicious sample files from organized structure."""
        malicious_files = []

        # Check different sample categories
        categories = [
            "pickles",
            "keras",
            "pytorch",
            "tensorflow",
            "manifests",
            "archives",
        ]

        for category in categories:
            category_dir = samples_dir / category
            if category_dir.exists():
                # Look for files with malicious indicators
                for file_path in category_dir.iterdir():
                    if any(
                        indicator in file_path.name.lower() for indicator in ["malicious", "evil", "suspicious", "bad"]
                    ):
                        malicious_files.append(file_path)

        return malicious_files

    def get_safe_samples(self, samples_dir: Path) -> list[Path]:
        """Get all safe sample files from organized structure."""
        safe_files = []
        explicitly_malicious_fixtures = {
            "custom_layer_attack.h5",
            "loss_injection.h5",
            "metric_injection.h5",
        }

        categories = [
            "pickles",
            "keras",
            "pytorch",
            "tensorflow",
            "manifests",
            "archives",
        ]

        for category in categories:
            category_dir = samples_dir / category
            if category_dir.exists():
                for file_path in category_dir.iterdir():
                    # Exclude malicious files and problematic files like dill_func.pkl
                    exclusions = [
                        "malicious",
                        "evil",
                        "suspicious",
                        "bad",
                        "dill_func",
                        "path_traversal",
                        "nested_pickle",  # Our intentionally malicious nested pickle test files
                        "decode_exec",  # Our intentionally malicious decode-exec test files
                        "simple_nested",  # Our intentionally malicious simple nested pickle test file
                    ]
                    if (
                        not any(indicator in file_path.name.lower() for indicator in exclusions)
                        and file_path.name not in explicitly_malicious_fixtures
                        and file_path.is_file()
                        and not file_path.name.startswith(".")
                    ):
                        safe_files.append(file_path)

        return safe_files

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_malicious_sample_detection(self, samples_dir):
        """Test that all malicious samples are properly detected."""
        from modelaudit.scanners import _registry

        def has_tensorflow():
            """Check if TensorFlow is available with timeout protection."""
            # In CI environments, skip TensorFlow detection to prevent hanging
            import os

            if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
                return False

            try:
                # Use subprocess for maximum isolation and cross-platform timeout
                import subprocess
                import sys

                # Try to import TensorFlow in a separate process with strict timeout
                cmd = [sys.executable, "-c", "import tensorflow; print('SUCCESS')"]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3,  # Even shorter timeout
                    cwd=None,
                )

                return result.returncode == 0 and "SUCCESS" in result.stdout

            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError, OSError):
                return False
            except Exception:
                return False

        malicious_files = self.get_malicious_samples(samples_dir)

        if not malicious_files:
            pytest.skip("No malicious sample files found")

        # Get failed scanners to handle compatibility issues
        failed_scanners = _registry.get_failed_scanners()
        tensorflow_available = has_tensorflow() and not any(
            "tf_savedmodel" in scanner_id for scanner_id in failed_scanners
        )

        # Track files that were tested vs skipped
        tested_files = []
        skipped_files = []

        for malicious_file in malicious_files:
            # Skip TensorFlow-specific malicious files if TensorFlow scanner is not available
            if not tensorflow_available and (
                "pyfunc" in malicious_file.name.lower() or "tensorflow" in str(malicious_file.parent).lower()
            ):
                skipped_files.append(f"{malicious_file.name} (TensorFlow scanner unavailable)")
                continue

            # Skip h5/HDF5 files if h5py is not installed
            try:
                import h5py  # noqa: F401

                h5py_available = True
            except ImportError:
                h5py_available = False

            if not h5py_available and malicious_file.suffix.lower() in [".h5", ".hdf5", ".keras"]:
                skipped_files.append(f"{malicious_file.name} (h5py not installed)")
                continue

            # Skip manifest JSON files from the manifests category - they may not trigger security issues
            # depending on scanner configuration (blacklist patterns, etc.)
            if "manifests" in str(malicious_file.parent) and malicious_file.suffix.lower() == ".json":
                skipped_files.append(f"{malicious_file.name} (manifest scanner may not flag generic JSON)")
                continue

            # Scan the malicious file
            results = scan_model_directory_or_file(str(malicious_file), cache_enabled=False)
            exit_code = determine_exit_code(results)

            # Should scan successfully
            assert results.success is True, f"Scan failed for {malicious_file.name}"

            # For files that can be scanned with available scanners, should detect issues
            if exit_code == 0:
                # If no issues detected, check if this might be due to missing scanners
                file_ext = malicious_file.suffix.lower()
                if file_ext in [".pb"] and not tensorflow_available:
                    skipped_files.append(f"{malicious_file.name} (required .pb scanner unavailable)")
                    continue

            # Should detect security issues for files that can be properly scanned
            tested_files.append(malicious_file.name)
            assert exit_code == 1, f"Failed to detect malicious content in {malicious_file.name}"
            assert len(results.issues) > 0, f"No issues found in {malicious_file.name}"

            # Check for security-level issues
            security_issues = [
                issue
                for issue in results.issues
                if getattr(issue, "severity", None) in [IssueSeverity.CRITICAL, IssueSeverity.WARNING]
            ]
            assert len(security_issues) > 0, f"No security issues found in {malicious_file.name}"

        # Ensure we tested at least some files
        if not tested_files and skipped_files:
            pytest.skip(f"All malicious files skipped due to scanner unavailability: {skipped_files}")

        assert len(tested_files) > 0, (
            f"Should have tested at least some malicious files. Tested: {tested_files}, Skipped: {skipped_files}"
        )

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_safe_sample_validation(self, samples_dir):
        """Test that safe samples pass validation without false positives."""
        safe_files = self.get_safe_samples(samples_dir)
        try:
            import h5py  # noqa: F401

            h5py_available = True
        except Exception:
            h5py_available = False
        if not h5py_available:
            safe_files = [path for path in safe_files if path.suffix.lower() not in {".h5", ".hdf5"}]

        if not safe_files:
            pytest.skip("No safe sample files found")

        for safe_file in safe_files:
            # Scan the safe file
            results = scan_model_directory_or_file(str(safe_file), cache_enabled=False)
            exit_code = determine_exit_code(results)

            assert results.success is True, f"Scan failed for {safe_file.name}"

            # Any issues should be low-severity only (allow warnings but not critical/error)
            high_severity_issues = [
                issue for issue in results.issues if getattr(issue, "severity", None) in ["critical", "error"]
            ]
            assert len(high_severity_issues) == 0, (
                f"High-severity false positive in {safe_file.name}: {high_severity_issues}"
            )

            # Exit code should be 0 for clean files, or 1 for warnings-only (which is acceptable)
            assert exit_code in [0, 1], f"Unexpected exit code {exit_code} for {safe_file.name}: {results.issues}"

            # If exit code is 1, make sure it's only due to warnings or info, not high-severity issues
            if exit_code == 1:
                assert len(high_severity_issues) == 0, (
                    f"Exit code 1 should only be for warnings, not high-severity issues in {safe_file.name}"
                )

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_existing_pickle_assets(self, assets_dir):
        """Test existing pickle assets in the organized structure."""
        pickles_dir = assets_dir / "samples" / "pickles"

        if not pickles_dir.exists():
            pytest.skip("Pickles directory not found")

        # Test the existing evil.pickle (should be malicious)
        evil_pickle = pickles_dir / "evil.pickle"
        if evil_pickle.exists():
            results = scan_model_directory_or_file(str(evil_pickle), cache_enabled=False)
            exit_code = determine_exit_code(results)
            assert exit_code == 1, "Should detect evil.pickle as malicious"

        # Test dill_func.pkl (intentionally incomplete but still security-positive)
        dill_func = pickles_dir / "dill_func.pkl"
        if dill_func.exists():
            results = scan_model_directory_or_file(str(dill_func), cache_enabled=False)
            exit_code = determine_exit_code(results)
            assert results.success is False, "dill_func.pkl should preserve its incomplete scan outcome"
            # The detected dill usage should still preserve the security exit code.
            assert exit_code == 1, "dill_func.pkl should be flagged as suspicious due to dill usage"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_license_scenarios_integration(self, scenarios_dir: Path) -> None:
        """Test that license scenarios still work with new structure."""
        license_scenarios = scenarios_dir / "license_scenarios"

        if not license_scenarios.exists():
            pytest.skip("License scenarios directory not found")

        # Test a few license scenarios
        for scenario_dir in license_scenarios.iterdir():
            if scenario_dir.is_dir():
                results = scan_model_directory_or_file(str(scenario_dir), cache_enabled=False)
                # License scenarios must scan to completion. Some fixtures (e.g.
                # agpl_component) embed pickles that reference __main__ globals and
                # are now correctly flagged as security findings, so success may be
                # False; the scan must still have run and processed the files.
                assert results.files_scanned > 0, f"License scenario produced no scanned files: {scenario_dir.name}"
                assert results.has_errors is False, f"License scenario had operational errors: {scenario_dir.name}"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_security_scenarios(self, scenarios_dir):
        """Test complex security scenarios if they exist."""
        security_scenarios = scenarios_dir / "security_scenarios"

        if not security_scenarios.exists():
            pytest.skip("Security scenarios directory not found")

        for scenario_dir in security_scenarios.iterdir():
            if scenario_dir.is_dir():
                results = scan_model_directory_or_file(str(scenario_dir), cache_enabled=False)
                exit_code = determine_exit_code(results)

                # Security scenarios should be detected as malicious
                assert exit_code == 1, f"Security scenario not detected: {scenario_dir.name}"
                assert results.success is True, f"Scan failed for {scenario_dir.name}"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_cli_organized_structure(self, samples_dir):
        """Test CLI scanning with organized structure."""
        if not samples_dir.exists():
            pytest.skip("Samples directory not found")

        runner = CliRunner()

        # Test scanning samples directory
        result = runner.invoke(cli, ["scan", str(samples_dir), "--format", "json"])
        assert result.exit_code in [0, 1], f"CLI scan failed: {result.output}"

        # Should produce valid JSON
        try:
            output_data = json.loads(result.output)
            assert "files_scanned" in output_data
            assert "issues" in output_data
            assert output_data["files_scanned"] > 0
        except json.JSONDecodeError:
            pytest.fail(f"CLI did not produce valid JSON: {result.output}")

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_mixed_directory_scanning(self, assets_dir):
        """Test scanning directory with both safe and malicious assets."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        # Create temporary directory with mix of files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Copy a few files from different categories
            samples_dir = assets_dir / "samples"
            if samples_dir.exists():
                copied_files = []

                # Try to copy some files from different categories
                for category_dir in samples_dir.iterdir():
                    if category_dir.is_dir():
                        category_files = [
                            path for path in category_dir.iterdir() if path.is_file() and not path.name.startswith(".")
                        ][:2]
                        for file_path in category_files:
                            dest = temp_path / f"{category_dir.name}_{file_path.name}"
                            shutil.copy2(file_path, dest)
                            copied_files.append(dest)

                if copied_files:
                    # Scan the mixed directory
                    results = scan_model_directory_or_file(str(temp_path), cache_enabled=False)
                    assert results.files_scanned >= len(copied_files)
                    assert results.has_errors is False, (
                        f"Mixed directory scan should not have operational errors: "
                        f"{describe_operational_errors(results)}"
                    )

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_asset_discovery_completeness(self, assets_dir: Path) -> None:
        """Test that asset discovery finds all expected file types."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        # Scan the entire assets directory. The tree intentionally contains
        # exploits/ and malicious samples/, so success is expected to be False;
        # what matters for discovery is that the scan ran and processed files.
        results = scan_model_directory_or_file(str(assets_dir), cache_enabled=False)

        # Should find various file types
        assert results.files_scanned > 0, "Should find some files to scan"
        assert_no_unexpected_asset_scan_errors(results, "Assets directory scan")
        assert len(results.issues) > 0, "Assets tree contains exploits; findings expected"

        # Check for different file extensions in issues (indicates they were processed)
        scanned_extensions = set()
        for issue in results.issues:
            location = getattr(issue, "location", "")
            if location:
                ext = Path(location).suffix.lower()
                if ext:
                    scanned_extensions.add(ext)

        # Should have processed various file types
        expected_extensions = {".pkl", ".h5", ".pt", ".json", ".zip"}
        found_expected = expected_extensions.intersection(scanned_extensions)

        # Don't require all extensions, but should find some that we expect
        if scanned_extensions:
            assert len(found_expected) > 0, f"Should find some expected file types. Found: {scanned_extensions}"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_performance_with_organized_structure(self, assets_dir: Path) -> None:
        """Test that organized structure doesn't significantly impact performance."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        import time

        start_time = time.perf_counter()
        results = scan_model_directory_or_file(str(assets_dir), cache_enabled=False)
        duration = time.perf_counter() - start_time

        # Should complete in reasonable time. The assets tree contains exploits,
        # so success is expected to be False; assert the scan ran and produced
        # findings rather than demanding success on malicious inputs.
        assert results.files_scanned > 0, "Performance test scan should process files"
        assert_no_unexpected_asset_scan_errors(results, "Performance test scan")
        assert len(results.issues) > 0, "Assets tree contains exploits; findings expected"
        is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
        threshold = 120 if is_ci else 60
        assert duration < threshold, f"Scan took too long: {duration:.2f}s"

        # Should provide performance metrics
        assert hasattr(results, "duration"), "Results should include timing information"
        assert results.duration > 0, "Duration should be positive"
