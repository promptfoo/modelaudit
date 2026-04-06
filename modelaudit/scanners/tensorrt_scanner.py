"""Scanner for TensorRT engine files (.engine, .plan, .trt)."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from typing import ClassVar, Literal

from .base import BaseScanner, IssueSeverity, ScanResult

SUSPICIOUS_PATTERN_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("../", re.compile(r"(?<![A-Za-z0-9_.-])(?:\.\./|\.\.\\)", re.IGNORECASE)),
    ("/tmp/", re.compile(r"(?<![A-Za-z0-9_.-])(?:/tmp/|(?:[A-Za-z]:)?\\tmp\\)", re.IGNORECASE)),
    (
        ".so",
        re.compile(
            r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_+.-]+)?\.so(?:\.[0-9]+(?:\.[0-9]+)*)?(?![A-Za-z0-9_.-])",
            re.IGNORECASE,
        ),
    ),
    (
        ".dll",
        re.compile(r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_+.-]+)?\.dll(?![A-Za-z0-9_.-])", re.IGNORECASE),
    ),
    (
        "LoadLibrary",
        re.compile(r"(?<![A-Za-z0-9_])LoadLibrary(?:Ex)?[AW]?(?![A-Za-z0-9_])", re.IGNORECASE),
    ),
    (
        "TensorRT plugin entry point",
        re.compile(r"(?<![A-Za-z0-9_])(?:setLoggerFinder|getCreators|getPluginCreators)(?![A-Za-z0-9_])"),
    ),
    ("python", re.compile(r"(?<![A-Za-z0-9_])python(?:[0-9.]+)?(?:\.exe)?(?![A-Za-z0-9_])", re.IGNORECASE)),
    ("import", re.compile(r"(?<![A-Za-z0-9_])import(?![A-Za-z0-9_])", re.IGNORECASE)),
    (
        "exec",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:execvpe|execvp|execve|execlpe|execlp|execle|execl|execv|exec)(?![A-Za-z0-9_])",
            re.IGNORECASE,
        ),
    ),
    ("eval", re.compile(r"(?<![A-Za-z0-9_])eval(?![A-Za-z0-9_])", re.IGNORECASE)),
)
_ASCII_STRING_PATTERN = re.compile(rb"[\t\n\r\x20-\x7e]{3,}")
_UTF16LE_STRING_PATTERN = re.compile(rb"(?:(?:[\t\n\r\x20-\x7e]\x00){3,})")
_UTF16BE_STRING_PATTERN = re.compile(rb"(?:(?:\x00[\t\n\r\x20-\x7e]){3,})")
_PE_POINTER_OFFSET = 0x3C
_PE_MIN_HEADER_OFFSET = 0x40
_PE_MAX_HEADER_OFFSET = 1024 * 1024
_PE_SIGNATURE = b"PE\x00\x00"
_ELF_SIGNATURE = b"\x7fELF"
_ELF_TYPE_SHARED_OBJECT = 3
_ELF_SUPPORTED_MACHINES = {3, 40, 62, 183}


def _iter_engine_strings(data: bytes) -> Iterator[str]:
    """Yield printable ASCII and UTF-16 strings extracted from engine bytes."""
    for match in _ASCII_STRING_PATTERN.finditer(data):
        yield match.group(0).decode("utf-8", "ignore")

    for match in _UTF16LE_STRING_PATTERN.finditer(data):
        yield match.group(0).decode("utf-16le", "ignore")

    for match in _UTF16BE_STRING_PATTERN.finditer(data):
        yield match.group(0).decode("utf-16be", "ignore")


def _find_embedded_pe_header(data: bytes) -> int | None:
    """Return the offset of a validated embedded Windows PE header, if present."""
    start = 0
    while True:
        mz_offset = data.find(b"MZ", start)
        if mz_offset == -1:
            return None

        pe_pointer_offset = mz_offset + _PE_POINTER_OFFSET
        if pe_pointer_offset + 4 <= len(data):
            pe_offset = int.from_bytes(data[pe_pointer_offset : pe_pointer_offset + 4], "little")
            pe_signature_offset = mz_offset + pe_offset
            if (
                _PE_MIN_HEADER_OFFSET <= pe_offset <= _PE_MAX_HEADER_OFFSET
                and pe_signature_offset + len(_PE_SIGNATURE) <= len(data)
                and data[pe_signature_offset : pe_signature_offset + len(_PE_SIGNATURE)] == _PE_SIGNATURE
            ):
                return mz_offset

        start = mz_offset + 1


def _find_embedded_elf_shared_object(data: bytes) -> int | None:
    """Return the offset of a validated embedded ELF shared object, if present."""
    start = 0
    while True:
        elf_offset = data.find(_ELF_SIGNATURE, start)
        if elf_offset == -1:
            return None

        if elf_offset + 24 <= len(data):
            elf_class = data[elf_offset + 4]
            byte_order = data[elf_offset + 5]
            elf_version = data[elf_offset + 6]
            if elf_class in {1, 2} and byte_order in {1, 2} and elf_version == 1:
                endian: Literal["little", "big"] = "little" if byte_order == 1 else "big"
                object_type = int.from_bytes(data[elf_offset + 16 : elf_offset + 18], endian)
                machine = int.from_bytes(data[elf_offset + 18 : elf_offset + 20], endian)
                object_version = int.from_bytes(data[elf_offset + 20 : elf_offset + 24], endian)
                if (
                    object_type == _ELF_TYPE_SHARED_OBJECT
                    and machine in _ELF_SUPPORTED_MACHINES
                    and object_version == 1
                ):
                    return elf_offset

        start = elf_offset + 1


class TensorRTScanner(BaseScanner):
    """Basic scanner for NVIDIA TensorRT engine files."""

    name = "tensorrt"
    description = "Scans TensorRT engine files for suspicious strings"
    supported_extensions: ClassVar[list[str]] = [".engine", ".plan", ".trt"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        return os.path.isfile(path) and os.path.splitext(path)[1].lower() in cls.supported_extensions

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
            data = self._read_file_safely(path)
            result.bytes_scanned = len(data)
        except Exception as e:  # pragma: no cover - unexpected read errors
            result.add_check(
                name="TensorRT Engine Read",
                passed=False,
                message=f"Error reading TensorRT engine: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        matched_patterns: set[str] = set()
        for engine_string in _iter_engine_strings(data):
            for pattern_name, pattern_regex in SUSPICIOUS_PATTERN_RULES:
                if pattern_name in matched_patterns:
                    continue
                if not pattern_regex.search(engine_string):
                    continue

                matched_patterns.add(pattern_name)
                result.add_check(
                    name="Suspicious Pattern Detection",
                    passed=False,
                    message=f"Suspicious pattern '{pattern_name}' found",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"pattern": pattern_name},
                    rule_code="S902",
                )

        pe_header_offset = _find_embedded_pe_header(data)
        if pe_header_offset is not None:
            result.add_check(
                name="Embedded PE Detection",
                passed=False,
                message="Embedded Windows PE/DLL header found",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"pattern": "embedded PE", "offset": pe_header_offset},
                rule_code="S902",
            )

        elf_header_offset = _find_embedded_elf_shared_object(data)
        if elf_header_offset is not None:
            result.add_check(
                name="Embedded ELF Detection",
                passed=False,
                message="Embedded Linux ELF shared-object header found",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"pattern": "embedded ELF", "offset": elf_header_offset},
                rule_code="S902",
            )

        result.finish(success=not result.has_errors)
        return result
