"""Scanner for R serialized model artifacts."""

from __future__ import annotations

import bz2
import gzip
import ipaddress
import lzma
import os
import re
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit

from ..core_results import mark_operational_scan_error
from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ._evidence_redaction import redact_evidence_string
from .base import BaseScanner, CheckStatus, IssueSeverity, ScanResult

_DECODE_INCONCLUSIVE_REASON = "r_serialized_decode_incomplete"
_READ_INCONCLUSIVE_REASON = "r_serialized_read_failed"
_STRING_EXTRACTION_INCONCLUSIVE_REASON = "r_serialized_string_extraction_incomplete"
_R_CREDENTIAL_KEY_PATTERN = (
    r"(?:[a-z0-9]+[_-])*"
    r"(?:access[_-]?key|access[_-]?token|api[_-]?key|apikey|auth[_-]?token|client[_-]?secret|password|"
    r"passwd|private[_-]?key|refresh[_-]?token|secret|secret[_-]?key|token)"
)
_R_BACKTICK_CREDENTIAL_KEY_PATTERN = (
    r"(?:[a-z0-9]+[\s_-]+)*"
    r"(?:access[\s_-]*key|access[\s_-]*token|api[\s_-]*key|apikey|auth[\s_-]*token|client[\s_-]*secret|"
    r"password|passwd|private[\s_-]*key|refresh[\s_-]*token|secret|secret[\s_-]*key|token)"
)
_R_CREDENTIAL_IDENTIFIER = rf"(?:`{_R_BACKTICK_CREDENTIAL_KEY_PATTERN}`|\b{_R_CREDENTIAL_KEY_PATTERN}\b)"
_R_QUOTED_CREDENTIAL_VALUE = r"""(?:"(?:\\.|[^"\\]){6,}"|'(?:\\.|[^'\\]){6,}')"""
_R_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rf"""(?ix)(?:
        {_R_CREDENTIAL_IDENTIFIER}\s*(?::|=|<{{1,2}}-)\s*{_R_QUOTED_CREDENTIAL_VALUE}
        |
        {_R_QUOTED_CREDENTIAL_VALUE}\s*->{{1,2}}\s*{_R_CREDENTIAL_IDENTIFIER}
    )"""
)


def _redact_url_for_display(url: str) -> str:
    """Return a URL safe for scan output while preserving routing context."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return "[invalid-url]"

    if not parsed.scheme or not parsed.hostname:
        return "[invalid-url]"

    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    netloc = f"{hostname}:{port}" if port is not None else hostname
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _redact_sample_for_display(text: str) -> str:
    return redact_evidence_string(text, max_chars=200)


@dataclass(frozen=True)
class _ExtractedString:
    text: str
    offset: int


class RSerializedScanner(BaseScanner):
    """Static scanner for R serialized files."""

    name = "r_serialized"
    description = "Scans R serialized model files for unsafe deserialization indicators"
    supported_extensions: ClassVar[list[str]] = [".rds", ".rda", ".rdata"]

    _SERIALIZATION_MARKERS: ClassVar[tuple[bytes, ...]] = (b"X\n", b"A\n", b"B\n")
    _WORKSPACE_HEADERS: ClassVar[tuple[bytes, ...]] = (b"RDX2\n", b"RDX3\n", b"RDA2\n", b"RDA3\n")

    _GZIP_MAGIC: ClassVar[bytes] = b"\x1f\x8b"
    _BZIP2_MAGIC: ClassVar[bytes] = b"BZh"
    _XZ_MAGIC: ClassVar[bytes] = b"\xfd7zXZ\x00"

    _CAN_HANDLE_DECOMPRESSED_LIMIT: ClassVar[int] = 128 * 1024
    _SIGNATURE_PROBE_BYTES: ClassVar[int] = 7
    _XZ_DECOMPRESS_MEMLIMIT: ClassVar[int] = 128 * 1024 * 1024
    _XZ_READ_CHUNK_SIZE: ClassVar[int] = 64 * 1024
    _PRINTABLE_RE: ClassVar[re.Pattern[bytes]] = re.compile(rb"[ -~]{3,512}")
    _EXECUTABLE_SYMBOL_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w.])(?:base::|utils::)?"
        r"(?:system2?|eval|parse|source|do\.call|dyn\.load|socketconnection|pipe|url|download\.file)"
        r"(?![\w.])",
        re.IGNORECASE,
    )
    _EXECUTABLE_CALL_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w.])(?:base::|utils::)?"
        r"(?:system2?|eval|parse|source|do\.call|dyn\.load|socketConnection|pipe|url|download\.file)\s*\(",
        re.IGNORECASE,
    )
    _COMMAND_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b("
        r"curl|wget|powershell|invoke-webrequest|cmd(?:\.exe)?|/bin/sh|/bin/bash|"
        r"python\s+-c|rscript\s+-e|rm\s+-rf|chmod\s+\+x|nc|netcat"
        r")\b"
    )
    _URL_RE: ClassVar[re.Pattern[str]] = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    _IP_RE: ClassVar[re.Pattern[str]] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _CODE_CONTEXT_MARKERS: ClassVar[tuple[str, ...]] = (
        "expression",
        "language",
        "call",
        "function",
        "quote",
        "substitute",
        "closure",
        "promise",
    )
    _CREDENTIAL_PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "github_token": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        "openai_key_like": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        "generic_secret_assignment": _R_CREDENTIAL_ASSIGNMENT_RE,
    }

    def __init__(self, config: dict[str, object] | None = None):
        super().__init__(config=config)
        self.max_scan_bytes = int(self.config.get("r_max_scan_bytes", 16 * 1024 * 1024))
        self.max_decompressed_bytes = int(self.config.get("r_max_decompressed_bytes", 64 * 1024 * 1024))
        self.max_decompression_ratio = float(self.config.get("r_max_decompression_ratio", 250.0))
        self.max_extracted_strings = int(self.config.get("r_max_extracted_strings", 12_000))
        self.read_chunk_size = int(self.config.get("r_read_chunk_size", 64 * 1024))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        known_extension = os.path.splitext(path)[1].lower() in cls.supported_extensions

        try:
            with open(path, "rb") as file_obj:
                header = file_obj.read(16)
        except OSError:
            # Preserve declared ownership so scan() can report unavailable
            # coverage; readable suffix-only near matches are still rejected.
            return True

        compression = cls._detect_compression(header)
        if compression is None:
            if known_extension:
                return cls._looks_like_r_serialization(header)
            return cls._looks_like_renamed_r_serialization(header)

        if not known_extension:
            return False

        try:
            prefix = cls._read_decompressed_prefix(path, compression, cls._CAN_HANDLE_DECOMPRESSED_LIMIT)
        except (EOFError, OSError, gzip.BadGzipFile, lzma.LZMAError):
            # Corrupt compressed wrappers should still route to this scanner.
            return True

        return cls._looks_like_r_serialization(prefix)

    @classmethod
    def _looks_like_renamed_r_serialization(cls, data: bytes) -> bool:
        return any(
            data.startswith(workspace_header + marker)
            for workspace_header in cls._WORKSPACE_HEADERS
            for marker in cls._SERIALIZATION_MARKERS
        )

    @classmethod
    def _detect_compression(cls, header: bytes) -> str | None:
        if header.startswith(cls._GZIP_MAGIC):
            return "gzip"
        if header.startswith(cls._BZIP2_MAGIC):
            return "bzip2"
        if header.startswith(cls._XZ_MAGIC):
            return "xz"
        return None

    @classmethod
    def _looks_like_r_serialization(cls, data: bytes) -> bool:
        if any(data.startswith(marker) for marker in cls._SERIALIZATION_MARKERS):
            return True

        for header in cls._WORKSPACE_HEADERS:
            if data.startswith(header):
                trailing = data[len(header) : len(header) + 2]
                if not trailing or trailing in cls._SERIALIZATION_MARKERS:
                    return True

        return False

    @classmethod
    def _read_decompressed_prefix(cls, path: str, compression: str, limit: int) -> bytes:
        read_limit = limit + 1
        if compression == "gzip":
            with gzip.open(path, "rb") as stream:
                return stream.read(read_limit)[:limit]
        if compression == "bzip2":
            with bz2.open(path, "rb") as stream:
                return stream.read(read_limit)[:limit]
        if compression == "xz":
            return cls._read_xz_signature_prefix(
                path=path,
                limit=min(limit, cls._SIGNATURE_PROBE_BYTES),
                memlimit=cls._XZ_DECOMPRESS_MEMLIMIT,
            )
        return b""

    @classmethod
    def _read_xz_signature_prefix(cls, path: str, limit: int, memlimit: int) -> bytes:
        if limit <= 0:
            return b""

        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=memlimit)
        prefix = bytearray()
        pending = b""

        with open(path, "rb") as file_obj:
            while len(prefix) < limit:
                if not pending:
                    pending = file_obj.read(cls._XZ_READ_CHUNK_SIZE)

                if not pending:
                    if not decompressor.eof:
                        raise EOFError("Incomplete XZ stream ended before EOF marker")
                    break

                piece = decompressor.decompress(pending, max_length=limit - len(prefix))
                pending = decompressor.unused_data

                while True:
                    if piece:
                        prefix.extend(piece)
                        if len(prefix) >= limit:
                            return bytes(prefix)

                    if decompressor.eof or decompressor.needs_input:
                        break

                    piece = decompressor.decompress(b"", max_length=limit - len(prefix))

                if decompressor.eof:
                    if not pending:
                        pending = file_obj.read(cls._XZ_READ_CHUNK_SIZE)
                        if not pending:
                            break
                    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=memlimit)
                    continue

                pending = b""

        return bytes(prefix)

    @classmethod
    def _read_xz_with_memlimit(
        cls,
        path: str,
        output_limit: int,
        memlimit: int,
        *,
        compressed_size: int,
        max_decompressed_bytes: int,
        max_decompression_ratio: float,
    ) -> tuple[bytes, bool, int]:
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=memlimit)
        decompressed = bytearray()
        total_decompressed = 0
        truncated = False
        pending = b""

        with open(path, "rb") as file_obj:
            while True:
                if not pending:
                    pending = file_obj.read(cls._XZ_READ_CHUNK_SIZE)

                if not pending:
                    if not truncated and not decompressor.eof:
                        raise EOFError("Incomplete XZ stream ended before EOF marker")
                    break

                piece = decompressor.decompress(pending, max_length=cls._XZ_READ_CHUNK_SIZE)
                pending = decompressor.unused_data
                while True:
                    if piece:
                        total_decompressed += len(piece)
                        if total_decompressed > max_decompressed_bytes:
                            raise ValueError(f"Decompressed stream exceeded limit ({max_decompressed_bytes} bytes)")

                        if compressed_size > 0 and total_decompressed / compressed_size > max_decompression_ratio:
                            raise ValueError(
                                f"Suspicious decompression ratio ({total_decompressed / compressed_size:.1f}x > "
                                f"{max_decompression_ratio:.1f}x)"
                            )

                        remaining = max(output_limit - len(decompressed), 0)
                        decompressed.extend(piece[:remaining])
                        if len(piece) > remaining:
                            truncated = True

                    if truncated or decompressor.eof or decompressor.needs_input:
                        break

                    piece = decompressor.decompress(b"", max_length=cls._XZ_READ_CHUNK_SIZE)

                if truncated:
                    break

                if decompressor.eof:
                    if not pending:
                        pending = file_obj.read(cls._XZ_READ_CHUNK_SIZE)
                        if not pending:
                            break
                    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=memlimit)
                    continue

                pending = b""

        return bytes(decompressed), truncated, total_decompressed

    def _read_payload_for_analysis(self, path: str, file_size: int) -> tuple[bytes, str, bool, int]:
        with open(path, "rb") as file_obj:
            header = file_obj.read(16)

        compression = self._detect_compression(header)
        if compression is None:
            with open(path, "rb") as file_obj:
                payload = file_obj.read(self.max_scan_bytes + 1)
            truncated = len(payload) > self.max_scan_bytes
            return payload[: self.max_scan_bytes], "none", truncated, min(len(payload), self.max_scan_bytes)

        if compression == "gzip":
            with gzip.open(path, "rb") as stream:
                payload, truncated, total_decompressed = self._read_decompressed_stream(stream, file_size)
        elif compression == "bzip2":
            with bz2.open(path, "rb") as stream:
                payload, truncated, total_decompressed = self._read_decompressed_stream(stream, file_size)
        else:
            payload, truncated, total_decompressed = self._read_xz_with_memlimit(
                path=path,
                output_limit=self.max_scan_bytes,
                memlimit=self.max_decompressed_bytes,
                compressed_size=file_size,
                max_decompressed_bytes=self.max_decompressed_bytes,
                max_decompression_ratio=self.max_decompression_ratio,
            )

        return payload, compression, truncated, total_decompressed

    def _read_decompressed_stream(self, stream: Any, file_size: int) -> tuple[bytes, bool, int]:
        decompressed = bytearray()
        total_decompressed = 0
        truncated = False

        while True:
            chunk = stream.read(self.read_chunk_size)
            if not chunk:
                break

            total_decompressed += len(chunk)
            if total_decompressed > self.max_decompressed_bytes:
                raise ValueError(f"Decompressed stream exceeded limit ({self.max_decompressed_bytes} bytes)")

            if file_size > 0 and total_decompressed / file_size > self.max_decompression_ratio:
                raise ValueError(
                    f"Suspicious decompression ratio ({total_decompressed / file_size:.1f}x > "
                    f"{self.max_decompression_ratio:.1f}x)"
                )

            if len(decompressed) >= self.max_scan_bytes:
                truncated = True
                break

            remaining = self.max_scan_bytes - len(decompressed)
            decompressed.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
                break

        return bytes(decompressed), truncated, total_decompressed

    def _extract_strings(self, payload: bytes) -> tuple[list[_ExtractedString], bool, int, int]:
        strings: list[_ExtractedString] = []
        truncated = False
        total_printable_bytes = 0
        longest_string = 0
        current_parts: list[str] = []
        current_offset = 0
        previous_match_end: int | None = None

        def append_current_run() -> bool:
            nonlocal total_printable_bytes, longest_string
            if not current_parts:
                return True
            text = "".join(current_parts).strip()
            if not text:
                return True
            longest_string = max(longest_string, len(text))
            if len(strings) >= self.max_extracted_strings:
                return False
            strings.append(_ExtractedString(text=text, offset=current_offset))
            total_printable_bytes += len(text)
            return True

        def append_printable_tail(start: int, end: int) -> None:
            if not current_parts or start >= end:
                return
            tail_end = start
            while tail_end < end and 0x20 <= payload[tail_end] <= 0x7E:
                tail_end += 1
            if tail_end == start:
                return
            tail = payload[start:tail_end]
            current_parts.append(tail.decode("utf-8", errors="ignore"))

        for match in self._PRINTABLE_RE.finditer(payload):
            if previous_match_end != match.start():
                if previous_match_end is not None:
                    append_printable_tail(previous_match_end, match.start())
                if not append_current_run():
                    truncated = True
                    break
                current_parts = []
                current_offset = match.start()

            current_parts.append(match.group().decode("utf-8", errors="ignore"))
            previous_match_end = match.end()
        else:
            if previous_match_end is not None:
                append_printable_tail(previous_match_end, len(payload))
            if not append_current_run():
                truncated = True

        return strings, truncated, total_printable_bytes, longest_string

    def _context_window(self, strings: list[_ExtractedString], index: int, window_size: int = 2) -> str:
        start = max(0, index - window_size)
        end = min(len(strings), index + window_size + 1)
        return " ".join(item.text for item in strings[start:end])

    def _is_primarily_documentation(self, text: str) -> bool:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return False

        documentation_lines = sum(
            1
            for line in lines
            if line.startswith(("#", "//", "*", ";"))
            or line.lower().startswith(("note:", "description:", "documentation:", "comment:"))
        )
        return documentation_lines / len(lines) > 0.5

    def _is_valid_public_ip(self, candidate: str) -> bool:
        try:
            value = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return not (value.is_private or value.is_loopback or value.is_link_local or value.is_multicast)

    def _add_symbol_and_payload_checks(self, result: ScanResult, strings: list[_ExtractedString], path: str) -> None:
        critical_symbol_hits: list[dict[str, object]] = []
        metadata_symbol_hits: list[dict[str, object]] = []
        critical_payload_hits: list[dict[str, object]] = []
        warning_payload_hits: list[dict[str, object]] = []
        url_hits: set[str] = set()
        ip_hits: set[str] = set()
        credential_hits: set[str] = set()

        for index, extracted in enumerate(strings):
            text = extracted.text
            lowered = text.lower()
            context = self._context_window(strings, index).lower()
            has_code_context = any(marker in context for marker in self._CODE_CONTEXT_MARKERS)
            has_exec_symbol = bool(self._EXECUTABLE_SYMBOL_RE.search(lowered))
            has_exec_call = bool(self._EXECUTABLE_CALL_RE.search(lowered))
            documentation_only = self._is_primarily_documentation(text)

            if has_exec_symbol:
                match = self._EXECUTABLE_SYMBOL_RE.search(lowered)
                assert match is not None
                hit = {"symbol": match.group(0), "offset": extracted.offset, "sample": _redact_sample_for_display(text)}
                if has_exec_call or has_code_context:
                    if not documentation_only or has_exec_call:
                        critical_symbol_hits.append(hit)
                else:
                    metadata_symbol_hits.append(hit)

            command_match = self._COMMAND_RE.search(text)
            if command_match:
                hit = {
                    "pattern": command_match.group(0),
                    "offset": extracted.offset,
                    "sample": _redact_sample_for_display(text),
                }
                if has_exec_call or has_code_context or has_exec_symbol:
                    critical_payload_hits.append(hit)
                elif not documentation_only:
                    warning_payload_hits.append(hit)

            for url in self._URL_RE.findall(text):
                url_hits.add(_redact_url_for_display(url))

            for ip in self._IP_RE.findall(text):
                if self._is_valid_public_ip(ip):
                    ip_hits.add(ip)

            for name, pattern in self._CREDENTIAL_PATTERNS.items():
                if pattern.search(text):
                    credential_hits.add(name)

        if critical_symbol_hits:
            result.add_check(
                name="Executable Symbol Context Analysis",
                passed=False,
                message=(
                    f"Found {len(critical_symbol_hits)} risky R symbol reference(s) in executable serialization context"
                ),
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "hit_count": len(critical_symbol_hits),
                    "examples": critical_symbol_hits[:5],
                    "detection_scope": "serialized_code_context",
                },
                why=(
                    "R serialized language objects can execute these functions when loaded/evaluated. "
                    "Treat artifacts containing executable symbol contexts as untrusted."
                ),
            )
        else:
            result.add_check(
                name="Executable Symbol Context Analysis",
                passed=True,
                message="No risky executable symbol references detected in code-like contexts",
                location=path,
            )

        if metadata_symbol_hits:
            result.add_check(
                name="Risky Symbol Metadata Mentions",
                passed=False,
                message=(f"Found {len(metadata_symbol_hits)} risky symbol mention(s) outside executable context"),
                severity=IssueSeverity.INFO,
                location=path,
                details={"hit_count": len(metadata_symbol_hits), "examples": metadata_symbol_hits[:5]},
                why=(
                    "These names may be benign metadata, but should be reviewed when artifacts come from "
                    "untrusted sources."
                ),
            )

        if critical_payload_hits:
            result.add_check(
                name="Serialized Expression Payload Detection",
                passed=False,
                message=f"Detected {len(critical_payload_hits)} command-like payload indicator(s) in code context",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"hit_count": len(critical_payload_hits), "examples": critical_payload_hits[:5]},
                why=(
                    "Command-oriented payload markers inside serialized expression contexts are strong indicators "
                    "of unsafe deserialization behavior."
                ),
            )
        elif warning_payload_hits:
            result.add_check(
                name="Serialized Expression Payload Detection",
                passed=False,
                message=f"Detected {len(warning_payload_hits)} command-like payload indicator(s)",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"hit_count": len(warning_payload_hits), "examples": warning_payload_hits[:5]},
                why=("Command-like tokens may indicate staging content. Review file provenance and loading path."),
            )
        else:
            result.add_check(
                name="Serialized Expression Payload Detection",
                passed=True,
                message="No command-like payload indicators detected",
                location=path,
            )

        if url_hits or ip_hits:
            result.add_check(
                name="Embedded Network Indicator Detection",
                passed=False,
                message=(f"Detected {len(url_hits)} URL indicator(s) and {len(ip_hits)} public IP indicator(s)"),
                severity=IssueSeverity.WARNING,
                location=path,
                details={"urls": sorted(url_hits)[:10], "public_ips": sorted(ip_hits)[:10]},
                why=(
                    "Embedded external endpoints can indicate data-exfiltration or payload-fetch behavior when "
                    "coupled with dynamic evaluation."
                ),
            )
        else:
            result.add_check(
                name="Embedded Network Indicator Detection",
                passed=True,
                message="No suspicious URL/IP indicators detected",
                location=path,
            )

        if credential_hits:
            result.add_check(
                name="Credential-like String Detection",
                passed=False,
                message=f"Detected {len(credential_hits)} credential-like pattern class(es)",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"pattern_classes": sorted(credential_hits)},
                why="Serialized artifacts should not contain long-lived secrets or access tokens.",
            )
        else:
            result.add_check(
                name="Credential-like String Detection",
                passed=True,
                message="No credential-like patterns detected",
                location=path,
            )

    def _add_payload_stuffing_check(
        self,
        result: ScanResult,
        path: str,
        payload_size: int,
        string_count: int,
        total_printable_bytes: int,
        longest_string: int,
        strings_truncated: bool,
    ) -> None:
        printable_ratio = total_printable_bytes / payload_size if payload_size > 0 else 0.0
        looks_stuffed = longest_string > 8_192 or (payload_size >= 1_000_000 and printable_ratio > 0.80)

        if looks_stuffed:
            result.add_check(
                name="Serialized Payload Stuffing Detection",
                passed=False,
                message="Serialized object contains unusually dense or oversized embedded text payloads",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "string_count": string_count,
                    "max_allowed_strings": self.max_extracted_strings,
                    "total_printable_bytes": total_printable_bytes,
                    "printable_ratio": round(printable_ratio, 4),
                    "longest_string": longest_string,
                    "truncated_string_extraction": strings_truncated,
                },
                why=(
                    "Abnormally dense textual content in serialized objects can indicate payload stuffing "
                    "for staged execution."
                ),
            )
            return

        result.add_check(
            name="Serialized Payload Stuffing Detection",
            passed=True,
            message="No payload stuffing anomalies detected",
            location=path,
            details={
                "string_count": string_count,
                "total_printable_bytes": total_printable_bytes,
                "printable_ratio": round(printable_ratio, 4),
                "longest_string": longest_string,
            },
        )

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            if any(
                check.name == "Path Readable" and check.status == CheckStatus.FAILED
                for check in path_check_result.checks
            ):
                result = self._create_result()
                self._mark_read_failure(result, path, PermissionError(f"Path is not readable: {path}"))
                result.finish(success=False)
                return result
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            payload, compression, truncated, decompressed_bytes = self._read_payload_for_analysis(path, file_size)
        except gzip.BadGzipFile as exc:
            self._mark_decode_failure(result, path, exc)
            result.finish(success=False)
            return result
        except OSError as exc:
            if exc.errno is not None:
                self._mark_read_failure(result, path, exc)
            else:
                self._mark_decode_failure(result, path, exc)
            result.finish(success=False)
            return result
        except (EOFError, ValueError, MemoryError, lzma.LZMAError) as exc:
            self._mark_decode_failure(result, path, exc)
            result.finish(success=False)
            return result

        result.add_check(
            name="R Serialized Decompression",
            passed=True,
            message="Safely decoded R serialized payload for analysis",
            location=path,
            details={
                "compression": compression,
                "compressed_bytes": file_size,
                "decompressed_bytes": decompressed_bytes,
            },
        )

        if not payload:
            result.add_check(
                name="R Serialization Signature",
                passed=False,
                message="R serialized payload is empty after decoding",
                severity=IssueSeverity.INFO,
                location=path,
            )
            result.finish(success=False)
            return result

        if not self._looks_like_r_serialization(payload):
            result.add_check(
                name="R Serialization Signature",
                passed=False,
                message="File does not contain a recognized R serialization header/signature",
                severity=IssueSeverity.INFO,
                location=path,
                details={"compression": compression},
            )
            result.finish(success=False)
            return result

        result.add_check(
            name="R Serialization Signature",
            passed=True,
            message="Recognized R serialization header/signature",
            location=path,
            details={"compression": compression},
        )

        if truncated:
            mark_inconclusive_scan_result(result, "r_serialized_byte_ceiling_incomplete")
            result.add_check(
                name="Byte Scan Ceiling",
                passed=False,
                message=f"Analysis truncated at configured byte ceiling ({self.max_scan_bytes} bytes)",
                severity=IssueSeverity.INFO,
                location=path,
                details={"max_scan_bytes": self.max_scan_bytes, "compression": compression},
                why="A scan ceiling limits resource usage. Review with higher limits if deeper inspection is needed.",
            )
        else:
            result.add_check(
                name="Byte Scan Ceiling",
                passed=True,
                message="File analyzed within configured byte ceiling",
                location=path,
                details={"max_scan_bytes": self.max_scan_bytes, "compression": compression},
            )

        extracted_strings, strings_truncated, total_printable_bytes, longest_string = self._extract_strings(payload)
        result.metadata["compression"] = compression
        result.metadata["decompressed_bytes"] = decompressed_bytes
        result.metadata["extracted_string_count"] = len(extracted_strings)
        result.bytes_scanned = len(payload)

        if strings_truncated:
            mark_inconclusive_scan_result(result, _STRING_EXTRACTION_INCONCLUSIVE_REASON)
            result.add_check(
                name="String Extraction Ceiling",
                passed=False,
                message=(
                    f"Analysis reached configured extracted-string ceiling ({self.max_extracted_strings} strings)"
                ),
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "max_extracted_strings": self.max_extracted_strings,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": _STRING_EXTRACTION_INCONCLUSIVE_REASON,
                },
                why=(
                    "An extracted-string ceiling limits resource usage. Review with higher limits if deeper "
                    "inspection is needed."
                ),
            )

        self._add_symbol_and_payload_checks(result, extracted_strings, path)
        self._add_payload_stuffing_check(
            result=result,
            path=path,
            payload_size=len(payload),
            string_count=len(extracted_strings),
            total_printable_bytes=total_printable_bytes,
            longest_string=longest_string,
            strings_truncated=strings_truncated,
        )

        result.finish(
            success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors,
        )
        return result

    @staticmethod
    def _mark_read_failure(result: ScanResult, path: str, error: OSError) -> None:
        """Record file-access coverage loss separately from malformed serialized data."""
        mark_inconclusive_scan_result(result, _READ_INCONCLUSIVE_REASON)
        mark_operational_scan_error(result, _READ_INCONCLUSIVE_REASON)
        result.add_check(
            name="R Serialized Read",
            passed=False,
            message=f"Unable to read R serialized payload for analysis: {error!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": _READ_INCONCLUSIVE_REASON,
            },
            why="The artifact could not be read, so R serialized security analysis did not complete.",
        )

    @staticmethod
    def _mark_decode_failure(result: ScanResult, path: str, error: Exception) -> None:
        """Record bounded decode or decompression coverage loss."""
        mark_inconclusive_scan_result(result, _DECODE_INCONCLUSIVE_REASON)
        result.add_check(
            name="R Serialized Decompression",
            passed=False,
            message=f"Failed to safely read R serialized payload: {error}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": _DECODE_INCONCLUSIVE_REASON,
            },
            why=(
                "Malformed or unsafe compressed streams are treated as scan failures to avoid unsafe parsing behavior."
            ),
        )
