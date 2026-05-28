"""Scanner for Llamafile executable model artifacts."""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from pathlib import Path
from typing import Any, ClassVar

from ..scanner_selection import add_scanner_selection_skip_check, policy_from_config
from ..utils.file.detection import (
    LLAMAFILE_MARKER,
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    find_structural_torch7_offset,
    is_llamafile_executable,
)
from ._evidence_redaction import redact_evidence_string
from .archive_dispatch import merge_executable_zip_container_findings
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult

__all__ = ["LLAMAFILE_MARKER", "LLAMAFILE_ROUTE_SCAN_BYTES", "LLAMAFILE_ROUTE_TAIL_SCAN_BYTES", "LlamafileScanner"]

GGUF_MARKER = b"GGUF"
LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON = "llamafile_payload_scan_limited"
LLAMAFILE_RUNTIME_PREVIEW_READ_REASON = "llamafile_runtime_preview_read_failed"
LLAMAFILE_TORCH7_CARVE_FAILURE_REASON = "llamafile_torch7_payload_carve_failed"
LLAMAFILE_TORCH7_ANALYSIS_INCOMPLETE_REASON = "llamafile_torch7_analysis_incomplete"
TORCH7_SIGNATURE_WINDOW_BYTES = 4096

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}

PRINTABLE_TEXT_RE = re.compile(rb"[ -~]{8,}")
SAFE_LOCALHOST_URL_RE = re.compile(
    r"https?://(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|::1)(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)
SAFE_JSON_SCHEMA_URL_RE = re.compile(
    r"https?://(?:www\.)?json-schema\.org(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)
ENDPOINT_TOKEN_RE = re.compile(
    r"(?:localhost|\[::1\]|::1|0\.0\.0\.0|\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?",
    re.IGNORECASE,
)

COMMAND_TOKENS = (
    "bash -c",
    "sh -c",
    "powershell",
    "cmd.exe",
    "python -c",
    "os.system",
    "subprocess.",
    "curl ",
    "wget ",
)

NETWORK_TOKENS = (
    "http://",
    "https://",
    "tcp://",
    "udp://",
    "socket",
    "connect(",
)

# Patterns found in the legitimate llamafile/cosmopolitan runtime that are
# NOT indicators of compromise.  These appear in error messages, debug format
# strings, and server status output.
LLAMAFILE_RUNTIME_SAFE_EXACT_PATTERNS: tuple[str, ...] = (
    "llamafile",
    "llama.cpp",
    "cosmopolitan",
    "binfmt_misc",
    "%rSYS",
    "llama_new_context_with_model",
)

LLAMAFILE_RUNTIME_SAFE_FRAGMENT_PATTERNS: tuple[str, ...] = (
    "llama server listening",
    "APE is running on WIN32 inside WSL",
    "json-schema.org",
    "%'18T connect",
    "%'18T socket",
)
LLAMAFILE_RUNTIME_SAFE_EXACT_LOWER: set[str] = {pattern.lower() for pattern in LLAMAFILE_RUNTIME_SAFE_EXACT_PATTERNS}
LLAMAFILE_RUNTIME_SAFE_FRAGMENT_LOWER: set[str] = {
    pattern.lower() for pattern in LLAMAFILE_RUNTIME_SAFE_FRAGMENT_PATTERNS
}


def _is_local_endpoint_token(token: str) -> bool:
    """Return True when an extracted endpoint token resolves to a local-only address."""
    host = token.strip().lower()
    if host == "localhost":
        return True

    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif host.count(":") == 1 and "." in host and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]

    if host in {"::1", "0.0.0.0"}:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


class LlamafileScanner(BaseScanner):
    """Scanner for Llamafile binaries that package runtime + embedded model data."""

    name = "llamafile"
    description = "Scans Llamafile executables and embedded GGUF payloads"
    supported_extensions: ClassVar[list[str]] = [".llamafile", ".exe", ""]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.preview_bytes = int(self.config.get("llamafile_preview_bytes", 2 * 1024 * 1024))
        self.max_payload_scan_bytes = int(self.config.get("llamafile_payload_scan_bytes", 512 * 1024 * 1024))
        self.max_payload_carve_bytes = int(self.config.get("llamafile_payload_carve_bytes", 256 * 1024 * 1024))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        return is_llamafile_executable(path)

    @classmethod
    def _detect_executable_format(cls, path: Path) -> str | None:
        try:
            with path.open("rb") as handle:
                header = handle.read(4)
        except OSError:
            return None

        if header.startswith(ELF_MAGIC):
            return "elf"
        if header.startswith(PE_MAGIC):
            return "pe"
        if header in MACHO_MAGICS:
            return "mach-o"
        return None

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path
        self.add_file_integrity_check(path, result)

        path_obj = Path(path)
        executable_format = self._detect_executable_format(path_obj)
        if executable_format is None:
            result.add_check(
                name="Llamafile Executable Header Check",
                passed=False,
                message="File is not a supported executable container (ELF/Mach-O/PE)",
                severity=IssueSeverity.INFO,
                location=path,
            )
            result.finish(success=False)
            return result

        result.metadata["executable_format"] = executable_format
        result.metadata["is_executable_permission"] = os.access(path, os.X_OK)

        result.add_check(
            name="Llamafile Executable Detection",
            passed=False,
            message="Llamafile executable artifact detected",
            severity=IssueSeverity.INFO,
            location=path,
            details={"executable_format": executable_format},
        )

        runtime_blobs: list[bytes] = []
        marker_probe = b""
        runtime_preview_bytes = 0
        try:
            head = self._read_prefix(path_obj, self.preview_bytes)
            runtime_blobs.append(head)
            runtime_preview_bytes += len(head)
            tail = self._read_suffix(path_obj, self.preview_bytes)
            runtime_blobs.append(tail)
            runtime_preview_bytes += len(tail)
            marker_offset, marker_probe = self._find_casefolded_marker_offset(
                path_obj,
                LLAMAFILE_MARKER,
                LLAMAFILE_ROUTE_SCAN_BYTES,
                self.preview_bytes,
            )
            if marker_offset is not None and not self._offset_is_in_preview_windows(
                marker_offset,
                path_obj.stat().st_size,
                self.preview_bytes,
            ):
                middle = self._read_window_around_offset(path_obj, marker_offset, self.preview_bytes)
                runtime_blobs.append(middle)
                runtime_preview_bytes += len(middle)
        except OSError as exc:
            if marker_probe:
                runtime_blobs.append(marker_probe)
                runtime_preview_bytes += len(marker_probe)
            result.bytes_scanned = runtime_preview_bytes
            if runtime_blobs:
                self._scan_runtime_strings(path, b"\n".join(runtime_blobs), result)
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_PREVIEW_READ_REASON)
            result.add_check(
                name="Llamafile Runtime Preview Read",
                passed=False,
                message=f"Failed reading runtime preview bytes: {exc!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_RUNTIME_PREVIEW_READ_REASON,
                },
            )
            try:
                _, torch7_offset = self._find_embedded_payload_offsets(
                    path_obj,
                    self.max_payload_scan_bytes,
                    stop_at_gguf=False,
                )
            except OSError:
                torch7_offset = None
            self._merge_polyglot_findings(path_obj, result, torch7_offset)
            result.finish(success=False)
            return result

        result.bytes_scanned = runtime_preview_bytes
        self._scan_runtime_strings(path, b"\n".join(runtime_blobs), result)

        gguf_offset, torch7_offset = self._find_embedded_payload_offsets(path_obj, self.max_payload_scan_bytes)
        payload_bytes_scanned, _valid_gguf_payload = self._scan_embedded_payload(path_obj, result, gguf_offset)
        if gguf_offset is not None and torch7_offset is None:
            torch7_offset = self._find_embedded_torch7_offset(
                path_obj,
                self.max_payload_scan_bytes,
                start_offset=gguf_offset + len(GGUF_MARKER),
            )
        result.bytes_scanned += payload_bytes_scanned
        self._merge_polyglot_findings(path_obj, result, torch7_offset)

        result.finish(
            success=not result.has_errors and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        )
        return result

    @staticmethod
    def _is_known_runtime_string(text: str) -> bool:
        """Return True if the string matches a known-safe llamafile runtime pattern."""
        lowered = text.lower()
        if any(token in lowered for token in COMMAND_TOKENS):
            return False
        if lowered in LLAMAFILE_RUNTIME_SAFE_EXACT_LOWER:
            return True

        normalized = SAFE_LOCALHOST_URL_RE.sub("", lowered)
        normalized = SAFE_JSON_SCHEMA_URL_RE.sub("json-schema.org", normalized)

        for fragment in LLAMAFILE_RUNTIME_SAFE_FRAGMENT_LOWER:
            if fragment not in normalized:
                continue
            candidate = normalized.replace(fragment, "", 1)
            if not any(token in candidate for token in NETWORK_TOKENS):
                if fragment in {"%'18t connect", "%'18t socket"}:
                    endpoints = [match.group(0) for match in ENDPOINT_TOKEN_RE.finditer(candidate)]
                    if endpoints and not all(_is_local_endpoint_token(endpoint) for endpoint in endpoints):
                        continue
                return True
        return False

    def _scan_runtime_strings(self, path: str, blob: bytes, result: ScanResult) -> None:
        command_hits: set[str] = set()
        network_hits: set[str] = set()

        for match in PRINTABLE_TEXT_RE.finditer(blob):
            text = match.group().decode("utf-8", errors="ignore").strip()
            if self._is_known_runtime_string(text):
                continue
            lowered = text.lower()
            has_command_token = any(token in lowered for token in COMMAND_TOKENS)
            has_network_token = any(token in lowered for token in NETWORK_TOKENS)
            if not has_command_token and not has_network_token:
                continue

            redacted_text = redact_evidence_string(text, max_chars=200)
            if has_command_token:
                command_hits.add(redacted_text)
            if has_network_token:
                network_hits.add(redacted_text)

        if not command_hits and not network_hits:
            return

        if command_hits and network_hits:
            severity = IssueSeverity.CRITICAL
            message = "Executable runtime contains command execution and network indicators"
        elif command_hits:
            severity = IssueSeverity.WARNING
            message = "Executable runtime contains command execution indicators"
        else:
            severity = IssueSeverity.INFO
            message = "Executable runtime contains network indicators"

        result.add_check(
            name="Llamafile Runtime String Analysis",
            passed=False,
            message=message,
            severity=severity,
            location=path,
            details={
                "command_evidence": sorted(command_hits)[:5],
                "network_evidence": sorted(network_hits)[:5],
            },
        )

    def _scan_embedded_payload(self, path: Path, result: ScanResult, gguf_offset: int | None) -> tuple[int, bool]:
        if gguf_offset is None:
            file_size = self.get_file_size(str(path))
            details = {"max_scan_bytes": self.max_payload_scan_bytes}
            if file_size > self.max_payload_scan_bytes:
                self._mark_inconclusive(result, LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON)
                details["analysis_incomplete"] = True
                details["file_size"] = file_size
            result.add_check(
                name="Llamafile Embedded Payload Detection",
                passed=False,
                message=(
                    "No embedded GGUF payload marker found before bounded scan window ended"
                    if file_size > self.max_payload_scan_bytes
                    else "No embedded GGUF payload marker found within bounded scan window"
                ),
                severity=IssueSeverity.INFO,
                location=str(path),
                details=details,
            )
            return 0, False

        file_size = self.get_file_size(str(path))
        payload_available = max(0, file_size - gguf_offset)
        carve_size = min(payload_available, self.max_payload_carve_bytes)

        result.metadata["embedded_payload_offset"] = gguf_offset
        result.metadata["embedded_payload_size"] = carve_size

        result.add_check(
            name="Llamafile Embedded Payload Detection",
            passed=False,
            message="Embedded GGUF payload marker detected",
            severity=IssueSeverity.INFO,
            location=f"{path} (llamafile:{gguf_offset})",
            details={"offset": gguf_offset, "carve_size": carve_size},
        )

        # Large binaries should not place model payload immediately in the prologue.
        if gguf_offset < 4096 and file_size > 1024 * 1024:
            result.add_check(
                name="Llamafile Section Layout Check",
                passed=False,
                message="Embedded GGUF payload appears unusually early in binary layout",
                severity=IssueSeverity.WARNING,
                location=f"{path} (llamafile:{gguf_offset})",
                details={"offset": gguf_offset},
            )

        if carve_size < 24:
            result.add_check(
                name="Llamafile Embedded Payload Integrity",
                passed=False,
                message="Embedded GGUF payload pointer appears truncated",
                severity=IssueSeverity.WARNING,
                location=f"{path} (llamafile:{gguf_offset})",
                details={"offset": gguf_offset, "available_bytes": payload_available},
            )
            return 0, False

        carved_path = self._carve_payload(path, gguf_offset, carve_size)
        if carved_path is None:
            result.add_check(
                name="Llamafile Embedded Payload Carve",
                passed=False,
                message="Failed to carve embedded GGUF payload",
                severity=IssueSeverity.CRITICAL,
                location=f"{path} (llamafile:{gguf_offset})",
            )
            return 0, False

        try:
            from modelaudit.scanners.gguf_scanner import GgufScanner

            if not GgufScanner.can_handle(str(carved_path)):
                result.add_check(
                    name="Llamafile Embedded Payload Integrity",
                    passed=False,
                    message="Carved embedded payload did not validate as GGUF",
                    severity=IssueSeverity.WARNING,
                    location=f"{path} (llamafile:{gguf_offset})",
                )
                return carve_size, False

            embedded_result = GgufScanner(config=self.config).scan(str(carved_path))
            self._append_embedded_findings(result, embedded_result, gguf_offset)
            return carve_size, embedded_result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        finally:
            carved_path.unlink(missing_ok=True)

    def _append_embedded_findings(self, result: ScanResult, embedded: ScanResult, offset: int) -> None:
        for check in embedded.checks:
            prefixed_location = f"llamafile:{offset}"
            if check.location:
                prefixed_location = f"{prefixed_location} -> {check.location}"

            details = dict(check.details)
            details["embedded_offset"] = offset
            details["embedded_scanner"] = embedded.scanner_name

            result.add_check(
                name=f"Llamafile Embedded {check.name}",
                passed=check.status == CheckStatus.PASSED,
                message=check.message,
                severity=check.severity,
                location=prefixed_location,
                details=details,
                why=check.why,
            )

    @staticmethod
    def _mark_inconclusive(result: ScanResult, reason: str) -> None:
        """Mark Llamafile analysis coverage as explicitly incomplete."""
        result.metadata["analysis_incomplete"] = True
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME

        reasons = result.metadata.get("scan_outcome_reasons")
        if not isinstance(reasons, list):
            reasons = []
            result.metadata["scan_outcome_reasons"] = reasons
        if reason not in reasons:
            reasons.append(reason)

    def _merge_polyglot_findings(self, path: Path, result: ScanResult, torch7_offset: int | None) -> None:
        """Preserve trusted secondary-format coverage for executable polyglots."""
        if torch7_offset is not None:
            self._merge_torch7_findings(path, result, torch7_offset)

        merge_executable_zip_container_findings(
            str(path),
            result,
            self.config,
            context="embedded executable ZIP polyglot",
        )

    def _merge_torch7_findings(self, path: Path, result: ScanResult, offset: int) -> None:
        scanner_selection = policy_from_config(self.config)
        if not scanner_selection.allows("torch7"):
            add_scanner_selection_skip_check(
                result,
                str(path),
                "torch7",
                scanner_selection,
                context="embedded Llamafile/Torch7 polyglot analysis",
            )
            return

        from .torch7_scanner import Torch7Scanner

        scanner = Torch7Scanner(config=self.config)
        payload_available = max(0, self.get_file_size(str(path)) - offset)
        carve_size = min(payload_available, scanner.max_scan_bytes + 1)
        carved_path = self._carve_payload(path, offset, carve_size, suffix=".t7")
        if carved_path is None:
            result.metadata["embedded_torch7_offset"] = offset
            result.metadata["embedded_torch7_size"] = carve_size
            self._mark_inconclusive(result, LLAMAFILE_TORCH7_CARVE_FAILURE_REASON)
            result.add_check(
                name="Llamafile Embedded Torch7 Payload Carve",
                passed=False,
                message="Failed to carve embedded Torch7 payload",
                severity=IssueSeverity.CRITICAL,
                location=f"{path} (llamafile:{offset})",
            )
            return

        try:
            if not scanner.can_handle(str(carved_path)):
                return

            result.metadata["embedded_torch7_offset"] = offset
            result.metadata["embedded_torch7_size"] = carve_size
            embedded_result = scanner.scan(str(carved_path))
            self._append_torch7_findings(result, embedded_result, offset)
        finally:
            carved_path.unlink(missing_ok=True)

    def _append_torch7_findings(self, result: ScanResult, embedded: ScanResult, offset: int) -> None:
        embedded_location = f"{self.current_file_path} (llamafile:{offset})"
        for check in embedded.checks:
            check.location = embedded_location
            check.details = {
                **check.details,
                "embedded_offset": offset,
                "embedded_scanner": embedded.scanner_name,
            }
        for issue in embedded.issues:
            issue.location = embedded_location
            issue.details = {
                **issue.details,
                "embedded_offset": offset,
                "embedded_scanner": embedded.scanner_name,
            }

        result.checks.extend(embedded.checks)
        result.issues.extend(embedded.issues)
        result.bytes_scanned += embedded.bytes_scanned
        result.metadata["embedded_torch7_metadata"] = dict(embedded.metadata)
        if embedded.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME or (
            not embedded.success and not embedded.has_errors
        ):
            self._mark_inconclusive(result, LLAMAFILE_TORCH7_ANALYSIS_INCOMPLETE_REASON)

    def _carve_payload(self, path: Path, offset: int, size: int, suffix: str = ".gguf") -> Path | None:
        try:
            with tempfile.NamedTemporaryFile(prefix="llamafile-payload-", suffix=suffix, delete=False) as handle:
                carved_path = Path(handle.name)
                with path.open("rb") as source:
                    source.seek(offset)
                    remaining = size
                    while remaining > 0:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        handle.write(chunk)
                        remaining -= len(chunk)
            return carved_path
        except OSError:
            return None

    @staticmethod
    def _find_embedded_payload_offsets(
        path: Path,
        max_scan_bytes: int,
        *,
        stop_at_gguf: bool = True,
    ) -> tuple[int | None, int | None]:
        """Find GGUF and Torch7 payload signatures in one bounded pass."""
        search_limit = min(path.stat().st_size, max_scan_bytes)
        overlap = max(len(GGUF_MARKER) - 1, TORCH7_SIGNATURE_WINDOW_BYTES - 1)
        scanned = 0
        carry = b""
        gguf_offset: int | None = None
        torch7_offset: int | None = None

        with path.open("rb") as handle:
            while scanned < search_limit:
                to_read = min(1024 * 1024, search_limit - scanned)
                chunk = handle.read(to_read)
                if not chunk:
                    break

                haystack = carry + chunk
                window_offset = scanned - len(carry)
                if gguf_offset is None:
                    gguf_relative_index = haystack.find(GGUF_MARKER)
                    if gguf_relative_index != -1:
                        gguf_offset = window_offset + gguf_relative_index
                else:
                    gguf_relative_index = -1

                if torch7_offset is None:
                    torch7_window = (
                        haystack if not stop_at_gguf or gguf_relative_index == -1 else haystack[:gguf_relative_index]
                    )
                    torch7_relative_index = find_structural_torch7_offset(torch7_window)
                    if torch7_relative_index is not None:
                        torch7_offset = window_offset + torch7_relative_index

                if stop_at_gguf and gguf_relative_index != -1:
                    return gguf_offset, torch7_offset

                carry = haystack[-overlap:] if overlap > 0 else b""
                scanned += len(chunk)

        return gguf_offset, torch7_offset

    @staticmethod
    def _find_embedded_torch7_offset(path: Path, max_scan_bytes: int, *, start_offset: int = 0) -> int | None:
        """Find a Torch7 payload signature after a known payload boundary."""
        file_size = path.stat().st_size
        search_limit = min(file_size, max_scan_bytes)
        if start_offset >= search_limit:
            return None

        overlap = TORCH7_SIGNATURE_WINDOW_BYTES - 1
        scanned = start_offset
        carry = b""

        with path.open("rb") as handle:
            handle.seek(start_offset)
            while scanned < search_limit:
                to_read = min(1024 * 1024, search_limit - scanned)
                chunk = handle.read(to_read)
                if not chunk:
                    break

                haystack = carry + chunk
                window_offset = scanned - len(carry)
                torch7_relative_index = find_structural_torch7_offset(haystack)
                if torch7_relative_index is not None:
                    return window_offset + torch7_relative_index

                carry = haystack[-overlap:] if overlap > 0 else b""
                scanned += len(chunk)

        return None

    @staticmethod
    def _find_casefolded_marker_offset(
        path: Path,
        marker: bytes,
        max_scan_bytes: int,
        evidence_bytes: int,
    ) -> tuple[int | None, bytes]:
        marker_len = len(marker)
        search_limit = min(path.stat().st_size, max_scan_bytes)
        overlap = marker_len - 1
        scanned = 0
        carry = b""
        evidence_carry = b""
        normalized_marker = marker.lower()

        with path.open("rb") as handle:
            while scanned < search_limit:
                to_read = min(1024 * 1024, search_limit - scanned)
                chunk = handle.read(to_read)
                if not chunk:
                    break

                haystack = carry + chunk.lower()
                evidence_window = (evidence_carry + chunk)[-evidence_bytes:]
                relative_index = haystack.find(normalized_marker)
                if relative_index != -1:
                    return scanned - len(carry) + relative_index, evidence_window

                carry = haystack[-overlap:] if overlap > 0 else b""
                evidence_carry = evidence_window
                scanned += len(chunk)

        return None, b""

    @staticmethod
    def _read_prefix(path: Path, num_bytes: int) -> bytes:
        with path.open("rb") as handle:
            return handle.read(num_bytes)

    @staticmethod
    def _read_suffix(path: Path, num_bytes: int) -> bytes:
        file_size = path.stat().st_size
        if file_size <= num_bytes:
            return LlamafileScanner._read_prefix(path, num_bytes)
        with path.open("rb") as handle:
            handle.seek(file_size - num_bytes)
            return handle.read(num_bytes)

    @staticmethod
    def _offset_is_in_preview_windows(offset: int, file_size: int, preview_bytes: int) -> bool:
        """Return whether an offset is already covered by the head or tail preview."""
        return offset < preview_bytes or offset >= max(0, file_size - preview_bytes)

    @staticmethod
    def _read_window_around_offset(path: Path, offset: int, num_bytes: int) -> bytes:
        """Read a bounded preview window centered around a routed marker offset."""
        file_size = path.stat().st_size
        window_start = max(0, offset - (num_bytes // 2))
        window_end = min(file_size, window_start + num_bytes)
        if window_end - window_start < num_bytes:
            window_start = max(0, window_end - num_bytes)
        with path.open("rb") as handle:
            handle.seek(window_start)
            return handle.read(window_end - window_start)
