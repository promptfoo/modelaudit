"""Scanner for Llamafile executable model artifacts."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import ClassVar
from typing import Any, ClassVar

from .base import BaseScanner, CheckStatus, IssueSeverity, ScanResult

LLAMAFILE_MARKER = b"llamafile"
GGUF_MARKER = b"GGUF"

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
LLAMAFILE_RUNTIME_SAFE_PATTERNS = (
    "llamafile",
    "llama server listening",
    "llama.cpp",
    "cosmopolitan",
    "APE is running on WIN32 inside WSL",
    "binfmt_misc",
    "%rSYS",
    "json-schema.org",
    "%'18T connect",
    "%'18T socket",
    "llama_new_context_with_model",
)


class LlamafileScanner(BaseScanner):
    """Scanner for Llamafile binaries that package runtime + embedded model data."""

    name = "llamafile"
    description = "Scans Llamafile executables and embedded GGUF payloads"
    supported_extensions: ClassVar[list[str]] = [".llamafile", ".exe", ""]

    def __init__(self, config: dict | None = None):
    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.preview_bytes = int(self.config.get("llamafile_preview_bytes", 2 * 1024 * 1024))
        self.max_payload_scan_bytes = int(self.config.get("llamafile_payload_scan_bytes", 512 * 1024 * 1024))
        self.max_payload_carve_bytes = int(self.config.get("llamafile_payload_carve_bytes", 256 * 1024 * 1024))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        path_obj = Path(path)
        if not path_obj.is_file():
            return False

        suffix = path_obj.suffix.lower()
        if suffix not in cls.supported_extensions:
            return False

        executable_format = cls._detect_executable_format(path_obj)
        if executable_format is None:
            return False

        try:
            head = cls._read_prefix(path_obj, 2 * 1024 * 1024)
            tail = cls._read_suffix(path_obj, 2 * 1024 * 1024)
        except OSError:
            return False

        marker_blob = (head + tail).lower()
        return LLAMAFILE_MARKER in marker_blob

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

        runtime_preview_bytes = 0
        try:
            head = self._read_prefix(path_obj, self.preview_bytes)
            tail = self._read_suffix(path_obj, self.preview_bytes)
            runtime_preview_bytes = len(head) + len(tail)
        except OSError as exc:
            result.add_check(
                name="Llamafile Runtime Preview Read",
                passed=False,
                message=f"Failed reading runtime preview bytes: {exc!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(exc), "exception_type": type(exc).__name__},
            )
            result.finish(success=False)
            return result

        result.bytes_scanned = runtime_preview_bytes
        self._scan_runtime_strings(path, head + b"\n" + tail, result)

        payload_bytes_scanned = self._scan_embedded_payload(path_obj, result)
        result.bytes_scanned += payload_bytes_scanned

        result.finish(success=not result.has_errors)
        return result

    @staticmethod
    def _is_known_runtime_string(text: str) -> bool:
        """Return True if the string matches a known-safe llamafile runtime pattern."""
        lowered = text.lower()
        return any(pattern.lower() in lowered for pattern in LLAMAFILE_RUNTIME_SAFE_PATTERNS)

    def _scan_runtime_strings(self, path: str, blob: bytes, result: ScanResult) -> None:
        command_hits: set[str] = set()
        network_hits: set[str] = set()

        for match in PRINTABLE_TEXT_RE.finditer(blob):
            text = match.group().decode("utf-8", errors="ignore").strip()
            if self._is_known_runtime_string(text):
                continue
            lowered = text.lower()
            for token in COMMAND_TOKENS:
                if token in lowered:
                    command_hits.add(text[:200])
            for token in NETWORK_TOKENS:
                if token in lowered:
                    network_hits.add(text[:200])

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

    def _scan_embedded_payload(self, path: Path, result: ScanResult) -> int:
        gguf_offset = self._find_marker_offset(path, GGUF_MARKER, self.max_payload_scan_bytes)
        if gguf_offset is None:
            result.add_check(
                name="Llamafile Embedded Payload Detection",
                passed=False,
                message="No embedded GGUF payload marker found within bounded scan window",
                severity=IssueSeverity.INFO,
                location=str(path),
                details={"max_scan_bytes": self.max_payload_scan_bytes},
            )
            return 0

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
            return 0

        carved_path = self._carve_payload(path, gguf_offset, carve_size)
        if carved_path is None:
            result.add_check(
                name="Llamafile Embedded Payload Carve",
                passed=False,
                message="Failed to carve embedded GGUF payload",
                severity=IssueSeverity.CRITICAL,
                location=f"{path} (llamafile:{gguf_offset})",
            )
            return 0

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
                return carve_size

            embedded_result = GgufScanner(config=self.config).scan(str(carved_path))
            self._append_embedded_findings(result, embedded_result, gguf_offset)
            return carve_size
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

    def _carve_payload(self, path: Path, offset: int, size: int) -> Path | None:
        try:
            with tempfile.NamedTemporaryFile(prefix="llamafile-payload-", suffix=".gguf", delete=False) as handle:
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
    def _find_marker_offset(path: Path, marker: bytes, max_scan_bytes: int) -> int | None:
        marker_len = len(marker)
        search_limit = min(path.stat().st_size, max_scan_bytes)
        overlap = marker_len - 1
        scanned = 0
        carry = b""

        with path.open("rb") as handle:
            while scanned < search_limit:
                to_read = min(1024 * 1024, search_limit - scanned)
                chunk = handle.read(to_read)
                if not chunk:
                    break

                haystack = carry + chunk
                relative_index = haystack.find(marker)
                if relative_index != -1:
                    return scanned - len(carry) + relative_index

                carry = haystack[-overlap:] if overlap > 0 else b""
                scanned += len(chunk)

        return None

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
