"""Scanner for Rockchip RKNN model artifacts (.rknn)."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

RKNN_MAGIC = b"RKNN"
MIN_RKNN_SIZE = 16
MAX_SIGNATURE_BYTES = 64
MAX_SCAN_BYTES = 12 * 1024 * 1024
MAX_EXTRACTED_STRINGS = 4000
PRINTABLE_TEXT_PATTERN = re.compile(rb"[ -~]{6,512}")

ABSOLUTE_PATH_PATTERN = re.compile(r"^(?:[a-zA-Z]:[\\/]|/|~)")
TRAVERSAL_PATH_PATTERN = re.compile(r"(^|[\\/])\.\.([\\/]|$)")
URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp|s3|gs|file)://[^\s\"'<>]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")

COMMAND_PATTERN = re.compile(
    r"(?i)\b("
    r"os\.system|subprocess\.(?:popen|run|call|check_output|check_call)|"
    r"powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|/bin/sh|/bin/bash|bash\s+-c|sh\s+-c|curl\s+|wget\s+|netcat|nc\s+"
    r")"
)
NETWORK_CONTEXT_PATTERN = re.compile(r"(?i)\b(socket|http|https|ftp|tcp|udp|dns|webhook|callback|exfil)\b")
EXEC_CONTEXT_PATTERN = re.compile(r"(?i)\b(eval\(|exec\(|__import__|loadlibrary|dlopen\(|ctypes\.)")
BASE64_BLOB_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{96,}={0,2}\b")
DECODE_CONTEXT_PATTERN = re.compile(r"(?i)\b(base64|b64decode|decode\(|frombase64string|atob\()")

KNOWN_SAFE_KEYS = frozenset(
    {
        "model_name",
        "model_version",
        "platform",
        "target",
        "device",
        "author",
        "description",
        "framework",
        "input",
        "output",
        "quantization",
        "runtime",
        "dtype",
    }
)

# Paths starting with known system/user directory prefixes are more likely
# to be genuine filesystem references rather than ONNX-style tensor names.
REAL_FS_PREFIX_PATTERN = re.compile(
    r"^(?:"
    r"/(?:bin|dev|etc|home|lib|mnt|opt|proc|root|run|sbin|srv|sys|tmp|usr|var)/"
    r"|/(?:Users|Windows|Program Files|AppData)/"
    r"|[a-zA-Z]:[\\/]"
    r"|~/"
    r")"
)


class RknnScanner(BaseScanner):
    """Static scanner for RKNN models."""

    name = "rknn"
    description = "Scans RKNN .rknn model files for suspicious metadata references and command/network indicators"
    supported_extensions: ClassVar[list[str]] = [".rknn"]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config=config)
        self.max_scan_bytes = int(self.config.get("rknn_max_scan_bytes", MAX_SCAN_BYTES))
        self.max_extracted_strings = int(self.config.get("rknn_max_extracted_strings", MAX_EXTRACTED_STRINGS))

    @staticmethod
    def _has_rknn_signature(prefix: bytes) -> bool:
        return prefix.startswith(RKNN_MAGIC)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        if Path(path).suffix.lower() not in cls.supported_extensions:
            return False

        try:
            file_size = os.path.getsize(path)
            if file_size < MIN_RKNN_SIZE:
                return False
            with open(path, "rb") as file_obj:
                prefix = file_obj.read(MAX_SIGNATURE_BYTES)
        except OSError:
            return False

        return cls._has_rknn_signature(prefix)

    def scan(self, path: str) -> ScanResult:
        path_check = self._check_path(path)
        if path_check:
            return path_check

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path
        self.add_file_integrity_check(path, result)
        result.metadata["file_size"] = self.get_file_size(path)
        result.metadata["max_scan_bytes"] = self.max_scan_bytes

        try:
            with open(path, "rb") as file_obj:
                data = file_obj.read(self.max_scan_bytes + 1)
        except OSError as exc:
            result.add_check(
                name="RKNN File Read",
                passed=False,
                message=f"Failed to read RKNN file: {exc!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(exc), "exception_type": type(exc).__name__},
            )
            result.finish(success=False)
            return result

        truncated = len(data) > self.max_scan_bytes
        payload = data[: self.max_scan_bytes]
        result.bytes_scanned = len(payload)
        result.metadata["scan_truncated"] = truncated

        if truncated:
            result.add_check(
                name="RKNN Bounded Read",
                passed=False,
                message=f"RKNN scan truncated after {self.max_scan_bytes} bytes (bounded read limit)",
                severity=IssueSeverity.INFO,
                location=path,
                details={"max_scan_bytes": self.max_scan_bytes},
            )
        else:
            result.add_check(
                name="RKNN Bounded Read",
                passed=True,
                message="RKNN file read within bounded scan budget",
                location=path,
                details={"bytes_scanned": len(payload)},
            )

        if not self._has_rknn_signature(payload[:MAX_SIGNATURE_BYTES]):
            result.add_check(
                name="RKNN Header Signature",
                passed=False,
                message="File does not start with RKNN signature bytes",
                severity=IssueSeverity.INFO,
                location=path,
                details={"expected_magic": RKNN_MAGIC.decode("ascii"), "actual_magic_hex": payload[:4].hex()},
            )
            result.finish(success=False)
            return result

        result.add_check(
            name="RKNN Header Signature",
            passed=True,
            message="RKNN signature bytes validated",
            location=path,
        )

        if len(payload) < MIN_RKNN_SIZE:
            result.add_check(
                name="RKNN Structural Integrity",
                passed=False,
                message="RKNN file is truncated or structurally incomplete",
                severity=IssueSeverity.INFO,
                location=path,
                details={"bytes_scanned": len(payload), "minimum_expected_bytes": MIN_RKNN_SIZE},
            )
            result.finish(success=False)
            return result

        structural_magic_count = self._count_structural_magic(payload)
        if structural_magic_count > 2:
            result.add_check(
                name="RKNN Structural Integrity",
                passed=False,
                message="Unexpectedly many RKNN structural magic headers found; possible tampering",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"structural_magic_count": structural_magic_count},
            )
        else:
            result.add_check(
                name="RKNN Structural Integrity",
                passed=True,
                message="RKNN container header layout appears consistent",
                location=path,
            )

        extracted_strings = self._extract_strings(payload)
        result.metadata["extracted_string_count"] = len(extracted_strings)

        self._check_path_references(path, extracted_strings, result)
        self._check_command_and_network_indicators(path, extracted_strings, result)
        self._check_obfuscated_payload_hints(path, extracted_strings, result)

        result.finish(success=not result.has_errors)
        return result

    @staticmethod
    def _count_structural_magic(payload: bytes) -> int:
        """Count RKNN magic bytes that appear as structural headers.

        RKNN files legitimately contain two structural magic markers (file
        header + FlatBuffer header) plus occurrences inside JSON metadata
        strings like ``RKNN_OP_NNBG``.  Only count magic bytes that are
        NOT part of a longer ASCII identifier (i.e. not preceded or followed
        by an alphanumeric/underscore character).
        """
        count = 0
        idx = 0
        while True:
            pos = payload.find(RKNN_MAGIC, idx)
            if pos == -1:
                break
            before_ok = pos == 0 or payload[pos - 1 : pos] not in (
                b"_",
                *[bytes([c]) for c in range(ord("A"), ord("Z") + 1)],
                *[bytes([c]) for c in range(ord("a"), ord("z") + 1)],
                *[bytes([c]) for c in range(ord("0"), ord("9") + 1)],
            )
            after_pos = pos + len(RKNN_MAGIC)
            after_ok = after_pos >= len(payload) or payload[after_pos : after_pos + 1] not in (
                b"_",
                *[bytes([c]) for c in range(ord("A"), ord("Z") + 1)],
                *[bytes([c]) for c in range(ord("a"), ord("z") + 1)],
                *[bytes([c]) for c in range(ord("0"), ord("9") + 1)],
            )
            if before_ok and after_ok:
                count += 1
            idx = pos + 4
        return count

    def _extract_strings(self, payload: bytes) -> list[str]:
        strings: list[str] = []
        for match in PRINTABLE_TEXT_PATTERN.finditer(payload):
            candidate = match.group(0).decode("utf-8", errors="ignore").strip()
            if not candidate:
                continue
            strings.append(candidate)
            if len(strings) >= self.max_extracted_strings:
                break
        return strings

    @staticmethod
    def _is_public_ip(candidate: str) -> bool:
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)

    @staticmethod
    def _is_safe_metadata_string(text: str) -> bool:
        if "=" not in text:
            return False
        key = text.split("=", 1)[0].strip().lower()
        return key in KNOWN_SAFE_KEYS

    @staticmethod
    def _snippet(text: str, max_chars: int = 180) -> str:
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 3] + "..."

    def _check_path_references(self, path: str, extracted_strings: list[str], result: ScanResult) -> None:
        risky_references: list[dict[str, str]] = []
        for text in extracted_strings:
            if self._is_safe_metadata_string(text):
                continue

            if TRAVERSAL_PATH_PATTERN.search(text):
                risky_references.append({"reference": self._snippet(text), "type": "filesystem_path"})
                continue
            if REAL_FS_PREFIX_PATTERN.search(text):
                # Short strings matching ~/ are likely binary noise, not real
                # home-directory references — require a minimum length.
                if text.startswith("~/") and len(text) < 8:
                    continue
                risky_references.append({"reference": self._snippet(text), "type": "filesystem_path"})
                continue
            if URL_PATTERN.search(text):
                risky_references.append({"reference": self._snippet(text), "type": "url_reference"})

        if risky_references:
            result.add_check(
                name="RKNN Path Reference Validation",
                passed=False,
                message="Suspicious file/URL references detected in RKNN metadata text",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"references": risky_references[:10]},
            )
        else:
            result.add_check(
                name="RKNN Path Reference Validation",
                passed=True,
                message="No suspicious path or URL references detected in extracted metadata text",
                location=path,
            )

    def _check_command_and_network_indicators(
        self,
        path: str,
        extracted_strings: list[str],
        result: ScanResult,
    ) -> None:
        command_hits: list[str] = []
        command_network_hits: list[str] = []

        for text in extracted_strings:
            if self._is_safe_metadata_string(text):
                continue

            command_match = COMMAND_PATTERN.search(text)
            if not command_match:
                continue

            snippet = self._snippet(text)
            has_network_context = bool(NETWORK_CONTEXT_PATTERN.search(text) or URL_PATTERN.search(text))
            has_public_ip = any(self._is_public_ip(candidate) for candidate in IP_PATTERN.findall(text))

            if has_network_context or has_public_ip:
                command_network_hits.append(snippet)
            else:
                command_hits.append(snippet)

        if command_network_hits:
            result.add_check(
                name="RKNN Command and Network Indicator Correlation",
                passed=False,
                message="Correlated command execution and network indicators detected in RKNN metadata text",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"examples": command_network_hits[:5], "signal_type": "command_and_network"},
            )
        elif command_hits:
            result.add_check(
                name="RKNN Command Indicator Detection",
                passed=False,
                message="Command execution indicators detected in RKNN metadata text",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"examples": command_hits[:5], "signal_type": "command_only"},
            )
        else:
            result.add_check(
                name="RKNN Command Indicator Detection",
                passed=True,
                message="No command execution indicators detected in extracted metadata text",
                location=path,
            )

    def _check_obfuscated_payload_hints(self, path: str, extracted_strings: list[str], result: ScanResult) -> None:
        obfuscated_hits: list[str] = []

        for text in extracted_strings:
            if not BASE64_BLOB_PATTERN.search(text):
                continue
            if not DECODE_CONTEXT_PATTERN.search(text):
                continue
            if not (EXEC_CONTEXT_PATTERN.search(text) or COMMAND_PATTERN.search(text)):
                continue
            obfuscated_hits.append(self._snippet(text))

        if obfuscated_hits:
            result.add_check(
                name="RKNN Obfuscated Payload Indicators",
                passed=False,
                message="Possible encoded payload markers found with decode/exec context",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"examples": obfuscated_hits[:5]},
            )
        else:
            result.add_check(
                name="RKNN Obfuscated Payload Indicators",
                passed=True,
                message="No encoded payload markers found in executable context",
                location=path,
            )
