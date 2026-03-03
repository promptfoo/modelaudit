"""Scanner for legacy Torch7 serialized model artifacts."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

TORCH7_SIGNATURE_READ_BYTES = 4096
MAX_SCAN_BYTES = 12 * 1024 * 1024
MAX_EXTRACTED_STRINGS = 5000
MIN_TORCH7_SIZE = 8

PRINTABLE_TEXT_PATTERN = re.compile(rb"[ -~]{6,512}")

EXEC_PRIMITIVE_CALL_PATTERN = re.compile(
    r"(?i)\b(?:os\.execute|io\.popen|loadstring|dofile|loadfile|setfenv|getfenv)\s*\("
)
NETWORK_OR_SHELL_PATTERN = re.compile(
    r"(?i)\b("
    r"https?://|ftp://|socket\.|luasocket|curl|wget|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|"
    r"/bin/sh|/bin/bash|bash\s+-c|sh\s+-c|netcat|nc\s+"
    r")"
)
REQUIRE_PATTERN = re.compile(r"(?i)\brequire\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
DYNAMIC_LOAD_PATTERN = re.compile(r"(?i)\b(?:package\.loadlib|ffi\.load|loadlib)\b")

SAFE_REQUIRE_MODULES = frozenset(
    {
        "torch",
        "nn",
        "nngraph",
        "image",
        "paths",
        "math",
        "string",
        "table",
        "cunn",
        "cutorch",
        "optim",
    }
)


def is_torch7_signature(prefix: bytes) -> bool:
    """Return True if the prefix resembles a Torch7 serialization header/marker."""
    lowered = prefix.lower()
    if prefix.startswith(b"T7\x00\x00"):
        return True
    has_torch_marker = b"torch" in lowered or b"luat" in lowered
    has_structure_marker = b"nn." in lowered or b"tensor" in lowered or b"thnn" in lowered
    return has_torch_marker and has_structure_marker


class Torch7Scanner(BaseScanner):
    """Static scanner for Torch7 `.t7` / `.th` / `.net` artifacts."""

    name = "torch7"
    description = "Scans Torch7 serialized model files for Lua execution and dynamic loading indicators"
    supported_extensions: ClassVar[list[str]] = [".t7", ".th", ".net"]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config=config)
        self.max_scan_bytes = int(self.config.get("torch7_max_scan_bytes", MAX_SCAN_BYTES))
        self.max_extracted_strings = int(self.config.get("torch7_max_extracted_strings", MAX_EXTRACTED_STRINGS))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        if Path(path).suffix.lower() not in cls.supported_extensions:
            return False

        try:
            if os.path.getsize(path) < MIN_TORCH7_SIZE:
                return False
            with open(path, "rb") as file_obj:
                prefix = file_obj.read(TORCH7_SIGNATURE_READ_BYTES)
        except OSError:
            return False

        return is_torch7_signature(prefix)

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
                name="Torch7 File Read",
                passed=False,
                message=f"Failed to read Torch7 file: {exc!s}",
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
                name="Torch7 Bounded Read",
                passed=False,
                message=f"Torch7 scan truncated after {self.max_scan_bytes} bytes (bounded read limit)",
                severity=IssueSeverity.INFO,
                location=path,
                details={"max_scan_bytes": self.max_scan_bytes},
            )
        else:
            result.add_check(
                name="Torch7 Bounded Read",
                passed=True,
                message="Torch7 file read within bounded scan budget",
                location=path,
                details={"bytes_scanned": len(payload)},
            )

        if not is_torch7_signature(payload[:TORCH7_SIGNATURE_READ_BYTES]):
            result.add_check(
                name="Torch7 Header Signature",
                passed=False,
                message="File does not match expected Torch7 serialization markers",
                severity=IssueSeverity.INFO,
                location=path,
            )
            result.finish(success=False)
            return result

        result.add_check(
            name="Torch7 Header Signature",
            passed=True,
            message="Torch7 serialization markers detected",
            location=path,
        )

        if len(payload) < MIN_TORCH7_SIZE:
            result.add_check(
                name="Torch7 Structural Integrity",
                passed=False,
                message="Torch7 file appears truncated or structurally incomplete",
                severity=IssueSeverity.INFO,
                location=path,
                details={"bytes_scanned": len(payload), "minimum_expected_bytes": MIN_TORCH7_SIZE},
            )
            result.finish(success=False)
            return result

        extracted_strings = self._extract_strings(payload)
        result.metadata["extracted_string_count"] = len(extracted_strings)

        self._analyze_execution_primitives(path, extracted_strings, result)
        self._analyze_dynamic_loads(path, extracted_strings, result)
        self._analyze_network_shell_strings(path, extracted_strings, result)

        result.finish(success=not result.has_errors)
        return result

    def _extract_strings(self, payload: bytes) -> list[str]:
        strings: list[str] = []
        for match in PRINTABLE_TEXT_PATTERN.finditer(payload):
            text = match.group(0).decode("utf-8", errors="ignore").strip()
            if not text:
                continue
            strings.append(text)
            if len(strings) >= self.max_extracted_strings:
                break
        return strings

    @staticmethod
    def _snippet(text: str, max_chars: int = 180) -> str:
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 3] + "..."

    def _analyze_execution_primitives(self, path: str, strings: list[str], result: ScanResult) -> None:
        critical_hits: list[str] = []
        warning_hits: list[str] = []

        for index, text in enumerate(strings):
            if not EXEC_PRIMITIVE_CALL_PATTERN.search(text):
                continue

            window_start = max(0, index - 1)
            window_end = min(len(strings), index + 2)
            context_window = " ".join(strings[window_start:window_end])
            has_network_shell_context = bool(NETWORK_OR_SHELL_PATTERN.search(context_window))

            snippet = self._snippet(text)
            if has_network_shell_context:
                critical_hits.append(snippet)
            else:
                warning_hits.append(snippet)

        if critical_hits:
            result.add_check(
                name="Torch7 Lua Execution Primitive Analysis",
                passed=False,
                message="Execution primitives found with network/shell context",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"examples": critical_hits[:5], "signal": "exec_with_network_shell_context"},
            )
        elif warning_hits:
            result.add_check(
                name="Torch7 Lua Execution Primitive Analysis",
                passed=False,
                message="Execution primitives found without correlated network/shell context",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"examples": warning_hits[:5], "signal": "exec_only"},
            )
        else:
            result.add_check(
                name="Torch7 Lua Execution Primitive Analysis",
                passed=True,
                message="No Lua execution primitive calls detected",
                location=path,
            )

    def _analyze_dynamic_loads(self, path: str, strings: list[str], result: ScanResult) -> None:
        dynamic_hits: list[str] = []

        for text in strings:
            load_hit = bool(DYNAMIC_LOAD_PATTERN.search(text))
            requires = REQUIRE_PATTERN.findall(text)
            suspicious_requires = [
                module
                for module in requires
                if module.lower() not in SAFE_REQUIRE_MODULES and not module.lower().startswith("torch.")
            ]

            if load_hit or suspicious_requires:
                dynamic_hits.append(self._snippet(text))

        if dynamic_hits:
            result.add_check(
                name="Torch7 Dynamic Module Load Analysis",
                passed=False,
                message="Dynamic module loading references detected in Torch7 text regions",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"examples": dynamic_hits[:5]},
            )
        else:
            result.add_check(
                name="Torch7 Dynamic Module Load Analysis",
                passed=True,
                message="No suspicious dynamic module loading references detected",
                location=path,
            )

    def _analyze_network_shell_strings(self, path: str, strings: list[str], result: ScanResult) -> None:
        findings: list[str] = []
        for text in strings:
            if NETWORK_OR_SHELL_PATTERN.search(text):
                findings.append(self._snippet(text))

        if findings:
            result.add_check(
                name="Torch7 Network and Shell String Analysis",
                passed=False,
                message="Network or shell-related strings detected in Torch7 serialized text",
                severity=IssueSeverity.INFO,
                location=path,
                details={"examples": findings[:8]},
            )
        else:
            result.add_check(
                name="Torch7 Network and Shell String Analysis",
                passed=True,
                message="No network or shell-related strings detected",
                location=path,
            )
