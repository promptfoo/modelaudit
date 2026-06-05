"""Scanner for legacy Torch7 serialized model artifacts."""

from __future__ import annotations

import os
import re
from typing import Any, ClassVar

from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ..utils.file.detection import _is_torch7_signature as is_torch7_signature
from ._evidence_redaction import REDACTED_EVIDENCE_VALUE, is_sensitive_evidence_key, redact_evidence_string
from ._string_extraction import extract_bounded_printable_strings
from .base import BaseScanner, IssueSeverity, ScanResult

TORCH7_SIGNATURE_READ_BYTES = 4096
MAX_SCAN_BYTES = 12 * 1024 * 1024
MAX_EXTRACTED_STRINGS = 5000
PRINTABLE_TEXT_OVERLAP_CHARS = 64
MIN_TORCH7_SIZE = 8
CONTENT_ROUTE_BLOCKED_EXTENSIONS = frozenset({".bin", ".meta", ".pb"})

PRINTABLE_TEXT_PATTERN = re.compile(rb"[\t\n\r -~]{6,512}")

EXEC_PRIMITIVE_NAME_PATTERN = (
    r"(?:os\s*(?:\.\s*execute|\[\s*['\"]execute['\"]\s*\])|"
    r"io\s*(?:\.\s*popen|\[\s*['\"]popen['\"]\s*\])|"
    r"loadstring|dofile|loadfile|setfenv|getfenv)"
)
EXEC_PRIMITIVE_CALL_PATTERN = re.compile(rf"(?i)(?:\(\s*)*\b{EXEC_PRIMITIVE_NAME_PATTERN}\s*(?:\)\s*)*\(")
EXECUTION_ASSIGNMENT_TARGET_PATTERN = re.compile(
    r"(?i)(?P<target>\b(?:local\s+)?[a-z_][\w.]*(?:\s*\[[^\]\n]{1,120}\])*\s*=\s*)"
)
EXECUTION_VALUE_WRAPPER_PREFIX_PATTERN = re.compile(
    r"(?is)^(?:(?:[a-z_]\w*(?:\.[a-z_]\w*)*)\s*\(\s*|\(\s*)*(?:function\s*\(\s*\)\s*return\s*)?$"
)
COMPOUND_EXECUTION_VALUE_PREFIX_PATTERN = re.compile(
    r"(?is)^\s*(?P<value>.+?)\s*(?P<operator>(?<!\w)(?:or|and)(?!\w)|\.\.)\s*$"
)
NETWORK_OR_SHELL_PATTERN = re.compile(
    r"(?i)\b("
    r"https?://|ftp://|socket\.|luasocket|curl|wget|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|"
    r"/bin/sh|/bin/bash|bash\s+-c|sh\s+-c|netcat|nc\s+"
    r")"
)
_LUA_GAP_PATTERN = r"(?:\s|--[^\r\n]*(?:\r?\n|$))*"
REQUIRE_PATTERN = re.compile(
    rf"(?is)\brequire{_LUA_GAP_PATTERN}"
    rf"(?:\({_LUA_GAP_PATTERN}(?:['\"]([^'\"]+)['\"]|\[(=*)\[(.*?)\]\2\]){_LUA_GAP_PATTERN}\)"
    rf"|['\"]([^'\"]+)['\"]|\[(=*)\[(.*?)\]\5\])"
)
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


class Torch7Scanner(BaseScanner):
    """Static scanner for signature-valid Torch7 serialized artifacts."""

    name = "torch7"
    description = "Scans Torch7 serialized model files for Lua execution and dynamic loading indicators"
    supported_extensions: ClassVar[list[str]] = [".t7", ".th", ".net"]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config=config)
        self.max_scan_bytes = int(self.config.get("torch7_max_scan_bytes", MAX_SCAN_BYTES))
        self.max_extracted_strings = int(self.config.get("torch7_max_extracted_strings", MAX_EXTRACTED_STRINGS))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Recognize Torch7 content unless a conflicting suffix retains primary ownership."""
        if not os.path.isfile(path):
            return False
        if os.path.splitext(path)[1].lower() in CONTENT_ROUTE_BLOCKED_EXTENSIONS:
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
            mark_inconclusive_scan_result(result, "torch7_read_failed")
            result.add_check(
                name="Torch7 File Read",
                passed=False,
                message=f"Failed to read Torch7 file: {exc!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torch7_read_failed",
                },
            )
            result.finish(success=False)
            return result

        truncated = len(data) > self.max_scan_bytes
        payload = data[: self.max_scan_bytes]
        result.bytes_scanned = len(payload)
        result.metadata["scan_truncated"] = truncated

        if truncated:
            mark_inconclusive_scan_result(result, "torch7_bounded_read_incomplete")
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

        extracted_strings, strings_truncated = self._extract_strings(payload)
        result.metadata["extracted_string_count"] = len(extracted_strings)
        result.metadata["string_extraction_truncated"] = strings_truncated

        if strings_truncated:
            mark_inconclusive_scan_result(result, "torch7_string_extraction_limit_exceeded")
        result.add_check(
            name="Torch7 Text Fragment Budget",
            passed=not strings_truncated,
            message=(
                "Torch7 text fragment analysis stopped at the configured extraction limit"
                if strings_truncated
                else "Torch7 text fragment analysis completed within the configured extraction limit"
            ),
            severity=IssueSeverity.INFO if strings_truncated else None,
            location=path,
            details={
                "max_extracted_strings": self.max_extracted_strings,
                "analysis_incomplete": strings_truncated,
            },
        )

        self._analyze_execution_primitives(path, extracted_strings, result)
        self._analyze_dynamic_loads(path, extracted_strings, result)
        self._analyze_network_shell_strings(path, extracted_strings, result)

        result.finish(
            success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors,
        )
        return result

    def _extract_strings(self, payload: bytes) -> tuple[list[str], bool]:
        return extract_bounded_printable_strings(
            payload,
            PRINTABLE_TEXT_PATTERN,
            self.max_extracted_strings,
            overlap_chars=PRINTABLE_TEXT_OVERLAP_CHARS,
        )

    @staticmethod
    def _snippet(text: str, max_chars: int = 180) -> str:
        protected_targets: list[str] = []
        protected_parts: list[str] = []
        placeholder_prefix = "__MODELAUDIT_TORCH7_TARGET_"
        while placeholder_prefix in text:
            placeholder_prefix = f"_{placeholder_prefix}"
        cursor = 0

        for match in EXECUTION_ASSIGNMENT_TARGET_PATTERN.finditer(text):
            if match.start() < cursor:
                continue
            statement_end = Torch7Scanner._statement_end(text, match.end())
            execution_match = EXEC_PRIMITIVE_CALL_PATTERN.search(text, match.end(), statement_end)
            if execution_match is None:
                continue

            value_prefix = text[match.end() : execution_match.start()]
            leading_execution_parentheses = re.match(r"(?:\(\s*)*", execution_match.group(0))
            wrapper_prefix = value_prefix + (
                leading_execution_parentheses.group(0) if leading_execution_parentheses is not None else ""
            )
            replacement_end = match.end()
            replacement_suffix = ""
            if EXECUTION_VALUE_WRAPPER_PREFIX_PATTERN.fullmatch(wrapper_prefix) is None:
                compound_match = COMPOUND_EXECUTION_VALUE_PREFIX_PATTERN.fullmatch(value_prefix)
                target_name = match.group("target").rsplit("=", 1)[0].strip()
                if target_name.lower().startswith("local "):
                    target_name = target_name[6:].strip()
                if compound_match is None or not is_sensitive_evidence_key(target_name):
                    continue
                replacement_end = execution_match.start()
                replacement_suffix = f"{REDACTED_EVIDENCE_VALUE} {compound_match.group('operator').lower()} "

            protected_parts.append(text[cursor : match.start()])
            protected_targets.append(redact_evidence_string(match.group("target"), max_chars=None))
            protected_parts.append(f"{placeholder_prefix}{len(protected_targets) - 1}__{replacement_suffix}")
            cursor = replacement_end

        protected_parts.append(text[cursor:])
        protected = "".join(protected_parts)
        redacted = redact_evidence_string(protected, max_chars=None)
        for index, target in enumerate(protected_targets):
            redacted = redacted.replace(f"{placeholder_prefix}{index}__", target)
        if len(redacted) <= max_chars:
            return redacted
        if max_chars <= 3:
            return redacted[:max_chars]
        return f"{redacted[: max_chars - 3]}..."

    @staticmethod
    def _statement_end(text: str, start: int) -> int:
        quote: str | None = None
        escaped = False
        depth = 0
        for index in range(start, len(text)):
            character = text[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
                continue
            if character in {"'", '"'}:
                quote = character
            elif character in "([{":
                depth += 1
            elif character in ")]}" and depth > 0:
                depth -= 1
            elif character in ";\r\n" and depth == 0:
                return index
        return len(text)

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
            requires = [
                module
                for quoted_paren, _, long_paren, quoted_bare, _, long_bare in REQUIRE_PATTERN.findall(text)
                for module in (quoted_paren, long_paren, quoted_bare, long_bare)
                if module
            ]
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
