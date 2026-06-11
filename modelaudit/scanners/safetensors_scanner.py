"""SafeTensors model scanner."""

from __future__ import annotations

import json
import os
import re
import struct
from collections.abc import Iterator
from typing import Any, ClassVar

from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_METADATA_PATTERNS

from ..core_results import mark_operational_scan_error
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult

# Map SafeTensors dtypes to bit sizes for integrity checking. Sub-byte
# dtypes are valid only when the complete tensor occupies whole bytes.
_DTYPE_BITS = {
    "BOOL": 8,
    "BF16": 16,
    "C64": 64,
    "F4": 4,
    "F6_E2M3": 6,
    "F6_E3M2": 6,
    "F16": 16,
    "F32": 32,
    "F64": 64,
    "F8_E4M3": 8,
    "F8_E4M3FNUZ": 8,
    "F8_E5M2": 8,
    "F8_E5M2FNUZ": 8,
    "F8_E8M0": 8,
    "I8": 8,
    "I16": 16,
    "I32": 32,
    "I64": 64,
    "U8": 8,
    "U16": 16,
    "U32": 32,
    "U64": 64,
}
MAX_HEADER_BYTES = 16 * 1024 * 1024
_MAX_PLATFORM_USIZE = (1 << (8 * struct.calcsize("P"))) - 1
SAFETENSORS_HEADER_INCONCLUSIVE_REASON = "safetensors_header_validation_failed"
SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON = "safetensors_structure_validation_failed"
SAFETENSORS_HEADER_LIMIT_INCONCLUSIVE_REASON = "safetensors_header_size_limit_exceeded"
SAFETENSORS_READ_INCONCLUSIVE_REASON = "safetensors_read_failed"
_REMOTE_HEADER_ONLY_CONFIG_KEY = "_safetensors_header_only_remote"
_REMOTE_HEADER_BYTES_SCANNED_CONFIG_KEY = "_safetensors_remote_header_bytes_scanned"
_REMOTE_HEADER_INTEGRITY_CONFIG_KEY = "_safetensors_remote_header_integrity"

_HTML_METADATA_PATTERNS = (
    r"javascript:",
    r"vbscript:",
    r"data:text/html",
)
_RISKY_HTML_TAGS = frozenset({"script", "iframe", "object", "embed", "form"})
_HTML_TAG_NAME_PATTERN = re.compile(r"[a-z][\w:-]*", re.IGNORECASE)
_HTML_EVENT_HANDLER_PATTERN = re.compile(r"\b(on[a-z][\w:-]*)\s*=", re.IGNORECASE)
_HTML_EVENT_NAMES = frozenset(
    {
        "abort",
        "afterprint",
        "animationcancel",
        "animationend",
        "animationiteration",
        "animationstart",
        "auxclick",
        "beforeinput",
        "beforematch",
        "beforeprint",
        "beforetoggle",
        "beforeunload",
        "begin",
        "blur",
        "cancel",
        "canplay",
        "canplaythrough",
        "change",
        "click",
        "close",
        "contextlost",
        "contextmenu",
        "contextrestored",
        "copy",
        "cuechange",
        "cut",
        "dblclick",
        "drag",
        "dragend",
        "dragenter",
        "dragleave",
        "dragover",
        "dragstart",
        "drop",
        "durationchange",
        "emptied",
        "end",
        "ended",
        "error",
        "focus",
        "focusin",
        "focusout",
        "formdata",
        "fullscreenchange",
        "fullscreenerror",
        "gotpointercapture",
        "hashchange",
        "input",
        "invalid",
        "keydown",
        "keypress",
        "keyup",
        "languagechange",
        "load",
        "loadeddata",
        "loadedmetadata",
        "loadstart",
        "lostpointercapture",
        "message",
        "messageerror",
        "mousedown",
        "mouseenter",
        "mouseleave",
        "mousemove",
        "mouseout",
        "mouseover",
        "mouseup",
        "offline",
        "online",
        "pagehide",
        "pageshow",
        "paste",
        "pause",
        "play",
        "playing",
        "pointercancel",
        "pointerdown",
        "pointerenter",
        "pointerleave",
        "pointermove",
        "pointerout",
        "pointerover",
        "pointerrawupdate",
        "pointerup",
        "popstate",
        "progress",
        "ratechange",
        "rejectionhandled",
        "repeat",
        "reset",
        "resize",
        "scroll",
        "scrollend",
        "securitypolicyviolation",
        "seeked",
        "seeking",
        "select",
        "selectionchange",
        "selectstart",
        "slotchange",
        "stalled",
        "storage",
        "submit",
        "suspend",
        "timeupdate",
        "toggle",
        "touchcancel",
        "touchend",
        "touchmove",
        "touchstart",
        "transitioncancel",
        "transitionend",
        "transitionrun",
        "transitionstart",
        "unhandledrejection",
        "unload",
        "volumechange",
        "waiting",
        "wheel",
    }
)
_CODE_METADATA_PATTERNS = (
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__\s*\(",
    r"compile\s*\(",
    r"subprocess\.",
    r"os\.system",
    r"os\.popen",
    r"\\x[0-9a-fA-F]{2}",
    r"\\u[0-9a-fA-F]{4}",
    r"base64\.(?:[a-z0-9_]*decode|decodebytes)\s*\(",
    r"pickle\.(?:load|loads|unpickler)\s*\(",
    r"marshal\.(?:load|loads)\s*\(",
)
_PATH_TRAVERSAL_METADATA_PATTERNS = (
    r"\.\./+",
    r"\.\.\\+",
    r"%2e%2e(?:%2f|/|%5c|\\)",
)
_CREDENTIAL_METADATA_PATTERNS = (
    r'password["\'\s]*[:=]["\'\s]*\w+',
    r'api[_-]?key["\'\s]*[:=]["\'\s]*[\w-]+',
    r'secret["\'\s]*[:=]["\'\s]*[\w-]+',
    r'token["\'\s]*[:=]["\'\s]*[\w.-]+',
    r"-----BEGIN [A-Z ]+-----",
    r"sk-[a-zA-Z0-9]{32,}",
    r"xox[boaprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
    r"ghp_[a-zA-Z0-9]{36}",
)


class SafeTensorsScanner(BaseScanner):
    """Scanner for SafeTensors model files."""

    name = "safetensors"
    description = "Scans SafeTensors model files for integrity issues"
    supported_extensions: ClassVar[list[str]] = [".safetensors"]
    default_max_file_read_size: ClassVar[int] = 0

    @staticmethod
    def _mark_inconclusive(result: ScanResult, reason: str) -> None:
        """Mark malformed safetensors framing as an explicit inconclusive scan."""
        result.metadata["analysis_incomplete"] = True
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME

        reasons = result.metadata.get("scan_outcome_reasons")
        if not isinstance(reasons, list):
            reasons = []
            result.metadata["scan_outcome_reasons"] = reasons
        if reason not in reasons:
            reasons.append(reason)

    @staticmethod
    def _is_unreadable_path_result(result: ScanResult) -> bool:
        return any(check.name == "Path Readable" and check.status == CheckStatus.FAILED for check in result.checks)

    @staticmethod
    def _json_duplicate_key_hook(duplicate_keys: list[str]) -> Any:
        def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            parsed: dict[str, Any] = {}
            for key, value in pairs:
                if key in parsed:
                    duplicate_keys.append(key)
                parsed[key] = value
            return parsed

        return hook

    @classmethod
    def _finish_read_failure(cls, result: ScanResult, path: str, error: OSError) -> ScanResult:
        cls._mark_inconclusive(result, SAFETENSORS_READ_INCONCLUSIVE_REASON)
        mark_operational_scan_error(result, SAFETENSORS_READ_INCONCLUSIVE_REASON)
        result.add_check(
            name="SafeTensors File Read",
            passed=False,
            message=f"Unable to read SafeTensors file: {error!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": SAFETENSORS_READ_INCONCLUSIVE_REASON,
            },
        )
        result.finish(success=False)
        return result

    @staticmethod
    def _is_valid_shape(shape: Any) -> bool:
        """Return True when shape is a safetensors-compatible list of non-negative ints."""
        return isinstance(shape, list) and all(
            isinstance(dim, int) and not isinstance(dim, bool) and dim >= 0 for dim in shape
        )

    @staticmethod
    def _summarize_custom_metadata_structure(custom_metadata: Any) -> dict[str, Any]:
        """Return a privacy-safe structural summary for custom metadata."""
        summary: dict[str, Any] = {
            "has_custom_metadata": True,
            "custom_metadata_valid": False,
        }
        if not isinstance(custom_metadata, dict):
            summary["custom_metadata_type"] = type(custom_metadata).__name__
            return summary

        summary["custom_metadata_entry_count"] = len(custom_metadata)
        invalid_value_count = sum(not isinstance(value, str) for value in custom_metadata.values())
        if invalid_value_count:
            summary["custom_metadata_invalid_value_count"] = invalid_value_count
            return summary

        summary["custom_metadata_valid"] = True
        return summary

    @staticmethod
    def _iter_custom_metadata_strings(custom_metadata: Any) -> Iterator[tuple[str, str]]:
        """Yield string values from nested JSON metadata without recursion."""
        if isinstance(custom_metadata, dict):
            stack = [(str(key), value) for key, value in reversed(list(custom_metadata.items()))]
        else:
            stack = [("<metadata>", custom_metadata)]

        while stack:
            key, value = stack.pop()
            if isinstance(value, str):
                yield key, value
            elif isinstance(value, dict):
                stack.extend((key, nested) for nested in reversed(list(value.values())))
            elif isinstance(value, list):
                stack.extend((key, nested) for nested in reversed(value))

    @staticmethod
    def _find_html_tag_matches(metadata_str: str) -> tuple[list[str], int]:
        """Find risky opening tags in non-overlapping tags in linear time."""
        first_matches: list[str] = []
        total_matches = 0
        cursor = 0
        while True:
            tag_start = metadata_str.find("<", cursor)
            if tag_start < 0:
                break
            tag_end = metadata_str.find(">", tag_start + 1)
            if tag_end < 0:
                break
            tag_body = metadata_str[tag_start + 1 : tag_end].lstrip()
            if tag_body and tag_body[0] not in "/!?":
                tag_name_match = _HTML_TAG_NAME_PATTERN.match(tag_body)
                if tag_name_match and tag_name_match.group(0).lower() in _RISKY_HTML_TAGS:
                    total_matches += 1
                    if len(first_matches) < 5:
                        first_matches.append(f"<{tag_name_match.group(0)}")
            cursor = tag_end + 1
        return first_matches, total_matches

    @staticmethod
    def _find_html_event_handler_matches(metadata_str: str) -> tuple[list[str], int]:
        """Find recognized inline event-handler assignments without broad on-prefix matches."""
        first_matches: list[str] = []
        total_matches = 0
        for match in _HTML_EVENT_HANDLER_PATTERN.finditer(metadata_str):
            if match.group(1)[2:].lower() not in _HTML_EVENT_NAMES:
                continue
            total_matches += 1
            if len(first_matches) < 5:
                first_matches.append(match.group(0))
        return first_matches, total_matches

    @staticmethod
    def _find_bounded_matches(pattern: str, content: str, flags: int = 0) -> tuple[list[str], int]:
        """Return at most five regex matches plus the total match count."""
        first_matches: list[str] = []
        total_matches = 0
        for match in re.finditer(pattern, content, flags):
            total_matches += 1
            if len(first_matches) < 5:
                first_matches.append(match.group(0))
        return first_matches, total_matches

    @classmethod
    def _summarize_custom_metadata(cls, custom_metadata: Any) -> dict[str, Any]:
        """Return a privacy-safe structural and security summary for custom metadata."""
        summary = cls._summarize_custom_metadata_structure(custom_metadata)
        flags: set[str] = set()
        serialized = json.dumps(custom_metadata, ensure_ascii=False)
        _, html_tag_match_count = cls._find_html_tag_matches(serialized)
        _, event_handler_match_count = cls._find_html_event_handler_matches(serialized)
        if (
            html_tag_match_count
            or event_handler_match_count
            or any(re.search(pattern, serialized, re.IGNORECASE) for pattern in _HTML_METADATA_PATTERNS)
        ):
            flags.add("xss_html_injection")
        if any(re.search(pattern, serialized, re.IGNORECASE) for pattern in _CODE_METADATA_PATTERNS):
            flags.add("code_injection")
        if any(re.search(pattern, serialized, re.IGNORECASE) for pattern in _PATH_TRAVERSAL_METADATA_PATTERNS):
            flags.add("path_traversal")
        if any(re.search(pattern, serialized, re.IGNORECASE) for pattern in _CREDENTIAL_METADATA_PATTERNS):
            flags.add("credential_exposure")

        for _, value in cls._iter_custom_metadata_strings(custom_metadata):
            if len(value) > 1000:
                flags.add("unusually_long_value")
            if any(marker in value.lower() for marker in ("import ", "#!/")):
                flags.add("code_like_value")
            if any(re.search(pattern, value) for pattern in SUSPICIOUS_METADATA_PATTERNS):
                flags.add("suspicious_pattern")

        summary["custom_metadata_security_flags"] = sorted(flags)
        return summary

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path."""
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            return True

        try:
            from modelaudit.utils.file.detection import detect_file_format

            return detect_file_format(path) == "safetensors"
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a SafeTensors file."""
        remote_header_only = bool(self.config.get(_REMOTE_HEADER_ONLY_CONFIG_KEY))
        path_check_result = self._check_path(path)
        if path_check_result:
            if self._is_unreadable_path_result(path_check_result):
                return self._finish_read_failure(
                    self._create_result(),
                    path,
                    PermissionError(f"Path is not readable: {path}"),
                )
            return path_check_result

        if remote_header_only:
            if self._path_validation_result is None:
                self._path_validation_result = ScanResult(scanner_name=self.name, scanner=self)
            self._path_validation_result.metadata["file_size"] = self.get_file_size(path)
        else:
            size_check = self._check_size_limit(path)
            if size_check:
                return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        structural_validation_failed = False

        def add_integrity_evidence() -> None:
            if remote_header_only:
                integrity_details = self.config.get(_REMOTE_HEADER_INTEGRITY_CONFIG_KEY)
                result.add_check(
                    name="Remote SafeTensors Header Integrity",
                    passed=True,
                    message="SafeTensors header was fetched with bounded remote range validation",
                    location=path,
                    details=integrity_details if isinstance(integrity_details, dict) else {},
                )
                result.metadata["remote_header_only"] = True
                result.metadata["content_hash_unavailable_reason"] = "remote_safetensors_header_only"
            else:
                self.add_file_integrity_check(path, result)

        def scanned_bytes_for_result() -> int:
            remote_bytes_scanned = self.config.get(_REMOTE_HEADER_BYTES_SCANNED_CONFIG_KEY)
            return (
                remote_bytes_scanned
                if remote_header_only
                and isinstance(remote_bytes_scanned, int)
                and not isinstance(remote_bytes_scanned, bool)
                and remote_bytes_scanned >= 0
                else file_size
            )

        try:
            self.current_file_path = path
            with open(path, "rb") as f:
                header_len_bytes = f.read(8)
                if len(header_len_bytes) != 8:
                    add_integrity_evidence()
                    result.add_check(
                        name="SafeTensors Header Size Check",
                        passed=False,
                        message="File too small to contain SafeTensors header length",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"bytes_read": len(header_len_bytes), "required": 8},
                    )
                    self._mark_inconclusive(result, SAFETENSORS_HEADER_INCONCLUSIVE_REASON)
                    result.bytes_scanned = scanned_bytes_for_result()
                    result.finish(success=False)
                    return result

                header_len = struct.unpack("<Q", header_len_bytes)[0]
                max_header_bytes = int(self.config.get("max_safetensors_header_bytes", MAX_HEADER_BYTES))
                if header_len <= 0 or header_len > file_size - 8:
                    add_integrity_evidence()
                    result.add_check(
                        name="Header Length Validation",
                        passed=False,
                        message="Invalid SafeTensors header length",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"header_len": header_len, "max_allowed": file_size - 8},
                    )
                    self._mark_inconclusive(result, SAFETENSORS_HEADER_INCONCLUSIVE_REASON)
                    result.bytes_scanned = scanned_bytes_for_result()
                    result.finish(success=False)
                    return result
                else:
                    result.add_check(
                        name="Header Length Validation",
                        passed=True,
                        message="SafeTensors header length is valid",
                        location=path,
                        details={"header_len": header_len},
                    )

                if header_len > max_header_bytes:
                    result.add_check(
                        name="Header Size Limit",
                        passed=False,
                        message=(
                            f"SafeTensors header exceeds maximum allowed size ({header_len} > {max_header_bytes})"
                        ),
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"header_len": header_len, "max_allowed": max_header_bytes},
                        why=(
                            "Large metadata headers can trigger expensive regular-expression processing and increase "
                            "denial-of-service risk."
                        ),
                    )
                    result.metadata["analysis_incomplete"] = True
                    self._mark_inconclusive(result, SAFETENSORS_HEADER_LIMIT_INCONCLUSIVE_REASON)
                    remote_bytes_scanned = self.config.get(_REMOTE_HEADER_BYTES_SCANNED_CONFIG_KEY)
                    result.bytes_scanned = (
                        remote_bytes_scanned
                        if remote_header_only
                        and isinstance(remote_bytes_scanned, int)
                        and not isinstance(remote_bytes_scanned, bool)
                        and remote_bytes_scanned >= 0
                        else file_size
                    )
                    result.finish(success=False)
                    return result

                result.add_check(
                    name="Header Size Limit",
                    passed=True,
                    message="SafeTensors header is within configured size limit",
                    location=path,
                    details={"header_len": header_len, "max_allowed": max_header_bytes},
                )

                # Do not hash an artifact that has already failed the bounded header gate.
                add_integrity_evidence()

                header_bytes = f.read(header_len)
                if len(header_bytes) != header_len:
                    result.add_check(
                        name="SafeTensors Header Read",
                        passed=False,
                        message="Failed to read SafeTensors header",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"bytes_read": len(header_bytes), "expected": header_len},
                    )
                    self._mark_inconclusive(result, SAFETENSORS_HEADER_INCONCLUSIVE_REASON)
                    result.finish(success=False)
                    return result

                if not header_bytes.strip().startswith(b"{"):
                    result.add_check(
                        name="Header Format Validation",
                        passed=False,
                        message="SafeTensors header does not start with '{'",
                        severity=IssueSeverity.INFO,
                        location=path,
                    )
                    self._mark_inconclusive(result, SAFETENSORS_HEADER_INCONCLUSIVE_REASON)
                    result.finish(success=False)
                    return result
                else:
                    result.add_check(
                        name="Header Format Validation",
                        passed=True,
                        message="SafeTensors header format is valid JSON",
                        location=path,
                    )

                try:
                    duplicate_keys: list[str] = []
                    header = json.loads(
                        header_bytes.decode("utf-8"),
                        object_pairs_hook=self._json_duplicate_key_hook(duplicate_keys),
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as e:
                    result.add_check(
                        name="SafeTensors JSON Parse",
                        passed=False,
                        message=f"Invalid JSON header: {e!s}",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"exception": str(e), "exception_type": type(e).__name__},
                        why="SafeTensors header contained invalid JSON.",
                    )
                    self._mark_inconclusive(result, SAFETENSORS_HEADER_INCONCLUSIVE_REASON)
                    result.finish(success=False)
                    return result

                if duplicate_keys:
                    result.add_check(
                        name="SafeTensors Duplicate Header Key Validation",
                        passed=False,
                        message="SafeTensors header contains duplicate JSON keys",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "duplicate_keys": duplicate_keys[:20],
                            "duplicate_key_count": len(duplicate_keys),
                            "duplicate_keys_truncated": len(duplicate_keys) > 20,
                        },
                    )
                    self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                    structural_validation_failed = True

                if "__metadata__" in header:
                    custom_metadata_summary = self._summarize_custom_metadata_structure(header["__metadata__"])
                    result.metadata.update(custom_metadata_summary)
                    if custom_metadata_summary["custom_metadata_valid"]:
                        result.add_check(
                            name="SafeTensors Metadata Structure Validation",
                            passed=True,
                            message="SafeTensors custom metadata is a string-to-string map",
                            location=path,
                            details={"entry_count": custom_metadata_summary["custom_metadata_entry_count"]},
                        )
                    else:
                        result.add_check(
                            name="SafeTensors Metadata Structure Validation",
                            passed=False,
                            message="SafeTensors custom metadata must be a string-to-string map",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                key: custom_metadata_summary[key]
                                for key in ("custom_metadata_type", "custom_metadata_invalid_value_count")
                                if key in custom_metadata_summary
                            },
                        )
                        self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                        structural_validation_failed = True

                tensor_names = [k for k in header if k != "__metadata__"]
                result.metadata["tensor_count"] = len(tensor_names)
                result.metadata["tensors"] = tensor_names

                # Enhanced SafeTensors metadata injection detection
                custom_metadata_security_flags = self._detect_metadata_injection_attacks(
                    header=header,
                    result=result,
                    path=path,
                    analyze_metadata_content=True,
                )

                # Validate tensor offsets and sizes
                tensor_entries: list[tuple[str, Any]] = [(k, v) for k, v in header.items() if k != "__metadata__"]

                data_size = file_size - (8 + header_len)
                offsets = []
                for name, info in tensor_entries:
                    if not isinstance(info, dict):
                        result.add_check(
                            name="Tensor Entry Type Validation",
                            passed=False,
                            message=f"Invalid tensor entry for {name}",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={"tensor": name, "actual_type": type(info).__name__, "expected_type": "dict"},
                        )
                        self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                        structural_validation_failed = True
                        continue

                    raw_offsets = info.get("data_offsets")
                    dtype = info.get("dtype")
                    shape = info.get("shape", [])

                    if not isinstance(raw_offsets, list) or len(raw_offsets) != 2:
                        result.add_check(
                            name="Tensor Offset Structure Validation",
                            passed=False,
                            message=f"Invalid data_offsets structure for {name}",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                "tensor": name,
                                "actual_type": type(raw_offsets).__name__,
                                "expected_type": "list",
                                "expected_length": 2,
                            },
                        )
                        self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                        structural_validation_failed = True
                        continue

                    begin, end = raw_offsets

                    if (
                        not isinstance(begin, int)
                        or isinstance(begin, bool)
                        or not isinstance(end, int)
                        or isinstance(end, bool)
                    ):
                        result.add_check(
                            name="Tensor Offset Type Validation",
                            passed=False,
                            message=f"Invalid data_offsets for {name}",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                "tensor": name,
                                "begin_type": type(begin).__name__,
                                "end_type": type(end).__name__,
                            },
                        )
                        self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                        structural_validation_failed = True
                        continue

                    if (
                        begin < 0
                        or end < begin
                        or begin > _MAX_PLATFORM_USIZE
                        or end > _MAX_PLATFORM_USIZE
                        or end > data_size
                    ):
                        result.add_check(
                            name="Tensor Offset Validation",
                            passed=False,
                            message=f"Tensor {name} offsets out of bounds",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={
                                "tensor": name,
                                "begin": begin,
                                "end": end,
                                "data_size": data_size,
                                "max_platform_offset": _MAX_PLATFORM_USIZE,
                            },
                        )
                        continue
                    else:
                        result.add_check(
                            name="Tensor Offset Validation",
                            passed=True,
                            message=f"Tensor {name} offsets are valid",
                            location=path,
                            details={"tensor": name, "begin": begin, "end": end},
                        )

                    offsets.append((begin, end))

                    # Validate dtype/shape size
                    if not isinstance(dtype, str) or dtype not in _DTYPE_BITS:
                        result.add_check(
                            name="Tensor Dtype Validation",
                            passed=False,
                            message=f"Invalid dtype for tensor {name}",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                "tensor": name,
                                "dtype": dtype,
                                "actual_type": type(dtype).__name__,
                            },
                        )
                        self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                        structural_validation_failed = True
                        continue

                    if not self._is_valid_shape(shape):
                        result.add_check(
                            name="Tensor Shape Validation",
                            passed=False,
                            message=f"Invalid shape for tensor {name}",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                "tensor": name,
                                "shape": shape,
                                "actual_type": type(shape).__name__,
                            },
                        )
                        self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                        structural_validation_failed = True
                        continue

                    expected_size = self._expected_size(dtype, shape)
                    if expected_size is None:
                        result.add_check(
                            name="Tensor Size Computation Check",
                            passed=False,
                            message=f"Unable to compute expected size for tensor {name}",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                "tensor": name,
                                "dtype": dtype,
                                "shape": shape,
                            },
                        )
                        self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                        structural_validation_failed = True
                        continue

                    if expected_size != end - begin:
                        result.add_check(
                            name="Tensor Size Consistency Check",
                            passed=False,
                            message=f"Size mismatch for tensor {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={
                                "tensor": name,
                                "expected_size": expected_size,
                                "actual_size": end - begin,
                            },
                        )
                    else:
                        result.add_check(
                            name="Tensor Size Consistency Check",
                            passed=True,
                            message=f"Tensor {name} size matches dtype/shape",
                            location=path,
                            details={
                                "tensor": name,
                                "size": expected_size,
                            },
                        )

                # Check offset continuity
                offsets.sort()
                last_end = 0
                has_gap_or_overlap = False
                for begin, end in offsets:
                    if begin != last_end:
                        has_gap_or_overlap = True
                        result.add_check(
                            name="Offset Continuity Check",
                            passed=False,
                            message="Tensor data offsets have gaps or overlap",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={"gap_at": begin, "expected": last_end},
                        )
                        self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                        structural_validation_failed = True
                        break
                    last_end = end

                if not has_gap_or_overlap and offsets:
                    result.add_check(
                        name="Offset Continuity Check",
                        passed=True,
                        message="Tensor offsets are continuous without gaps",
                        location=path,
                        details={"total_offsets": len(offsets)},
                    )

                data_size = file_size - (8 + header_len)
                if last_end != data_size:
                    result.add_check(
                        name="Tensor Data Coverage Check",
                        passed=False,
                        message="Tensor data does not cover entire file",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"last_offset": last_end, "data_size": data_size},
                    )
                    self._mark_inconclusive(result, SAFETENSORS_STRUCTURE_INCONCLUSIVE_REASON)
                    structural_validation_failed = True

                # Check metadata
                metadata = header.get("__metadata__", {})
                for key, value in self._iter_custom_metadata_strings(metadata):
                    if len(value) > 1000:
                        custom_metadata_security_flags.add("unusually_long_value")
                        result.add_check(
                            name="Metadata Length Check",
                            passed=False,
                            message=f"Metadata value for {key} is very long",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={"key": key, "length": len(value), "threshold": 1000},
                            why=(
                                "Metadata fields over 1000 characters are unusual in model files. Long strings "
                                "in metadata could contain encoded payloads, scripts, or data exfiltration "
                                "attempts."
                            ),
                        )

                    lower_val = value.lower()

                    # Check for simple code-like patterns
                    if any(s in lower_val for s in ["import ", "#!/"]):
                        custom_metadata_security_flags.add("code_like_value")
                        result.add_check(
                            name="Metadata Code Pattern Check",
                            passed=False,
                            message=f"Suspicious metadata value for {key}",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={"key": key, "pattern": "code-like"},
                            why=(
                                "Metadata containing code-like patterns (import statements, shebangs, escape "
                                "sequences) is atypical for model files and may indicate embedded scripts or "
                                "injection attempts."
                            ),
                        )

                    # Check for regex-based suspicious patterns (independent of above check)
                    for pattern in SUSPICIOUS_METADATA_PATTERNS:
                        if re.search(pattern, value):
                            custom_metadata_security_flags.add("suspicious_pattern")
                            result.add_check(
                                name="Metadata Pattern Check",
                                passed=False,
                                message=f"Suspicious metadata value for {key}",
                                severity=IssueSeverity.INFO,
                                location=path,
                                details={"key": key, "pattern": pattern},
                                why="Metadata matched known suspicious pattern",
                            )
                            break

                if "__metadata__" in header:
                    result.metadata["custom_metadata_security_flags"] = sorted(custom_metadata_security_flags)

                # Bytes scanned = file size for local scans. Remote header-only scans
                # report transferred header bytes while retaining the declared file size
                # in metadata.
                remote_bytes_scanned = self.config.get(_REMOTE_HEADER_BYTES_SCANNED_CONFIG_KEY)
                result.bytes_scanned = (
                    remote_bytes_scanned
                    if remote_header_only
                    and isinstance(remote_bytes_scanned, int)
                    and not isinstance(remote_bytes_scanned, bool)
                    and remote_bytes_scanned >= 0
                    else file_size
                )

        except OSError as e:
            return self._finish_read_failure(result, path, e)
        except Exception as e:
            result.add_check(
                name="SafeTensors File Scan",
                passed=False,
                message=f"Error scanning SafeTensors file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors and not structural_validation_failed)
        return result

    @staticmethod
    def _expected_size(dtype: str | None, shape: Any) -> int | None:
        """Return expected tensor byte size from dtype and shape."""
        if dtype not in _DTYPE_BITS:
            return None
        if not isinstance(shape, list):
            return None
        bits = _DTYPE_BITS[dtype]
        total = 1
        for dim in shape:
            if not isinstance(dim, int) or isinstance(dim, bool) or dim < 0:
                return None
            if dim > _MAX_PLATFORM_USIZE or (dim and total > _MAX_PLATFORM_USIZE // dim):
                return None
            total *= dim
        total_bits = total * bits
        if total_bits % 8:
            return None
        total_bytes = total_bits // 8
        if total_bytes > _MAX_PLATFORM_USIZE:
            return None
        return total_bytes

    def _detect_metadata_injection_attacks(
        self,
        header: dict[str, Any],
        result: ScanResult,
        path: str,
        analyze_metadata_content: bool = True,
    ) -> set[str]:
        """Detect metadata injection attacks in SafeTensors files"""
        security_flags: set[str] = set()

        # Check if __metadata__ exists and analyze it
        metadata = header.get("__metadata__", {})

        if "__metadata__" in header and analyze_metadata_content:
            # Analyze the metadata for injection patterns
            security_flags.update(self._analyze_metadata_content(metadata, result, path))

        # Check tensor names for injection attempts
        tensor_names = [k for k in header if k != "__metadata__"]
        for tensor_name in tensor_names:
            if self._is_suspicious_tensor_name(tensor_name):
                result.add_check(
                    name="SafeTensors Tensor Name Injection Check",
                    passed=False,
                    message=f"Suspicious tensor name detected: {tensor_name}",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={
                        "tensor_name": tensor_name,
                        "attack_type": "tensor_name_injection",
                        "reason": "Contains path traversal or dangerous characters",
                    },
                )

        # Check tensor metadata for injection
        for tensor_name, tensor_info in header.items():
            if tensor_name == "__metadata__":
                continue

            if isinstance(tensor_info, dict):
                # Check for unusual keys in tensor metadata
                expected_keys = {"dtype", "shape", "data_offsets"}
                unexpected_keys = set(tensor_info.keys()) - expected_keys

                if unexpected_keys:
                    result.add_check(
                        name="SafeTensors Tensor Metadata Injection Check",
                        passed=False,
                        message=f"Tensor {tensor_name} contains unexpected metadata keys: {list(unexpected_keys)}",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "tensor_name": tensor_name,
                            "unexpected_keys": list(unexpected_keys),
                            "attack_type": "tensor_metadata_injection",
                        },
                    )

        return security_flags

    def _analyze_metadata_content(self, metadata: Any, result: ScanResult, path: str) -> set[str]:
        """Analyze SafeTensors metadata content for injection attacks"""
        security_flags: set[str] = set()

        # Convert metadata to string for pattern analysis
        metadata_str = json.dumps(metadata, indent=2, ensure_ascii=False)

        # XSS/HTML injection patterns
        for pattern in _HTML_METADATA_PATTERNS:
            matches, total_matches = self._find_bounded_matches(pattern, metadata_str, re.IGNORECASE)
            if total_matches:
                security_flags.add("xss_html_injection")
                result.add_check(
                    name="SafeTensors XSS/HTML Injection Detection",
                    passed=False,
                    message="Potential XSS/HTML injection detected in metadata",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "pattern_matched": pattern,
                        "matches": matches,
                        "attack_type": "xss_html_injection",
                        "total_matches": total_matches,
                    },
                )

        html_tag_matches, html_tag_match_count = self._find_html_tag_matches(metadata_str)
        event_handler_matches, event_handler_match_count = self._find_html_event_handler_matches(metadata_str)
        if html_tag_match_count or event_handler_match_count:
            security_flags.add("xss_html_injection")
            result.add_check(
                name="SafeTensors XSS/HTML Injection Detection",
                passed=False,
                message="Potential XSS/HTML injection detected in metadata",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "pattern_matched": "HTML tag or event handler attribute",
                    "matches": (html_tag_matches + event_handler_matches)[:5],
                    "attack_type": "xss_html_injection",
                    "total_matches": html_tag_match_count + event_handler_match_count,
                },
            )

        # Code injection patterns
        for pattern in _CODE_METADATA_PATTERNS:
            matches, total_matches = self._find_bounded_matches(pattern, metadata_str, re.IGNORECASE)
            if total_matches:
                security_flags.add("code_injection")
                result.add_check(
                    name="SafeTensors Code Injection Detection",
                    passed=False,
                    message="Potential code injection detected in metadata",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "pattern_matched": pattern,
                        "matches": matches,
                        "attack_type": "code_injection",
                        "total_matches": total_matches,
                    },
                )

        # Path traversal patterns
        for pattern in _PATH_TRAVERSAL_METADATA_PATTERNS:
            matches, total_matches = self._find_bounded_matches(pattern, metadata_str, re.IGNORECASE)
            if total_matches:
                security_flags.add("path_traversal")
                result.add_check(
                    name="SafeTensors Path Traversal Detection",
                    passed=False,
                    message="Potential path traversal detected in metadata",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={
                        "pattern_matched": pattern,
                        "matches": matches,
                        "attack_type": "path_traversal",
                        "total_matches": total_matches,
                    },
                )

        # Check for embedded credentials or secrets
        for pattern in _CREDENTIAL_METADATA_PATTERNS:
            _, total_matches = self._find_bounded_matches(pattern, metadata_str, re.IGNORECASE)
            if total_matches:
                security_flags.add("credential_exposure")
                result.add_check(
                    name="SafeTensors Embedded Credentials Detection",
                    passed=False,
                    message="Potential embedded credentials detected in metadata",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "pattern_matched": pattern,
                        "attack_type": "credential_exposure",
                        "total_matches": total_matches,
                    },
                )

        return security_flags

    def _is_suspicious_tensor_name(self, name: str) -> bool:
        """Check if a tensor name contains suspicious patterns"""
        suspicious_patterns = [
            "../",  # Path traversal
            "..\\",  # Windows path traversal
            "/etc/",  # System directories
            "/proc/",
            "/root/",
            "\\x",  # Hex encoding
            "\\u",  # Unicode escapes
            "<script",  # HTML/XSS
            "javascript:",
            "eval(",
            "exec(",
        ]

        name_lower = name.lower()
        return any(pattern in name_lower for pattern in suspicious_patterns)

    def _calculate_json_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate maximum depth of JSON object"""
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(self._calculate_json_depth(v, current_depth + 1) for v in obj.values())

        if isinstance(obj, list):
            if not obj:
                return current_depth
            return max(self._calculate_json_depth(v, current_depth + 1) for v in obj)

        # For primitive types (str, int, float, bool, None)
        return current_depth

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract SafeTensors metadata."""
        metadata = super().extract_metadata(file_path)

        try:
            with open(file_path, "rb") as f:
                # Read header length
                header_len_bytes = f.read(8)
                if len(header_len_bytes) != 8:
                    metadata["extraction_error"] = "Invalid SafeTensors header"
                    return metadata

                header_len = struct.unpack("<Q", header_len_bytes)[0]
                file_size = self.get_file_size(file_path)
                MAX_HEADER_BYTES = int(self.config.get("max_safetensors_header_bytes", 16 * 1024 * 1024))
                max_allowed = max(0, min(MAX_HEADER_BYTES, file_size - 8))
                if header_len <= 0 or header_len > max_allowed:
                    metadata["extraction_error"] = f"Invalid SafeTensors header length: {header_len}"
                    return metadata
                header_bytes = f.read(header_len)
                if len(header_bytes) != header_len:
                    metadata["extraction_error"] = "Truncated SafeTensors header"
                    return metadata
                header = json.loads(header_bytes)

                # Extract tensor info
                tensors: dict[str, dict[str, Any]] = {}
                total_params = 0
                invalid_tensor_entries: list[str] = []

                for name, info in header.items():
                    if name != "__metadata__":  # Skip metadata entry
                        if not isinstance(info, dict):
                            invalid_tensor_entries.append(name)
                            continue

                        dtype = info.get("dtype")
                        shape = info.get("shape")
                        if not isinstance(dtype, str) or not isinstance(shape, list):
                            invalid_tensor_entries.append(name)
                            continue
                        if not all(isinstance(dim, int) and dim >= 0 for dim in shape):
                            invalid_tensor_entries.append(name)
                            continue

                        tensors[name] = {"dtype": dtype, "shape": shape}
                        # Calculate parameter count
                        param_count = 1
                        for dim in shape:
                            param_count *= dim
                        total_params += param_count

                metadata.update(
                    {
                        "tensor_count": len(tensors),
                        "total_parameters": total_params,
                        "tensors": tensors,
                        "dtypes": sorted({info["dtype"] for info in tensors.values()}),
                    }
                )
                if invalid_tensor_entries:
                    metadata["invalid_tensor_entries"] = invalid_tensor_entries[:20]

                # Extract custom metadata if present
                if "__metadata__" in header:
                    custom_metadata = header["__metadata__"]
                    metadata["custom_metadata"] = custom_metadata

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
