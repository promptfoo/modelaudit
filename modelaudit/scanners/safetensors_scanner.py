"""SafeTensors model scanner."""

from __future__ import annotations

import base64
import binascii
import html
import json
import os
import re
import struct
from collections.abc import Iterator
from typing import Any, ClassVar
from urllib.parse import unquote, urlparse

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
_GENERIC_URL_METADATA_PATTERN = r"https?://"
_ENCODED_URL_DELIMITER_METADATA_PATTERN = "encoded-url-delimiter"
_BACKSLASH_URL_DELIMITER_METADATA_PATTERN = "backslash-url-delimiter"
_WRAPPED_OPAQUE_TOKEN_METADATA_PATTERN = "wrapped-opaque-token"
_LICENSE_METADATA_KEYS = frozenset({"license"})
_LICENSE_DOCUMENT_MARKERS = (
    "license agreement",
    "terms and conditions",
    "permission is hereby granted",
    "grant of license",
    "apache license",
    "mit license",
    "gnu general public license",
    "creative commons",
    "bsd license",
    "mozilla public license",
)
_LICENSE_DOCUMENT_MIN_CHARS = 500
_LICENSE_DOCUMENT_MAX_CHARS = 128 * 1024
_LICENSE_DOCUMENT_MAX_LINE_CHARS = 2000
_LICENSE_DOCUMENT_LINE_MARKERS = (
    "agreement",
    "arbitration",
    "copyright",
    "derivative",
    "distribute",
    "entity",
    "grant",
    "law",
    "liability",
    "license",
    "licensor",
    "may",
    "must",
    "output",
    "patent",
    "permission",
    "reproduce",
    "restriction",
    "shall",
    "terms",
    "trademark",
    "use",
)
_LICENSE_DOCUMENT_BASE64_WORD_TOKENS = frozenset(
    {
        *_LICENSE_DOCUMENT_LINE_MARKERS,
        "a",
        "additional",
        "apache",
        "applicable",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "by",
        "charge",
        "com",
        "conditions",
        "contributor",
        "defined",
        "definitions",
        "distribution",
        "display",
        "dmca",
        "document",
        "each",
        "exclusive",
        "free",
        "github",
        "grants",
        "hereby",
        "http",
        "https",
        "i",
        "irrevocable",
        "january",
        "legal",
        "licence",
        "licenses",
        "licensing",
        "lightricks",
        "mean",
        "model",
        "not",
        "notice",
        "of",
        "ordinary",
        "or",
        "perform",
        "policies",
        "policy",
        "prepare",
        "publicly",
        "reference",
        "royalty",
        "royalty-free",
        "sections",
        "source",
        "spdx",
        "subject",
        "sublicense",
        "the",
        "this",
        "to",
        "through",
        "under",
        "version",
        "video",
        "whereas",
        "work",
        "works",
        "worldwide",
    }
)
_DUPLICATE_JSON_KEY_DETAIL_LIMIT = 20
_URL_METADATA_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_LICENSE_REFERENCE_HOST_SUFFIXES = (
    "apache.org",
    "creativecommons.org",
    "github.com",
    "gnu.org",
    "ltx.io",
    "mozilla.org",
    "opensource.org",
    "spdx.org",
)
_LICENSE_REFERENCE_PATH_COMPONENTS = frozenset(
    {
        "copying",
        "legal",
        "legalcode",
        "licence",
        "license",
        "licenses",
        "licensing",
        "notice",
        "policies",
        "policy",
        "terms",
    }
)
_LICENSE_REFERENCE_FILE_MARKERS = (
    "copying",
    "legalcode",
    "licence",
    "license",
    "licensing",
    "notice",
    "policy",
    "terms",
)
_SUSPICIOUS_LICENSE_URL_PATH_COMPONENTS = frozenset({"download", "raw", "releases"})
_SUSPICIOUS_LICENSE_URL_PATH_SUFFIXES = (
    ".bat",
    ".bin",
    ".bz2",
    ".cjs",
    ".cmd",
    ".ckpt",
    ".com",
    ".dll",
    ".dylib",
    ".exe",
    ".gguf",
    ".gz",
    ".h5",
    ".jar",
    ".js",
    ".joblib",
    ".jsx",
    ".keras",
    ".mjs",
    ".model",
    ".msgpack",
    ".npy",
    ".npz",
    ".onnx",
    ".php",
    ".pickle",
    ".pkl",
    ".pl",
    ".ps1",
    ".pt",
    ".pth",
    ".py",
    ".rar",
    ".rb",
    ".safetensors",
    ".safetensors.index.json",
    ".sh",
    ".so",
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tgz",
    ".ts",
    ".tsx",
    ".xz",
    ".whl",
    ".zip",
)
_OPAQUE_LICENSE_TOKEN_MIN_CHARS = 128
_OPAQUE_LICENSE_TOKEN_PATTERN = re.compile(rf"\b[A-Za-z0-9+/=_-]{{{_OPAQUE_LICENSE_TOKEN_MIN_CHARS},}}\b")
_BASE64_LICENSE_WRAP_LINE_MIN_CHARS = 4
_BASE64_LICENSE_WRAP_TOKEN_MIN_CHARS = 4
_BASE64_LICENSE_WRAP_MIN_DECODE_CHARS = 24
_BASE64_LICENSE_WRAP_MAX_LINES = 128
_BASE64_LICENSE_WRAP_MAX_CHARS = 8192
_BASE64_LICENSE_WRAP_MAX_DECODED_BYTES = 6144
_BASE64_LICENSE_WRAP_MAX_SEPARATOR_LINES = 4
_BASE64_LICENSE_WRAP_METADATA_SCAN_MAX_LINES = _BASE64_LICENSE_WRAP_MAX_LINES * 2
_BASE64_LICENSE_WRAP_SEPARATOR_OVERFLOW_MIN_CHARS = 4
_BASE64_LICENSE_WRAP_MIN_FRAGMENT_RATIO = 0.15
_BASE64_LICENSE_WRAP_ANNOTATED_OPAQUE_MIN_CHARS = 64
_BASE64_LICENSE_WRAP_TRAILING_DOCUMENTARY_TOKENS = frozenset({"and", "or"})
_BASE64_LICENSE_WRAP_LINE_PATTERN = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_BASE64_LICENSE_WRAP_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/_-])(?:"
    rf"[A-Za-z0-9+/_-]{{{_BASE64_LICENSE_WRAP_TOKEN_MIN_CHARS},}}"
    r"|[A-Za-z0-9+/_-]{3}="
    r"|[A-Za-z0-9+/_-]{2}=="
    r")(?![A-Za-z0-9+/_-])"
)
_BASE64_LICENSE_WRAP_SHORT_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{1,3}(?![A-Za-z0-9+/_-])")
_BASE64_LICENSE_WRAP_SEPARATOR_PATTERN = re.compile(
    r"^(?:[#>;]|//|--|\*)\s*(?:continued|continuation|wrapped|base64|license(?:\s+terms?)?)?\s*$",
    re.IGNORECASE,
)
_SUSPICIOUS_LICENSE_URL_MARKERS = ("payload", "exfil", "webhook", "callback")
_BASE64_LICENSE_DECODED_ACTIVE_MARKERS = (
    "#!",
    "chmod +x",
    "curl ",
    "eval(",
    "exec(",
    "http://",
    "https://",
    "import ",
    "os.system",
    "rm -rf",
    "subprocess",
    "wget ",
)
_URL_PATH_NORMALIZATION_PASSES = 4
_URL_DELIMITER_ENTITY_DECODE_PASSES = 4
_PERCENT_ENCODED_BYTE_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
_HTML_ENTITY_REFERENCE_SOURCE = r"&(?:#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[A-Za-z][A-Za-z0-9]{1,31};)"
_RESIDUAL_NESTED_HTML_ENTITY_REFERENCE_SOURCE = (
    r"&(?:amp;)*(?:#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[A-Za-z][A-Za-z0-9]{1,31};)"
)
_RESIDUAL_NESTED_ENTITY_H = r"&(?:amp;)*(?:#0*(?:72|104);?|#[xX]0*(?:48|68);?)"
_RESIDUAL_NESTED_ENTITY_T = r"&(?:amp;)*(?:#0*(?:84|116);?|#[xX]0*(?:54|74);?)"
_RESIDUAL_NESTED_ENTITY_P = r"&(?:amp;)*(?:#0*(?:80|112);?|#[xX]0*(?:50|70);?)"
_RESIDUAL_NESTED_ENTITY_S = r"&(?:amp;)*(?:#0*(?:83|115);?|#[xX]0*(?:53|73);?)"
_RESIDUAL_NESTED_ENTITY_SCHEME_LETTERS = (
    rf"(?:h|{_RESIDUAL_NESTED_ENTITY_H})",
    rf"(?:t|{_RESIDUAL_NESTED_ENTITY_T})",
    rf"(?:t|{_RESIDUAL_NESTED_ENTITY_T})",
    rf"(?:p|{_RESIDUAL_NESTED_ENTITY_P})",
    rf"(?:s|{_RESIDUAL_NESTED_ENTITY_S})?",
)
_HTML_ENTITY_REFERENCE_PATTERN = re.compile(_HTML_ENTITY_REFERENCE_SOURCE)
_RESIDUAL_ENTITY_URL_DELIMITER_PATTERN = re.compile(
    rf"{''.join(_RESIDUAL_NESTED_ENTITY_SCHEME_LETTERS)}(?:{_RESIDUAL_NESTED_HTML_ENTITY_REFERENCE_SOURCE}|:)"
    rf"(?:{_RESIDUAL_NESTED_HTML_ENTITY_REFERENCE_SOURCE}|/|\\)"
    rf"(?:{_RESIDUAL_NESTED_HTML_ENTITY_REFERENCE_SOURCE}|/|\\)",
    re.IGNORECASE,
)
_ENCODED_URL_SCHEME_LETTERS = (
    r"(?:h|%(?:25)*(?:48|68))",
    r"(?:t|%(?:25)*(?:54|74))",
    r"(?:t|%(?:25)*(?:54|74))",
    r"(?:p|%(?:25)*(?:50|70))",
    r"(?:s|%(?:25)*(?:53|73))?",
)
_ENCODED_URL_DELIMITER_PATTERN = re.compile(
    rf"(?P<scheme>{''.join(_ENCODED_URL_SCHEME_LETTERS)})(?P<colon>%(?:25)*3a|:)"
    r"(?P<slash1>%(?:25)*(?:2f|5c)|/|\\)(?P<slash2>%(?:25)*(?:2f|5c)|/|\\)",
    re.IGNORECASE,
)
_RAW_BACKSLASH_URL_DELIMITER_PATTERN = re.compile(r"https?:(?:\\\\|/\\|\\/|\\(?![\\/])|/(?!/))", re.IGNORECASE)


def _url_path_has_unsafe_decoded_char(path: str) -> bool:
    return any(char == "\\" or ord(char) < 0x20 or ord(char) == 0x7F for char in path)


def _html_unescape_with_entity_mask(value: str, entity_mask: bytearray) -> tuple[str, bytearray, bool]:
    decoded_parts: list[str] = []
    decoded_entity_mask = bytearray()
    cursor = 0
    changed = False

    for match in _HTML_ENTITY_REFERENCE_PATTERN.finditer(value):
        start, end = match.span()
        decoded_parts.append(value[cursor:start])
        decoded_entity_mask.extend(entity_mask[cursor:start])

        raw_entity = match.group(0)
        decoded_entity = html.unescape(raw_entity)
        if decoded_entity != raw_entity:
            decoded_parts.append(decoded_entity)
            decoded_entity_mask.extend(b"\x01" * len(decoded_entity))
            changed = True
        else:
            decoded_parts.append(raw_entity)
            decoded_entity_mask.extend(entity_mask[start:end])

        cursor = end

    decoded_parts.append(value[cursor:])
    decoded_entity_mask.extend(entity_mask[cursor:])
    return "".join(decoded_parts), decoded_entity_mask, changed


def _encoded_url_delimiter_match_has_encoded_component(
    value: str,
    match: re.Match[str],
    *,
    entity_mask: bytearray | None = None,
) -> bool:
    for group_name in ("scheme", "colon", "slash1", "slash2"):
        start, end = match.span(group_name)
        if "%" in value[start:end]:
            return True
        if entity_mask is not None and any(entity_mask[start:end]):
            return True
    return False


def _value_has_encoded_url_delimiter(value: str) -> bool:
    if any(
        _encoded_url_delimiter_match_has_encoded_component(value, match)
        for match in _ENCODED_URL_DELIMITER_PATTERN.finditer(value)
    ):
        return True
    if "&" not in value:
        return False

    decoded_value = value
    entity_mask = bytearray(len(value))
    for _ in range(_URL_DELIMITER_ENTITY_DECODE_PASSES):
        decoded_value, entity_mask, changed = _html_unescape_with_entity_mask(decoded_value, entity_mask)
        if not changed:
            return False
        if any(
            _encoded_url_delimiter_match_has_encoded_component(decoded_value, match, entity_mask=entity_mask)
            for match in _ENCODED_URL_DELIMITER_PATTERN.finditer(decoded_value)
        ):
            return True
    return any(
        _HTML_ENTITY_REFERENCE_PATTERN.search(match.group(0)) is not None
        for match in _RESIDUAL_ENTITY_URL_DELIMITER_PATTERN.finditer(decoded_value)
    )


def _value_has_raw_backslash_url_delimiter(value: str) -> bool:
    return _RAW_BACKSLASH_URL_DELIMITER_PATTERN.search(value) is not None


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
    def _load_json_header(cls, header_bytes: bytes) -> tuple[Any, list[str]]:
        """Parse a SafeTensors header while tracking duplicate object keys."""
        duplicate_keys: list[str] = []

        def track_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            parsed: dict[str, Any] = {}
            seen: set[str] = set()
            for key, value in pairs:
                if key in seen and len(duplicate_keys) < _DUPLICATE_JSON_KEY_DETAIL_LIMIT:
                    duplicate_keys.append(key)
                seen.add(key)
                parsed[key] = value
            return parsed

        return json.loads(header_bytes.decode("utf-8"), object_pairs_hook=track_duplicate_keys), duplicate_keys

    @classmethod
    def _looks_like_ordinary_license_document(cls, value: str) -> bool:
        lower_value = value.lower()
        if len(value) < _LICENSE_DOCUMENT_MIN_CHARS:
            return False
        return (
            "license" in lower_value
            and any(marker in lower_value for marker in _LICENSE_DOCUMENT_MARKERS)
            and cls._license_document_body_is_bounded_and_coherent(value)
        )

    @staticmethod
    def _license_document_line_looks_documentary(line: str) -> bool:
        return any(marker in line for marker in _LICENSE_DOCUMENT_LINE_MARKERS)

    @staticmethod
    def _license_document_line_looks_opaque(line: str) -> bool:
        return _OPAQUE_LICENSE_TOKEN_PATTERN.search(line) is not None

    @staticmethod
    def _license_document_line_is_wrapped_base64_fragment(line: str) -> bool:
        stripped = line.strip()
        return (
            len(stripped) >= _BASE64_LICENSE_WRAP_LINE_MIN_CHARS
            and not any(char.isspace() for char in stripped)
            and _BASE64_LICENSE_WRAP_LINE_PATTERN.fullmatch(stripped) is not None
            and not SafeTensorsScanner._license_document_token_looks_documentary(stripped)
        )

    @staticmethod
    def _license_document_annotation_looks_documentary(text: str) -> bool:
        stripped = text.strip()
        if not stripped:
            return True
        lower_text = stripped.lower()
        return (
            lower_text.startswith(("#", ">", ";", "//", "--", "*"))
            or SafeTensorsScanner._license_document_line_looks_documentary(lower_text)
            or _BASE64_LICENSE_WRAP_SEPARATOR_PATTERN.fullmatch(stripped) is not None
        )

    @staticmethod
    def _license_document_line_base64_fragments(line: str) -> tuple[list[str], bool]:
        stripped = line.strip()
        if SafeTensorsScanner._license_document_line_is_wrapped_base64_fragment(stripped):
            return [stripped], False

        nonspace_len = sum(1 for char in stripped if not char.isspace())
        if nonspace_len == 0:
            return [], False

        fragments: list[str] = []
        has_documentary_annotation = False
        token_matches = list(_BASE64_LICENSE_WRAP_TOKEN_PATTERN.finditer(stripped))
        for match in token_matches:
            token = match.group(0)
            if SafeTensorsScanner._license_document_span_is_inside_url(stripped, match.start(), match.end()):
                continue
            before = stripped[: match.start()]
            after = stripped[match.end() :]
            token_decodes = SafeTensorsScanner._base64_candidate_decodes(token)
            if (
                len(token) / nonspace_len < _BASE64_LICENSE_WRAP_MIN_FRAGMENT_RATIO
                and not token_decodes
                and SafeTensorsScanner._license_document_token_looks_documentary(token)
            ):
                continue
            annotations = [annotation for annotation in (before, after) if annotation.strip()]
            if not all(
                SafeTensorsScanner._license_document_annotation_looks_documentary(annotation)
                for annotation in annotations
            ):
                continue
            has_documentary_annotation = has_documentary_annotation or bool(annotations)
            if not token_decodes and SafeTensorsScanner._license_document_token_looks_documentary(token):
                continue
            fragments.append(token)
        return fragments, has_documentary_annotation

    @staticmethod
    def _license_document_span_is_inside_url(line: str, start: int, end: int) -> bool:
        return any(match.start() <= start and end <= match.end() for match in _URL_METADATA_PATTERN.finditer(line))

    @staticmethod
    def _license_document_line_short_base64_fragments(line: str) -> list[str]:
        stripped = line.strip()
        if SafeTensorsScanner._license_document_line_is_wrapped_base64_fragment(stripped):
            return []

        token_matches = list(_BASE64_LICENSE_WRAP_SHORT_TOKEN_PATTERN.finditer(stripped))
        fragments: list[str] = []
        documentary_fragments: list[str] = []
        for match in token_matches:
            token = match.group(0)
            if SafeTensorsScanner._license_document_span_is_inside_url(stripped, match.start(), match.end()):
                continue
            before = stripped[: match.start()]
            after = stripped[match.end() :]
            annotations = [annotation for annotation in (before, after) if annotation.strip()]
            if not all(
                SafeTensorsScanner._license_document_annotation_looks_documentary(annotation)
                for annotation in annotations
            ):
                continue
            if SafeTensorsScanner._license_document_token_looks_documentary(token):
                documentary_fragments.append(token)
                continue
            fragments.append(token)
        if fragments:
            return fragments
        if documentary_fragments:
            if (
                len(documentary_fragments) > 1
                and documentary_fragments[-1].strip("=").lower() in _BASE64_LICENSE_WRAP_TRAILING_DOCUMENTARY_TOKENS
            ):
                return [documentary_fragments[-2]]
            return [documentary_fragments[-1]]
        return fragments

    @staticmethod
    def _license_document_token_looks_documentary(token: str) -> bool:
        normalized = token.strip("=").lower()
        if not normalized:
            return True
        if normalized.isdecimal():
            return True
        return normalized in _LICENSE_DOCUMENT_BASE64_WORD_TOKENS

    @staticmethod
    def _license_document_line_is_bounded_documentary_separator(line: str) -> bool:
        if len(line) > _LICENSE_DOCUMENT_MAX_LINE_CHARS:
            return False
        return SafeTensorsScanner._license_document_line_looks_documentary(line.lower())

    @staticmethod
    def _license_document_line_is_wrapped_base64_separator(line: str) -> bool:
        return len(line) <= _LICENSE_DOCUMENT_MAX_LINE_CHARS and (
            _BASE64_LICENSE_WRAP_SEPARATOR_PATTERN.fullmatch(line) is not None
            or SafeTensorsScanner._license_document_line_is_bounded_documentary_separator(line)
        )

    @staticmethod
    def _decoded_license_blob_has_active_pattern(decoded_text: str) -> bool:
        return any(marker in decoded_text for marker in _BASE64_LICENSE_DECODED_ACTIVE_MARKERS) or any(
            re.search(pattern, decoded_text, re.IGNORECASE) for pattern in _CODE_METADATA_PATTERNS
        )

    @staticmethod
    def _base64_candidate_decodes(
        candidate: str,
        *,
        require_active_pattern: bool = False,
        fail_on_invalid_padding: bool = True,
    ) -> bool:
        if len(candidate) < _BASE64_LICENSE_WRAP_MIN_DECODE_CHARS:
            return False
        if len(candidate) > _BASE64_LICENSE_WRAP_MAX_CHARS:
            return True

        normalized = candidate.replace("-", "+").replace("_", "/")
        if "=" in normalized.rstrip("="):
            return True
        if len(normalized) % 4 == 1:
            return fail_on_invalid_padding
        padding = "=" * ((4 - len(normalized) % 4) % 4)
        padded = f"{normalized}{padding}"
        estimated_decoded_bytes = (len(padded) // 4) * 3
        if estimated_decoded_bytes > _BASE64_LICENSE_WRAP_MAX_DECODED_BYTES:
            return True
        try:
            decoded = base64.b64decode(padded, validate=True)
        except binascii.Error:
            return False
        if require_active_pattern or len(candidate) < _OPAQUE_LICENSE_TOKEN_MIN_CHARS:
            decoded_text = decoded.decode("utf-8", errors="ignore").lower()
            return SafeTensorsScanner._decoded_license_blob_has_active_pattern(decoded_text)
        return len(decoded) >= (_OPAQUE_LICENSE_TOKEN_MIN_CHARS * 3) // 4

    @classmethod
    def _license_document_has_wrapped_opaque_token(cls, lines: list[str]) -> bool:
        chunks: list[str] = []
        total_chars = 0
        total_lines = 0
        separator_lines = 0
        has_short_fragments = False
        has_non_documentary_short_fragment = False
        has_low_ratio_documentary_annotations = False
        high_ratio_documentary_fragment_chars = 0
        high_ratio_documentary_fragment_lines = 0

        def requires_active_pattern() -> bool:
            has_annotated_wrapped_payload = (
                high_ratio_documentary_fragment_lines >= 2
                and high_ratio_documentary_fragment_chars >= _OPAQUE_LICENSE_TOKEN_MIN_CHARS
            )
            return has_short_fragments or (has_low_ratio_documentary_annotations and not has_annotated_wrapped_payload)

        def flush() -> bool:
            return total_chars >= _BASE64_LICENSE_WRAP_MIN_DECODE_CHARS and cls._base64_candidate_decodes(
                "".join(chunks),
                require_active_pattern=requires_active_pattern(),
                fail_on_invalid_padding=not requires_active_pattern() or has_non_documentary_short_fragment,
            )

        def reset() -> None:
            nonlocal chunks, total_chars, total_lines, separator_lines, has_short_fragments
            nonlocal has_non_documentary_short_fragment, has_low_ratio_documentary_annotations
            nonlocal high_ratio_documentary_fragment_chars, high_ratio_documentary_fragment_lines
            chunks = []
            total_chars = 0
            total_lines = 0
            separator_lines = 0
            has_short_fragments = False
            has_non_documentary_short_fragment = False
            has_low_ratio_documentary_annotations = False
            high_ratio_documentary_fragment_chars = 0
            high_ratio_documentary_fragment_lines = 0

        for line in [*lines, ""]:
            fragments, line_has_documentary_annotation = cls._license_document_line_base64_fragments(line)
            short_fragments = False
            if not fragments:
                fragments = cls._license_document_line_short_base64_fragments(line)
                short_fragments = bool(fragments)
            if fragments:
                current_line_has_annotated_opaque_fragment = line_has_documentary_annotation and any(
                    len(fragment) >= _BASE64_LICENSE_WRAP_ANNOTATED_OPAQUE_MIN_CHARS for fragment in fragments
                )
                if chunks and current_line_has_annotated_opaque_fragment and requires_active_pattern():
                    if flush():
                        return True
                    reset()
                current_line_decodes_active = not short_fragments and cls._base64_candidate_decodes(
                    "".join(fragments),
                    require_active_pattern=True,
                    fail_on_invalid_padding=False,
                )
                starts_distinct_payload = not line_has_documentary_annotation or current_line_decodes_active
                if chunks and not short_fragments and starts_distinct_payload and requires_active_pattern():
                    if flush():
                        return True
                    reset()
                total_lines += 1
                separator_lines = 0
                has_short_fragments = has_short_fragments or short_fragments
                fragment_chars = sum(len(fragment) for fragment in fragments)
                nonspace_chars = sum(1 for char in line if not char.isspace())
                if line_has_documentary_annotation and nonspace_chars > 0:
                    if any(len(fragment) >= _BASE64_LICENSE_WRAP_ANNOTATED_OPAQUE_MIN_CHARS for fragment in fragments):
                        high_ratio_documentary_fragment_chars += fragment_chars
                        high_ratio_documentary_fragment_lines += 1
                    elif fragment_chars / nonspace_chars < _BASE64_LICENSE_WRAP_MIN_FRAGMENT_RATIO:
                        has_low_ratio_documentary_annotations = True
                    elif any(len(fragment) >= _BASE64_LICENSE_WRAP_MIN_DECODE_CHARS for fragment in fragments):
                        high_ratio_documentary_fragment_chars += fragment_chars
                        high_ratio_documentary_fragment_lines += 1
                    else:
                        has_low_ratio_documentary_annotations = True
                if short_fragments:
                    has_non_documentary_short_fragment = has_non_documentary_short_fragment or any(
                        not cls._license_document_token_looks_documentary(fragment) for fragment in fragments
                    )
                total_chars += fragment_chars
                if total_lines > _BASE64_LICENSE_WRAP_MAX_LINES or total_chars > _BASE64_LICENSE_WRAP_MAX_CHARS:
                    if flush():
                        return True
                    reset()
                    continue
                chunks.extend(fragments)
                continue

            if chunks and cls._license_document_line_is_wrapped_base64_separator(line):
                total_lines += 1
                separator_lines += 1
                if total_lines > _BASE64_LICENSE_WRAP_MAX_LINES:
                    if flush() or (chunks and not requires_active_pattern()):
                        return True
                    reset()
                    continue
                if separator_lines > _BASE64_LICENSE_WRAP_MAX_SEPARATOR_LINES:
                    if flush():
                        return True
                    if requires_active_pattern():
                        continue
                    if total_chars >= _BASE64_LICENSE_WRAP_SEPARATOR_OVERFLOW_MIN_CHARS:
                        return True
                    reset()
                    continue
                continue

            if flush():
                return True
            reset()

        return False

    @classmethod
    def _metadata_value_has_wrapped_opaque_token(cls, value: str) -> bool:
        scan_value = value[-_LICENSE_DOCUMENT_MAX_CHARS:]
        lines = [line.strip() for line in scan_value.splitlines() if line.strip()]
        return len(lines) > 1 and cls._license_document_has_wrapped_opaque_token(lines)

    @classmethod
    def _license_document_body_is_bounded_and_coherent(cls, value: str) -> bool:
        if len(value) > _LICENSE_DOCUMENT_MAX_CHARS:
            return False

        lines = [line.strip() for line in value.splitlines() if line.strip()]
        if not lines or any(len(line) > _LICENSE_DOCUMENT_MAX_LINE_CHARS for line in lines):
            return False
        if any(cls._license_document_line_looks_opaque(line) for line in lines):
            return False
        if cls._license_document_has_wrapped_opaque_token(lines):
            return False

        documentary_lines = sum(cls._license_document_line_looks_documentary(line.lower()) for line in lines)
        return documentary_lines / len(lines) > 0.5

    @staticmethod
    def _url_host_matches_suffix(hostname: str, suffix: str) -> bool:
        return hostname == suffix or hostname.endswith(f".{suffix}")

    @staticmethod
    def _normalize_url_path(path: str) -> tuple[str, bool]:
        normalized = path
        for _ in range(_URL_PATH_NORMALIZATION_PASSES):
            decoded = unquote(normalized)
            if decoded == normalized:
                normalized_path = normalized.lower()
                return normalized_path, not normalized_path.isascii() or _url_path_has_unsafe_decoded_char(
                    normalized_path
                )
            normalized = decoded
        normalized_path = normalized.lower()
        return (
            normalized_path,
            not normalized_path.isascii()
            or _url_path_has_unsafe_decoded_char(normalized_path)
            or _PERCENT_ENCODED_BYTE_PATTERN.search(normalized_path) is not None,
        )

    @classmethod
    def _url_path_segments(cls, path: str) -> tuple[list[str], bool]:
        normalized_path, has_residual_encoding = cls._normalize_url_path(path)
        return [segment for segment in normalized_path.strip("/").split("/") if segment], has_residual_encoding

    @classmethod
    def _url_path_has_suspicious_target(cls, path: str) -> bool:
        segments, has_residual_encoding = cls._url_path_segments(path)
        if has_residual_encoding:
            return True
        return (
            any(segment in _SUSPICIOUS_LICENSE_URL_PATH_COMPONENTS for segment in segments)
            or any(marker in segment for segment in segments for marker in _SUSPICIOUS_LICENSE_URL_MARKERS)
            or any(segment.endswith(suffix) for segment in segments for suffix in _SUSPICIOUS_LICENSE_URL_PATH_SUFFIXES)
        )

    @classmethod
    def _url_path_has_embedded_url(cls, path: str) -> bool:
        normalized_path, has_residual_encoding = cls._normalize_url_path(path)
        if has_residual_encoding:
            return True
        return "://" in normalized_path or "http:/" in normalized_path or "https:/" in normalized_path

    @classmethod
    def _url_path_looks_like_license_reference(cls, hostname: str, path: str) -> bool:
        segments, has_residual_encoding = cls._url_path_segments(path)
        if has_residual_encoding:
            return False

        if cls._url_host_matches_suffix(hostname, "github.com") and len(segments) == 2:
            return True

        if any(segment in _LICENSE_REFERENCE_PATH_COMPONENTS for segment in segments):
            return True

        return any(
            segment in _LICENSE_REFERENCE_FILE_MARKERS
            or any(segment.startswith(f"{marker}.") for marker in _LICENSE_REFERENCE_FILE_MARKERS)
            for segment in segments
        )

    @classmethod
    def _url_looks_like_license_reference(cls, raw_url: str) -> bool:
        cleaned_url = raw_url.rstrip(").,;:]}")
        try:
            parsed = urlparse(cleaned_url)
            port = parsed.port
            hostname = parsed.hostname.lower() if parsed.hostname else ""
        except ValueError:
            return False
        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            return False
        if port is not None and not 0 <= port <= 65535:
            return False
        if parsed.netloc.rsplit("@", maxsplit=1)[-1].endswith(":"):
            return False
        if parsed.username or parsed.password:
            return False
        if not parsed.netloc.isascii() or not parsed.path.isascii():
            return False
        if parsed.params or parsed.query or parsed.fragment:
            return False

        lowered_url = cleaned_url.lower()
        if any(marker in lowered_url for marker in _SUSPICIOUS_LICENSE_URL_MARKERS):
            return False
        if cls._url_path_has_embedded_url(parsed.path):
            return False
        if cls._url_path_has_suspicious_target(parsed.path):
            return False

        return any(cls._url_host_matches_suffix(hostname, suffix) for suffix in _LICENSE_REFERENCE_HOST_SUFFIXES) and (
            cls._url_path_looks_like_license_reference(hostname, parsed.path)
        )

    @classmethod
    def _license_document_urls_are_documentary(cls, value: str) -> bool:
        if _value_has_encoded_url_delimiter(value) or _value_has_raw_backslash_url_delimiter(value):
            return False
        urls = _URL_METADATA_PATTERN.findall(value)
        return all(cls._url_looks_like_license_reference(url) for url in urls)

    @classmethod
    def _looks_like_ordinary_license_reference_value(cls, value: str) -> bool:
        stripped = value.strip()
        if not stripped or any(char.isspace() for char in stripped):
            return False
        urls = _URL_METADATA_PATTERN.findall(stripped)
        if len(urls) != 1:
            return False
        return urls[0].rstrip(").,;:]}") == stripped.rstrip(").,;:]}") and cls._url_looks_like_license_reference(
            urls[0]
        )

    @classmethod
    def _metadata_value_has_active_risk(cls, value: str) -> bool:
        lower_value = value.lower()
        if any(marker in lower_value for marker in ("import ", "#!/")):
            return True
        if cls._find_html_tag_matches(value)[1] or cls._find_html_event_handler_matches(value)[1]:
            return True

        active_pattern_groups = (
            _HTML_METADATA_PATTERNS,
            _CODE_METADATA_PATTERNS,
            _PATH_TRAVERSAL_METADATA_PATTERNS,
            _CREDENTIAL_METADATA_PATTERNS,
        )
        if any(
            re.search(pattern, value, re.IGNORECASE)
            for pattern_group in active_pattern_groups
            for pattern in pattern_group
        ):
            return True

        return any(
            pattern != _GENERIC_URL_METADATA_PATTERN and re.search(pattern, value, re.IGNORECASE)
            for pattern in SUSPICIOUS_METADATA_PATTERNS
        )

    @staticmethod
    def _add_metadata_pattern_check(result: ScanResult, path: str, key: str, pattern: str) -> None:
        result.add_check(
            name="Metadata Pattern Check",
            passed=False,
            message=f"Suspicious metadata value for {key}",
            severity=IssueSeverity.INFO,
            location=path,
            details={"key": key, "pattern": pattern},
            why="Metadata matched known suspicious pattern",
        )

    @classmethod
    def _is_ordinary_license_metadata_value(
        cls,
        key: str,
        value: str,
        *,
        metadata_is_valid: bool,
    ) -> bool:
        if not metadata_is_valid:
            return False
        if key.strip().lower() not in _LICENSE_METADATA_KEYS:
            return False
        if cls._metadata_value_has_active_risk(value):
            return False
        return (
            cls._looks_like_ordinary_license_document(value) and cls._license_document_urls_are_documentary(value)
        ) or cls._looks_like_ordinary_license_reference_value(value)

    @classmethod
    def _summarize_custom_metadata(cls, custom_metadata: Any) -> dict[str, Any]:
        """Return a privacy-safe structural and security summary for custom metadata."""
        summary = cls._summarize_custom_metadata_structure(custom_metadata)
        flags: set[str] = set()
        metadata_is_valid = summary["custom_metadata_valid"] is True
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

        for key, value in cls._iter_custom_metadata_strings(custom_metadata):
            is_ordinary_license = cls._is_ordinary_license_metadata_value(
                key,
                value,
                metadata_is_valid=metadata_is_valid,
            )
            if len(value) > 1000 and not is_ordinary_license:
                flags.add("unusually_long_value")
            if any(marker in value.lower() for marker in ("import ", "#!/")):
                flags.add("code_like_value")
            if (
                any(
                    (pattern != _GENERIC_URL_METADATA_PATTERN or not is_ordinary_license)
                    and re.search(pattern, value, re.IGNORECASE)
                    for pattern in SUSPICIOUS_METADATA_PATTERNS
                )
                or _value_has_encoded_url_delimiter(value)
                or _value_has_raw_backslash_url_delimiter(value)
                or cls._metadata_value_has_wrapped_opaque_token(value)
            ):
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
        path_check_result = self._check_path(path)
        if path_check_result:
            if self._is_unreadable_path_result(path_check_result):
                return self._finish_read_failure(
                    self._create_result(),
                    path,
                    PermissionError(f"Path is not readable: {path}"),
                )
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        structural_validation_failed = False

        try:
            self.current_file_path = path
            with open(path, "rb") as f:
                header_len_bytes = f.read(8)
                if len(header_len_bytes) != 8:
                    self.add_file_integrity_check(path, result)
                    result.add_check(
                        name="SafeTensors Header Size Check",
                        passed=False,
                        message="File too small to contain SafeTensors header length",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"bytes_read": len(header_len_bytes), "required": 8},
                    )
                    self._mark_inconclusive(result, SAFETENSORS_HEADER_INCONCLUSIVE_REASON)
                    result.finish(success=False)
                    return result

                header_len = struct.unpack("<Q", header_len_bytes)[0]
                max_header_bytes = int(self.config.get("max_safetensors_header_bytes", MAX_HEADER_BYTES))
                if header_len <= 0 or header_len > file_size - 8:
                    self.add_file_integrity_check(path, result)
                    result.add_check(
                        name="Header Length Validation",
                        passed=False,
                        message="Invalid SafeTensors header length",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"header_len": header_len, "max_allowed": file_size - 8},
                    )
                    self._mark_inconclusive(result, SAFETENSORS_HEADER_INCONCLUSIVE_REASON)
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
                    result.bytes_scanned = file_size
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
                self.add_file_integrity_check(path, result)

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
                    header, duplicate_keys = self._load_json_header(header_bytes)
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
                        name="SafeTensors Duplicate Key Detection",
                        passed=False,
                        message="SafeTensors header contains duplicate JSON keys",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "duplicate_keys": duplicate_keys,
                            "duplicate_key_count": len(duplicate_keys),
                        },
                    )
                    self._mark_inconclusive(result, SAFETENSORS_HEADER_INCONCLUSIVE_REASON)
                    result.finish(success=False)
                    return result

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
                metadata_is_valid = result.metadata.get("custom_metadata_valid") is True
                for key, value in self._iter_custom_metadata_strings(metadata):
                    is_ordinary_license = self._is_ordinary_license_metadata_value(
                        key,
                        value,
                        metadata_is_valid=metadata_is_valid,
                    )
                    if len(value) > 1000 and not is_ordinary_license:
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
                    suspicious_pattern: str | None = None
                    for pattern in SUSPICIOUS_METADATA_PATTERNS:
                        if pattern == _GENERIC_URL_METADATA_PATTERN and is_ordinary_license:
                            continue
                        if re.search(pattern, value, re.IGNORECASE):
                            suspicious_pattern = pattern
                            break
                    if suspicious_pattern is None and _value_has_encoded_url_delimiter(value):
                        suspicious_pattern = _ENCODED_URL_DELIMITER_METADATA_PATTERN
                    if suspicious_pattern is None and _value_has_raw_backslash_url_delimiter(value):
                        suspicious_pattern = _BACKSLASH_URL_DELIMITER_METADATA_PATTERN
                    has_wrapped_opaque_token = self._metadata_value_has_wrapped_opaque_token(value)
                    if suspicious_pattern is None and has_wrapped_opaque_token:
                        suspicious_pattern = _WRAPPED_OPAQUE_TOKEN_METADATA_PATTERN
                    if suspicious_pattern is not None:
                        custom_metadata_security_flags.add("suspicious_pattern")
                        self._add_metadata_pattern_check(result, path, key, suspicious_pattern)
                        if has_wrapped_opaque_token and suspicious_pattern != _WRAPPED_OPAQUE_TOKEN_METADATA_PATTERN:
                            self._add_metadata_pattern_check(
                                result,
                                path,
                                key,
                                _WRAPPED_OPAQUE_TOKEN_METADATA_PATTERN,
                            )

                if "__metadata__" in header:
                    result.metadata["custom_metadata_security_flags"] = sorted(custom_metadata_security_flags)

                # Bytes scanned = file size
                result.bytes_scanned = file_size

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
                header, duplicate_keys = self._load_json_header(header_bytes)
                if duplicate_keys:
                    metadata["extraction_error"] = "Duplicate SafeTensors header keys"
                    metadata["duplicate_header_keys"] = duplicate_keys
                    return metadata

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
