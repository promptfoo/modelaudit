"""Scanner for CNTK model artifacts with strict signature-based identification."""

from __future__ import annotations

import os
import re
from typing import ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

# Discovery assumptions captured from upstream CNTK sources:
# 1) Legacy CNTK models begin with UTF-16LE "BCN" marker bytes and contain
#    a UTF-16LE "BVersion" section marker.
# 2) CNTKv2 protobuf artifacts include protobuf key markers for "version" and
#    "uid", typically alongside structure keys like "CompositeFunction" and
#    "primitive_functions".
# 3) ".model" is intentionally excluded from v1 scanner ownership because it
#    overlaps with XGBoost's ".model" extension in this codebase.
DISCOVERY_ASSUMPTIONS = [
    "Legacy CNTK marker uses UTF-16LE BCN/BVersion section headers.",
    "CNTKv2 artifacts expose protobuf key markers for version/uid and graph structure fields.",
    "The .model extension is excluded in v1 to avoid ambiguity with XGBoost .model files.",
]

_CNTK_SUPPORTED_EXTENSIONS = frozenset({".dnn", ".cmf"})
_CNTK_CANDIDATE_EXTENSIONS = frozenset({".dnn", ".cmf", ".model"})

_MAX_SIGNATURE_BYTES = 4096
_MAX_SCAN_BYTES = 10 * 1024 * 1024  # 10MB parser budget per file
_MAX_EVIDENCE_PER_CATEGORY = 5
_MAX_EXTRACTED_STRINGS = 2000

_CNTK_LEGACY_MAGIC = b"B\x00C\x00N\x00\x00\x00"
_CNTK_LEGACY_VERSION_MARKER = b"B\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00"
_CNTK_V2_REQUIRED_MARKERS = (b"\x0a\x07version", b"\x0a\x03uid")
_CNTK_V2_STRUCTURE_MARKERS = (b"CompositeFunction", b"primitive_functions", b"PrimitiveFunction")

_ASCII_STRING_RE = re.compile(rb"[ -~]{6,512}")
_UTF16LE_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,256}")

_PATH_OR_LIBRARY_RE = re.compile(
    r"(?:\b[a-z]:\\[^\s\"']+|\.{2}[/\\][^\s\"']+|(?:/[^\s\"']+){2,}|[^\s\"']+\.(?:dll|so|dylib)\b|https?://[^\s\"']+)",
    re.IGNORECASE,
)
_LOAD_CONTEXT_RE = re.compile(
    r"(?:loadlibrary|dlopen|native_user_function|plugin|importlib|__import__|module|library)",
    re.IGNORECASE,
)
_COMMAND_CONTEXT_RE = re.compile(
    r"(?:os\.system|subprocess\.(?:run|popen|call)|powershell(?:\.exe)?|cmd\.exe|/bin/sh|bash\s+-c|curl\s+|wget\s+|netcat|nc\s+)",
    re.IGNORECASE,
)
_NETWORK_REFERENCE_RE = re.compile(
    r"(?:https?://|ftp://|tcp://|udp://|socket\b|\b(?:\d{1,3}\.){3}\d{1,3}\b)",
    re.IGNORECASE,
)
_EVAL_EXEC_RE = re.compile(r"(?:eval\(|exec\(|os\.system|subprocess\.)", re.IGNORECASE)
_BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")
_DECODE_CONTEXT_RE = re.compile(r"(?:base64|b64decode|frombase64string|decode\(|atob\()", re.IGNORECASE)

_KNOWN_SAFE_METADATA_KEYS = frozenset(
    {
        "version",
        "uid",
        "name",
        "type",
        "inputs",
        "outputs",
        "attributes",
        "shape",
        "parameter",
        "constant",
        "placeholder",
        "primitive_functions",
        "compositefunction",
        "times",
        "plus",
        "relu",
        "convolution",
        "batchnormalization",
        "labelnodes",
        "featurenodes",
        "outputnodes",
        "criterionnodes",
    }
)


def _read_prefix(path: str, limit: int = _MAX_SIGNATURE_BYTES) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _read_bounded(path: str, limit: int) -> tuple[bytes, bool]:
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    return (data[:limit], len(data) > limit)


def _has_cntkv2_core_markers(prefix: bytes) -> bool:
    return all(marker in prefix for marker in _CNTK_V2_REQUIRED_MARKERS)


def _has_cntkv2_structure_markers(prefix: bytes) -> bool:
    return any(marker in prefix for marker in _CNTK_V2_STRUCTURE_MARKERS)


def _detect_cntk_variant(prefix: bytes, extension: str) -> tuple[str, str]:
    if extension not in _CNTK_CANDIDATE_EXTENSIONS:
        return "not_cntk", "extension_not_cntk_candidate"

    if prefix.startswith(_CNTK_LEGACY_MAGIC):
        if _CNTK_LEGACY_VERSION_MARKER in prefix:
            return "legacy_v1", "legacy_bcn_and_bversion_markers"
        return "unsupported_cntk_variant", "legacy_marker_without_bversion_marker"

    if _has_cntkv2_core_markers(prefix):
        if extension == ".model":
            return "unsupported_cntk_variant", "cntkv2_model_extension_deferred_v1"
        if _has_cntkv2_structure_markers(prefix):
            return "cntk_v2", "protobuf_core_and_structure_markers"
        return "unsupported_cntk_variant", "protobuf_core_markers_without_structure_markers"

    return "not_cntk", "no_cntk_markers_detected"


def _extract_candidate_strings(data: bytes) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    for match in _ASCII_STRING_RE.finditer(data):
        text = match.group(0).decode("utf-8", "ignore").strip()
        if text and text not in seen:
            seen.add(text)
            candidates.append(text)
            if len(candidates) >= _MAX_EXTRACTED_STRINGS:
                return candidates

    for match in _UTF16LE_STRING_RE.finditer(data):
        raw = match.group(0)
        text = raw[::2].decode("ascii", "ignore").strip()
        if text and text not in seen:
            seen.add(text)
            candidates.append(text)
            if len(candidates) >= _MAX_EXTRACTED_STRINGS:
                break

    return candidates


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _snippet(text: str, max_length: int = 180) -> str:
    normalized = _normalize(text)
    if len(normalized) <= max_length:
        return normalized
    return normalized[: max_length - 3] + "..."


def _is_known_safe_metadata_entry(text: str) -> bool:
    lowered = text.lower().strip()
    if lowered in _KNOWN_SAFE_METADATA_KEYS:
        return True
    return bool(re.fullmatch(r"(?:parameter|placeholder|times|plus|compositefunction)\d+", lowered))


def _has_external_load_reference(text: str) -> bool:
    return bool(_PATH_OR_LIBRARY_RE.search(text) and _LOAD_CONTEXT_RE.search(text))


def _has_command_network_execution(text: str) -> bool:
    if not _COMMAND_CONTEXT_RE.search(text):
        return False
    return bool(_NETWORK_REFERENCE_RE.search(text) or _EVAL_EXEC_RE.search(text))


def _has_obfuscated_payload_indicator(text: str) -> bool:
    if not _BASE64_BLOB_RE.search(text):
        return False
    return bool(_DECODE_CONTEXT_RE.search(text) or _EVAL_EXEC_RE.search(text) or _COMMAND_CONTEXT_RE.search(text))


def _collect_security_evidence(strings: list[str]) -> dict[str, list[str]]:
    evidence: dict[str, list[str]] = {
        "external_load_reference": [],
        "command_network_execution": [],
        "obfuscated_payload_indicator": [],
    }

    for text in strings:
        if _is_known_safe_metadata_entry(text):
            continue

        if _has_external_load_reference(text) and len(evidence["external_load_reference"]) < _MAX_EVIDENCE_PER_CATEGORY:
            evidence["external_load_reference"].append(_snippet(text))
        if (
            _has_command_network_execution(text)
            and len(evidence["command_network_execution"]) < _MAX_EVIDENCE_PER_CATEGORY
        ):
            evidence["command_network_execution"].append(_snippet(text))
        if (
            _has_obfuscated_payload_indicator(text)
            and len(evidence["obfuscated_payload_indicator"]) < _MAX_EVIDENCE_PER_CATEGORY
        ):
            evidence["obfuscated_payload_indicator"].append(_snippet(text))

    return evidence


class CntkScanner(BaseScanner):
    """Scanner for CNTK model files with strict format detection."""

    name = "cntk"
    description = "Scans CNTK .dnn/.cmf model artifacts for load-time execution indicators"
    supported_extensions: ClassVar[list[str]] = [".dnn", ".cmf"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        extension = os.path.splitext(path)[1].lower()
        if extension not in _CNTK_SUPPORTED_EXTENSIONS:
            return False

        prefix = _read_prefix(path)
        variant, _reason = _detect_cntk_variant(prefix, extension)
        return variant in {"legacy_v1", "cntk_v2"}

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        result.metadata["file_size"] = self.get_file_size(path)
        result.metadata["scan_byte_limit"] = _MAX_SCAN_BYTES
        result.metadata["discovery_assumptions"] = DISCOVERY_ASSUMPTIONS

        extension = os.path.splitext(path)[1].lower()
        signature_prefix = _read_prefix(path)
        variant, variant_reason = _detect_cntk_variant(signature_prefix, extension)
        result.metadata["cntk_variant"] = variant
        result.metadata["variant_reason"] = variant_reason
        result.metadata["signature_prefix_bytes"] = min(len(signature_prefix), _MAX_SIGNATURE_BYTES)

        if variant not in {"legacy_v1", "cntk_v2"}:
            result.add_check(
                name="CNTK Variant Support",
                passed=False,
                message=(
                    "Unsupported or out-of-scope CNTK variant detected. "
                    "Current scanner supports only signature-backed .dnn/.cmf variants."
                ),
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "variant": variant,
                    "reason": variant_reason,
                    "supported_extensions": sorted(_CNTK_SUPPORTED_EXTENSIONS),
                },
            )
            result.finish(success=False)
            return result

        try:
            data, truncated = _read_bounded(path, _MAX_SCAN_BYTES)
        except OSError as e:
            result.add_check(
                name="CNTK File Read",
                passed=False,
                message=f"Error reading CNTK file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.bytes_scanned = len(data)
        result.metadata["scan_truncated"] = truncated

        if (variant == "legacy_v1" and len(data) < 32) or (variant == "cntk_v2" and len(data) < 24):
            result.add_check(
                name="CNTK Structural Integrity",
                passed=False,
                message="CNTK file appears truncated or structurally incomplete",
                severity=IssueSeverity.INFO,
                location=path,
                details={"variant": variant, "bytes_scanned": len(data)},
            )
            result.finish(success=False)
            return result

        extracted_strings = _extract_candidate_strings(data)
        result.metadata["extracted_string_count"] = len(extracted_strings)
        evidence = _collect_security_evidence(extracted_strings)

        signal_count = sum(1 for snippets in evidence.values() if snippets)
        if signal_count == 0:
            result.add_check(
                name="CNTK Static Security Analysis",
                passed=True,
                message="No suspicious load-time execution indicators found in CNTK strings",
                location=path,
                details={"variant": variant},
            )
            result.finish(success=True)
            return result

        category_messages = {
            "external_load_reference": "External library/path reference in executable load context",
            "command_network_execution": "Command/network execution string found in metadata content",
            "obfuscated_payload_indicator": "Encoded payload indicator with decode/exec context found",
        }

        for category, snippets in evidence.items():
            if not snippets:
                continue
            result.add_check(
                name="CNTK Suspicious Content Detection",
                passed=False,
                message=category_messages[category],
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "category": category,
                    "variant": variant,
                    "examples": snippets,
                },
            )

        if signal_count >= 2:
            result.add_check(
                name="CNTK Multi-Signal Correlation",
                passed=False,
                message="Multiple independent suspicious signals detected in CNTK executable-capable fields",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "variant": variant,
                    "signals": sorted([category for category, snippets in evidence.items() if snippets]),
                },
            )

        result.finish(success=not result.has_errors)
        return result
