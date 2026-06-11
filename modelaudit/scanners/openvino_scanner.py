"""OpenVINO IR scanner for security vulnerabilities."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit

from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_STRING_PATTERNS

from .base import BaseScanner, IssueSeverity, ScanResult

try:
    from defusedxml import ElementTree as DefusedET

    HAS_DEFUSEDXML = True
except ImportError:  # pragma: no cover - optional dependency
    import xml.etree.ElementTree as DefusedET

    HAS_DEFUSEDXML = False


_OPENVINO_ROOT_TAGS = frozenset({"model", "net"})
_OPENVINO_SUSPICIOUS_STRING_PATTERNS = [
    r"\bimportlib\b" if pattern == r"importlib" else pattern
    for pattern in SUSPICIOUS_STRING_PATTERNS
    if pattern != r"__[\w]+__"
]
_OPENVINO_SUSPICIOUS_PATTERN = (
    re.compile("|".join(_OPENVINO_SUSPICIOUS_STRING_PATTERNS), re.IGNORECASE)
    if _OPENVINO_SUSPICIOUS_STRING_PATTERNS
    else None
)
_OPENVINO_NATIVE_LIBRARY_SUFFIX = re.compile(r"(?:\.so(?:\.\d+)*|\.dll|\.dylib|\.lib)$", re.IGNORECASE)
_URL_REFERENCE_PATTERN = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.IGNORECASE)


def _local_tag_name(tag: str) -> str:
    """Return an XML tag's namespace-stripped local name."""
    return tag.rsplit("}", 1)[-1].lower()


def _is_contained_in(child: Path, parent: Path) -> bool:
    """Return True when child resolves under parent directory."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _skip_doctype_declaration(xml_prefix: bytes, start_offset: int) -> int | None:
    """Skip a DOCTYPE declaration without expanding entities."""
    index = start_offset + len(b"<!DOCTYPE")
    bracket_depth = 0
    quote_char: int | None = None

    while index < len(xml_prefix):
        byte = xml_prefix[index]
        if quote_char is not None:
            if byte == quote_char:
                quote_char = None
        elif byte in {ord("'"), ord('"')}:
            quote_char = byte
        elif byte == ord("["):
            bracket_depth += 1
        elif byte == ord("]") and bracket_depth > 0:
            bracket_depth -= 1
        elif byte == ord(">") and bracket_depth == 0:
            return index + 1
        index += 1

    return None


def _get_doctype_root_tag(xml_prefix: bytes, start_offset: int) -> str | None:
    """Return the root element name declared by a DOCTYPE declaration."""
    index = start_offset + len(b"<!DOCTYPE")
    prefix_length = len(xml_prefix)
    while index < prefix_length and chr(xml_prefix[index]).isspace():
        index += 1

    name_start = index
    while index < prefix_length and xml_prefix[index : index + 1] not in b" \t\r\n\f[>":
        index += 1

    if index == name_start:
        return None
    return _local_tag_name(xml_prefix[name_start:index].decode("utf-8", "ignore"))


def _looks_like_openvino_xml_prefix(xml_prefix: bytes) -> bool:
    """Sniff the first root element without relying on entity-expanding XML parsing."""
    index = 3 if xml_prefix.startswith(b"\xef\xbb\xbf") else 0
    prefix_length = len(xml_prefix)

    while index < prefix_length:
        while index < prefix_length and chr(xml_prefix[index]).isspace():
            index += 1

        if xml_prefix.startswith(b"<?", index):
            end_offset = xml_prefix.find(b"?>", index + 2)
            if end_offset == -1:
                return False
            index = end_offset + 2
            continue

        if xml_prefix.startswith(b"<!--", index):
            end_offset = xml_prefix.find(b"-->", index + 4)
            if end_offset == -1:
                return False
            index = end_offset + 3
            continue

        if xml_prefix[index : index + len(b"<!DOCTYPE")].upper() == b"<!DOCTYPE":
            doctype_root_tag = _get_doctype_root_tag(xml_prefix, index)
            next_index = _skip_doctype_declaration(xml_prefix, index)
            if next_index is None:
                return doctype_root_tag in _OPENVINO_ROOT_TAGS
            index = next_index
            continue

        break

    if index >= prefix_length or xml_prefix[index : index + 1] != b"<":
        return False
    if xml_prefix[index + 1 : index + 2] in {b"/", b"!", b"?"}:
        return False

    tag_end = index + 1
    while tag_end < prefix_length and xml_prefix[tag_end : tag_end + 1] not in b" \t\r\n\f/>":
        tag_end += 1
    if tag_end == index + 1:
        return False

    root_tag = xml_prefix[index + 1 : tag_end].decode("utf-8", "ignore")
    return _local_tag_name(root_tag) in _OPENVINO_ROOT_TAGS


def _iter_element_attributes(layer: Any) -> Iterator[tuple[str, str, str]]:
    """Yield normalized attributes from a layer and its nested config nodes."""
    for element in layer.iter():
        element_tag = _local_tag_name(str(element.tag))
        for attr_name, attr_value in element.attrib.items():
            normalized_value = str(attr_value).strip()
            if normalized_value:
                yield element_tag, attr_name.strip().lower(), normalized_value


def _is_likely_external_library_reference(value: str) -> bool:
    """Return True for native-library filenames or path-like OpenVINO plugin references."""
    normalized_value = value.strip().strip("\"'")
    if not normalized_value:
        return False

    if _OPENVINO_NATIVE_LIBRARY_SUFFIX.search(normalized_value):
        return True

    return "/" in normalized_value or "\\" in normalized_value


def _redact_url_reference(value: str) -> str:
    """Redact URL credentials, query strings, and fragments from scanner evidence."""

    def replace_url(match: re.Match[str]) -> str:
        raw_url = match.group(0)
        try:
            parts = urlsplit(raw_url)
        except ValueError:
            return "<url redacted>"

        if not parts.scheme:
            return raw_url

        netloc = parts.hostname or ""
        if parts.port is not None:
            netloc = f"{netloc}:{parts.port}"

        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))

    return _URL_REFERENCE_PATTERN.sub(replace_url, value)


def openvino_xml_companion_for_weights(path: str | os.PathLike[str]) -> Path | None:
    """Return the owning OpenVINO XML path for a same-stem weights sidecar."""
    weights_path = Path(path)
    if weights_path.suffix.lower() != ".bin":
        return None

    xml_path = weights_path.with_suffix(".xml")
    if not xml_path.is_file():
        return None
    if not OpenVinoScanner.can_handle(str(xml_path)):
        return None
    return xml_path


class OpenVinoScanner(BaseScanner):
    """Scanner for OpenVINO IR (.xml/.bin) model files."""

    name = "openvino"
    description = "Scans OpenVINO IR models for suspicious layers and external references"
    supported_extensions: ClassVar[list[str]] = [".xml"]
    CAN_HANDLE_MAX_PARSE_BYTES: ClassVar[int] = 1024 * 1024

    def _record_bin_size(self, result: ScanResult, bin_path: Path) -> None:
        bin_size = self.get_file_size(str(bin_path))
        result.metadata["bin_size"] = bin_size

        configured_limit = self.config.get("max_file_size", 0)
        max_file_size = configured_limit if isinstance(configured_limit, int) and configured_limit > 0 else 0
        if max_file_size and bin_size > max_file_size:
            reason = "openvino_weights_file_size_exceeded"
            result.metadata["operational_error"] = True
            result.metadata["operational_error_reason"] = reason
            result.metadata["analysis_incomplete"] = True
            result.metadata["scan_outcome"] = "inconclusive"
            result.metadata["scan_outcome_reason"] = reason
            result.metadata["scan_outcome_reasons"] = [reason]
            result.add_check(
                name="OpenVINO Weights File Size Limit",
                passed=False,
                message=f"Associated .bin weights file too large to scan: {bin_size} bytes (max: {max_file_size})",
                severity=IssueSeverity.INFO,
                location=str(bin_path),
                details={
                    "file_size": bin_size,
                    "max_file_size": max_file_size,
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": reason,
                },
            )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        if os.path.splitext(path)[1].lower() != ".xml":
            return False

        try:
            with open(path, "rb") as xml_file:
                xml_prefix = xml_file.read(cls.CAN_HANDLE_MAX_PARSE_BYTES)
                try:
                    for _event, element in DefusedET.iterparse(BytesIO(xml_prefix), events=("start",)):
                        return _local_tag_name(str(element.tag)) in _OPENVINO_ROOT_TAGS
                except Exception:
                    return _looks_like_openvino_xml_prefix(xml_prefix)
        except Exception:
            return False

        return False

    def scan(self, path: str) -> ScanResult:
        result = self._create_scan_result_after_preflight(path)
        if not result.success:
            return result

        result.metadata["xml_size"] = self.get_file_size(path)

        model_dir = Path(path).resolve().parent
        bin_path = Path(os.path.splitext(path)[0] + ".bin")
        if bin_path.is_symlink():
            resolved_bin_path = bin_path.resolve(strict=False)
            if not _is_contained_in(resolved_bin_path, model_dir):
                result.add_check(
                    name="OpenVINO Weights Symlink Boundary Check",
                    passed=False,
                    message="Associated .bin weights file resolves outside the model directory",
                    severity=IssueSeverity.CRITICAL,
                    location=str(bin_path),
                    details={
                        "expected_file": str(bin_path),
                        "resolved_path": str(resolved_bin_path),
                        "model_directory": str(model_dir),
                        "cwe": "CWE-22",
                    },
                    rule_code="S701",
                    why=(
                        "OpenVINO sidecar weights are loaded from the .bin file adjacent to the XML. "
                        "A symlinked sidecar can make model loading read data outside the model directory."
                    ),
                )
            elif bin_path.is_file():
                self._record_bin_size(result, bin_path)
        elif bin_path.is_file():
            self._record_bin_size(result, bin_path)
        else:
            result.add_check(
                name="OpenVINO Weights File Check",
                passed=False,
                message="Associated .bin weights file not found",
                severity=IssueSeverity.INFO,
                location=str(bin_path),
                details={"expected_file": str(bin_path)},
                rule_code="S701",
            )

        try:
            tree = DefusedET.parse(path)
            root = tree.getroot()
        except Exception as e:  # pragma: no cover - parse errors
            result.metadata["operational_error"] = True
            result.metadata["operational_error_reason"] = "openvino_xml_parse_failed"
            result.add_check(
                name="OpenVINO XML Parse",
                passed=False,
                message=f"Invalid OpenVINO XML: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        version = root.attrib.get("version") or root.attrib.get("ir_version")
        if version:
            result.metadata["ir_version"] = version

        for layer in (element for element in root.iter() if _local_tag_name(str(element.tag)) == "layer"):
            layer_type = layer.attrib.get("type", "").strip().lower()
            layer_name = layer.attrib.get("name", "")
            if layer_type in {"python", "custom"}:
                result.add_check(
                    name="Suspicious Layer Type Detection",
                    passed=False,
                    message=f"OpenVINO model uses {layer_type} layer '{layer_name}'",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"layer_type": layer_type, "layer_name": layer_name},
                    rule_code="S902",
                )

            for element_tag, attr_name, attr_val in _iter_element_attributes(layer):
                loggable_attr_val = _redact_url_reference(attr_val)
                if attr_name in {"library", "implementation"} and _is_likely_external_library_reference(attr_val):
                    result.add_check(
                        name="External Library Reference Check",
                        passed=False,
                        message=f"Layer '{layer_name}' references external library '{loggable_attr_val}'",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "layer_name": layer_name,
                            "attribute": attr_name,
                            "element": element_tag,
                            "library": loggable_attr_val,
                        },
                        rule_code="S902",
                    )

                if _OPENVINO_SUSPICIOUS_PATTERN and _OPENVINO_SUSPICIOUS_PATTERN.search(attr_val):
                    result.add_check(
                        name="Layer Attribute Security Check",
                        passed=False,
                        message="Suspicious content in layer attributes",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "layer_name": layer_name,
                            "attribute": attr_name,
                            "element": element_tag,
                            "value": loggable_attr_val,
                        },
                        rule_code="S902",
                    )

        result.finish(success=not result.has_errors)
        return result
