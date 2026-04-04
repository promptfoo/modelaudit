"""OpenVINO IR scanner for security vulnerabilities."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from io import BytesIO
from typing import Any, ClassVar

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


def _local_tag_name(tag: str) -> str:
    """Return an XML tag's namespace-stripped local name."""
    return tag.rsplit("}", 1)[-1].lower()


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
            next_index = _skip_doctype_declaration(xml_prefix, index)
            if next_index is None:
                return False
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


class OpenVinoScanner(BaseScanner):
    """Scanner for OpenVINO IR (.xml/.bin) model files."""

    name = "openvino"
    description = "Scans OpenVINO IR models for suspicious layers and external references"
    supported_extensions: ClassVar[list[str]] = [".xml"]
    CAN_HANDLE_MAX_PARSE_BYTES: ClassVar[int] = 1024 * 1024

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
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check_result = self._check_size_limit(path)
        if size_check_result:
            return size_check_result

        result = self._create_result()
        result.metadata["xml_size"] = self.get_file_size(path)

        bin_path = os.path.splitext(path)[0] + ".bin"
        if os.path.isfile(bin_path):
            result.metadata["bin_size"] = self.get_file_size(bin_path)
        else:
            result.add_check(
                name="OpenVINO Weights File Check",
                passed=False,
                message="Associated .bin weights file not found",
                severity=IssueSeverity.INFO,
                location=bin_path,
                details={"expected_file": bin_path},
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

        for layer in root.findall(".//layer"):
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
                if attr_name in {"library", "implementation"}:
                    result.add_check(
                        name="External Library Reference Check",
                        passed=False,
                        message=f"Layer '{layer_name}' references external library '{attr_val}'",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "layer_name": layer_name,
                            "attribute": attr_name,
                            "element": element_tag,
                            "library": attr_val,
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
                            "value": attr_val,
                        },
                        rule_code="S902",
                    )

        result.finish(success=not result.has_errors)
        return result
