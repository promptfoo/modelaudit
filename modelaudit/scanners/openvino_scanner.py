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
                for _event, element in DefusedET.iterparse(BytesIO(xml_prefix), events=("start",)):
                    return _local_tag_name(str(element.tag)) in _OPENVINO_ROOT_TAGS
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
