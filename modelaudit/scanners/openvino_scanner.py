"""OpenVINO IR scanner for security vulnerabilities."""

from __future__ import annotations

import os
import re
from typing import ClassVar

from modelaudit.suspicious_symbols import SUSPICIOUS_STRING_PATTERNS

from .base import BaseScanner, IssueSeverity, ScanResult

try:
    from defusedxml import ElementTree as DefusedET

    HAS_DEFUSEDXML = True
except ImportError:  # pragma: no cover - optional dependency
    import xml.etree.ElementTree as DefusedET

    HAS_DEFUSEDXML = False


class OpenVinoScanner(BaseScanner):
    """Scanner for OpenVINO IR (.xml/.bin) model files."""

    name = "openvino"
    description = "Scans OpenVINO IR models for suspicious layers and external references"
    supported_extensions: ClassVar[list[str]] = [".xml"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        if os.path.splitext(path)[1].lower() != ".xml":
            return False
        try:
            with open(path, "rb") as f:
                head = f.read(256).lower()
            return b"<net" in head or b"<model" in head
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

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
                severity=IssueSeverity.WARNING,
                location=bin_path,
                details={"expected_file": bin_path},
            )

        try:
            tree = DefusedET.parse(path)
            root = tree.getroot()
        except Exception as e:  # pragma: no cover - parse errors
            result.add_check(
                name="OpenVINO XML Parse",
                passed=False,
                message=f"Invalid OpenVINO XML: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        version = root.attrib.get("version") or root.attrib.get("ir_version")
        if version:
            result.metadata["ir_version"] = version

        suspicious_pattern = re.compile("|".join(SUSPICIOUS_STRING_PATTERNS), re.IGNORECASE)

        for layer in root.findall(".//layer"):
            layer_type = layer.attrib.get("type", "").lower()
            layer_name = layer.attrib.get("name", "")
            if layer_type in {"python", "custom"}:
                result.add_check(
                    name="Suspicious Layer Type Detection",
                    passed=False,
                    message=f"OpenVINO model uses {layer_type} layer '{layer_name}'",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"layer_type": layer_type, "layer_name": layer_name},
                )
            library = layer.attrib.get("library")
            if library:
                result.add_check(
                    name="External Library Reference Check",
                    passed=False,
                    message=f"Layer '{layer_name}' references external library '{library}'",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"layer_name": layer_name, "library": library},
                )
            for attr_val in layer.attrib.values():
                if suspicious_pattern.search(str(attr_val)):
                    result.add_check(
                        name="Layer Attribute Security Check",
                        passed=False,
                        message="Suspicious content in layer attributes",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"attribute": attr_val},
                    )

        result.finish(success=not result.has_errors)
        return result
