import os
import re
from typing import ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

try:
    from defusedxml import ElementTree as DefusedET

    HAS_DEFUSEDXML = True
except ImportError:  # pragma: no cover - defusedxml may not be installed
    HAS_DEFUSEDXML = False
    DefusedET = None

# Only import unsafe XML as fallback
if not HAS_DEFUSEDXML:
    import xml.etree.ElementTree as UnsafeET


SUSPICIOUS_PATTERNS = [
    r"<script",
    r"exec\(",
    r"eval\(",
    r"import\s+os",
    r"subprocess",
    r"__import__",
    r"system\(",
]
URL_PATTERNS = ["http://", "https://", "file://", "ftp://"]
DANGEROUS_ENTITIES = ["<!DOCTYPE", "<!ENTITY", "<!ELEMENT", "<!ATTLIST"]


class PmmlScanner(BaseScanner):
    """Scanner for PMML model files.

    This scanner performs security checks on PMML (Predictive Model Markup Language) files
    to detect potential XML External Entity (XXE) attacks, malicious scripts, and suspicious
    external references.

    Security features:
    - Uses defusedxml for safe XML parsing when available
    - Detects DOCTYPE and ENTITY declarations that could enable XXE attacks
    - Scans for suspicious patterns in Extension elements
    - Identifies external resource references
    - Validates PMML structure and version
    """

    name = "pmml"
    description = "Scans PMML files for XML security issues and suspicious content"
    supported_extensions: ClassVar[list[str]] = [".pmml"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            return True
        try:
            with open(path, "rb") as f:
                head = f.read(512)  # Increased from 256 for better detection
            return b"<PMML" in head or b"<pmml" in head
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        result.metadata["has_defusedxml"] = HAS_DEFUSEDXML

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            with open(path, "rb") as f:
                data = f.read()
            result.bytes_scanned = len(data)
        except Exception as e:  # pragma: no cover - unexpected read errors
            result.add_check(
                name="PMML File Read",
                passed=False,
                message=f"Error reading file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = data.decode("utf-8", errors="replace")
                result.add_check(
                    name="PMML UTF-8 Encoding Check",
                    passed=False,
                    message="Non UTF-8 characters in PMML file",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    why="PMML files should be valid UTF-8 encoded XML. Non-UTF-8 characters may indicate "
                    "corruption or malicious content.",
                )
            except Exception as e:
                result.add_check(
                    name="PMML Text Decoding",
                    passed=False,
                    message=f"Failed to decode file as text: {e}",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"exception": str(e), "exception_type": type(e).__name__},
                )
                result.finish(success=False)
                return result

        # Check for dangerous XML constructs before parsing
        self._check_dangerous_xml_constructs(text, result, path)

        # Parse XML using safe parser when available
        try:
            if HAS_DEFUSEDXML:
                root = DefusedET.fromstring(text)
            else:
                # Warn about using unsafe parser
                result.add_check(
                    name="XML Parser Security Check",
                    passed=False,
                    message="Using unsafe XML parser - defusedxml not available",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    why="defusedxml is not installed. The standard XML parser may be vulnerable to XXE attacks. "
                    "Install defusedxml for better security.",
                )
                root = UnsafeET.fromstring(text)
        except Exception as e:
            result.add_check(
                name="XML Parse Validation",
                passed=False,
                message=f"Malformed XML: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
                why=(
                    "The file contains malformed XML that cannot be parsed. This may indicate corruption "
                    "or malicious content."
                ),
            )
            result.finish(success=False)
            return result

        # Validate PMML structure
        self._validate_pmml_structure(root, result, path)

        # Check for suspicious content in the parsed XML
        self._check_suspicious_content(root, result, path)

        result.finish(success=True)
        return result

    def _check_dangerous_xml_constructs(
        self,
        text: str,
        result: ScanResult,
        path: str,
    ) -> None:
        """Check for dangerous XML constructs that could enable XXE attacks."""
        text_upper = text.upper()

        for construct in DANGEROUS_ENTITIES:
            if construct in text_upper:
                result.add_check(
                    name="XXE Attack Vector Check",
                    passed=False,
                    message=f"PMML file contains {construct} declaration",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"construct": construct},
                    why=f"{construct} declarations can enable XML External Entity (XXE) attacks, "
                    "allowing attackers to read local files, perform SSRF attacks, or cause denial of service.",
                )

    def _validate_pmml_structure(self, root, result: ScanResult, path: str) -> None:
        """Validate basic PMML structure and extract metadata."""
        if root.tag.lower() != "pmml":
            result.add_check(
                name="PMML Root Element Validation",
                passed=False,
                message="Root element is not <PMML>",
                severity=IssueSeverity.WARNING,
                location=path,
                why="Valid PMML files should have <PMML> as the root element.",
            )
        else:
            version = root.attrib.get("version", "")
            result.metadata["pmml_version"] = version
            if not version:
                result.add_check(
                    name="PMML Version Check",
                    passed=False,
                    message="PMML missing version attribute",
                    severity=IssueSeverity.INFO,
                    location=path,
                    why="PMML files should specify a version for compatibility.",
                )

    def _check_suspicious_content(self, root, result: ScanResult, path: str) -> None:
        """Check for suspicious patterns and external references in PMML content."""
        for elem in root.iter():
            # Combine element text content with attributes for comprehensive scanning
            elem_text = elem.text or ""
            attr_text = " ".join(f"{k}={v}" for k, v in elem.attrib.items())

            # For Extension elements, also include all child element text content and names
            if elem.tag.lower() == "extension":
                # Get all text content recursively
                all_text = self._get_all_text_content(elem)
                combined = f"{elem_text} {attr_text} {all_text}".lower()
            else:
                combined = f"{elem_text} {attr_text}".lower()

            # Check for external resource references
            for url_pattern in URL_PATTERNS:
                if url_pattern in combined:
                    result.add_check(
                        name="External Resource Reference Check",
                        passed=False,
                        message=f"PMML references external resource: {url_pattern}",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"tag": elem.tag, "url_pattern": url_pattern},
                        why=(
                            "External references in PMML files may be used to exfiltrate data or perform "
                            "network requests."
                        ),
                    )
                    break

            # Check for suspicious element names (like <script>)
            if elem.tag.lower() in ["script", "javascript", "python", "exec", "eval"]:
                result.add_check(
                    name="Suspicious XML Element Check",
                    passed=False,
                    message=f"Suspicious XML element found: <{elem.tag}>",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"tag": elem.tag},
                    why="Suspicious XML elements may contain executable code or scripts.",
                )

            # Special attention to Extension elements which can contain arbitrary content
            if elem.tag.lower() == "extension":
                for pattern in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, combined, re.IGNORECASE):
                        result.add_check(
                            name="Extension Element Security Check",
                            passed=False,
                            message="Suspicious content in <Extension> element",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={"tag": elem.tag, "pattern": pattern},
                            why=(
                                "Extension elements can contain arbitrary content and may be used to embed "
                                "malicious code or scripts."
                            ),
                        )
                        break

    def _get_all_text_content(self, element) -> str:
        """Recursively get all text content from an element and its children."""
        text_parts = []

        # Add element name as it might be suspicious (e.g., <script>)
        text_parts.append(element.tag)

        # Add element text
        if element.text:
            text_parts.append(element.text.strip())

        # Add tail text (text after the element)
        if element.tail:
            text_parts.append(element.tail.strip())

        # Recursively process children
        for child in element:
            text_parts.append(self._get_all_text_content(child))

        return " ".join(filter(None, text_parts))
