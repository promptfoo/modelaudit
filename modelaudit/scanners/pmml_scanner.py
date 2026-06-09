"""Scanner for PMML model definition files (.pmml)."""

import os
import re
from typing import TYPE_CHECKING, Any, ClassVar

from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from .base import BaseScanner, IssueSeverity, ScanResult

try:
    from defusedxml import ElementTree as DefusedET

    HAS_DEFUSEDXML = True
except ImportError:  # pragma: no cover - defusedxml may not be installed
    HAS_DEFUSEDXML = False
    if TYPE_CHECKING:
        from defusedxml import ElementTree as DefusedET  # type: ignore[no-redef]
    else:
        DefusedET = None  # type: ignore[assignment]

# Only import unsafe XML as fallback
if not HAS_DEFUSEDXML:
    import xml.etree.ElementTree as UnsafeET


SUSPICIOUS_PATTERNS = [
    r"<script",
    r"exec\s*\(",
    r"eval\s*\(",
    r"import\s+os",
    r"\b(?:importlib\s*\.\s*)?import_module\s*\(\s*['\"]subprocess['\"]\s*\)",
    r"\b(?:from\s+subprocess\s+import|import\s+subprocess)\b",
    r"\bsubprocess\s*\.\s*(?:popen|run|call|check_call|check_output|getoutput|getstatusoutput)\s*\(",
    r"__import__",
    r"\bsystem\s*\(",
]
_COMPILED_SUSPICIOUS_PATTERNS = tuple((pattern, re.compile(pattern)) for pattern in SUSPICIOUS_PATTERNS)
URL_PATTERNS = ["http://", "https://", "file://", "ftp://"]
BENIGN_DOCUMENTATION_URL_PATTERNS = frozenset({"http://", "https://"})
DANGEROUS_ENTITIES = ["<!DOCTYPE", "<!ENTITY", "<!ELEMENT", "<!ATTLIST"]
XML_COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL)
XML_CDATA_PATTERN = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
SUSPICIOUS_ELEMENT_NAMES = frozenset({"script", "javascript", "python", "exec", "eval"})
DOCUMENTATION_ELEMENT_NAMES = frozenset({"annotation", "copyright", "description", "documentation"})
DOCUMENTATION_ATTRIBUTE_NAMES = frozenset({"description", "documentation", "label"})
PMML_NAMESPACE_PATTERN = re.compile(r"^https?://(?:www\.)?dmg\.org/PMML-\d+(?:_\d+)*$")
EXTERNAL_RESOURCE_ATTRIBUTE_NAMES = frozenset(
    {
        "file",
        "filename",
        "href",
        "location",
        "nonamespaceschemalocation",
        "path",
        "schemalocation",
        "source",
        "src",
        "uri",
        "url",
    },
)


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
    MAX_EXTENSION_TEXT_NODES: ClassVar[int] = 20000
    FILE_READ_INCOMPLETE_REASON: ClassVar[str] = "pmml_file_read_failed"
    EXTENSION_TRAVERSAL_INCOMPLETE_REASON: ClassVar[str] = "pmml_extension_traversal_limit_exceeded"
    XML_PARSE_INCOMPLETE_REASON: ClassVar[str] = "pmml_xml_parse_failed"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        pmml_config = dict(config or {})
        max_file_size = pmml_config.get("max_file_size")
        if (
            "max_file_read_size" not in pmml_config
            and isinstance(max_file_size, int)
            and not isinstance(max_file_size, bool)
            and max_file_size > 0
        ):
            pmml_config["max_file_read_size"] = min(max_file_size, self.default_max_file_read_size)
        super().__init__(config=pmml_config)

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

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

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
        except Exception as e:
            mark_inconclusive_scan_result(result, self.FILE_READ_INCOMPLETE_REASON)
            result.add_check(
                name="PMML File Read",
                passed=False,
                message=f"Error reading file: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self.FILE_READ_INCOMPLETE_REASON,
                },
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
                    rule_code="S902",
                )
            except Exception as e:
                result.add_check(
                    name="PMML Text Decoding",
                    passed=False,
                    message=f"Failed to decode file as text: {e}",
                    severity=IssueSeverity.INFO,
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
                    rule_code="S902",
                )
                root = UnsafeET.fromstring(text)
        except Exception as e:
            mark_inconclusive_scan_result(result, self.XML_PARSE_INCOMPLETE_REASON)
            result.add_check(
                name="XML Parse Validation",
                passed=False,
                message=f"Malformed XML: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self.XML_PARSE_INCOMPLETE_REASON,
                },
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

        result.finish(
            success=not result.has_errors and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        )
        return result

    def _check_dangerous_xml_constructs(
        self,
        text: str,
        result: ScanResult,
        path: str,
    ) -> None:
        """Check for dangerous XML constructs that could enable XXE attacks."""
        scrubbed_text = XML_COMMENT_PATTERN.sub("", text)
        scrubbed_text = XML_CDATA_PATTERN.sub("", scrubbed_text)
        text_upper = scrubbed_text.upper()

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
                    rule_code="S902",
                )

    def _validate_pmml_structure(self, root: Any, result: ScanResult, path: str) -> None:
        """Validate basic PMML structure and extract metadata."""
        # Extract local tag name (without namespace)
        # Tags can be "{http://namespace}PMML" or just "PMML"
        tag_name = self._local_xml_name(root.tag)

        if tag_name != "pmml":
            result.add_check(
                name="PMML Root Element Validation",
                passed=False,
                message="Root element is not <PMML>",
                severity=IssueSeverity.WARNING,
                location=path,
                why="Valid PMML files should have <PMML> as the root element.",
                rule_code="S902",
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
                    rule_code="S902",
                )

    def _check_suspicious_content(self, root: Any, result: ScanResult, path: str) -> None:
        """Check for suspicious patterns and external references in PMML content."""
        parent_by_child = {child: parent for parent in root.iter() for child in parent}
        root_namespace = self._xml_namespace(root.tag)
        root_is_pmml = self._is_pmml_root(root.tag, root_namespace)
        for elem in root.iter():
            tag_name = self._local_xml_name(elem.tag)
            is_pmml_element = self._is_pmml_element(elem.tag, root_namespace, root_is_pmml=root_is_pmml)
            parent = parent_by_child.get(elem)
            parent_tag_name = self._local_xml_name(parent.tag) if parent is not None else ""
            parent_is_pmml_element = parent is not None and self._is_pmml_element(
                parent.tag,
                root_namespace,
                root_is_pmml=root_is_pmml,
            )
            in_header_metadata = (is_pmml_element and tag_name == "header") or (
                is_pmml_element and parent_is_pmml_element and tag_name == "application" and parent_tag_name == "header"
            )

            # Combine element text content with attributes for comprehensive scanning
            elem_text = elem.text or ""
            attr_text = " ".join(f"{k}={v}" for k, v in elem.attrib.items())

            # For Extension elements, also include all child element text content and names
            if tag_name == "extension":
                all_text, truncated = self._get_all_text_content(elem)
                if truncated:
                    mark_inconclusive_scan_result(result, self.EXTENSION_TRAVERSAL_INCOMPLETE_REASON)
                    result.add_check(
                        name="Extension Element Completeness Check",
                        passed=False,
                        message=("PMML <Extension> content exceeds the safe inspection node limit; scan is incomplete"),
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "tag": elem.tag,
                            "max_extension_text_nodes": self.MAX_EXTENSION_TEXT_NODES,
                            "analysis_incomplete": True,
                            "scan_outcome_reason": self.EXTENSION_TRAVERSAL_INCOMPLETE_REASON,
                        },
                        why=(
                            "Attackers can pad nested Extension trees to move malicious code beyond "
                            "a bounded traversal window. Reporting incomplete coverage prevents a "
                            "false sense of safety without claiming observed malicious content."
                        ),
                    )
                combined = f"{elem_text} {attr_text} {all_text}".lower()
            else:
                combined = f"{elem_text} {attr_text}".lower()

            # Check for external resource references
            if tag_name == "extension":
                self._add_external_resource_check_if_url(result, path, elem.tag, combined, context="extension")
            else:
                is_pmml_documentation_element = is_pmml_element and tag_name in DOCUMENTATION_ELEMENT_NAMES
                if not is_pmml_documentation_element:
                    self._add_external_resource_check_if_url(result, path, elem.tag, elem_text, context="text")
                else:
                    url_pattern = self._find_url_pattern(
                        elem_text,
                        ignored_patterns=BENIGN_DOCUMENTATION_URL_PATTERNS,
                    )
                    if url_pattern is not None:
                        self._add_external_resource_check_if_url(
                            result,
                            path,
                            elem.tag,
                            elem_text,
                            context="text",
                            url_pattern=url_pattern,
                        )

                for attr_name, attr_value in elem.attrib.items():
                    normalized_attr_name = self._local_xml_name(attr_name)
                    url_pattern = self._external_resource_attribute_url_pattern(
                        tag_name,
                        attr_name,
                        normalized_attr_name,
                        str(attr_value),
                        elem.attrib,
                        in_pmml_element=is_pmml_element,
                        in_header_metadata=in_header_metadata,
                    )
                    if url_pattern is not None:
                        self._add_external_resource_check_if_url(
                            result,
                            path,
                            elem.tag,
                            str(attr_value),
                            context="attribute",
                            attribute=attr_name,
                            url_pattern=url_pattern,
                        )

            # Check for suspicious element names (like <script>)
            if tag_name in SUSPICIOUS_ELEMENT_NAMES:
                result.add_check(
                    name="Suspicious XML Element Check",
                    passed=False,
                    message=f"Suspicious XML element found: <{elem.tag}>",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"tag": elem.tag},
                    why="Suspicious XML elements may contain executable code or scripts.",
                    rule_code="S902",
                )

            # Special attention to Extension elements which can contain arbitrary content
            if tag_name == "extension":
                for pattern, compiled_pattern in _COMPILED_SUSPICIOUS_PATTERNS:
                    if compiled_pattern.search(combined):
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
                            rule_code="S902",
                        )
                        break

    @staticmethod
    def _find_url_pattern(text: str, *, ignored_patterns: frozenset[str] | None = None) -> str | None:
        """Return the first URL scheme pattern found in text."""
        normalized_text = text.lower()
        for url_pattern in URL_PATTERNS:
            if ignored_patterns is not None and url_pattern in ignored_patterns:
                continue
            if url_pattern in normalized_text:
                return url_pattern
        return None

    @staticmethod
    def _external_resource_attribute_url_pattern(
        tag_name: str,
        attr_name: str,
        normalized_attr_name: str,
        attr_value: str,
        attributes: dict[str, Any],
        *,
        in_pmml_element: bool,
        in_header_metadata: bool,
    ) -> str | None:
        """Return the URL pattern when an attribute is an external resource reference."""
        normalized_attr_name_lower = normalized_attr_name.lower()
        is_unqualified_attr = PmmlScanner._xml_namespace(attr_name) is None and ":" not in attr_name
        if normalized_attr_name_lower in DOCUMENTATION_ATTRIBUTE_NAMES:
            ignored_patterns = BENIGN_DOCUMENTATION_URL_PATTERNS if in_pmml_element and is_unqualified_attr else None
            return PmmlScanner._find_url_pattern(
                attr_value,
                ignored_patterns=ignored_patterns,
            )
        if normalized_attr_name_lower == "reference":
            ignored_patterns = BENIGN_DOCUMENTATION_URL_PATTERNS if is_unqualified_attr and in_header_metadata else None
            return PmmlScanner._find_url_pattern(attr_value, ignored_patterns=ignored_patterns)
        if normalized_attr_name_lower in EXTERNAL_RESOURCE_ATTRIBUTE_NAMES:
            return PmmlScanner._find_url_pattern(attr_value)

        if (
            tag_name == "value"
            and normalized_attr_name_lower == "value"
            and attributes.get("property", "").lower() == "external"
        ):
            return PmmlScanner._find_url_pattern(attr_value)
        return None

    def _add_external_resource_check_if_url(
        self,
        result: ScanResult,
        path: str,
        tag: Any,
        text: str,
        *,
        context: str,
        attribute: str | None = None,
        url_pattern: str | None = None,
    ) -> None:
        """Add an external resource warning when text contains a resource URL."""
        url_pattern = url_pattern or self._find_url_pattern(text)
        if url_pattern is None:
            return

        details = {"tag": tag, "url_pattern": url_pattern, "context": context}
        if attribute is not None:
            details["attribute"] = attribute

        result.add_check(
            name="External Resource Reference Check",
            passed=False,
            message=f"PMML references external resource: {url_pattern}",
            severity=IssueSeverity.WARNING,
            location=path,
            details=details,
            why=("External references in PMML files may be used to exfiltrate data or perform network requests."),
            rule_code="S902",
        )

    @staticmethod
    def _local_xml_name(name: Any) -> str:
        """Extract a lowercase local name from namespaced ElementTree names."""
        if not isinstance(name, str):
            return ""
        local_name = name.split("}")[-1] if "}" in name else name
        return local_name.rsplit(":", 1)[-1].strip().lower()

    @staticmethod
    def _xml_namespace(name: Any) -> str | None:
        """Extract an ElementTree expanded namespace URI from a tag or attribute name."""
        if not isinstance(name, str) or not name.startswith("{") or "}" not in name:
            return None
        return name[1:].split("}", 1)[0]

    @classmethod
    def _is_pmml_root(cls, tag: Any, root_namespace: str | None) -> bool:
        """Return whether the document root is a recognized PMML root."""
        if cls._local_xml_name(tag) != "pmml":
            return False
        return root_namespace is None or PMML_NAMESPACE_PATTERN.fullmatch(root_namespace) is not None

    @classmethod
    def _is_pmml_element(cls, tag: Any, root_namespace: str | None, *, root_is_pmml: bool) -> bool:
        """Return whether a tag belongs to the PMML document namespace."""
        if not root_is_pmml:
            return False
        if root_namespace is None:
            return cls._xml_namespace(tag) is None
        return cls._xml_namespace(tag) == root_namespace

    def _get_all_text_content(self, element: Any) -> tuple[str, bool]:
        """Collect Extension text and report whether traversal hit the node budget."""
        text_parts: list[str] = []
        stack = [element]
        nodes_seen = 0
        truncated = False

        while stack:
            if nodes_seen >= self.MAX_EXTENSION_TEXT_NODES:
                truncated = True
                break

            current = stack.pop()
            nodes_seen += 1

            tag_name = self._local_xml_name(current.tag)
            if tag_name:
                text_parts.append(tag_name)

            if current.text:
                text_parts.append(current.text.strip())
            if current.tail:
                text_parts.append(current.tail.strip())

            try:
                child_count = len(current)
            except TypeError:
                continue

            remaining_budget = self.MAX_EXTENSION_TEXT_NODES - nodes_seen
            if child_count > remaining_budget:
                truncated = True
                child_count = max(remaining_budget, 0)

            for child_index in range(child_count - 1, -1, -1):
                stack.append(current[child_index])

        return " ".join(filter(None, text_parts)), truncated
