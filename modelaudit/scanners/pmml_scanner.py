import os
import re

from .base import BaseScanner, IssueSeverity, ScanResult

try:
    from defusedxml import ElementTree as ET  # type: ignore

    HAS_DEFUSEDXML = True
except Exception:  # pragma: no cover - defusedxml may not be installed
    import xml.etree.ElementTree as ET  # type: ignore

    HAS_DEFUSEDXML = False


SUSPICIOUS_PATTERNS = [r"<script", r"exec\(", r"eval\("]
URL_PATTERNS = ["http://", "https://", "file://"]


class PmmlScanner(BaseScanner):
    """Scanner for PMML model files."""

    name = "pmml"
    description = "Scans PMML files for XML security issues"
    supported_extensions = [".pmml"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            return True
        try:
            with open(path, "rb") as f:
                head = f.read(256)
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

        try:
            with open(path, "rb") as f:
                data = f.read()
            result.bytes_scanned = len(data)
        except Exception as e:  # pragma: no cover - unexpected read errors
            result.add_issue(
                f"Error reading file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        try:
            text = data.decode("utf-8")
        except Exception:
            text = data.decode("utf-8", errors="replace")
            result.add_issue(
                "Non UTF-8 characters in PMML file",
                severity=IssueSeverity.WARNING,
                location=path,
            )

        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            result.add_issue(
                "PMML file contains DOCTYPE or ENTITY declaration",
                severity=IssueSeverity.CRITICAL,
                location=path,
                why="External entities may lead to XXE vulnerabilities.",
            )

        try:
            root = ET.fromstring(text)
        except Exception as e:
            result.add_issue(
                f"Malformed XML: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        if root.tag.lower() != "pmml":
            result.add_issue(
                "Root element is not <PMML>",
                severity=IssueSeverity.WARNING,
                location=path,
            )
        else:
            result.metadata["pmml_version"] = root.attrib.get("version", "")

        for elem in root.iter():
            combined = f"{elem.text or ''} {' '.join(f'{k}={v}' for k, v in elem.attrib.items())}".lower()
            for url in URL_PATTERNS:
                if url in combined:
                    result.add_issue(
                        f"PMML references external resource: {url}",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"tag": elem.tag},
                    )
                    break
            if elem.tag.lower() == "extension":
                for pat in SUSPICIOUS_PATTERNS:
                    if re.search(pat, combined):
                        result.add_issue(
                            "Suspicious content in <Extension> element",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={"pattern": pat},
                        )
                        break

        result.finish(success=True)
        return result
