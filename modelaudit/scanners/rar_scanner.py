"""Fail-closed scanner for RAR archives.

ModelAudit does not currently implement RAR extraction. Recognizing RAR
containers explicitly keeps directory scans from silently skipping archives
that may contain model artifacts.
"""

import os
from typing import ClassVar

from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult

RAR_UNSUPPORTED_REASON = "rar_archive_unsupported"


class RarScanner(BaseScanner):
    """Recognize RAR archives and fail closed until extraction support exists."""

    name = "rar"
    description = "Recognizes RAR archives and marks their contents as unsupported for scanning"
    supported_extensions: ClassVar[list[str]] = [".rar"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        return os.path.splitext(path)[1].lower() in cls.supported_extensions

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.bytes_scanned = file_size
        result.metadata["file_size"] = file_size
        result.metadata["archive_format"] = "rar"
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata["scan_outcome_reasons"] = [RAR_UNSUPPORTED_REASON]

        result.add_check(
            name="RAR Archive Support",
            passed=False,
            message="RAR archive contents were not scanned because RAR extraction is not supported",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "format": "rar",
                "scan_outcome_reason": RAR_UNSUPPORTED_REASON,
                "remediation": "Extract trusted RAR archives outside ModelAudit and scan the extracted contents.",
            },
            rule_code="S902",
        )
        result.finish(success=False)
        return result
