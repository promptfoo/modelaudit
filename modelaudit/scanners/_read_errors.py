"""Shared reporting for scanners that treat read failures as operational errors."""

from dataclasses import dataclass
from typing import Literal

from ..core_results import mark_operational_scan_error
from ..scanner_results import IssueSeverity, ScanResult, mark_inconclusive_scan_result


@dataclass(frozen=True)
class ReadFailure:
    """Finish a failed scan using the format's existing diagnostics."""

    reason: str
    check_name: str
    message: str
    error_key: Literal["exception", "error"] = "exception"

    def __call__(self, result: ScanResult, path: str, error: OSError) -> ScanResult:
        mark_inconclusive_scan_result(result, self.reason)
        mark_operational_scan_error(result, self.reason)
        result.add_check(
            name=self.check_name,
            passed=False,
            message=self.message.format(error=error),
            severity=IssueSeverity.INFO,
            location=path,
            details={
                self.error_key: str(error),
                f"{self.error_key}_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": self.reason,
            },
        )
        result.finish(success=False)
        return result
