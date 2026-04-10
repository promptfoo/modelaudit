"""Shared metadata helpers for archive scans that intentionally stop early."""

from __future__ import annotations

from .base import INCONCLUSIVE_SCAN_OUTCOME, ScanResult


def mark_archive_scan_incomplete(result: ScanResult, reason: str) -> None:
    """Mark an archive result as explicitly inconclusive without changing findings."""
    result.metadata["analysis_incomplete"] = True
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME

    existing_reasons = result.metadata.get("scan_outcome_reasons")
    reasons = existing_reasons if isinstance(existing_reasons, list) else []
    if reason not in reasons:
        reasons.append(reason)
    result.metadata["scan_outcome_reasons"] = reasons
