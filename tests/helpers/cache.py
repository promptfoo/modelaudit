"""Shared result helpers and assertions for fail-closed scan cache behavior."""

import os
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.scan_results_cache import AncestorIdentity, ScanResultsCache
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanner_results import (
    ACTIONABLE_FAILED_CHECKS_METADATA_KEY,
    INCONCLUSIVE_SCAN_OUTCOME,
    Check,
    IssueSeverity,
    ScanResult,
)


def scope_cache_ancestor_identity_to_tree(
    cache: ScanResultsCache,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep cache identity checks within the test tree while other workers change shared ancestors."""
    original_capture = cache._capture_ancestor_identity
    root_path = Path(os.path.abspath(root))

    def capture_ancestor_identity(file_path: str) -> AncestorIdentity:
        identity = original_capture(file_path)
        entries = tuple(
            entry
            for entry in identity
            if (entry_path := Path(entry[0])) == root_path or root_path in entry_path.parents
        )
        return AncestorIdentity(entries)

    monkeypatch.setattr(cache, "_capture_ancestor_identity", capture_ancestor_identity)


def assert_inconclusive_not_cached(
    path: Path,
    expected_reason: str,
    cache_dir: Path,
    **scan_kwargs: Any,
) -> None:
    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert expected_reason in metadata["scan_outcome_reasons"]
            assert not [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def private_actionable_failed_checks(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    private_metadata = scan_result.get("_private_metadata")
    if not isinstance(private_metadata, dict):
        return []
    actionable_failed_checks = private_metadata.get(ACTIONABLE_FAILED_CHECKS_METADATA_KEY)
    if not isinstance(actionable_failed_checks, list):
        return []
    return [entry for entry in actionable_failed_checks if isinstance(entry, dict)]


def scan_without_cache(path: Path) -> ModelAuditResultModel:
    return scan_model_directory_or_file(str(path), cache_scan_results=False)


def single_file_metadata(aggregate: Any) -> Any:
    return next(iter(aggregate.file_metadata.values()))


def check_by_name(result: ScanResult, name: str) -> list[Check]:
    return [check for check in result.checks if check.name == name]
