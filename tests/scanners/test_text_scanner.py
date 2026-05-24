from pathlib import Path

import pytest

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity
from modelaudit.scanners.text_scanner import TextScanner


def test_text_scanner_handles_routable_vocabulary_file(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert result.success is True
    assert not result.issues


def test_text_metadata_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    def raise_os_error(_path: str) -> int:
        raise OSError("simulated text metadata read failure")

    monkeypatch.setattr(TextScanner, "_get_file_size", staticmethod(raise_os_error))

    direct = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_scan_results=False)

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert "text_metadata_read_failed" in direct.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "Text File Metadata Read"
        and check.severity == IssueSeverity.INFO
        and check.details.get("scan_outcome_reason") == "text_metadata_read_failed"
        for check in direct.checks
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert aggregate.file_metadata[str(text_path)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(aggregate) == 2
