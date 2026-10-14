"""
Tests to ensure telemetry is properly decoupled from core functionality.
"""

import json
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.telemetry import (
    TelemetryClient,
    TelemetryEvent,
    disable_telemetry,
    enable_telemetry,
    flush_telemetry,
    get_telemetry_client,
    is_telemetry_available,
    is_telemetry_enabled,
    record_command_used,
    record_event,
    record_feature_used,
    record_file_type_detected,
    record_issue_found,
    record_scanner_used,
    safe_telemetry,
    telemetry_context,
)


@contextmanager
def _temporary_telemetry_home(tmp_path: Path) -> Iterator[None]:
    """Keep config-file cleanup in the test call so leaked handles fail the test."""
    with (
        tempfile.TemporaryDirectory(dir=tmp_path) as home,
        patch("modelaudit.telemetry.Path.home", return_value=Path(home)),
    ):
        yield


@pytest.fixture
def telemetry_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Prepare an isolated runtime without constructing the telemetry client."""
    for name in (
        "CI",
        "IS_TESTING",
        "PROMPTFOO_DISABLE_TELEMETRY",
        "NO_ANALYTICS",
        "MODELAUDIT_TELEMETRY_FLUSH_IMMEDIATELY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("modelaudit.telemetry.Path.home", lambda: tmp_path)
    monkeypatch.setattr("modelaudit.telemetry._IS_DEVELOPMENT", False)
    monkeypatch.setattr("modelaudit.telemetry.POSTHOG_AVAILABLE", True)
    monkeypatch.setattr("modelaudit.telemetry.POSTHOG_PROJECT_KEY", "test-key")
    monkeypatch.setattr("modelaudit.telemetry._telemetry_client", None)
    monkeypatch.setattr("modelaudit.telemetry.atexit.register", lambda callback: None)
    constructor = MagicMock()
    monkeypatch.setattr("modelaudit.telemetry.Posthog", constructor)
    return constructor


@pytest.fixture
def captured_telemetry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TelemetryClient, dict[str, object]]:
    """Capture payloads independently of transport and opt-out behavior."""
    monkeypatch.setattr("modelaudit.telemetry.Path.home", lambda: tmp_path)
    monkeypatch.setattr("modelaudit.telemetry.POSTHOG_AVAILABLE", False)
    captured: dict[str, object] = {}

    def capture_event(event: TelemetryEvent, properties: dict[str, object] | None = None) -> None:
        captured["event"] = event
        captured["properties"] = properties or {}

    client = TelemetryClient()
    client.record_event = capture_event  # type: ignore[method-assign]
    return client, captured


def _scan_properties(
    captured_telemetry: tuple[TelemetryClient, dict[str, object]],
    scanner: str,
    issues: list[dict[str, Any]],
) -> dict[str, Any]:
    client, captured = captured_telemetry
    client.record_scan_completed(0.1, {"files_scanned": 1, "scanner_names": [scanner], "issues": issues, "assets": []})
    assert captured["event"] == TelemetryEvent.SCAN_COMPLETED
    properties = captured["properties"]
    assert isinstance(properties, dict)
    return properties


class TestTelemetryDecoupling:
    """Test that telemetry failures don't break core functionality."""

    def test_safe_telemetry_decorator_handles_exceptions(self) -> None:
        """Test that safe_telemetry decorator catches all exceptions."""

        @safe_telemetry
        def failing_function() -> None:
            raise Exception("This should not propagate")

        # Should not raise an exception
        result = failing_function()
        assert result is None

    def test_telemetry_context_handles_exceptions(self) -> None:
        """Test that telemetry_context catches all exceptions."""
        # Exception should not have propagated
        with telemetry_context():
            raise Exception("This should not propagate")

    def test_all_record_functions_safe_when_client_fails(self) -> None:
        """Test that all telemetry record functions are safe when client initialization fails."""
        # Mock get_telemetry_client to return None (simulating initialization failure)
        with patch("modelaudit.telemetry.get_telemetry_client", return_value=None):
            # All these should complete without raising exceptions
            record_event(TelemetryEvent.COMMAND_USED, {"test": "data"})
            record_command_used("test_command", duration=1.0, extra="param")
            record_feature_used("test_feature", enabled=True)
            record_scanner_used("test_scanner", "pkl", 0.5)
            record_file_type_detected("/path/to/file.pkl", "pickle", 0.9)
            record_issue_found("malicious_code", "critical", "test_scanner")
            flush_telemetry()

    def test_telemetry_functions_safe_when_client_raises_exception(self) -> None:
        """Test that telemetry functions are safe when client methods raise exceptions."""
        mock_client = MagicMock()
        mock_client.record_event.side_effect = Exception("Network error")
        mock_client.record_command_used.side_effect = Exception("Disk error")

        with patch("modelaudit.telemetry.get_telemetry_client", return_value=mock_client):
            # All these should complete without raising exceptions
            record_event(TelemetryEvent.COMMAND_USED, {"test": "data"})
            record_command_used("test_command")
            mock_client.record_event.assert_called_once()
            mock_client.record_command_used.assert_called_once()

    @pytest.mark.parametrize("check", [is_telemetry_available, is_telemetry_enabled], ids=["available", "enabled"])
    @pytest.mark.parametrize("error", [None, Exception("Init error")], ids=["absent", "raises"])
    def test_telemetry_status_handles_failures(self, check: Callable[[], bool], error: Exception | None) -> None:
        with patch("modelaudit.telemetry.get_telemetry_client", return_value=None, side_effect=error) as get_client:
            assert check() is False
            get_client.assert_called_once()

    def test_enable_disable_telemetry_safe_when_client_fails(self) -> None:
        """Test that enable/disable telemetry functions are safe when client fails."""
        with patch("modelaudit.telemetry.get_telemetry_client", return_value=None):
            # Should not raise exceptions
            enable_telemetry()
            disable_telemetry()

    @pytest.mark.parametrize("constructor", ["TelemetryClient", "UserConfig"])
    def test_initialization_failure_handled(self, telemetry_runtime: MagicMock, constructor: str) -> None:
        with patch(f"modelaudit.telemetry.{constructor}", side_effect=Exception("Init failed")) as initialize:
            assert get_telemetry_client() is None
            initialize.assert_called_once()

    def test_posthog_import_failure_handled(
        self, tmp_path: Path, telemetry_runtime: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with _temporary_telemetry_home(tmp_path):
            monkeypatch.setattr("modelaudit.telemetry.POSTHOG_AVAILABLE", False)
            client = get_telemetry_client()
            assert client is not None
            assert client._posthog_client is None
            telemetry_runtime.assert_not_called()

    def test_network_failures_dont_break_functionality(self, tmp_path: Path, telemetry_runtime: MagicMock) -> None:
        with _temporary_telemetry_home(tmp_path):
            transport = telemetry_runtime.return_value
            transport.capture.side_effect = Exception("Network down")
            transport.flush.side_effect = Exception("Network down")
            assert get_telemetry_client() is not None
            telemetry_runtime.assert_called_once()
            record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})
            record_command_used("test")
            flush_telemetry()
            assert transport.capture.call_count == 2
            transport.flush.assert_called_once()

    def test_file_system_failures_handled(self, telemetry_runtime: MagicMock) -> None:
        with patch.object(Path, "mkdir", side_effect=PermissionError("Read-only home")) as mkdir:
            assert get_telemetry_client() is not None
            record_command_used("test")
            mkdir.assert_called()
        telemetry_runtime.return_value.capture.assert_called_once()


class TestTelemetryFunctionalityWhenWorking:
    """Test that telemetry still works correctly when everything is functioning."""

    def test_telemetry_works_when_enabled_and_available(self, tmp_path: Path, telemetry_runtime: MagicMock) -> None:
        with _temporary_telemetry_home(tmp_path):
            client = get_telemetry_client()
            assert client is not None
            client._user_config.telemetry_enabled = True
            assert is_telemetry_enabled() is True
            assert is_telemetry_available() is True
            telemetry_runtime.assert_called_once()

    def test_safe_decorator_passes_through_return_values(self) -> None:
        """Test that safe_telemetry decorator doesn't interfere with return values."""

        @safe_telemetry
        def working_function() -> str:
            return "success"

        result = working_function()
        assert result == "success"

    def test_telemetry_context_allows_normal_execution(self) -> None:
        """Test that telemetry_context allows normal execution when no errors occur."""
        result = None

        with telemetry_context():
            result = "executed successfully"

        assert result == "executed successfully"

    def test_record_issue_found_redacts_sensitive_data(
        self, tmp_path: Path, captured_telemetry: tuple[TelemetryClient, dict[str, object]]
    ) -> None:
        """Issue telemetry should not copy free-form scanner messages into analytics fields."""
        client, captured = captured_telemetry

        sensitive_path = tmp_path / "private-model.pkl"
        another_sensitive_path = tmp_path / "secrets" / "weights.bin"
        message = (
            f"Unsafe pickle found in {sensitive_path}; "
            f"secondary artifact at {another_sensitive_path}; "
            "downloaded from https://example.com/model?token=secret&api_key=AKIA1234567890; "
            "Authorization: Bearer very-secret-token"
        )

        client.record_issue_found(
            message,
            "critical",
            "pickle",
            file_path=str(sensitive_path),
        )

        assert captured["event"] == TelemetryEvent.ISSUE_FOUND
        properties = captured["properties"]
        assert isinstance(properties, dict)
        assert properties["issue_type"] == "unknown_issue"
        assert "issue_message" not in properties
        serialized = json.dumps(properties)
        assert str(sensitive_path) not in serialized
        assert str(another_sensitive_path) not in serialized
        assert "token=secret" not in serialized
        assert "api_key=AKIA1234567890" not in serialized
        assert "Bearer very-secret-token" not in serialized

    def test_record_issue_found_filters_token_like_strings(
        self, captured_telemetry: tuple[TelemetryClient, dict[str, object]]
    ) -> None:
        """Slug-like filenames and tokens must not be treated as stable issue IDs."""
        client, captured = captured_telemetry
        cases: list[tuple[str, str, str | None, str]] = [
            ("private-model.pkl", "pickle", None, "unknown_issue"),
            ("secret-token-abc123", "pickle", None, "unknown_issue"),
            ("sk_live_1234567890abcdef", "pickle", None, "unknown_issue"),
            (
                "legacy message mentions CVE-2025-23304",
                "nemo",
                "legacy message mentions CVE-2025-23304",
                "cve:CVE-2025-23304",
            ),
            ("legacy message mentions S1101", "nemo", "legacy message mentions S1101", "rule:S1101"),
            ("pickle_dangerous_global", "pickle", None, "pickle_dangerous_global"),
        ]
        properties = []
        for issue_type, scanner, issue_message, _ in cases:
            kwargs = {"issue_message": issue_message} if issue_message is not None else {}
            client.record_issue_found(issue_type, "critical", scanner, **kwargs)
            properties.append(captured["properties"])

        for (issue_type, _, issue_message, expected), payload in zip(cases, properties, strict=True):
            assert isinstance(payload, dict), issue_type
            assert payload.get("issue_type") == expected, issue_type
            if issue_message is not None:
                assert "legacy message" not in json.dumps(payload), issue_type
        serialized = json.dumps([properties[0], properties[1], properties[2], properties[5]])
        assert "private-model.pkl" not in serialized
        assert "secret-token-abc123" not in serialized
        assert "sk_live_1234567890abcdef" not in serialized

    def test_scan_completed_uses_rule_identifiers_not_issue_messages(
        self, tmp_path: Path, captured_telemetry: tuple[TelemetryClient, dict[str, object]]
    ) -> None:
        """Completed-scan telemetry should count stable rule IDs and omit raw issue text."""
        sensitive_path = tmp_path / "secret-model.nemo"
        raw_message = f"CVE-2025-23304: dangerous target in {sensitive_path} https://example.com/?token=secret"

        properties = _scan_properties(
            captured_telemetry,
            "nemo",
            [
                {
                    "message": raw_message,
                    "severity": "critical",
                    "location": str(sensitive_path),
                    "type": "nemo_check",
                    "rule_code": "S1101",
                    "details": {"cve_id": "CVE-2025-23304"},
                }
            ],
        )

        assert properties["issue_types"] == {"rule:S1101": 1}
        assert properties["issue_details"][0]["type"] == "rule:S1101"
        serialized = json.dumps(properties)
        assert raw_message not in serialized
        assert str(sensitive_path) not in serialized
        assert "token=secret" not in serialized

    def test_scan_completed_handles_missing_or_malformed_issue_metadata(
        self, tmp_path: Path, captured_telemetry: tuple[TelemetryClient, dict[str, object]]
    ) -> None:
        """Completed-scan telemetry should handle incomplete issue metadata without raw text."""
        sensitive_path = tmp_path / "private-artifact.nemo"
        raw_message = f"Legacy finding in {sensitive_path} token=topsecret"

        properties = _scan_properties(
            captured_telemetry,
            "nemo",
            [
                {"message": raw_message, "severity": "critical"},
                {"message": raw_message, "severity": "high", "rule_code": None},
                {"message": raw_message, "severity": "medium", "rule_code": ""},
                {"message": raw_message, "severity": "low", "cve_id": None},
                {"message": raw_message, "severity": "low", "cve_id": ""},
            ],
        )

        assert properties["issue_types"] == {"unknown_issue": 5}
        serialized = json.dumps(properties)
        assert raw_message not in serialized
        assert str(sensitive_path) not in serialized
        assert "token=topsecret" not in serialized

    @pytest.mark.parametrize(
        "token_messages",
        [
            [
                "private-model.pkl",
                "secret-token-abc123",
                "sk_live_1234567890abcdef",
            ],
            [
                "AKIAIOSFODNN7EXAMPLE",
                "ghp_1234567890abcdef1234567890abcdef1234",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            ],
        ],
    )
    def test_scan_completed_rejects_token_shaped_legacy_messages(
        self, captured_telemetry: tuple[TelemetryClient, dict[str, object]], token_messages: list[str]
    ) -> None:
        """Message-only telemetry can expose rule/CVE tokens, not arbitrary slug-like text."""
        properties = _scan_properties(
            captured_telemetry,
            "pickle",
            [
                *[{"message": message, "severity": "critical"} for message in token_messages],
                {"message": "CVE-2025-23304 in sanitized legacy text", "severity": "critical"},
                {"message": "S1101 in sanitized legacy text", "severity": "critical"},
            ],
        )

        assert properties["issue_types"] == {
            "unknown_issue": len(token_messages),
            "cve:CVE-2025-23304": 1,
            "rule:S1101": 1,
        }
        serialized = json.dumps(properties)
        for message in token_messages:
            assert message not in serialized


if __name__ == "__main__":
    pytest.main([__file__])
