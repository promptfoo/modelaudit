"""
Comprehensive tests for ModelAudit telemetry system.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from modelaudit.telemetry import (
    TelemetryClient,
    TelemetryEvent,
    UserConfig,
    enable_telemetry,
    get_telemetry_client,
    is_telemetry_available,
    record_event,
    record_scan_started,
)

_NO_CI_ENV = (
    "CI",
    "GITHUB_ACTIONS",
    "TRAVIS",
    "CIRCLECI",
    "JENKINS",
    "GITLAB_CI",
    "APPVEYOR",
    "CODEBUILD_BUILD_ID",
    "TF_BUILD",
    "BITBUCKET_COMMIT",
    "BUDDY",
    "BUILDKITE",
    "TEAMCITY_VERSION",
    "IS_TESTING",
    "PROMPTFOO_DISABLE_TELEMETRY",
    "NO_ANALYTICS",
)


class TestUserConfig:
    """Test user configuration management."""

    def test_user_config_creates_user_id(self, tmp_path: Path) -> None:
        """Test that user config generates a UUID in Promptfoo's config format."""
        promptfoo_config_file = tmp_path / ".promptfoo" / "promptfoo.yaml"

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            config = UserConfig()

            assert config.user_id
            assert len(config.user_id) == 36  # UUID length
            assert promptfoo_config_file.parent.exists()
            assert promptfoo_config_file.exists()
            assert yaml.safe_load(promptfoo_config_file.read_text())["id"] == config.user_id

    def test_user_config_uses_existing_promptfoo_user_id(self, tmp_path: Path) -> None:
        """Existing Promptfoo IDs should be reused without rewriting ModelAudit config."""
        promptfoo_config_file = tmp_path / ".promptfoo" / "promptfoo.yaml"
        promptfoo_config_file.parent.mkdir()
        promptfoo_config_file.write_text(yaml.safe_dump({"id": "promptfoo-id", "cloud": {"enabled": True}}))

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            config = UserConfig()

            assert config.user_id == "promptfoo-id"
            promptfoo_config = yaml.safe_load(promptfoo_config_file.read_text())
            assert promptfoo_config["cloud"] == {"enabled": True}
            assert not (tmp_path / ".modelaudit" / "user_config.json").exists()

    def test_user_config_migrates_legacy_modelaudit_user_id_to_promptfoo_config(self, tmp_path: Path) -> None:
        """Legacy ModelAudit IDs should remain stable when adopting Promptfoo config."""
        legacy_user_id = "11111111-2222-4333-8444-555555555555"
        modelaudit_config_file = tmp_path / ".modelaudit" / "user_config.json"
        modelaudit_config_file.parent.mkdir()
        modelaudit_config_file.write_text(json.dumps({"user_id": legacy_user_id}))
        promptfoo_config_file = tmp_path / ".promptfoo" / "promptfoo.yaml"

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            config = UserConfig()

            assert config.user_id == legacy_user_id
            assert yaml.safe_load(promptfoo_config_file.read_text())["id"] == legacy_user_id

    def test_user_config_migrates_legacy_id_into_existing_promptfoo_config(self, tmp_path: Path) -> None:
        """Promptfoo configs without an ID should receive the legacy ID without losing settings."""
        legacy_user_id = "11111111-2222-4333-8444-555555555555"
        modelaudit_config_file = tmp_path / ".modelaudit" / "user_config.json"
        modelaudit_config_file.parent.mkdir()
        modelaudit_config_file.write_text(json.dumps({"user_id": legacy_user_id}))
        promptfoo_config_file = tmp_path / ".promptfoo" / "promptfoo.yaml"
        promptfoo_config_file.parent.mkdir()
        promptfoo_config_file.write_text(
            yaml.safe_dump({"cloud": {"apiKey": "test-key"}, "hasHarmfulRedteamConsent": True})
        )

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            config = UserConfig()

            assert config.user_id == legacy_user_id

        promptfoo_config = yaml.safe_load(promptfoo_config_file.read_text())
        assert promptfoo_config["id"] == legacy_user_id
        assert promptfoo_config["cloud"] == {"apiKey": "test-key"}
        assert promptfoo_config["hasHarmfulRedteamConsent"] is True

    def test_user_config_falls_back_when_promptfoo_yaml_is_corrupt(self, tmp_path: Path) -> None:
        """A malformed promptfoo.yaml must not crash; the legacy file is used."""
        promptfoo_config_file = tmp_path / ".promptfoo" / "promptfoo.yaml"
        promptfoo_config_file.parent.mkdir()
        promptfoo_config_file.write_text("{not: valid: yaml: ::")
        modelaudit_config_file = tmp_path / ".modelaudit" / "user_config.json"

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            config = UserConfig()
            user_id = config.user_id

        assert len(user_id) == 36
        # The corrupt promptfoo file is left alone.
        assert promptfoo_config_file.read_text() == "{not: valid: yaml: ::"
        # Legacy fallback persists the freshly-minted ID.
        assert modelaudit_config_file.exists()
        assert json.loads(modelaudit_config_file.read_text())["user_id"] == user_id

    def test_user_config_falls_back_when_promptfoo_yaml_is_unwritable(self, tmp_path: Path) -> None:
        """If we cannot persist to promptfoo.yaml, the ID still lands in the legacy config."""
        modelaudit_config_file = tmp_path / ".modelaudit" / "user_config.json"

        with (
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.auth.config._write_yaml_atomic", side_effect=OSError("disk full")),
        ):
            mock_home.return_value = tmp_path
            config = UserConfig()
            user_id = config.user_id

        assert len(user_id) == 36
        assert modelaudit_config_file.exists()
        assert json.loads(modelaudit_config_file.read_text())["user_id"] == user_id

    def test_user_config_defaults_to_enabled(self):
        """Test that telemetry defaults to enabled (opt-out model)."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            config = UserConfig()

            assert config.telemetry_enabled is True

    def test_user_config_persists_settings(self):
        """Test that settings are persisted to file."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)

            config1 = UserConfig()
            config1.telemetry_enabled = True
            config1.email = "test@example.com"

            # Create new instance to test persistence
            config2 = UserConfig()
            assert config2.telemetry_enabled is True
            assert config2.email == "test@example.com"

    def test_user_config_handles_corrupted_file(self):
        """Test that corrupted config files are handled gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / ".modelaudit" / "user_config.json"
            config_file.parent.mkdir()
            config_file.write_text("invalid json{")

            with patch("modelaudit.telemetry.Path.home") as mock_home:
                mock_home.return_value = Path(temp_dir)
                config = UserConfig()

                # Should create new config despite corrupted file
                assert config.user_id
                # Default to enabled (opt-out model)
                assert config.telemetry_enabled is True


class TestTelemetryClient:
    """Test telemetry client functionality."""

    def test_telemetry_enabled_by_default_in_production(self):
        """Test that telemetry is enabled by default in production (non-editable install)."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),  # Simulate production
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Telemetry should be enabled by default in production
            assert client._is_disabled() is False

    def test_telemetry_disabled_in_development(self):
        """Test that telemetry is disabled by default in development (editable install)."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", True),  # Simulate development
            patch.dict(
                os.environ,
                {
                    "CI": "",
                    "IS_TESTING": "",
                    "PROMPTFOO_DISABLE_TELEMETRY": "",
                    "NO_ANALYTICS": "",
                    "MODELAUDIT_TELEMETRY_DEV": "",
                },
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Telemetry should be disabled by default in development
            assert client._is_disabled() is True

    def test_telemetry_can_be_enabled_in_development(self):
        """Test that telemetry can be explicitly enabled in development."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", True),  # Simulate development
            patch.dict(
                os.environ,
                {
                    "CI": "",
                    "IS_TESTING": "",
                    "PROMPTFOO_DISABLE_TELEMETRY": "",
                    "NO_ANALYTICS": "",
                    "MODELAUDIT_TELEMETRY_DEV": "1",
                },
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Telemetry should be enabled when explicitly opted in during development
            assert client._is_disabled() is False

    def test_promptfoo_disable_env_var(self):
        """Test that PROMPTFOO_DISABLE_TELEMETRY works."""
        with (
            patch.dict(os.environ, {"PROMPTFOO_DISABLE_TELEMETRY": "1"}),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            assert client._is_disabled() is True

    def test_ci_environment_disables_telemetry(self):
        """Test that CI environment disables telemetry."""
        with (
            patch.dict(os.environ, {"CI": "1"}),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            assert client._is_disabled() is True

    def test_promptfoo_truthy_aliases_disable_telemetry(self, tmp_path: Path) -> None:
        """Promptfoo truthy env aliases should use the same disable path as true/1."""
        with (
            patch.dict(os.environ, {"NO_ANALYTICS": "yeppers"}, clear=False),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = tmp_path
            client = TelemetryClient()

            assert client._is_disabled() is True

    def test_telemetry_can_be_disabled_via_config(self):
        """Test that telemetry can be disabled via user config."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            # Explicitly disable via config
            client._user_config.telemetry_enabled = False

            assert client._is_disabled() is True

    def test_event_recording_when_enabled(self):
        """Test that events are recorded when telemetry is enabled."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", True),
            patch("modelaudit.telemetry.Posthog", return_value=mock_posthog),
            patch.dict(
                os.environ,
                dict.fromkeys(_NO_CI_ENV, ""),
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            client.record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

            # Should call PostHog capture
            mock_posthog.capture.assert_called_once()
            capture_kwargs = mock_posthog.capture.call_args.kwargs
            assert capture_kwargs["distinct_id"] == client._user_config.user_id
            assert capture_kwargs["properties"]["isRunningInCi"] is False
            mock_posthog.flush.assert_not_called()

    def test_identify_user_uses_stable_promptfoo_id_and_ci_property(self) -> None:
        """Identify should use the same stable ID and Promptfoo-style CI property."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", True),
            patch("modelaudit.telemetry.Posthog", return_value=mock_posthog),
            patch.dict(os.environ, dict.fromkeys(_NO_CI_ENV, ""), clear=False),
        ):
            home = Path(temp_dir)
            promptfoo_config_file = home / ".promptfoo" / "promptfoo.yaml"
            promptfoo_config_file.parent.mkdir()
            promptfoo_config_file.write_text(yaml.safe_dump({"id": "promptfoo-id"}))
            mock_home.return_value = home

            TelemetryClient()

            mock_posthog.set.assert_called_once()
            set_kwargs = mock_posthog.set.call_args.kwargs
            assert set_kwargs["distinct_id"] == "promptfoo-id"
            assert set_kwargs["properties"]["isRunningInCi"] is False

    def test_event_properties_mark_ci_environment(self) -> None:
        """Telemetry payloads should expose Promptfoo-compatible CI state."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", False),
            patch.dict(os.environ, {**dict.fromkeys(_NO_CI_ENV, ""), "GITHUB_ACTIONS": "true"}, clear=False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog

            client._send_event_internal(TelemetryEvent.COMMAND_USED, {"command": "test"})

            properties = mock_posthog.capture.call_args.kwargs["properties"]
            assert properties["isRunningInCi"] is True

    @pytest.mark.parametrize(
        ("env_var", "value"),
        [
            ("TEAMCITY_VERSION", "2024.07.1"),
            ("CODEBUILD_BUILD_ID", "codebuild:abc-123"),
            ("BITBUCKET_COMMIT", "deadbeefcafef00ddeadbeefcafef00ddeadbeef"),
            ("JENKINS", "/var/jenkins_home"),
        ],
    )
    def test_marker_style_ci_vars_are_detected_by_presence(self, env_var: str, value: str) -> None:
        """Marker-style CI vars carry build IDs, version strings, or paths — not booleans."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", False),
            patch.dict(os.environ, {**dict.fromkeys(_NO_CI_ENV, ""), env_var: value}, clear=False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog

            client._send_event_internal(TelemetryEvent.COMMAND_USED, {"command": "test"})

            properties = mock_posthog.capture.call_args.kwargs["properties"]
            assert properties["isRunningInCi"] is True

    def test_event_recording_can_flush_immediately_when_configured(self):
        """Immediate flush can be enabled for low-latency delivery."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", True),
            patch("modelaudit.telemetry.Posthog", return_value=mock_posthog),
            patch.dict(
                os.environ,
                {
                    "CI": "",
                    "IS_TESTING": "",
                    "PROMPTFOO_DISABLE_TELEMETRY": "",
                    "NO_ANALYTICS": "",
                    "MODELAUDIT_TELEMETRY_FLUSH_IMMEDIATELY": "1",
                },
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            client.record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

            mock_posthog.capture.assert_called_once()
            mock_posthog.flush.assert_called()

    def test_event_not_recorded_when_disabled(self):
        """Test that events are not recorded when telemetry is disabled."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            # Explicitly disable telemetry
            client._user_config.telemetry_enabled = False

            client.record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

            # Should not call PostHog
            mock_posthog.capture.assert_not_called()

    def test_scan_completed_uses_top_level_results_schema(self, tmp_path: Path) -> None:
        """Test that scan completion telemetry aggregates without file identifiers."""
        mock_posthog = MagicMock()
        first_model = tmp_path / "a.pkl"
        second_model = tmp_path / "b.zip"
        first_model.write_bytes(b"pickle")
        second_model.write_bytes(b"zip")

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            results = {
                "files_scanned": 2,
                "scanner_names": ["pickle", "zip"],
                "assets": [
                    {"path": str(first_model), "type": "pickle"},
                    {"path": str(second_model), "type": "zip"},
                ],
                "issues": [
                    {"message": "Issue A", "severity": "critical", "location": str(first_model)},
                    {"message": "Issue B", "severity": "warning", "location": str(second_model)},
                    {
                        "type": "pickle_dangerous_global",
                        "message": "Legacy message should not be used when type exists",
                        "severity": "info",
                        "location": str(first_model),
                    },
                    {
                        "message": "Issue with no location",
                        "severity": "warning",
                        "location": None,
                    },
                ],
            }

            client.record_scan_completed(1.5, results)
            properties = mock_posthog.capture.call_args.kwargs["properties"]

            assert properties["total_files"] == 2
            assert properties["total_issues"] == 4
            assert properties["issue_types"]["unknown_issue"] == 3
            assert properties["issue_types"]["pickle_dangerous_global"] == 1
            assert "Issue A" not in properties["issue_types"]
            assert "Issue B" not in properties["issue_types"]
            assert "Issue with no location" not in properties["issue_types"]
            assert "Legacy message should not be used when type exists" not in properties["issue_types"]
            assert properties["issue_severities"]["critical"] == 1
            assert properties["issue_severities"]["warning"] == 2
            assert properties["issue_severities"]["info"] == 1
            assert properties["file_types"]["pickle"] == 1
            assert properties["file_types"]["zip"] == 1
            assert sorted(properties["scanners_used"]) == ["pickle", "zip"]
            assert "files_scanned" not in properties
            assert "file_identifiers" not in properties
            assert "model_references" not in properties
            assert properties["asset_reference_types"] == ["file:.pkl", "file:.zip"]
            canonical_issue = next(
                (detail for detail in properties["issue_details"] if detail["type"] == "pickle_dangerous_global"),
                None,
            )
            assert canonical_issue is not None, "Expected issue detail with type 'pickle_dangerous_global'"
            assert "model_name" not in canonical_issue
            assert "model_reference" not in canonical_issue
            assert "location_file_extension" not in canonical_issue
            assert "location_reference_type" not in canonical_issue
            missing_location_issue = next(
                (
                    detail
                    for detail in properties["issue_details"]
                    if detail["type"] == "unknown_issue" and detail["location_type"] == "unknown"
                ),
                None,
            )
            assert missing_location_issue is not None, (
                "Expected issue detail with type 'unknown_issue' and location_type 'unknown'"
            )
            assert missing_location_issue["location_type"] == "unknown"
            assert "location_file_extension" not in missing_location_issue
            assert "location_reference_type" not in missing_location_issue
            assert "location_identifier" not in canonical_issue
            serialized = json.dumps(properties)
            assert str(first_model) not in serialized
            assert "a.pkl" not in serialized
            assert "b.zip" not in serialized
            assert '"None"' not in json.dumps(properties)

    def test_scan_started_includes_per_path_fields(self, tmp_path: Path) -> None:
        """Scan started events include coarse path metadata but no identifiers."""
        mock_posthog = MagicMock()
        model_path = tmp_path / "model.pkl"
        model_path.write_bytes(b"pickle")

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            paths = [str(model_path), "hf://meta-llama/Llama-2-7b"]
            client.record_scan_started(paths, {"format": "json"})

            properties = mock_posthog.capture.call_args.kwargs["properties"]
            assert "paths" not in properties
            assert "model_names" not in properties
            assert "model_references" not in properties
            assert properties["model_reference_types"] == ["file:.pkl", "huggingface:no_extension"]
            assert properties["file_extensions"] == [".pkl", ""]
            assert properties["file_extension_counts"] == {".pkl": 1}
            assert properties["source_types"] == ["local", "huggingface"]
            assert properties["path_types"][0] == "file"
            assert properties["path_types"][1] == "huggingface_shorthand"
            assert "path_identifiers" not in properties
            serialized = json.dumps(properties)
            assert str(model_path) not in serialized
            assert "model.pkl" not in serialized
            assert "meta-llama" not in serialized
            assert "Llama-2-7b" not in serialized

    def test_path_and_url_fields_omit_identifiers(self, tmp_path: Path) -> None:
        """Path and URL fields should not include raw sensitive values or identifiers."""
        mock_posthog = MagicMock()
        sensitive_path = tmp_path / "private" / "model.pkl"
        sensitive_path.parent.mkdir()
        sensitive_path.write_bytes(b"pickle")

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            sensitive_url = "https://user:pass@example.com/model.bin?token=secret"

            client.record_file_type_detected(str(sensitive_path), "pickle")
            file_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert "file_path" not in file_props
            assert "model_name" not in file_props
            assert "model_reference" not in file_props
            assert file_props["model_reference_type"] == "file:.pkl"
            assert file_props["source_type"] == "local"
            assert "path_identifier" not in file_props
            assert str(sensitive_path) not in json.dumps(file_props)
            assert "model.pkl" not in json.dumps(file_props)

            client.record_issue_found("dangerous pattern", "critical", "pickle", str(sensitive_path))
            issue_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert "file_path" not in issue_props
            assert "model_name" not in issue_props
            assert "model_reference" not in issue_props
            assert issue_props["model_reference_type"] == "file:.pkl"
            assert issue_props["source_type"] == "local"
            assert "path_identifier" not in issue_props
            assert str(sensitive_path) not in json.dumps(issue_props)
            assert "model.pkl" not in json.dumps(issue_props)

            client.record_download_started("http", sensitive_url)
            download_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert "url" not in download_props
            assert download_props["domain"] == "custom"
            assert "model_name" not in download_props
            assert "model_reference" not in download_props
            assert download_props["model_reference_type"] == "http:.bin"
            assert download_props["file_extension"] == ".bin"
            assert "url_identifier" not in download_props
            assert sensitive_url not in json.dumps(download_props)
            assert "user:pass@" not in json.dumps(download_props)
            assert "example.com" not in json.dumps(download_props)
            assert "model.bin" not in json.dumps(download_props)

            client.record_download_completed("http", 2.0, 2048, sensitive_url)
            completed_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert "url" not in completed_props
            assert completed_props["domain"] == "custom"
            assert "model_name" not in completed_props
            assert "model_reference" not in completed_props
            assert completed_props["model_reference_type"] == "http:.bin"
            assert completed_props["file_extension"] == ".bin"
            assert "url_identifier" not in completed_props
            assert sensitive_url not in json.dumps(completed_props)
            assert "user:pass@" not in json.dumps(completed_props)
            assert "example.com" not in json.dumps(completed_props)
            assert "model.bin" not in json.dumps(completed_props)

    def test_download_events_preserve_explicit_source_type(self) -> None:
        """URL classification must not overwrite the download integration name."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            client.record_download_started("jfrog", "https://tenant.jfrog.io/artifactory/model.pt")
            started_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert started_props["source_type"] == "jfrog"
            assert started_props["model_reference_type"] == "jfrog:.pt"

            client.record_download_completed(
                "mlflow",
                duration=1.0,
                size_bytes=1024,
                url="models:/private-model/Production",
            )
            completed_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert completed_props["source_type"] == "mlflow"
            assert completed_props["model_reference_type"] == "mlflow:no_extension"

    def test_source_type_classification_uses_scheme_and_provider_boundaries(self) -> None:
        """Provider names in local paths or unrelated hosts must not change source type."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            assert client._classify_source_type("/tmp/huggingface-private/model.pt") == "local"
            assert client._classify_source_type("https://huggingface.evil.example/model.pt") == "http"
            assert client._classify_source_type("https://example.com/pytorch/model.pt") == "http"
            assert client._classify_source_type("https://tenant.jfrog.io/model.pt") == "jfrog"
            assert client._classify_source_type("pytorch://org/repo/model.pt") == "pytorch_hub"
            assert client._classify_source_type("azure://bucket/model.pt") == "azure"
            assert client._classify_source_type("models:/private-model/Production") == "mlflow"

    def test_model_reference_helpers_do_not_preserve_url_identifiers(self) -> None:
        """Legacy model reference helpers should expose only coarse buckets."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            assert client._extract_model_name("https://example.com/model.bin?token=secret") is None
            assert client._extract_model_name("https://example.com/model.bin#fragment") is None
            assert client._extract_domain("https://user:pass@example.com:8443") == "custom"
            assert client._extract_model_name("https://user:pass@example.com") is None
            assert (
                client._extract_model_reference("https://user:pass@example.com/model.bin?token=secret") == "http:.bin"
            )
            assert client._extract_model_reference("https://user:pass@example.com") == "http:no_extension"

    def test_unknown_extensions_are_bucketed_without_preserving_identifiers(self) -> None:
        """User-defined suffixes should collapse to one non-identifying bucket."""
        mock_posthog = MagicMock()
        sensitive_path = "weights.customer-secret-project"

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            client.record_scan_started([sensitive_path], {"format": "json"})
            properties = mock_posthog.capture.call_args.kwargs["properties"]
            assert properties["file_extensions"] == ["other_extension"]
            assert properties["file_extension_counts"] == {"other_extension": 1}
            assert properties["model_reference_types"] == ["unknown:other_extension"]
            assert sensitive_path not in json.dumps(properties)
            assert "customer-secret-project" not in json.dumps(properties)

            assert (
                client._extract_file_extension("https://example.com/model.internal?token=secret") == "other_extension"
            )
            assert client._extract_model_reference("https://example.com/model.internal") == "http:other_extension"
            assert client._extract_file_extension("model.safetensors") == ".safetensors"

    def test_scan_completed_omits_metadata_derived_from_free_form_locations(self) -> None:
        """Issue location prose must not become identifying telemetry dimensions."""
        mock_posthog = MagicMock()
        sensitive_location = "/tmp/model.pb (node: company.secret)"

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            client.record_scan_completed(
                0.1,
                {
                    "issues": [
                        {
                            "type": "protobuf_dangerous_node",
                            "severity": "critical",
                            "location": sensitive_location,
                        }
                    ]
                },
            )

            properties = mock_posthog.capture.call_args.kwargs["properties"]
            issue_detail = properties["issue_details"][0]
            assert issue_detail == {
                "type": "protobuf_dangerous_node",
                "severity": "critical",
                "location_type": "unknown",
            }
            assert sensitive_location not in json.dumps(properties)
            assert "company.secret" not in json.dumps(properties)

    def test_cloud_url_telemetry_fields_strip_query_and_fragment(self) -> None:
        """Cloud URL telemetry should not retain presigned query material."""
        mock_posthog = MagicMock()
        cloud_url = "s3://access:secret@bucket/path/model.pt?X-Amz-Signature=SECRET#frag"

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            client.record_scan_started([cloud_url], {"format": "json"})
            started_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert "model_names" not in started_props
            assert "model_references" not in started_props
            assert started_props["model_reference_types"] == ["s3:.pt"]
            assert started_props["file_extensions"] == [".pt"]
            assert "SECRET" not in json.dumps(started_props)
            assert "access:secret@" not in json.dumps(started_props)
            assert "bucket" not in json.dumps(started_props)
            assert "path/model.pt" not in json.dumps(started_props)

            client.record_file_type_detected(cloud_url, "pytorch")
            file_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert file_props["file_extension"] == ".pt"
            assert "model_name" not in file_props
            assert "model_reference" not in file_props
            assert file_props["model_reference_type"] == "s3:.pt"
            assert "SECRET" not in json.dumps(file_props)
            assert "access:secret@" not in json.dumps(file_props)
            assert "bucket" not in json.dumps(file_props)
            assert "path/model.pt" not in json.dumps(file_props)

            client.record_download_started("s3", cloud_url)
            download_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert download_props["domain"] == "s3"
            assert "model_name" not in download_props
            assert "model_reference" not in download_props
            assert download_props["model_reference_type"] == "s3:.pt"
            assert "SECRET" not in json.dumps(download_props)
            assert "access:secret@" not in json.dumps(download_props)
            assert "bucket" not in json.dumps(download_props)
            assert "path/model.pt" not in json.dumps(download_props)

    def test_telemetry_available_false_when_posthog_unavailable(self):
        """Telemetry should be unavailable when transport client is missing."""
        with (
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", False),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
            patch("modelaudit.telemetry._telemetry_client", None),
        ):
            mock_home.return_value = Path(temp_dir)
            assert is_telemetry_available() is False

    def test_enable_telemetry_initializes_transport_for_existing_client(self, tmp_path: Path) -> None:
        """Enabling telemetry should lazily initialize PostHog for an existing client."""
        mock_posthog = MagicMock()

        with (
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", True),
            patch("modelaudit.telemetry.Posthog", return_value=mock_posthog),
            patch("modelaudit.telemetry._telemetry_client", None),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = tmp_path
            config_dir = tmp_path / ".modelaudit"
            config_dir.mkdir()
            (config_dir / "user_config.json").write_text(json.dumps({"telemetry_enabled": False}))

            client = get_telemetry_client()
            assert client is not None
            assert client._posthog_client is None

            enable_telemetry()
            refreshed_client = get_telemetry_client()

            assert refreshed_client is not None
            assert refreshed_client._user_config.telemetry_enabled is True
            assert refreshed_client._posthog_client is mock_posthog
            assert is_telemetry_available() is True


class TestDataHandling:
    """Test data handling and sanitization."""

    def test_error_events_omit_free_form_text(self) -> None:
        """Error telemetry should retain categories, never exception or context prose."""
        mock_posthog = MagicMock()
        sensitive_error = "Invalid max-size: secret-model.pkl password=hunter2 alice@example.com"
        sensitive_context = "s3://access:secret@bucket/customer/model.pt?token=shortsecret"

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            client.record_scan_failed(0.5, sensitive_error)
            scan_failed_properties = mock_posthog.capture.call_args.kwargs["properties"]
            assert scan_failed_properties["error_type"] == "str"
            assert scan_failed_properties["error_category"] == "invalid_max_size"
            assert "error_message" not in scan_failed_properties

            client.record_error(ValueError(sensitive_error), sensitive_context)
            error_properties = mock_posthog.capture.call_args.kwargs["properties"]
            assert error_properties["error_type"] == "ValueError"
            assert error_properties["has_context"] is True
            assert "error_message" not in error_properties
            assert "context" not in error_properties

            serialized = json.dumps({"scan_failed": scan_failed_properties, "error": error_properties})
            assert sensitive_error not in serialized
            assert "secret-model.pkl" not in serialized
            assert "password=hunter2" not in serialized
            assert "alice@example.com" not in serialized
            assert sensitive_context not in serialized
            assert "shortsecret" not in serialized

    def test_scan_error_categories_do_not_depend_on_user_text(self) -> None:
        """Known failure prefixes should map to fixed telemetry values."""
        assert TelemetryClient._classify_scan_error("No matching paths") == "no_matching_paths"
        assert TelemetryClient._classify_scan_error("Invalid scanner selection: customer_alpha") == (
            "invalid_scanner_selection"
        )
        assert TelemetryClient._classify_scan_error("customer-specific failure") == "other"
        assert TelemetryClient._classify_scan_error(ValueError("customer-specific failure")) == "exception"


class TestPrivacyCompliance:
    """Test privacy and compliance features."""

    def test_no_file_content_collection(self):
        """Test that file contents are never collected."""
        # This test verifies our implementation doesn't collect file contents
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Inspect all record methods to ensure no file content collection
            methods_to_check = [
                "record_scan_started",
                "record_file_type_detected",
                "record_scanner_used",
                "record_issue_found",
            ]

            for method_name in methods_to_check:
                method = getattr(client, method_name)
                # Method signatures should not include content parameters
                assert "content" not in str(method.__annotations__)
                assert "data" not in str(method.__annotations__)


class TestConvenienceFunctions:
    """Test convenience functions for telemetry."""

    @patch("modelaudit.telemetry.get_telemetry_client")
    def test_record_event_function(self, mock_get_client):
        """Test the record_event convenience function."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

        mock_client.record_event.assert_called_once_with(TelemetryEvent.COMMAND_USED, {"command": "test"})

    @patch("modelaudit.telemetry.get_telemetry_client")
    def test_record_scan_started_function(self, mock_get_client):
        """Test the record_scan_started convenience function."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        paths = ["test.pkl"]
        options = {"format": "json"}

        record_scan_started(paths, options)

        mock_client.record_scan_started.assert_called_once_with(paths, options)


class TestTelemetryIntegration:
    """Test telemetry integration points."""

    def test_global_client_singleton(self):
        """Test that get_telemetry_client returns same instance."""
        client1 = get_telemetry_client()
        client2 = get_telemetry_client()

        assert client1 is client2

    def test_global_client_refreshes_when_runtime_changes(self, tmp_path: Path) -> None:
        """Runtime-sensitive singleton state should refresh between different environments."""
        mock_posthog = MagicMock()
        first_home = tmp_path / "first-home"
        second_home = tmp_path / "second-home"
        first_home.mkdir()
        second_home.mkdir()

        with patch("modelaudit.telemetry._telemetry_client", None):
            with (
                patch("modelaudit.telemetry.Path.home") as mock_home,
                patch.dict(os.environ, {"PROMPTFOO_DISABLE_TELEMETRY": "1"}, clear=False),
            ):
                mock_home.return_value = first_home
                first_client = get_telemetry_client()

            with (
                patch("modelaudit.telemetry.Path.home") as mock_home,
                patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
                patch("modelaudit.telemetry.POSTHOG_AVAILABLE", True),
                patch("modelaudit.telemetry.Posthog", return_value=mock_posthog),
                patch.dict(
                    os.environ,
                    {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                    clear=False,
                ),
            ):
                mock_home.return_value = second_home
                refreshed_client = get_telemetry_client()

            assert refreshed_client is not None
            assert refreshed_client is not first_client
            assert refreshed_client._posthog_client is mock_posthog

    def test_posthog_import_failure_handling(self):
        """Test that missing PostHog dependency is handled gracefully."""
        with (
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", False),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Should still work without PostHog
            assert client._posthog_client is None

    def test_core_scan_emits_issue_found_telemetry(self) -> None:
        """Core scans should emit issue telemetry for detected findings."""
        from modelaudit.core import scan_model_directory_or_file

        sample = Path(__file__).parent / "assets" / "samples" / "pickles" / "malicious_system_call.pkl"
        with (
            patch("modelaudit.core.record_issue_found") as mock_core_record_issue_found,
            patch("modelaudit.core_results.record_issue_found") as mock_results_record_issue_found,
        ):
            result = scan_model_directory_or_file(str(sample))

        assert len(result.issues) > 0
        assert mock_core_record_issue_found.call_count + mock_results_record_issue_found.call_count > 0


if __name__ == "__main__":
    pytest.main([__file__])
