"""Tests for the debug command."""

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli


@pytest.mark.unit
class TestDebugCommand:
    """Tests for the modelaudit debug command."""

    @pytest.fixture(autouse=True)
    def isolated_debug_environment(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Debug tests never inspect the host's credentials, proxies, or config."""
        for name in tuple(os.environ):
            if any(
                marker in name.upper()
                for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD", "PROXY", "AUTH", "CREDENTIAL")
            ):
                monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    @pytest.fixture
    def runner(self) -> CliRunner:
        """Create a CLI runner."""
        return CliRunner()

    @pytest.fixture
    def parsed(self, runner: CliRunner) -> dict[str, Any]:
        """Invoke JSON diagnostics anew for each requesting test."""
        result = runner.invoke(cli, ["debug", "--json"])
        assert result.exit_code == 0
        parsed: dict[str, Any] = json.loads(result.output)
        return parsed

    def test_debug_command_success(self, runner: CliRunner) -> None:
        """Debug command should always succeed."""
        result = runner.invoke(cli, ["debug"])
        assert result.exit_code == 0
        assert "version" in result.output

    def test_debug_json_output_is_valid_json(self, parsed: dict[str, Any]) -> None:
        """JSON output should be valid and parseable."""

        # Should be valid JSON
        assert isinstance(parsed, dict)

    def test_debug_json_output_has_required_fields(self, parsed: dict[str, Any]) -> None:
        """JSON output should have all required fields."""

        # Check all required top-level fields
        assert "version" in parsed
        assert "platform" in parsed
        assert "install" in parsed
        assert "dependencies" in parsed
        assert "env" in parsed
        assert "auth" in parsed
        assert "scanners" in parsed
        assert "cache" in parsed
        assert "config" in parsed

    def test_debug_platform_info_structure(self, parsed: dict[str, Any]) -> None:
        """Platform info should have expected structure."""

        platform_info = parsed["platform"]
        assert "os" in platform_info
        assert "release" in platform_info
        assert "arch" in platform_info
        assert "pythonVersion" in platform_info
        assert "pythonExecutable" in platform_info
        assert "pythonRecursionLimit" in platform_info
        assert isinstance(platform_info["pythonRecursionLimit"], int)
        assert platform_info["pythonRecursionLimit"] > 0

    def test_debug_install_info_structure(self, parsed: dict[str, Any]) -> None:
        """Install info should have expected structure."""

        install_info = parsed["install"]
        # editable should always be present
        assert "editable" in install_info

    def test_debug_env_info_structure(self, parsed: dict[str, Any]) -> None:
        """Environment info should have expected structure."""

        env_info = parsed["env"]
        assert "telemetryDisabled" in env_info
        assert "noColor" in env_info
        assert "ciEnvironment" in env_info
        assert "jfrogConfigured" in env_info
        assert "mlflowConfigured" in env_info

    def test_debug_scanner_info_structure(self, parsed: dict[str, Any]) -> None:
        """Scanner info should have expected structure."""

        scanner_info = parsed["scanners"]
        assert "total" in scanner_info
        assert "available" in scanner_info
        assert "failed" in scanner_info
        assert "successRate" in scanner_info

        # Total should be greater than 0
        assert scanner_info["total"] > 0
        # Available should be <= total
        assert scanner_info["available"] <= scanner_info["total"]

    def test_debug_scanner_has_available_list(self, parsed: dict[str, Any]) -> None:
        """Scanner info should include list of available scanners."""

        scanner_info = parsed["scanners"]
        assert "availableList" in scanner_info
        assert isinstance(scanner_info["availableList"], list)
        # Should have at least some scanners
        assert len(scanner_info["availableList"]) > 0

    def test_debug_cache_info_structure(self, parsed: dict[str, Any]) -> None:
        """Cache info should have expected structure."""

        cache_info = parsed["cache"]
        # Should have either enabled=True with stats, or enabled=False with error
        if cache_info.get("enabled"):
            assert "directory" in cache_info
            assert "entries" in cache_info
            assert "sizeMb" in cache_info
        else:
            assert "error" in cache_info

    def test_debug_config_info_structure(self, parsed: dict[str, Any]) -> None:
        """Config info should have expected structure."""

        config_info = parsed["config"]
        # Should have both shared and modelaudit config paths
        if "error" not in config_info:
            assert "sharedConfigPath" in config_info
            assert "sharedConfigExists" in config_info
            assert "modelauditConfigPath" in config_info
            assert "modelauditConfigExists" in config_info

    def test_debug_never_exposes_api_keys(self, runner: CliRunner) -> None:
        """Ensure no API keys or tokens appear in output."""
        # Set a fake API key in environment
        with patch.dict(os.environ, {"MODELAUDIT_API_KEY": "secret-test-key-12345"}):
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        output_lower = result.output.lower()

        # Should not contain the actual key value
        assert "secret-test-key-12345" not in result.output
        # Should not have fields that expose keys
        assert '"apikey"' not in output_lower
        assert '"token"' not in output_lower
        assert '"secret"' not in output_lower

    def test_debug_verbose_includes_more_details(self, runner: CliRunner) -> None:
        """Verbose mode should include additional details when there are scanner failures."""
        result = runner.invoke(cli, ["debug", "--verbose", "--json"])
        assert result.exit_code == 0

        parsed = json.loads(result.output)
        scanner_info = parsed["scanners"]

        # If there are failed scanners, verbose should include details
        if scanner_info.get("failed", 0) > 0:
            assert "failedList" in scanner_info
            assert "failedDetails" in scanner_info

    def test_debug_pretty_output_has_quick_diagnosis(self, runner: CliRunner) -> None:
        """Pretty output should include quick diagnosis section."""
        result = runner.invoke(cli, ["debug"])
        assert result.exit_code == 0

        # Should have header
        assert "ModelAudit Debug Information" in result.output
        # Should have quick diagnosis
        assert "Quick diagnosis:" in result.output
        # Should have Python version
        assert "Python" in result.output
        # Should mention scanners
        assert "scanners" in result.output

    def test_debug_pretty_output_requires_review_before_sharing(self, runner: CliRunner) -> None:
        """Raw diagnostics should explain what to check before filing an issue."""
        with patch.dict(os.environ, {"HTTP_PROXY": "http://user:secret@proxy:8080"}):
            result = runner.invoke(cli, ["debug"])
        assert result.exit_code == 0

        assert "http://user:secret@proxy:8080" in result.output
        assert "Inspect this output and remove sensitive values before sharing" in result.output
        assert "https://github.com/promptfoo/modelaudit/issues" in result.output

    def test_debug_handles_missing_cache_gracefully(self, parsed: dict[str, Any]) -> None:
        """Debug should handle cache errors gracefully."""
        # Even if cache has issues, debug should not fail

        # Cache section should exist and have either enabled or error
        assert "cache" in parsed
        cache_info = parsed["cache"]
        assert "enabled" in cache_info or "error" in cache_info

    @pytest.mark.parametrize(
        ("name", "value", "field"),
        [
            # Debug should detect CI environment.
            pytest.param("CI", "true", "ciEnvironment", id="ci"),
            # Debug should detect NO_COLOR environment variable.
            pytest.param("NO_COLOR", "1", "noColor", id="no_color"),
            # Debug should detect JFrog configuration (presence only).
            pytest.param("JFROG_API_TOKEN", "fake-token", "jfrogConfigured", id="jfrog"),
            # Debug should detect MLflow configuration.
            pytest.param("MLFLOW_TRACKING_URI", "http://localhost:5000", "mlflowConfigured", id="mlflow"),
        ],
    )
    def test_debug_env_detection(self, runner: CliRunner, name: str, value: str, field: str) -> None:
        """Configured environment flags should be JSON booleans."""
        with patch.dict(os.environ, {name: value}):
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["env"][field] is True
        if name == "JFROG_API_TOKEN":
            # But should not expose the actual token
            assert value not in result.output

    @pytest.mark.parametrize(
        "proxy",
        [
            # Proxy without credentials should be shown as-is.
            pytest.param("http://proxy:8080", id="without_credentials"),
            # Debug reports configured proxy URLs as provided.
            pytest.param("http://user:secret@proxy:8080", id="preserves_credentials"),
        ],
    )
    def test_debug_proxy_detection(self, runner: CliRunner, proxy: str) -> None:
        """Debug should detect proxy settings."""
        with patch.dict(os.environ, {"HTTP_PROXY": proxy}):
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["env"]["httpProxy"] == proxy

    @pytest.mark.parametrize("outside_home", [False, True])
    def test_debug_paths_preserve_configured_paths(self, runner: CliRunner, tmp_path: Path, outside_home: bool) -> None:
        """Debug shows actual paths while filesystem checks keep using those paths."""
        base = tmp_path.parent / "outside-home" if outside_home else tmp_path
        shared_config_dir = base / "shared-config"
        cache_dir = base / "cache"
        with (
            patch("modelaudit.cli.get_config_directory_path", return_value=str(shared_config_dir)),
            patch("modelaudit.cache.get_cache_manager") as get_cache_manager,
        ):
            manager = get_cache_manager.return_value
            manager.cache.cache_dir = cache_dir
            manager.get_stats.return_value = {}
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        config_info = parsed["config"]
        assert config_info["sharedConfigPath"] == str(shared_config_dir / "promptfoo.yaml")
        assert config_info["sharedConfigExists"] == (shared_config_dir / "promptfoo.yaml").exists()
        assert config_info["modelauditConfigPath"] == str(tmp_path / ".modelaudit" / "user_config.json")
        assert config_info["modelauditConfigExists"] == (tmp_path / ".modelaudit" / "user_config.json").exists()
        assert parsed["cache"]["directory"] == str(cache_dir)

    def test_debug_command_is_fast(self, runner: CliRunner) -> None:
        """Debug command should complete quickly (under 10 seconds)."""
        import time

        start = time.time()
        result = runner.invoke(cli, ["debug", "--json"])
        duration = time.time() - start

        assert result.exit_code == 0
        # Should be fast - under 10 seconds even with scanner loading
        # (relaxed from 5s to account for CI variance)
        assert duration < 10.0, f"Debug command took {duration:.2f}s, expected < 10s"

    def test_debug_auth_info_structure(self, parsed: dict[str, Any]) -> None:
        """Auth info should have expected structure."""

        auth_info = parsed["auth"]
        assert "authenticated" in auth_info
        assert "delegatedFromPromptfoo" in auth_info
        # Should NOT expose internal URLs
        assert "apiHost" not in auth_info
        assert "appUrl" not in auth_info

    def test_debug_help_text(self, runner: CliRunner) -> None:
        """Debug command should have helpful description."""
        result = runner.invoke(cli, ["debug", "--help"])
        assert result.exit_code == 0
        assert "troubleshooting" in result.output.lower()
        assert "bug" in result.output.lower() or "issue" in result.output.lower()
        assert "raw configuration values" in result.output
        assert "remove sensitive values" in " ".join(result.output.split())

    def test_debug_dependencies_structure(self, parsed: dict[str, Any]) -> None:
        """Dependencies info should have expected structure."""

        # Dependencies section should exist
        assert "dependencies" in parsed
        deps = parsed["dependencies"]

        # Should have categorized dependencies
        assert "core" in deps
        assert "mlFrameworks" in deps
        assert "serialization" in deps
        assert "utilities" in deps

        # Core dependencies should have at least click (always installed)
        assert "click" in deps["core"]

    def test_debug_dependencies_has_numpy(self, parsed: dict[str, Any]) -> None:
        """Dependencies should include numpy version (since it's a core dependency)."""

        deps = parsed.get("dependencies", {})
        ml_frameworks = deps.get("mlFrameworks", {})

        # NumPy should be listed in ML frameworks
        assert "numpy" in ml_frameworks

    def test_debug_pretty_output_shows_ml_frameworks(self, runner: CliRunner) -> None:
        """Pretty output should show ML framework summary."""
        result = runner.invoke(cli, ["debug"])
        assert result.exit_code == 0

        # Should mention ML frameworks in quick diagnosis
        assert "ML frameworks" in result.output or "No ML frameworks" in result.output
