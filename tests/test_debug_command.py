"""Tests for the debug command."""

import json
import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli


class TestDebugCommand:
    """Tests for the modelaudit debug command."""

    @pytest.fixture
    def runner(self):
        """Create a CLI runner."""
        return CliRunner()

    def test_debug_command_success(self, runner):
        """Debug command should always succeed."""
        result = runner.invoke(cli, ["debug"])
        assert result.exit_code == 0
        assert "version" in result.output

    def test_debug_json_output_is_valid_json(self, runner):
        """JSON output should be valid and parseable."""
        result = runner.invoke(cli, ["debug", "--json"])
        assert result.exit_code == 0

        # Should be valid JSON
        parsed = json.loads(result.output)
        assert isinstance(parsed, dict)

    def test_debug_json_output_has_required_fields(self, runner):
        """JSON output should have all required fields."""
        result = runner.invoke(cli, ["debug", "--json"])
        assert result.exit_code == 0

        parsed = json.loads(result.output)

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

    def test_debug_platform_info_structure(self, runner):
        """Platform info should have expected structure."""
        result = runner.invoke(cli, ["debug", "--json"])
        parsed = json.loads(result.output)

        platform_info = parsed["platform"]
        assert "os" in platform_info
        assert "release" in platform_info
        assert "arch" in platform_info
        assert "pythonVersion" in platform_info
        assert "pythonExecutable" in platform_info

    def test_debug_install_info_structure(self, runner):
        """Install info should have expected structure."""
        result = runner.invoke(cli, ["debug", "--json"])
        parsed = json.loads(result.output)

        install_info = parsed["install"]
        # editable should always be present
        assert "editable" in install_info

    def test_debug_env_info_structure(self, runner):
        """Environment info should have expected structure."""
        result = runner.invoke(cli, ["debug", "--json"])
        parsed = json.loads(result.output)

        env_info = parsed["env"]
        assert "telemetryDisabled" in env_info
        assert "noColor" in env_info
        assert "ciEnvironment" in env_info
        assert "jfrogConfigured" in env_info
        assert "mlflowConfigured" in env_info

    def test_debug_scanner_info_structure(self, runner):
        """Scanner info should have expected structure."""
        result = runner.invoke(cli, ["debug", "--json"])
        parsed = json.loads(result.output)

        scanner_info = parsed["scanners"]
        assert "total" in scanner_info
        assert "available" in scanner_info
        assert "failed" in scanner_info
        assert "successRate" in scanner_info

        # Total should be greater than 0
        assert scanner_info["total"] > 0
        # Available should be <= total
        assert scanner_info["available"] <= scanner_info["total"]

    def test_debug_scanner_has_available_list(self, runner):
        """Scanner info should include list of available scanners."""
        result = runner.invoke(cli, ["debug", "--json"])
        parsed = json.loads(result.output)

        scanner_info = parsed["scanners"]
        assert "availableList" in scanner_info
        assert isinstance(scanner_info["availableList"], list)
        # Should have at least some scanners
        assert len(scanner_info["availableList"]) > 0

    def test_debug_cache_info_structure(self, runner):
        """Cache info should have expected structure."""
        result = runner.invoke(cli, ["debug", "--json"])
        parsed = json.loads(result.output)

        cache_info = parsed["cache"]
        # Should have either enabled=True with stats, or enabled=False with error
        if cache_info.get("enabled"):
            assert "directory" in cache_info
            assert "entries" in cache_info
            assert "sizeMb" in cache_info
        else:
            assert "error" in cache_info

    def test_debug_config_info_structure(self, runner):
        """Config info should have expected structure."""
        result = runner.invoke(cli, ["debug", "--json"])
        parsed = json.loads(result.output)

        config_info = parsed["config"]
        # Should have both shared and modelaudit config paths
        if "error" not in config_info:
            assert "sharedConfigPath" in config_info
            assert "sharedConfigExists" in config_info
            assert "modelauditConfigPath" in config_info
            assert "modelauditConfigExists" in config_info

    def test_debug_never_exposes_api_keys(self, runner):
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

    def test_debug_verbose_includes_more_details(self, runner):
        """Verbose mode should include additional details when there are scanner failures."""
        result = runner.invoke(cli, ["debug", "--verbose", "--json"])
        assert result.exit_code == 0

        parsed = json.loads(result.output)
        scanner_info = parsed["scanners"]

        # If there are failed scanners, verbose should include details
        if scanner_info.get("failed", 0) > 0:
            assert "failedList" in scanner_info
            assert "failedDetails" in scanner_info

    def test_debug_pretty_output_has_quick_diagnosis(self, runner):
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

    def test_debug_pretty_output_has_issue_url(self, runner):
        """Pretty output should include GitHub issues URL."""
        result = runner.invoke(cli, ["debug"])
        assert result.exit_code == 0

        assert "github.com" in result.output
        assert "issues" in result.output

    def test_debug_handles_missing_cache_gracefully(self, runner):
        """Debug should handle cache errors gracefully."""
        # Even if cache has issues, debug should not fail
        result = runner.invoke(cli, ["debug", "--json"])
        assert result.exit_code == 0

        parsed = json.loads(result.output)
        # Cache section should exist and have either enabled or error
        assert "cache" in parsed
        cache_info = parsed["cache"]
        assert "enabled" in cache_info or "error" in cache_info

    def test_debug_env_detection_ci(self, runner):
        """Debug should detect CI environment."""
        with patch.dict(os.environ, {"CI": "true"}):
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["env"]["ciEnvironment"] is True

    def test_debug_env_detection_no_color(self, runner):
        """Debug should detect NO_COLOR environment variable."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["env"]["noColor"] is True

    def test_debug_env_detection_jfrog(self, runner):
        """Debug should detect JFrog configuration (presence only)."""
        with patch.dict(os.environ, {"JFROG_API_TOKEN": "fake-token"}):
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["env"]["jfrogConfigured"] is True
        # But should not expose the actual token
        assert "fake-token" not in result.output

    def test_debug_env_detection_mlflow(self, runner):
        """Debug should detect MLflow configuration."""
        with patch.dict(os.environ, {"MLFLOW_TRACKING_URI": "http://localhost:5000"}):
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["env"]["mlflowConfigured"] is True

    def test_debug_proxy_detection(self, runner):
        """Debug should detect proxy settings."""
        with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy:8080"}):
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        # Proxy without credentials should be shown as-is
        assert parsed["env"]["httpProxy"] == "http://proxy:8080"

    def test_debug_proxy_redacts_credentials(self, runner):
        """Debug should redact credentials from proxy URLs."""
        with patch.dict(os.environ, {"HTTP_PROXY": "http://user:secret@proxy:8080"}):
            result = runner.invoke(cli, ["debug", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        # Credentials should be stripped, only host:port remains
        assert parsed["env"]["httpProxy"] == "http://proxy:8080"
        # Secret should never appear in output
        assert "secret" not in result.output
        assert "user:" not in result.output

    def test_debug_path_privacy(self, runner):
        """Debug should use ~ for home directory paths."""
        result = runner.invoke(cli, ["debug", "--json"])
        assert result.exit_code == 0

        parsed = json.loads(result.output)

        # Config path should use ~
        config_info = parsed.get("config", {})
        shared_config_path = config_info.get("sharedConfigPath")
        if shared_config_path:
            assert shared_config_path.startswith("~") or "error" in config_info

        # Cache directory should use ~
        cache_info = parsed.get("cache", {})
        if cache_info.get("enabled") and cache_info.get("directory"):
            assert cache_info["directory"].startswith("~")

    def test_debug_command_is_fast(self, runner):
        """Debug command should complete quickly (under 10 seconds)."""
        import time

        start = time.time()
        result = runner.invoke(cli, ["debug", "--json"])
        duration = time.time() - start

        assert result.exit_code == 0
        # Should be fast - under 10 seconds even with scanner loading
        # (relaxed from 5s to account for CI variance)
        assert duration < 10.0, f"Debug command took {duration:.2f}s, expected < 10s"

    def test_debug_auth_info_structure(self, runner):
        """Auth info should have expected structure."""
        result = runner.invoke(cli, ["debug", "--json"])
        parsed = json.loads(result.output)

        auth_info = parsed["auth"]
        assert "authenticated" in auth_info
        assert "delegatedFromPromptfoo" in auth_info
        # Should NOT expose internal URLs
        assert "apiHost" not in auth_info
        assert "appUrl" not in auth_info

    def test_debug_help_text(self, runner):
        """Debug command should have helpful description."""
        result = runner.invoke(cli, ["debug", "--help"])
        assert result.exit_code == 0
        assert "troubleshooting" in result.output.lower()
        assert "bug" in result.output.lower() or "issue" in result.output.lower()

    def test_debug_dependencies_structure(self, runner):
        """Dependencies info should have expected structure."""
        result = runner.invoke(cli, ["debug", "--json"])
        assert result.exit_code == 0

        parsed = json.loads(result.output)

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

    def test_debug_dependencies_has_numpy(self, runner):
        """Dependencies should include numpy version (since it's a core dependency)."""
        result = runner.invoke(cli, ["debug", "--json"])
        assert result.exit_code == 0

        parsed = json.loads(result.output)
        deps = parsed.get("dependencies", {})
        ml_frameworks = deps.get("mlFrameworks", {})

        # NumPy should be listed in ML frameworks
        assert "numpy" in ml_frameworks

    def test_debug_pretty_output_shows_ml_frameworks(self, runner):
        """Pretty output should show ML framework summary."""
        result = runner.invoke(cli, ["debug"])
        assert result.exit_code == 0

        # Should mention ML frameworks in quick diagnosis
        assert "ML frameworks" in result.output or "No ML frameworks" in result.output
