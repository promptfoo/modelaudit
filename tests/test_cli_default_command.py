"""Test the default command behavior of the CLI."""

import tempfile
from pathlib import Path

from click.testing import CliRunner

from modelaudit.cli import DefaultCommandGroup, cli


class TestDefaultCommandGroup:
    """Test the DefaultCommandGroup class behavior."""

    def test_get_command_returns_none_for_unknown_commands(self):
        """Test that get_command returns None for unknown commands."""
        from click import Context

        group = DefaultCommandGroup()

        # Add a dummy command to the group
        @group.command("dummy")
        def dummy_cmd():
            pass

        ctx = Context(group)

        # Should return the command for known commands
        assert group.get_command(ctx, "dummy") is not None

        # Should return None for unknown commands
        assert group.get_command(ctx, "unknown") is None
        assert group.get_command(ctx, "model.pkl") is None
        assert group.get_command(ctx, "/path/to/file") is None

    def test_default_scan_command_with_file_path(self):
        """Test that providing a file path without command defaults to scan."""
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(b"test content")

        try:
            # Test without explicit scan command
            result = runner.invoke(cli, [str(tmp_path)])

            # Should not fail due to unknown command
            assert "No such command" not in result.output
            assert "Usage:" not in result.output or "error" not in result.output.lower()

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_default_scan_command_with_multiple_paths(self):
        """Test that providing multiple paths without command defaults to scan."""
        runner = CliRunner()
        with (
            tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp1,
            tempfile.NamedTemporaryFile(suffix=".h5", delete=False) as tmp2,
        ):
            tmp_path1 = Path(tmp1.name)
            tmp_path2 = Path(tmp2.name)
            tmp1.write(b"test content 1")
            tmp2.write(b"test content 2")

        try:
            # Test without explicit scan command
            result = runner.invoke(cli, [str(tmp_path1), str(tmp_path2)])

            # Should not fail due to unknown command
            assert "No such command" not in result.output
            assert result.exit_code != 2  # Exit code 2 typically indicates command not found

        finally:
            tmp_path1.unlink(missing_ok=True)
            tmp_path2.unlink(missing_ok=True)

    def test_explicit_scan_command_still_works(self):
        """Test that explicit scan command still works as expected."""
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(b"test content")

        try:
            # Test with explicit scan command
            result = runner.invoke(cli, ["scan", str(tmp_path)])

            # Should work normally
            assert "No such command" not in result.output

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_other_commands_work_normally(self):
        """Test that other commands like 'doctor' work without issues."""
        runner = CliRunner()

        # Test doctor command
        result = runner.invoke(cli, ["doctor"])
        assert result.exit_code == 0
        assert "ModelAudit Scanner Diagnostic Report" in result.output

    def test_invalid_command_shows_error(self):
        """Test that invalid commands are treated as paths and scanned."""
        runner = CliRunner()

        # Test with a string that looks like a command but isn't
        result = runner.invoke(cli, ["invalidcommand"])

        # With our default command behavior, this will be treated as a path to scan
        assert result.exit_code == 2  # Exit code 2 for scan errors (file not found)
        assert "Path does not exist: invalidcommand" in result.output

    def test_help_without_command(self):
        """Test that --help without command shows custom help."""
        runner = CliRunner()

        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

        # Should show our custom help format
        assert "modelaudit [OPTIONS] PATHS..." in result.output
        assert "modelaudit scan [OPTIONS] PATHS..." in result.output

    def test_options_before_paths(self):
        """Test that options work correctly with default command."""
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(b"test content")

        try:
            # Test with options before path
            result = runner.invoke(cli, ["--format", "json", str(tmp_path)])

            # Should work with default scan command
            assert "No such command" not in result.output

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_urls_as_default_arguments(self):
        """Test that URLs work with default command."""
        runner = CliRunner()

        # Test with a URL (won't actually download, but should parse correctly)
        result = runner.invoke(cli, ["https://example.com/model.pkl"])

        # Should not fail with "No such command"
        assert "No such command" not in result.output
