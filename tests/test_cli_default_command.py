"""Test the default command behavior of the CLI."""

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

    def test_default_scan_command_with_file_path(self, tmp_path: Path) -> None:
        """Test that providing a file path without command defaults to scan."""
        runner = CliRunner()
        model_path = tmp_path / "model.pkl"
        model_path.touch(mode=0o600)
        model_path.write_bytes(b"test content")

        # Test without explicit scan command
        result = runner.invoke(cli, [str(model_path)])

        # Should not fail due to unknown command
        assert "No such command" not in result.output
        assert "Usage:" not in result.output or "error" not in result.output.lower()
        # Delete before fixture teardown to catch leaked file handles.
        model_path.unlink(missing_ok=True)

    def test_default_scan_command_with_multiple_paths(self, tmp_path: Path) -> None:
        """Test that providing multiple paths without command defaults to scan."""
        runner = CliRunner()
        model_path1 = tmp_path / "model.pkl"
        model_path2 = tmp_path / "model.h5"
        model_path1.touch(mode=0o600)
        model_path2.touch(mode=0o600)
        model_path1.write_bytes(b"test content 1")
        model_path2.write_bytes(b"test content 2")

        # Test without explicit scan command
        result = runner.invoke(cli, [str(model_path1), str(model_path2)])

        # Should not fail due to unknown command
        assert "No such command" not in result.output
        assert result.exit_code != 2  # Exit code 2 typically indicates command not found
        model_path1.unlink(missing_ok=True)
        model_path2.unlink(missing_ok=True)

    def test_explicit_scan_command_still_works(self, tmp_path: Path) -> None:
        """Test that explicit scan command still works as expected."""
        runner = CliRunner()
        model_path = tmp_path / "model.pkl"
        model_path.touch(mode=0o600)
        model_path.write_bytes(b"test content")

        # Test with explicit scan command
        result = runner.invoke(cli, ["scan", str(model_path)])

        # Should work normally
        assert "No such command" not in result.output
        model_path.unlink(missing_ok=True)

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

    def test_options_before_paths(self, tmp_path: Path) -> None:
        """Test that options work correctly with default command."""
        runner = CliRunner()
        model_path = tmp_path / "model.pkl"
        model_path.touch(mode=0o600)
        model_path.write_bytes(b"test content")

        # Test with options before path
        result = runner.invoke(cli, ["--format", "json", str(model_path)])

        # Should work with default scan command
        assert "No such command" not in result.output
        model_path.unlink(missing_ok=True)

    def test_urls_as_default_arguments(self):
        """Test that URLs work with default command."""
        runner = CliRunner()

        # Test with a URL (won't actually download, but should parse correctly)
        result = runner.invoke(cli, ["https://example.com/model.pkl"])

        # Should not fail with "No such command"
        assert "No such command" not in result.output
