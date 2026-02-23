"""Tests for Python version warnings in __init__.py and cli.py."""

import importlib
import sys
import warnings
from unittest.mock import call, patch

import click

import modelaudit


class TestInitVersionWarning:
    """Tests for the warnings.warn() in modelaudit/__init__.py."""

    def test_warning_fires_on_old_python(self):
        """Should emit a warning when Python < 3.10."""
        fake_version = (3, 9, 0, "final", 0)
        with patch.object(sys, "version_info", fake_version), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            importlib.reload(modelaudit)

        warning_messages = [str(w.message) for w in caught]
        assert any("Python 3.10+" in msg for msg in warning_messages)
        assert any("3.9" in msg for msg in warning_messages)

    def test_no_warning_on_supported_python(self):
        """Should NOT emit a warning when Python >= 3.10."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            importlib.reload(modelaudit)

        warning_messages = [str(w.message) for w in caught]
        assert not any("Python 3.10+" in msg for msg in warning_messages)


class TestCliVersionWarning:
    """Tests for the click.echo warning in cli.py main()."""

    def test_cli_warning_on_old_python(self):
        """main() should echo a yellow warning when Python < 3.10."""
        fake_version = (3, 9, 0, "final", 0)
        with (
            patch("modelaudit.cli.sys") as mock_sys,
            patch("modelaudit.cli.click.echo") as mock_echo,
            patch("modelaudit.cli.cli"),
        ):
            mock_sys.version_info = fake_version
            from modelaudit.cli import main

            main()

        assert mock_echo.call_count >= 1
        first_call = mock_echo.call_args_list[0]
        assert first_call == call(
            click.style(
                "WARNING: modelaudit requires Python 3.10+, but you are running "
                "Python 3.9. "
                "Please upgrade: https://www.promptfoo.dev/docs/model-audit/",
                fg="yellow",
            ),
            err=True,
        )

    def test_cli_no_warning_on_supported_python(self):
        """main() should NOT echo a warning when Python >= 3.10."""
        with (
            patch("modelaudit.cli.click.echo") as mock_echo,
            patch("modelaudit.cli.cli"),
        ):
            from modelaudit.cli import main

            main()

        for c in mock_echo.call_args_list:
            if c.kwargs.get("err") or (len(c.args) > 1 and c.args[1]):
                msg = str(c.args[0]) if c.args else ""
                assert "modelaudit requires Python 3.10+" not in msg
