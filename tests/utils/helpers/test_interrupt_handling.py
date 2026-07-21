"""Test interrupt handling functionality."""

import builtins
import runpy
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


def test_module_entrypoint_handles_interrupt_during_cli_import(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Startup Ctrl+C should not leak a raw import traceback."""
    original_import = builtins.__import__

    def interrupt_cli_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "cli" and level == 1:
            raise KeyboardInterrupt
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", interrupt_cli_import)

    with pytest.raises(SystemExit, match="2"):
        runpy.run_module("modelaudit", run_name="__main__")

    assert capsys.readouterr().err == "Scan interrupted by user\n"


def test_package_init_defers_scanner_result_imports() -> None:
    """Package discovery must stay lightweight until the startup guard runs."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import modelaudit, sys; assert 'modelaudit.scanner_results' not in sys.modules",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_interrupt_handler_initialization_and_context() -> None:
    """Test interrupt handler reset, initialization, and context behavior."""
    from modelaudit.utils.helpers.interrupt_handler import (
        get_interrupt_handler,
        interruptible_scan,
        reset_interrupt,
    )

    # Test reset
    reset_interrupt()
    handler = get_interrupt_handler()
    assert not handler.is_interrupted()

    # Test signal handling context
    with interruptible_scan() as h:
        assert h == handler
        # Can't easily test actual signal handling in unit tests


def test_interrupt_flag_detection_and_exception_raising() -> None:
    """Test interrupt flag detection and KeyboardInterrupt raising."""
    from modelaudit.utils.helpers.interrupt_handler import (
        check_interrupted,
        get_interrupt_handler,
        is_interrupted,
        reset_interrupt,
    )

    reset_interrupt()
    assert not is_interrupted()

    # Manually set interrupt flag
    handler = get_interrupt_handler()
    handler._interrupted.set()

    assert is_interrupted()
    with pytest.raises(KeyboardInterrupt):
        check_interrupted()

    # Reset for cleanup
    reset_interrupt()


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT handling differs on Windows")
def test_interrupt_during_scan() -> None:
    """Test interrupting a scan in progress."""
    import pickle

    # Create test files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create several pickle files with larger data to slow down scan
        for i in range(50):  # More files
            file_path = Path(temp_dir) / f"model_{i}.pkl"
            with open(file_path, "wb") as f:
                # Larger data to make scanning take longer
                data = {"model_id": i, "weights": [0.1, 0.2, 0.3] * 10000, "large_data": list(range(10000))}
                pickle.dump(data, f)

        # Start scan in subprocess
        cmd = [sys.executable, "-m", "modelaudit", "scan", temp_dir]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Give it time to start scanning
        time.sleep(1.0)  # Increased delay

        # Send interrupt
        process.send_signal(signal.SIGINT)

        # Wait for completion
        stdout, stderr = process.communicate(timeout=10)

        # Check for graceful shutdown
        assert "Scan interrupted by user" in stdout or "Scan interrupted by user" in stderr, (
            f"Interrupt message not found. stdout: {stdout}, stderr: {stderr}"
        )

        # Exit code should be 2 (errors) or 1 (issues found)
        assert process.returncode in [1, 2]
