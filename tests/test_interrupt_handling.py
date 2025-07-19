"""Test interrupt handling functionality."""

import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


def test_interrupt_handler_basic():
    """Test basic interrupt handler functionality."""
    from modelaudit.interrupt_handler import (
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


def test_interrupt_check():
    """Test interrupt checking."""
    from modelaudit.interrupt_handler import (
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
def test_interrupt_during_scan():
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
