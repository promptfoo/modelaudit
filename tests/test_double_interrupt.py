"""Test double interrupt functionality."""

import signal
import threading
import time
import unittest
from unittest.mock import patch

from modelaudit.interrupt_handler import InterruptHandler, get_interrupt_handler, interruptible_scan


class TestDoubleInterrupt(unittest.TestCase):
    """Test cases for double interrupt (Ctrl+C) functionality."""

    def setUp(self):
        """Reset interrupt handler state before each test."""
        handler = get_interrupt_handler()
        handler.reset()
        # Ensure not active
        handler._active = False

    def tearDown(self):
        """Clean up after each test."""
        handler = get_interrupt_handler()
        handler.reset()
        handler._active = False

    def test_single_interrupt_graceful_shutdown(self):
        """Test that single interrupt triggers graceful shutdown."""
        handler = InterruptHandler()

        # Simulate first interrupt
        handler._signal_handler(signal.SIGINT, None)

        # Should be marked as interrupted
        self.assertTrue(handler.is_interrupted())

        # check_interrupted should raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            handler.check_interrupted()

    def test_double_interrupt_immediate_exit(self):
        """Test that double interrupt causes immediate exit."""
        handler = InterruptHandler()

        # Mock os._exit to prevent actual process termination
        with patch("os._exit") as mock_exit:
            # First interrupt
            handler._signal_handler(signal.SIGINT, None)
            self.assertTrue(handler.is_interrupted())

            # Second interrupt immediately
            handler._signal_handler(signal.SIGINT, None)

            # Should have called os._exit with code 130
            mock_exit.assert_called_once_with(130)

    def test_reset_clears_state(self):
        """Test that reset() clears interrupt state."""
        handler = InterruptHandler()

        # Set up some state
        handler._signal_handler(signal.SIGINT, None)
        self.assertTrue(handler.is_interrupted())

        # Reset
        handler.reset()

        # State should be cleared
        self.assertFalse(handler.is_interrupted())

    def test_interruptible_scan_context_manager(self):
        """Test that interruptible_scan context manager works correctly."""
        original_handler = signal.getsignal(signal.SIGINT)

        with interruptible_scan() as handler:
            # Handler should be installed
            current_handler = signal.getsignal(signal.SIGINT)
            self.assertNotEqual(current_handler, original_handler)

            # Handler should be reset
            self.assertFalse(handler.is_interrupted())

        # Original handler should be restored
        restored_handler = signal.getsignal(signal.SIGINT)
        self.assertEqual(restored_handler, original_handler)

    def test_thread_safety(self):
        """Test that interrupt handler is thread-safe."""
        handler = InterruptHandler()
        results = []
        started_event = threading.Event()

        def worker():
            """Worker thread that checks for interrupts."""
            started_event.set()  # Signal that worker has started
            try:
                for _ in range(10):
                    handler.check_interrupted()
                    time.sleep(0.01)
                results.append("completed")
            except KeyboardInterrupt:
                results.append("interrupted")

        # Start worker thread
        thread = threading.Thread(target=worker)
        thread.start()

        # Wait for worker to start, then trigger interrupt
        started_event.wait(timeout=1.0)
        handler._signal_handler(signal.SIGINT, None)

        # Wait for thread to finish
        thread.join(timeout=2.0)

        # Ensure thread completed (either normally or interrupted)
        self.assertFalse(thread.is_alive(), "Thread should have finished")

        # Worker should have been interrupted
        self.assertEqual(results, ["interrupted"])

    def test_nested_contexts(self):
        """Test that nested interruptible_scan contexts work correctly."""
        handler = get_interrupt_handler()

        # Ensure clean state before test
        handler.reset()

        with interruptible_scan():
            self.assertTrue(handler._active)

            # Nested context should not interfere
            with interruptible_scan():
                self.assertTrue(handler._active)

            # Should still be active after inner context exits
            self.assertTrue(handler._active)

        # Should be inactive after outer context exits
        self.assertFalse(handler._active)


if __name__ == "__main__":
    unittest.main()
