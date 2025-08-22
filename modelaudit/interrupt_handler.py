"""Interrupt handling for ModelAudit scanning operations.

This module provides centralized interrupt handling for graceful shutdown
of scanning operations. It captures SIGINT (Ctrl+C) and SIGTERM signals
and allows scanners to check for interruption at safe points.

The handler supports:
- Graceful shutdown on first Ctrl+C
- Immediate termination on second Ctrl+C (if interrupt is already pending)

Usage:
    # In scanning loops:
    from modelaudit.interrupt_handler import check_interrupted

    for file in files:
        check_interrupted()  # Raises KeyboardInterrupt if interrupted
        scan_file(file)

    # For main scanning context:
    from modelaudit.interrupt_handler import interruptible_scan

    with interruptible_scan() as handler:
        # Signal handlers are installed
        perform_scanning()
        # Signal handlers are restored on exit
"""

import contextlib
import logging
import os
import signal
import threading
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("modelaudit.interrupt")


class InterruptHandler:
    """Manages interrupt signals and provides a way to check if scanning should stop.

    This class is thread-safe and handles proper installation/restoration of signal
    handlers. It uses a threading.Event to track interrupt state across threads.

    On the first interrupt (Ctrl+C), it initiates graceful shutdown. If a second
    interrupt is received while the first is still pending, it performs immediate termination.
    """

    def __init__(self) -> None:
        """Initialize the interrupt handler."""
        self._interrupted = threading.Event()
        self._original_sigint_handler: Any = None
        self._original_sigterm_handler: Any = None
        self._lock = threading.Lock()
        self._active = False

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle interrupt signals.

        Args:
            signum: Signal number (SIGINT=2, SIGTERM=15)
            frame: Current stack frame (unused)
        """
        if self._interrupted.is_set():
            # Already interrupted - force immediate termination
            logger.warning("Second interrupt received - forcing immediate termination")
            os._exit(130)  # 130 is the standard exit code for SIGINT
        else:
            # First interrupt - initiate graceful shutdown
            logger.info(f"Signal {signum} received, initiating graceful shutdown")
            logger.info("Press Ctrl+C again to force immediate termination")
            self._interrupted.set()

    def is_interrupted(self) -> bool:
        """Check if an interrupt has been requested.

        Returns:
            True if an interrupt signal was received, False otherwise
        """
        return self._interrupted.is_set()

    def reset(self) -> None:
        """Reset the interrupt state."""
        self._interrupted.clear()

    def check_interrupted(self) -> None:
        """Check if interrupted and raise KeyboardInterrupt if so.

        This method should be called periodically during long-running operations
        to allow for graceful interruption.

        Raises:
            KeyboardInterrupt: If an interrupt signal was received
        """
        if self.is_interrupted():
            raise KeyboardInterrupt("Scan interrupted by user")

    @contextmanager
    def install_handlers(self) -> Generator[None, None, None]:
        """Context manager to install and uninstall signal handlers.

        This ensures signal handlers are properly restored even if an
        exception occurs. Handles nested contexts gracefully.

        Yields:
            None
        """
        # Check if already active outside the lock to avoid deadlock
        if self._active:
            # Already active, just yield without acquiring lock
            yield
            return

        # Not active, need to acquire lock and install handlers
        with self._lock:
            # Double-check inside lock (in case state changed while acquiring lock)
            if self._active:
                # Another thread activated it while we were waiting for the lock
                yield  # type: ignore[unreachable]
            else:
                # We need to install handlers
                try:
                    # Store original handlers
                    self._original_sigint_handler = signal.signal(signal.SIGINT, self._signal_handler)

                    # SIGTERM might not be available on Windows
                    try:
                        self._original_sigterm_handler = signal.signal(signal.SIGTERM, self._signal_handler)
                    except (AttributeError, ValueError):
                        # SIGTERM not available on this platform
                        self._original_sigterm_handler = None

                    self._active = True
                    logger.debug("Interrupt handlers installed")
                    yield
                finally:
                    # Restore original handlers
                    if self._original_sigint_handler is not None:
                        signal.signal(signal.SIGINT, self._original_sigint_handler)
                    if self._original_sigterm_handler is not None:
                        with contextlib.suppress(AttributeError, ValueError):
                            signal.signal(signal.SIGTERM, self._original_sigterm_handler)
                    self._active = False
                    logger.debug("Interrupt handlers restored")


# Global interrupt handler instance
_interrupt_handler = InterruptHandler()


def get_interrupt_handler() -> InterruptHandler:
    """Get the global interrupt handler instance.

    Returns:
        The singleton InterruptHandler instance used throughout the application
    """
    return _interrupt_handler


def check_interrupted() -> None:
    """Check if interrupted and raise KeyboardInterrupt if so.

    This is a convenience function that uses the global interrupt handler.
    Call this periodically in long-running loops to enable graceful interruption.

    Raises:
        KeyboardInterrupt: If an interrupt signal was received

    Example:
        for item in large_list:
            check_interrupted()  # Allow interruption between items
            process_item(item)
    """
    _interrupt_handler.check_interrupted()


def is_interrupted() -> bool:
    """Check if an interrupt has been requested.

    This is a convenience function that uses the global interrupt handler.
    Unlike check_interrupted(), this does not raise an exception.

    Returns:
        True if an interrupt signal was received, False otherwise
    """
    return _interrupt_handler.is_interrupted()


def reset_interrupt() -> None:
    """Reset the interrupt state.

    Clears any pending interrupt flag. This is typically called at the
    start of a new scanning operation.
    """
    _interrupt_handler.reset()


@contextmanager
def interruptible_scan() -> Generator["InterruptHandler", None, None]:
    """Context manager for interruptible scanning operations.

    This installs signal handlers for SIGINT and SIGTERM, allowing the
    scanning operation to be interrupted gracefully. The interrupt state
    is reset at the start, and signal handlers are restored on exit.

    Behavior:
    - First Ctrl+C: Initiates graceful shutdown
    - Second Ctrl+C (while interrupt is pending): Forces immediate termination (exit code 130)

    Yields:
        InterruptHandler: The interrupt handler instance for checking state

    Example:
        with interruptible_scan() as handler:
            for file in files_to_scan:
                if handler.is_interrupted():
                    break
                scan_file(file)
    """
    handler = get_interrupt_handler()
    handler.reset()
    with handler.install_handlers():
        yield handler
