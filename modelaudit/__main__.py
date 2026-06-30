"""Entry point for running modelaudit as a module with python -m modelaudit."""

import signal
import sys
from types import FrameType


class _StartupInterrupted(BaseException):
    """Keep Click from converting a startup SIGINT into a generic abort."""


def _raise_startup_interrupt(signum: int, frame: FrameType | None) -> None:
    del signum, frame
    raise _StartupInterrupted


def _run() -> None:
    """Run the CLI while keeping startup interrupts user-friendly."""
    original_sigint_handler = signal.signal(signal.SIGINT, _raise_startup_interrupt)
    try:
        # Keep this import inside the guard: CLI imports can take long enough for
        # a user to interrupt before the scan-specific handler is installed.
        from .cli import main

        main()
    except (_StartupInterrupted, KeyboardInterrupt):
        print("Scan interrupted by user", file=sys.stderr)
        raise SystemExit(2) from None
    finally:
        signal.signal(signal.SIGINT, original_sigint_handler)


if __name__ == "__main__":
    _run()
