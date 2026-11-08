"""Shared SIGINT handling for the CLI module entry point."""

from types import FrameType


class StartupInterrupted(BaseException):
    """Keep Click from converting a startup SIGINT into a generic abort."""


def raise_startup_interrupt(signum: int, frame: FrameType | None) -> None:
    del signum, frame
    raise StartupInterrupted
