"""Cache lifecycle helpers used by tests."""

from collections.abc import Callable
from types import TracebackType


class IsolatedCacheManager:
    def __init__(self, reset: Callable[[], None]) -> None:
        self._reset = reset

    def __enter__(self) -> None:
        self._reset()

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self._reset()
