"""Base classes and interfaces for progress tracking."""

import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

logger = logging.getLogger("modelaudit.progress")


class ProgressPhase(Enum):
    """Phases of model scanning operation."""

    INITIALIZING = "initializing"
    LOADING = "loading"
    TOKENIZING = "tokenizing"
    ANALYZING = "analyzing"
    CHECKING = "checking"
    FINALIZING = "finalizing"


@dataclass
class ProgressStats:
    """Statistics about progress tracking."""

    # Time tracking
    start_time: float = field(default_factory=time.time)
    last_update_time: float = field(default_factory=time.time)

    # Byte-level progress
    bytes_processed: int = 0
    total_bytes: int = 0

    # Item-level progress (layers, modules, files, etc.)
    items_processed: int = 0
    total_items: int = 0

    # Phase tracking
    current_phase: ProgressPhase = ProgressPhase.INITIALIZING

    # Performance metrics
    bytes_per_second: float = 0.0
    items_per_second: float = 0.0
    estimated_time_remaining: float = 0.0

    # Additional context
    current_item: str = ""
    status_message: str = ""

    def __post_init__(self):
        """Initialize computed fields."""
        self.update_performance_metrics()

    def update_performance_metrics(self) -> None:
        """Update performance metrics based on current progress."""
        now = time.time()
        elapsed = now - self.start_time

        if elapsed > 0:
            self.bytes_per_second = self.bytes_processed / elapsed
            self.items_per_second = self.items_processed / elapsed

            # Estimate time remaining based on bytes processed
            if self.bytes_processed > 0 and self.total_bytes > 0:
                remaining_bytes = self.total_bytes - self.bytes_processed
                if self.bytes_per_second > 0:
                    self.estimated_time_remaining = remaining_bytes / self.bytes_per_second
                else:
                    self.estimated_time_remaining = 0.0
            else:
                self.estimated_time_remaining = 0.0

        self.last_update_time = now

    @property
    def elapsed_time(self) -> float:
        """Get elapsed time since start."""
        return time.time() - self.start_time

    @property
    def bytes_percentage(self) -> float:
        """Get percentage of bytes processed."""
        if self.total_bytes <= 0:
            return 0.0
        return min(100.0, (self.bytes_processed / self.total_bytes) * 100)

    @property
    def items_percentage(self) -> float:
        """Get percentage of items processed."""
        if self.total_items <= 0:
            return 0.0
        return min(100.0, (self.items_processed / self.total_items) * 100)

    def format_bytes(self, bytes_val: int) -> str:
        """Format bytes in human-readable format."""
        bytes_float = float(bytes_val)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_float < 1024.0:
                return f"{bytes_float:.1f} {unit}"
            bytes_float /= 1024.0
        return f"{bytes_float:.1f} PB"

    def format_time(self, seconds: float) -> str:
        """Format time duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"


# Type alias for progress callback functions
ProgressCallback = Callable[[ProgressStats], None]


class ProgressReporter(ABC):
    """Abstract base class for progress reporters."""

    def __init__(self, update_interval: float = 1.0):
        """Initialize progress reporter.

        Args:
            update_interval: Minimum time between updates in seconds
        """
        self.update_interval = update_interval
        self._last_report_time = 0.0
        self._lock = threading.Lock()

    @abstractmethod
    def report_progress(self, stats: ProgressStats) -> None:
        """Report progress statistics.

        Args:
            stats: Current progress statistics
        """
        pass

    @abstractmethod
    def report_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase) -> None:
        """Report phase change.

        Args:
            old_phase: Previous phase
            new_phase: New phase
        """
        pass

    @abstractmethod
    def report_completion(self, stats: ProgressStats) -> None:
        """Report scan completion.

        Args:
            stats: Final progress statistics
        """
        pass

    @abstractmethod
    def report_error(self, error: Exception, stats: ProgressStats) -> None:
        """Report an error during scanning.

        Args:
            error: The error that occurred
            stats: Progress statistics at time of error
        """
        pass

    def should_update(self) -> bool:
        """Check if enough time has passed for an update."""
        now = time.time()
        with self._lock:
            if now - self._last_report_time >= self.update_interval:
                self._last_report_time = now
                return True
        return False


class ProgressTracker:
    """Main progress tracking coordinator."""

    def __init__(
        self,
        total_bytes: int = 0,
        total_items: int = 0,
        reporters: Optional[list[ProgressReporter]] = None,
        update_interval: float = 1.0,
    ):
        """Initialize progress tracker.

        Args:
            total_bytes: Total bytes to process (if known)
            total_items: Total items to process (if known)
            reporters: List of progress reporters
            update_interval: Minimum time between updates
        """
        self.stats = ProgressStats(
            total_bytes=total_bytes,
            total_items=total_items,
        )
        self.reporters = reporters or []
        self.update_interval = update_interval
        self._lock = threading.Lock()
        self._callbacks: list[ProgressCallback] = []
        self._last_update_time = 0.0

    def add_reporter(self, reporter: ProgressReporter) -> None:
        """Add a progress reporter."""
        with self._lock:
            self.reporters.append(reporter)

    def add_callback(self, callback: ProgressCallback) -> None:
        """Add a progress callback function."""
        with self._lock:
            self._callbacks.append(callback)

    def set_phase(self, phase: ProgressPhase, message: str = "") -> None:
        """Change the current phase.

        Args:
            phase: New phase
            message: Optional status message
        """
        with self._lock:
            old_phase = self.stats.current_phase
            self.stats.current_phase = phase
            if message:
                self.stats.status_message = message
            self.stats.update_performance_metrics()

            # Report phase change to all reporters
            for reporter in self.reporters:
                try:
                    reporter.report_phase_change(old_phase, phase)
                except Exception as e:
                    logger.warning(f"Progress reporter failed during phase change: {e}")

    def update_bytes(self, bytes_processed: int, current_item: str = "") -> None:
        """Update bytes processed.

        Args:
            bytes_processed: Number of bytes processed so far
            current_item: Name of current item being processed
        """
        with self._lock:
            self.stats.bytes_processed = bytes_processed
            if current_item:
                self.stats.current_item = current_item
            self.stats.update_performance_metrics()
            self._maybe_report_progress()

    def increment_bytes(self, bytes_delta: int, current_item: str = "") -> None:
        """Increment bytes processed by a delta.

        Args:
            bytes_delta: Additional bytes processed
            current_item: Name of current item being processed
        """
        with self._lock:
            self.stats.bytes_processed += bytes_delta
            if current_item:
                self.stats.current_item = current_item
            self.stats.update_performance_metrics()
            self._maybe_report_progress()

    def update_items(self, items_processed: int, current_item: str = "") -> None:
        """Update items processed.

        Args:
            items_processed: Number of items processed so far
            current_item: Name of current item being processed
        """
        with self._lock:
            self.stats.items_processed = items_processed
            if current_item:
                self.stats.current_item = current_item
            self.stats.update_performance_metrics()
            self._maybe_report_progress()

    def increment_items(self, items_delta: int = 1, current_item: str = "") -> None:
        """Increment items processed by a delta.

        Args:
            items_delta: Additional items processed
            current_item: Name of current item being processed
        """
        with self._lock:
            self.stats.items_processed += items_delta
            if current_item:
                self.stats.current_item = current_item
            self.stats.update_performance_metrics()
            self._maybe_report_progress()

    def set_status(self, message: str) -> None:
        """Set status message.

        Args:
            message: Status message
        """
        with self._lock:
            self.stats.status_message = message
            self._maybe_report_progress()

    def set_totals(self, total_bytes: Optional[int] = None, total_items: Optional[int] = None) -> None:
        """Update total counts.

        Args:
            total_bytes: Total bytes to process
            total_items: Total items to process
        """
        with self._lock:
            if total_bytes is not None:
                self.stats.total_bytes = total_bytes
            if total_items is not None:
                self.stats.total_items = total_items
            self.stats.update_performance_metrics()
            self._maybe_report_progress()

    def force_update(self) -> None:
        """Force an immediate progress update."""
        with self._lock:
            self.stats.update_performance_metrics()
            self._report_progress()

    def complete(self) -> None:
        """Mark scanning as complete."""
        with self._lock:
            self.stats.update_performance_metrics()
            # Report completion to all reporters
            for reporter in self.reporters:
                try:
                    reporter.report_completion(self.stats)
                except Exception as e:
                    logger.warning(f"Progress reporter failed during completion: {e}")

    def report_error(self, error: Exception) -> None:
        """Report an error during scanning.

        Args:
            error: The error that occurred
        """
        with self._lock:
            self.stats.update_performance_metrics()
            # Report error to all reporters
            for reporter in self.reporters:
                try:
                    reporter.report_error(error, self.stats)
                except Exception as e:
                    logger.warning(f"Progress reporter failed during error reporting: {e}")

    def _maybe_report_progress(self) -> None:
        """Report progress if enough time has passed."""
        now = time.time()
        if now - self._last_update_time >= self.update_interval:
            self._last_update_time = now
            self._report_progress()

    def _report_progress(self) -> None:
        """Report progress to all reporters and callbacks."""
        # Call callbacks first
        for callback in self._callbacks:
            try:
                callback(self.stats)
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")

        # Report to progress reporters
        for reporter in self.reporters:
            if reporter.should_update():
                try:
                    reporter.report_progress(self.stats)
                except Exception as e:
                    logger.warning(f"Progress reporter failed: {e}")

    def get_stats(self) -> ProgressStats:
        """Get current progress statistics."""
        with self._lock:
            # Return a copy to avoid race conditions
            stats_copy = ProgressStats(
                start_time=self.stats.start_time,
                last_update_time=self.stats.last_update_time,
                bytes_processed=self.stats.bytes_processed,
                total_bytes=self.stats.total_bytes,
                items_processed=self.stats.items_processed,
                total_items=self.stats.total_items,
                current_phase=self.stats.current_phase,
                bytes_per_second=self.stats.bytes_per_second,
                items_per_second=self.stats.items_per_second,
                estimated_time_remaining=self.stats.estimated_time_remaining,
                current_item=self.stats.current_item,
                status_message=self.stats.status_message,
            )
            return stats_copy
