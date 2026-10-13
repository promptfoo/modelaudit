"""Tests for progress tracking base module."""

import time
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.progress.base import (
    ProgressPhase,
    ProgressReporter,
    ProgressStats,
    ProgressTracker,
)


class TestProgressPhase:
    """Tests for ProgressPhase enum."""

    def test_all_phases_defined(self):
        """Test that all expected phases are defined."""
        phases = [p.value for p in ProgressPhase]
        assert "initializing" in phases
        assert "loading" in phases
        assert "analyzing" in phases
        assert "finalizing" in phases


class TestProgressStats:
    """Tests for ProgressStats dataclass."""

    def test_default_values(self) -> None:
        """Test default values are set correctly."""
        stats = ProgressStats()
        assert stats.bytes_processed == 0
        assert stats.total_bytes == 0
        assert stats.items_processed == 0
        assert stats.total_items == 0
        assert stats.current_item == ""
        assert stats.status_message == ""
        assert stats.bytes_per_second >= 0
        assert stats.items_per_second >= 0
        assert stats.current_phase == ProgressPhase.INITIALIZING

    def test_elapsed_time(self):
        """Test elapsed time calculation."""
        stats = ProgressStats()
        time.sleep(0.05)
        assert stats.elapsed_time >= 0.05

    @pytest.mark.parametrize("counter", ["bytes", "items"])
    @pytest.mark.parametrize(
        ("processed", "total", "expected"),
        [(0, 0, 0.0), (25, 100, 25.0), (50, 100, 50.0), (150, 100, 100.0)],
        ids=["zero-total", "quarter", "half", "capped"],
    )
    def test_percentage(self, counter: str, processed: int, total: int, expected: float) -> None:
        """Test percentages for empty, partially processed and exceeded totals."""
        stats = ProgressStats()
        setattr(stats, f"{counter}_processed", processed)
        setattr(stats, f"total_{counter}", total)
        assert getattr(stats, f"{counter}_percentage") == expected

    @pytest.mark.parametrize(
        ("size", "expected"),
        [(500, "500.0 B"), (1536, "1.5 KB"), (2048 * 1024, "2.0 MB"), (3 * 1024**3, "3.0 GB")],
        ids=["bytes", "kilobytes", "megabytes", "gigabytes"],
    )
    def test_format_bytes(self, size: int, expected: str) -> None:
        assert ProgressStats().format_bytes(size) == expected

    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [(30, "30.0s"), (90, "1m 30s"), (3661, "1h 1m")],
        ids=["seconds", "minutes", "hours"],
    )
    def test_format_time(self, seconds: int, expected: str) -> None:
        assert ProgressStats().format_time(seconds) == expected

    def test_update_performance_metrics(self) -> None:
        """Test performance metrics update."""
        stats = ProgressStats(total_bytes=2000, total_items=10)
        stats.bytes_processed = 1000
        stats.items_processed = 5
        time.sleep(0.01)
        stats.update_performance_metrics()
        assert stats.bytes_per_second > 0
        assert stats.bytes_percentage == 50.0
        assert stats.items_percentage == 50.0
        assert stats.elapsed_time > 0

    def test_estimated_time_remaining(self):
        """Test estimated time remaining calculation."""
        stats = ProgressStats(bytes_processed=500, total_bytes=1000)
        time.sleep(0.01)
        stats.update_performance_metrics()
        # Should have some estimate
        assert stats.estimated_time_remaining >= 0


class MockReporter(ProgressReporter):
    """Mock progress reporter for testing."""

    def __init__(self, update_interval: float = 0.0):
        super().__init__(update_interval)
        self.progress_calls: list[ProgressStats] = []
        self.phase_changes: list[tuple[ProgressPhase, ProgressPhase]] = []
        self.completions: list[ProgressStats] = []
        self.errors: list[tuple[Exception, ProgressStats]] = []

    def report_progress(self, stats: ProgressStats) -> None:
        self.progress_calls.append(stats)

    def report_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase) -> None:
        self.phase_changes.append((old_phase, new_phase))

    def report_completion(self, stats: ProgressStats) -> None:
        self.completions.append(stats)

    def report_error(self, error: Exception, stats: ProgressStats) -> None:
        self.errors.append((error, stats))


class TestProgressReporter:
    """Tests for ProgressReporter base class."""

    def test_should_update_respects_interval(self):
        """Test that should_update respects update interval."""
        reporter = MockReporter(update_interval=1.0)
        assert reporter.should_update() is True
        assert reporter.should_update() is False

    def test_should_update_zero_interval(self):
        """Test should_update with zero interval."""
        reporter = MockReporter(update_interval=0.0)
        assert reporter.should_update() is True
        assert reporter.should_update() is True


class TestProgressTracker:
    """Tests for ProgressTracker class."""

    def test_initialization(self) -> None:
        """Test tracker initialization."""
        tracker = ProgressTracker(total_bytes=1000, total_items=10)
        assert tracker.stats.total_bytes == 1000
        assert tracker.stats.total_items == 10
        assert tracker.reporters == []
        assert tracker._callbacks == []

    def test_add_reporter(self):
        """Test adding a reporter."""
        tracker = ProgressTracker()
        reporter = MockReporter()
        tracker.add_reporter(reporter)
        assert reporter in tracker.reporters

    def test_add_callback(self):
        """Test adding a callback."""
        tracker = ProgressTracker()
        callback = MagicMock()
        tracker.add_callback(callback)
        assert callback in tracker._callbacks

    def test_set_phase(self):
        """Test setting phase."""
        reporter = MockReporter()
        tracker = ProgressTracker(reporters=[reporter])
        tracker.set_phase(ProgressPhase.ANALYZING, "Analyzing model")
        assert tracker.stats.current_phase == ProgressPhase.ANALYZING
        assert tracker.stats.status_message == "Analyzing model"
        assert len(reporter.phase_changes) == 1

    def test_update_bytes(self):
        """Test updating bytes."""
        tracker = ProgressTracker(total_bytes=1000, update_interval=0)
        tracker.update_bytes(500, "file.pkl")
        assert tracker.stats.bytes_processed == 500
        assert tracker.stats.current_item == "file.pkl"

    def test_increment_bytes(self) -> None:
        """Test incrementing bytes."""
        tracker = ProgressTracker(total_bytes=1000, update_interval=0)
        tracker.increment_bytes(100)
        tracker.increment_bytes(200, "file2.txt")
        assert tracker.stats.current_item == "file2.txt"
        assert tracker.stats.bytes_processed == 300

    def test_update_items(self):
        """Test updating items."""
        tracker = ProgressTracker(total_items=10, update_interval=0)
        tracker.update_items(5, "layer_5")
        assert tracker.stats.items_processed == 5
        assert tracker.stats.current_item == "layer_5"

    def test_increment_items(self):
        """Test incrementing items."""
        tracker = ProgressTracker(total_items=10, update_interval=0)
        tracker.increment_items(1)
        tracker.increment_items(2)
        assert tracker.stats.items_processed == 3

    def test_set_status(self):
        """Test setting status message."""
        tracker = ProgressTracker(update_interval=0)
        tracker.set_status("Processing...")
        assert tracker.stats.status_message == "Processing..."

    def test_set_totals(self):
        """Test setting totals."""
        tracker = ProgressTracker()
        tracker.set_totals(total_bytes=5000, total_items=50)
        assert tracker.stats.total_bytes == 5000
        assert tracker.stats.total_items == 50

    def test_force_update(self) -> None:
        """Test forcing update."""
        reporter = MockReporter(update_interval=0)
        tracker = ProgressTracker(reporters=[reporter], update_interval=0)
        tracker.force_update()
        assert reporter.progress_calls == [tracker.stats]

    def test_complete(self):
        """Test completion."""
        reporter = MockReporter()
        tracker = ProgressTracker(reporters=[reporter])
        tracker.complete()
        assert len(reporter.completions) == 1

    def test_report_error(self) -> None:
        """Test error reporting."""
        reporter = MockReporter()
        tracker = ProgressTracker(reporters=[reporter])
        error = ValueError("Test error")
        tracker.report_error(error)
        assert len(reporter.errors) == 1
        assert reporter.errors[0] == (error, tracker.stats)

    def test_get_stats_returns_copy(self):
        """Test that get_stats returns a copy."""
        tracker = ProgressTracker(total_bytes=1000)
        stats1 = tracker.get_stats()
        tracker.update_bytes(500)
        stats2 = tracker.get_stats()
        assert stats1.bytes_processed != stats2.bytes_processed

    def test_callback_invocation(self) -> None:
        """Test that callbacks are invoked."""
        callback = MagicMock()
        tracker = ProgressTracker(update_interval=0)
        tracker.add_callback(callback)
        tracker.force_update()
        callback.assert_called_once()
        observed = []
        callback.side_effect = lambda stats: observed.append(stats.bytes_processed)
        tracker.update_bytes(200)
        tracker.update_bytes(500)
        assert observed == [200, 500]

    @pytest.mark.parametrize(
        ("reporter_method", "tracker_method", "args", "message"),
        [
            ("report_progress", "force_update", (), "Reporter failed"),
            ("report_phase_change", "set_phase", (ProgressPhase.ANALYZING,), "Phase change failed"),
            ("report_completion", "complete", (), "Completion failed"),
            ("report_error", "report_error", (ValueError("Original error"),), "Error reporting failed"),
        ],
        ids=["progress", "phase-change", "completion", "error-reporting"],
    )
    def test_reporter_exception_handling(
        self,
        reporter_method: str,
        tracker_method: str,
        args: tuple[object, ...],
        message: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test each reporter failure is reached and logged without crashing the tracker."""
        caplog.set_level("WARNING", logger="modelaudit.progress")
        reporter = MockReporter(update_interval=0)
        tracker = ProgressTracker(reporters=[reporter], update_interval=0)
        with patch.object(reporter, reporter_method, side_effect=RuntimeError(message)) as failing_method:
            getattr(tracker, tracker_method)(*args)
        failing_method.assert_called_once()
        assert message in caplog.text

    def test_callback_exception_handling(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that callback exceptions don't crash tracker."""
        caplog.set_level("WARNING", logger="modelaudit.progress")
        callback = MagicMock(side_effect=RuntimeError("Callback failed"))
        tracker = ProgressTracker(update_interval=0)
        tracker.add_callback(callback)
        tracker.force_update()
        callback.assert_called_once_with(tracker.stats)
        assert "Callback failed" in caplog.text
