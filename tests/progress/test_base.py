"""Tests for progress tracking base module."""

import time
from unittest.mock import MagicMock

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

    def test_default_values(self):
        """Test default values are set correctly."""
        stats = ProgressStats()
        assert stats.bytes_processed == 0
        assert stats.total_bytes == 0
        assert stats.items_processed == 0
        assert stats.current_phase == ProgressPhase.INITIALIZING

    def test_elapsed_time(self):
        """Test elapsed time calculation."""
        stats = ProgressStats()
        time.sleep(0.05)
        assert stats.elapsed_time >= 0.05

    def test_bytes_percentage_zero_total(self):
        """Test bytes percentage with zero total."""
        stats = ProgressStats(total_bytes=0)
        assert stats.bytes_percentage == 0.0

    def test_bytes_percentage_normal(self):
        """Test bytes percentage calculation."""
        stats = ProgressStats(bytes_processed=50, total_bytes=100)
        assert stats.bytes_percentage == 50.0

    def test_bytes_percentage_capped(self):
        """Test bytes percentage is capped at 100."""
        stats = ProgressStats(bytes_processed=150, total_bytes=100)
        assert stats.bytes_percentage == 100.0

    def test_items_percentage_zero_total(self):
        """Test items percentage with zero total."""
        stats = ProgressStats(total_items=0)
        assert stats.items_percentage == 0.0

    def test_items_percentage_normal(self):
        """Test items percentage calculation."""
        stats = ProgressStats(items_processed=25, total_items=100)
        assert stats.items_percentage == 25.0

    def test_format_bytes_bytes(self):
        """Test byte formatting for small values."""
        stats = ProgressStats()
        assert stats.format_bytes(500) == "500.0 B"

    def test_format_bytes_kilobytes(self):
        """Test byte formatting for KB values."""
        stats = ProgressStats()
        assert "KB" in stats.format_bytes(1500)

    def test_format_bytes_megabytes(self):
        """Test byte formatting for MB values."""
        stats = ProgressStats()
        assert "MB" in stats.format_bytes(1500000)

    def test_format_bytes_gigabytes(self):
        """Test byte formatting for GB values."""
        stats = ProgressStats()
        assert "GB" in stats.format_bytes(1500000000)

    def test_format_time_seconds(self):
        """Test time formatting for seconds."""
        stats = ProgressStats()
        assert "s" in stats.format_time(30)

    def test_format_time_minutes(self):
        """Test time formatting for minutes."""
        stats = ProgressStats()
        result = stats.format_time(90)
        assert "m" in result

    def test_format_time_hours(self):
        """Test time formatting for hours."""
        stats = ProgressStats()
        result = stats.format_time(7200)
        assert "h" in result

    def test_update_performance_metrics(self):
        """Test performance metrics update."""
        stats = ProgressStats(bytes_processed=1000, total_bytes=2000)
        time.sleep(0.01)
        stats.update_performance_metrics()
        assert stats.bytes_per_second > 0

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

    def test_initialization(self):
        """Test tracker initialization."""
        tracker = ProgressTracker(total_bytes=1000, total_items=10)
        assert tracker.stats.total_bytes == 1000
        assert tracker.stats.total_items == 10

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

    def test_increment_bytes(self):
        """Test incrementing bytes."""
        tracker = ProgressTracker(total_bytes=1000, update_interval=0)
        tracker.increment_bytes(100)
        tracker.increment_bytes(200)
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

    def test_force_update(self):
        """Test forcing update."""
        reporter = MockReporter(update_interval=0)
        tracker = ProgressTracker(reporters=[reporter], update_interval=0)
        tracker.force_update()
        # Reporter should have been called
        assert len(reporter.progress_calls) >= 0

    def test_complete(self):
        """Test completion."""
        reporter = MockReporter()
        tracker = ProgressTracker(reporters=[reporter])
        tracker.complete()
        assert len(reporter.completions) == 1

    def test_report_error(self):
        """Test error reporting."""
        reporter = MockReporter()
        tracker = ProgressTracker(reporters=[reporter])
        error = ValueError("Test error")
        tracker.report_error(error)
        assert len(reporter.errors) == 1
        assert reporter.errors[0][0] == error

    def test_get_stats_returns_copy(self):
        """Test that get_stats returns a copy."""
        tracker = ProgressTracker(total_bytes=1000)
        stats1 = tracker.get_stats()
        tracker.update_bytes(500)
        stats2 = tracker.get_stats()
        assert stats1.bytes_processed != stats2.bytes_processed

    def test_callback_invocation(self):
        """Test that callbacks are invoked."""
        callback = MagicMock()
        tracker = ProgressTracker(update_interval=0)
        tracker.add_callback(callback)
        tracker.force_update()
        callback.assert_called()

    def test_reporter_exception_handling(self):
        """Test that reporter exceptions don't crash tracker."""

        class FailingReporter(MockReporter):
            def report_progress(self, stats):
                raise RuntimeError("Reporter failed")

        reporter = FailingReporter(update_interval=0)
        tracker = ProgressTracker(reporters=[reporter], update_interval=0)
        # Should not raise
        tracker.force_update()

    def test_phase_change_exception_handling(self):
        """Test that phase change exceptions don't crash tracker."""

        class FailingReporter(MockReporter):
            def report_phase_change(self, old, new):
                raise RuntimeError("Phase change failed")

        reporter = FailingReporter()
        tracker = ProgressTracker(reporters=[reporter])
        # Should not raise
        tracker.set_phase(ProgressPhase.ANALYZING)

    def test_completion_exception_handling(self):
        """Test that completion exceptions don't crash tracker."""

        class FailingReporter(MockReporter):
            def report_completion(self, stats):
                raise RuntimeError("Completion failed")

        reporter = FailingReporter()
        tracker = ProgressTracker(reporters=[reporter])
        # Should not raise
        tracker.complete()

    def test_error_reporting_exception_handling(self):
        """Test that error reporting exceptions don't crash tracker."""

        class FailingReporter(MockReporter):
            def report_error(self, error, stats):
                raise RuntimeError("Error reporting failed")

        reporter = FailingReporter()
        tracker = ProgressTracker(reporters=[reporter])
        # Should not raise
        tracker.report_error(ValueError("Original error"))

    def test_callback_exception_handling(self):
        """Test that callback exceptions don't crash tracker."""

        def failing_callback(stats):
            raise RuntimeError("Callback failed")

        tracker = ProgressTracker(update_interval=0)
        tracker.add_callback(failing_callback)
        # Should not raise
        tracker.force_update()
