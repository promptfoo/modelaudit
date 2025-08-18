"""Tests for progress tracking functionality."""

import os
import tempfile
import time
from unittest.mock import Mock

import pytest

from modelaudit.progress import (
    ConsoleProgressReporter,
    FileProgressReporter,
    ProgressPhase,
    ProgressReporter,
    ProgressStats,
    ProgressTracker,
    SimpleConsoleReporter,
)
from modelaudit.progress.hooks import (
    CustomFunctionHook,
    ProgressHookManager,
)
from modelaudit.progress.multi_phase import MultiPhaseProgressTracker


class TestProgressStats:
    """Test ProgressStats functionality."""

    def test_init_and_defaults(self):
        """Test ProgressStats initialization and defaults."""
        stats = ProgressStats()

        assert stats.bytes_processed == 0
        assert stats.total_bytes == 0
        assert stats.items_processed == 0
        assert stats.total_items == 0
        assert stats.current_phase == ProgressPhase.INITIALIZING
        assert stats.current_item == ""
        assert stats.status_message == ""
        assert stats.bytes_per_second >= 0
        assert stats.items_per_second >= 0

    def test_performance_metrics_update(self):
        """Test performance metrics calculation."""
        stats = ProgressStats(total_bytes=1000, total_items=10)

        # Simulate some progress
        time.sleep(0.1)  # Small delay for elapsed time
        stats.bytes_processed = 500
        stats.items_processed = 5
        stats.update_performance_metrics()

        assert stats.bytes_percentage == 50.0
        assert stats.items_percentage == 50.0
        assert stats.elapsed_time > 0

    def test_format_bytes(self):
        """Test byte formatting."""
        stats = ProgressStats()

        assert stats.format_bytes(500) == "500.0 B"
        assert stats.format_bytes(1536) == "1.5 KB"
        assert stats.format_bytes(2048 * 1024) == "2.0 MB"
        assert stats.format_bytes(3 * 1024 * 1024 * 1024) == "3.0 GB"

    def test_format_time(self):
        """Test time formatting."""
        stats = ProgressStats()

        assert stats.format_time(30) == "30.0s"
        assert stats.format_time(90) == "1m 30s"
        assert stats.format_time(3661) == "1h 1m"


class TestProgressTracker:
    """Test ProgressTracker functionality."""

    def test_init(self):
        """Test ProgressTracker initialization."""
        tracker = ProgressTracker(total_bytes=1000, total_items=10)

        assert tracker.stats.total_bytes == 1000
        assert tracker.stats.total_items == 10
        assert len(tracker.reporters) == 0
        assert len(tracker._callbacks) == 0

    def test_update_bytes(self):
        """Test byte progress updates."""
        tracker = ProgressTracker(total_bytes=1000)

        tracker.update_bytes(500, "file.txt")
        assert tracker.stats.bytes_processed == 500
        assert tracker.stats.current_item == "file.txt"

    def test_increment_bytes(self):
        """Test byte progress increments."""
        tracker = ProgressTracker(total_bytes=1000)

        tracker.increment_bytes(200, "file1.txt")
        assert tracker.stats.bytes_processed == 200

        tracker.increment_bytes(300, "file2.txt")
        assert tracker.stats.bytes_processed == 500
        assert tracker.stats.current_item == "file2.txt"

    def test_update_items(self):
        """Test item progress updates."""
        tracker = ProgressTracker(total_items=10)

        tracker.update_items(5, "layer_5")
        assert tracker.stats.items_processed == 5
        assert tracker.stats.current_item == "layer_5"

    def test_increment_items(self):
        """Test item progress increments."""
        tracker = ProgressTracker(total_items=10)

        tracker.increment_items(2, "layers_1_2")
        assert tracker.stats.items_processed == 2

        tracker.increment_items(3, "layers_3_5")
        assert tracker.stats.items_processed == 5

    def test_set_phase(self):
        """Test phase changes."""
        mock_reporter = Mock(spec=ProgressReporter)
        mock_reporter.should_update.return_value = True

        tracker = ProgressTracker()
        tracker.add_reporter(mock_reporter)

        tracker.set_phase(ProgressPhase.LOADING, "Loading model")

        assert tracker.stats.current_phase == ProgressPhase.LOADING
        assert tracker.stats.status_message == "Loading model"
        mock_reporter.report_phase_change.assert_called_once()

    def test_callbacks(self):
        """Test progress callbacks."""
        callback_calls = []

        def test_callback(stats):
            callback_calls.append(stats.bytes_processed)

        tracker = ProgressTracker(total_bytes=1000, update_interval=0.0)  # No throttling
        tracker.add_callback(test_callback)

        tracker.update_bytes(200)
        tracker.update_bytes(500)

        # Should have at least some callback calls
        assert len(callback_calls) >= 1

    def test_completion(self):
        """Test scan completion."""
        mock_reporter = Mock(spec=ProgressReporter)

        tracker = ProgressTracker()
        tracker.add_reporter(mock_reporter)

        tracker.complete()

        mock_reporter.report_completion.assert_called_once()

    def test_error_reporting(self):
        """Test error reporting."""
        mock_reporter = Mock(spec=ProgressReporter)

        tracker = ProgressTracker()
        tracker.add_reporter(mock_reporter)

        error = Exception("Test error")
        tracker.report_error(error)

        mock_reporter.report_error.assert_called_once_with(error, tracker.stats)


class TestMultiPhaseProgressTracker:
    """Test MultiPhaseProgressTracker functionality."""

    def test_init_with_phases(self):
        """Test initialization with phases."""
        phases = [ProgressPhase.LOADING, ProgressPhase.ANALYZING, ProgressPhase.CHECKING]
        tracker = MultiPhaseProgressTracker(phases, total_bytes=1000)

        assert tracker.phases == phases
        assert tracker.stats.current_phase == ProgressPhase.LOADING
        assert len(tracker._phase_stats) == 3

    def test_next_phase(self):
        """Test phase progression."""
        phases = [ProgressPhase.LOADING, ProgressPhase.ANALYZING, ProgressPhase.CHECKING]
        tracker = MultiPhaseProgressTracker(phases)

        # Should start at first phase
        assert tracker.stats.current_phase == ProgressPhase.LOADING

        # Move to next phase
        result = tracker.next_phase("Starting analysis")
        assert result is True
        assert tracker.stats.current_phase == ProgressPhase.ANALYZING
        assert tracker.stats.status_message == "Starting analysis"

        # Move to last phase
        result = tracker.next_phase("Final checks")
        assert result is True
        assert tracker.stats.current_phase == ProgressPhase.CHECKING

        # No more phases
        result = tracker.next_phase()
        assert result is False

    def test_overall_progress(self):
        """Test overall progress calculation."""
        phases = [ProgressPhase.LOADING, ProgressPhase.ANALYZING]
        weights = {ProgressPhase.LOADING: 0.3, ProgressPhase.ANALYZING: 0.7}
        tracker = MultiPhaseProgressTracker(phases, phase_weights=weights, total_bytes=1000)

        # Complete first phase
        tracker.update_bytes(500)  # 50% of bytes for this phase

        # Should show partial progress weighted by phase
        progress = tracker.get_overall_progress()
        # First phase is 30% weight, 50% complete = 15% overall
        assert 10 <= progress <= 20  # Allow some tolerance

        # Complete first phase and move to next
        tracker.update_bytes(1000)  # 100% of bytes for this phase
        tracker.next_phase()

        # Should be 30% complete (first phase weight)
        progress = tracker.get_overall_progress()
        assert 25 <= progress <= 35  # Allow some tolerance

    def test_phase_stats(self):
        """Test phase statistics tracking."""
        phases = [ProgressPhase.LOADING, ProgressPhase.ANALYZING]
        tracker = MultiPhaseProgressTracker(phases)

        # Get current phase stats
        current_stats = tracker.get_current_phase_stats()
        assert current_stats is not None
        assert current_stats.phase == ProgressPhase.LOADING
        assert not current_stats.is_complete

        # Move to next phase
        tracker.next_phase()

        # Previous phase should be complete
        loading_stats = tracker._phase_stats[ProgressPhase.LOADING]
        assert loading_stats.is_complete
        assert loading_stats.end_time is not None


class MockReporter(ProgressReporter):
    """Mock reporter for testing."""

    def __init__(self):
        super().__init__()
        self.progress_calls = []
        self.phase_changes = []
        self.completion_calls = []
        self.error_calls = []

    def report_progress(self, stats):
        self.progress_calls.append(stats)

    def report_phase_change(self, old_phase, new_phase):
        self.phase_changes.append((old_phase, new_phase))

    def report_completion(self, stats):
        self.completion_calls.append(stats)

    def report_error(self, error, stats):
        self.error_calls.append((error, stats))


class TestProgressReporters:
    """Test progress reporters."""

    def test_console_reporter_creation(self):
        """Test console reporter creation."""
        reporter = ConsoleProgressReporter()
        # Note: tqdm might be disabled on non-TTY environments (CI)
        assert reporter.show_bytes
        assert reporter.show_items

    def test_simple_console_reporter(self):
        """Test simple console reporter."""
        reporter = SimpleConsoleReporter()

        stats = ProgressStats(total_bytes=1000)
        stats.bytes_processed = 500
        stats.current_phase = ProgressPhase.ANALYZING
        stats.current_item = "model.pkl"
        stats.update_performance_metrics()

        # Should not raise any errors
        reporter.report_progress(stats)
        reporter.report_phase_change(ProgressPhase.LOADING, ProgressPhase.ANALYZING)
        reporter.report_completion(stats)
        reporter.report_error(Exception("Test error"), stats)

    def test_file_reporter(self):
        """Test file progress reporter."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            log_file = f.name

        try:
            reporter = FileProgressReporter(
                log_file=log_file,
                format_type="json",
                append_mode=False,
            )

            stats = ProgressStats(total_bytes=1000)
            stats.bytes_processed = 500
            stats.current_phase = ProgressPhase.ANALYZING
            stats.update_performance_metrics()

            # Report some progress
            reporter.report_progress(stats)
            reporter.report_completion(stats)
            reporter.close()

            # Check that log file was written
            assert os.path.exists(log_file)
            with open(log_file) as f:
                content = f.read()
                assert "header" in content
                assert "progress" in content
                assert "completion" in content

        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)


class TestProgressHooks:
    """Test progress hooks system."""

    def test_custom_function_hook(self):
        """Test custom function hook."""
        start_calls = []
        progress_calls = []
        complete_calls = []

        def on_start(stats):
            start_calls.append(stats)

        def on_progress(stats):
            progress_calls.append(stats)

        def on_complete(stats):
            complete_calls.append(stats)

        hook = CustomFunctionHook(
            name="test_hook",
            on_start_func=on_start,
            on_progress_func=on_progress,
            on_complete_func=on_complete,
        )

        stats = ProgressStats()

        hook.on_start(stats)
        assert len(start_calls) == 1

        hook.on_progress(stats)
        assert len(progress_calls) == 1

        hook.on_complete(stats)
        assert len(complete_calls) == 1

    def test_hook_manager(self):
        """Test progress hook manager."""
        manager = ProgressHookManager()

        # Add hooks
        hook1 = CustomFunctionHook("hook1")
        hook2 = CustomFunctionHook("hook2")

        manager.add_hook(hook1)
        manager.add_hook(hook2)

        assert len(manager.list_hooks()) == 2
        assert manager.get_hook("hook1") == hook1
        assert manager.get_hook("hook2") == hook2

        # Remove hook
        assert manager.remove_hook("hook1") is True
        assert len(manager.list_hooks()) == 1
        assert manager.get_hook("hook1") is None

        # Clear all hooks
        manager.clear_hooks()
        assert len(manager.list_hooks()) == 0

    def test_hook_enable_disable(self):
        """Test hook enable/disable functionality."""
        calls = []

        def on_progress(stats):
            calls.append(stats)

        hook = CustomFunctionHook("test", on_progress_func=on_progress)
        manager = ProgressHookManager()
        manager.add_hook(hook)

        stats = ProgressStats()

        # Hook should be enabled by default
        manager.trigger_progress(stats)
        assert len(calls) == 1

        # Disable hook
        manager.disable_hook("test")
        manager.trigger_progress(stats)
        assert len(calls) == 1  # No new calls

        # Re-enable hook
        manager.enable_hook("test")
        manager.trigger_progress(stats)
        assert len(calls) == 2


@pytest.mark.integration
class TestProgressIntegration:
    """Integration tests for progress tracking."""

    def test_progress_with_mock_scanner(self):
        """Test progress tracking with a mock scanner."""
        from modelaudit.scanners.base import BaseScanner

        class MockScanner(BaseScanner):
            name = "mock"

            def __init__(self, config=None):
                super().__init__(config)

            def can_handle(self, path):
                return True

            def scan(self, path):
                result = self._create_result()

                # Simulate progress updates
                if self.progress_tracker:
                    self._set_progress_phase(ProgressPhase.LOADING, "Loading file")
                    time.sleep(0.1)

                    self._update_progress_bytes(512, "Reading headers")
                    time.sleep(0.1)

                    self._next_progress_phase("Analyzing content")
                    self._update_progress_bytes(1024, "Processing data")
                    time.sleep(0.1)

                    self._next_progress_phase("Final checks")
                    self._update_progress_bytes(1024, "Completing scan")

                result.finish(success=True)
                return result

        # Create mock file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data" * 128)  # 1024 bytes
            temp_file = f.name

        try:
            # Create scanner with progress tracking enabled
            config = {"enable_progress": True}
            scanner = MockScanner(config)

            # Add mock reporter
            mock_reporter = MockReporter()
            scanner.add_progress_reporter(mock_reporter)

            # Run scan
            result = scanner.scan_with_progress(temp_file)

            # Check that progress was tracked
            assert result.success
            assert len(mock_reporter.progress_calls) > 0
            assert len(mock_reporter.phase_changes) > 0
            assert len(mock_reporter.completion_calls) == 1

            # Check final stats
            final_stats = mock_reporter.completion_calls[0]
            assert final_stats.bytes_processed == 1024

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


if __name__ == "__main__":
    pytest.main([__file__])
