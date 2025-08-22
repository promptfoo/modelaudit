"""Multi-phase progress tracking for complex scanning operations."""

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .base import ProgressPhase, ProgressReporter, ProgressStats, ProgressTracker

logger = logging.getLogger("modelaudit.progress.multi_phase")


@dataclass
class PhaseStats:
    """Statistics for a single phase."""

    phase: ProgressPhase
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    bytes_processed: int = 0
    items_processed: int = 0
    estimated_duration: float = 0.0
    actual_duration: Optional[float] = None

    @property
    def is_complete(self) -> bool:
        """Check if phase is complete."""
        return self.end_time is not None

    @property
    def duration(self) -> float:
        """Get phase duration."""
        if self.end_time is not None:
            return self.end_time - self.start_time
        return time.time() - self.start_time


class MultiPhaseProgressTracker(ProgressTracker):
    """Progress tracker with multi-phase support and better time estimation."""

    def __init__(
        self,
        phases: list[ProgressPhase],
        total_bytes: int = 0,
        total_items: int = 0,
        phase_weights: Optional[dict[ProgressPhase, float]] = None,
        reporters: Optional[list[ProgressReporter]] = None,
        update_interval: float = 1.0,
    ):
        """Initialize multi-phase progress tracker.

        Args:
            phases: List of phases in order
            total_bytes: Total bytes to process across all phases
            total_items: Total items to process across all phases
            phase_weights: Relative weights of phases for time estimation
            reporters: List of progress reporters
            update_interval: Minimum time between updates
        """
        super().__init__(total_bytes, total_items, reporters, update_interval)

        self.phases = phases
        self.phase_weights = phase_weights or dict.fromkeys(phases, 1.0)
        self._normalize_weights()

        # Phase tracking
        self._current_phase_index = 0
        self._phase_stats: dict[ProgressPhase, PhaseStats] = {}
        self._completed_phases: list[ProgressPhase] = []

        # Initialize phase stats
        for phase in phases:
            self._phase_stats[phase] = PhaseStats(
                phase=phase,
                estimated_duration=self._estimate_phase_duration(phase),
            )

        # Set initial phase
        if phases:
            self.set_phase(phases[0])

    def _normalize_weights(self) -> None:
        """Normalize phase weights to sum to 1.0."""
        total_weight = sum(self.phase_weights.values())
        if total_weight > 0:
            for phase in self.phase_weights:
                self.phase_weights[phase] /= total_weight

    def _estimate_phase_duration(self, phase: ProgressPhase) -> float:
        """Estimate duration for a phase based on weight and total expected time."""
        # Base estimates (can be refined with historical data)
        base_estimates = {
            ProgressPhase.INITIALIZING: 5.0,  # seconds
            ProgressPhase.LOADING: 30.0,
            ProgressPhase.TOKENIZING: 60.0,
            ProgressPhase.ANALYZING: 300.0,
            ProgressPhase.CHECKING: 120.0,
            ProgressPhase.FINALIZING: 10.0,
        }

        base_time = base_estimates.get(phase, 60.0)  # Default 1 minute
        weight = self.phase_weights.get(phase, 1.0)

        # Adjust based on data size
        if self.stats.total_bytes > 0:
            # Scale with data size (rough heuristic)
            size_gb = self.stats.total_bytes / (1024**3)
            scale_factor = max(1.0, size_gb * 0.1)  # 10% increase per GB
            base_time *= scale_factor

        return base_time * weight

    def next_phase(self, status_message: str = "") -> bool:
        """Move to next phase.

        Args:
            status_message: Optional status message for the new phase

        Returns:
            True if there is a next phase, False if all phases complete
        """
        # Complete current phase
        current_phase = self.stats.current_phase
        if current_phase in self._phase_stats and current_phase not in self._completed_phases:
            phase_stat = self._phase_stats[current_phase]
            phase_stat.end_time = time.time()
            phase_stat.actual_duration = phase_stat.duration
            phase_stat.bytes_processed = self.stats.bytes_processed
            phase_stat.items_processed = self.stats.items_processed
            self._completed_phases.append(current_phase)

        # Move to next phase
        self._current_phase_index += 1

        if self._current_phase_index >= len(self.phases):
            # All phases complete
            return False

        next_phase = self.phases[self._current_phase_index]
        self.set_phase(next_phase, status_message)

        # Reset progress tracking for new phase
        # In a proper implementation, we'd track bytes/items per phase
        # For this simplified model, we reset the counters when starting a new phase
        self.stats.bytes_processed = 0
        self.stats.items_processed = 0

        # Start timing for new phase
        if next_phase in self._phase_stats:
            self._phase_stats[next_phase].start_time = time.time()

        return True

    def get_phase_stats(self) -> dict[ProgressPhase, PhaseStats]:
        """Get statistics for all phases."""
        return self._phase_stats.copy()

    def get_current_phase_stats(self) -> Optional[PhaseStats]:
        """Get statistics for current phase."""
        return self._phase_stats.get(self.stats.current_phase)

    def get_overall_progress(self) -> float:
        """Get overall progress across all phases (0-100)."""
        if not self.phases:
            return 100.0

        # Calculate progress based on completed phases only
        completed_weight = sum(self.phase_weights.get(phase, 1.0) for phase in self._completed_phases)

        # Add progress from current phase only if we have meaningful progress data
        current_phase = self.stats.current_phase
        if current_phase in self.phase_weights and current_phase not in self._completed_phases:
            current_weight = self.phase_weights[current_phase]

            # Calculate current phase progress
            current_progress = 0.0

            # If we have byte/item tracking, use that for current phase
            if self.stats.total_bytes > 0:
                # In multi-phase, we assume the bytes represent progress within current phase
                # This is a simplification - in reality we'd track bytes per phase
                current_progress = self.stats.bytes_percentage / 100.0
            elif self.stats.total_items > 0:
                current_progress = self.stats.items_percentage / 100.0
            else:
                # Use time-based estimation for current phase
                phase_stat = self._phase_stats.get(current_phase)
                if phase_stat and phase_stat.estimated_duration > 0:
                    elapsed = phase_stat.duration
                    current_progress = min(1.0, elapsed / phase_stat.estimated_duration)

            completed_weight += current_weight * current_progress

        return min(100.0, completed_weight * 100.0)

    def get_estimated_total_time(self) -> float:
        """Get estimated total time for all phases."""
        total_estimated = 0.0

        for phase in self.phases:
            phase_stat = self._phase_stats.get(phase)
            if phase_stat:
                if phase_stat.is_complete:
                    # Use actual duration for completed phases
                    total_estimated += phase_stat.duration
                else:
                    # Use estimated duration for remaining phases
                    total_estimated += phase_stat.estimated_duration

        return total_estimated

    def get_estimated_remaining_time(self) -> float:
        """Get estimated remaining time for all remaining phases."""
        remaining_time = 0.0
        current_phase = self.stats.current_phase

        # Add remaining time for current phase
        if current_phase in self._phase_stats:
            phase_stat = self._phase_stats[current_phase]
            if not phase_stat.is_complete:
                elapsed = phase_stat.duration
                estimated = phase_stat.estimated_duration
                remaining_time += max(0.0, estimated - elapsed)

        # Add time for future phases
        current_index = self.phases.index(current_phase) if current_phase in self.phases else -1
        for i in range(current_index + 1, len(self.phases)):
            future_phase = self.phases[i]
            phase_stat = self._phase_stats.get(future_phase)  # type: ignore[assignment]
            if phase_stat:
                remaining_time += phase_stat.estimated_duration

        return remaining_time

    def update_phase_estimate(self, phase: ProgressPhase, estimated_duration: float) -> None:
        """Update estimated duration for a phase.

        Args:
            phase: Phase to update
            estimated_duration: New estimated duration in seconds
        """
        if phase in self._phase_stats:
            self._phase_stats[phase].estimated_duration = estimated_duration

    def get_stats(self) -> ProgressStats:
        """Get enhanced progress statistics."""
        stats = super().get_stats()

        # Override time estimates with multi-phase calculations
        stats.estimated_time_remaining = self.get_estimated_remaining_time()

        return stats

    def get_phase_summary(self) -> dict[str, Any]:
        """Get summary of all phase progress."""
        summary: dict[str, Any] = {
            "overall_progress": self.get_overall_progress(),
            "estimated_total_time": self.get_estimated_total_time(),
            "estimated_remaining_time": self.get_estimated_remaining_time(),
            "current_phase": self.stats.current_phase.value,
            "completed_phases": len(self._completed_phases),
            "total_phases": len(self.phases),
            "phases": {},
        }

        for phase, stats in self._phase_stats.items():
            phase_info = {
                "name": phase.value,
                "weight": self.phase_weights.get(phase, 1.0),
                "estimated_duration": stats.estimated_duration,
                "is_complete": stats.is_complete,
                "bytes_processed": stats.bytes_processed,
                "items_processed": stats.items_processed,
            }

            if stats.is_complete:
                if stats.actual_duration is not None:
                    phase_info["actual_duration"] = stats.actual_duration
                phase_info["duration"] = stats.duration
            else:
                phase_info["duration"] = stats.duration
                if stats.estimated_duration > 0:
                    phase_info["progress_percentage"] = min(100.0, (stats.duration / stats.estimated_duration) * 100.0)

            summary["phases"][phase.value] = phase_info

        return summary


class CheckpointProgressTracker(MultiPhaseProgressTracker):
    """Progress tracker with checkpoint/resume capability."""

    def __init__(self, phases: list[ProgressPhase], checkpoint_file: Optional[str] = None, **kwargs):
        """Initialize checkpoint progress tracker.

        Args:
            phases: List of phases in order
            checkpoint_file: Path to checkpoint file for resume capability
            **kwargs: Additional arguments passed to MultiPhaseProgressTracker
        """
        super().__init__(phases, **kwargs)

        self.checkpoint_file = checkpoint_file
        self._checkpoint_interval = 30.0  # seconds
        self._last_checkpoint_time = 0.0

    def save_checkpoint(self) -> None:
        """Save current progress to checkpoint file."""
        if not self.checkpoint_file:
            return

        checkpoint_data = {
            "timestamp": time.time(),
            "current_phase_index": self._current_phase_index,
            "completed_phases": [phase.value for phase in self._completed_phases],
            "stats": {
                "bytes_processed": self.stats.bytes_processed,
                "items_processed": self.stats.items_processed,
                "current_item": self.stats.current_item,
                "status_message": self.stats.status_message,
            },
            "phase_stats": {
                phase.value: {
                    "start_time": stats.start_time,
                    "end_time": stats.end_time,
                    "bytes_processed": stats.bytes_processed,
                    "items_processed": stats.items_processed,
                    "actual_duration": stats.actual_duration,
                }
                for phase, stats in self._phase_stats.items()
            },
        }

        try:
            import json

            with open(self.checkpoint_file, "w") as f:
                json.dump(checkpoint_data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {e}")

    def load_checkpoint(self) -> bool:
        """Load progress from checkpoint file.

        Returns:
            True if checkpoint was loaded successfully
        """
        if not self.checkpoint_file or not os.path.exists(self.checkpoint_file):
            return False

        try:
            import json

            with open(self.checkpoint_file) as f:
                checkpoint_data = json.load(f)

            # Restore phase progress
            self._current_phase_index = checkpoint_data.get("current_phase_index", 0)

            completed_phase_names = checkpoint_data.get("completed_phases", [])
            self._completed_phases = [
                ProgressPhase(name) for name in completed_phase_names if name in [p.value for p in self.phases]
            ]

            # Restore stats
            stats_data = checkpoint_data.get("stats", {})
            self.stats.bytes_processed = stats_data.get("bytes_processed", 0)
            self.stats.items_processed = stats_data.get("items_processed", 0)
            self.stats.current_item = stats_data.get("current_item", "")
            self.stats.status_message = stats_data.get("status_message", "")

            # Restore phase stats
            phase_stats_data = checkpoint_data.get("phase_stats", {})
            for phase_name, phase_data in phase_stats_data.items():
                try:
                    phase = ProgressPhase(phase_name)
                    if phase in self._phase_stats:
                        stats = self._phase_stats[phase]
                        stats.start_time = phase_data.get("start_time", stats.start_time)
                        stats.end_time = phase_data.get("end_time")
                        stats.bytes_processed = phase_data.get("bytes_processed", 0)
                        stats.items_processed = phase_data.get("items_processed", 0)
                        stats.actual_duration = phase_data.get("actual_duration")
                except ValueError:
                    # Skip invalid phase names
                    continue

            # Set current phase
            if self._current_phase_index < len(self.phases):
                current_phase = self.phases[self._current_phase_index]
                self.stats.current_phase = current_phase

            return True

        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {e}")
            return False

    def _maybe_save_checkpoint(self) -> None:
        """Save checkpoint if enough time has passed."""
        now = time.time()
        if now - self._last_checkpoint_time >= self._checkpoint_interval:
            self._last_checkpoint_time = now
            self.save_checkpoint()

    def update_bytes(self, bytes_processed: int, current_item: str = "") -> None:
        """Update bytes processed and maybe save checkpoint."""
        super().update_bytes(bytes_processed, current_item)
        self._maybe_save_checkpoint()

    def update_items(self, items_processed: int, current_item: str = "") -> None:
        """Update items processed and maybe save checkpoint."""
        super().update_items(items_processed, current_item)
        self._maybe_save_checkpoint()

    def set_phase(self, phase: ProgressPhase, message: str = "") -> None:
        """Change phase and save checkpoint."""
        super().set_phase(phase, message)
        self.save_checkpoint()
