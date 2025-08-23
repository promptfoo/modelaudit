"""Console-based progress reporting with tqdm integration."""

import sys
from typing import Optional

from .base import ProgressPhase, ProgressReporter, ProgressStats

try:
    from tqdm import tqdm

    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class ConsoleProgressReporter(ProgressReporter):
    """Console progress reporter using tqdm for progress bars."""

    def __init__(
        self,
        update_interval: float = 0.5,
        use_tqdm: bool = True,
        show_bytes: bool = True,
        show_items: bool = True,
        show_speed: bool = True,
        show_eta: bool = True,
        disable_on_non_tty: bool = True,
        unit_scale: bool = True,
    ):
        """Initialize console progress reporter.

        Args:
            update_interval: Minimum time between updates
            use_tqdm: Whether to use tqdm for progress bars
            show_bytes: Whether to show byte-level progress
            show_items: Whether to show item-level progress
            show_speed: Whether to show processing speed
            show_eta: Whether to show estimated time remaining
            disable_on_non_tty: Disable progress bars when not on a TTY
            unit_scale: Enable unit scaling (K, M, G, etc.)
        """
        super().__init__(update_interval)

        self.use_tqdm = use_tqdm and TQDM_AVAILABLE
        self.show_bytes = show_bytes
        self.show_items = show_items
        self.show_speed = show_speed
        self.show_eta = show_eta
        self.unit_scale = unit_scale

        # Disable if not TTY (for CI/CD environments)
        if disable_on_non_tty and not sys.stdout.isatty():
            self.use_tqdm = False

        self._byte_pbar: Optional[tqdm] = None
        self._item_pbar: Optional[tqdm] = None
        self._current_phase = ProgressPhase.INITIALIZING

    def _create_byte_progress_bar(self, stats: ProgressStats) -> "Optional[tqdm]":
        """Create byte-level progress bar."""
        if not self.use_tqdm or not self.show_bytes or stats.total_bytes <= 0:
            return None

        return tqdm(
            total=stats.total_bytes,
            desc="Bytes",
            unit="B" if self.unit_scale else "bytes",
            unit_scale=self.unit_scale,
            unit_divisor=1024,
            disable=False,
            ncols=80,
            leave=True,
        )

    def _create_item_progress_bar(self, stats: ProgressStats) -> "Optional[tqdm]":
        """Create item-level progress bar."""
        if not self.use_tqdm or not self.show_items or stats.total_items <= 0:
            return None

        return tqdm(
            total=stats.total_items,
            desc="Items",
            unit="item" if not self.unit_scale else "",
            unit_scale=self.unit_scale,
            disable=False,
            ncols=80,
            leave=True,
        )

    def _update_progress_bar_desc(self, pbar: "tqdm", stats: ProgressStats) -> None:
        """Update progress bar description with current phase and item."""
        desc_parts = [stats.current_phase.value.capitalize()]

        if stats.current_item:
            # Truncate long item names
            item_name = stats.current_item
            if len(item_name) > 30:
                item_name = item_name[:27] + "..."
            desc_parts.append(f"({item_name})")

        if stats.status_message:
            desc_parts.append(f"- {stats.status_message}")

        pbar.set_description(" ".join(desc_parts))

    def report_progress(self, stats: ProgressStats) -> None:
        """Report progress statistics."""
        # Create progress bars if they don't exist and we have totals
        if self._byte_pbar is None and self.show_bytes and stats.total_bytes > 0:
            self._byte_pbar = self._create_byte_progress_bar(stats)

        if self._item_pbar is None and self.show_items and stats.total_items > 0:
            self._item_pbar = self._create_item_progress_bar(stats)

        # Update byte progress bar
        if self._byte_pbar is not None:
            # Update to current position
            current_pos = min(stats.bytes_processed, stats.total_bytes)
            self._byte_pbar.n = current_pos

            # Update description
            self._update_progress_bar_desc(self._byte_pbar, stats)

            # Add performance metrics to postfix
            postfix = {}
            if self.show_speed and stats.bytes_per_second > 0:
                speed_str = stats.format_bytes(int(stats.bytes_per_second)) + "/s"
                postfix["Speed"] = speed_str

            if self.show_eta and stats.estimated_time_remaining > 0:
                eta_str = stats.format_time(stats.estimated_time_remaining)
                postfix["ETA"] = eta_str

            if postfix:
                self._byte_pbar.set_postfix(postfix)

            self._byte_pbar.refresh()

        # Update item progress bar
        if self._item_pbar is not None:
            # Update to current position
            current_pos = min(stats.items_processed, stats.total_items)
            self._item_pbar.n = current_pos

            # Update description
            self._update_progress_bar_desc(self._item_pbar, stats)

            # Add performance metrics to postfix
            postfix = {}
            if self.show_speed and stats.items_per_second > 0:
                postfix["Speed"] = f"{stats.items_per_second:.1f}/s"

            if self.show_eta and stats.estimated_time_remaining > 0:
                eta_str = stats.format_time(stats.estimated_time_remaining)
                postfix["ETA"] = eta_str

            if postfix:
                self._item_pbar.set_postfix(postfix)

            self._item_pbar.refresh()

        # If no progress bars, fall back to simple text updates
        if not self.use_tqdm:
            self._print_simple_progress(stats)

    def _print_simple_progress(self, stats: ProgressStats) -> None:
        """Print simple text progress when tqdm is not available."""
        parts = [f"Phase: {stats.current_phase.value}"]

        if stats.total_bytes > 0:
            byte_pct = stats.bytes_percentage
            parts.append(f"Bytes: {byte_pct:.1f}%")

        if stats.total_items > 0:
            item_pct = stats.items_percentage
            parts.append(f"Items: {item_pct:.1f}%")

        if stats.current_item:
            parts.append(f"Current: {stats.current_item}")

        if stats.status_message:
            parts.append(f"Status: {stats.status_message}")

        progress_line = " | ".join(parts)
        print(f"\r{progress_line}", end="", flush=True)

    def report_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase) -> None:
        """Report phase change."""
        self._current_phase = new_phase

        if not self.use_tqdm:
            print(f"\nPhase changed: {old_phase.value} → {new_phase.value}")

    def report_completion(self, stats: ProgressStats) -> None:
        """Report scan completion."""
        # Close and finalize progress bars
        if self._byte_pbar is not None:
            # Ensure we show 100% completion
            self._byte_pbar.n = self._byte_pbar.total
            self._byte_pbar.set_description("Completed")
            self._byte_pbar.close()
            self._byte_pbar = None

        if self._item_pbar is not None:
            # Ensure we show 100% completion
            self._item_pbar.n = self._item_pbar.total
            self._item_pbar.set_description("Completed")
            self._item_pbar.close()
            self._item_pbar = None

        # Print completion message
        elapsed_str = stats.format_time(stats.elapsed_time)
        print(f"\nScan completed in {elapsed_str}")

        if stats.bytes_processed > 0:
            processed_str = stats.format_bytes(stats.bytes_processed)
            print(f"Processed: {processed_str}")

        if stats.items_processed > 0:
            print(f"Items processed: {stats.items_processed}")

    def report_error(self, error: Exception, stats: ProgressStats) -> None:
        """Report an error during scanning."""
        # Close progress bars on error
        if self._byte_pbar is not None:
            self._byte_pbar.set_description(f"Error: {str(error)[:50]}")
            self._byte_pbar.close()
            self._byte_pbar = None

        if self._item_pbar is not None:
            self._item_pbar.set_description(f"Error: {str(error)[:50]}")
            self._item_pbar.close()
            self._item_pbar = None

        print(f"\nError during scan: {error}")

    def cleanup(self) -> None:
        """Clean up resources."""
        if self._byte_pbar is not None:
            self._byte_pbar.close()
            self._byte_pbar = None

        if self._item_pbar is not None:
            self._item_pbar.close()
            self._item_pbar = None


class SimpleConsoleReporter(ProgressReporter):
    """Simple console reporter without tqdm dependency."""

    def __init__(
        self,
        update_interval: float = 2.0,
        show_percentage: bool = True,
        show_speed: bool = True,
        show_eta: bool = True,
    ):
        """Initialize simple console reporter.

        Args:
            update_interval: Minimum time between updates
            show_percentage: Whether to show percentage progress
            show_speed: Whether to show processing speed
            show_eta: Whether to show estimated time remaining
        """
        super().__init__(update_interval)
        self.show_percentage = show_percentage
        self.show_speed = show_speed
        self.show_eta = show_eta
        self._last_message_length = 0

    def report_progress(self, stats: ProgressStats) -> None:
        """Report progress statistics."""
        parts = [f"[{stats.current_phase.value.upper()}]"]

        if stats.current_item:
            item_name = stats.current_item
            if len(item_name) > 40:
                item_name = item_name[:37] + "..."
            parts.append(item_name)

        if self.show_percentage and stats.total_bytes > 0:
            parts.append(f"{stats.bytes_percentage:.1f}%")

        if self.show_speed and stats.bytes_per_second > 0:
            speed_str = stats.format_bytes(int(stats.bytes_per_second))
            parts.append(f"{speed_str}/s")

        if self.show_eta and stats.estimated_time_remaining > 0:
            eta_str = stats.format_time(stats.estimated_time_remaining)
            parts.append(f"ETA: {eta_str}")

        if stats.status_message:
            parts.append(f"({stats.status_message})")

        message = " ".join(parts)

        # Clear previous line and print new message
        if self._last_message_length > 0:
            print("\r" + " " * self._last_message_length, end="")

        print(f"\r{message}", end="", flush=True)
        self._last_message_length = len(message)

    def report_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase) -> None:
        """Report phase change."""
        print(f"\n→ {new_phase.value.capitalize()}")

    def report_completion(self, stats: ProgressStats) -> None:
        """Report scan completion."""
        print("\n✓ Scan completed")

        elapsed_str = stats.format_time(stats.elapsed_time)
        print(f"  Duration: {elapsed_str}")

        if stats.bytes_processed > 0:
            processed_str = stats.format_bytes(stats.bytes_processed)
            avg_speed = stats.format_bytes(int(stats.bytes_per_second)) if stats.bytes_per_second > 0 else "N/A"
            print(f"  Processed: {processed_str} (avg: {avg_speed}/s)")

    def report_error(self, error: Exception, stats: ProgressStats) -> None:
        """Report an error during scanning."""
        print(f"\n✗ Error: {error}")
