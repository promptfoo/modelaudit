"""File-based progress reporting for logging and monitoring."""

import json
import time
from pathlib import Path
from typing import Optional, TextIO

from .base import ProgressPhase, ProgressReporter, ProgressStats


class FileProgressReporter(ProgressReporter):
    """File-based progress reporter that writes to log files."""

    def __init__(
        self,
        log_file: str,
        update_interval: float = 5.0,
        format_type: str = "json",
        append_mode: bool = True,
        include_timestamps: bool = True,
        auto_flush: bool = True,
    ):
        """Initialize file progress reporter.

        Args:
            log_file: Path to log file
            update_interval: Minimum time between updates
            format_type: Format type ('json' or 'text')
            append_mode: Whether to append to existing file
            include_timestamps: Whether to include timestamps
            auto_flush: Whether to flush after each write
        """
        super().__init__(update_interval)

        self.log_file = Path(log_file)
        self.format_type = format_type.lower()
        self.include_timestamps = include_timestamps
        self.auto_flush = auto_flush

        # Create directory if it doesn't exist
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Open file
        mode = "a" if append_mode else "w"
        self._file: Optional[TextIO] = open(self.log_file, mode, encoding="utf-8")  # type: ignore[assignment] # noqa: SIM115

        # Write header for new files
        if not append_mode or self.log_file.stat().st_size == 0:
            self._write_header()

    def _write_header(self) -> None:
        """Write log file header."""
        if self.format_type == "json":
            header = {
                "type": "header",
                "timestamp": time.time(),
                "message": "ModelAudit progress log started",
                "format_version": "1.0",
            }
            self._write_json(header)
        else:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            self._write_line(f"[{timestamp}] ModelAudit progress log started")
            self._write_line("-" * 60)

    def _write_json(self, data: dict) -> None:
        """Write JSON data to file."""
        if self._file is None:
            return

        if self.include_timestamps and "timestamp" not in data:
            data["timestamp"] = time.time()

        json.dump(data, self._file)
        self._file.write("\n")

        if self.auto_flush:
            self._file.flush()

    def _write_line(self, line: str) -> None:
        """Write text line to file."""
        if self._file is None:
            return

        if self.include_timestamps and not line.startswith("["):
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            line = f"[{timestamp}] {line}"

        self._file.write(line + "\n")

        if self.auto_flush:
            self._file.flush()

    def _format_stats_json(self, stats: ProgressStats) -> dict:
        """Format stats as JSON object."""
        return {
            "type": "progress",
            "timestamp": time.time(),
            "phase": stats.current_phase.value,
            "elapsed_time": stats.elapsed_time,
            "bytes": {
                "processed": stats.bytes_processed,
                "total": stats.total_bytes,
                "percentage": stats.bytes_percentage,
                "speed": stats.bytes_per_second,
            },
            "items": {
                "processed": stats.items_processed,
                "total": stats.total_items,
                "percentage": stats.items_percentage,
                "speed": stats.items_per_second,
            },
            "current_item": stats.current_item,
            "status_message": stats.status_message,
            "eta_seconds": stats.estimated_time_remaining,
        }

    def _format_stats_text(self, stats: ProgressStats) -> str:
        """Format stats as text line."""
        parts = [f"Phase: {stats.current_phase.value}"]

        if stats.total_bytes > 0:
            byte_pct = stats.bytes_percentage
            processed_str = stats.format_bytes(stats.bytes_processed)
            total_str = stats.format_bytes(stats.total_bytes)
            parts.append(f"Bytes: {processed_str}/{total_str} ({byte_pct:.1f}%)")

        if stats.total_items > 0:
            item_pct = stats.items_percentage
            parts.append(f"Items: {stats.items_processed}/{stats.total_items} ({item_pct:.1f}%)")

        if stats.bytes_per_second > 0:
            speed_str = stats.format_bytes(int(stats.bytes_per_second))
            parts.append(f"Speed: {speed_str}/s")

        if stats.estimated_time_remaining > 0:
            eta_str = stats.format_time(stats.estimated_time_remaining)
            parts.append(f"ETA: {eta_str}")

        if stats.current_item:
            parts.append(f"Current: {stats.current_item}")

        if stats.status_message:
            parts.append(f"Status: {stats.status_message}")

        return " | ".join(parts)

    def report_progress(self, stats: ProgressStats) -> None:
        """Report progress statistics."""
        if self.format_type == "json":
            self._write_json(self._format_stats_json(stats))
        else:
            self._write_line(self._format_stats_text(stats))

    def report_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase) -> None:
        """Report phase change."""
        if self.format_type == "json":
            data = {
                "type": "phase_change",
                "timestamp": time.time(),
                "old_phase": old_phase.value,
                "new_phase": new_phase.value,
            }
            self._write_json(data)
        else:
            self._write_line(f"Phase changed: {old_phase.value} → {new_phase.value}")

    def report_completion(self, stats: ProgressStats) -> None:
        """Report scan completion."""
        if self.format_type == "json":
            data = {
                "type": "completion",
                "timestamp": time.time(),
                "duration": stats.elapsed_time,
                "bytes_processed": stats.bytes_processed,
                "items_processed": stats.items_processed,
                "final_phase": stats.current_phase.value,
            }
            self._write_json(data)
        else:
            elapsed_str = stats.format_time(stats.elapsed_time)
            self._write_line(f"Scan completed in {elapsed_str}")
            if stats.bytes_processed > 0:
                processed_str = stats.format_bytes(stats.bytes_processed)
                self._write_line(f"Total processed: {processed_str}")
            if stats.items_processed > 0:
                self._write_line(f"Items processed: {stats.items_processed}")

    def report_error(self, error: Exception, stats: ProgressStats) -> None:
        """Report an error during scanning."""
        if self.format_type == "json":
            data = {
                "type": "error",
                "timestamp": time.time(),
                "error_type": type(error).__name__,
                "error_message": str(error),
                "phase": stats.current_phase.value,
                "bytes_processed": stats.bytes_processed,
                "items_processed": stats.items_processed,
            }
            self._write_json(data)
        else:
            self._write_line(f"ERROR: {type(error).__name__}: {error}")
            self._write_line(f"  Phase: {stats.current_phase.value}")
            self._write_line(f"  Progress: {stats.bytes_processed} bytes, {stats.items_processed} items")

    def close(self) -> None:
        """Close the log file."""
        if self._file is not None:
            # Write footer
            if self.format_type == "json":
                footer = {
                    "type": "footer",
                    "timestamp": time.time(),
                    "message": "Log file closed",
                }
                self._write_json(footer)
            else:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                self._write_line(f"[{timestamp}] Log file closed")

            self._file.close()
            self._file = None

    def __del__(self):
        """Cleanup when object is destroyed."""
        self.close()


class CSVProgressReporter(ProgressReporter):
    """CSV-based progress reporter for data analysis."""

    def __init__(
        self,
        csv_file: str,
        update_interval: float = 10.0,
        append_mode: bool = True,
    ):
        """Initialize CSV progress reporter.

        Args:
            csv_file: Path to CSV file
            update_interval: Minimum time between updates
            append_mode: Whether to append to existing file
        """
        super().__init__(update_interval)

        self.csv_file = Path(csv_file)
        self.csv_file.parent.mkdir(parents=True, exist_ok=True)

        # Check if we need to write header
        write_header = not append_mode or not self.csv_file.exists() or self.csv_file.stat().st_size == 0

        # Open CSV file
        mode = "a" if append_mode else "w"
        self._file: Optional[TextIO] = open(self.csv_file, mode, encoding="utf-8")  # type: ignore[assignment] # noqa: SIM115

        if write_header:
            self._write_header()

    def _write_header(self) -> None:
        """Write CSV header row."""
        if self._file is None:
            return

        headers = [
            "timestamp",
            "phase",
            "elapsed_time",
            "bytes_processed",
            "total_bytes",
            "bytes_percentage",
            "bytes_per_second",
            "items_processed",
            "total_items",
            "items_percentage",
            "items_per_second",
            "eta_seconds",
            "current_item",
            "status_message",
        ]

        self._file.write(",".join(headers) + "\n")
        self._file.flush()

    def _write_stats_row(self, stats: ProgressStats, event_type: str = "progress") -> None:
        """Write stats as CSV row."""
        if self._file is None:
            return

        # Escape commas and quotes in string fields
        def escape_csv(value: str) -> str:
            if "," in value or '"' in value or "\n" in value:
                escaped = value.replace('"', '""')
                return f'"{escaped}"'
            return value

        values = [
            str(time.time()),
            stats.current_phase.value,
            f"{stats.elapsed_time:.2f}",
            str(stats.bytes_processed),
            str(stats.total_bytes),
            f"{stats.bytes_percentage:.2f}",
            f"{stats.bytes_per_second:.2f}",
            str(stats.items_processed),
            str(stats.total_items),
            f"{stats.items_percentage:.2f}",
            f"{stats.items_per_second:.2f}",
            f"{stats.estimated_time_remaining:.2f}",
            escape_csv(stats.current_item),
            escape_csv(stats.status_message),
        ]

        self._file.write(",".join(values) + "\n")
        self._file.flush()

    def report_progress(self, stats: ProgressStats) -> None:
        """Report progress statistics."""
        self._write_stats_row(stats, "progress")

    def report_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase) -> None:
        """Report phase change."""
        # Phase changes are captured in regular progress updates
        pass

    def report_completion(self, stats: ProgressStats) -> None:
        """Report scan completion."""
        self._write_stats_row(stats, "completion")

    def report_error(self, error: Exception, stats: ProgressStats) -> None:
        """Report an error during scanning."""
        # Create stats with error information in status message
        error_stats = ProgressStats(
            start_time=stats.start_time,
            last_update_time=stats.last_update_time,
            bytes_processed=stats.bytes_processed,
            total_bytes=stats.total_bytes,
            items_processed=stats.items_processed,
            total_items=stats.total_items,
            current_phase=stats.current_phase,
            bytes_per_second=stats.bytes_per_second,
            items_per_second=stats.items_per_second,
            estimated_time_remaining=stats.estimated_time_remaining,
            current_item=stats.current_item,
            status_message=f"ERROR: {type(error).__name__}: {str(error)[:100]}",
        )
        self._write_stats_row(error_stats, "error")

    def close(self) -> None:
        """Close the CSV file."""
        if self._file is not None:
            self._file.close()
            self._file = None

    def __del__(self):
        """Cleanup when object is destroyed."""
        self.close()
