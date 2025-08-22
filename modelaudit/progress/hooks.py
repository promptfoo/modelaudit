"""Progress hooks system for extensible progress reporting."""

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from .base import ProgressPhase, ProgressStats

logger = logging.getLogger("modelaudit.progress.hooks")


class ProgressHook(ABC):
    """Abstract base class for progress hooks."""

    def __init__(self, name: str):
        """Initialize progress hook.

        Args:
            name: Unique name for this hook
        """
        self.name = name
        self.enabled = True

    @abstractmethod
    def on_start(self, stats: ProgressStats) -> None:
        """Called when scanning starts.

        Args:
            stats: Initial progress statistics
        """
        pass

    @abstractmethod
    def on_progress(self, stats: ProgressStats) -> None:
        """Called on progress updates.

        Args:
            stats: Current progress statistics
        """
        pass

    @abstractmethod
    def on_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase, stats: ProgressStats) -> None:
        """Called when phase changes.

        Args:
            old_phase: Previous phase
            new_phase: New phase
            stats: Current progress statistics
        """
        pass

    @abstractmethod
    def on_complete(self, stats: ProgressStats) -> None:
        """Called when scanning completes.

        Args:
            stats: Final progress statistics
        """
        pass

    @abstractmethod
    def on_error(self, error: Exception, stats: ProgressStats) -> None:
        """Called when an error occurs.

        Args:
            error: The error that occurred
            stats: Progress statistics at time of error
        """
        pass

    def enable(self) -> None:
        """Enable this hook."""
        self.enabled = True

    def disable(self) -> None:
        """Disable this hook."""
        self.enabled = False


class WebhookProgressHook(ProgressHook):
    """Progress hook that sends updates to a webhook URL."""

    def __init__(
        self,
        name: str,
        webhook_url: str,
        headers: Optional[dict[str, str]] = None,
        timeout: float = 10.0,
        retry_attempts: int = 3,
        min_interval: float = 30.0,
    ):
        """Initialize webhook progress hook.

        Args:
            name: Unique name for this hook
            webhook_url: URL to send webhook requests to
            headers: Optional HTTP headers to include
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts on failure
            min_interval: Minimum time between webhook calls
        """
        super().__init__(name)

        self.webhook_url = webhook_url
        self.headers = headers or {}
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.min_interval = min_interval

        self._last_webhook_time = 0.0

    def _should_send_webhook(self) -> bool:
        """Check if enough time has passed to send another webhook."""
        now = time.time()
        if now - self._last_webhook_time >= self.min_interval:
            self._last_webhook_time = now
            return True
        return False

    def _send_webhook(self, payload: dict[str, Any]) -> bool:
        """Send webhook with payload.

        Args:
            payload: JSON payload to send

        Returns:
            True if webhook was sent successfully
        """
        if not self.enabled:
            return False

        try:
            import requests

            for attempt in range(self.retry_attempts):
                try:
                    response = requests.post(
                        self.webhook_url,
                        json=payload,
                        headers=self.headers,
                        timeout=self.timeout,
                    )
                    response.raise_for_status()
                    return True

                except requests.RequestException as e:
                    if attempt == self.retry_attempts - 1:
                        logger.warning(f"Webhook {self.name} failed after {self.retry_attempts} attempts: {e}")
                    else:
                        time.sleep(2**attempt)  # Exponential backoff

        except ImportError:
            logger.warning("requests library not available for webhook hook")

        return False

    def _create_base_payload(self, stats: ProgressStats, event_type: str) -> dict[str, Any]:
        """Create base webhook payload.

        Args:
            stats: Progress statistics
            event_type: Type of event (start, progress, phase_change, complete, error)

        Returns:
            Base payload dictionary
        """
        return {
            "hook_name": self.name,
            "event_type": event_type,
            "timestamp": time.time(),
            "phase": stats.current_phase.value,
            "elapsed_time": stats.elapsed_time,
            "bytes_processed": stats.bytes_processed,
            "total_bytes": stats.total_bytes,
            "bytes_percentage": stats.bytes_percentage,
            "items_processed": stats.items_processed,
            "total_items": stats.total_items,
            "items_percentage": stats.items_percentage,
            "current_item": stats.current_item,
            "status_message": stats.status_message,
            "estimated_time_remaining": stats.estimated_time_remaining,
        }

    def on_start(self, stats: ProgressStats) -> None:
        """Called when scanning starts."""
        payload = self._create_base_payload(stats, "start")
        self._send_webhook(payload)

    def on_progress(self, stats: ProgressStats) -> None:
        """Called on progress updates."""
        if self._should_send_webhook():
            payload = self._create_base_payload(stats, "progress")
            self._send_webhook(payload)

    def on_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase, stats: ProgressStats) -> None:
        """Called when phase changes."""
        payload = self._create_base_payload(stats, "phase_change")
        payload["old_phase"] = old_phase.value
        payload["new_phase"] = new_phase.value
        self._send_webhook(payload)

    def on_complete(self, stats: ProgressStats) -> None:
        """Called when scanning completes."""
        payload = self._create_base_payload(stats, "complete")
        self._send_webhook(payload)

    def on_error(self, error: Exception, stats: ProgressStats) -> None:
        """Called when an error occurs."""
        payload = self._create_base_payload(stats, "error")
        payload["error_type"] = type(error).__name__
        payload["error_message"] = str(error)
        self._send_webhook(payload)


class EmailProgressHook(ProgressHook):
    """Progress hook that sends email notifications."""

    def __init__(
        self,
        name: str,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_email: str,
        to_emails: list[str],
        use_tls: bool = True,
        send_on_start: bool = True,
        send_on_complete: bool = True,
        send_on_error: bool = True,
        send_periodic: bool = False,
        periodic_interval: float = 1800.0,  # 30 minutes
    ):
        """Initialize email progress hook.

        Args:
            name: Unique name for this hook
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            username: SMTP username
            password: SMTP password
            from_email: From email address
            to_emails: List of recipient email addresses
            use_tls: Whether to use TLS
            send_on_start: Send email when scanning starts
            send_on_complete: Send email when scanning completes
            send_on_error: Send email when errors occur
            send_periodic: Send periodic progress emails
            periodic_interval: Interval for periodic emails in seconds
        """
        super().__init__(name)

        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_emails = to_emails
        self.use_tls = use_tls

        self.send_on_start = send_on_start
        self.send_on_complete = send_on_complete
        self.send_on_error = send_on_error
        self.send_periodic = send_periodic
        self.periodic_interval = periodic_interval

        self._last_periodic_email = 0.0
        self._scan_start_time: Optional[float] = None

    def _send_email(self, subject: str, body: str) -> bool:
        """Send email notification.

        Args:
            subject: Email subject
            body: Email body

        Returns:
            True if email was sent successfully
        """
        if not self.enabled:
            return False

        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            # Create message
            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.to_emails)
            msg["Subject"] = subject

            msg.attach(MIMEText(body, "plain"))

            # Send email
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            if self.use_tls:
                server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()

            logger.debug(f"Email sent successfully from hook {self.name}")
            return True

        except Exception as e:
            logger.warning(f"Failed to send email from hook {self.name}: {e}")
            return False

    def _format_stats(self, stats: ProgressStats) -> str:
        """Format progress statistics for email body."""
        lines = [
            f"Phase: {stats.current_phase.value.capitalize()}",
            f"Elapsed Time: {stats.format_time(stats.elapsed_time)}",
        ]

        if stats.total_bytes > 0:
            processed = stats.format_bytes(stats.bytes_processed)
            total = stats.format_bytes(stats.total_bytes)
            pct = stats.bytes_percentage
            lines.append(f"Bytes Processed: {processed} / {total} ({pct:.1f}%)")

        if stats.total_items > 0:
            lines.append(
                f"Items Processed: {stats.items_processed:,} / {stats.total_items:,} ({stats.items_percentage:.1f}%)"
            )

        if stats.bytes_per_second > 0:
            lines.append(f"Speed: {stats.format_bytes(int(stats.bytes_per_second))}/s")

        if stats.estimated_time_remaining > 0:
            lines.append(f"Estimated Time Remaining: {stats.format_time(stats.estimated_time_remaining)}")

        if stats.current_item:
            lines.append(f"Current Item: {stats.current_item}")

        if stats.status_message:
            lines.append(f"Status: {stats.status_message}")

        return "\n".join(lines)

    def on_start(self, stats: ProgressStats) -> None:
        """Called when scanning starts."""
        self._scan_start_time = time.time()

        if self.send_on_start:
            subject = f"ModelAudit Scan Started - {self.name}"
            body = f"ModelAudit scan has started.\n\n{self._format_stats(stats)}"
            self._send_email(subject, body)

    def on_progress(self, stats: ProgressStats) -> None:
        """Called on progress updates."""
        if self.send_periodic:
            now = time.time()
            if now - self._last_periodic_email >= self.periodic_interval:
                self._last_periodic_email = now

                subject = f"ModelAudit Scan Progress - {self.name}"
                body = f"ModelAudit scan progress update.\n\n{self._format_stats(stats)}"
                self._send_email(subject, body)

    def on_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase, stats: ProgressStats) -> None:
        """Called when phase changes."""
        # Could optionally send phase change notifications
        pass

    def on_complete(self, stats: ProgressStats) -> None:
        """Called when scanning completes."""
        if self.send_on_complete:
            subject = f"ModelAudit Scan Completed - {self.name}"
            body = f"ModelAudit scan has completed successfully.\n\n{self._format_stats(stats)}"
            self._send_email(subject, body)

    def on_error(self, error: Exception, stats: ProgressStats) -> None:
        """Called when an error occurs."""
        if self.send_on_error:
            subject = f"ModelAudit Scan Error - {self.name}"
            error_info = f"{type(error).__name__}: {error}"
            progress_info = self._format_stats(stats)
            body = (
                f"An error occurred during ModelAudit scan:\n\n{error_info}"
                f"\n\nProgress at time of error:\n{progress_info}"
            )
            self._send_email(subject, body)


class SlackProgressHook(ProgressHook):
    """Progress hook that sends updates to Slack."""

    def __init__(
        self,
        name: str,
        webhook_url: str,
        channel: Optional[str] = None,
        username: str = "ModelAudit",
        emoji: str = ":robot_face:",
        send_on_start: bool = True,
        send_on_complete: bool = True,
        send_on_error: bool = True,
        min_interval: float = 300.0,  # 5 minutes
    ):
        """Initialize Slack progress hook.

        Args:
            name: Unique name for this hook
            webhook_url: Slack webhook URL
            channel: Optional channel to send to
            username: Username for bot messages
            emoji: Emoji icon for bot messages
            send_on_start: Send message when scanning starts
            send_on_complete: Send message when scanning completes
            send_on_error: Send message when errors occur
            min_interval: Minimum interval between progress messages
        """
        super().__init__(name)

        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.emoji = emoji

        self.send_on_start = send_on_start
        self.send_on_complete = send_on_complete
        self.send_on_error = send_on_error
        self.min_interval = min_interval

        self._last_message_time = 0.0

    def _should_send_message(self) -> bool:
        """Check if enough time has passed to send another message."""
        now = time.time()
        if now - self._last_message_time >= self.min_interval:
            self._last_message_time = now
            return True
        return False

    def _send_slack_message(self, message: str, color: str = "good") -> bool:
        """Send message to Slack.

        Args:
            message: Message text to send
            color: Message color (good, warning, danger)

        Returns:
            True if message was sent successfully
        """
        if not self.enabled:
            return False

        try:
            import requests

            payload: dict[str, Any] = {
                "text": message,
                "username": self.username,
                "icon_emoji": self.emoji,
            }

            if self.channel:
                payload["channel"] = self.channel

            # Add color for rich formatting
            if color:
                payload["attachments"] = [
                    {
                        "color": color,
                        "text": message,
                    }
                ]
                payload["text"] = ""  # Move text to attachment

            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()

            logger.debug(f"Slack message sent successfully from hook {self.name}")
            return True

        except Exception as e:
            logger.warning(f"Failed to send Slack message from hook {self.name}: {e}")
            return False

    def _format_progress_message(self, stats: ProgressStats, event_type: str) -> tuple[str, str]:
        """Format progress statistics for Slack message.

        Returns:
            Tuple of (message, color)
        """
        if event_type == "start":
            message = f"🚀 ModelAudit scan started\nPhase: {stats.current_phase.value.capitalize()}"
            color = "good"
        elif event_type == "complete":
            elapsed_str = stats.format_time(stats.elapsed_time)
            message = f"✅ ModelAudit scan completed in {elapsed_str}"
            if stats.bytes_processed > 0:
                processed_str = stats.format_bytes(stats.bytes_processed)
                message += f"\nProcessed: {processed_str}"
            color = "good"
        elif event_type == "progress":
            parts = [f"⚡ Scan Progress: {stats.current_phase.value.capitalize()}"]

            if stats.total_bytes > 0:
                parts.append(f"📊 {stats.bytes_percentage:.1f}% complete")

            if stats.bytes_per_second > 0:
                speed_str = stats.format_bytes(int(stats.bytes_per_second))
                parts.append(f"🚀 Speed: {speed_str}/s")

            if stats.estimated_time_remaining > 0:
                eta_str = stats.format_time(stats.estimated_time_remaining)
                parts.append(f"⏱️ ETA: {eta_str}")

            message = "\n".join(parts)
            color = "warning"
        else:  # error
            message = f"❌ ModelAudit scan error in {stats.current_phase.value} phase"
            color = "danger"

        return message, color

    def on_start(self, stats: ProgressStats) -> None:
        """Called when scanning starts."""
        if self.send_on_start:
            message, color = self._format_progress_message(stats, "start")
            self._send_slack_message(message, color)

    def on_progress(self, stats: ProgressStats) -> None:
        """Called on progress updates."""
        if self._should_send_message():
            message, color = self._format_progress_message(stats, "progress")
            self._send_slack_message(message, color)

    def on_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase, stats: ProgressStats) -> None:
        """Called when phase changes."""
        message = f"🔄 Phase changed: {old_phase.value} → {new_phase.value}"
        self._send_slack_message(message, "warning")

    def on_complete(self, stats: ProgressStats) -> None:
        """Called when scanning completes."""
        if self.send_on_complete:
            message, color = self._format_progress_message(stats, "complete")
            self._send_slack_message(message, color)

    def on_error(self, error: Exception, stats: ProgressStats) -> None:
        """Called when an error occurs."""
        if self.send_on_error:
            message = f"❌ ModelAudit scan error: {type(error).__name__}\n{str(error)[:200]}"
            self._send_slack_message(message, "danger")


class CustomFunctionHook(ProgressHook):
    """Progress hook that calls custom functions."""

    def __init__(
        self,
        name: str,
        on_start_func: Optional[Callable[[ProgressStats], None]] = None,
        on_progress_func: Optional[Callable[[ProgressStats], None]] = None,
        on_phase_change_func: Optional[Callable[[ProgressPhase, ProgressPhase, ProgressStats], None]] = None,
        on_complete_func: Optional[Callable[[ProgressStats], None]] = None,
        on_error_func: Optional[Callable[[Exception, ProgressStats], None]] = None,
    ):
        """Initialize custom function hook.

        Args:
            name: Unique name for this hook
            on_start_func: Function to call on scan start
            on_progress_func: Function to call on progress updates
            on_phase_change_func: Function to call on phase changes
            on_complete_func: Function to call on scan completion
            on_error_func: Function to call on errors
        """
        super().__init__(name)

        self._on_start_func = on_start_func
        self._on_progress_func = on_progress_func
        self._on_phase_change_func = on_phase_change_func
        self._on_complete_func = on_complete_func
        self._on_error_func = on_error_func

    def on_start(self, stats: ProgressStats) -> None:
        """Called when scanning starts."""
        if self._on_start_func:
            try:
                self._on_start_func(stats)
            except Exception as e:
                logger.warning(f"Custom start function failed in hook {self.name}: {e}")

    def on_progress(self, stats: ProgressStats) -> None:
        """Called on progress updates."""
        if self._on_progress_func:
            try:
                self._on_progress_func(stats)
            except Exception as e:
                logger.warning(f"Custom progress function failed in hook {self.name}: {e}")

    def on_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase, stats: ProgressStats) -> None:
        """Called when phase changes."""
        if self._on_phase_change_func:
            try:
                self._on_phase_change_func(old_phase, new_phase, stats)
            except Exception as e:
                logger.warning(f"Custom phase change function failed in hook {self.name}: {e}")

    def on_complete(self, stats: ProgressStats) -> None:
        """Called when scanning completes."""
        if self._on_complete_func:
            try:
                self._on_complete_func(stats)
            except Exception as e:
                logger.warning(f"Custom complete function failed in hook {self.name}: {e}")

    def on_error(self, error: Exception, stats: ProgressStats) -> None:
        """Called when an error occurs."""
        if self._on_error_func:
            try:
                self._on_error_func(error, stats)
            except Exception as e:
                logger.warning(f"Custom error function failed in hook {self.name}: {e}")


class ProgressHookManager:
    """Manager for progress hooks."""

    def __init__(self) -> None:
        """Initialize progress hook manager."""
        self._hooks: dict[str, ProgressHook] = {}

    def add_hook(self, hook: ProgressHook) -> None:
        """Add a progress hook.

        Args:
            hook: Progress hook to add
        """
        self._hooks[hook.name] = hook
        logger.debug(f"Added progress hook: {hook.name}")

    def remove_hook(self, name: str) -> bool:
        """Remove a progress hook.

        Args:
            name: Name of hook to remove

        Returns:
            True if hook was removed
        """
        if name in self._hooks:
            del self._hooks[name]
            logger.debug(f"Removed progress hook: {name}")
            return True
        return False

    def get_hook(self, name: str) -> Optional[ProgressHook]:
        """Get a progress hook by name.

        Args:
            name: Name of hook to get

        Returns:
            Progress hook or None if not found
        """
        return self._hooks.get(name)

    def list_hooks(self) -> list[str]:
        """List all hook names.

        Returns:
            List of hook names
        """
        return list(self._hooks.keys())

    def enable_hook(self, name: str) -> bool:
        """Enable a hook.

        Args:
            name: Name of hook to enable

        Returns:
            True if hook was enabled
        """
        hook = self._hooks.get(name)
        if hook:
            hook.enable()
            return True
        return False

    def disable_hook(self, name: str) -> bool:
        """Disable a hook.

        Args:
            name: Name of hook to disable

        Returns:
            True if hook was disabled
        """
        hook = self._hooks.get(name)
        if hook:
            hook.disable()
            return True
        return False

    def clear_hooks(self) -> None:
        """Remove all hooks."""
        self._hooks.clear()
        logger.debug("Cleared all progress hooks")

    def trigger_start(self, stats: ProgressStats) -> None:
        """Trigger start event for all hooks."""
        for hook in self._hooks.values():
            if hook.enabled:
                try:
                    hook.on_start(stats)
                except Exception as e:
                    logger.warning(f"Hook {hook.name} failed on start: {e}")

    def trigger_progress(self, stats: ProgressStats) -> None:
        """Trigger progress event for all hooks."""
        for hook in self._hooks.values():
            if hook.enabled:
                try:
                    hook.on_progress(stats)
                except Exception as e:
                    logger.warning(f"Hook {hook.name} failed on progress: {e}")

    def trigger_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase, stats: ProgressStats) -> None:
        """Trigger phase change event for all hooks."""
        for hook in self._hooks.values():
            if hook.enabled:
                try:
                    hook.on_phase_change(old_phase, new_phase, stats)
                except Exception as e:
                    logger.warning(f"Hook {hook.name} failed on phase change: {e}")

    def trigger_complete(self, stats: ProgressStats) -> None:
        """Trigger complete event for all hooks."""
        for hook in self._hooks.values():
            if hook.enabled:
                try:
                    hook.on_complete(stats)
                except Exception as e:
                    logger.warning(f"Hook {hook.name} failed on complete: {e}")

    def trigger_error(self, error: Exception, stats: ProgressStats) -> None:
        """Trigger error event for all hooks."""
        for hook in self._hooks.values():
            if hook.enabled:
                try:
                    hook.on_error(error, stats)
                except Exception as e:
                    logger.warning(f"Hook {hook.name} failed on error: {e}")


# Global hook manager instance
global_hook_manager = ProgressHookManager()
