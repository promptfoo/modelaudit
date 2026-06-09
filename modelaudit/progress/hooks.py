"""Progress hooks system for extensible progress reporting."""

import http.client
import ipaddress
import json
import logging
import math
import os
import socket
import ssl
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Collection
from typing import Any
from urllib.parse import unquote, urlparse

from .base import ProgressPhase, ProgressStats

logger = logging.getLogger("modelaudit.progress.hooks")

_PROGRESS_ALLOWED_HOSTS_ENV = "MODELAUDIT_PROGRESS_ALLOWED_HOSTS"
_PROGRESS_WEBHOOK_ALLOWED_HOSTS_ENV = "MODELAUDIT_PROGRESS_WEBHOOK_ALLOWED_HOSTS"
_PROGRESS_SMTP_ALLOWED_HOSTS_ENV = "MODELAUDIT_PROGRESS_SMTP_ALLOWED_HOSTS"
_DEFAULT_SLACK_WEBHOOK_HOSTS = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})
_INTERNAL_HOST_SUFFIXES = frozenset({".localhost", ".local", ".internal", ".lan", ".home", ".corp", ".intranet"})
_NAT64_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)
_ISATAP_MARKERS = frozenset({b"\x00\x00\x5e\xfe", b"\x02\x00\x5e\xfe"})
_DEFAULT_NETWORK_TIMEOUT_SECONDS = 10.0
_MAX_NETWORK_TIMEOUT_SECONDS = 60.0

ResolvedAddress = tuple[socket.AddressFamily, str, int]


def _normalize_destination_host(hostname: str) -> str:
    return unquote(hostname).strip().lower().rstrip(".")


def _host_from_config_value(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""

    parsed_ip = _parse_ip_literal(candidate)
    if parsed_ip is not None:
        return parsed_ip.compressed

    try:
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        if parsed.username is not None or parsed.password is not None:
            return ""
        hostname = parsed.hostname or ""
    except ValueError:
        return ""
    if not hostname:
        return ""
    return _canonical_destination_host(hostname)


def _get_allowed_hosts(env_name: str, configured_hosts: Collection[str] | None = None) -> set[str]:
    hosts = {_host_from_config_value(host) for host in configured_hosts or ()}
    for current_env_name in (_PROGRESS_ALLOWED_HOSTS_ENV, env_name):
        raw_hosts = os.getenv(current_env_name, "")
        hosts.update(_host_from_config_value(value) for value in raw_hosts.split(","))
    return {host for host in hosts if host}


def _parse_ip_literal(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    candidate = hostname.strip("[]")
    if ":" in candidate and "%" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass

    if not candidate or any(char not in "0123456789abcdefABCDEFxX." for char in candidate):
        return None

    try:
        return ipaddress.ip_address(socket.inet_aton(candidate))
    except OSError:
        return None


def _canonical_destination_host(hostname: str) -> str:
    normalized = _normalize_destination_host(hostname)
    parsed_ip = _parse_ip_literal(normalized)
    if parsed_ip is not None:
        return parsed_ip.compressed
    try:
        return normalized.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"Invalid internationalized destination host '{hostname}'") from exc


def _embedded_ipv4_addresses(address: ipaddress.IPv6Address) -> tuple[ipaddress.IPv4Address, ...]:
    embedded: list[ipaddress.IPv4Address] = []
    if address.ipv4_mapped is not None:
        embedded.append(address.ipv4_mapped)
    if address.sixtofour is not None:
        embedded.append(address.sixtofour)
    if address.teredo is not None:
        embedded.extend(address.teredo)
    if int(address) >> 32 == 0:
        embedded.append(ipaddress.IPv4Address(address.packed[-4:]))
    if any(address in network for network in _NAT64_NETWORKS):
        embedded.append(ipaddress.IPv4Address(address.packed[-4:]))
    if address.packed[8:12] in _ISATAP_MARKERS:
        embedded.append(ipaddress.IPv4Address(address.packed[-4:]))
    return tuple(embedded)


def _is_public_ip_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if not address.is_global or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        return all(_is_public_ip_address(embedded) for embedded in _embedded_ipv4_addresses(address))
    return True


def _is_internal_destination_host(hostname: str) -> bool:
    if not hostname:
        return True
    if hostname == "localhost" or hostname.endswith(tuple(_INTERNAL_HOST_SUFFIXES)):
        return True
    if "." not in hostname and ":" not in hostname:
        return True

    parsed_ip = _parse_ip_literal(hostname)
    if parsed_ip is None:
        return False
    return not _is_public_ip_address(parsed_ip)


def _validate_public_destination_host(hostname: str, destination_type: str) -> None:
    if _is_internal_destination_host(hostname):
        raise ValueError(f"{destination_type} host '{hostname}' is not a permitted public egress destination")


def _resolve_public_addresses(hostname: str, port: int, destination_type: str) -> tuple[ResolvedAddress, ...]:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"{destination_type} port is invalid")
    try:
        address_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(
            f"{destination_type} host '{hostname}' could not be resolved to a permitted public address"
        ) from exc

    resolved_addresses: list[ResolvedAddress] = []
    seen_addresses: set[tuple[socket.AddressFamily, str, int]] = set()
    for family, socket_type, protocol, _canonical_name, socket_address in address_info:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            raise ValueError(f"{destination_type} host '{hostname}' resolved to an unsupported socket family")
        if socket_type not in {0, socket.SOCK_STREAM} or protocol not in {0, socket.IPPROTO_TCP}:
            raise ValueError(f"{destination_type} host '{hostname}' resolved to a non-TCP socket")
        if not isinstance(socket_address, tuple) or len(socket_address) < 2:
            raise ValueError(f"{destination_type} host '{hostname}' returned a malformed socket address")
        raw_address, resolved_port = socket_address[:2]
        if not isinstance(raw_address, str) or not isinstance(resolved_port, int) or resolved_port != port:
            raise ValueError(f"{destination_type} host '{hostname}' returned an invalid socket address or port")
        if "%" in raw_address:
            raise ValueError(f"{destination_type} host '{hostname}' returned a scoped IPv6 address")
        try:
            parsed_address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise ValueError(f"{destination_type} host '{hostname}' returned an invalid IP address") from exc
        if not _is_public_ip_address(parsed_address):
            raise ValueError(
                f"{destination_type} host '{hostname}' did not resolve exclusively to permitted public addresses"
            )
        canonical_address = parsed_address.compressed
        address_key = (family, canonical_address, resolved_port)
        if address_key not in seen_addresses:
            seen_addresses.add(address_key)
            resolved_addresses.append(address_key)

    if not resolved_addresses:
        raise ValueError(
            f"{destination_type} host '{hostname}' did not resolve exclusively to permitted public addresses"
        )
    return tuple(resolved_addresses)


def _webhook_destination(webhook_url: str, destination_type: str) -> tuple[str, int]:
    if "\\" in webhook_url or any(ord(char) < 32 or ord(char) == 127 for char in webhook_url):
        raise ValueError(f"{destination_type} URL has an invalid host or port")
    parsed = urlparse(webhook_url)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{destination_type} URL must not include user information")
    try:
        hostname = _canonical_destination_host(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{destination_type} URL has an invalid host or port") from exc
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    return hostname, port


def _validate_allowed_destination_host(
    hostname: str,
    *,
    destination_type: str,
    allowed_hosts: Collection[str] | None,
    env_name: str,
    default_allowed_hosts: Collection[str] = (),
) -> None:
    normalized_defaults = {_host_from_config_value(host) for host in default_allowed_hosts}
    trusted_hosts = normalized_defaults | _get_allowed_hosts(env_name, allowed_hosts)
    if hostname not in trusted_hosts:
        raise ValueError(
            f"{destination_type} host '{hostname}' is not allowed; configure {env_name} or "
            f"{_PROGRESS_ALLOWED_HOSTS_ENV} with the explicit public host"
        )


def _validate_progress_webhook_url(
    webhook_url: str,
    *,
    destination_type: str,
    allowed_hosts: Collection[str] | None = None,
    default_allowed_hosts: Collection[str] = (),
    require_https: bool = False,
) -> str:
    parsed = urlparse(webhook_url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"{destination_type} URL must use http or https")
    if require_https and scheme != "https":
        raise ValueError(f"{destination_type} URL must use https")

    hostname, _port = _webhook_destination(webhook_url, destination_type)
    _validate_public_destination_host(hostname, destination_type)
    _validate_allowed_destination_host(
        hostname,
        destination_type=destination_type,
        allowed_hosts=allowed_hosts,
        env_name=_PROGRESS_WEBHOOK_ALLOWED_HOSTS_ENV,
        default_allowed_hosts=default_allowed_hosts,
    )
    return webhook_url


def _validate_progress_smtp_host(
    smtp_host: str,
    *,
    allowed_hosts: Collection[str] | None = None,
) -> str:
    hostname = _host_from_config_value(smtp_host)
    _validate_public_destination_host(hostname, "SMTP")
    _validate_allowed_destination_host(
        hostname,
        destination_type="SMTP",
        allowed_hosts=allowed_hosts,
        env_name=_PROGRESS_SMTP_ALLOWED_HOSTS_ENV,
    )
    return hostname


def _bounded_network_timeout(timeout: float) -> float:
    try:
        numeric_timeout = float(timeout)
    except (TypeError, ValueError):
        return _DEFAULT_NETWORK_TIMEOUT_SECONDS
    if not math.isfinite(numeric_timeout) or numeric_timeout <= 0:
        return _DEFAULT_NETWORK_TIMEOUT_SECONDS
    return min(numeric_timeout, _MAX_NETWORK_TIMEOUT_SECONDS)


def _secure_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _connect_pinned_socket(family: socket.AddressFamily, address: str, port: int, timeout: float) -> socket.socket:
    connection = socket.socket(family, socket.SOCK_STREAM)
    try:
        connection.settimeout(_bounded_network_timeout(timeout))
        socket_address: tuple[Any, ...]
        socket_address = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
        connection.connect(socket_address)
        return connection
    except Exception:
        connection.close()
        raise


def _webhook_request_target(webhook_url: str, destination_type: str) -> tuple[str, str, int, str]:
    import requests

    configured_destination = _webhook_destination(webhook_url, destination_type)
    try:
        prepared_url = requests.Request("POST", webhook_url).prepare().url
    except requests.RequestException as exc:
        raise ValueError(f"{destination_type} URL could not be prepared safely") from exc
    if not prepared_url:
        raise ValueError(f"{destination_type} URL could not be prepared safely")

    prepared = urlparse(prepared_url)
    prepared_destination = _webhook_destination(prepared_url, destination_type)
    if configured_destination != prepared_destination:
        raise ValueError(f"{destination_type} URL resolves to an ambiguous network destination")

    request_target = prepared.path or "/"
    if prepared.params:
        request_target += f";{prepared.params}"
    if prepared.query:
        request_target += f"?{prepared.query}"
    return prepared.scheme.lower(), prepared_destination[0], prepared_destination[1], request_target


def _host_header(hostname: str, port: int, scheme: str) -> str:
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    if port != default_port:
        return f"{rendered_host}:{port}"
    return rendered_host


def _post_to_pinned_address(
    *,
    scheme: str,
    hostname: str,
    port: int,
    request_target: str,
    resolved_address: ResolvedAddress,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
) -> int:
    family, address, resolved_port = resolved_address
    raw_socket = _connect_pinned_socket(family, address, resolved_port, timeout)
    connection: http.client.HTTPConnection | None = None
    try:
        if scheme == "https":
            context = _secure_tls_context()
            wrapped_socket = context.wrap_socket(raw_socket, server_hostname=hostname)
            connection = http.client.HTTPSConnection(hostname, port, timeout=timeout, context=context)
            connection.sock = wrapped_socket
        else:
            connection = http.client.HTTPConnection(hostname, port, timeout=timeout)
            connection.sock = raw_socket
        connection.request("POST", request_target, body=body, headers=headers)
        response = connection.getresponse()
        return response.status
    finally:
        if connection is not None:
            connection.close()
        else:
            raw_socket.close()


def _connect_pinned_smtp(
    hostname: str,
    port: int,
    resolved_address: ResolvedAddress,
    timeout: float,
) -> Any:
    import smtplib

    family, address, resolved_port = resolved_address

    class PinnedSMTP(smtplib.SMTP):
        def _get_socket(self, requested_host: str, _port: int, _timeout: float) -> socket.socket:
            self._host = requested_host
            return _connect_pinned_socket(family, address, resolved_port, timeout)

    server = PinnedSMTP(timeout=_bounded_network_timeout(timeout))
    try:
        server.connect(hostname, port)
        return server
    except Exception:
        server.close()
        raise


def _post_progress_payload(
    webhook_url: str,
    *,
    payload: dict[str, Any],
    timeout: float,
    destination_type: str,
    headers: dict[str, str] | None = None,
) -> None:
    scheme, hostname, port, request_target = _webhook_request_target(webhook_url, destination_type)
    resolved_addresses = _resolve_public_addresses(hostname, port, destination_type)
    request_headers = {"Content-Type": "application/json", **(headers or {})}
    for header_name in tuple(request_headers):
        if header_name.lower() == "host":
            request_headers.pop(header_name)
    request_headers["Host"] = _host_header(hostname, port, scheme)
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    bounded_timeout = _bounded_network_timeout(timeout)

    last_error: Exception | None = None
    for resolved_address in resolved_addresses:
        try:
            status = _post_to_pinned_address(
                scheme=scheme,
                hostname=hostname,
                port=port,
                request_target=request_target,
                resolved_address=resolved_address,
                body=body,
                headers=request_headers,
                timeout=bounded_timeout,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
            continue
        if 300 <= status < 400:
            raise OSError(f"{destination_type} redirects are not permitted")
        if status >= 400:
            raise OSError(f"{destination_type} returned HTTP status {status}")
        return

    if last_error is not None:
        raise last_error
    raise OSError(f"{destination_type} could not connect to a validated public address")


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

    @abstractmethod
    def on_progress(self, stats: ProgressStats) -> None:
        """Called on progress updates.

        Args:
            stats: Current progress statistics
        """

    @abstractmethod
    def on_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase, stats: ProgressStats) -> None:
        """Called when phase changes.

        Args:
            old_phase: Previous phase
            new_phase: New phase
            stats: Current progress statistics
        """

    @abstractmethod
    def on_complete(self, stats: ProgressStats) -> None:
        """Called when scanning completes.

        Args:
            stats: Final progress statistics
        """

    @abstractmethod
    def on_error(self, error: Exception, stats: ProgressStats) -> None:
        """Called when an error occurs.

        Args:
            error: The error that occurred
            stats: Progress statistics at time of error
        """

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
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        retry_attempts: int = 3,
        min_interval: float = 30.0,
        allowed_hosts: Collection[str] | None = None,
    ):
        """Initialize webhook progress hook.

        Args:
            name: Unique name for this hook
            webhook_url: URL to send webhook requests to
            headers: Optional HTTP headers to include
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts on failure
            min_interval: Minimum time between webhook calls
            allowed_hosts: Optional explicit public webhook hosts or URLs
        """
        super().__init__(name)

        self.webhook_url = _validate_progress_webhook_url(
            webhook_url,
            destination_type="progress webhook",
            allowed_hosts=allowed_hosts,
        )
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
                    _post_progress_payload(
                        self.webhook_url,
                        payload=payload,
                        headers=self.headers,
                        timeout=self.timeout,
                        destination_type="progress webhook",
                    )
                    return True

                except (OSError, requests.RequestException, ValueError, http.client.HTTPException) as e:
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
        allowed_hosts: Collection[str] | None = None,
        timeout: float = _DEFAULT_NETWORK_TIMEOUT_SECONDS,
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
            allowed_hosts: Optional explicit public SMTP hosts
            timeout: SMTP connection and operation timeout in seconds
        """
        super().__init__(name)

        self.smtp_host = _validate_progress_smtp_host(smtp_host, allowed_hosts=allowed_hosts)
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_emails = to_emails
        self.use_tls = use_tls
        self.timeout = _bounded_network_timeout(timeout)

        self.send_on_start = send_on_start
        self.send_on_complete = send_on_complete
        self.send_on_error = send_on_error
        self.send_periodic = send_periodic
        self.periodic_interval = periodic_interval

        self._last_periodic_email = 0.0
        self._scan_start_time: float | None = None

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

            resolved_addresses = _resolve_public_addresses(self.smtp_host, self.smtp_port, "SMTP")
            last_error: Exception | None = None
            for resolved_address in resolved_addresses:
                server: smtplib.SMTP | None = None
                try:
                    server = _connect_pinned_smtp(
                        self.smtp_host,
                        self.smtp_port,
                        resolved_address,
                        self.timeout,
                    )
                    if self.use_tls:
                        server.starttls(context=_secure_tls_context())
                    server.login(self.username, self.password)
                    server.send_message(msg)
                    try:
                        server.quit()
                    except Exception:
                        server.close()

                    logger.debug(f"Email sent successfully from hook {self.name}")
                    return True
                except Exception as exc:
                    last_error = exc
                    if server is not None:
                        server.close()

            if last_error is not None:
                raise last_error
            raise OSError("SMTP could not connect to a validated public address")

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
        channel: str | None = None,
        username: str = "ModelAudit",
        emoji: str = ":robot_face:",
        send_on_start: bool = True,
        send_on_complete: bool = True,
        send_on_error: bool = True,
        min_interval: float = 300.0,  # 5 minutes
        allowed_hosts: Collection[str] | None = None,
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
            allowed_hosts: Optional explicit public custom Slack webhook hosts or URLs
        """
        super().__init__(name)

        self.webhook_url = _validate_progress_webhook_url(
            webhook_url,
            destination_type="Slack webhook",
            allowed_hosts=allowed_hosts,
            default_allowed_hosts=_DEFAULT_SLACK_WEBHOOK_HOSTS,
            require_https=True,
        )
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

            _post_progress_payload(
                self.webhook_url,
                payload=payload,
                timeout=10.0,
                destination_type="Slack webhook",
            )

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
        on_start_func: Callable[[ProgressStats], None] | None = None,
        on_progress_func: Callable[[ProgressStats], None] | None = None,
        on_phase_change_func: Callable[[ProgressPhase, ProgressPhase, ProgressStats], None] | None = None,
        on_complete_func: Callable[[ProgressStats], None] | None = None,
        on_error_func: Callable[[Exception, ProgressStats], None] | None = None,
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

    def get_hook(self, name: str) -> ProgressHook | None:
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

    def _set_hook_enabled(self, name: str, enabled: bool) -> bool:
        """Enable or disable a hook by name."""
        hook = self._hooks.get(name)
        if not hook:
            return False

        if enabled:
            hook.enable()
        else:
            hook.disable()
        return True

    def enable_hook(self, name: str) -> bool:
        """Enable a hook.

        Args:
            name: Name of hook to enable

        Returns:
            True if hook was enabled
        """
        return self._set_hook_enabled(name, True)

    def disable_hook(self, name: str) -> bool:
        """Disable a hook.

        Args:
            name: Name of hook to disable

        Returns:
            True if hook was disabled
        """
        return self._set_hook_enabled(name, False)

    def clear_hooks(self) -> None:
        """Remove all hooks."""
        self._hooks.clear()
        logger.debug("Cleared all progress hooks")

    def _trigger_hooks(
        self,
        event_name: str,
        callback: Callable[[ProgressHook], None],
    ) -> None:
        """Invoke a hook callback for all enabled hooks."""
        for hook in self._hooks.values():
            if not hook.enabled:
                continue

            try:
                callback(hook)
            except Exception as e:
                logger.warning(f"Hook {hook.name} failed on {event_name}: {e}")

    def trigger_start(self, stats: ProgressStats) -> None:
        """Trigger start event for all hooks."""
        self._trigger_hooks("start", lambda hook: hook.on_start(stats))

    def trigger_progress(self, stats: ProgressStats) -> None:
        """Trigger progress event for all hooks."""
        self._trigger_hooks("progress", lambda hook: hook.on_progress(stats))

    def trigger_phase_change(self, old_phase: ProgressPhase, new_phase: ProgressPhase, stats: ProgressStats) -> None:
        """Trigger phase change event for all hooks."""
        self._trigger_hooks(
            "phase change",
            lambda hook: hook.on_phase_change(old_phase, new_phase, stats),
        )

    def trigger_complete(self, stats: ProgressStats) -> None:
        """Trigger complete event for all hooks."""
        self._trigger_hooks("complete", lambda hook: hook.on_complete(stats))

    def trigger_error(self, error: Exception, stats: ProgressStats) -> None:
        """Trigger error event for all hooks."""
        self._trigger_hooks("error", lambda hook: hook.on_error(error, stats))


# Global hook manager instance
global_hook_manager = ProgressHookManager()
