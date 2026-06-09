"""Progress hook outbound destination validation tests."""

import http.client
import ipaddress
import json
import socket
import ssl
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.progress import ProgressPhase, ProgressStats
from modelaudit.progress.hooks import EmailProgressHook, SlackProgressHook, WebhookProgressHook


def _address_info(
    address: str = "93.184.216.34",
    port: int = 443,
    *,
    family: socket.AddressFamily | None = None,
    socket_type: socket.SocketKind = socket.SOCK_STREAM,
    protocol: int = socket.IPPROTO_TCP,
) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    resolved_family = family or (socket.AF_INET6 if ":" in address else socket.AF_INET)
    socket_address: tuple[object, ...]
    socket_address = (address, port, 0, 0) if resolved_family == socket.AF_INET6 else (address, port)
    return [(resolved_family, socket_type, protocol, "", socket_address)]


def _stats() -> ProgressStats:
    return ProgressStats(
        bytes_processed=128,
        total_bytes=256,
        items_processed=1,
        total_items=2,
        current_phase=ProgressPhase.ANALYZING,
        current_item="model.pkl",
        status_message="Scanning model.pkl",
    )


def test_webhook_rejects_loopback_url_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODELAUDIT_PROGRESS_WEBHOOK_ALLOWED_HOSTS", "127.0.0.1")

    with (
        patch("modelaudit.progress.hooks._post_to_pinned_address") as mock_post,
        pytest.raises(ValueError, match="not a permitted public egress"),
    ):
        WebhookProgressHook(name="ssrf", webhook_url="http://127.0.0.1:8080/progress")

    mock_post.assert_not_called()


def test_webhook_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="must use http or https"):
        WebhookProgressHook(
            name="file-url",
            webhook_url="file:///var/run/docker.sock",
            allowed_hosts={"example.com"},
        )


def test_webhook_requires_explicit_allowed_host_for_custom_egress() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        WebhookProgressHook(name="missing-allowlist", webhook_url="https://hooks.example.com/modelaudit")


@pytest.mark.parametrize(
    "webhook_url, error",
    [
        (r"https://127.0.0.1\@hooks.example.com/progress", "invalid host or port"),
        ("https://user:pass@hooks.example.com/progress", "must not include user information"),
    ],
)
def test_webhook_rejects_host_parser_differentials(webhook_url: str, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        WebhookProgressHook(name="parser-differential", webhook_url=webhook_url, allowed_hosts={"hooks.example.com"})


def test_public_https_webhook_uses_pinned_address_and_preserves_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    stats = _stats()
    resolver = MagicMock(return_value=_address_info())
    monkeypatch.setattr("socket.getaddrinfo", resolver)

    with patch("modelaudit.progress.hooks._post_to_pinned_address", return_value=200) as mock_post:
        hook = WebhookProgressHook(
            name="audit",
            webhook_url="https://hooks.example.com/modelaudit?source=test",
            headers={"X-ModelAudit-Test": "1"},
            timeout=999.0,
            retry_attempts=1,
            allowed_hosts={"hooks.example.com"},
        )
        assert hook._send_webhook(hook._create_base_payload(stats, "progress")) is True

    resolver.assert_called_once_with("hooks.example.com", 443, type=socket.SOCK_STREAM)
    kwargs = mock_post.call_args.kwargs
    assert kwargs["resolved_address"] == (socket.AF_INET, "93.184.216.34", 443)
    assert kwargs["hostname"] == "hooks.example.com"
    assert kwargs["request_target"] == "/modelaudit?source=test"
    assert kwargs["timeout"] == 60.0
    assert kwargs["headers"]["Host"] == "hooks.example.com"
    assert kwargs["headers"]["X-ModelAudit-Test"] == "1"
    payload = json.loads(kwargs["body"])
    assert payload["hook_name"] == "audit"
    assert payload["event_type"] == "progress"
    assert payload["current_item"] == "model.pkl"


def test_custom_host_header_cannot_override_validated_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: _address_info())
    with patch("modelaudit.progress.hooks._post_to_pinned_address", return_value=200) as mock_post:
        hook = WebhookProgressHook(
            name="host-header",
            webhook_url="https://hooks.example.com/modelaudit",
            headers={"host": "127.0.0.1", "X-Test": "1"},
            retry_attempts=1,
            allowed_hosts={"hooks.example.com"},
        )
        assert hook._send_webhook({"event_type": "progress"}) is True

    assert mock_post.call_args.kwargs["headers"]["Host"] == "hooks.example.com"
    assert "host" not in mock_post.call_args.kwargs["headers"]


@pytest.mark.parametrize(
    ("unicode_host", "punycode_host"),
    [
        ("bücher.example", "xn--bcher-kva.example"),
        ("faß.de", "xn--fa-hia.de"),
    ],
)
def test_unicode_url_matches_punycode_allowlist(
    monkeypatch: pytest.MonkeyPatch,
    unicode_host: str,
    punycode_host: str,
) -> None:
    resolver = MagicMock(return_value=_address_info())
    monkeypatch.setattr("socket.getaddrinfo", resolver)
    with patch("modelaudit.progress.hooks._post_to_pinned_address", return_value=200) as mock_post:
        hook = WebhookProgressHook(
            name="idn",
            webhook_url=f"https://{unicode_host}/modelaudit",
            retry_attempts=1,
            allowed_hosts={punycode_host},
        )
        assert hook._send_webhook({"event_type": "progress"}) is True

    resolver.assert_called_once_with(punycode_host, 443, type=socket.SOCK_STREAM)
    assert mock_post.call_args.kwargs["hostname"] == punycode_host
    assert mock_post.call_args.kwargs["headers"]["Host"] == punycode_host


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "192.168.1.10"])
def test_webhook_rejects_private_dns_resolution_before_connect(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
) -> None:
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: _address_info(address))
    hook = WebhookProgressHook(
        name="dns-rebinding",
        webhook_url="https://hooks.example.com/modelaudit",
        retry_attempts=1,
        allowed_hosts={"hooks.example.com"},
    )

    with patch("modelaudit.progress.hooks._post_to_pinned_address") as mock_post:
        assert hook._send_webhook({"event_type": "progress"}) is False
    mock_post.assert_not_called()


def test_webhook_rejects_mixed_public_and_private_dns_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: _address_info() + _address_info("10.0.0.5"),
    )
    hook = WebhookProgressHook(
        name="split-dns",
        webhook_url="https://hooks.example.com/modelaudit",
        retry_attempts=1,
        allowed_hosts={"hooks.example.com"},
    )

    with patch("modelaudit.progress.hooks._post_to_pinned_address") as mock_post:
        assert hook._send_webhook({"event_type": "progress"}) is False
    mock_post.assert_not_called()


@pytest.mark.parametrize(
    "hostname",
    [
        "192.88.99.2",
        "100:0:0:1::1",
        "5f00::1",
        "::ffff:93.184.216.34",
    ],
)
def test_webhook_rejects_iana_non_global_destinations_when_ipaddress_is_stale(
    monkeypatch: pytest.MonkeyPatch,
    hostname: str,
) -> None:
    address = ipaddress.ip_address(hostname)
    monkeypatch.setattr(type(address), "is_global", property(lambda _address: True))
    rendered_hostname = f"[{hostname}]" if address.version == 6 else hostname

    with pytest.raises(ValueError, match="not a permitted public egress"):
        WebhookProgressHook(
            name="iana-non-global",
            webhook_url=f"https://{rendered_hostname}/progress",
            allowed_hosts={hostname},
        )


@pytest.mark.parametrize(
    "hostname",
    [
        "192.0.0.9",
        "192.0.0.10",
        "2001:1::1",
        "2001:1::2",
        "2001:1::3",
        "2001:3::1",
        "2001:4:112::1",
        "2001:20::1",
        "2001:30::1",
    ],
)
def test_webhook_accepts_iana_global_exceptions_when_ipaddress_is_stale(
    monkeypatch: pytest.MonkeyPatch,
    hostname: str,
) -> None:
    address = ipaddress.ip_address(hostname)
    monkeypatch.setattr(type(address), "is_global", property(lambda _address: False))
    rendered_hostname = f"[{hostname}]" if address.version == 6 else hostname

    hook = WebhookProgressHook(
        name="iana-global",
        webhook_url=f"https://{rendered_hostname}/progress",
        allowed_hosts={hostname},
    )

    assert hook.webhook_url == f"https://{rendered_hostname}/progress"


@pytest.mark.parametrize("hostname", ["64:ff9b::5db8:d822", "::ffff:0:5db8:d822"])
def test_webhook_accepts_public_ipv4_embedded_destination(hostname: str) -> None:
    hook = WebhookProgressHook(
        name="public-nat64",
        webhook_url=f"https://[{hostname}]/progress",
        allowed_hosts={hostname},
    )

    assert hook.webhook_url == f"https://[{hostname}]/progress"


@pytest.mark.parametrize(
    "address_info",
    [
        _address_info(family=cast(socket.AddressFamily, -1)),
        _address_info(socket_type=socket.SOCK_DGRAM),
        _address_info(port=444),
        [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("2606:2800:220:1:248:1893:25c8:1946", 443),
            )
        ],
        [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443, 0, 0),
            )
        ],
        [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443, 0, 0),
            )
        ],
        [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("2606:2800:220:1:248:1893:25c8:1946", 443, 1, 0),
            )
        ],
        [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("2606:2800:220:1:248:1893:25c8:1946", 443, 0, 1),
            )
        ],
    ],
)
def test_webhook_rejects_malformed_resolver_answers(
    monkeypatch: pytest.MonkeyPatch,
    address_info: list[tuple[int, int, int, str, tuple[object, ...]]],
) -> None:
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: address_info)
    hook = WebhookProgressHook(
        name="invalid-dns",
        webhook_url="https://hooks.example.com/modelaudit",
        retry_attempts=1,
        allowed_hosts={"hooks.example.com"},
    )
    with patch("modelaudit.progress.hooks._post_to_pinned_address") as mock_post:
        assert hook._send_webhook({"event_type": "progress"}) is False
    mock_post.assert_not_called()


def test_webhook_uses_one_dns_snapshot_during_rebinding(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = MagicMock(side_effect=[_address_info(), _address_info("127.0.0.1")])
    monkeypatch.setattr("socket.getaddrinfo", resolver)
    with patch("modelaudit.progress.hooks._post_to_pinned_address", return_value=200) as mock_post:
        hook = WebhookProgressHook(
            name="rebind",
            webhook_url="https://hooks.example.com/modelaudit",
            retry_attempts=1,
            allowed_hosts={"hooks.example.com"},
        )
        assert hook._send_webhook({"event_type": "progress"}) is True

    assert resolver.call_count == 1
    assert mock_post.call_args.kwargs["resolved_address"][1] == "93.184.216.34"


def test_webhook_falls_back_across_validated_public_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: _address_info("93.184.216.34") + _address_info("93.184.216.35"),
    )
    with patch(
        "modelaudit.progress.hooks._post_to_pinned_address",
        side_effect=[http.client.HTTPException("first address failed"), 200],
    ) as mock_post:
        hook = WebhookProgressHook(
            name="fallback",
            webhook_url="https://hooks.example.com/modelaudit",
            retry_attempts=1,
            allowed_hosts={"hooks.example.com"},
        )
        assert hook._send_webhook({"event_type": "progress"}) is True

    assert [item.kwargs["resolved_address"][1] for item in mock_post.call_args_list] == [
        "93.184.216.34",
        "93.184.216.35",
    ]


def test_webhook_rejects_redirect_without_retrying_other_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: _address_info())
    with patch("modelaudit.progress.hooks._post_to_pinned_address", return_value=302) as mock_post:
        hook = WebhookProgressHook(
            name="redirect",
            webhook_url="https://hooks.example.com/modelaudit",
            retry_attempts=1,
            allowed_hosts={"hooks.example.com"},
        )
        assert hook._send_webhook({"event_type": "progress"}) is False
    mock_post.assert_called_once()


def test_connect_pinned_socket_uses_numeric_address_without_dns() -> None:
    fake_socket = MagicMock()
    with patch("socket.socket", return_value=fake_socket) as socket_factory, patch("socket.getaddrinfo") as resolver:
        from modelaudit.progress.hooks import _connect_pinned_socket

        assert _connect_pinned_socket(socket.AF_INET, "93.184.216.34", 443, 5.0) is fake_socket

    socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    fake_socket.connect.assert_called_once_with(("93.184.216.34", 443))
    resolver.assert_not_called()


def test_connect_pinned_socket_closes_failed_connection() -> None:
    fake_socket = MagicMock()
    fake_socket.connect.side_effect = OSError("connect failed")
    with patch("socket.socket", return_value=fake_socket), pytest.raises(OSError, match="connect failed"):
        from modelaudit.progress.hooks import _connect_pinned_socket

        _connect_pinned_socket(socket.AF_INET, "93.184.216.34", 443, 5.0)
    fake_socket.close.assert_called_once()


def test_https_pinned_transport_preserves_sni_and_host_header() -> None:
    from modelaudit.progress.hooks import _post_to_pinned_address

    raw_socket = MagicMock()
    wrapped_socket = MagicMock()
    tls_context = MagicMock()
    tls_context.wrap_socket.return_value = wrapped_socket
    connection = MagicMock()
    connection.getresponse.return_value.status = 200

    with (
        patch("modelaudit.progress.hooks._connect_pinned_socket", return_value=raw_socket),
        patch("ssl.create_default_context", return_value=tls_context),
        patch("http.client.HTTPSConnection", return_value=connection) as connection_factory,
    ):
        status = _post_to_pinned_address(
            scheme="https",
            hostname="hooks.example.com",
            port=443,
            request_target="/modelaudit",
            resolved_address=(socket.AF_INET, "93.184.216.34", 443),
            body=b"{}",
            headers={"Host": "hooks.example.com", "Content-Type": "application/json"},
            timeout=10.0,
        )

    assert status == 200
    assert tls_context.minimum_version == ssl.TLSVersion.TLSv1_2
    tls_context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="hooks.example.com")
    connection_factory.assert_called_once_with("hooks.example.com", 443, timeout=10.0, context=tls_context)
    assert connection.sock is wrapped_socket
    connection.request.assert_called_once_with(
        "POST",
        "/modelaudit",
        body=b"{}",
        headers={"Host": "hooks.example.com", "Content-Type": "application/json"},
    )
    connection.close.assert_called_once()


def test_smtp_pinned_transport_retains_original_starttls_hostname() -> None:
    import smtplib

    from modelaudit.progress.hooks import _connect_pinned_smtp

    fake_socket = MagicMock()

    def fake_connect(server: smtplib.SMTP, host: str, port: int) -> tuple[int, bytes]:
        server_any: Any = server
        server.sock = server_any._get_socket(host, port, server.timeout)
        return 220, b"ready"

    with (
        patch("smtplib.SMTP.connect", fake_connect),
        patch("modelaudit.progress.hooks._connect_pinned_socket", return_value=fake_socket) as pinned_connect,
    ):
        server = _connect_pinned_smtp(
            "smtp.example.com",
            587,
            (socket.AF_INET, "93.184.216.34", 587),
            10.0,
        )

    server_any: Any = server
    assert server_any._host == "smtp.example.com"
    pinned_connect.assert_called_once_with(socket.AF_INET, "93.184.216.34", 587, 10.0)

    tls_context = MagicMock()
    wrapped_socket = MagicMock()
    tls_context.wrap_socket.return_value = wrapped_socket
    server.ehlo_or_helo_if_needed = MagicMock()
    server.has_extn = MagicMock(return_value=True)
    server.docmd = MagicMock(return_value=(220, b"ready"))

    server.starttls(context=tls_context)

    tls_context.wrap_socket.assert_called_once_with(fake_socket, server_hostname="smtp.example.com")
    assert server.sock is wrapped_socket
    server.close()


def test_slack_default_host_uses_pinned_https(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: _address_info())
    with patch("modelaudit.progress.hooks._post_to_pinned_address", return_value=200) as mock_post:
        hook = SlackProgressHook(
            name="slack",
            webhook_url="https://hooks.slack.com/services/T000/B000/token",
            channel="#modelaudit",
        )
        assert hook._send_slack_message("scan finished", "good") is True

    kwargs = mock_post.call_args.kwargs
    payload = json.loads(kwargs["body"])
    assert kwargs["scheme"] == "https"
    assert kwargs["hostname"] == "hooks.slack.com"
    assert payload["channel"] == "#modelaudit"
    assert payload["attachments"][0]["text"] == "scan finished"


def test_slack_custom_host_allowed_by_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODELAUDIT_PROGRESS_WEBHOOK_ALLOWED_HOSTS", "hooks.example.net")
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: _address_info())
    with patch("modelaudit.progress.hooks._post_to_pinned_address", return_value=200) as mock_post:
        hook = SlackProgressHook(name="custom-slack", webhook_url="https://hooks.example.net/services/token")
        assert hook._send_slack_message("scan finished", "warning") is True
    assert mock_post.call_args.kwargs["hostname"] == "hooks.example.net"


def test_slack_rejects_cleartext_url() -> None:
    with pytest.raises(ValueError, match="must use https"):
        SlackProgressHook(name="cleartext", webhook_url="http://hooks.slack.com/services/token")


def test_email_rejects_private_smtp_host_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODELAUDIT_PROGRESS_SMTP_ALLOWED_HOSTS", "10.0.0.5")
    with (
        patch("modelaudit.progress.hooks._connect_pinned_smtp") as mock_connect,
        pytest.raises(ValueError, match="not a permitted public egress"),
    ):
        EmailProgressHook(
            name="smtp-ssrf",
            smtp_host="10.0.0.5",
            smtp_port=587,
            username="user",
            password="pass",
            from_email="scanner@example.com",
            to_emails=["security@example.com"],
        )
    mock_connect.assert_not_called()


def test_email_requires_allowed_smtp_host() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        EmailProgressHook(
            name="smtp-missing-allowlist",
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="user",
            password="pass",
            from_email="scanner@example.com",
            to_emails=["security@example.com"],
        )


def test_email_allowed_host_uses_pinned_address_and_preserves_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODELAUDIT_PROGRESS_SMTP_ALLOWED_HOSTS", "smtp.example.com")
    resolver = MagicMock(return_value=_address_info(port=587))
    monkeypatch.setattr("socket.getaddrinfo", resolver)
    stats = _stats()
    smtp_server = MagicMock()
    tls_context = MagicMock()

    with (
        patch("modelaudit.progress.hooks._connect_pinned_smtp", return_value=smtp_server) as mock_connect,
        patch("ssl.create_default_context", return_value=tls_context),
    ):
        hook = EmailProgressHook(
            name="smtp",
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="user",
            password="pass",
            from_email="scanner@example.com",
            to_emails=["security@example.com"],
            timeout=999.0,
        )
        assert hook._send_email("ModelAudit Scan", hook._format_stats(stats)) is True

    resolver.assert_called_once_with("smtp.example.com", 587, type=socket.SOCK_STREAM)
    mock_connect.assert_called_once_with(
        "smtp.example.com",
        587,
        (socket.AF_INET, "93.184.216.34", 587),
        60.0,
    )
    assert tls_context.minimum_version == ssl.TLSVersion.TLSv1_2
    smtp_server.starttls.assert_called_once_with(context=tls_context)
    smtp_server.login.assert_called_once_with("user", "pass")
    smtp_server.send_message.assert_called_once()
    rendered_message = smtp_server.send_message.call_args.args[0].as_string()
    assert "Subject: ModelAudit Scan" in rendered_message
    assert "Current Item: model.pkl" in rendered_message
    smtp_server.quit.assert_called_once()


def test_email_unicode_host_uses_idna2008_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODELAUDIT_PROGRESS_SMTP_ALLOWED_HOSTS", "xn--fa-hia.de")
    resolver = MagicMock(return_value=_address_info(port=587))
    monkeypatch.setattr("socket.getaddrinfo", resolver)
    smtp_server = MagicMock()

    with patch("modelaudit.progress.hooks._connect_pinned_smtp", return_value=smtp_server) as mock_connect:
        hook = EmailProgressHook(
            name="smtp-idn",
            smtp_host="faß.de",
            smtp_port=587,
            username="user",
            password="pass",
            from_email="scanner@example.com",
            to_emails=["security@example.com"],
        )
        assert hook._send_email("ModelAudit Scan", "body") is True

    assert hook.smtp_host == "xn--fa-hia.de"
    resolver.assert_called_once_with("xn--fa-hia.de", 587, type=socket.SOCK_STREAM)
    assert mock_connect.call_args.args[:2] == ("xn--fa-hia.de", 587)


def test_email_rejects_private_dns_resolution_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODELAUDIT_PROGRESS_SMTP_ALLOWED_HOSTS", "smtp.example.com")
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: _address_info("192.168.1.10", 587))
    hook = EmailProgressHook(
        name="smtp-dns-rebinding",
        smtp_host="smtp.example.com",
        smtp_port=587,
        username="user",
        password="pass",
        from_email="scanner@example.com",
        to_emails=["security@example.com"],
    )
    with patch("modelaudit.progress.hooks._connect_pinned_smtp") as mock_connect:
        assert hook._send_email("ModelAudit Scan", "body") is False
    mock_connect.assert_not_called()


def test_email_uses_one_dns_snapshot_during_rebinding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODELAUDIT_PROGRESS_SMTP_ALLOWED_HOSTS", "smtp.example.com")
    resolver = MagicMock(side_effect=[_address_info(port=587), _address_info("127.0.0.1", 587)])
    monkeypatch.setattr("socket.getaddrinfo", resolver)
    smtp_server = MagicMock()
    with patch("modelaudit.progress.hooks._connect_pinned_smtp", return_value=smtp_server) as mock_connect:
        hook = EmailProgressHook(
            name="smtp-rebind",
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="user",
            password="pass",
            from_email="scanner@example.com",
            to_emails=["security@example.com"],
        )
        assert hook._send_email("ModelAudit Scan", "body") is True
    assert resolver.call_count == 1
    assert mock_connect.call_args.args[2][1] == "93.184.216.34"


def test_email_falls_back_and_closes_failed_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODELAUDIT_PROGRESS_SMTP_ALLOWED_HOSTS", "smtp.example.com")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: _address_info("93.184.216.34", 587) + _address_info("93.184.216.35", 587),
    )
    failed_server = MagicMock()
    failed_server.starttls.side_effect = OSError("TLS failed")
    successful_server = MagicMock()
    with patch(
        "modelaudit.progress.hooks._connect_pinned_smtp",
        side_effect=[failed_server, successful_server],
    ) as mock_connect:
        hook = EmailProgressHook(
            name="smtp-fallback",
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="user",
            password="pass",
            from_email="scanner@example.com",
            to_emails=["security@example.com"],
        )
        assert hook._send_email("ModelAudit Scan", "body") is True

    assert [item.args[2][1] for item in mock_connect.call_args_list] == ["93.184.216.34", "93.184.216.35"]
    failed_server.close.assert_called_once()
    successful_server.send_message.assert_called_once()


@pytest.mark.parametrize(
    "hostname",
    [
        "64:ff9b::7f00:1",
        "2001:4860::5efe:7f00:1",
        "::ffff:127.0.0.1",
        "::ffff:0:127.0.0.1",
        "::7f00:1",
        "::0a00:5",
    ],
)
def test_webhook_rejects_ipv6_embedded_private_destinations(hostname: str) -> None:
    with pytest.raises(ValueError, match="not a permitted public egress"):
        WebhookProgressHook(
            name="ipv6-transition",
            webhook_url=f"https://[{hostname}]/progress",
            allowed_hosts={hostname},
        )
