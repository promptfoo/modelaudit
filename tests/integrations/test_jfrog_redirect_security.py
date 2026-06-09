from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from modelaudit.utils.sources.jfrog import _JFROG_NO_NETRC_AUTH, download_artifact


class _FakeStreamingResponse:
    def __init__(self, payload: bytes, *, status_code: int = 200, headers: dict[str, str] | None = None) -> None:
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.cookies = requests.cookies.RequestsCookieJar()
        self.closed = False

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        for offset in range(0, len(self.payload), chunk_size):
            yield self.payload[offset : offset + chunk_size]

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    "location",
    [
        "https://10.0.0.8/artifacts/model.bin",
        "https://172.16.0.8/artifacts/model.bin",
        "https://192.168.1.8/artifacts/model.bin",
        "https://169.254.169.254/latest/meta-data/",
        "https://100.64.0.8/artifacts/model.bin",
        "https://[fd00::1]/artifacts/model.bin",
        "https://[::ffff:127.0.0.1]/artifacts/model.bin",
        "https://[64:ff9b::7f00:1]/artifacts/model.bin",
        "https://[64:ff9b::a9fe:a9fe]/artifacts/model.bin",
        "https://[::127.0.0.1]/artifacts/model.bin",
        "https://[::10.0.0.8]/artifacts/model.bin",
        "https://[::ffff:0:127.0.0.1]/artifacts/model.bin",
        "https://[2002:7f00:1::]/artifacts/model.bin",
        "https://[2001::1]/artifacts/model.bin",
        "https://[fec0::1]/artifacts/model.bin",
        "https://[fe80::1%25eth0]/artifacts/model.bin",
        "https://[2606:4700:4700::1111%25eth0]/artifacts/model.bin",
        "https://[::ffff:93.184.216.34]/artifacts/model.bin",
        "https://[2606:4700:4700:0:0:5efe:5db8:d822]/artifacts/model.bin",
        "https://[2606:4700:4700:0:200:5efe:5db8:d822]/artifacts/model.bin",
        "https://2130706433/artifacts/model.bin",
        "https://127.1/artifacts/model.bin",
        "https://0177.0.0.1/artifacts/model.bin",
        "https://017700000001/artifacts/model.bin",
        "https://0x7f000001/artifacts/model.bin",
        "https://0x7f.0.0.1/artifacts/model.bin",
        "https://010.010.010.010/artifacts/model.bin",
        "https://8.8.8/artifacts/model.bin",
        "https://0x08080808/artifacts/model.bin",
        "https://224.0.0.1/artifacts/model.bin",
        "https://[ff02::1]/artifacts/model.bin",
    ],
)
@patch("modelaudit.utils.sources.jfrog.requests.get")
def test_download_rejects_unsafe_ip_redirect_targets(
    mock_get: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
    redirect_response = _FakeStreamingResponse(b"", status_code=302, headers={"Location": location})
    mock_get.return_value = redirect_response

    with pytest.raises(Exception, match="Refusing unsafe JFrog download target"):
        download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

    mock_get.assert_called_once()
    assert redirect_response.closed is True
    assert not any(tmp_path.iterdir())


@patch("modelaudit.utils.sources.jfrog.requests.get")
def test_download_allows_explicit_private_redirect_host_without_credentials(
    mock_get: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "10.0.0.8")
    redirect_response = _FakeStreamingResponse(
        b"",
        status_code=302,
        headers={"Location": "https://10.0.0.8/artifacts/model.bin"},
    )
    final_response = _FakeStreamingResponse(b"data")
    mock_get.side_effect = [redirect_response, final_response]

    result = download_artifact(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        cache_dir=tmp_path,
        api_token="test-token",
    )

    assert result.read_bytes() == b"data"
    assert mock_get.call_args_list[0].kwargs["headers"] == {"X-JFrog-Art-Api": "test-token"}
    assert mock_get.call_args_list[1].args[0] == "https://10.0.0.8/artifacts/model.bin"
    assert mock_get.call_args_list[1].kwargs["headers"] == {}
    assert redirect_response.closed is True
    assert final_response.closed is True


@patch("modelaudit.utils.sources.jfrog.requests.get")
def test_download_allows_public_ip_redirect_without_credentials(
    mock_get: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
    redirect_response = _FakeStreamingResponse(
        b"",
        status_code=302,
        headers={"Location": "https://93.184.216.34/artifacts/model.bin"},
    )
    final_response = _FakeStreamingResponse(b"data")
    mock_get.side_effect = [redirect_response, final_response]

    result = download_artifact(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        cache_dir=tmp_path,
        api_token="test-token",
    )

    assert result.read_bytes() == b"data"
    assert mock_get.call_args_list[1].kwargs["headers"] == {}


@patch("modelaudit.utils.sources.jfrog.requests.get")
def test_download_allows_public_ipv6_redirect_without_credentials(
    mock_get: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
    redirect_response = _FakeStreamingResponse(
        b"",
        status_code=302,
        headers={"Location": "https://[2606:4700:4700::1111]/artifacts/model.bin"},
    )
    final_response = _FakeStreamingResponse(b"data")
    mock_get.side_effect = [redirect_response, final_response]

    result = download_artifact(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        cache_dir=tmp_path,
        api_token="test-token",
    )

    assert result.read_bytes() == b"data"
    assert mock_get.call_args_list[1].kwargs["headers"] == {}


@patch("modelaudit.utils.sources.jfrog.requests.get")
def test_download_rejects_untrusted_redirect_hostname_by_default(
    mock_get: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
    redirect_response = _FakeStreamingResponse(
        b"",
        status_code=302,
        headers={"Location": "https://storage.redirect.test/artifacts/model.bin"},
    )
    mock_get.return_value = redirect_response

    with pytest.raises(Exception, match="Refusing unsafe JFrog download target"):
        download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin",
            cache_dir=tmp_path,
            api_token="test-token",
        )

    mock_get.assert_called_once()
    assert redirect_response.closed is True
    assert not any(tmp_path.iterdir())


@patch("modelaudit.utils.sources.jfrog.requests.get")
def test_download_allows_explicit_redirect_hostname_without_credentials(
    mock_get: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "public.redirect.test")
    redirect_response = _FakeStreamingResponse(
        b"",
        status_code=302,
        headers={"Location": "https://public.redirect.test/artifacts/model.bin"},
    )
    final_response = _FakeStreamingResponse(b"data")
    mock_get.side_effect = [redirect_response, final_response]

    result = download_artifact(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        cache_dir=tmp_path,
        api_token="test-token",
    )

    assert result.read_bytes() == b"data"
    assert mock_get.call_args_list[1].kwargs["headers"] == {}


@patch("modelaudit.utils.sources.jfrog.requests.get")
def test_download_allows_explicit_private_redirect_hostname_without_credentials(
    mock_get: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "storage.internal")
    redirect_response = _FakeStreamingResponse(
        b"",
        status_code=302,
        headers={"Location": "https://storage.internal/artifacts/model.bin"},
    )
    final_response = _FakeStreamingResponse(b"data")
    mock_get.side_effect = [redirect_response, final_response]

    result = download_artifact(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        cache_dir=tmp_path,
        api_token="test-token",
    )

    assert result.read_bytes() == b"data"
    assert mock_get.call_args_list[1].kwargs["headers"] == {}


@patch("modelaudit.utils.sources.jfrog.requests.get")
def test_download_redirects_do_not_load_netrc_credentials(
    mock_get: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "public.redirect.test")
    responses = iter(
        [
            _FakeStreamingResponse(
                b"",
                status_code=302,
                headers={"Location": "https://public.redirect.test/artifacts/model.bin"},
            ),
            _FakeStreamingResponse(b"data"),
        ]
    )
    prepared_requests: list[requests.PreparedRequest] = []

    def prepare_request(url: str, **kwargs: Any) -> _FakeStreamingResponse:
        with patch("requests.sessions.get_netrc_auth", return_value=("ambient-user", "ambient-secret")):
            prepared = requests.Session().prepare_request(
                requests.Request(
                    "GET",
                    url,
                    headers=kwargs["headers"],
                    auth=kwargs["auth"],
                )
            )
        prepared_requests.append(prepared)
        return next(responses)

    mock_get.side_effect = prepare_request

    result = download_artifact(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        cache_dir=tmp_path,
        access_token="test-token",
    )

    assert result.read_bytes() == b"data"
    assert [request.headers.get("Authorization") for request in prepared_requests] == ["Bearer test-token", None]
    assert all(call.kwargs["auth"] is _JFROG_NO_NETRC_AUTH for call in mock_get.call_args_list)


@patch("modelaudit.utils.sources.jfrog.requests.get")
def test_download_isolates_cookies_between_untrusted_redirect_origins(
    mock_get: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "company.jfrog.io")
    monkeypatch.setenv("MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS", "a.redirect.test,b.redirect.test")
    first_redirect = _FakeStreamingResponse(
        b"",
        status_code=302,
        headers={"Location": "https://a.redirect.test/artifacts/model.bin"},
    )
    second_redirect = _FakeStreamingResponse(
        b"",
        status_code=302,
        headers={"Location": "https://b.redirect.test/artifacts/model.bin"},
    )
    second_redirect.cookies.set_cookie(requests.cookies.create_cookie("CDN_SESSION", "host-a", domain=".redirect.test"))
    final_response = _FakeStreamingResponse(b"data")
    mock_get.side_effect = [first_redirect, second_redirect, final_response]

    result = download_artifact(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        cache_dir=tmp_path,
        api_token="test-token",
    )

    assert result.read_bytes() == b"data"
    host_a_cookies = mock_get.call_args_list[1].kwargs["cookies"]
    host_b_cookies = mock_get.call_args_list[2].kwargs["cookies"]
    assert host_a_cookies is not host_b_cookies
    assert host_a_cookies.get("CDN_SESSION") == "host-a"
    assert host_b_cookies.get("CDN_SESSION") is None
