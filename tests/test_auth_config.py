import os
import stat
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from modelaudit.auth import client as auth_client_module
from modelaudit.auth import config as auth_config


class _FakeResponse:
    ok = True
    status_code = 200
    reason = "OK"

    def json(self) -> dict[str, Any]:
        return {
            "user": {"email": "user@example.com"},
            "organization": {"id": "org-1"},
            "app": {"url": "https://www.promptfoo.app"},
        }


class _FakeCloudConfig:
    def __init__(self, api_host: str = "https://api.promptfoo.app", api_key: str | None = "secret-token"):
        self.api_host = api_host
        self.api_key = api_key
        self.app_url = ""

    def get_api_host(self) -> str:
        return self.api_host

    def set_api_host(self, api_host: str) -> None:
        self.api_host = api_host

    def get_api_key(self) -> str | None:
        return self.api_key

    def set_api_key(self, api_key: str) -> None:
        self.api_key = api_key

    def set_app_url(self, app_url: str) -> None:
        self.app_url = app_url


def _patch_config_paths(
    module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    primary_dir: Path,
    fallback_dir: Path,
) -> None:
    monkeypatch.setattr(module, "user_config_dir", lambda _app_name: str(primary_dir))
    monkeypatch.setattr(module, "_home_fallback_config_dir", lambda: fallback_dir)


def test_get_config_directory_path_falls_back_to_private_home_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    primary_parent = tmp_path / "xdg"
    primary_parent.mkdir()
    symlink_target = tmp_path / "attacker"
    symlink_target.mkdir()
    primary_dir = primary_parent / "promptfoo"
    primary_dir.symlink_to(symlink_target, target_is_directory=True)
    fallback_dir = tmp_path / "home" / ".promptfoo"

    _patch_config_paths(auth_config, monkeypatch, primary_dir, fallback_dir)

    config_dir = Path(auth_config.get_config_directory_path(create_if_not_exists=True))

    assert config_dir == fallback_dir
    assert config_dir.is_dir()
    assert not config_dir.is_symlink()
    if os.name != "nt":
        assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(config_dir.parent.stat().st_mode) == 0o700


def test_write_global_config_replaces_symlink_instead_of_following_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "promptfoo.yaml"
    target_file = tmp_path / "sensitive.yaml"
    target_file.write_text("do-not-touch")
    config_file.symlink_to(target_file)
    fallback_dir = tmp_path / "home" / ".promptfoo"

    _patch_config_paths(auth_config, monkeypatch, config_dir, fallback_dir)

    auth_config.write_global_config(auth_config.GlobalConfig({"id": "fixed-id", "cloud": {"apiKey": "secret"}}))

    assert target_file.read_text() == "do-not-touch"
    assert config_file.exists()
    assert not config_file.is_symlink()
    written = yaml.safe_load(config_file.read_text())
    assert written["id"] == "fixed-id"
    assert written["cloud"]["apiKey"] == "secret"


def test_read_global_config_ignores_symlinked_config_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    primary_parent = tmp_path / "xdg"
    primary_parent.mkdir()
    attacker_dir = tmp_path / "attacker"
    attacker_dir.mkdir()
    primary_dir = primary_parent / "promptfoo"
    primary_dir.symlink_to(attacker_dir, target_is_directory=True)
    (attacker_dir / "promptfoo.yaml").write_text(
        yaml.safe_dump({"id": "attacker-id", "cloud": {"apiKey": "stolen-secret"}})
    )

    fallback_dir = tmp_path / "home" / ".promptfoo"
    fallback_dir.mkdir(parents=True)
    (fallback_dir / "promptfoo.yaml").write_text(yaml.safe_dump({"id": "safe-id", "cloud": {"apiKey": "safe-key"}}))

    _patch_config_paths(auth_config, monkeypatch, primary_dir, fallback_dir)

    config = auth_config.read_global_config()

    assert config.id == "safe-id"
    assert config.cloud["apiKey"] == "safe-key"


def test_read_global_config_does_not_read_attacker_file_when_safe_fallback_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    primary_parent = tmp_path / "xdg"
    primary_parent.mkdir()
    attacker_dir = tmp_path / "attacker"
    attacker_dir.mkdir()
    primary_dir = primary_parent / "promptfoo"
    primary_dir.symlink_to(attacker_dir, target_is_directory=True)
    (attacker_dir / "promptfoo.yaml").write_text(
        yaml.safe_dump({"id": "attacker-id", "cloud": {"apiKey": "stolen-secret"}})
    )

    fallback_dir = tmp_path / "home" / ".promptfoo"

    _patch_config_paths(auth_config, monkeypatch, primary_dir, fallback_dir)

    config = auth_config.read_global_config()

    assert config.id != "attacker-id"
    assert config.cloud.get("apiKey") != "stolen-secret"
    assert (fallback_dir / "promptfoo.yaml").exists()


def test_read_global_config_ignores_config_directory_under_symlinked_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    attacker_root = tmp_path / "attacker-root"
    attacker_root.mkdir()
    redirected_root = tmp_path / "redirected-root"
    redirected_root.symlink_to(attacker_root, target_is_directory=True)
    primary_dir = redirected_root / "promptfoo"
    primary_dir.mkdir()
    (primary_dir / "promptfoo.yaml").write_text(
        yaml.safe_dump({"id": "attacker-id", "cloud": {"apiKey": "stolen-secret"}})
    )

    fallback_dir = tmp_path / "home" / ".promptfoo"
    fallback_dir.mkdir(parents=True)
    (fallback_dir / "promptfoo.yaml").write_text(yaml.safe_dump({"id": "safe-id", "cloud": {"apiKey": "safe-key"}}))

    _patch_config_paths(auth_config, monkeypatch, primary_dir, fallback_dir)

    config = auth_config.read_global_config()

    assert config.id == "safe-id"
    assert config.cloud["apiKey"] == "safe-key"


def test_write_global_config_avoids_directory_under_symlinked_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    attacker_root = tmp_path / "attacker-root"
    attacker_root.mkdir()
    redirected_root = tmp_path / "redirected-root"
    redirected_root.symlink_to(attacker_root, target_is_directory=True)
    primary_dir = redirected_root / "promptfoo"
    fallback_dir = tmp_path / "home" / ".promptfoo"

    _patch_config_paths(auth_config, monkeypatch, primary_dir, fallback_dir)

    auth_config.write_global_config(auth_config.GlobalConfig({"id": "safe-id", "cloud": {"apiKey": "safe-key"}}))

    assert not (attacker_root / "promptfoo" / "promptfoo.yaml").exists()
    assert (fallback_dir / "promptfoo.yaml").exists()


def test_write_global_config_uses_private_file_permissions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    fallback_dir = tmp_path / "home" / ".promptfoo"

    _patch_config_paths(auth_config, monkeypatch, config_dir, fallback_dir)

    auth_config.write_global_config(auth_config.GlobalConfig({"id": "fixed-id", "cloud": {"apiKey": "secret"}}))

    config_file = config_dir / "promptfoo.yaml"
    assert config_file.exists()
    written = yaml.safe_load(config_file.read_text())
    assert written["cloud"]["apiKey"] == "secret"

    if os.name != "nt":
        assert stat.S_IMODE(config_file.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("api_host", "expected"),
    [
        ("https://api.promptfoo.app", "https://api.promptfoo.app"),
        (" https://API.PROMPTFOO.APP/ ", "https://api.promptfoo.app"),
        ("https://api.promptfoo.app:443", "https://api.promptfoo.app"),
    ],
)
def test_validate_api_host_for_bearer_auth_accepts_trusted_https_hosts(api_host: str, expected: str) -> None:
    assert auth_config.validate_api_host_for_bearer_auth(api_host) == expected


@pytest.mark.parametrize(
    "api_host",
    [
        "http://api.promptfoo.app",
        "api.promptfoo.app",
        "https://api.promptfoo.app.evil.example",
        "https://localhost:3000",
        "http://127.0.0.1:3000",
        "https://user:pass@api.promptfoo.app",
        "https://api.promptfoo.app/path",
        "https://api.promptfoo.app?token=leak",
        "https://api.promptfoo.app:4443",
    ],
)
def test_validate_api_host_for_bearer_auth_rejects_untrusted_hosts(api_host: str) -> None:
    with pytest.raises(ValueError, match="API host for bearer-token authentication"):
        auth_config.validate_api_host_for_bearer_auth(api_host)


def test_cloud_config_set_api_host_rejects_untrusted_hosts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    fallback_dir = tmp_path / "home" / ".promptfoo"
    _patch_config_paths(auth_config, monkeypatch, config_dir, fallback_dir)

    cloud_config = auth_config.CloudConfig()

    with pytest.raises(ValueError, match="must be one of"):
        cloud_config.set_api_host("https://attacker.example")


def test_validate_and_set_api_token_rejects_untrusted_host_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_fetch(_url: str, **_kwargs: Any) -> _FakeResponse:
        raise AssertionError("fetch_with_proxy must not be called for untrusted API hosts")

    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fail_fetch)

    with pytest.raises(ValueError, match="must use HTTPS"):
        auth_client_module.AuthClient().validate_and_set_api_token("secret-token", "http://api.promptfoo.app")


def test_auth_login_rejects_untrusted_host_before_request(monkeypatch: pytest.MonkeyPatch) -> None:
    from click.testing import CliRunner

    from modelaudit.cli import cli

    def fail_fetch(_url: str, **_kwargs: Any) -> _FakeResponse:
        raise AssertionError("fetch_with_proxy must not be called for untrusted API hosts")

    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fail_fetch)

    result = CliRunner().invoke(
        cli,
        ["auth", "login", "--api-key", "secret-token", "--host", "http://api.promptfoo.app"],
    )

    assert result.exit_code == 1
    assert "Authentication failed: API host for bearer-token authentication must use HTTPS" in result.output


def test_validate_and_set_api_token_accepts_trusted_host_and_stores_normalized_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_config = _FakeCloudConfig()
    requested_urls: list[str] = []

    def fake_fetch(url: str, **_kwargs: Any) -> _FakeResponse:
        requested_urls.append(url)
        return _FakeResponse()

    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fake_fetch)

    result = auth_client_module.AuthClient().validate_and_set_api_token(
        "secret-token",
        "https://API.PROMPTFOO.APP/",
    )

    assert result["user"].email == "user@example.com"
    assert requested_urls == ["https://api.promptfoo.app/api/v1/users/me"]
    assert fake_config.api_host == "https://api.promptfoo.app"
    assert fake_config.api_key == "secret-token"


def test_get_user_info_rejects_untrusted_config_host_before_request(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_config = _FakeCloudConfig(api_host="https://attacker.example", api_key="secret-token")

    def fail_fetch(_url: str, **_kwargs: Any) -> _FakeResponse:
        raise AssertionError("fetch_with_proxy must not be called for untrusted API hosts")

    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "get_user_email", lambda: "user@example.com")
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fail_fetch)

    with pytest.raises(ValueError, match="must be one of"):
        auth_client_module.AuthClient().get_user_info()
