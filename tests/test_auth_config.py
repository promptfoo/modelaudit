import os
import stat
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import requests
import yaml

from modelaudit.auth import client as auth_client_module
from modelaudit.auth import config as auth_config


@pytest.fixture(autouse=True)
def clear_api_host_trust_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("MODELAUDIT_API_ALLOWED_HOSTS", "MODELAUDIT_API_HOST", "API_HOST"):
        monkeypatch.delenv(name, raising=False)


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
    def __init__(self, api_host: str = "https://api.promptfoo.app", api_key: str | None = None):
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

    def set_credentials(self, api_host: str, api_key: str, app_url: str) -> None:
        self.api_host = api_host
        self.api_key = api_key
        self.app_url = app_url

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


def test_write_global_config_partial_preserves_account_siblings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    fallback_dir = tmp_path / "home" / ".promptfoo"
    _patch_config_paths(auth_config, monkeypatch, config_dir, fallback_dir)

    auth_config.write_global_config(
        auth_config.GlobalConfig(
            {
                "id": "fixed-id",
                "account": {
                    "email": "old@example.com",
                    "name": "Keep Me",
                    "organization": "promptfoo",
                },
                "cloud": {"apiKey": "secret"},
            }
        )
    )

    auth_config.write_global_config_partial({"account": {"email": "new@example.com"}})

    written = yaml.safe_load((config_dir / "promptfoo.yaml").read_text())

    assert written["account"] == {
        "email": "new@example.com",
        "name": "Keep Me",
        "organization": "promptfoo",
    }
    assert written["cloud"] == {"apiKey": "secret"}


def test_write_global_config_partial_deep_merges_cloud_section(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    fallback_dir = tmp_path / "home" / ".promptfoo"
    _patch_config_paths(auth_config, monkeypatch, config_dir, fallback_dir)

    auth_config.write_global_config(
        auth_config.GlobalConfig(
            {
                "id": "fixed-id",
                "account": {"email": "user@example.com"},
                "cloud": {
                    "apiHost": "https://old-api.example",
                    "apiKey": "old-token",
                    "featureFlags": {"beta": True, "region": "eu"},
                    "customField": "keep-me",
                },
            }
        )
    )

    auth_config.write_global_config_partial(
        {
            "cloud": {
                "apiHost": "https://new-api.example",
                "featureFlags": {"region": "us"},
            }
        }
    )

    written = yaml.safe_load((config_dir / "promptfoo.yaml").read_text())

    assert written["cloud"] == {
        "apiHost": "https://new-api.example",
        "apiKey": "old-token",
        "featureFlags": {"beta": True, "region": "us"},
        "customField": "keep-me",
    }
    assert written["account"] == {"email": "user@example.com"}


def test_write_global_config_partial_preserves_nested_none_and_siblings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    fallback_dir = tmp_path / "home" / ".promptfoo"
    _patch_config_paths(auth_config, monkeypatch, config_dir, fallback_dir)
    auth_config.write_global_config(
        auth_config.GlobalConfig(
            {
                "id": "fixed-id",
                "account": {"email": "old@example.com", "name": "Keep Me", "organization": "promptfoo"},
                "cloud": {"apiKey": "secret"},
            }
        )
    )

    auth_config.write_global_config_partial({"account": {"name": None}})

    written = yaml.safe_load((config_dir / "promptfoo.yaml").read_text())
    assert written["account"] == {"email": "old@example.com", "name": None, "organization": "promptfoo"}
    assert written["cloud"] == {"apiKey": "secret"}


def test_cloud_config_delete_clears_cloud_section_without_touching_account(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    fallback_dir = tmp_path / "home" / ".promptfoo"
    _patch_config_paths(auth_config, monkeypatch, config_dir, fallback_dir)

    auth_config.write_global_config(
        auth_config.GlobalConfig(
            {
                "id": "fixed-id",
                "account": {"email": "user@example.com", "name": "Keep Me"},
                "cloud": {
                    "apiHost": "https://api.promptfoo.app",
                    "apiKey": "secret-token",
                    "customField": "remove-me",
                },
            }
        )
    )

    auth_config.CloudConfig().delete()

    written = yaml.safe_load((config_dir / "promptfoo.yaml").read_text())

    assert written["account"] == {"email": "user@example.com", "name": "Keep Me"}
    assert written["cloud"] == {}


@pytest.mark.parametrize(
    ("api_host", "expected"),
    [
        ("https://api.promptfoo.app", "https://api.promptfoo.app"),
        (" https://API.PROMPTFOO.APP/ ", "https://api.promptfoo.app"),
        ("https://api.promptfoo.app:443", "https://api.promptfoo.app"),
        ("https://api.promptfoo.app./", "https://api.promptfoo.app"),
        ("https://your-company.promptfoo.app", "https://your-company.promptfoo.app"),
    ],
)
def test_validate_api_host_for_bearer_auth_accepts_trusted_promptfoo_https_hosts(
    api_host: str,
    expected: str,
) -> None:
    assert auth_config.validate_api_host_for_bearer_auth(api_host) == expected


def test_validate_api_host_for_bearer_auth_accepts_explicitly_allowed_https_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", "enterprise.example,https://api.internal:9443")

    assert (
        auth_config.validate_api_host_for_bearer_auth("https://ENTERPRISE.EXAMPLE:8443/")
        == "https://enterprise.example:8443"
    )
    assert auth_config.validate_api_host_for_bearer_auth("https://api.internal:9443/") == "https://api.internal:9443"
    with pytest.raises(ValueError, match="trusted Promptfoo API host"):
        auth_config.validate_api_host_for_bearer_auth("https://api.internal/")


@pytest.mark.parametrize(
    ("configured_host", "api_host", "expected"),
    [
        ("https://[0:0:0:0:0:0:0:1]:8443", "https://[::1]:8443", "https://[::1]:8443"),
        ("[::1]", "https://[0:0:0:0:0:0:0:1]", "https://[::1]"),
        ("[::ffff:127.0.0.1]", "https://[::ffff:7f00:1]", "https://[::ffff:127.0.0.1]"),
    ],
)
def test_validate_api_host_for_bearer_auth_canonicalizes_allowed_ipv6_hosts(
    monkeypatch: pytest.MonkeyPatch,
    configured_host: str,
    api_host: str,
    expected: str,
) -> None:
    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", configured_host)

    assert auth_config.validate_api_host_for_bearer_auth(api_host) == expected


@pytest.mark.parametrize(
    ("configured_host", "api_host", "expected"),
    [
        ("faß.example", "https://faß.example", "https://xn--fa-hia.example"),
        ("βόλος.example", "https://βόλος.example", "https://xn--nxasmm1c.example"),
        ("ς.example", "https://ς.example", "https://xn--3xa.example"),
    ],
)
def test_validate_api_host_for_bearer_auth_matches_requests_idna_normalization(
    monkeypatch: pytest.MonkeyPatch,
    configured_host: str,
    api_host: str,
    expected: str,
) -> None:
    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", configured_host)

    normalized = auth_config.validate_api_host_for_bearer_auth(api_host)

    assert normalized == expected
    assert requests.Request("GET", api_host).prepare().url == f"{normalized}/"


@pytest.mark.parametrize(
    ("configured_host", "api_host"),
    [
        ("faß.example", "https://fass.example"),
        ("fass.example", "https://faß.example"),
    ],
)
def test_validate_api_host_for_bearer_auth_does_not_merge_distinct_idna_hosts(
    monkeypatch: pytest.MonkeyPatch,
    configured_host: str,
    api_host: str,
) -> None:
    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", configured_host)

    with pytest.raises(ValueError, match="trusted Promptfoo API host"):
        auth_config.validate_api_host_for_bearer_auth(api_host)


def test_validate_api_host_for_bearer_auth_rejects_allowlisted_invalid_ip_literal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", "[v1.fe80::]")

    with pytest.raises(ValueError, match="valid HTTPS URL"):
        auth_config.validate_api_host_for_bearer_auth("https://[v1.fe80::]")


@pytest.mark.parametrize("env_name", ["MODELAUDIT_API_HOST", "API_HOST"])
def test_validate_api_host_for_bearer_auth_trusts_exact_environment_host(
    monkeypatch: pytest.MonkeyPatch,
    env_name: str,
) -> None:
    monkeypatch.delenv("MODELAUDIT_API_ALLOWED_HOSTS", raising=False)
    for name in ("MODELAUDIT_API_HOST", "API_HOST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(env_name, "https://ENTERPRISE.EXAMPLE:8443/")

    assert auth_config.validate_api_host_for_bearer_auth("https://enterprise.example:8443") == (
        "https://enterprise.example:8443"
    )
    with pytest.raises(ValueError, match="trusted Promptfoo API host"):
        auth_config.validate_api_host_for_bearer_auth("https://enterprise.example:9443")
    with pytest.raises(ValueError, match="trusted Promptfoo API host"):
        auth_config.validate_api_host_for_bearer_auth("https://enterprise.example")
    with pytest.raises(ValueError, match="trusted Promptfoo API host"):
        auth_config.validate_api_host_for_bearer_auth("https://enterprise.example.attacker.test")


@pytest.mark.parametrize(
    "configured_host",
    [
        "http://attacker.example",
        "https://trusted.example@attacker.example",
        "https://attacker.example/path",
        "https://attacker.example?query=value",
        "https://attacker.example%2ftrusted.example",
        "https://attacker.example:0",
        "https://attacker.example:65536",
    ],
)
def test_validate_api_host_for_bearer_auth_ignores_ambiguous_allowlist_entries(
    monkeypatch: pytest.MonkeyPatch,
    configured_host: str,
) -> None:
    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", configured_host)
    monkeypatch.delenv("MODELAUDIT_API_HOST", raising=False)
    monkeypatch.delenv("API_HOST", raising=False)

    with pytest.raises(ValueError, match="trusted Promptfoo API host"):
        auth_config.validate_api_host_for_bearer_auth("https://attacker.example")


@pytest.mark.parametrize(
    "api_host",
    [
        "http://api.promptfoo.app",
        "api.promptfoo.app",
        "http://127.0.0.1:3000",
        "https://attacker.example",
        "https://api.promptfoo.app.evil.example",
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]:8443",
        "https://user:pass@api.promptfoo.app",
        "https://@api.promptfoo.app",
        "https://api.promptfoo.app/path",
        "https://api.promptfoo.app?token=leak",
        "https://api.promptfoo.app\\@attacker.example",
        "https://api.promptfoo.app%5c@attacker.example",
        "https://api.promptfoo.app\n.attacker.example",
        "https://api.promptfoo.app\x7f.attacker.example",
        "https://api.promptfoo.app:0",
        "https://api.promptfoo.app:8443",
        "https://api.promptfoo.app:65536",
        "https://.promptfoo.app",
        "https://foo..promptfoo.app",
        "https://promptfoo.app:/",
    ],
)
def test_validate_api_host_for_bearer_auth_rejects_unsafe_hosts(api_host: str) -> None:
    with pytest.raises(ValueError, match="API host for bearer-token authentication"):
        auth_config.validate_api_host_for_bearer_auth(api_host)


def test_cloud_config_set_api_host_rejects_non_https_hosts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    fallback_dir = tmp_path / "home" / ".promptfoo"
    _patch_config_paths(auth_config, monkeypatch, config_dir, fallback_dir)

    cloud_config = auth_config.CloudConfig()

    with pytest.raises(ValueError, match="must use HTTPS"):
        cloud_config.set_api_host("http://attacker.example")


def test_cloud_config_set_api_host_accepts_allowlisted_enterprise_https_hosts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    fallback_dir = tmp_path / "home" / ".promptfoo"
    _patch_config_paths(auth_config, monkeypatch, config_dir, fallback_dir)
    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", "enterprise.example")

    cloud_config = auth_config.CloudConfig()
    cloud_config.set_api_host("https://ENTERPRISE.EXAMPLE:8443/")

    assert cloud_config.get_api_host() == "https://enterprise.example:8443"


def test_cloud_config_set_api_host_rolls_back_in_memory_on_write_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cloud_config = auth_config.CloudConfig.__new__(auth_config.CloudConfig)
    old_config = {
        "appUrl": "https://old-app.example",
        "apiHost": "https://old-api.example",
        "apiKey": "old-token",
    }
    cloud_config.config = dict(old_config)

    def fail_save() -> None:
        raise OSError("disk full")

    monkeypatch.setattr(cloud_config, "_save_config", fail_save)

    with pytest.raises(OSError, match="disk full"):
        cloud_config.set_api_host("https://new-api.promptfoo.app")

    assert cloud_config.config == old_config


def test_cloud_config_set_api_host_detects_silent_persistence_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cloud_config = auth_config.CloudConfig.__new__(auth_config.CloudConfig)
    old_config = {
        "appUrl": "https://old-app.example",
        "apiHost": "https://old-api.example",
        "apiKey": "old-token",
    }
    cloud_config.config = dict(old_config)

    def silently_restore_old_config() -> None:
        cloud_config.config = dict(old_config)

    monkeypatch.setattr(cloud_config, "_save_config", silently_restore_old_config)

    with pytest.raises(OSError, match="Unable to persist cloud API host"):
        cloud_config.set_api_host("https://new-api.promptfoo.app")

    assert cloud_config.config == old_config


def test_validate_and_set_api_token_rejects_http_host_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_fetch(_url: str, **_kwargs: Any) -> _FakeResponse:
        raise AssertionError("fetch_with_proxy must not be called for untrusted API hosts")

    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fail_fetch)

    with pytest.raises(ValueError, match="must use HTTPS"):
        auth_client_module.AuthClient().validate_and_set_api_token("secret-token", "http://api.promptfoo.app")


def test_validate_and_set_api_token_rejects_attacker_https_host_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_fetch(_url: str, **_kwargs: Any) -> _FakeResponse:
        raise AssertionError("fetch_with_proxy must not be called for untrusted API hosts")

    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fail_fetch)

    with pytest.raises(ValueError, match="trusted Promptfoo API host"):
        auth_client_module.AuthClient().validate_and_set_api_token("secret-token", "https://attacker.example")


@pytest.mark.parametrize(
    ("api_host", "expected_message"),
    [
        ("http://api.promptfoo.app", "API host for bearer-token authentication must use HTTPS"),
        (
            "https://attacker.example",
            "API host for bearer-token authentication must be a trusted Promptfoo API host",
        ),
    ],
)
def test_auth_login_rejects_untrusted_host_before_request(
    monkeypatch: pytest.MonkeyPatch,
    api_host: str,
    expected_message: str,
) -> None:
    from click.testing import CliRunner

    from modelaudit.cli import cli

    def fail_fetch(_url: str, **_kwargs: Any) -> _FakeResponse:
        raise AssertionError("fetch_with_proxy must not be called for untrusted API hosts")

    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fail_fetch)

    result = CliRunner().invoke(
        cli,
        ["auth", "login", "--api-key", "secret-token", "--host", api_host],
    )

    assert result.exit_code == 1
    assert f"Authentication failed: {expected_message}" in result.output


def test_auth_login_accepts_explicit_enterprise_https_host(monkeypatch: pytest.MonkeyPatch) -> None:
    from click.testing import CliRunner

    from modelaudit.cli import cli

    fake_config = _FakeCloudConfig()
    requested_urls: list[str] = []

    def fake_fetch(url: str, **_kwargs: Any) -> _FakeResponse:
        requested_urls.append(url)
        return _FakeResponse()

    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", "enterprise.example")
    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fake_fetch)
    monkeypatch.setattr("modelaudit.cli.get_user_email", lambda: None)
    monkeypatch.setattr("modelaudit.cli.set_user_email", lambda _email: None)

    result = CliRunner().invoke(
        cli,
        ["auth", "login", "--api-key", "secret-token", "--host", "https://ENTERPRISE.EXAMPLE:8443/"],
    )

    assert result.exit_code == 0, result.output
    assert "Successfully logged in" in result.output
    assert requested_urls == ["https://enterprise.example:8443/api/v1/users/me"]
    assert fake_config.api_host == "https://enterprise.example:8443"


def test_auth_login_uses_environment_host_instead_of_persisted_host(monkeypatch: pytest.MonkeyPatch) -> None:
    from click.testing import CliRunner

    from modelaudit.cli import cli

    fake_config = _FakeCloudConfig(api_host="https://old.promptfoo.app")
    requested_urls: list[str] = []

    def fake_fetch(url: str, **_kwargs: Any) -> _FakeResponse:
        requested_urls.append(url)
        return _FakeResponse()

    monkeypatch.setenv("MODELAUDIT_API_HOST", "https://enterprise.example:8443")
    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fake_fetch)
    monkeypatch.setattr("modelaudit.cli.get_user_email", lambda: None)
    monkeypatch.setattr("modelaudit.cli.set_user_email", lambda _email: None)

    result = CliRunner().invoke(cli, ["auth", "login", "--api-key", "enterprise-token"])

    assert result.exit_code == 0, result.output
    assert requested_urls == ["https://enterprise.example:8443/api/v1/users/me"]
    assert fake_config.api_host == "https://enterprise.example:8443"


def test_auth_login_help_documents_custom_host_trust_configuration() -> None:
    from click.testing import CliRunner

    from modelaudit.cli import cli

    result = CliRunner().invoke(cli, ["auth", "login", "--help"])

    assert result.exit_code == 0, result.output
    assert "MODELAUDIT_API_ALLOWED_HOSTS" in result.output
    assert "MODELAUDIT_API_HOST" in result.output
    assert "API_HOST" in result.output


def test_validate_and_set_api_token_accepts_configured_host_and_stores_normalized_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_config = _FakeCloudConfig()
    requested_urls: list[str] = []
    requested_kwargs: list[dict[str, Any]] = []

    def fake_fetch(url: str, **kwargs: Any) -> _FakeResponse:
        requested_urls.append(url)
        requested_kwargs.append(kwargs)
        return _FakeResponse()

    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", "enterprise.example")
    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fake_fetch)

    result = auth_client_module.AuthClient().validate_and_set_api_token(
        "secret-token",
        "https://ENTERPRISE.EXAMPLE:8443/",
    )

    assert result["user"].email == "user@example.com"
    assert requested_urls == ["https://enterprise.example:8443/api/v1/users/me"]
    assert requested_kwargs[0]["allow_redirects"] is False
    assert fake_config.api_host == "https://enterprise.example:8443"
    assert fake_config.api_key == "secret-token"


def test_validate_and_set_api_token_uses_environment_host_instead_of_persisted_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_config = _FakeCloudConfig(api_host="https://old.promptfoo.app")
    requested_urls: list[str] = []

    def fake_fetch(url: str, **_kwargs: Any) -> _FakeResponse:
        requested_urls.append(url)
        return _FakeResponse()

    monkeypatch.setenv("MODELAUDIT_API_HOST", "https://enterprise.example:8443")
    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fake_fetch)

    auth_client_module.AuthClient().validate_and_set_api_token("enterprise-token")

    assert requested_urls == ["https://enterprise.example:8443/api/v1/users/me"]
    assert fake_config.api_host == "https://enterprise.example:8443"
    assert fake_config.api_key == "enterprise-token"


def test_validate_and_set_api_token_does_not_change_credentials_when_atomic_persistence_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingCredentialsConfig(_FakeCloudConfig):
        def set_credentials(self, api_host: str, api_key: str, app_url: str) -> None:
            raise OSError(f"cannot persist {api_host}, {api_key}, {app_url}")

    fake_config = FailingCredentialsConfig(api_host="https://old.example", api_key="old-token")
    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", lambda _url, **_kwargs: _FakeResponse())

    with pytest.raises(OSError, match="cannot persist"):
        auth_client_module.AuthClient().validate_and_set_api_token(
            "new-token",
            "https://safe.promptfoo.app",
        )

    assert fake_config.api_host == "https://old.example"
    assert fake_config.api_key == "old-token"


def test_cloud_config_set_credentials_uses_one_cloud_write(monkeypatch: pytest.MonkeyPatch) -> None:
    cloud_config = auth_config.CloudConfig.__new__(auth_config.CloudConfig)
    cloud_config.config = {
        "appUrl": "https://old-app.example",
        "apiHost": "https://old-api.example",
        "apiKey": "old-token",
    }
    writes: list[dict[str, Any]] = []

    monkeypatch.setattr(auth_config, "write_global_config_partial", lambda partial: writes.append(partial))
    monkeypatch.setattr(cloud_config, "_reload", lambda: None)

    cloud_config.set_credentials("https://NEW-API.PROMPTFOO.APP:443/", "new-token", "https://new-app.example")

    expected_cloud_config = {
        "appUrl": "https://new-app.example",
        "apiHost": "https://new-api.promptfoo.app",
        "apiKey": "new-token",
    }
    assert cloud_config.config == expected_cloud_config
    assert writes == [{"cloud": expected_cloud_config}]


def test_cloud_config_set_credentials_rolls_back_in_memory_on_write_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cloud_config = auth_config.CloudConfig.__new__(auth_config.CloudConfig)
    old_config = {
        "appUrl": "https://old-app.example",
        "apiHost": "https://old-api.example",
        "apiKey": "old-token",
    }
    cloud_config.config = dict(old_config)

    def fail_write(_partial: dict[str, Any]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(auth_config, "write_global_config_partial", fail_write)

    with pytest.raises(OSError, match="disk full"):
        cloud_config.set_credentials("https://new-api.promptfoo.app", "new-token", "https://new-app.example")

    assert cloud_config.config == old_config


def test_cloud_config_set_credentials_detects_silent_persistence_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cloud_config = auth_config.CloudConfig.__new__(auth_config.CloudConfig)
    old_config = {
        "appUrl": "https://old-app.example",
        "apiHost": "https://old-api.example",
        "apiKey": "old-token",
    }
    cloud_config.config = dict(old_config)

    def silently_restore_old_config() -> None:
        cloud_config.config = dict(old_config)

    monkeypatch.setattr(cloud_config, "_save_config", silently_restore_old_config)

    with pytest.raises(OSError, match="Unable to persist cloud authentication credentials"):
        cloud_config.set_credentials("https://new-api.promptfoo.app", "new-token", "https://new-app.example")

    assert cloud_config.config == old_config


def test_validate_and_set_api_token_rejects_redirect_response_without_persisting_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RedirectResponse(_FakeResponse):
        status_code = 302
        reason = "Found"

    fake_config = _FakeCloudConfig(api_host="https://old.example", api_key="old-token")
    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", lambda _url, **_kwargs: RedirectResponse())

    with pytest.raises(Exception, match="Failed to validate API token: Found"):
        auth_client_module.AuthClient().validate_and_set_api_token(
            "new-token",
            "https://safe.promptfoo.app",
        )

    assert fake_config.api_host == "https://old.example"
    assert fake_config.api_key == "old-token"


def test_get_user_info_rejects_non_https_config_host_before_request(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_config = _FakeCloudConfig(api_host="http://attacker.example", api_key="secret-token")

    def fail_fetch(_url: str, **_kwargs: Any) -> _FakeResponse:
        raise AssertionError("fetch_with_proxy must not be called for untrusted API hosts")

    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module.config, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "get_user_email", lambda: "user@example.com")
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fail_fetch)

    with pytest.raises(ValueError, match="must use HTTPS"):
        auth_client_module.AuthClient().get_user_info()


def test_get_user_info_rejects_attacker_https_config_host_before_request(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_config = _FakeCloudConfig(api_host="https://attacker.example", api_key="secret-token")

    def fail_fetch(_url: str, **_kwargs: Any) -> _FakeResponse:
        raise AssertionError("fetch_with_proxy must not be called for untrusted API hosts")

    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module.config, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "get_user_email", lambda: "user@example.com")
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fail_fetch)

    with pytest.raises(ValueError, match="trusted Promptfoo API host"):
        auth_client_module.AuthClient().get_user_info()


def test_get_user_info_accepts_persisted_enterprise_https_host(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_config = _FakeCloudConfig(api_host="https://enterprise.example:8443", api_key="secret-token")
    requested_urls: list[str] = []
    requested_kwargs: list[dict[str, Any]] = []

    def fake_fetch(url: str, **kwargs: Any) -> _FakeResponse:
        requested_urls.append(url)
        requested_kwargs.append(kwargs)
        return _FakeResponse()

    monkeypatch.setenv("MODELAUDIT_API_ALLOWED_HOSTS", "enterprise.example")
    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module.config, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "get_user_email", lambda: "user@example.com")
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fake_fetch)

    auth_client_module.AuthClient().get_user_info()

    assert requested_urls == ["https://enterprise.example:8443/api/v1/users/me"]
    assert requested_kwargs[0]["allow_redirects"] is False


def test_get_user_info_uses_environment_host_instead_of_persisted_host(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_config = _FakeCloudConfig(api_host="https://old.promptfoo.app", api_key="enterprise-token")
    requested_urls: list[str] = []

    def fake_fetch(url: str, **_kwargs: Any) -> _FakeResponse:
        requested_urls.append(url)
        return _FakeResponse()

    monkeypatch.setenv("MODELAUDIT_API_HOST", "https://enterprise.example:8443")
    monkeypatch.setattr(auth_client_module, "cloud_config", fake_config)
    monkeypatch.setattr(auth_client_module, "get_user_email", lambda: "user@example.com")
    monkeypatch.setattr(auth_client_module, "fetch_with_proxy", fake_fetch)

    auth_client_module.AuthClient().get_user_info()

    assert requested_urls == ["https://enterprise.example:8443/api/v1/users/me"]
