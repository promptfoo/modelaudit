import os
import stat
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from modelaudit.auth import config as auth_config


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
