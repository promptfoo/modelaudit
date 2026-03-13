import ntpath
import os
from pathlib import Path, PureWindowsPath

import pytest

from modelaudit import utils
from modelaudit.utils import is_within_directory, sanitize_archive_path


def test_is_within_directory_simple(tmp_path: Path) -> None:
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    inside = base_dir / "file.txt"
    inside.write_text("data")
    assert is_within_directory(str(base_dir), str(inside)) is True


def test_is_within_directory_outside(tmp_path: Path) -> None:
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("data")
    assert is_within_directory(str(base_dir), str(outside)) is False


def test_is_within_directory_symlink_inside_to_outside(tmp_path: Path, requires_symlinks: None) -> None:
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("secret")
    link = base_dir / "link.txt"
    link.symlink_to(outside_file)
    assert is_within_directory(str(base_dir), str(link)) is False


def test_is_within_directory_symlink_outside_to_inside(tmp_path: Path, requires_symlinks: None) -> None:
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    inside_file = base_dir / "inside.txt"
    inside_file.write_text("data")
    link = tmp_path / "outside_link.txt"
    link.symlink_to(inside_file)
    assert is_within_directory(str(base_dir), str(link)) is True


def test_sanitize_archive_path_does_not_follow_symlinked_base(tmp_path: Path, requires_symlinks: None) -> None:
    base_target = tmp_path / "real_extract_root"
    base_target.mkdir()
    symlinked_base = tmp_path / "extract"
    symlinked_base.symlink_to(base_target, target_is_directory=True)

    resolved_path, is_safe = sanitize_archive_path("../escape.txt", str(symlinked_base))

    assert is_safe is False
    assert Path(resolved_path) == tmp_path / "escape.txt"


def test_sanitize_archive_path_keeps_safe_paths_under_symlinked_base(tmp_path: Path, requires_symlinks: None) -> None:
    base_target = tmp_path / "real_extract_root"
    base_target.mkdir()
    symlinked_base = tmp_path / "extract"
    symlinked_base.symlink_to(base_target, target_is_directory=True)

    resolved_path, is_safe = sanitize_archive_path("nested/model.pkl", str(symlinked_base))

    assert is_safe is True
    assert Path(resolved_path) == symlinked_base / "nested" / "model.pkl"


def test_sanitize_archive_path_rejects_traversal_from_symlinked_base(tmp_path: Path, requires_symlinks: None) -> None:
    container = tmp_path / "container"
    container.mkdir()
    real_root = container / "real-root"
    real_root.mkdir()
    symlinked_base = container / "extract"
    symlinked_base.symlink_to(real_root, target_is_directory=True)

    resolved, is_safe = sanitize_archive_path("../real-root/secret.txt", str(symlinked_base))

    assert resolved == str(real_root / "secret.txt")
    assert is_safe is False


def test_sanitize_archive_path_keeps_safe_entry_within_symlinked_base(tmp_path: Path, requires_symlinks: None) -> None:
    container = tmp_path / "container"
    container.mkdir()
    real_root = container / "real-root"
    real_root.mkdir()
    symlinked_base = container / "extract"
    symlinked_base.symlink_to(real_root, target_is_directory=True)

    resolved, is_safe = sanitize_archive_path("nested/model.bin", str(symlinked_base))

    assert resolved == str(symlinked_base / "nested" / "model.bin")
    assert is_safe is True


def test_sanitize_archive_path_rejects_drive_qualified_absolute_entry(tmp_path: Path) -> None:
    base_dir = tmp_path / "extract"
    base_dir.mkdir()

    resolved, is_safe = sanitize_archive_path("C:/Windows/System32/drivers/etc/hosts", str(base_dir))

    expected = f"{base_dir}{os.sep}C:{os.sep}Windows{os.sep}System32{os.sep}drivers{os.sep}etc{os.sep}hosts"
    assert os.path.normpath(resolved) == os.path.normpath(expected)
    assert is_safe is False


def test_sanitize_archive_path_keeps_windows_drive_entry_under_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(utils.os, "path", ntpath)
    monkeypatch.setattr(utils.os, "sep", "\\")
    monkeypatch.setattr(utils, "_absolute_without_resolving", lambda path: PureWindowsPath(os.fspath(path)))

    resolved, is_safe = sanitize_archive_path("C:/Windows/System32/drivers/etc/hosts", "C:/extract")

    assert resolved == r"C:\extract\C:\Windows\System32\drivers\etc\hosts"
    assert is_safe is False


def test_sanitize_archive_path_normalizes_unsafe_absolute_like_entry(tmp_path: Path) -> None:
    base_dir = tmp_path / "extract"
    base_dir.mkdir()

    resolved, is_safe = sanitize_archive_path("/../secret.txt", str(base_dir))

    assert resolved == os.path.normpath(str(base_dir / ".." / "secret.txt"))
    assert is_safe is False
