from pathlib import Path

from modelaudit.utils import is_within_directory, sanitize_archive_path


def test_is_within_directory_simple(tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    inside = base_dir / "file.txt"
    inside.write_text("data")
    assert is_within_directory(str(base_dir), str(inside)) is True


def test_is_within_directory_outside(tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("data")
    assert is_within_directory(str(base_dir), str(outside)) is False


def test_is_within_directory_symlink_inside_to_outside(tmp_path, requires_symlinks):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("secret")
    link = base_dir / "link.txt"
    link.symlink_to(outside_file)
    assert is_within_directory(str(base_dir), str(link)) is False


def test_is_within_directory_symlink_outside_to_inside(tmp_path, requires_symlinks):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    inside_file = base_dir / "inside.txt"
    inside_file.write_text("data")
    link = tmp_path / "outside_link.txt"
    link.symlink_to(inside_file)
    assert is_within_directory(str(base_dir), str(link)) is True


def test_sanitize_archive_path_rejects_traversal_from_symlinked_base(tmp_path: Path, requires_symlinks) -> None:
    container = tmp_path / "container"
    container.mkdir()
    real_root = container / "real-root"
    real_root.mkdir()
    symlinked_base = container / "extract"
    symlinked_base.symlink_to(real_root, target_is_directory=True)

    resolved, is_safe = sanitize_archive_path("../real-root/secret.txt", str(symlinked_base))

    assert resolved == str(real_root / "secret.txt")
    assert is_safe is False


def test_sanitize_archive_path_keeps_safe_entry_within_symlinked_base(tmp_path: Path, requires_symlinks) -> None:
    container = tmp_path / "container"
    container.mkdir()
    real_root = container / "real-root"
    real_root.mkdir()
    symlinked_base = container / "extract"
    symlinked_base.symlink_to(real_root, target_is_directory=True)

    resolved, is_safe = sanitize_archive_path("nested/model.bin", str(symlinked_base))

    assert resolved == str(symlinked_base / "nested" / "model.bin")
    assert is_safe is True
