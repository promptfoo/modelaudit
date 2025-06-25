from modelaudit.utils import is_within_directory


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


def test_is_within_directory_symlink_inside_to_outside(tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("secret")
    link = base_dir / "link.txt"
    link.symlink_to(outside_file)
    assert is_within_directory(str(base_dir), str(link)) is False


def test_is_within_directory_symlink_outside_to_inside(tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    inside_file = base_dir / "inside.txt"
    inside_file.write_text("data")
    link = tmp_path / "outside_link.txt"
    link.symlink_to(inside_file)
    assert is_within_directory(str(base_dir), str(link)) is True
