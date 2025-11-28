from modelaudit.core import scan_model_directory_or_file
from modelaudit.scanners.base import IssueSeverity


def test_symlink_outside_directory(tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    (outside_dir / "secret.txt").write_text("secret")
    (base_dir / "safe.txt").write_text("safe")
    (base_dir / "link.txt").symlink_to(outside_dir / "secret.txt")

    results = scan_model_directory_or_file(str(base_dir))

    traversal_issues = [i for i in results.issues if "path traversal" in i.message.lower()]
    assert len(traversal_issues) == 1
    assert traversal_issues[0].severity == IssueSeverity.CRITICAL
