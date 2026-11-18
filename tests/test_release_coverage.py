import json
import subprocess
import sys
from pathlib import Path

from tests.test_release_notes import git

COVERAGE = Path(__file__).resolve().parents[1] / "scripts/release_coverage.py"
SIBLING = "packages/modelaudit-picklescan"


def test_grouped_coverage_uses_each_tag_current_main_and_net_effects(tmp_path: Path) -> None:
    root = tmp_path
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.name", "test")
    git(root, "config", "user.email", "test@example.invalid")

    def commit(subject: str, files: dict[str, str], body: str = "") -> str:
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        git(root, "add", ".")
        git(root, "commit", "-qm", subject, "-m", body)
        return git(root, "rev-parse", "HEAD")

    def changes(root_ver: str, sibling_ver: str, root_notes: str = "", sibling_notes: str = "") -> dict[str, str]:
        return {
            ".release-please-manifest.json": json.dumps({".": root_ver, SIBLING: sibling_ver}),
            "CHANGELOG.md": f"## [{root_ver}]\n\n{root_notes}\n",
            f"{SIBLING}/CHANGELOG.md": f"## [{sibling_ver}]\n\n{sibling_notes}\n",
        }

    commit("chore: previous root version", changes("0.1.0", "0.1.0"))
    git(root, "tag", "v0.1.0")
    commit("fix: already in sibling release (#10)", {f"{SIBLING}/engine": "old"})
    git(root, "tag", "modelaudit-picklescan-v0.1.0")
    commit("fix: cross-package fix (#17)", {"modelaudit/code": "fixed", f"{SIBLING}/code": "fixed"})
    reverted = commit("feat: discontinued (#18)", {"modelaudit/draft": "x"})
    git(root, "revert", "--no-edit", reverted)
    restored = commit("feat: restored (#19)", {"modelaudit/new": "new"})
    git(root, "revert", "--no-edit", restored)
    git(root, "revert", "--no-edit", "HEAD")
    preserved = commit("fix: short hash under older version (#20)", {"modelaudit/hash": "new"})
    commit("docs: usage notes", {"README.md": "docs"})
    shadowed = commit("fix: correct wrongly linked PR (#23)", {"modelaudit/other": "fix"})
    git(root, "switch", "-qc", "candidate")
    candidate = commit(
        "chore: release",
        changes(
            "0.1.1",
            "0.1.1",
            f"[#17](https://github.com/promptfoo/modelaudit/pull/17)\n"
            f"[#23](https://github.com/elsewhere/other/pull/23)\n\n"
            f"<!-- release-note-source: {shadowed} -->\n\n## [0.1.0]\n\n{preserved}",
            "Previously included fix #10.",
        ),
    )
    git(root, "switch", "-q", "main")
    security = commit("chore(deps): risky <@team> `branch` [security] (#21)", {"uv.lock": "new"})
    breaking = commit("chore: adjust file layout", {"modelaudit/path": "new"}, "BREAKING CHANGE: update paths")
    report = subprocess.check_output([sys.executable, str(COVERAGE), "main", candidate], cwd=root, text=True)
    assert report.startswith("\n\n## Release note coverage")
    root_report, sibling_report = report.split("### modelaudit-picklescan 0.1.1")
    assert all(sha in root_report for sha in (restored, preserved, security, breaking, shadowed))
    assert all(text not in root_report for text in ("#10", "#17", "#18", "usage notes"))
    assert "#17" in sibling_report and "1 change has no matching" in sibling_report
    assert f"modelaudit-picklescan-v0.1.0...{breaking}" in sibling_report
    assert "`` chore(deps): risky <@team> `branch` [security] (#21) ``" in report

    for index in range(13):
        commit(f"fix: additional change {index}", {"modelaudit/bulk": str(index)})
    bounded = subprocess.check_output([sys.executable, str(COVERAGE), "main", candidate], cwd=root, text=True)
    assert "Showing 12 of 18." in bounded
    assert bounded.split("### modelaudit-picklescan")[0].count("/commit/") == 12


def test_unchanged_components_emit_nothing(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / ".release-please-manifest.json").write_text(json.dumps({".": "0.1.0", SIBLING: "0.1.0"}))
    git(tmp_path, "add", ".")
    git(tmp_path, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "test")
    result = subprocess.check_output([sys.executable, str(COVERAGE), "HEAD", "HEAD"], cwd=tmp_path)
    assert not result
