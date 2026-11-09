from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/release_notes.py"
SIBLING = "packages/modelaudit-picklescan"


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def run(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=root, capture_output=True, text=True, check=check)


def write_manifest(root: Path, root_version: str, sibling_version: str) -> None:
    (root / ".release-please-manifest.json").write_text(json.dumps({".": root_version, SIBLING: sibling_version}))


def commit(root: Path, title: str) -> str:
    git(root, "add", ".")
    git(root, "commit", "-qm", title)
    return git(root, "rev-parse", "HEAD")


def fragment(root: Path, path: str, text: str) -> None:
    file = root / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text, encoding="utf-8")


def raw_section(root: Path, path: str, before: str, after: str, prefix: str) -> None:
    file = root / path / "CHANGELOG.md"
    comparison = f"https://github.com/promptfoo/modelaudit/compare/{prefix}{before}...{prefix}{after}"
    header = f"## [{after}]({comparison}) (2026-11-08)"
    old = file.read_text()
    file.write_text(
        old.replace("## [Unreleased]", f"{header}\n\n### Bug Fixes\n\n- merged change\n\n## [Unreleased]", 1)
    )


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Release Test")
    git(tmp_path, "config", "user.email", "release@example.invalid")
    write_manifest(tmp_path, "0.2.1", "0.1.1")
    for path, version, prefix in ((".", "0.2.1", "v"), (SIBLING, "0.1.1", "modelaudit-picklescan-v")):
        f = tmp_path / path / "CHANGELOG.md"
        f.parent.mkdir(parents=True, exist_ok=True)
        package = "modelaudit" if path == "." else "modelaudit-picklescan"
        comparison = f"https://github.com/promptfoo/modelaudit/compare/{prefix}{version}...main"
        f.write_text(
            f"# Changelog\n\n## [Unreleased]\n\n[Commits since the latest release]({comparison}). "
            f"To preview pending [release note fragments](changes/), run `python scripts/release_notes.py "
            f"pending --package {package}` from the repository root.\n\n"
            f"## [{version}] - 2026-10-01\n\n- Earlier fix.\n"
        )
    commit(tmp_path, "previous paired release")
    for tag in ("v0.2.1", "modelaudit-picklescan-v0.1.1"):
        git(tmp_path, "tag", tag)
    return tmp_path


def test_reviewed_notes_follow_each_package_across_release_boundaries(repository: Path) -> None:
    root = repository
    source = "changes/42.upgrade.md"
    fragment(root, source, "Draft instructions.\n")
    fragment(root, "changes/43.security.md", "Updates a vulnerable dependency.\n")
    fragment(root, f"{SIBLING}/changes/44.other.md", "More storage coverage.\n")
    base = commit(root, "first changes")
    write_manifest(root, "0.2.2", "0.1.2")
    raw_section(root, ".", "0.2.1", "0.2.2", "v")
    raw_section(root, SIBLING, "0.1.1", "0.1.2", "modelaudit-picklescan-v")
    reviews = root.parent / f"{root.name}-reviews.json"
    marker = f"<!-- release-note: {source} -->"
    reviews.write_text(json.dumps([{"id": 1, "body": f"{marker}\r\n\r\nReviewed instructions."}]))
    run(root, "render", "--base", base, "--reviews", str(reviews))
    changelogs = [root / "CHANGELOG.md", root / SIBLING / "CHANGELOG.md"]
    initial = [p.read_bytes() for p in changelogs]
    run(root, "check")
    run(root, "render", "--base", base, "--reviews", str(reviews))
    assert [p.read_bytes() for p in changelogs] == initial
    assert initial[0].count(b"Reviewed instructions.") == 1
    assert b"### Security\n\n- Updates a vulnerable dependency." in initial[0]
    assert b"Reviewed instructions. [#42](https://github.com/promptfoo/modelaudit/issues/42)" in initial[0]
    assert b"Draft instructions" not in initial[0]
    assert b"storage coverage" not in initial[0]
    assert b"storage coverage" in initial[1]
    assert b"Other changes" in initial[1]
    assert b"merged change" in initial[0] and b"All changes" in initial[0]
    # Simulate a bot refresh from main: its default changelogs are rebuilt and a new PR has landed.
    for file in changelogs:
        git(root, "restore", "--source", base, "--", str(file.relative_to(root)))
    write_manifest(root, "0.2.1", "0.1.1")
    fragment(root, "changes/+late.highlight.md", "Newly merged.\n")
    base = commit(root, "another change while under review")
    write_manifest(root, "0.2.2", "0.1.2")
    raw_section(root, ".", "0.2.1", "0.2.2", "v")
    raw_section(root, SIBLING, "0.1.1", "0.1.2", "modelaudit-picklescan-v")
    run(root, "render", "--base", base, "--reviews", str(reviews))
    commit(root, "paired release")
    for tag in ("v0.2.2", "modelaudit-picklescan-v0.1.2"):
        git(root, "tag", tag)
    for package, path, version, tag in (
        ("modelaudit", ".", "0.2.2", "v0.2.2"),
        ("modelaudit-picklescan", SIBLING, "0.1.2", "modelaudit-picklescan-v0.1.2"),
    ):
        public = run(root, "extract", "--package", package, "--version", version, "--ref", f"refs/tags/{tag}").stdout
        text = (root / path / "CHANGELOG.md").read_text()
        reviewed = text[text.index(f"## [{version}]") :].split("\n## [", 1)[0].rstrip() + "\n"
        assert public == reviewed
    assert b"Reviewed instructions." in changelogs[0].read_bytes()
    assert b"Newly merged." in changelogs[0].read_bytes()
    sibling_after_release = changelogs[1].read_bytes()
    fragment(root, "changes/45.highlight.md", "Post-release only.\n")
    base = commit(root, "post-release change")
    pending = run(root, "pending", "--package", "modelaudit").stdout
    assert "Post-release only." in pending and "Reviewed instructions." not in pending
    write_manifest(root, "0.2.3", "0.1.2")
    raw_section(root, ".", "0.2.2", "0.2.3", "v")
    run(root, "render", "--base", base)
    assert changelogs[1].read_bytes() == sibling_after_release
    second = run(root, "extract", "--package", "modelaudit", "--version", "0.2.3").stdout
    assert "Post-release only." in second and "Newly merged." not in second
    assert (
        "Post-release only."
        not in run(root, "extract", "--package", "modelaudit", "--version", "0.2.2", "--ref", "v0.2.2").stdout
    )


@pytest.mark.parametrize("entry", ["- Wrong location.", "Plain paragraph.", "1. Numbered change.", "+ New feature."])
def test_invalid_unreleased_entries_and_fragments_report_a_fix(repository: Path, entry: str) -> None:
    root = repository
    file = root / "CHANGELOG.md"
    file.write_text(file.read_text().replace("## [Unreleased]", f"## [Unreleased]\n\n{entry}"))
    assert "changes/" in run(root, "check", check=False).stderr
    git(root, "restore", "CHANGELOG.md")
    fragment(root, "changes/7.unknown.md", "Misspelled category.\n")
    invalid = run(root, "check", check=False)
    assert invalid.returncode != 0
    assert "7.unknown.md" in invalid.stderr


def test_sibling_only_release_with_no_fragments_retains_inventory(repository: Path) -> None:
    root = repository
    before = (root / "CHANGELOG.md").read_bytes()
    base = git(root, "rev-parse", "HEAD")
    write_manifest(root, "0.2.1", "0.1.2")
    raw_section(root, SIBLING, "0.1.1", "0.1.2", "modelaudit-picklescan-v")
    run(root, "render", "--base", base)
    public = run(root, "extract", "--package", "modelaudit-picklescan", "--version", "0.1.2").stdout
    assert "<summary>All changes</summary>" in public
    assert "merged change" in public
    assert "### Highlights" not in public
    assert (root / "CHANGELOG.md").read_bytes() == before


@pytest.mark.parametrize(
    ("old", "new", "error"),
    [
        ("## [0.1.2]", "## [0.1.3]", "expected 0.1.2 immediately after Unreleased"),
        ("/compare/modelaudit-picklescan-v0.1.1...", "/compare/v0.1.1...", "expected release comparison"),
        ("<summary>All changes</summary>", "<summary>Miscellaneous</summary>", "missing All changes"),
        ("</details>\n\n## [0.1.1]", "## [0.1.1]", "incomplete All changes"),
        ("[Full comparison]", "[Old comparison]", "missing Full comparison"),
        ("<!-- release-note-source:", "<!-- removed:", "missing release-note-source"),
        ("<!-- release-note-entries:", "<!-- removed:", "reviewed entry count"),
        ("### Upgrade notes", "", "missing reviewed category"),
        ("<summary>Other changes</summary>", "", "missing reviewed category"),
        ("- First change. [#42]", "- First change. [#43]", "missing reviewed reference for"),
    ],
)
def test_check_rejects_incomplete_release_candidate(repository: Path, old: str, new: str, error: str) -> None:
    fragment(repository, f"{SIBLING}/changes/42.upgrade.md", "First change.\n")
    fragment(repository, f"{SIBLING}/changes/43.upgrade.md", "Second change.\n")
    fragment(repository, f"{SIBLING}/changes/+cli.other.md", "The CLI reports progress.\n")
    base = commit(repository, "add standalone release notes")
    write_manifest(repository, "0.2.1", "0.1.2")
    raw_section(repository, SIBLING, "0.1.1", "0.1.2", "modelaudit-picklescan-v")
    run(repository, "render", "--base", base)
    run(repository, "check", "--base", base)
    changelog = repository / SIBLING / "CHANGELOG.md"
    changelog.write_text(changelog.read_text().replace(old, new, 1))
    rejected = run(repository, "check", "--base", base, check=False)
    assert rejected.returncode != 0
    assert f"{Path(SIBLING) / 'CHANGELOG.md'}: {error}" in rejected.stderr


@pytest.mark.parametrize("repository_url", ["https://example.org", "https://github.com/another/project"])
def test_release_comparisons_must_point_to_this_repository(repository: Path, repository_url: str) -> None:
    base = git(repository, "rev-parse", "HEAD")
    write_manifest(repository, "0.2.2", "0.1.1")
    raw_section(repository, ".", "0.2.1", "0.2.2", "v")
    file = repository / "CHANGELOG.md"
    comparison = "https://github.com/promptfoo/modelaudit/compare/v0.2.1...v0.2.2"
    wrong = f"{repository_url}/compare/v0.2.1...v0.2.2"
    raw = file.read_text()
    file.write_text(raw.replace(comparison, wrong))
    assert "expected release comparison" in run(repository, "render", "--base", base, check=False).stderr

    file.write_text(raw)
    run(repository, "render", "--base", base)
    reviewed = file.read_text()
    assert reviewed.count(comparison) == 2  # Heading and full comparison in the inventory.
    file.write_text(reviewed.replace(comparison, wrong))
    assert "expected release comparison" in run(repository, "check", "--base", base, check=False).stderr


def test_sibling_release_leaves_root_fragments_pending(repository: Path) -> None:
    root = repository
    fragment(root, "changes/42.upgrade.md", "Root callers must migrate.\n")
    fragment(root, f"{SIBLING}/changes/42.other.md", "Standalone diagnostics improved.\n")
    base = commit(root, "changes for both packages")
    root_draft = run(root, "pending", "--package", "modelaudit").stdout
    assert "Root callers must migrate." in root_draft
    write_manifest(root, "0.2.1", "0.1.2")
    raw_section(root, SIBLING, "0.1.1", "0.1.2", "modelaudit-picklescan-v")
    run(root, "render", "--base", base)
    assert git(root, "diff", base, "--", "CHANGELOG.md") == ""
    sibling = run(root, "extract", "--package", "modelaudit-picklescan", "--version", "0.1.2").stdout
    assert "Standalone diagnostics improved." in sibling
    assert "Root callers must migrate." not in sibling
    commit(root, "standalone release")
    git(root, "tag", "modelaudit-picklescan-v0.1.2")
    assert run(root, "pending", "--package", "modelaudit").stdout == root_draft
    assert run(root, "pending", "--package", "modelaudit-picklescan").stdout.strip() == "No pending release notes."


def test_shipped_fragment_paths_cannot_be_silently_reused(repository: Path) -> None:
    root = repository
    fragment(root, "changes/46.other.md", "First.\n")
    base = commit(root, "first change")
    write_manifest(root, "0.2.2", "0.1.1")
    raw_section(root, ".", "0.2.1", "0.2.2", "v")
    run(root, "render", "--base", base)
    commit(root, "release")
    git(root, "tag", "v0.2.2")
    fragment(root, "changes/46.other.md", "Different.\n")
    for args in (("check",), ("pending", "--package", "modelaudit")):
        rejected = run(root, *args, check=False)
        assert rejected.returncode != 0
        assert "new fragment filename" in rejected.stderr


def test_late_fragments_survive_a_squash_of_an_older_release_candidate(repository: Path) -> None:
    root = repository
    git(root, "branch", "-M", "main")
    fragment(root, "changes/70.other.md", "Reviewed earlier.\n")
    fragment(root, "changes/71.other.md", "Original instructions.\n")
    source = commit(root, "review these fragments")
    git(root, "switch", "-c", "release-pr")
    write_manifest(root, "0.2.2", "0.1.1")
    raw_section(root, ".", "0.2.1", "0.2.2", "v")
    run(root, "render", "--base", source)
    commit(root, "render reviewed changelog")
    git(root, "switch", "main")
    fragment(root, "changes/71.other.md", "Revised instructions.\n")
    fragment(root, "changes/72.security.md", "Late security fix.\n")
    late = commit(root, "amend a pending note and add a fix before the bot refreshes")
    git(root, "merge", "--squash", "release-pr")
    released = commit(root, "squash release onto a newer main")
    run(root, "check", "--base", late)
    git(root, "tag", "v0.2.2")
    first = run(root, "extract", "--package", "modelaudit", "--version", "0.2.2", "--ref", "v0.2.2").stdout
    assert f"<!-- release-note-source: {source} -->" in first
    assert "Late security fix." not in first and "Original instructions." in first
    pending = run(root, "pending", "--package", "modelaudit").stdout
    assert "Late security fix." in pending and "Revised instructions." in pending and "Reviewed earlier." not in pending

    write_manifest(root, "0.2.3", "0.1.1")
    raw_section(root, ".", "0.2.2", "0.2.3", "v")
    run(root, "render", "--base", released)
    second = run(root, "extract", "--package", "modelaudit", "--version", "0.2.3").stdout
    assert pending in second and "Reviewed earlier." not in second
    commit(root, "ship the late notes")
    git(root, "tag", "v0.2.3")
    assert run(root, "pending", "--package", "modelaudit").stdout.strip() == "No pending release notes."


def test_render_rejects_fragments_missing_from_or_changed_since_review_base(repository: Path) -> None:
    root = repository
    path = "changes/70.other.md"
    fragment(root, path, "Original.\n")
    source = commit(root, "release base")
    write_manifest(root, "0.2.2", "0.1.1")
    raw_section(root, ".", "0.2.1", "0.2.2", "v")
    for name in ("changes/71.other.md", path):
        fragment(root, name, "Candidate-only addition or edit.\n")
        rejected = run(root, "render", "--base", source, check=False)
        assert rejected.returncode != 0 and "release candidate fragments differ" in rejected.stderr
        (root / name).unlink()


def test_legacy_and_invalid_tagged_fragment_sources(repository: Path) -> None:
    root = repository
    fragment(root, "changes/70.other.md", "Shipped before source markers.\n")
    base = commit(root, "last release without a snapshot")
    git(root, "tag", "-f", "v0.2.1", base)
    assert run(root, "pending", "--package", "modelaudit").stdout.strip() == "No pending release notes."
    other_history = git(root, "commit-tree", "HEAD^{tree}", "-m", "unrelated history")
    file = root / "CHANGELOG.md"
    original = file.read_text()
    for marker in ("HEAD", other_history):
        file.write_text(
            original.replace(
                "## [0.2.1] - 2026-10-01", f"## [0.2.1] - 2026-10-01\n\n<!-- release-note-source: {marker} -->"
            )
        )
        git(root, "tag", "-f", "v0.2.1", commit(root, "tag with a bad marker"))
        rejected = run(root, "pending", "--package", "modelaudit", check=False)
        assert rejected.returncode != 0 and (
            "Invalid release-note-source" in rejected.stderr or "must be a commit" in rejected.stderr
        )


def test_untagged_release_uses_the_pr_base_but_normal_checkout_requires_its_exact_tag(repository: Path) -> None:
    fragment(repository, "changes/72.other.md", "Pending release wording.\n")
    base = commit(repository, "add a fragment before preparing the candidate")
    git(repository, "update-ref", "refs/remotes/origin/main", base)
    git(repository, "switch", "-c", "release-please--branches--main")
    write_manifest(repository, "0.2.2", "0.1.1")
    raw_section(repository, ".", "0.2.1", "0.2.2", "v")
    run(repository, "render", "--base", base)
    commit(repository, "release candidate")
    run(repository, "check")
    pending = run(repository, "pending", "--package", "modelaudit").stdout
    assert "Pending release wording." in pending

    # A detached checkout can specify its PR base. Without it, do not guess
    # that an older available tag is the latest release in an incomplete clone.
    git(repository, "switch", "--detach")
    run(repository, "check", "--base", base)
    assert run(repository, "pending", "--package", "modelaudit", "--base", base).stdout == pending
    for args in (("check",), ("pending", "--package", "modelaudit")):
        missing = run(repository, *args, check=False)
        assert missing.returncode != 0
        assert "git fetch origin tag v0.2.2" in missing.stderr


def test_extract_from_historical_tags_with_repeated_unreleased_headings(repository: Path) -> None:
    # Older tags such as v0.2.49 contain multiple Unreleased sections.
    changelog = repository / "CHANGELOG.md"
    section = "## [0.2.1] - 2026-10-01\n\n- Earlier fix.\n"
    with changelog.open("a", encoding="utf-8") as stream:
        stream.write("\n## [Unreleased]\n")
    ref = commit(repository, "older layout")
    assert run(repository, "extract", "--package", "modelaudit", "--version", "0.2.1", "--ref", ref).stdout == section
    with changelog.open("a", encoding="utf-8") as stream:
        stream.write("\n" + section)
    result = run(repository, "extract", "--package", "modelaudit", "--version", "0.2.1", check=False)
    assert result.returncode != 0
    assert "Duplicate changelog section 0.2.1" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="release publication runs in Bash on Ubuntu")
@pytest.mark.parametrize(
    ("manual", "exists", "tagged", "predates_changelog", "expected"),
    [
        (False, True, True, False, "edit"),
        (True, False, True, False, "create"),
        (True, False, False, False, "create"),
        (True, False, True, True, "create"),
    ],
)
def test_publication_sends_the_exact_tagged_section(
    repository: Path,
    tmp_path_factory: pytest.TempPathFactory,
    manual: bool,
    exists: bool,
    tagged: bool,
    predates_changelog: bool,
    expected: str,
) -> None:
    root = repository
    scratch = tmp_path_factory.mktemp("publish")
    (root / "scripts").mkdir()
    shutil.copyfile(SCRIPT, root / "scripts" / SCRIPT.name)
    fragment(root, "changes/47.upgrade.md", "Use the new interface.\n")
    base = commit(root, "add reviewed fragment")
    write_manifest(root, "0.2.2", "0.1.1")
    raw_section(root, ".", "0.2.1", "0.2.2", "v")
    run(root, "render", "--base", base)
    expected_notes = run(root, "extract", "--package", "modelaudit", "--version", "0.2.2").stdout
    if predates_changelog:
        (root / "CHANGELOG.md").unlink()
        (root / "scripts" / SCRIPT.name).unlink()
        expected_notes = "Manual recovery release for modelaudit 0.2.2.\n"
    dispatch = commit(root, "release")
    if tagged:
        git(root, "tag", "v0.2.2")
    shutil.copyfile(SCRIPT, root / "scripts" / SCRIPT.name)
    (root / "CHANGELOG.md").write_text("Notes changed on main after tagging.\n")
    gh = scratch / "gh"
    gh.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys\n"
        "if sys.argv[1] == 'api':\n"
        " assert 'POST' in sys.argv and 'ref=refs/tags/v0.2.2' in sys.argv\n"
        " assert 'sha=' + os.environ['GITHUB_SHA'] in sys.argv\n"
        " pathlib.Path(os.environ['RUNNER_TEMP'], 'created-tag').touch()\n"
        " sys.exit(0)\n"
        "assert sys.argv[1] == 'release'\n"
        "if sys.argv[2] == 'view': sys.exit(0 if os.environ['MOCK_EXISTS'] == 'yes' else 1)\n"
        "assert sys.argv[2] in ('create', 'edit') and sys.argv[3] == 'v0.2.2'\n"
        "if sys.argv[2] == 'create': assert '--verify-tag' in sys.argv\n"
        "notes = pathlib.Path(sys.argv[sys.argv.index('--notes-file') + 1]).read_text()\n"
        "pathlib.Path(os.environ['RUNNER_TEMP'], 'sent.json').write_text(json.dumps([sys.argv[2], notes]))\n"
    )
    gh.chmod(0o755)
    workflow = yaml.safe_load((SCRIPT.parents[1] / ".github/workflows/release-please.yml").read_text())
    steps = workflow["jobs"]["release-please"]["steps"]
    shell = next(step["run"] for step in steps if step.get("name") == "Publish notes from the tagged changelogs")
    env = {
        **os.environ,
        "PATH": str(scratch) + os.pathsep + os.environ["PATH"],
        "GITHUB_REPOSITORY": "example/modelaudit",
        "RUNNER_TEMP": str(scratch),
        "ROOT_VERSION": "0.2.2",
        "PICKLESCAN_VERSION": "",
        "MANUAL_RELEASE": str(manual).lower(),
        "MOCK_EXISTS": "yes" if exists else "no",
        "GITHUB_SHA": dispatch,
    }
    subprocess.run(["bash", "-c", shell], cwd=root, env=env, check=True, capture_output=True)
    assert json.loads((scratch / "sent.json").read_text()) == [expected, expected_notes]
    assert (scratch / "created-tag").exists() == (not tagged)


@pytest.mark.skipif(os.name == "nt" or shutil.which("jq") is None, reason="metadata job uses Bash and jq on Ubuntu")
def test_metadata_job_accepts_only_review_comments_from_writers(
    repository: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    root = repository
    scratch = tmp_path_factory.mktemp("review")
    notes = "changes/42.upgrade.md"
    (root / "scripts").mkdir()
    shutil.copyfile(SCRIPT, root / "scripts" / SCRIPT.name)
    tools = root / "scripts/release-tools"
    tools.mkdir()
    for filename in ("towncrier.toml", "template.md", "uv.lock", "pyproject.toml"):
        shutil.copyfile(SCRIPT.parent / "release-tools" / filename, tools / filename)
    fragment(root, notes, "Draft instructions.\n")
    base = commit(root, "pending change")
    git(root, "update-ref", "refs/remotes/origin/main", base)
    (root / "scripts" / SCRIPT.name).write_text("raise SystemExit('candidate code was executed')\n")
    (tools / "template.md").write_text("Candidate template was executed.\n")
    (tools / "uv.lock").write_text("invalid-lock\n")
    write_manifest(root, "0.2.2", "0.1.1")
    raw_section(root, ".", "0.2.1", "0.2.2", "v")
    head = commit(root, "release proposal")
    marker = f"<!-- release-note: {notes} -->\n\n"
    comments = [
        {"id": 1, "user": {"login": "editor"}, "body": marker + "Approved wording."},
        {"id": 2, "user": {"login": "visitor"}, "body": marker + "Unapproved wording."},
    ]
    (scratch / "comments.json").write_text(json.dumps([[comments[0]], [comments[1]]]))
    gh = scratch / "gh"
    gh.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys\n"
        "if sys.argv[1:3] == ['pr', 'view']:\n"
        " print(json.dumps(dict(state='OPEN', number=7, isCrossRepository=False, baseRefName='main',"
        " headRefOid=os.environ['MOCK_HEAD'])))\n"
        "elif '--paginate' in sys.argv: print(pathlib.Path(os.environ['RUNNER_TEMP'],'comments.json').read_text())\n"
        "elif sys.argv[2].endswith('/editor/permission'): print('write')\n"
        "elif sys.argv[2].endswith('/visitor/permission'): print('read')\n"
        "else: sys.exit(2)\n"
    )
    gh.chmod(0o755)
    workflow = yaml.safe_load((SCRIPT.parents[1] / ".github/workflows/release-please.yml").read_text())
    steps = workflow["jobs"]["sync-release-metadata"]["steps"]
    shell = next(step["run"] for step in steps if step.get("name") == "Assemble reviewed package notes")
    env = {
        **os.environ,
        "PATH": str(scratch) + os.pathsep + os.environ["PATH"],
        "GITHUB_REPOSITORY": "example/modelaudit",
        "PR_BRANCH": "release-please--branches--main",
        "RUNNER_TEMP": str(scratch),
        "MOCK_HEAD": head,
    }
    subprocess.run(["bash", "-c", shell], cwd=root, env=env, check=True, capture_output=True)
    public = run(root, "extract", "--package", "modelaudit", "--version", "0.2.2").stdout
    assert "Approved wording." in public
    assert "Candidate template" not in public
    assert "Unapproved wording." not in public
    assert "Draft instructions." not in public


def test_multiline_upgrade_note_keeps_reference_outside_the_code_block(repository: Path) -> None:
    fragment(repository, "changes/42.upgrade.md", "Scan locally.\n\n```sh\nmodelaudit scan ./model\n```\n")
    base = commit(repository, "document an upgrade command")
    expected = (
        "- Scan locally.\n\n  ```sh\n  modelaudit scan ./model\n  ```\n\n"
        "  [#42](https://github.com/promptfoo/modelaudit/issues/42)"
    )
    preview = run(repository, "pending", "--package", "modelaudit").stdout
    assert expected in preview

    write_manifest(repository, "0.2.2", "0.1.1")
    raw_section(repository, ".", "0.2.1", "0.2.2", "v")
    run(repository, "render", "--base", base)
    run(repository, "render", "--base", base)
    ref = commit(repository, "render release notes")
    public = run(repository, "extract", "--package", "modelaudit", "--version", "0.2.2", "--ref", ref).stdout
    assert public.count(expected) == 1


def test_reviewed_entry_count_preserves_grouping_and_catches_dropped_notes(repository: Path) -> None:
    fragments = {
        "80.other.md": "Shared note.",
        "81.other.md": "Shared note.",
        "80.other.1.md": "Second note for the same issue.",
        "+one.upgrade.md": "Unnumbered instructions.",
        "+two.upgrade.md": "Separate orphan note.",
        "+multi.upgrade.md": "Run these steps.\n\n- nested list\n\n```text\n- example line\n```",
    }
    for name, body in fragments.items():
        fragment(repository, f"changes/{name}", body)
    base = commit(repository, "add duplicate, numbered and unnumbered entries")
    write_manifest(repository, "0.2.2", "0.1.1")
    raw_section(repository, ".", "0.2.1", "0.2.2", "v")
    run(repository, "render", "--base", base)
    changelog = repository / "CHANGELOG.md"
    original = changelog.read_text()
    assert original.count("- Shared note.") == 1
    assert "<!-- release-note-entries: 5 -->" in original
    run(repository, "check", "--base", base)

    for missing in ("- Second note for the same issue.", "- Separate orphan note."):
        changelog.write_text("\n".join(line for line in original.split("\n") if not line.startswith(missing)))
        result = run(repository, "check", "--base", base, check=False)
        assert result.returncode != 0 and "reviewed entry count" in result.stderr

    # Reviewers can intentionally give two fragments the same wording. Towncrier
    # consolidates the resulting entry even though the source texts differ.
    changelog.write_text(original)
    reviews = repository.parent / f"{repository.name}-merged-entries.json"
    reviews.write_text(
        json.dumps([{"body": "<!-- release-note: changes/+two.upgrade.md -->\nUnnumbered instructions."}])
    )
    run(repository, "render", "--base", base, "--reviews", str(reviews))
    approved = changelog.read_text()
    assert "<!-- release-note-entries: 4 -->" in approved
    assert approved.count("- Unnumbered instructions.") == 1
    run(repository, "check", "--base", base)
