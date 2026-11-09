"""Build package release notes from reviewed Markdown fragments using the local Git history."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PACKAGES = {
    "modelaudit": (".", "v"),
    "modelaudit-picklescan": ("packages/modelaudit-picklescan", "modelaudit-picklescan-v"),
}
TOOLS = Path(__file__).resolve().with_name("release-tools")
REPOSITORY_URL = "https://github.com/promptfoo/modelaudit"
RELEASE = re.compile(r"^## \[(Unreleased|\d+\.\d+\.\d+)\][^\n]*$", re.MULTILINE)
INVENTORY = "<details>\n<summary>All changes</summary>"
SOURCE_MARKER = "<!-- release-note-source:"


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], encoding="utf-8")


def versioned_sections(text: str, only: str | None = None) -> dict[str, str]:
    headers = list(RELEASE.finditer(text))
    sections = {}
    for index, header in enumerate(headers):
        version = header[1]
        if only is not None and version != only:
            continue
        if version in sections:
            raise ValueError(f"Duplicate changelog section {version}")
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        sections[version] = text[header.start() : end].rstrip() + "\n"
    return sections


def unreleased_section(package: str, tag: str) -> str:
    comparison = f"{REPOSITORY_URL}/compare/{tag}...main"
    return (
        f"## [Unreleased]\n\n[Commits since the latest release]({comparison}). "
        f"To preview pending [release note fragments](changes/), run `python scripts/release_notes.py pending "
        f"--package {package}` from the repository root.\n"
    )


def validate_unreleased(sections: dict[str, str], package: str, tag: str) -> None:
    path, _ = PACKAGES[package]
    expected = unreleased_section(package, tag).split()
    if next(iter(sections), None) != "Unreleased" or sections["Unreleased"].split() != expected:
        raise ValueError(
            f"{path}/CHANGELOG.md: restore the generated Unreleased introduction as the first section; "
            f"put pending release notes in {path}/changes/"
        )


def review_overrides(file: Path | None) -> dict[str, str]:
    if file is None:
        return {}
    overrides = {}
    comments = sorted(
        json.loads(file.read_text(encoding="utf-8")), key=lambda x: (x.get("updated_at", ""), x.get("id", 0))
    )
    for comment in comments:
        first, _, rest = comment["body"].replace("\r\n", "\n").partition("\n")
        marker = re.fullmatch(r"<!-- release-note: (\S+) -->", first)
        if marker:
            overrides[marker[1]] = rest
    return overrides


def default_base() -> str:
    # An uncommitted version bump still uses HEAD's published versions. On the
    # rolling release branch, the bump is committed but its tags do not exist yet.
    if git("branch", "--show-current").strip() == "release-please--branches--main":
        return git("merge-base", "HEAD", "refs/remotes/origin/main").strip()
    return "HEAD"


def base_versions(base: str) -> dict[str, str]:
    versions: dict[str, str] = json.loads(git("show", f"{base}:.release-please-manifest.json"))
    return versions


def reviewed_source(section: str, ancestor: str) -> str | None:
    body = section.partition("\n")[2].strip()
    markers = [line for line in body.splitlines() if line.startswith("<!-- release-note-source")]
    if not markers:
        return None  # Releases generated before source commits were recorded.
    match = re.fullmatch(r"<!-- release-note-source: ([0-9a-f]{40}|[0-9a-f]{64}) -->", markers[0])
    if len(markers) != 1 or body.splitlines()[0] != markers[0] or not match:
        raise ValueError("Invalid release-note-source marker immediately below the version heading")
    source = match[1]
    if (
        subprocess.run(["git", "merge-base", "--is-ancestor", source, ancestor]).returncode
        or git("cat-file", "-t", source).strip() != "commit"
    ):
        raise ValueError(
            f"Release note source {source} must be a commit in {ancestor}'s history; fetch the full history"
        )
    return source


def fragment_tree(folder: Path, ref: str) -> set[Path]:
    names = git("ls-tree", "-r", "--name-only", "-z", ref, "--", folder.as_posix())
    return {Path(name) for name in names.split("\0") if name}


def changed_fragments(folder: Path, *revisions: str) -> set[Path]:
    names = git("diff", "--no-renames", "--name-only", "-z", *revisions, "--", folder.as_posix())
    return {Path(name) for name in names.split("\0") if name}


def shipped_fragments(folder: Path, prefix: str, version: str) -> set[Path]:
    tag = prefix + version
    ref = f"refs/tags/{tag}"
    if subprocess.run(["git", "show-ref", "--verify", "--quiet", ref]).returncode:
        raise ValueError(f"Missing release boundary {tag}. Fetch it with 'git fetch origin tag {tag}'.")
    shipped = fragment_tree(folder, ref)
    file = f"{ref}:{(folder.parent / 'CHANGELOG.md').as_posix()}"
    if subprocess.run(["git", "cat-file", "-e", file], stderr=subprocess.DEVNULL).returncode == 0:
        section = versioned_sections(git("show", file), only=version).get(version, "")
        source = reviewed_source(section, ref)
        if source:
            # A squash can include new or revised fragments merged after review.
            shipped -= changed_fragments(folder, source, ref)
    reused = shipped & changed_fragments(folder, ref)
    if reused:
        raise ValueError(f"{min(reused)}: this release note has shipped; use a new fragment filename")
    return shipped


def pending_fragments(folder: Path, shipped: set[Path]) -> list[Path]:
    if folder.is_symlink():
        raise ValueError(f"{folder}: expected a package-local directory of release notes")
    paths = sorted(folder.glob("*"))
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.suffix != ".md" or len(path.suffixes) < 2:
            raise ValueError(f"{path}: expected a Towncrier Markdown fragment such as 123.upgrade.md")
    return [path for path in paths if path not in shipped]


def towncrier_summary(paths: list[Path], version: str, reviews: dict[str, str]) -> str:
    if not paths:
        return ""
    # Stage only this component's pending fragments. Review comments replace prose,
    # while the protected tool directory supplies the configuration and template.
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        changes = stage / "changes"
        changes.mkdir()
        for filename in ("towncrier.toml", "template.md"):
            shutil.copyfile(TOOLS / filename, stage / filename)
        for path in paths:
            body = reviews.get(path.as_posix())
            if body is None:
                body = path.read_text(encoding="utf-8")
            if not body.strip():
                raise ValueError(f"{path}: empty release note")
            (changes / path.name).write_text(body, encoding="utf-8", newline="\n")
        result = subprocess.run(
            [
                "uv",
                "run",
                "--frozen",
                "--no-dev",
                "--project",
                str(TOOLS),
                "towncrier",
                "build",
                "--draft",
                "--config",
                "towncrier.toml",
                "--version",
                version,
            ],
            cwd=stage,
            capture_output=True,
            encoding="utf-8",
        )
        if result.returncode:
            raise ValueError(f"Towncrier could not render {paths[0].parent}: {result.stderr.strip()}")
        return result.stdout.strip()


def candidate_inventory(
    sections: dict[str, str], changelog: Path, prefix: str, before: str, after: str
) -> tuple[str, str]:
    heading, _, body = sections[after].partition("\n")
    comparison = f"{REPOSITORY_URL}/compare/{prefix}{before}...{prefix}{after}"
    if not heading.startswith(f"## [{after}]({comparison})"):
        raise ValueError(f"{changelog}: expected release comparison {comparison}")
    link = f"[Full comparison]({comparison})"
    _, disclosure, inventory = body.partition(INVENTORY)
    if disclosure:
        if INVENTORY in inventory:
            raise ValueError(f"{changelog}: multiple All changes disclosures; restore the generated inventory")
        inventory = inventory.rstrip()
        if not inventory.endswith("</details>"):
            raise ValueError(f"{changelog}: incomplete All changes disclosure")
        inventory = inventory.removesuffix("</details>").strip()
        if link not in inventory.splitlines():
            raise ValueError(f"{changelog}: missing Full comparison link in All changes")
    elif next(iter(sections)) != after or body.lstrip().startswith(SOURCE_MARKER):
        # Only Release Please's newly prepended version can contain a raw inventory.
        raise ValueError(
            f"{changelog}: missing All changes disclosure; restore the generated inventory before retrying"
        )
    else:
        inventory = body.strip() + "\n\n" + link
    return heading, inventory


def entry_count_marker(summary: str) -> str:
    # Towncrier groups identical reviewed prose and indents all continuation lines.
    entries = sum(line.startswith("- ") for line in summary.splitlines())
    return f"<!-- release-note-entries: {entries} -->"


def check_candidate(
    changelog: Path, sections: dict[str, str], prefix: str, before: str, after: str, paths: list[Path], summary: str
) -> None:
    candidate_inventory(sections, changelog, prefix, before, after)
    # Review comments can replace the prose. The categories and numbered references
    # still come from the fragment filenames and belong above the generated inventory.
    reviewed, _, _ = sections[after].partition(INVENTORY)
    reviewed_lines = set(reviewed.splitlines())
    for line in summary.splitlines():
        if line.startswith(("### ", "<summary>")) and line not in reviewed_lines:
            raise ValueError(f"{changelog}: missing reviewed category {line}")
    for path in paths:
        issue = path.name.partition(".")[0]
        if issue.isdecimal() and f"[#{issue}]({REPOSITORY_URL}/issues/{issue})" not in reviewed:
            raise ValueError(f"{changelog}: missing reviewed reference for {path}")
    markers = [line for line in reviewed.splitlines() if line.startswith("<!-- release-note-entries")]
    if markers != [entry_count_marker(reviewed)]:
        raise ValueError(f"{changelog}: reviewed entry count differs or is missing; refresh the release PR metadata")


def render(base: str, reviews: dict[str, str]) -> None:
    base = git("rev-parse", "--verify", f"{base}^{{commit}}").strip()
    previous = base_versions(base)
    current = json.loads(Path(".release-please-manifest.json").read_text())
    writes = {}
    for package, (path, prefix) in PACKAGES.items():
        before, after = previous[path], current[path]
        if before == after:
            continue
        changelog = Path(path) / "CHANGELOG.md"
        original = git("show", f"{base}:{changelog.as_posix()}")
        sections = versioned_sections(original)
        validate_unreleased(sections, package, prefix + before)
        if after in sections:
            raise ValueError(f"{changelog}: invalid changelog at release base")
        candidate = versioned_sections(changelog.read_text(encoding="utf-8"))
        if after not in candidate:
            raise ValueError(f"{changelog}: Release Please did not generate {after}")
        heading, inventory = candidate_inventory(candidate, changelog, prefix, before, after)
        folder = Path(path) / "changes"
        shipped = shipped_fragments(folder, prefix, before)
        paths = pending_fragments(folder, shipped)
        if set(paths) != fragment_tree(folder, base) - shipped or changed_fragments(folder, base):
            raise ValueError(
                f"{folder}: release candidate fragments differ from {base}; merge fragment edits on main first"
            )
        summary = towncrier_summary(paths, after, reviews)
        markers = f"{SOURCE_MARKER} {base} -->\n\n{entry_count_marker(summary)}"
        next_section = "\n\n".join(
            filter(None, [heading, markers, summary, f"{INVENTORY}\n\n{inventory}\n\n</details>"])
        )
        start = original.index(sections["Unreleased"])
        position = start + len(sections["Unreleased"])
        preamble = original[:start] + unreleased_section(package, prefix + after).rstrip()
        writes[changelog] = preamble + "\n\n" + next_section + "\n\n" + original[position:].lstrip("\n")
    for changelog, text in writes.items():
        changelog.write_text(text, encoding="utf-8", newline="\n")


def check(base: str) -> None:
    previous = base_versions(base)
    current = json.loads(Path(".release-please-manifest.json").read_text())
    for package, (path, prefix) in PACKAGES.items():
        before, after = previous[path], current[path]
        root = Path(path)
        changelog = root / "CHANGELOG.md"
        sections = versioned_sections(changelog.read_text(encoding="utf-8"))
        validate_unreleased(sections, package, prefix + after)
        folder = root / "changes"
        shipped = shipped_fragments(folder, prefix, before)
        paths = pending_fragments(folder, shipped)
        summary = towncrier_summary(paths, after, {})
        if before == after:
            continue
        if list(sections)[1:2] != [after]:
            raise ValueError(f"{changelog}: expected {after} immediately after Unreleased")
        section = sections[after]
        source = reviewed_source(section, base)
        if source is None:
            raise ValueError(f"{changelog}: missing release-note-source; refresh the release PR metadata")
        if base_versions(source)[path] != before:
            raise ValueError(f"{changelog}: source {source} does not belong to this release")
        reviewed_paths = sorted(fragment_tree(folder, source) - shipped)
        if reviewed_paths != paths:
            # Only the categories are needed here. Towncrier derives them from
            # the reviewed filenames, including those removed from the checkout.
            placeholders = {path.as_posix(): path.name for path in reviewed_paths}
            summary = towncrier_summary(reviewed_paths, after, placeholders)
        check_candidate(changelog, sections, prefix, before, after, reviewed_paths, summary)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="op", required=True)
    base_help = "use the package release boundaries from this Git ref's manifest"
    validate = sub.add_parser("check", help="validate changelogs and package-local fragments")
    validate.add_argument("--base", help=base_help)
    cmd = sub.add_parser("render", help="assemble the bumped components on a Release Please candidate")
    cmd.add_argument("--base", required=True)
    cmd.add_argument("--reviews", type=Path)
    for op, help_text in (
        ("extract", "print one package's versioned changelog section"),
        ("pending", "preview the package's fragments added since its last release"),
    ):
        cmd = sub.add_parser(op, help=help_text)
        cmd.add_argument("--package", choices=PACKAGES, required=True)
        if op == "extract":
            cmd.add_argument("--version", required=True)
            cmd.add_argument("--ref")
        else:
            cmd.add_argument("--base", help=base_help)
    args = parser.parse_args()
    if args.op == "render":
        render(args.base, review_overrides(args.reviews))
    elif args.op == "check":
        check(args.base or default_base())
    else:
        path, prefix = PACKAGES[args.package]
        if args.op == "pending":
            version = base_versions(args.base or default_base())[path]
            folder = Path(path) / "changes"
            paths = pending_fragments(folder, shipped_fragments(folder, prefix, version))
            print(towncrier_summary(paths, version, {}) or "No pending release notes.")
        else:
            file = Path(path) / "CHANGELOG.md"
            text = git("show", f"{args.ref}:{file.as_posix()}") if args.ref else file.read_text(encoding="utf-8")
            print(versioned_sections(text, only=args.version)[args.version], end="")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
