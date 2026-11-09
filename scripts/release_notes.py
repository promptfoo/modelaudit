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


def base_versions(base: str | None) -> dict[str, str]:
    # An uncommitted version bump still uses HEAD's published versions. On the
    # rolling release branch, the bump is committed but its tags do not exist yet.
    if base is None and git("branch", "--show-current").strip() == "release-please--branches--main":
        base = git("merge-base", "HEAD", "refs/remotes/origin/main").strip()
    versions: dict[str, str] = json.loads(git("show", f"{base or 'HEAD'}:.release-please-manifest.json"))
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
    return {
        Path(name)
        for name in git("ls-tree", "-r", "--name-only", "-z", ref, "--", folder.as_posix()).split("\0")
        if name
    }


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
            late = git("diff", "--no-renames", "--name-only", "-z", source, ref, "--", folder.as_posix())
            shipped.difference_update(Path(name) for name in late.split("\0") if name)
    changed = git("diff", "--no-renames", "--name-only", "-z", ref, "--", folder.as_posix())
    reused = sorted(shipped.intersection(Path(name) for name in changed.split("\0") if name))
    if reused:
        raise ValueError(f"{reused[0]}: this release note has shipped; use a new fragment filename")
    return shipped


def pending_fragments(folder: Path, shipped: set[Path]) -> list[Path]:
    if folder.is_symlink():
        raise ValueError(f"{folder}: expected a package-local directory of release notes")
    paths = sorted(folder.glob("*"))
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.suffix != ".md" or len(path.suffixes) < 2:
            raise ValueError(f"{path}: expected a Towncrier Markdown fragment such as 123.upgrade.md")
    return [path for path in paths if path not in shipped]


def towncrier_summary(paths: list[Path], version: str, reviews: dict[str, str], *, source: str | None = None) -> str:
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
                body = git("show", f"{source}:{path.as_posix()}") if source else path.read_text(encoding="utf-8")
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
    section: str, changelog: Path, prefix: str, before: str, after: str, *, require_reviewed: bool
) -> tuple[str, str]:
    heading, _, body = section.partition("\n")
    comparison = re.search(r"\]\((https://[^)]+)\)", heading)
    expected_range = f"/compare/{prefix}{before}...{prefix}{after}"
    if not comparison or not comparison[1].endswith(expected_range):
        raise ValueError(f"{changelog}: expected release comparison ending in {expected_range}")
    link = f"[Full comparison]({comparison[1]})"
    _, disclosure, inventory = body.rpartition(INVENTORY)
    if disclosure:
        inventory = inventory.rstrip()
        if not inventory.endswith("</details>"):
            raise ValueError(f"{changelog}: incomplete All changes disclosure")
        inventory = inventory.removesuffix("</details>").strip()
        if link not in inventory.splitlines():
            raise ValueError(f"{changelog}: missing Full comparison link in All changes")
    elif require_reviewed:
        raise ValueError(f"{changelog}: missing All changes disclosure; run the release metadata refresh")
    else:
        inventory = body.strip() + "\n\n" + link
    return heading, inventory


def check_candidate(
    changelog: Path, section: str, prefix: str, before: str, after: str, paths: list[Path], summary: str
) -> None:
    candidate_inventory(section, changelog, prefix, before, after, require_reviewed=True)
    # Review comments can replace the prose. The categories and numbered references
    # still come from the fragment filenames and belong above the generated inventory.
    reviewed, _, _ = section.rpartition(INVENTORY)
    reviewed_lines = set(reviewed.splitlines())
    for line in summary.splitlines():
        if line.startswith(("### ", "<summary>")) and line not in reviewed_lines:
            raise ValueError(f"{changelog}: missing reviewed category {line}")
    for path in paths:
        issue = path.name.partition(".")[0]
        if issue.isdecimal() and f"[#{issue}]({REPOSITORY_URL}/issues/{issue})" not in reviewed:
            raise ValueError(f"{changelog}: missing reviewed reference for {path}")


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
        candidate = versioned_sections(changelog.read_text(encoding="utf-8")).get(after)
        if not candidate:
            raise ValueError(f"{changelog}: Release Please did not generate {after}")
        heading, inventory = candidate_inventory(candidate, changelog, prefix, before, after, require_reviewed=False)
        folder = Path(path) / "changes"
        shipped = shipped_fragments(folder, prefix, before)
        paths = pending_fragments(folder, shipped)
        if set(paths) != fragment_tree(folder, base) - shipped or git(
            "diff", "--name-only", base, "--", folder.as_posix()
        ):
            raise ValueError(
                f"{folder}: release candidate fragments differ from {base}; merge fragment edits on main first"
            )
        summary = towncrier_summary(paths, after, reviews)
        marker = f"{SOURCE_MARKER} {base} -->"
        next_section = "\n\n".join(
            filter(None, [heading, marker, summary, f"{INVENTORY}\n\n{inventory}\n\n</details>"])
        )
        start = original.index(sections["Unreleased"])
        position = start + len(sections["Unreleased"])
        preamble = original[:start] + unreleased_section(package, prefix + after).rstrip()
        writes[changelog] = preamble + "\n\n" + next_section + "\n\n" + original[position:].lstrip("\n")
    for changelog, text in writes.items():
        changelog.write_text(text, encoding="utf-8", newline="\n")


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
        previous = base_versions(args.base)
        current = json.loads(Path(".release-please-manifest.json").read_text())
        for package, (path, prefix) in PACKAGES.items():
            root = Path(path)
            changelog = root / "CHANGELOG.md"
            sections = versioned_sections(changelog.read_text(encoding="utf-8"))
            validate_unreleased(sections, package, prefix + current[path])
            folder = root / "changes"
            shipped = shipped_fragments(folder, prefix, previous[path])
            paths = pending_fragments(folder, shipped)
            summary = towncrier_summary(paths, current[path], {})
            if current[path] != previous[path]:
                if list(sections)[1:2] != [current[path]]:
                    raise ValueError(f"{changelog}: expected {current[path]} immediately after Unreleased")
                section = sections[current[path]]
                source = reviewed_source(section, args.base or "HEAD")
                if source is None:
                    raise ValueError(f"{changelog}: missing release-note-source; refresh the release PR metadata")
                if base_versions(source)[path] != previous[path]:
                    raise ValueError(f"{changelog}: source {source} does not belong to this release")
                reviewed_paths = sorted(fragment_tree(folder, source) - shipped)
                if reviewed_paths != paths:
                    summary = towncrier_summary(reviewed_paths, current[path], {}, source=source)
                check_candidate(changelog, section, prefix, previous[path], current[path], reviewed_paths, summary)
    else:
        path, prefix = PACKAGES[args.package]
        if args.op == "pending":
            version = base_versions(args.base)[path]
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
