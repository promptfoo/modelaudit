"""Build package release notes from reviewed Markdown fragments using the local Git history."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

PACKAGES = {
    "modelaudit": (".", "v"),
    "modelaudit-picklescan": ("packages/modelaudit-picklescan", "modelaudit-picklescan-v"),
}
SECTIONS = ("Highlights", "Upgrade notes", "Security", "Other changes")
RELEASE = re.compile(r"^## \[(Unreleased|\d+\.\d+\.\d+)\][^\n]*$", re.MULTILINE)
SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\.md\Z")
INVENTORY = "<details>\n<summary>All changes</summary>"
SECONDARY = "<details>\n<summary>Other changes</summary>"


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], encoding="utf-8")


def versioned_sections(text: str) -> dict[str, str]:
    headers = list(RELEASE.finditer(text))
    sections = {}
    for index, header in enumerate(headers):
        version = header[1]
        if version in sections:
            raise ValueError(f"Duplicate changelog section {version}")
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        sections[version] = text[header.start() : end].rstrip() + "\n"
    return sections


def unreleased_section(package: str, tag: str) -> str:
    comparison = f"https://github.com/promptfoo/modelaudit/compare/{tag}...main"
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


def parse_note(text: str, path: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    section = None
    for line in text.strip().splitlines():
        if not line.strip():
            continue
        if line.startswith("### ") and line[4:] in SECTIONS:
            section = line[4:]
            if section in sections:
                raise ValueError(f"{path}: duplicate {section}")
            sections[section] = []
        elif section is not None and line.startswith("- ") and line[2:].strip():
            sections[section].append(line)
        elif section is not None and sections[section] and line.startswith("  "):
            sections[section][-1] += "\n" + line
        else:
            raise ValueError(f"{path}: expected a section ({', '.join(SECTIONS)}) followed by Markdown bullets")
    if not sections or not all(sections.values()):
        raise ValueError(f"{path}: empty release note")
    return sections


def fragments(folder: Path) -> list[Path]:
    if folder.is_symlink():
        raise ValueError(f"{folder}: expected a package-local directory of release notes")
    paths = sorted(folder.glob("*"))
    for path in paths:
        if not SLUG.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            raise ValueError(f"Expected a Markdown fragment with a unique lowercase slug at {path}")
    return paths


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


def collect(folder: Path, tag: str, reviews: dict[str, str]) -> dict[str, list[str]]:
    ref = f"refs/tags/{tag}"
    if subprocess.run(["git", "show-ref", "--verify", "--quiet", ref]).returncode != 0:
        raise ValueError(f"Missing release boundary {tag}. Fetch it with 'git fetch origin tag {tag}'.")
    tagged = set(git("ls-tree", "-r", "--name-only", "-z", ref, "--", folder.as_posix()).split("\0"))
    changed = git("diff", "--no-renames", "--name-only", "-z", ref, "--", folder.as_posix()).split("\0")
    reused = sorted(tagged.intersection(changed) - {""})
    if reused:
        raise ValueError(f"{reused[0]}: this release note has shipped; use a new fragment filename")
    summary: dict[str, list[str]] = defaultdict(list)
    for path in fragments(folder):
        name = path.as_posix()
        if name in tagged:
            continue
        note = parse_note(reviews.get(name, path.read_text(encoding="utf-8")), name)
        for group, bullets in note.items():
            summary[group].extend(bullets)
    return summary


def markdown(summary: dict[str, list[str]]) -> str:
    out = []
    for title in SECTIONS:
        if lines := summary.get(title):
            bullets = "\n".join(lines)
            if title == "Other changes":
                out.append(f"{SECONDARY}\n\n{bullets}\n\n</details>")
            else:
                out.append(f"### {title}\n\n{bullets}")
    return "\n\n".join(out)


def render(base: str, reviews: dict[str, str]) -> None:
    previous = json.loads(git("show", f"{base}:.release-please-manifest.json"))
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
        heading, _, inventory = candidate.partition("\n")
        match = re.search(r"\]\((https://[^)]+)\)", heading)
        expected_range = f"/compare/{prefix}{before}...{prefix}{after}"
        if not match or not match[1].endswith(expected_range):
            raise ValueError(f"{changelog}: expected release comparison ending in {expected_range}")
        if INVENTORY in inventory:
            _, _, generated = inventory.rpartition(INVENTORY)
            if not generated.rstrip().endswith("</details>"):
                raise ValueError(f"{changelog}: incomplete All changes disclosure")
            inventory = generated.rstrip().removesuffix("</details>").strip()
        else:
            inventory = inventory.strip() + "\n\n" + f"[Full comparison]({match[1]})"
        summary = collect(Path(path) / "changes", prefix + before, reviews)
        next_section = "\n\n".join(
            filter(None, [heading, markdown(summary), f"{INVENTORY}\n\n{inventory}\n\n</details>"])
        )
        start = original.index(sections["Unreleased"])
        position = start + len(sections["Unreleased"])
        preamble = original[:start] + unreleased_section(package, prefix + after).rstrip()
        writes[changelog] = preamble + "\n\n" + next_section + "\n\n" + original[position:].lstrip("\n")
    for changelog, text in writes.items():
        changelog.write_text(text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="op", required=True)
    validate = sub.add_parser("check", help="validate changelogs and package-local fragments")
    validate.add_argument("--base", help="also check previously shipped filenames against the base manifest's tags")
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
    args = parser.parse_args()
    if args.op == "render":
        render(args.base, review_overrides(args.reviews))
    elif args.op == "check":
        previous = json.loads(git("show", f"{args.base}:.release-please-manifest.json")) if args.base else {}
        current = json.loads(Path(".release-please-manifest.json").read_text())
        for package, (path, prefix) in PACKAGES.items():
            root = Path(path)
            sections = versioned_sections((root / "CHANGELOG.md").read_text(encoding="utf-8"))
            validate_unreleased(sections, package, prefix + current[path])
            if args.base:
                collect(root / "changes", prefix + previous[path], {})
            else:
                for fragment in fragments(root / "changes"):
                    parse_note(fragment.read_text(encoding="utf-8"), fragment.as_posix())
    else:
        path, prefix = PACKAGES[args.package]
        if args.op == "pending":
            version = json.loads(Path(".release-please-manifest.json").read_text())[path]
            print(markdown(collect(Path(path) / "changes", prefix + version, {})) or "No pending release notes.")
        else:
            file = Path(path) / "CHANGELOG.md"
            text = git("show", f"{args.ref}:{file.as_posix()}") if args.ref else file.read_text(encoding="utf-8")
            print(versioned_sections(text)[args.version], end="")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
