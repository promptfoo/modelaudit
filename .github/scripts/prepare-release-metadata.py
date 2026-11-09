"""Prepare a protected release base for the lock generators and changelog renderer."""

import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

SIBLING = "packages/modelaudit-picklescan"
MANIFEST = ".release-please-manifest.json"
VERSION = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}")


def release_file(head: str, path: str) -> bytes:
    mode = subprocess.check_output(["git", "ls-tree", "--format=%(objectmode)", head, "--", path]).strip()
    if mode != b"100644":
        raise ValueError(f"Expected a regular release file at {path}")
    return subprocess.check_output(["git", "cat-file", "blob", f"{head}:{path}"])


def align_sibling_requirement(project: bytes, version: str) -> bytes:
    """Permit a release PR to raise the root dependency floor to the released sibling."""
    dependencies = tomllib.loads(project.decode())["project"].get("dependencies", [])
    for dependency in dependencies:
        bounds = re.fullmatch(r"modelaudit-picklescan>=([0-9.]+),<([0-9.]+)", dependency)
        if bounds:
            floor, ceiling = bounds.groups()
            released = tuple(map(int, version.split(".")))
            if released < tuple(map(int, floor.split("."))):
                break
            if released >= tuple(map(int, ceiling.split("."))):
                major, minor, _ = released
                ceiling = f"{major + 1}.0.0" if major else f"0.{minor + 1}.0"
            new = f"modelaudit-picklescan>={version},<{ceiling}"
            return project.replace(f'"{dependency}"'.encode(), f'"{new}"'.encode(), 1)
    return project


def prepare(base: str, head: str) -> None:
    # Only the merge base with protected main supplies tools, config, fragments and dependency locks.
    subprocess.run(["git", "switch", "--detach", base], check=True)
    if subprocess.run(["git", "diff", "--quiet", base, head, "--", "changes", f"{SIBLING}/changes"]).returncode:
        raise ValueError("Release candidate fragments differ from main; merge fragment edits on main first")

    candidate = release_file(head, MANIFEST)
    current = json.loads(candidate)
    previous = json.loads(Path(MANIFEST).read_bytes())
    projects = {".": ["pyproject.toml"], SIBLING: [f"{SIBLING}/pyproject.toml", f"{SIBLING}/Cargo.toml"]}
    if not isinstance(current, dict) or current.keys() != projects.keys():
        raise ValueError("Unexpected packages in the release manifest")
    if not all(isinstance(version, str) and VERSION.fullmatch(version) for version in current.values()):
        raise ValueError("Invalid release version")
    for package, paths in projects.items():
        version = current[package]
        for path in paths:
            original = release_file(base, path)
            table = "package" if path.endswith("/Cargo.toml") else "project"
            protected_version = tomllib.loads(original.decode())[table]["version"]
            # Main can already carry a future version for a component outside this release.
            target_version = protected_version if previous.get(package) == version else version
            before = f'version = "{protected_version}"'.encode()
            after = f'version = "{target_version}"'.encode()
            contents, count = re.subn(rb"^" + re.escape(before) + rb"(?=[ \t]*(?:#|\r?$))", after, original, flags=re.M)
            proposed = release_file(head, path)
            if path == "pyproject.toml" and proposed != contents:
                contents = align_sibling_requirement(contents, current[SIBLING])
            if count != 1 or proposed != contents:
                raise ValueError(f"Unexpected release configuration change in {path}")
            Path(path).write_bytes(contents)
        changelog = (Path(package) / "CHANGELOG.md").as_posix()
        Path(changelog).write_bytes(release_file(head, changelog))
    Path(MANIFEST).write_bytes(candidate)


if __name__ == "__main__":
    prepare(*sys.argv[1:])
