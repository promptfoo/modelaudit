"""Compare a release candidate's component notes with the changes currently on its target branch."""

from __future__ import annotations

import argparse
import re

from release_notes import PACKAGES, REPOSITORY_URL, base_versions, git, release_section

# Match the release-producing Conventional Commit types, explicit breaking changes and
# security-tagged changes (including Renovate's "chore(deps): ... [security]").
RELEASE_CHANGE = re.compile(
    r"^(?:(?:feat|feature|fix|perf|revert|security)(?:\([^()\n]+\))?!?|\w+(?:\([^()\n]+\))?!|\w+\(security\)):\s+\S"
    r"|^BREAKING[ -]CHANGE:\s+\S",
    re.MULTILINE | re.IGNORECASE,
)
LIMIT = 12


def references(section: str) -> tuple[set[str], set[str]]:
    # Remove hidden source metadata. For Markdown links, the destination identifies
    # the repository, regardless of the number or SHA shown in the label.
    text = re.sub(r"<!--[\s\S]*?(?:-->|$)", "", section)
    text = re.sub(r"\[[^\]\n]*\]\(([^()\s]+)\)", r"\1", text)
    shas: set[str] = set()
    pulls: set[str] = set()
    for url in re.findall(r"https?://[^\s)\]>]+", text):
        path = url.rstrip(".,;").removeprefix(REPOSITORY_URL + "/")
        match = re.fullmatch(r"(?:pull|issues)/([1-9]\d*)/?(?:[?#].*)?", path)
        if match:
            pulls.add(match[1])
        match = re.fullmatch(r"commit/([a-f0-9]{7,40})/?(?:[?#].*)?", path)
        if match:
            shas.add(match[1])
    plain = re.sub(r"https?://[^\s)\]>]+", " ", text)
    pulls.update(re.findall(r"(?<![\w./-])#([1-9]\d*)\b", plain))
    shas.update(re.findall(r"(?<![\w@/])\b[a-f0-9]{7,40}\b", plain))
    return shas, pulls


def report(base: str, head: str) -> str:
    base, head = (git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip() for ref in (base, head))
    # The merge base tells us which packages the PR bumped. Scan through current
    # protected main so changes that landed since the last bot refresh remain visible.
    previous = base_versions(git("merge-base", base, head).strip())
    current = base_versions(head)
    sections = []
    for package, (path, prefix) in PACKAGES.items():
        version = current[path]
        if previous[path] == version:
            continue
        tag = prefix + previous[path]
        boundary = git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}").strip()
        git("merge-base", "--is-ancestor", boundary, base)
        shas, pulls = references(release_section(package, version, head))
        # Sibling-only changes belong to PickleScan. A commit changing both package
        # trees is independently checked against each component's notes.
        paths = [path] if path != "." else [".", *(f":(exclude){p}" for p, _ in PACKAGES.values() if p != ".")]
        fields = git(
            "log", "--full-history", "--topo-order", "-z", "--format=%H%x00%B", f"{boundary}..{base}", "--", *paths
        )
        messages = iter(fields.split("\0")[:-1])
        commits = list(zip(messages, messages, strict=True))
        in_range = {sha for sha, _ in commits}
        reverted: set[str] = set()
        missing = []
        for sha, message in commits:
            if sha in reverted:
                continue
            subject = message.partition("\n")[0]
            is_revert = re.match(r'^(?:revert(?:\([^()]+\))?!?:\s|(?:Revert|Reapply) ")', subject, re.I)
            target = re.search(r"^This reverts commit ([a-f0-9]{40})\b", message, re.M) if is_revert else None
            if target and target[1] in in_range:
                # Newest first: an active revert cancels its target, a reverted revert restores it.
                reverted.add(target[1])
                continue
            if not (is_revert or RELEASE_CHANGE.search(message) or "[security]" in subject.lower()):
                continue
            pull = re.search(r"\(#(\d+)\)$|^Merge pull request #(\d+)\b", subject)
            number = next((n for n in pull.groups() if n), None) if pull else None
            if number in pulls or any(sha.startswith(abbrev) for abbrev in shas):
                continue
            title = "".join(c if c.isprintable() else " " for c in subject)[:160]
            # A code span safely displays untrusted titles containing Markdown, HTML or @mentions.
            fence = "`" * (1 + max((len(run) for run in re.findall(r"`+", title)), default=0))
            missing.append(f"- {fence} {title} {fence} ([{sha[:8]}]({REPOSITORY_URL}/commit/{sha}))")
        if missing:
            count = len(missing)
            compare = f"{REPOSITORY_URL}/compare/{tag}...{base}"
            sections.append(
                f"### {package} {version}\n\n{count} {'change has' if count == 1 else 'changes have'} "
                f"no matching PR or commit reference in the versioned notes. [Compare all changes]({compare})\n\n"
                + "\n".join(missing[:LIMIT])
                + (f"\n\nShowing {LIMIT} of {count}." if count > LIMIT else "")
            )
    return "\n\n## Release note coverage\n\n" + "\n\n".join(sections) if sections else ""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", help="current target branch commit")
    parser.add_argument("head", help="candidate changelog commit")
    args = parser.parse_args()
    result = report(args.base, args.head)
    if result:
        print(result)
