from __future__ import annotations

import re
import sys

_MAX_DOCKER_TAG_LENGTH = 128
_PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_VERSION_TAG_RE = re.compile(
    r"^v?"
    r"(0|[1-9][0-9]*)"
    r"\.(0|[1-9][0-9]*)"
    r"\.(0|[1-9][0-9]*)"
    rf"(?:-{_PRERELEASE_IDENTIFIER}(?:\.{_PRERELEASE_IDENTIFIER})*)?"
    r"$"
)


def normalize_publish_tag(tag: str) -> str | None:
    if tag != tag.strip():
        return None
    normalized_tag = tag.removeprefix("v")
    if not tag or len(normalized_tag) > _MAX_DOCKER_TAG_LENGTH:
        return None
    if _VERSION_TAG_RE.fullmatch(tag) is None:
        return None
    return normalized_tag


def is_allowed_publish_tag(tag: str) -> bool:
    return normalize_publish_tag(tag) is not None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate_docker_publish_tag.py <tag>", file=sys.stderr)
        return 2

    tag = argv[1]
    normalized_tag = normalize_publish_tag(tag)
    if normalized_tag is not None:
        print(normalized_tag)
        return 0

    print(
        "Manual Docker publishes only accept immutable version tags like 0.2.26, v0.2.26, or 0.2.26-rc.1.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
