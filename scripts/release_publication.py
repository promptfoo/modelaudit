"""Report the existing PyPI workflow's results on the PR that introduced each tag."""

import json
import os
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

PACKAGES = (
    ("modelaudit", "", "v", ("build", "publish-pypi", "verify-pypi", "provenance")),
    (
        "modelaudit-picklescan",
        "picklescan_",
        "modelaudit-picklescan-v",
        ("build-picklescan-package", "publish-picklescan-pypi", "verify-picklescan-pypi", "picklescan-provenance"),
    ),
)


def reports(needs: dict[str, Any], run_url: str) -> Iterator[tuple[str, str, str]]:
    release = needs["release-please"]["outputs"]
    for package, prefix, tag_prefix, jobs in PACKAGES:
        recovery = not prefix and release.get("root_provenance_recovery") == "true"
        if release.get(f"{prefix}release_created") != "true" and not recovery:
            continue
        version = release[f"{prefix}version"]
        tag = release[f"{prefix}tag_name"]
        if not re.fullmatch(r"(0|[1-9]\d*)(\.(0|[1-9]\d*)){2}", version) or tag != f"{tag_prefix}{version}":
            raise ValueError(f"Version and release tag disagree for {package}")
        marker = f"<!-- release-publication: {package}@{version} -->"
        if recovery:
            # A provenance-only retry must not replace the original upload and install results.
            marker = f"<!-- release-provenance-recovery: {package}@{version} -->"
            status = needs.get("root-provenance-recovery", {}).get("result", "in progress")
            details = f"Provenance recovery — **{status}**"
        elif jobs[0] not in needs:
            details = "Publication started. The workflow attempt below shows its current result."
        else:
            results = [needs[job]["result"] for job in jobs]
            details = "| Build | PyPI upload | Install from PyPI | Provenance |\n| --- | --- | --- | --- |\n"
            details += "| " + " | ".join(results) + " |"
        project = f"https://pypi.org/project/{package}/{version}/"
        release_url = f"{run_url.split('/actions/runs/')[0]}/releases/tag/{tag}"
        links = f"[GitHub release]({release_url}) · [PyPI]({project}) · [Release workflow]({run_url})"
        body = f"{marker}\n### {package} {version}\n\n{details}\n\n{links}"
        yield tag, marker, body


def github(repo: str, path: str, *args: str) -> Any:
    raw = subprocess.check_output(["gh", "api", f"repos/{repo}/{path}", *args], text=True)
    return json.loads(raw) if raw else None


def pages(repo: str, path: str) -> Iterator[dict[str, Any]]:
    page = 1
    while True:
        items = github(repo, f"{path}?per_page=100&page={page}")
        yield from items
        if len(items) < 100:
            return
        page += 1


def update(repo: str, tag: str, marker: str, body: str) -> None:
    # Backfills can run from a much later main commit. Always resolve the version tag.
    sha = github(repo, f"commits/{tag}")["sha"]
    pr = next(
        (
            item
            for item in pages(repo, f"commits/{sha}/pulls")
            if item["merged_at"]
            and item["merge_commit_sha"] == sha
            and item["base"]["ref"] == "main"
            and item["head"]["ref"] == "release-please--branches--main"
            and (item["head"]["repo"] or {}).get("full_name") == repo
        ),
        None,
    )
    if pr is None:
        print(f"::notice::No merged release PR for {tag} at {sha}.")
        return
    comments = f"issues/{pr['number']}/comments"
    existing = next(
        (
            item
            for item in pages(repo, comments)
            if (item.get("user") or {}).get("login") == "github-actions[bot]"
            and (item["body"] or "").startswith(marker + "\n")
        ),
        None,
    )
    if existing is None:
        github(repo, comments, "-X", "POST", "-f", f"body={body}", "--silent")
    elif existing["body"] != body:
        github(repo, f"issues/comments/{existing['id']}", "-X", "PATCH", "-f", f"body={body}", "--silent")


if __name__ == "__main__":
    repository = os.environ["GITHUB_REPOSITORY"]
    run = os.environ["GITHUB_RUN_ID"]
    attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    url = f"{os.environ['GITHUB_SERVER_URL']}/{repository}/actions/runs/{run}/attempts/{attempt}"
    for release_tag, comment_marker, report in reports(json.loads(os.environ["RELEASE_JOBS"]), url):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
            print(report, file=summary)
        update(repository, release_tag, comment_marker, report)
