"""Report the existing PyPI workflow's final results on the PR for each release tag."""

import json
import os
import re
import subprocess
import sys
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


def reports(needs: dict[str, Any], run_url: str) -> Iterator[tuple[str, str]]:
    release = needs["release-please"]["outputs"]
    for package, prefix, tag_prefix, jobs in PACKAGES:
        recovery = not prefix and release.get("root_provenance_recovery") == "true"
        if not recovery and release.get(f"{prefix}release_created") != "true":
            continue
        version, tag = release[f"{prefix}version"], release[f"{prefix}tag_name"]
        if not re.fullmatch(r"(0|[1-9]\d*)(\.(0|[1-9]\d*)){2}", version) or tag != tag_prefix + version:
            raise ValueError(f"Version and release tag disagree for {package}")
        if recovery:
            # Preserve the original upload and install results when only provenance is retried.
            kind = "release-provenance-recovery"
            details = f"Provenance recovery — **{needs['root-provenance-recovery']['result']}**"
        else:
            kind = "release-publication"
            values = " | ".join(needs[job]["result"] for job in jobs)
            details = (
                f"| Build | PyPI upload | Install from PyPI | Provenance |\n| --- | --- | --- | --- |\n| {values} |"
            )
        project = f"https://pypi.org/project/{package}/{version}/"
        url = f"{run_url.partition('/actions/runs/')[0]}/releases/tag/{tag}"
        body = f"<!-- {kind}: {package}@{version} -->\n### {package} {version}\n\n{details}\n\n"
        yield tag, body + f"[GitHub release]({url}) · [PyPI]({project}) · [Release workflow]({run_url})"


def github(path: str, *args: str, body: str | None = None) -> str:
    if body is not None:
        args = (*args, "-F", "body=@-", "--silent")
    return subprocess.check_output(["gh", "api", path, *args], input=body, text=True)


def items(path: str) -> Iterator[dict[str, Any]]:
    return map(json.loads, github(path + "?per_page=100", "--paginate", "--jq", ".[] | @json").splitlines())


def release_pr(repo: str, tag: str) -> int | None:
    # A manual retry can run from a later main commit. Follow the immutable tag.
    sha = github(f"repos/{repo}/commits/{tag}", "--jq", ".sha").strip()
    for pr in items(f"repos/{repo}/commits/{sha}/pulls"):
        if (
            pr["merged_at"]
            and pr["merge_commit_sha"] == sha
            and pr["base"]["ref"] == "main"
            and pr["head"]["ref"] == "release-please--branches--main"
            and (pr["head"]["repo"] or {}).get("full_name") == repo
        ):
            return int(pr["number"])
    return None


def update_comment(repo: str, number: int, body: str) -> None:
    marker = body.partition("\n")[0] + "\n"
    endpoint = f"repos/{repo}/issues/{number}/comments"
    for comment in items(endpoint):
        if (comment.get("user") or {}).get("login") == "github-actions[bot]" and comment["body"].startswith(marker):
            if comment["body"] != body:
                github(f"repos/{repo}/issues/comments/{comment['id']}", "-X", "PATCH", body=body)
            return
    github(endpoint, "-X", "POST", body=body)


if __name__ == "__main__":
    repo = os.environ["GITHUB_REPOSITORY"]
    if sys.argv[1:]:
        command, number, file = sys.argv[1:]
        preview = Path(file).read_text(encoding="utf-8")
        if command != "preview-comment" or not preview.startswith("<!-- modelaudit-release-notes-preview -->\n"):
            raise ValueError("Expected a marked release notes preview")
        update_comment(repo, int(number), preview)
    else:
        run = f"{os.environ['GITHUB_SERVER_URL']}/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        url = f"{run}/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}"
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
            for tag, report in reports(json.loads(os.environ["RELEASE_JOBS"]), url):
                print(report, file=summary)
                if pr := release_pr(repo, tag):
                    update_comment(repo, pr, report)
                else:
                    print(f"::notice::No merged release PR for {tag}.")
