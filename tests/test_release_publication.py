import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import release_publication as publication

RUN = "https://github.com/promptfoo/modelaudit/actions/runs/123/attempts/2"


def test_terminal_results_for_coordinated_release_and_provenance_recovery() -> None:
    outputs = {
        "release_created": "true",
        "version": "0.2.57",
        "tag_name": "v0.2.57",
        "picklescan_release_created": "true",
        "picklescan_version": "0.1.15",
        "picklescan_tag_name": "modelaudit-picklescan-v0.1.15",
    }
    needs: dict[str, Any] = {"release-please": {"outputs": outputs}}
    for _, _, _, jobs in publication.PACKAGES:
        needs.update({job: {"result": "success"} for job in jobs})
    needs["provenance"]["result"] = "failure"
    root, sibling = publication.reports(needs, RUN)
    assert "| success | success | success | failure |" in root[1]
    assert "| success | success | success | success |" in sibling[1]
    for tag, report in (root, sibling):
        assert RUN in report and f"/releases/tag/{tag}" in report
    assert "pypi.org/project/modelaudit/0.2.57/" in root[1]
    assert "pypi.org/project/modelaudit-picklescan/0.1.15/" in sibling[1]
    outputs["release_created"] = "false"
    assert list(publication.reports(needs, RUN)) == [sibling]
    outputs["picklescan_release_created"] = "false"
    assert not list(publication.reports(needs, RUN))
    outputs["root_provenance_recovery"] = "true"
    needs["root-provenance-recovery"] = {"result": "success"}
    (recovery,) = publication.reports(needs, RUN)
    assert root[1].splitlines()[0] != recovery[1].splitlines()[0]
    assert "recovery — **success**" in recovery[1] and "PyPI upload" not in recovery[1]


def test_tag_pr_and_bot_owned_comments(monkeypatch: pytest.MonkeyPatch) -> None:
    repo, sha = "promptfoo/modelaudit", "a" * 40
    pr = {
        "number": 2033,
        "merged_at": "2026-11-18",
        "merge_commit_sha": sha,
        "base": {"ref": "main"},
        "head": {"ref": "release-please--branches--main", "repo": {"full_name": repo}},
    }
    body = "<!-- release-publication: modelaudit@0.2.57 -->\nVerified"
    comments = [{"id": 7, "user": {"login": "human"}, "body": body}]
    writes = []

    def github(path: str, *args: str, body: str | None = None) -> str:
        if body is not None:
            writes.append((path, args, body))
            return ""
        if path.endswith("/commits/v0.2.57"):
            return sha
        assert "--paginate" in args
        rows = [{**pr, "number": 99, "merge_commit_sha": "b" * 40}, pr] if "/pulls?" in path else comments
        return "\n".join(json.dumps(row) for row in rows)

    monkeypatch.setattr(publication, "github", github)
    assert publication.release_pr(repo, "v0.2.57") == 2033
    publication.update_comment(repo, 2033, body)
    assert writes[-1][0].endswith("/issues/2033/comments") and "POST" in writes[-1][1]
    comments.append({"id": 8, "user": {"login": "github-actions[bot]"}, "body": body.replace("Verified", "Uploading")})
    publication.update_comment(repo, 2033, body)
    assert writes[-1][0].endswith("/issues/comments/8") and "PATCH" in writes[-1][1]
    comments[-1]["body"] = body
    publication.update_comment(repo, 2033, body)
    assert len(writes) == 2


def test_final_report_waits_for_each_stage() -> None:
    path = Path(__file__).resolve().parents[1] / ".github/workflows/release-please.yml"
    jobs = yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]
    stages = {stage for *_, stages in publication.PACKAGES for stage in stages}
    assert set(jobs["publication-finished"]["needs"]) == stages | {"release-please", "root-provenance-recovery"}
    assert stages <= jobs.keys()


def test_inconsistent_tag_cannot_post_to_another_release() -> None:
    outputs = {"release_created": "true", "version": "0.2.57", "tag_name": "v0.2.56"}
    with pytest.raises(ValueError, match="Version and release tag disagree"):
        list(publication.reports({"release-please": {"outputs": outputs}}, RUN))
