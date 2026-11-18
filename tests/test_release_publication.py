from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import release_publication as publication

RUN = "https://github.com/promptfoo/modelaudit/actions/runs/123/attempts/2"


def test_independent_results_for_coordinated_release() -> None:
    outputs = {
        "release_created": "true",
        "picklescan_release_created": "true",
        "version": "0.2.57",
        "picklescan_version": "0.1.15",
        "tag_name": "v0.2.57",
        "picklescan_tag_name": "modelaudit-picklescan-v0.1.15",
    }
    needs: dict[str, Any] = {"release-please": {"outputs": outputs}}
    pending = list(publication.reports(needs, RUN))
    assert len(pending) == 2
    assert all("Publication started" in body for _, _, body in pending)

    for _, _, _, jobs in publication.PACKAGES:
        needs.update({job: {"result": "success"} for job in jobs})
    needs["provenance"]["result"] = "failure"
    root, sibling = publication.reports(needs, RUN)
    assert root[:2] == pending[0][:2]
    assert sibling[:2] == pending[1][:2]
    assert "| success | success | success | failure |" in root[2]
    assert "| success | success | success | success |" in sibling[2]
    assert "https://pypi.org/project/modelaudit/0.2.57/" in root[2]
    assert "https://pypi.org/project/modelaudit-picklescan/0.1.15/" in sibling[2]
    assert "https://github.com/promptfoo/modelaudit/releases/tag/v0.2.57" in root[2]
    assert RUN in root[2] and RUN in sibling[2]

    outputs["release_created"] = "false"
    assert list(publication.reports(needs, RUN)) == [sibling]
    outputs["picklescan_release_created"] = "false"
    assert not list(publication.reports(needs, RUN))
    outputs["root_provenance_recovery"] = "true"
    needs["root-provenance-recovery"] = {"result": "success"}
    (recovery,) = publication.reports(needs, RUN)
    assert recovery[1] != root[1] and "recovery — **success**" in recovery[2]


def test_report_only_updates_bot_comment_on_matching_release_pr(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = "promptfoo/modelaudit"
    sha = "a" * 40
    pr = {
        "number": 2033,
        "merge_commit_sha": sha,
        "merged_at": "2026-11-18",
        "base": {"ref": "main"},
        "head": {"ref": "release-please--branches--main", "repo": {"full_name": repo}},
    }
    marker = "<!-- release-publication: modelaudit@0.2.57 -->"
    body = marker + "\nVerified"
    comments = [{"id": 7, "user": {"login": "human"}, "body": body}]
    writes = []

    def fake_github(repository: str, path: str, *args: str) -> Any:
        assert repository == repo
        if path == "commits/v0.2.57":
            return {"sha": sha}
        if path.startswith(f"commits/{sha}/pulls?"):
            if path.endswith("page=1"):
                return [{**pr, "number": 99, "merge_commit_sha": "b" * 40}] * 100
            return [pr]
        if path.startswith("issues/2033/comments?"):
            return comments
        writes.append((path, args))
        return None

    monkeypatch.setattr(publication, "github", fake_github)
    publication.update(repo, "v0.2.57", marker, body)
    assert writes[-1][0] == "issues/2033/comments" and "POST" in writes[-1][1]
    comments.append({"id": 8, "user": {"login": "github-actions[bot]"}, "body": marker + "\nBuilding"})
    publication.update(repo, "v0.2.57", marker, body)
    assert writes[-1][0] == "issues/comments/8" and "PATCH" in writes[-1][1]
    comments[-1]["body"] = body
    publication.update(repo, "v0.2.57", marker, body)
    assert len(writes) == 2


def test_final_report_waits_for_the_jobs_it_displays() -> None:
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/release-please.yml"
    jobs = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"]
    started, finished = jobs["publication-started"], jobs["publication-finished"]
    for _, _, _, stages in publication.PACKAGES:
        assert set(stages) <= set(finished["needs"]) <= set(jobs)
    assert {"release-please", "publication-started", "root-provenance-recovery"} <= set(finished["needs"])
    assert started["needs"] == "release-please" and started["steps"] == finished["steps"]
    assert started["permissions"] == finished["permissions"] == {"contents": "read", "pull-requests": "write"}


def test_inconsistent_version_and_tag_cannot_post_to_another_release() -> None:
    outputs = {"release_created": "true", "version": "0.2.57", "tag_name": "v0.2.56"}
    with pytest.raises(ValueError, match="Version and release tag disagree"):
        list(publication.reports({"release-please": {"outputs": outputs}}, RUN))
