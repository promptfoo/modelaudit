from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import time
import urllib.request
import zipfile
import zlib
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]


def _load_release_workflow() -> dict[str, Any]:
    workflow_path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release-please.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _workflow_triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    raw_workflow = cast(dict[Any, Any], workflow)
    triggers = raw_workflow.get("on", raw_workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


def _job_steps(workflow: dict[str, Any], job_name: str) -> list[dict[str, Any]]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = jobs[job_name]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)
    return steps


def _step_by_name(steps: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for step in steps:
        if step.get("name") == name:
            return step
    raise AssertionError(f"Step {name!r} not found")


def _jobs(workflow: dict[str, Any]) -> dict[str, Any]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def test_release_please_keeps_root_componentless_for_grouped_root_only_releases() -> None:
    root_dir = Path(__file__).resolve().parents[1]
    release_config = json.loads((root_dir / "release-please-config.json").read_text(encoding="utf-8"))
    root_package = release_config["packages"]["."]
    picklescan_package = release_config["packages"]["packages/modelaudit-picklescan"]
    pyproject = tomllib.loads((root_dir / "pyproject.toml").read_text(encoding="utf-8"))

    assert release_config["include-component-in-tag"] is False
    assert release_config["include-v-in-tag"] is True
    assert release_config.get("separate-pull-requests", False) is False
    assert root_package["release-type"] == "python"
    assert "component" not in root_package
    assert "package-name" not in root_package
    assert root_package.get("separate-pull-requests", False) is False
    assert pyproject["project"]["name"] == "modelaudit"
    assert picklescan_package["component"] == "modelaudit-picklescan"
    assert picklescan_package["include-component-in-tag"] is True
    assert picklescan_package.get("separate-pull-requests", False) is False


def test_release_workflow_manual_dispatch_inputs_and_guardrails() -> None:
    workflow = _load_release_workflow()

    triggers = _workflow_triggers(workflow)
    assert triggers["repository_dispatch"] == {"types": ["release-metadata-retry"]}
    dispatch_inputs = triggers["workflow_dispatch"]["inputs"]
    assert dispatch_inputs == {
        "root_version": {
            "description": "Publish an already-versioned root modelaudit release, for example 0.2.39",
            "required": False,
            "type": "string",
        },
        "picklescan_version": {
            "description": "Publish an already-versioned modelaudit-picklescan release, for example 0.1.2",
            "required": False,
            "type": "string",
        },
        "root_provenance_run_id": {
            "description": "Recover root provenance from the original verified publish run, for example 29787069929",
            "required": False,
            "type": "string",
        },
    }

    release_steps = _job_steps(workflow, "release-please")
    manual_step = _step_by_name(release_steps, "Resolve manual release inputs")
    assert manual_step["id"] == "manual"
    assert manual_step["env"] == {
        "ROOT_VERSION": "${{ github.event.inputs.root_version || '' }}",
        "PICKLESCAN_VERSION": "${{ github.event.inputs.picklescan_version || '' }}",
        "ROOT_PROVENANCE_RUN_ID": "${{ github.event.inputs.root_provenance_run_id || '' }}",
    }

    release_action_step = next(
        step for step in release_steps if step.get("uses", "").startswith("googleapis/release-please-action@")
    )
    assert (
        release_action_step["if"]
        == "steps.manual.outputs.manual_release != 'true' && github.event_name != 'repository_dispatch'"
    )

    ensure_release_step = _step_by_name(release_steps, "Ensure manual GitHub releases exist")
    assert ensure_release_step["if"] == (
        "steps.manual.outputs.manual_release == 'true' && steps.manual.outputs.root_provenance_recovery != 'true'"
    )
    ensure_release_run = ensure_release_step["run"]
    assert 'gh release view "$ROOT_TAG"' in ensure_release_run
    assert 'gh release view "$PICKLESCAN_TAG"' in ensure_release_run
    assert 'gh release create "$ROOT_TAG"' in ensure_release_run
    assert 'gh release create "$PICKLESCAN_TAG"' in ensure_release_run

    check_pr_step = _step_by_name(release_steps, "Check if PR exists")
    assert check_pr_step["env"] == {
        "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
        "PR_OUTPUT": "${{ steps.release.outputs.pr || '' }}",
        "RETRY_EVENT": "${{ github.event.action || '' }}",
        "RETRY_BRANCH": "${{ github.event.client_payload.pr_branch || '' }}",
    }
    check_pr_run = check_pr_step["run"]
    assert '"$RETRY_BRANCH" == "release-please--branches--main"' in check_pr_run
    assert 'gh pr view "$RETRY_BRANCH" --repo "$GITHUB_REPOSITORY" --json state,headRefName' in check_pr_run
    assert '"$OPEN_BRANCH" != "$RETRY_BRANCH"' in check_pr_run
    assert "Refusing release metadata retry for an unexpected branch." in check_pr_run


@pytest.mark.skipif(os.name == "nt", reason="Release workflow Bash execution requires POSIX filesystem semantics")
@pytest.mark.parametrize(
    ("root_version", "picklescan_version", "source_run_id", "expected_code", "expected_fragment"),
    [
        ("0.2.50", "", "29787069929", 0, "root_provenance_recovery=true"),
        ("", "", "29787069929", 1, "requires root_version in X.Y.Z format"),
        ("v0.2.50", "", "29787069929", 1, "requires root_version in X.Y.Z format"),
        ("0.2.50", "", "not-a-run", 1, "requires a numeric source run ID"),
        ("0.2.50", "0.1.9", "29787069929", 1, "cannot publish modelaudit-picklescan"),
        ("0.2.50", "", "", 0, "release_created=true"),
        ("", "0.1.9", "", 0, "picklescan_release_created=true"),
        ("", "", "", 0, "manual_release=false"),
    ],
)
def test_release_workflow_resolves_provenance_only_recovery_inputs(
    root_version: str,
    picklescan_version: str,
    source_run_id: str,
    expected_code: int,
    expected_fragment: str,
    tmp_path: Path,
) -> None:
    workflow = _load_release_workflow()
    script = _step_by_name(_job_steps(workflow, "release-please"), "Resolve manual release inputs")["run"]
    output_path = tmp_path / "github-output"

    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", script],
        env={
            "PATH": os.environ["PATH"],
            "GITHUB_OUTPUT": str(output_path),
            "ROOT_VERSION": root_version,
            "PICKLESCAN_VERSION": picklescan_version,
            "ROOT_PROVENANCE_RUN_ID": source_run_id,
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == expected_code
    output = output_path.read_text(encoding="utf-8") if output_path.exists() else result.stdout
    assert expected_fragment in output
    if source_run_id and expected_code == 0:
        assert "manual_release=true" in output
        assert "release_created=false" in output
        assert "picklescan_release_created=false" in output
        assert f"root_provenance_run_id={source_run_id}" in output
        assert f"version={root_version}" in output
        assert f"tag_name=v{root_version}" in output


def test_release_workflow_picklescan_artifacts_stay_in_package_workspace() -> None:
    workflow = _load_release_workflow()

    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    build_job = jobs["build-picklescan-package"]
    assert isinstance(build_job, dict)
    run_defaults = build_job["defaults"]["run"]
    assert run_defaults["working-directory"] == "packages/modelaudit-picklescan"

    build_steps = _job_steps(workflow, "build-picklescan-package")

    build_sdist_step = _step_by_name(build_steps, "Build standalone package sdist")
    assert "uv build --sdist --out-dir dist" in build_sdist_step["run"]

    build_manylinux_step = _step_by_name(build_steps, "Build standalone package manylinux wheel")
    assert build_manylinux_step["with"]["args"] == "--release --out dist"
    assert build_manylinux_step["with"]["manylinux"] == "2_28"
    assert "compatibility" not in build_manylinux_step["with"]["args"]

    validate_step = _step_by_name(build_steps, "Validate standalone package metadata")
    assert validate_step["run"] == "uvx twine check dist/*"

    version_check_step = _step_by_name(build_steps, "Verify standalone artifact version consistency")
    assert (
        "artifacts=(dist/modelaudit_picklescan-*.whl dist/modelaudit_picklescan-*.tar.gz)" in version_check_step["run"]
    )
    assert "ls -la dist/" in version_check_step["run"]

    smoke_step = _step_by_name(build_steps, "Smoke test standalone package wheel install")
    assert "picklescan_wheels=(dist/modelaudit_picklescan-*.whl)" in smoke_step["run"]

    upload_step = _step_by_name(build_steps, "Upload standalone package artifacts")
    assert upload_step["with"]["path"] == "packages/modelaudit-picklescan/dist/"

    publish_job = jobs["publish-picklescan-pypi"]
    assert isinstance(publish_job, dict)
    publish_steps = publish_job["steps"]
    assert isinstance(publish_steps, list)
    download_step = _step_by_name(publish_steps, "Download standalone pickle package artifacts")
    assert download_step["with"] == {
        "pattern": "modelaudit-picklescan-dist-*",
        "path": "dist/",
        "merge-multiple": True,
    }


def test_release_workflow_restores_root_runtime_python_after_type_check() -> None:
    workflow = _load_release_workflow()
    steps = _job_steps(workflow, "build")

    type_check_step = _step_by_name(steps, "Type check root package with mypy")
    sync_step = _step_by_name(steps, "Sync dependencies for root runtime checks")
    lint_step = _step_by_name(steps, "Lint root package with Ruff")
    test_step = _step_by_name(steps, "Run root package tests")
    build_step = _step_by_name(steps, "Build package")

    assert "uv sync --python 3.10 --locked --extra all-ci" in type_check_step["run"]
    assert "uv run --python 3.10 --locked mypy modelaudit/ tests/" in type_check_step["run"]
    assert type_check_step["run"].index("uv run --python 3.10 --locked mypy") < type_check_step["run"].index(
        "uv cache prune --ci"
    )
    assert "UV_PROJECT_ENVIRONMENT" not in type_check_step.get("env", {})
    assert "uv python pin 3.12" in sync_step["run"]
    assert "uv sync --locked --extra all-ci" in sync_step["run"]
    assert "uv python pin 3.10" not in "\n".join(step.get("run", "") for step in steps)
    assert steps.index(type_check_step) < steps.index(sync_step) < steps.index(lint_step) < steps.index(test_step)
    assert steps.index(test_step) < steps.index(build_step)


def test_release_workflow_refreshes_both_standalone_package_locks() -> None:
    workflow = _load_release_workflow()
    sync_job = _jobs(workflow)["sync-release-metadata"]
    assert isinstance(sync_job, dict)
    assert sync_job["permissions"] == {"contents": "read"}
    assert sync_job["needs"] == "release-please"
    assert sync_job["if"] == "needs.release-please.outputs.pr_branch != ''"
    assert sync_job["outputs"] == {"source_sha": "${{ steps.source.outputs.sha }}"}
    sync_steps = _job_steps(workflow, "sync-release-metadata")

    sync_step = _step_by_name(sync_steps, "Sync standalone package lock with pyproject.toml")
    assert sync_step["working-directory"] == "packages/modelaudit-picklescan"
    sync_run = sync_step["run"]
    assert "uv lock" in sync_run
    assert "cargo update --workspace --manifest-path Cargo.toml" in sync_run
    assert "cargo metadata --manifest-path Cargo.toml --locked --no-deps --format-version 1" in sync_run
    assert "cargo check" not in sync_run
    assert "git push" not in sync_run


def test_release_changelogs_keep_one_unreleased_section() -> None:
    root_dir = Path(__file__).resolve().parents[1]
    changelogs = (root_dir / "CHANGELOG.md", root_dir / "packages" / "modelaudit-picklescan" / "CHANGELOG.md")

    for changelog in changelogs:
        headings = [line for line in changelog.read_text(encoding="utf-8").splitlines() if line.startswith("## ")]
        assert headings.count("## [Unreleased]") == 1


def test_release_metadata_generation_does_not_keep_write_credentials() -> None:
    workflow = _load_release_workflow()
    sync_steps = _job_steps(workflow, "sync-release-metadata")
    checkout_step = next(step for step in sync_steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout_step["with"]["persist-credentials"] is False

    source_step = _step_by_name(sync_steps, "Record release metadata source")
    assert source_step["id"] == "source"
    assert 'echo "sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"' in source_step["run"]

    for name in (
        "Sync uv.lock with pyproject.toml",
        "Sync standalone package lock with pyproject.toml",
        "Install Node dependencies",
        "Format changelogs with Prettier",
    ):
        step = _step_by_name(sync_steps, name)
        assert "GH_TOKEN" not in step.get("env", {})
        assert "git push" not in step["run"]

    upload_step = _step_by_name(sync_steps, "Upload release metadata")
    assert upload_step["with"]["name"] == "modelaudit-release-metadata-${{ github.run_attempt }}"
    assert upload_step["with"]["if-no-files-found"] == "error"
    assert upload_step["with"]["path"].splitlines() == [
        "uv.lock",
        "CHANGELOG.md",
        "packages/modelaudit-picklescan/uv.lock",
        "packages/modelaudit-picklescan/Cargo.lock",
        "packages/modelaudit-picklescan/CHANGELOG.md",
    ]

    push_job = _jobs(workflow)["push-release-metadata"]
    assert isinstance(push_job, dict)
    assert push_job["permissions"] == {"contents": "write"}
    assert push_job["needs"] == ["release-please", "sync-release-metadata"]
    assert push_job["if"] == "needs.release-please.outputs.pr_branch != ''"
    push_steps = _job_steps(workflow, "push-release-metadata")
    push_checkout = next(step for step in push_steps if step.get("uses", "").startswith("actions/checkout@"))
    assert push_checkout["with"]["persist-credentials"] is False

    download_step = _step_by_name(push_steps, "Download release metadata")
    assert download_step["id"] == "download-metadata"
    assert download_step["continue-on-error"] is True
    assert download_step["with"] == {
        "name": "modelaudit-release-metadata-${{ github.run_attempt }}",
        "path": "/tmp/modelaudit-release-metadata",
    }

    retry_step = _step_by_name(push_steps, "Regenerate missing release metadata")
    assert retry_step["if"] == "steps.download-metadata.outcome != 'success'"
    assert retry_step["env"] == {
        "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
        "PR_BRANCH": "${{ needs.release-please.outputs.pr_branch }}",
        "RETRY_EVENT": "${{ github.event.action || '' }}",
    }
    retry_run = retry_step["run"]
    assert '"$RETRY_EVENT" == "release-metadata-retry"' in retry_run
    assert '"$PR_BRANCH" != "release-please--branches--main"' in retry_run
    assert (
        'gh api "repos/${GITHUB_REPOSITORY}/dispatches" -f event_type=release-metadata-retry '
        '-f "client_payload[pr_branch]=$PR_BRANCH"' in retry_run
    )
    assert "Re-run all jobs" in retry_run
    assert "uv lock" not in retry_run
    assert "git push" not in retry_run
    assert "exit 1" in retry_run

    push_step = _step_by_name(push_steps, "Push release metadata updates")
    assert push_step["env"] == {
        "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
        "PR_BRANCH": "${{ needs.release-please.outputs.pr_branch }}",
        "EXPECTED_HEAD": "${{ needs.sync-release-metadata.outputs.source_sha }}",
    }
    assert '"$(git rev-parse HEAD)" != "$EXPECTED_HEAD"' in push_step["run"]
    assert (
        'git push "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" "HEAD:${PR_BRANCH}"'
        in (push_step["run"])
    )


def test_release_workflow_verifies_published_picklescan_package() -> None:
    workflow = _load_release_workflow()

    job = _jobs(workflow)["verify-picklescan-pypi"]
    assert isinstance(job, dict)
    assert job["if"] == "needs.release-please.outputs.picklescan_release_created == 'true'"
    assert job["needs"] == ["publish-picklescan-pypi", "release-please"]
    assert job["permissions"] == {"contents": "read"}
    assert job["env"] == {"EXPECTED_VERSION": "${{ needs.release-please.outputs.picklescan_version }}"}

    steps = _job_steps(workflow, "verify-picklescan-pypi")
    wait_step = _step_by_name(steps, "Wait for modelaudit-picklescan files on PyPI")
    wait_run = wait_step["run"]
    assert "https://pypi.org/pypi/modelaudit-picklescan/{version}/json" in wait_run
    assert "https://pypi.org/simple/modelaudit-picklescan/" in wait_run
    assert (
        '"Accept": "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, '
        'text/html; q=0.01"' in wait_run
    )
    assert '"Accept-Encoding": "gzip, deflate"' in wait_run
    assert '"Cache-Control": "max-age=0"' in wait_run
    assert 'content_encoding == "gzip"' in wait_run
    assert 'content_encoding == "deflate"' in wait_run
    assert "deadline = time.monotonic() + 600" in wait_run
    assert 'if not entry.get("yanked", False)' in wait_run
    assert "missing_simple={missing_simple}" in wait_run
    for expected_fragment in (
        "modelaudit_picklescan-{version}-cp310-abi3-macosx_10_12_x86_64.whl",
        "modelaudit_picklescan-{version}-cp310-abi3-macosx_11_0_arm64.whl",
        "modelaudit_picklescan-{version}-cp310-abi3-manylinux_2_28_aarch64.whl",
        "modelaudit_picklescan-{version}-cp310-abi3-manylinux_2_28_x86_64.whl",
        "modelaudit_picklescan-{version}-cp310-abi3-win_amd64.whl",
        "modelaudit_picklescan-{version}.tar.gz",
    ):
        assert expected_fragment in wait_run

    smoke_step = _step_by_name(steps, "Install published modelaudit-picklescan and smoke test API")
    smoke_run = smoke_step["run"]
    assert "--no-cache-dir" in smoke_run
    assert '"modelaudit-picklescan==${EXPECTED_VERSION}"' in smoke_run
    assert 'md.version("modelaudit-picklescan")' in smoke_run
    assert 'find_spec("modelaudit_picklescan._rust")' in smoke_run
    assert 'clean_report.status.value != "complete"' in smoke_run
    assert 'malicious_report.verdict.value != "malicious"' in smoke_run
    assert 'finding.rule_code == "DANGEROUS_CALL"' in smoke_run


@pytest.mark.parametrize(
    ("job_name", "step_name", "project", "version", "expected_files"),
    [
        (
            "verify-picklescan-pypi",
            "Wait for modelaudit-picklescan files on PyPI",
            "modelaudit-picklescan",
            "0.1.9",
            (
                "modelaudit_picklescan-0.1.9-cp310-abi3-macosx_10_12_x86_64.whl",
                "modelaudit_picklescan-0.1.9-cp310-abi3-macosx_11_0_arm64.whl",
                "modelaudit_picklescan-0.1.9-cp310-abi3-manylinux_2_28_aarch64.whl",
                "modelaudit_picklescan-0.1.9-cp310-abi3-manylinux_2_28_x86_64.whl",
                "modelaudit_picklescan-0.1.9-cp310-abi3-win_amd64.whl",
                "modelaudit_picklescan-0.1.9.tar.gz",
            ),
        ),
        (
            "verify-pypi",
            "Wait for modelaudit files on PyPI",
            "modelaudit",
            "0.2.50",
            ("modelaudit-0.2.50-py3-none-any.whl", "modelaudit-0.2.50.tar.gz"),
        ),
    ],
)
@pytest.mark.parametrize("content_encoding", ["gzip", "deflate"])
def test_release_workflow_waits_for_compressed_pypi_simple_index(
    job_name: str,
    step_name: str,
    project: str,
    version: str,
    expected_files: tuple[str, ...],
    content_encoding: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = _load_release_workflow()
    wait_run = _step_by_name(_job_steps(workflow, job_name), step_name)["run"]
    lines = wait_run.splitlines()
    assert lines[0] == "python - <<'PY'"
    assert lines[-1] == "PY"
    script = "\n".join(lines[1:-1])

    class EncodedResponse(io.BytesIO):
        def __init__(self, body: bytes, encoding: str) -> None:
            super().__init__(body)
            self.headers = {"Content-Encoding": encoding}

    calls = {"api": 0, "simple": 0}
    api_payload = {"info": {"version": version}, "urls": [{"filename": name} for name in expected_files]}

    def fake_urlopen(url: str | urllib.request.Request, timeout: int = 20) -> io.BytesIO:
        assert timeout == 20
        if isinstance(url, str):
            assert url == f"https://pypi.org/pypi/{project}/{version}/json"
            calls["api"] += 1
            return io.BytesIO(json.dumps(api_payload).encode())

        assert url.full_url == f"https://pypi.org/simple/{project}/"
        assert url.get_header("Accept-encoding") == "gzip, deflate"
        assert url.get_header("Cache-control") == "max-age=0"
        calls["simple"] += 1
        files = [
            {"filename": name, "yanked": calls["simple"] == 1 and index == 0}
            for index, name in enumerate(expected_files)
        ]
        body = json.dumps({"files": files}).encode()
        encoded_body = gzip.compress(body) if content_encoding == "gzip" else zlib.compress(body)
        return EncodedResponse(encoded_body, content_encoding)

    ticks = iter((0.0, 1.0, 2.0, 3.0))
    monkeypatch.setenv("EXPECTED_VERSION", version)
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks, 3.0))
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    exec(compile(script, "release-pypi-propagation-step", "exec"), {})
    assert calls == {"api": 2, "simple": 2}


def test_release_workflow_publishes_picklescan_before_dependent_root() -> None:
    workflow = _load_release_workflow()

    job = _jobs(workflow)["publish-pypi"]
    assert isinstance(job, dict)
    job_condition = job["if"]
    assert "always()" in job_condition
    assert "needs.release-please.outputs.release_created == 'true'" in job_condition
    assert "needs.build.result == 'success'" in job_condition
    assert "needs.release-please.outputs.picklescan_release_created != 'true'" in job_condition
    assert "needs.verify-picklescan-pypi.result == 'success'" in job_condition
    assert job["needs"] == ["build", "release-please", "verify-picklescan-pypi"]

    steps = _job_steps(workflow, "publish-pypi")
    dependency_step = _step_by_name(steps, "Verify the root picklescan dependency is available on PyPI")
    dependency_run = dependency_step["run"]
    assert 'Path("dist").glob("modelaudit-*.whl")' in dependency_run
    assert 'metadata.get_all("Requires-Dist")' in dependency_run
    assert 're.sub(r"^modelaudit[-_]picklescan"' in dependency_run
    assert 're.fullmatch(r"(?:==|!=|>=|<=|>|<)' in dependency_run
    assert "https://pypi.org/pypi/modelaudit-picklescan/json" in dependency_run
    assert 'entry.get("yanked", False)' in dependency_run
    assert "deadline = time.monotonic() + 600" in dependency_run
    assert "Refusing to publish modelaudit with an unavailable picklescan dependency" in dependency_run
    assert "pip install" not in dependency_run
    assert "uv lock" not in dependency_run
    assert "git push" not in dependency_run
    assert steps.index(dependency_step) < steps.index(_step_by_name(steps, "Publish to PyPI"))


@pytest.mark.parametrize(
    ("requirement", "published_version", "missing_wheel", "missing_sdist", "yanked_wheel", "should_pass"),
    [
        ("modelaudit-picklescan<0.2.0,>=0.1.9", "0.1.8", False, False, False, False),
        ("modelaudit-picklescan<0.2.0,>=0.1.9", "0.1.9", True, False, False, False),
        ("modelaudit-picklescan<0.2.0,>=0.1.9", "0.1.9", False, True, False, False),
        ("modelaudit-picklescan<0.2.0,>=0.1.9", "0.1.9", False, False, True, False),
        ("modelaudit-picklescan<0.2.0,>=0.1.9", "0.1.9", False, False, False, True),
        ("modelaudit-picklescan<0.2.0,>=0.1.9", "0.1.9.post1", False, False, False, True),
        ("modelaudit-picklescan>0.1.9,<0.2.0", "0.1.9.post1", False, False, False, False),
        ("modelaudit-picklescan==0.1.9", "0.1.9.post1", False, False, False, False),
        ("modelaudit-picklescan!=0.1.9,<0.2.0", "0.1.9.post1", False, False, False, True),
        ("modelaudit-picklescan<0.2.0,>=0.1.9", "0.1.9rc1", False, False, False, False),
        ("modelaudit-picklescan<0.2.0,>=0.1.9", "0.2.0.post1", False, False, False, False),
        ("modelaudit-picklescan (>=0.1.9, <0.2.0)", "0.1.9", False, False, False, True),
        ("modelaudit-picklescan>=0.1.9rc1,<0.2.0", "0.1.9", False, False, False, False),
    ],
)
def test_root_publish_fails_closed_until_picklescan_is_available(
    requirement: str,
    published_version: str,
    missing_wheel: bool,
    missing_sdist: bool,
    yanked_wheel: bool,
    should_pass: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = _load_release_workflow()
    step = _step_by_name(
        _job_steps(workflow, "publish-pypi"),
        "Verify the root picklescan dependency is available on PyPI",
    )
    lines = step["run"].splitlines()
    assert lines[0] == "python - <<'PY'"
    assert lines[-1] == "PY"
    script = "\n".join(lines[1:-1])

    dist = tmp_path / "dist"
    dist.mkdir()
    with zipfile.ZipFile(dist / "modelaudit-0.2.50-py3-none-any.whl", "w") as archive:
        archive.writestr(
            "modelaudit-0.2.50.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: modelaudit\nVersion: 0.2.50\nRequires-Dist: {requirement}\n",
        )

    expected_files = [
        f"modelaudit_picklescan-{published_version}-cp310-abi3-macosx_10_12_x86_64.whl",
        f"modelaudit_picklescan-{published_version}-cp310-abi3-macosx_11_0_arm64.whl",
        f"modelaudit_picklescan-{published_version}-cp310-abi3-manylinux_2_28_aarch64.whl",
        f"modelaudit_picklescan-{published_version}-cp310-abi3-manylinux_2_28_x86_64.whl",
        f"modelaudit_picklescan-{published_version}-cp310-abi3-win_amd64.whl",
        f"modelaudit_picklescan-{published_version}.tar.gz",
    ]
    if missing_wheel:
        expected_files.pop(0)
    if missing_sdist:
        expected_files.pop()
    payload = {
        "releases": {
            published_version: [
                {"filename": filename, "yanked": yanked_wheel and index == 0}
                for index, filename in enumerate(expected_files)
            ]
        }
    }
    ticks = iter((0.0, 1.0, 601.0, 602.0))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _url, timeout=20: io.BytesIO(json.dumps(payload).encode()),
    )
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks, 602.0))
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    if should_pass:
        exec(compile(script, "release-availability-step", "exec"), {})
    else:
        with pytest.raises(SystemExit):
            exec(compile(script, "release-availability-step", "exec"), {})


def test_release_workflow_verifies_published_root_package_after_picklescan() -> None:
    workflow = _load_release_workflow()

    job = _jobs(workflow)["verify-pypi"]
    assert isinstance(job, dict)
    job_condition = job["if"]
    assert "always()" in job_condition
    assert "needs.release-please.outputs.release_created == 'true'" in job_condition
    assert "needs.publish-pypi.result == 'success'" in job_condition
    assert "needs.release-please.outputs.picklescan_release_created != 'true'" in job_condition
    assert "needs.verify-picklescan-pypi.result == 'success'" in job_condition
    assert job["needs"] == [
        "publish-pypi",
        "publish-picklescan-pypi",
        "release-please",
        "verify-picklescan-pypi",
    ]
    assert job["permissions"] == {"contents": "read"}
    assert job["env"] == {
        "EXPECTED_VERSION": "${{ needs.release-please.outputs.version }}",
        "EXPECTED_PICKLESCAN_VERSION": "${{ needs.release-please.outputs.picklescan_version }}",
        "PICKLESCAN_RELEASE_CREATED": "${{ needs.release-please.outputs.picklescan_release_created }}",
        "PROMPTFOO_DISABLE_TELEMETRY": "1",
    }

    steps = _job_steps(workflow, "verify-pypi")
    wait_step = _step_by_name(steps, "Wait for modelaudit files on PyPI")
    wait_run = wait_step["run"]
    assert "https://pypi.org/pypi/modelaudit/{version}/json" in wait_run
    assert "https://pypi.org/simple/modelaudit/" in wait_run
    assert (
        '"Accept": "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, '
        'text/html; q=0.01"' in wait_run
    )
    assert '"Accept-Encoding": "gzip, deflate"' in wait_run
    assert '"Cache-Control": "max-age=0"' in wait_run
    assert 'content_encoding == "gzip"' in wait_run
    assert 'content_encoding == "deflate"' in wait_run
    assert "deadline = time.monotonic() + 600" in wait_run
    assert 'if not entry.get("yanked", False)' in wait_run
    assert "missing_simple={missing_simple}" in wait_run
    assert "modelaudit-{version}-py3-none-any.whl" in wait_run
    assert "modelaudit-{version}.tar.gz" in wait_run

    smoke_step = _step_by_name(steps, "Install published modelaudit and run end-to-end smoke tests")
    smoke_run = smoke_step["run"]
    assert "--no-cache-dir" in smoke_run
    assert '"modelaudit[all]==${EXPECTED_VERSION}"' in smoke_run
    assert 'md.version("modelaudit")' in smoke_run
    assert 'md.version("modelaudit-picklescan")' in smoke_run
    assert 'os.environ.get("PICKLESCAN_RELEASE_CREATED") == "true"' in smoke_run
    assert 'env["PROMPTFOO_DISABLE_TELEMETRY"] = "1"' in smoke_run
    assert 'run([modelaudit, "--version"], 0)' in smoke_run
    assert 'run([modelaudit, "doctor", "--show-failed"], 0)' in smoke_run
    assert 'run([modelaudit, "scan", benign, "--format", "json", "--output", benign_json, "--no-cache"], 0)' in (
        smoke_run
    )
    assert 'run([modelaudit, "scan", malicious, "--format", "json", "--output", malicious_json, "--no-cache"], 1)' in (
        smoke_run
    )
    assert 'run([modelaudit, "scan", malicious_zip, "--format", "json", "--output", zip_json, "--no-cache"], 1)' in (
        smoke_run
    )
    assert 'result.get("ruleId") == "S201"' in smoke_run
    assert 'sbom_report.get("bomFormat") != "CycloneDX"' in smoke_run
    assert "Malicious pickle payload executed during scan" in smoke_run


def test_release_workflow_generates_root_provenance_after_successful_publish() -> None:
    workflow = _load_release_workflow()

    job = _jobs(workflow)["provenance"]
    assert isinstance(job, dict)
    job_condition = job["if"]
    assert "always()" in job_condition
    assert "!cancelled()" in job_condition
    assert "needs.release-please.outputs.release_created == 'true'" in job_condition
    assert "needs.build.result == 'success'" in job_condition
    assert "needs.publish-pypi.result == 'success'" in job_condition
    assert job["needs"] == ["build", "publish-pypi", "release-please"]


def test_release_workflow_recovers_root_provenance_without_republishing() -> None:
    workflow = _load_release_workflow()

    release_job = _jobs(workflow)["release-please"]
    assert isinstance(release_job, dict)
    assert release_job["outputs"]["root_provenance_recovery"] == "${{ steps.manual.outputs.root_provenance_recovery }}"
    assert release_job["outputs"]["root_provenance_run_id"] == "${{ steps.manual.outputs.root_provenance_run_id }}"

    job = _jobs(workflow)["root-provenance-recovery"]
    assert isinstance(job, dict)
    job_condition = job["if"]
    assert "!cancelled()" in job_condition
    assert "needs.release-please.result == 'success'" in job_condition
    assert "needs.release-please.outputs.root_provenance_recovery == 'true'" in job_condition
    assert job["needs"] == "release-please"
    assert job["permissions"] == {
        "actions": "read",
        "contents": "write",
        "id-token": "write",
        "attestations": "write",
    }

    steps = _job_steps(workflow, "root-provenance-recovery")
    checkout_step = _step_by_name(steps, "Checkout tagged root release")
    assert checkout_step["uses"] == "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
    assert checkout_step["with"] == {
        "ref": "refs/tags/${{ needs.release-please.outputs.tag_name }}",
        "sparse-checkout": "pyproject.toml\nuv.lock\n",
        "persist-credentials": False,
    }

    source_run_step = _step_by_name(steps, "Verify original root publish run")
    source_run = source_run_step["run"]
    assert source_run_step["env"] == {
        "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
        "SOURCE_RUN_ID": "${{ needs.release-please.outputs.root_provenance_run_id }}",
    }
    assert '[[ ! "$SOURCE_RUN_ID" =~ ^[1-9][0-9]*$ ]]' in source_run
    assert 'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${SOURCE_RUN_ID}"' in source_run
    assert "gh api --paginate --slurp" in source_run
    assert '"repos/${GITHUB_REPOSITORY}/actions/runs/${SOURCE_RUN_ID}/jobs?per_page=100"' in source_run
    assert 'run.get("path") != ".github/workflows/release-please.yml"' in source_run
    assert 'run.get("event") not in {"push", "workflow_dispatch"}' in source_run
    assert 'run.get("status") != "completed" or run.get("conclusion") not in {"success", "failure"}' in source_run
    assert 'run.get("repository", {}).get("full_name") != repository' in source_run
    assert 'run.get("head_repository", {}).get("full_name") != repository' in source_run
    assert '("build", "publish-pypi", "verify-pypi")' in source_run
    assert "if len(matching) != 1" in source_run
    assert 'job.get("status") != "completed" or job.get("conclusion") != "success"' in source_run

    download_step = _step_by_name(steps, "Download original root build artifacts")
    assert download_step["uses"] == "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
    assert download_step["with"] == {
        "name": "dist",
        "path": "dist/",
        "github-token": "${{ secrets.GITHUB_TOKEN }}",
        "repository": "${{ github.repository }}",
        "run-id": "${{ needs.release-please.outputs.root_provenance_run_id }}",
    }

    verify_step = _step_by_name(steps, "Verify recovered root artifacts match PyPI")
    verify_run = verify_step["run"]
    assert verify_step["env"] == {"EXPECTED_VERSION": "${{ needs.release-please.outputs.version }}"}
    assert 're.fullmatch(r"[0-9]+\\.[0-9]+\\.[0-9]+", version)' in verify_run
    assert 'Path("pyproject.toml").read_text(encoding="utf-8")' in verify_run
    assert 'f"modelaudit-{version}-py3-none-any.whl"' in verify_run
    assert 'f"modelaudit-{version}.tar.gz"' in verify_run
    assert "path.is_symlink()" in verify_run
    assert "https://pypi.org/pypi/modelaudit/{version}/json" in verify_run
    assert 'entry.get("yanked", False)' in verify_run
    assert 'entry.get("digests", {}).get("sha256")' in verify_run
    assert "hashlib.sha256(path.read_bytes()).hexdigest()" in verify_run

    attest_step = _step_by_name(steps, "Generate recovery integrity attestation")
    assert attest_step["uses"] == "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26"
    assert attest_step["with"]["subject-path"] == (
        "dist/modelaudit-${{ needs.release-please.outputs.version }}-py3-none-any.whl\n"
        "dist/modelaudit-${{ needs.release-please.outputs.version }}.tar.gz\n"
    )
    assert attest_step["with"]["predicate-type"] == "https://promptfoo.dev/modelaudit/attestations/recovery/v1"
    assert json.loads(attest_step["with"]["predicate"]) == {
        "package": "modelaudit",
        "version": "${{ needs.release-please.outputs.version }}",
        "tag": "${{ needs.release-please.outputs.tag_name }}",
        "source_run_id": "${{ needs.release-please.outputs.root_provenance_run_id }}",
        "pypi_json_url": "https://pypi.org/pypi/modelaudit/${{ needs.release-please.outputs.version }}/json",
    }

    sbom_step = _step_by_name(steps, "Generate SBOM from tagged root lockfile")
    assert sbom_step["env"] == {"EXPECTED_VERSION": "${{ needs.release-please.outputs.version }}"}
    assert "--frozen" in sbom_step["run"]
    assert '--output-file "dist/modelaudit-${EXPECTED_VERSION}.cdx.json"' in sbom_step["run"]

    upload_step = _step_by_name(steps, "Upload recovered root artifacts to GitHub Release")
    assert upload_step["env"] == {
        "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
        "ROOT_TAG": "${{ needs.release-please.outputs.tag_name }}",
    }
    assert 'gh release view "$ROOT_TAG" --repo "$GITHUB_REPOSITORY"' in upload_step["run"]
    assert 'gh release upload "$ROOT_TAG" dist/*' in upload_step["run"]
    assert steps.index(source_run_step) < steps.index(download_step) < steps.index(verify_step)
    assert steps.index(verify_step) < steps.index(attest_step) < steps.index(sbom_step)
    assert steps.index(sbom_step) < steps.index(upload_step)
    assert not any(step.get("uses", "").startswith("pypa/gh-action-pypi-publish@") for step in steps)


@pytest.mark.skipif(os.name == "nt", reason="Release workflow Bash mocks require POSIX filesystem semantics")
@pytest.mark.parametrize(
    ("mutation", "should_pass"),
    [
        ("workflow-dispatch", True),
        ("push", True),
        ("wrong-workflow", False),
        ("pull-request", False),
        ("wrong-repository", False),
        ("wrong-head-repository", False),
        ("run-in-progress", False),
        ("provenance-failed", True),
        ("run-cancelled", False),
        ("missing-job", False),
        ("duplicate-job", False),
        ("job-in-progress", False),
        ("job-failed", False),
        ("invalid-run-id", False),
    ],
)
def test_root_provenance_recovery_rejects_untrusted_source_runs(
    mutation: str,
    should_pass: bool,
    tmp_path: Path,
) -> None:
    workflow = _load_release_workflow()
    script = _step_by_name(_job_steps(workflow, "root-provenance-recovery"), "Verify original root publish run")["run"]
    repository = "promptfoo/modelaudit"
    source_run_id = "not-a-run" if mutation == "invalid-run-id" else "29787069929"
    run_metadata: dict[str, Any] = {
        "path": ".github/workflows/release-please.yml",
        "event": "push" if mutation == "push" else "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": repository},
        "head_repository": {"full_name": repository},
    }
    jobs: list[dict[str, Any]] = [
        {"name": job_name, "status": "completed", "conclusion": "success"}
        for job_name in ("release-please", "build", "publish-pypi", "verify-pypi", "provenance")
    ]
    if mutation == "wrong-workflow":
        run_metadata["path"] = ".github/workflows/test.yml"
    elif mutation == "pull-request":
        run_metadata["event"] = "pull_request"
    elif mutation == "wrong-repository":
        run_metadata["repository"]["full_name"] = "attacker/modelaudit"
    elif mutation == "wrong-head-repository":
        run_metadata["head_repository"]["full_name"] = "attacker/modelaudit"
    elif mutation == "run-in-progress":
        run_metadata["status"] = "in_progress"
        run_metadata["conclusion"] = None
    elif mutation == "provenance-failed":
        run_metadata["conclusion"] = "failure"
        jobs[4]["conclusion"] = "failure"
    elif mutation == "run-cancelled":
        run_metadata["conclusion"] = "cancelled"
        jobs[4]["conclusion"] = "cancelled"
    elif mutation == "missing-job":
        jobs = [job for job in jobs if job["name"] != "verify-pypi"]
    elif mutation == "duplicate-job":
        jobs.append({"name": "publish-pypi", "status": "completed", "conclusion": "success"})
    elif mutation == "job-in-progress":
        jobs[2]["status"] = "in_progress"
        jobs[2]["conclusion"] = None
    elif mutation == "job-failed":
        jobs[1]["conclusion"] = "failure"

    run_path = tmp_path / "run.json"
    jobs_path = tmp_path / "jobs.json"
    calls_path = tmp_path / "calls.jsonl"
    run_path.write_text(json.dumps(run_metadata), encoding="utf-8")
    jobs_path.write_text(json.dumps([{"jobs": jobs[:2]}, {"jobs": jobs[2:]}]), encoding="utf-8")
    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    gh_path = bin_path / "gh"
    gh_path.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "with Path(os.environ['CALLS_PATH']).open('a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps(args) + '\\n')\n"
        "source = 'JOBS_PATH' if '/jobs?' in args[-1] else 'RUN_PATH'\n"
        "print(Path(os.environ[source]).read_text(encoding='utf-8'))\n",
        encoding="utf-8",
    )
    gh_path.chmod(0o755)

    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", script],
        env={
            "PATH": f"{bin_path}{os.pathsep}{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
            "GH_TOKEN": "test-token",
            "GITHUB_REPOSITORY": repository,
            "SOURCE_RUN_ID": source_run_id,
            "RUN_PATH": str(run_path),
            "JOBS_PATH": str(jobs_path),
            "CALLS_PATH": str(calls_path),
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert (result.returncode == 0) is should_pass, result.stdout + result.stderr
    if mutation == "invalid-run-id":
        assert not calls_path.exists()
        assert "requires a numeric source run ID" in result.stdout
        return
    calls = [json.loads(line) for line in calls_path.read_text(encoding="utf-8").splitlines()]
    assert calls == [
        ["api", f"repos/{repository}/actions/runs/{source_run_id}"],
        ["api", "--paginate", "--slurp", f"repos/{repository}/actions/runs/{source_run_id}/jobs?per_page=100"],
    ]


@pytest.mark.parametrize(
    ("mutation", "should_pass"),
    [
        ("valid", True),
        ("invalid-version", False),
        ("wrong-tag-version", False),
        ("missing-local", False),
        ("extra-local", False),
        ("wrong-pypi-version", False),
        ("missing-pypi-file", False),
        ("yanked", False),
        ("invalid-digest", False),
        ("hash-mismatch", False),
    ],
)
def test_root_provenance_recovery_fails_closed_for_unverified_artifacts(
    mutation: str,
    should_pass: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workflow = _load_release_workflow()
    verify_run = _step_by_name(
        _job_steps(workflow, "root-provenance-recovery"), "Verify recovered root artifacts match PyPI"
    )["run"]
    lines = verify_run.splitlines()
    assert lines[0] == "python - <<'PY'"
    assert lines[-1] == "PY"
    script = "\n".join(lines[1:-1])

    version = "0.2.50"
    wheel_name = f"modelaudit-{version}-py3-none-any.whl"
    sdist_name = f"modelaudit-{version}.tar.gz"
    contents = {wheel_name: b"original wheel", sdist_name: b"original sdist"}
    dist_path = tmp_path / "dist"
    dist_path.mkdir()
    for filename, content in contents.items():
        (dist_path / filename).write_bytes(content)
    project_version = "0.2.49" if mutation == "wrong-tag-version" else version
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "modelaudit"\nversion = "{project_version}"\n', encoding="utf-8"
    )

    urls: list[dict[str, Any]] = [
        {"filename": filename, "yanked": False, "digests": {"sha256": hashlib.sha256(content).hexdigest()}}
        for filename, content in contents.items()
    ]
    payload: dict[str, Any] = {"info": {"version": version}, "urls": urls}
    if mutation == "missing-local":
        (dist_path / sdist_name).unlink()
    elif mutation == "extra-local":
        (dist_path / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    elif mutation == "wrong-pypi-version":
        payload["info"]["version"] = "0.2.49"
    elif mutation == "missing-pypi-file":
        urls.pop()
    elif mutation == "yanked":
        urls[0]["yanked"] = True
    elif mutation == "invalid-digest":
        urls[0]["digests"]["sha256"] = "not-a-sha256"
    elif mutation == "hash-mismatch":
        urls[0]["digests"]["sha256"] = "0" * 64

    def fake_urlopen(url: str, timeout: int = 20) -> io.BytesIO:
        assert url == f"https://pypi.org/pypi/modelaudit/{version}/json"
        assert timeout == 20
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EXPECTED_VERSION", "v0.2.50" if mutation == "invalid-version" else version)
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    if should_pass:
        exec(compile(script, "root-provenance-recovery-step", "exec"), {})
    else:
        with pytest.raises(SystemExit):
            exec(compile(script, "root-provenance-recovery-step", "exec"), {})
