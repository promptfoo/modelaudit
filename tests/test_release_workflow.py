from __future__ import annotations

import io
import json
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, cast

import pytest
import yaml


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
    }

    release_steps = _job_steps(workflow, "release-please")
    manual_step = _step_by_name(release_steps, "Resolve manual release inputs")
    assert manual_step["id"] == "manual"
    assert manual_step["env"] == {
        "ROOT_VERSION": "${{ github.event.inputs.root_version || '' }}",
        "PICKLESCAN_VERSION": "${{ github.event.inputs.picklescan_version || '' }}",
    }

    release_action_step = next(
        step for step in release_steps if step.get("uses", "").startswith("googleapis/release-please-action@")
    )
    assert (
        release_action_step["if"]
        == "steps.manual.outputs.manual_release != 'true' && github.event_name != 'repository_dispatch'"
    )

    ensure_release_step = _step_by_name(release_steps, "Ensure manual GitHub releases exist")
    assert ensure_release_step["if"] == "steps.manual.outputs.manual_release == 'true'"
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

    assert "uv sync --python 3.10 --frozen --extra all-ci" in type_check_step["run"]
    assert "uv run --python 3.10 --frozen mypy modelaudit/ tests/" in type_check_step["run"]
    assert type_check_step["run"].index("uv run --python 3.10 --frozen mypy") < type_check_step["run"].index(
        "uv cache prune --ci"
    )
    assert "UV_PROJECT_ENVIRONMENT" not in type_check_step.get("env", {})
    assert "uv python pin 3.12" in sync_step["run"]
    assert "uv sync --frozen --extra all-ci" in sync_step["run"]
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
    assert "deadline = time.monotonic() + 600" in wait_run
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
    assert "for attempt in {1..30}; do" in smoke_run
    assert "--no-cache-dir" in smoke_run
    assert '"modelaudit-picklescan==${EXPECTED_VERSION}"' in smoke_run
    assert 'if [[ "$attempt" -eq 30 ]]; then' in smoke_run
    assert "PyPI simple index" in smoke_run
    assert "exit 1" in smoke_run
    assert "sleep 10" in smoke_run
    assert 'md.version("modelaudit-picklescan")' in smoke_run
    assert 'find_spec("modelaudit_picklescan._rust")' in smoke_run
    assert 'clean_report.status.value != "complete"' in smoke_run
    assert 'malicious_report.verdict.value != "malicious"' in smoke_run
    assert 'finding.rule_code == "DANGEROUS_CALL"' in smoke_run


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
    assert "deadline = time.monotonic() + 600" in wait_run
    assert "modelaudit-{version}-py3-none-any.whl" in wait_run
    assert "modelaudit-{version}.tar.gz" in wait_run

    smoke_step = _step_by_name(steps, "Install published modelaudit and run end-to-end smoke tests")
    smoke_run = smoke_step["run"]
    assert "for attempt in {1..30}; do" in smoke_run
    assert "--no-cache-dir" in smoke_run
    assert '"modelaudit[all]==${EXPECTED_VERSION}"' in smoke_run
    assert 'if [[ "$attempt" -eq 30 ]]; then' in smoke_run
    assert "PyPI simple index" in smoke_run
    assert "exit 1" in smoke_run
    assert "sleep 10" in smoke_run
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
