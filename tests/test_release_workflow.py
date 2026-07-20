from __future__ import annotations

from pathlib import Path
from typing import Any, cast

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

    dispatch_inputs = _workflow_triggers(workflow)["workflow_dispatch"]["inputs"]
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
    assert release_action_step["if"] == "steps.manual.outputs.manual_release != 'true'"

    ensure_release_step = _step_by_name(release_steps, "Ensure manual GitHub releases exist")
    assert ensure_release_step["if"] == "steps.manual.outputs.manual_release == 'true'"
    ensure_release_run = ensure_release_step["run"]
    assert 'gh release view "$ROOT_TAG"' in ensure_release_run
    assert 'gh release view "$PICKLESCAN_TAG"' in ensure_release_run
    assert 'gh release create "$ROOT_TAG"' in ensure_release_run
    assert 'gh release create "$PICKLESCAN_TAG"' in ensure_release_run


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


def test_release_workflow_refreshes_both_standalone_package_locks() -> None:
    release_steps = _job_steps(_load_release_workflow(), "release-please")

    sync_step = _step_by_name(release_steps, "Sync standalone package lock with pyproject.toml")
    assert sync_step["working-directory"] == "packages/modelaudit-picklescan"
    sync_run = sync_step["run"]
    assert "uv lock" in sync_run
    assert "cargo check --manifest-path Cargo.toml\n" in sync_run
    assert "cargo check --manifest-path Cargo.toml --locked" in sync_run
    assert "git diff --quiet uv.lock Cargo.lock" in sync_run
    assert "git add uv.lock Cargo.lock" in sync_run


def test_release_changelogs_keep_one_current_unreleased_section() -> None:
    root_dir = Path(__file__).resolve().parents[1]
    changelogs = (root_dir / "CHANGELOG.md", root_dir / "packages" / "modelaudit-picklescan" / "CHANGELOG.md")

    for changelog in changelogs:
        headings = [line for line in changelog.read_text(encoding="utf-8").splitlines() if line.startswith("## ")]
        assert headings[0] == "## [Unreleased]"
        assert headings.count("## [Unreleased]") == 1


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
    assert "--no-cache-dir" in smoke_run
    assert '"modelaudit-picklescan==${EXPECTED_VERSION}"' in smoke_run
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
