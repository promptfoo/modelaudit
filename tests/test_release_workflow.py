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
