from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def _load_docker_workflow() -> dict[str, Any]:
    workflow_path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "docker-image-test.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _jobs(workflow: dict[str, Any]) -> dict[str, Any]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def _job_steps(workflow: dict[str, Any], job_name: str) -> list[dict[str, Any]]:
    job = _jobs(workflow)[job_name]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)
    return steps


def _step_by_name(steps: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for step in steps:
        if step.get("name") == name:
            return step
    raise AssertionError(f"Step {name!r} not found")


def test_docker_success_job_waits_for_full_image_result() -> None:
    workflow = _load_docker_workflow()

    success_job = _jobs(workflow)["docker-ci-success"]
    assert isinstance(success_job, dict)
    assert success_job["needs"] == ["build-test-lightweight", "build-test-full"]
    assert success_job["if"] == "always()"

    steps = _job_steps(workflow, "docker-ci-success")
    check_step = _step_by_name(steps, "Check if required jobs succeeded")
    check_run = check_step["run"]
    assert 'LIGHTWEIGHT_RESULT="${{ needs.build-test-lightweight.result }}"' in check_run
    assert 'FULL_RESULT="${{ needs.build-test-full.result }}"' in check_run
    assert 'echo "Full Docker build result: $FULL_RESULT"' in check_run
    assert '"$LIGHTWEIGHT_RESULT" == "success" || "$LIGHTWEIGHT_RESULT" == "skipped"' in check_run
    assert '"$FULL_RESULT" == "success" || "$FULL_RESULT" == "skipped"' in check_run


def test_full_image_ml_dependency_probe_fails_hard() -> None:
    workflow = _load_docker_workflow()

    full_job = _jobs(workflow)["build-test-full"]
    assert isinstance(full_job, dict)
    assert full_job["needs"] == ["changes", "build-test-lightweight"]
    assert full_job["if"] == "needs.changes.outputs.full-image == 'true'"

    steps = _job_steps(workflow, "build-test-full")
    dependency_step = _step_by_name(steps, "Verify ML dependencies in full image")
    dependency_run = dependency_step["run"]
    assert (
        'docker run --rm modelaudit:full python -c "import tensorflow, torch, onnx; '
        "print('All ML dependencies available')\""
    ) in dependency_run
    assert "|| echo" not in dependency_run
    assert "Some ML dependencies missing" not in dependency_run
