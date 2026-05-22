from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PINNED_PYTHON_IMAGE_RE = re.compile(r"^python:(?P<version>\d+\.\d+-slim)@sha256:(?P<digest>[0-9a-f]{64})$")
_PYTHON_3_12_SLIM_DIGEST = "401f6e1a67dad31a1bd78e9ad22d0ee0a3b52154e6bd30e90be696bb6a3d7461"
_PYTHON_3_13_SLIM_DIGEST = "e544a7fcbdf8555eceda66bf86cafb006c736339f76141918bcb812f3174c00a"


def _load_docker_workflow() -> dict[str, Any]:
    workflow_path = _REPO_ROOT / ".github" / "workflows" / "docker-image-test.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _dockerfile_lines(path: str) -> list[str]:
    return (_REPO_ROOT / path).read_text(encoding="utf-8").splitlines()


def _python_image_from_arg(path: str) -> str:
    lines = _dockerfile_lines(path)
    prefix = "ARG PYTHON_IMAGE="
    for line in lines:
        if line.startswith(prefix):
            return line.removeprefix(prefix)
    raise AssertionError(f"{path} does not define PYTHON_IMAGE")


def _assert_pinned_python_image(image: str, expected_version: str) -> None:
    match = _PINNED_PYTHON_IMAGE_RE.fullmatch(image)
    assert match is not None
    assert match.group("version") == expected_version


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


def test_dockerfiles_pin_python_base_images_by_digest() -> None:
    lightweight_image = _python_image_from_arg("Dockerfile")
    full_image = _python_image_from_arg("Dockerfile.full")

    assert full_image == lightweight_image
    _assert_pinned_python_image(lightweight_image, "3.13-slim")

    for path in ("Dockerfile", "Dockerfile.full"):
        lines = _dockerfile_lines(path)
        assert lines.count("FROM ${PYTHON_IMAGE} AS builder") == 1
        assert lines.count("FROM ${PYTHON_IMAGE} AS runtime") == 1

    tensorflow_from = _dockerfile_lines("Dockerfile.tensorflow")[0].removeprefix("FROM ")
    _assert_pinned_python_image(tensorflow_from, "3.12-slim")


def test_dockerfiles_use_current_python_base_digests() -> None:
    python_3_13_image = f"python:3.13-slim@sha256:{_PYTHON_3_13_SLIM_DIGEST}"
    python_3_12_image = f"python:3.12-slim@sha256:{_PYTHON_3_12_SLIM_DIGEST}"

    assert _python_image_from_arg("Dockerfile") == python_3_13_image
    assert _python_image_from_arg("Dockerfile.full") == python_3_13_image
    assert _dockerfile_lines("Dockerfile.tensorflow")[0] == f"FROM {python_3_12_image}"


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
