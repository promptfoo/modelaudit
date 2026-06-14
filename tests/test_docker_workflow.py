from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PINNED_PYTHON_IMAGE_RE = re.compile(r"^python:(?P<version>\d+\.\d+-slim)@sha256:(?P<digest>[0-9a-f]{64})$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _load_docker_workflow() -> dict[str, Any]:
    workflow_path = _REPO_ROOT / ".github" / "workflows" / "docker-image-test.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _load_docker_publish_workflow() -> dict[str, Any]:
    workflow_path = _REPO_ROOT / ".github" / "workflows" / "docker-publish.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _workflow_triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    raw_workflow = cast(dict[Any, Any], workflow)
    triggers = raw_workflow.get("on", raw_workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


def _run_tag_validator(tag: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_REPO_ROOT / "scripts" / "validate_docker_publish_tag.py"), tag],
        check=False,
        capture_output=True,
        text=True,
    )


def _dockerfile_lines(path: str) -> list[str]:
    return (_REPO_ROOT / path).read_text(encoding="utf-8").splitlines()


def _python_image_from_arg(path: str) -> str:
    return _dockerfile_arg(path, "PYTHON_IMAGE")


def _dockerfile_arg(path: str, name: str) -> str:
    lines = _dockerfile_lines(path)
    prefix = f"ARG {name}="
    for line in lines:
        if line.startswith(prefix):
            return line.removeprefix(prefix)
    raise AssertionError(f"{path} does not define {name}")


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


def test_docker_publish_manual_dispatch_is_guarded_before_push() -> None:
    workflow = _load_docker_publish_workflow()

    dispatch_inputs = _workflow_triggers(workflow)["workflow_dispatch"]["inputs"]
    assert dispatch_inputs["tag"] == {
        "description": "Image tag (e.g., 0.2.26)",
        "required": True,
        "type": "string",
    }

    validation_job = _jobs(workflow)["validate-manual-publish"]
    assert validation_job["if"] == "github.event_name == 'workflow_dispatch'"
    assert validation_job["outputs"] == {
        "image_tag": "${{ steps.validate.outputs.image_tag }}",
        "source_ref": "${{ steps.validate.outputs.source_ref }}",
        "source_sha": "${{ steps.validate.outputs.source_sha }}",
    }
    assert validation_job["environment"] == {"name": "ghcr-manual-publish"}

    validation_steps = _job_steps(workflow, "validate-manual-publish")
    validation_checkout = _step_by_name(validation_steps, "Checkout repo")
    assert validation_checkout["with"] == {"ref": "${{ github.event.repository.default_branch }}"}
    validation_step = _step_by_name(validation_steps, "Validate manual image tag")
    assert validation_step["id"] == "validate"
    assert validation_step["env"] == {"IMAGE_TAG": "${{ inputs.tag }}"}
    validation_run = validation_step["run"]
    assert 'SOURCE_TAG="$(python scripts/validate_docker_publish_tag.py "$IMAGE_TAG")"' in validation_run
    assert 'SOURCE_REF="refs/tags/v${SOURCE_TAG}"' in validation_run
    assert 'git fetch --no-tags --depth=1 origin "$SOURCE_REF"' in validation_run
    assert "SOURCE_SHA=\"$(git rev-parse 'FETCH_HEAD^{commit}')\"" in validation_run
    assert 'echo "image_tag=$SOURCE_TAG" >> "$GITHUB_OUTPUT"' in validation_run
    assert 'echo "source_ref=$SOURCE_REF" >> "$GITHUB_OUTPUT"' in validation_run
    assert 'echo "source_sha=$SOURCE_SHA" >> "$GITHUB_OUTPUT"' in validation_run

    release_validation_job = _jobs(workflow)["validate-release-publish"]
    assert release_validation_job["if"] == (
        "github.event_name == 'release' && startsWith(github.event.release.tag_name, 'v')"
    )
    assert release_validation_job["outputs"] == validation_job["outputs"]
    assert "environment" not in release_validation_job
    release_validation_steps = _job_steps(workflow, "validate-release-publish")
    release_checkout = _step_by_name(release_validation_steps, "Checkout repo")
    assert release_checkout["with"] == {"ref": "${{ github.event.repository.default_branch }}"}
    release_validation_step = _step_by_name(release_validation_steps, "Validate release image tag")
    assert release_validation_step["env"] == {"IMAGE_TAG": "${{ github.event.release.tag_name }}"}
    release_validation_run = release_validation_step["run"]
    assert 'SOURCE_TAG="$(python scripts/validate_docker_publish_tag.py "$IMAGE_TAG")"' in release_validation_run
    assert '[[ "$IMAGE_TAG" != "v${SOURCE_TAG}" ]]' in release_validation_run
    assert "Docker images are published only for root vX.Y.Z releases" in release_validation_run
    assert 'SOURCE_REF="refs/tags/v${SOURCE_TAG}"' in release_validation_run
    assert 'echo "image_tag=$SOURCE_TAG" >> "$GITHUB_OUTPUT"' in release_validation_run

    publish_job = _jobs(workflow)["publish"]
    assert publish_job["needs"] == ["validate-manual-publish", "validate-release-publish"]
    assert " ".join(publish_job["if"].split()) == (
        "${{ always() && ( "
        "(github.event_name == 'workflow_dispatch' && needs.validate-manual-publish.result == 'success') || "
        "(github.event_name == 'release' && needs.validate-release-publish.result == 'success') "
        ") }}"
    )
    publish_checkout = _step_by_name(_job_steps(workflow, "publish"), "Checkout repo")
    assert publish_checkout["with"] == {
        "ref": (
            "${{ github.event_name == 'workflow_dispatch' && "
            "needs.validate-manual-publish.outputs.source_ref || "
            "needs.validate-release-publish.outputs.source_ref }}"
        )
    }

    publish_steps = _job_steps(workflow, "publish")
    source_step = _step_by_name(publish_steps, "Resolve source commit")
    assert source_step["id"] == "source"
    assert source_step["env"] == {
        "EXPECTED_SOURCE_SHA": (
            "${{ github.event_name == 'workflow_dispatch' && needs.validate-manual-publish.outputs.source_sha || "
            "needs.validate-release-publish.outputs.source_sha }}"
        )
    }
    assert 'SOURCE_SHA="$(git rev-parse HEAD)"' in source_step["run"]
    assert '[[ -n "$EXPECTED_SOURCE_SHA" && "$SOURCE_SHA" != "$EXPECTED_SOURCE_SHA" ]]' in source_step["run"]
    assert 'echo "Validated source commit changed before publish" >&2' in source_step["run"]
    assert "exit 1" in source_step["run"]
    assert 'echo "short_sha=${SOURCE_SHA:0:7}" >> "$GITHUB_OUTPUT"' in source_step["run"]
    assert "git rev-parse --short" not in source_step["run"]

    metadata_step = _step_by_name(publish_steps, "Extract metadata")
    assert metadata_step["with"]["context"] == "git"
    assert metadata_step["with"]["flavor"] == "latest=false"
    metadata_tags = metadata_step["with"]["tags"]
    assert "type=semver,pattern={{version}},enable=${{ github.event_name == 'release' }}" in metadata_tags
    assert "type=semver,pattern={{major}}.{{minor}},enable=${{ github.event_name == 'release' }}" in metadata_tags
    assert (
        "type=raw,value=latest,enable=${{ github.event_name == 'release' && !github.event.release.prerelease }}"
    ) in metadata_tags
    assert (
        "type=raw,value=${{ needs.validate-manual-publish.outputs.image_tag }},"
        "enable=${{ github.event_name == 'workflow_dispatch' }}"
    ) in metadata_tags

    verify_step = _step_by_name(publish_steps, "Verify published image")
    verify_run = verify_step["run"]
    assert "GITHUB_SHA" not in verify_run
    assert verify_run.count("sha-${{ steps.source.outputs.short_sha }}") == 2


@pytest.mark.parametrize(
    ("tag", "expected_tag"),
    [
        ("0.2.26", "0.2.26"),
        ("v0.2.26", "0.2.26"),
        ("1.0.0-rc.1", "1.0.0-rc.1"),
        ("2.10.0-alpha.1", "2.10.0-alpha.1"),
        ("1.2.3--", "1.2.3--"),
        (f"1.2.3-{'a' * 122}", f"1.2.3-{'a' * 122}"),
    ],
)
def test_docker_publish_tag_validator_allows_immutable_version_tags(tag: str, expected_tag: str) -> None:
    result = _run_tag_validator(tag)

    assert result.returncode == 0
    assert result.stdout == f"{expected_tag}\n"


@pytest.mark.parametrize(
    "tag",
    [
        "",
        "latest",
        "main",
        "sha-abcdef0",
        "0.2",
        "01.2.3",
        "0.02.3",
        "0.2.03",
        "0.2.3+build.1",
        "0.2.3/evil",
        "0.2.3-",
        "0.2.3-01",
        "0.2.3-rc..1",
        "0.2.3-\nlatest",
        " 0.2.3",
        f"1.2.3-{'a' * 123}",
    ],
)
def test_docker_publish_tag_validator_rejects_mutable_or_non_version_tags(tag: str) -> None:
    result = _run_tag_validator(tag)

    assert result.returncode != 0
    assert "only accept immutable version tags" in result.stderr


def test_dockerfiles_verify_pinned_rustup_init_instead_of_streaming_shell() -> None:
    expected_rustup_version = _dockerfile_arg("Dockerfile", "RUSTUP_VERSION")
    expected_amd64_sha256 = _dockerfile_arg("Dockerfile", "RUSTUP_INIT_X86_64_UNKNOWN_LINUX_GNU_SHA256")
    expected_arm64_sha256 = _dockerfile_arg("Dockerfile", "RUSTUP_INIT_AARCH64_UNKNOWN_LINUX_GNU_SHA256")

    assert re.fullmatch(r"\d+\.\d+\.\d+", expected_rustup_version)
    assert _SHA256_RE.fullmatch(expected_amd64_sha256)
    assert _SHA256_RE.fullmatch(expected_arm64_sha256)

    for path in ("Dockerfile", "Dockerfile.full"):
        content = (_REPO_ROOT / path).read_text(encoding="utf-8")
        assert "https://sh.rustup.rs" not in content
        assert "| sh" not in content
        assert "sh -s --" not in content
        assert _dockerfile_arg(path, "RUSTUP_VERSION") == expected_rustup_version
        assert _dockerfile_arg(path, "RUSTUP_INIT_X86_64_UNKNOWN_LINUX_GNU_SHA256") == expected_amd64_sha256
        assert _dockerfile_arg(path, "RUSTUP_INIT_AARCH64_UNKNOWN_LINUX_GNU_SHA256") == expected_arm64_sha256
        assert "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rustup_target}/rustup-init" in content
        assert "printf '%s  %s\\n' \"${rustup_sha256}\" /tmp/rustup-init > /tmp/rustup-init.sha256" in content
        assert "sha256sum -c /tmp/rustup-init.sha256" in content
        assert content.index("sha256sum -c /tmp/rustup-init.sha256") < content.index(
            "/tmp/rustup-init -y --profile minimal --default-toolchain"
        )


@pytest.mark.parametrize("dockerfile", ("Dockerfile", "Dockerfile.full"))
def test_dockerfiles_fallback_to_native_architecture_without_buildkit(dockerfile: str) -> None:
    lines = _dockerfile_lines(dockerfile)
    content = "\n".join(lines)
    architecture_case = 'case "${TARGETARCH:=$(dpkg --print-architecture)}" in'

    assert lines.count("ARG TARGETARCH") == 1
    assert not any(line.startswith("ARG TARGETARCH=") for line in lines)
    assert architecture_case in content


def test_docker_success_job_waits_for_all_image_results() -> None:
    workflow = _load_docker_workflow()

    success_job = _jobs(workflow)["docker-ci-success"]
    assert isinstance(success_job, dict)
    assert success_job["needs"] == ["build-test-lightweight", "build-test-full", "build-test-tensorflow"]
    assert success_job["if"] == "always()"

    steps = _job_steps(workflow, "docker-ci-success")
    check_step = _step_by_name(steps, "Check if required jobs succeeded")
    check_run = check_step["run"]
    assert 'LIGHTWEIGHT_RESULT="${{ needs.build-test-lightweight.result }}"' in check_run
    assert 'FULL_RESULT="${{ needs.build-test-full.result }}"' in check_run
    assert 'TENSORFLOW_RESULT="${{ needs.build-test-tensorflow.result }}"' in check_run
    assert 'echo "Full Docker build result: $FULL_RESULT"' in check_run
    assert 'echo "TensorFlow Docker build result: $TENSORFLOW_RESULT"' in check_run
    assert '"$LIGHTWEIGHT_RESULT" == "success" || "$LIGHTWEIGHT_RESULT" == "skipped"' in check_run
    assert '"$FULL_RESULT" == "success" || "$FULL_RESULT" == "skipped"' in check_run
    assert '"$TENSORFLOW_RESULT" == "success" || "$TENSORFLOW_RESULT" == "skipped"' in check_run


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


def test_tensorflow_image_changes_are_built_and_probed() -> None:
    workflow = _load_docker_workflow()

    tensorflow_job = _jobs(workflow)["build-test-tensorflow"]
    assert isinstance(tensorflow_job, dict)
    assert tensorflow_job["needs"] == "changes"
    assert tensorflow_job["if"] == "needs.changes.outputs.tensorflow-image == 'true'"

    steps = _job_steps(workflow, "build-test-tensorflow")
    build_step = _step_by_name(steps, "Build TensorFlow image")
    assert build_step["with"]["file"] == "Dockerfile.tensorflow"
    dependency_step = _step_by_name(steps, "Verify TensorFlow dependency and non-root runtime")
    dependency_run = dependency_step["run"]
    assert "import os, tensorflow" in dependency_run
    assert "assert os.getuid() == 10001" in dependency_run
