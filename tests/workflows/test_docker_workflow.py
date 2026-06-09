from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from scripts.validate_docker_publish_tag import normalize_publish_tag

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"
_ACTION_DIR = _REPO_ROOT / ".github" / "actions"
_PINNED_ACTION_RE = re.compile(r"^[^@]+@[0-9a-f]{40}$")
_PINNED_DOCKER_ACTION_RE = re.compile(r"^docker://[^@]+@sha256:[0-9a-f]{64}$")


def _iter_workflow_paths(workflow_dir: Path) -> Iterator[Path]:
    yield from sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))


def _iter_action_paths(action_dir: Path) -> Iterator[Path]:
    yield from sorted((*action_dir.glob("**/action.yml"), *action_dir.glob("**/action.yaml")))


def _iter_step_uses(steps: Any) -> Iterator[str]:
    if not isinstance(steps, list):
        return
    for step in steps:
        if isinstance(step, dict) and isinstance(step.get("uses"), str):
            yield step["uses"]


def _iter_workflow_uses(workflow: Any) -> Iterator[str]:
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        return
    for job in workflow["jobs"].values():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            yield job["uses"]
        yield from _iter_step_uses(job.get("steps"))


def _iter_action_uses(action: Any) -> Iterator[str]:
    if not isinstance(action, dict) or not isinstance(action.get("runs"), dict):
        return
    runs = action["runs"]
    yield from _iter_step_uses(runs.get("steps"))
    image = runs.get("image")
    if isinstance(image, str) and image.startswith("docker://"):
        yield image


def _append_mutable_refs(config_path: Path, uses_values: Iterator[str], mutable_refs: list[str]) -> None:
    for uses_value in uses_values:
        if uses_value.startswith("./"):
            continue
        is_pinned = (
            _PINNED_DOCKER_ACTION_RE.fullmatch(uses_value)
            if uses_value.startswith("docker://")
            else _PINNED_ACTION_RE.fullmatch(uses_value)
        )
        if not is_pinned:
            relative_path = config_path.relative_to(_REPO_ROOT).as_posix()
            mutable_refs.append(f"{relative_path}: {uses_value}")


def test_external_github_actions_are_pinned_to_commit_sha() -> None:
    mutable_refs: list[str] = []

    for workflow_path in _iter_workflow_paths(_WORKFLOW_DIR):
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        _append_mutable_refs(workflow_path, _iter_workflow_uses(workflow), mutable_refs)

    for action_path in _iter_action_paths(_ACTION_DIR):
        action = yaml.safe_load(action_path.read_text(encoding="utf-8"))
        _append_mutable_refs(action_path, _iter_action_uses(action), mutable_refs)

    assert mutable_refs == []


def test_action_reference_discovery_covers_yaml_and_action_metadata(tmp_path: Path) -> None:
    workflow_dir = tmp_path / "workflows"
    action_dir = tmp_path / "actions"
    workflow_dir.mkdir()
    (action_dir / "example").mkdir(parents=True)
    for path in (
        workflow_dir / "first.yml",
        workflow_dir / "second.yaml",
        action_dir / "example" / "action.yml",
    ):
        path.touch()

    assert [path.name for path in _iter_workflow_paths(workflow_dir)] == ["first.yml", "second.yaml"]
    assert [path.name for path in _iter_action_paths(action_dir)] == ["action.yml"]

    workflow = {
        "jobs": {
            "reusable": {"uses": "owner/workflow@main"},
            "steps": {
                "steps": [
                    {"uses": "owner/action@main", "with": {"uses": "plain input value"}},
                ]
            },
        }
    }
    composite_action = {
        "inputs": {"uses": {"description": "An ordinary input"}},
        "runs": {"using": "composite", "steps": [{"uses": "owner/composite-step@main"}]},
    }
    docker_action = {
        "runs": {"using": "docker", "image": "docker://ghcr.io/owner/action:latest"},
    }
    local_docker_action = {
        "runs": {"using": "docker", "image": "Dockerfile"},
    }

    assert list(_iter_workflow_uses(workflow)) == ["owner/workflow@main", "owner/action@main"]
    assert list(_iter_action_uses(composite_action)) == ["owner/composite-step@main"]
    assert list(_iter_action_uses(docker_action)) == ["docker://ghcr.io/owner/action:latest"]
    assert list(_iter_action_uses(local_docker_action)) == []


def test_action_pin_validation_rejects_mutable_refs() -> None:
    config_path = _WORKFLOW_DIR / "example.yml"
    mutable_refs: list[str] = []

    _append_mutable_refs(
        config_path,
        iter(
            (
                "./local-action",
                f"owner/action@{'a' * 40}",
                f"docker://ghcr.io/owner/action@sha256:{'b' * 64}",
                "owner/action@v1",
                "docker://ghcr.io/owner/action:latest",
            )
        ),
        mutable_refs,
    )

    assert mutable_refs == [
        ".github/workflows/example.yml: owner/action@v1",
        ".github/workflows/example.yml: docker://ghcr.io/owner/action:latest",
    ]


def test_optional_v_prefix_preserves_maximum_docker_tag_length() -> None:
    normalized_tag = f"1.2.3-{'a' * 122}"
    overlong_tag = f"{normalized_tag}a"

    assert len(normalized_tag) == 128
    assert normalize_publish_tag(normalized_tag) == normalized_tag
    assert normalize_publish_tag(f"v{normalized_tag}") == normalized_tag
    assert normalize_publish_tag(overlong_tag) is None
    assert normalize_publish_tag(f"v{overlong_tag}") is None
