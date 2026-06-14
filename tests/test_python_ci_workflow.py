from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_INTEGRATION = "needs.changes.outputs.integration == 'true'"
_PYTHON = "needs.changes.outputs.python == 'true'"
_WORKFLOWS = "needs.changes.outputs.workflows == 'true'"
_DEPENDENCIES = "needs.changes.outputs.dependencies == 'true'"
_PICKLESCAN = "needs.changes.outputs.picklescan == 'true'"
_QUICK_FEEDBACK = f"github.event_name == 'pull_request' && ({_PYTHON} || {_WORKFLOWS})"
_CORE_FAST = f"{_INTEGRATION} || {_PYTHON} || {_WORKFLOWS}"
_SLOW = (
    f"{_INTEGRATION} || "
    "(github.event_name == 'pull_request' && contains(github.event.pull_request.labels.*.name, 'run-slow-tests'))"
)
_DEPENDENCY_AUDIT = (
    f"github.event_name == 'pull_request' && ({_DEPENDENCIES} || {_WORKFLOWS} || {_PYTHON} || {_PICKLESCAN})"
)
_DEPENDENCY_SURFACE = f"{_INTEGRATION} || {_DEPENDENCIES} || {_WORKFLOWS}"
_OPTIONAL_DEPENDENCY_LANES = f"{_INTEGRATION} || {_DEPENDENCIES}"
_VENDORED_PROTOS = f"{_INTEGRATION} || {_PYTHON} || {_DEPENDENCIES}"
_BUILD = f"{_INTEGRATION} || {_PYTHON} || {_DEPENDENCIES} || {_WORKFLOWS}"
_PICKLESCAN_SURFACE = f"{_INTEGRATION} || {_PICKLESCAN} || {_WORKFLOWS}"
_COVERAGE = f"{_INTEGRATION} || {_WORKFLOWS}"


def _github_output_assignment(name: str, expression: str) -> str:
    return f'{name}="${{{{ {expression} }}}}"'


def _matrix_options(expression: str) -> list[Any]:
    matches = re.findall(r"fromJSON\('([^']+)'\)", expression)
    assert matches
    return [json.loads(match) for match in matches]


def _load_python_ci_workflow() -> dict[str, Any]:
    workflow_path = _REPO_ROOT / ".github" / "workflows" / "test.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _workflow_triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    raw_workflow = cast(dict[Any, Any], workflow)
    triggers = raw_workflow.get("on", raw_workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


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


def test_python_ci_triggers_merge_group_and_classifies_integration_events() -> None:
    workflow = _load_python_ci_workflow()

    triggers = _workflow_triggers(workflow)
    assert triggers["merge_group"] == {"types": ["checks_requested"]}

    concurrency = workflow["concurrency"]
    assert isinstance(concurrency, dict)
    assert concurrency["group"] == "${{ github.workflow }}-${{ github.ref }}"
    assert concurrency["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"

    changes_job = _jobs(workflow)["changes"]
    assert isinstance(changes_job, dict)
    assert changes_job["outputs"]["integration"] == "${{ steps.classify.outputs.integration }}"

    classify_step = _step_by_name(_job_steps(workflow, "changes"), "Classify CI event")
    classify_run = classify_step["run"]
    assert '[[ "$GITHUB_REF" == "refs/heads/main" || "$GITHUB_EVENT_NAME" == "merge_group" ]]' in classify_run
    assert 'echo "integration=true" >> "$GITHUB_OUTPUT"' in classify_run
    assert 'echo "integration=false" >> "$GITHUB_OUTPUT"' in classify_run


def test_python_ci_merge_group_fail_closed_scheduling_covers_integration_surface() -> None:
    workflow = _load_python_ci_workflow()
    jobs = _jobs(workflow)

    expected_conditions = {
        "lint": _CORE_FAST,
        "quick-feedback": _QUICK_FEEDBACK,
        "windows-tests": _CORE_FAST,
        "test": _CORE_FAST,
        "slow-tests": _SLOW,
        "license-check": _DEPENDENCY_SURFACE,
        "uv-lock-check": _DEPENDENCY_SURFACE,
        "type-check": _CORE_FAST,
        "coverage": _COVERAGE,
        "test-numpy-compatibility": _OPTIONAL_DEPENDENCY_LANES,
        "test-vendored-protos": _VENDORED_PROTOS,
        "test-proto-reproducibility": _VENDORED_PROTOS,
        "test-extras-smoke": _OPTIONAL_DEPENDENCY_LANES,
        "build": _BUILD,
        "picklescan-package": _PICKLESCAN_SURFACE,
    }

    for job_name, expected_condition in expected_conditions.items():
        job = jobs[job_name]
        assert isinstance(job, dict)
        assert job["if"] == expected_condition

    dependency_audit_job = jobs["dependency-audit"]
    assert isinstance(dependency_audit_job, dict)
    assert dependency_audit_job["if"] == _DEPENDENCY_AUDIT
    assert "merge_group" not in dependency_audit_job["if"]


def test_python_ci_merge_group_uses_sharded_fast_matrices_and_real_pytest_steps() -> None:
    workflow = _load_python_ci_workflow()
    jobs = _jobs(workflow)

    windows_job = jobs["windows-tests"]
    assert isinstance(windows_job, dict)
    assert _matrix_options(windows_job["strategy"]["matrix"]["include"]) == [
        [{"shard-count": 1, "shard-index": 0, "shard-name": "1/1"}],
        [
            {"shard-count": 2, "shard-index": 0, "shard-name": "1/2"},
            {"shard-count": 2, "shard-index": 1, "shard-name": "2/2"},
        ],
    ]

    windows_steps = _job_steps(workflow, "windows-tests")
    windows_pr_step = _step_by_name(windows_steps, "Run fast tests with fail-fast")
    assert windows_pr_step["if"] == "github.event_name == 'pull_request' && needs.changes.outputs.workflows != 'true'"
    assert "--maxfail=1" in windows_pr_step["run"]
    assert "--modelaudit-shard-count ${{ matrix.shard-count }}" in windows_pr_step["run"]
    windows_integration_step = _step_by_name(windows_steps, "Run exhaustive fast-test shard")
    assert windows_integration_step["if"] == f"{_INTEGRATION} || {_WORKFLOWS}"
    assert "--maxfail=1" not in windows_integration_step["run"]

    test_job = jobs["test"]
    assert isinstance(test_job, dict)
    assert _matrix_options(test_job["strategy"]["matrix"]["include"]) == [
        [
            {"python-version": "3.10", "shard-count": 1, "shard-index": 0, "shard-name": "1/1"},
            {"python-version": "3.13", "shard-count": 1, "shard-index": 0, "shard-name": "1/1"},
        ],
        [
            {
                "python-version": python_version,
                "shard-count": 2,
                "shard-index": shard_index,
                "shard-name": f"{shard_index + 1}/2",
            }
            for python_version in ("3.10", "3.11", "3.12", "3.13")
            for shard_index in (0, 1)
        ],
    ]

    test_steps = _job_steps(workflow, "test")
    pr_fast_step = _step_by_name(test_steps, "Run fast tests with fail-fast")
    assert pr_fast_step["if"] == "github.event_name == 'pull_request' && needs.changes.outputs.workflows != 'true'"
    assert "uv run pytest tests -x --maxfail=1 -n auto" in pr_fast_step["run"]
    assert "--modelaudit-shard-count ${{ matrix.shard-count }}" in pr_fast_step["run"]
    integration_fast_step = _step_by_name(test_steps, "Run exhaustive fast-test shard")
    assert integration_fast_step["if"] == f"{_INTEGRATION} || {_WORKFLOWS}"
    assert "uv run pytest tests -n auto \\" in integration_fast_step["run"]
    assert "--modelaudit-shard-index ${{ matrix.shard-index }} \\" in integration_fast_step["run"]

    coverage_job = jobs["coverage"]
    assert isinstance(coverage_job, dict)
    assert coverage_job["if"] == _COVERAGE
    assert coverage_job["strategy"]["matrix"]["shard"] == list(range(10))

    numpy_job = jobs["test-numpy-compatibility"]
    assert isinstance(numpy_job, dict)
    assert _matrix_options(numpy_job["strategy"]["matrix"]["include"]) == [
        [
            {"python-version": "3.10", "numpy-mode": "1.x"},
            {"python-version": "3.11", "numpy-mode": "2.x"},
        ],
        [
            {"python-version": "3.10", "numpy-mode": "1.x"},
            {"python-version": "3.11", "numpy-mode": "2.x"},
            {"python-version": "3.12", "numpy-mode": "2.x"},
            {"python-version": "3.13", "numpy-mode": "2.x"},
        ],
    ]


def test_python_ci_keeps_pr_label_logic_in_the_dedicated_slow_job() -> None:
    workflow = _load_python_ci_workflow()
    jobs = _jobs(workflow)

    slow_job = jobs["slow-tests"]
    assert isinstance(slow_job, dict)
    assert slow_job["if"] == _SLOW

    slow_steps = _job_steps(workflow, "slow-tests")
    slow_run = _step_by_name(slow_steps, "Run slow, integration, and performance tests")["run"]
    assert 'uv run pytest tests -n auto -m "slow or integration or performance"' in slow_run

    fast_steps = _job_steps(workflow, "test")
    fast_step_names = {step.get("name") for step in fast_steps}
    assert "Run slow/integration tests on PR (if labeled)" not in fast_step_names
    assert "Run slow/integration tests (integration event only)" not in fast_step_names


def test_python_ci_success_requires_expected_jobs_to_report_exact_success() -> None:
    workflow = _load_python_ci_workflow()
    gate_script = _step_by_name(_job_steps(workflow, "ci-success"), "Check if all jobs succeeded")["run"]

    assert 'if [[ "$expected" == "true" && "$result" != "success" ]]; then' in gate_script
    assert '[[ "$CHANGES_RESULT" == "success" ]] || FAILED=true' in gate_script
    assert _github_output_assignment("EXPECT_QUICK_FEEDBACK", _QUICK_FEEDBACK) in gate_script
    assert _github_output_assignment("EXPECT_CORE_FAST", _CORE_FAST) in gate_script
    assert _github_output_assignment("EXPECT_SLOW", _SLOW) in gate_script
    assert _github_output_assignment("EXPECT_DEPENDENCY_AUDIT", _DEPENDENCY_AUDIT) in gate_script
    assert _github_output_assignment("EXPECT_DEPENDENCY_SURFACE", _DEPENDENCY_SURFACE) in gate_script
    assert _github_output_assignment("EXPECT_OPTIONAL_DEPENDENCY_LANES", _OPTIONAL_DEPENDENCY_LANES) in gate_script
    assert _github_output_assignment("EXPECT_VENDORED_PROTOS", _VENDORED_PROTOS) in gate_script
    assert _github_output_assignment("EXPECT_BUILD", _BUILD) in gate_script
    assert _github_output_assignment("EXPECT_PICKLESCAN", _PICKLESCAN_SURFACE) in gate_script
    assert _github_output_assignment("EXPECT_COVERAGE", _COVERAGE) in gate_script
    assert 'require_success "$EXPECT_QUICK_FEEDBACK" "$QUICK_FEEDBACK_RESULT" "quick-feedback"' in gate_script
    assert 'require_success "$EXPECT_CORE_FAST" "$WINDOWS_RESULT" "windows-tests"' in gate_script
    assert 'require_success "$EXPECT_CORE_FAST" "$TEST_RESULT" "test"' in gate_script
    assert 'require_success "$EXPECT_SLOW" "$SLOW_RESULT" "slow-tests"' in gate_script
    assert 'require_success "$EXPECT_COVERAGE" "$COVERAGE_RESULT" "coverage"' in gate_script
    assert (
        'require_success "$EXPECT_OPTIONAL_DEPENDENCY_LANES" "$NUMPY_RESULT" "test-numpy-compatibility"' in gate_script
    )
    assert 'require_success "$EXPECT_OPTIONAL_DEPENDENCY_LANES" "$EXTRAS_RESULT" "test-extras-smoke"' in gate_script
