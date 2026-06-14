from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_INTEGRATION = "needs.changes.outputs.integration == 'true'"
_PYTHON = "needs.changes.outputs.python == 'true'"
_WORKFLOWS = "needs.changes.outputs.workflows == 'true'"
_DEPENDENCIES = "needs.changes.outputs.dependencies == 'true'"
_PICKLESCAN = "needs.changes.outputs.picklescan == 'true'"
_CORE_PYTHON = f"{_INTEGRATION} || {_PYTHON} || {_WORKFLOWS}"
_DEPENDENCY_SURFACE = f"{_INTEGRATION} || {_DEPENDENCIES} || {_WORKFLOWS}"
_OPTIONAL_DEPENDENCY_LANES = f"{_INTEGRATION} || {_DEPENDENCIES}"
_VENDORED_PROTOS = f"{_INTEGRATION} || {_PYTHON} || {_DEPENDENCIES}"
_BUILD = f"{_INTEGRATION} || {_PYTHON} || {_DEPENDENCIES} || {_WORKFLOWS}"
_PICKLESCAN_SURFACE = f"{_INTEGRATION} || {_PICKLESCAN} || {_WORKFLOWS}"
_NUMPY_MATRIX = (
    "${{ github.event_name == 'pull_request' && "
    'fromJSON(\'[{"python-version":"3.10","numpy-mode":"1.x"},{"python-version":"3.11","numpy-mode":"2.x"}]\') || '
    'fromJSON(\'[{"python-version":"3.10","numpy-mode":"1.x"},{"python-version":"3.11","numpy-mode":"2.x"},'
    '{"python-version":"3.12","numpy-mode":"2.x"},{"python-version":"3.13","numpy-mode":"2.x"}]\') }}'
)
_TEST_MATRIX = (
    "${{ github.event_name == 'pull_request' && fromJSON('[\"3.10\", \"3.13\"]') || "
    'fromJSON(\'["3.10", "3.11", "3.12", "3.13"]\') }}'
)


def _github_output_assignment(name: str, expression: str) -> str:
    return f'{name}="${{{{ {expression} }}}}"'


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
        "lint": _CORE_PYTHON,
        "license-check": _DEPENDENCY_SURFACE,
        "uv-lock-check": _DEPENDENCY_SURFACE,
        "type-check": _CORE_PYTHON,
        "quick-feedback": _CORE_PYTHON,
        "windows-tests": _CORE_PYTHON,
        "test": _CORE_PYTHON,
        "coverage": f"{_INTEGRATION} || {_WORKFLOWS}",
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
    assert "github.event_name == 'pull_request'" in dependency_audit_job["if"]
    assert "merge_group" not in dependency_audit_job["if"]


def test_python_ci_merge_group_executes_real_pytest_steps_and_full_matrices() -> None:
    workflow = _load_python_ci_workflow()

    test_job = _jobs(workflow)["test"]
    assert isinstance(test_job, dict)
    assert test_job["strategy"]["matrix"]["python-version"] == _TEST_MATRIX

    test_steps = _job_steps(workflow, "test")
    pr_fast_step = _step_by_name(test_steps, "Run fast tests with fail-fast (PRs)")
    assert pr_fast_step["if"] == "github.event_name == 'pull_request'"
    assert 'echo "MODELAUDIT_PYTHON_TEST_JOB_RAN=1" >> "$GITHUB_ENV"' in pr_fast_step["run"]
    assert "uv run pytest tests -x --maxfail=1 -n auto" in pr_fast_step["run"]

    integration_fast_step = _step_by_name(test_steps, "Run fast tests (integration event)")
    assert integration_fast_step["if"] == _INTEGRATION
    assert 'echo "MODELAUDIT_PYTHON_TEST_JOB_RAN=1" >> "$GITHUB_ENV"' in integration_fast_step["run"]
    assert (
        'uv run pytest tests -n auto -m "not slow and not integration and not performance"'
        in integration_fast_step["run"]
    )

    integration_slow_step = _step_by_name(test_steps, "Run slow/integration tests (integration event only)")
    assert integration_slow_step["if"] == f"{_INTEGRATION} && matrix.python-version == '3.12'"
    assert 'echo "MODELAUDIT_PYTHON_TEST_JOB_RAN=1" >> "$GITHUB_ENV"' in integration_slow_step["run"]
    assert 'uv run pytest tests -n auto -m "slow or integration or performance"' in integration_slow_step["run"]

    verify_step = _step_by_name(test_steps, "Verify Python test command ran")
    assert verify_step["if"] == "always()"
    assert 'test "${MODELAUDIT_PYTHON_TEST_JOB_RAN:-}" = "1"' in verify_step["run"]

    coverage_job = _jobs(workflow)["coverage"]
    assert isinstance(coverage_job, dict)
    assert coverage_job["if"] == f"{_INTEGRATION} || {_WORKFLOWS}"

    numpy_job = _jobs(workflow)["test-numpy-compatibility"]
    assert isinstance(numpy_job, dict)
    assert numpy_job["strategy"]["matrix"]["include"] == _NUMPY_MATRIX


def test_python_ci_keeps_pr_label_slow_logic_pr_only() -> None:
    workflow = _load_python_ci_workflow()
    slow_step = _step_by_name(_job_steps(workflow, "test"), "Run slow/integration tests on PR (if labeled)")
    condition = slow_step["if"]
    assert "github.event_name == 'pull_request'" in condition
    assert "contains(github.event.pull_request.labels.*.name, 'run-slow-tests')" in condition
    assert "merge_group" not in condition


def test_python_ci_success_requires_expected_jobs_to_report_exact_success() -> None:
    workflow = _load_python_ci_workflow()
    gate_script = _step_by_name(_job_steps(workflow, "ci-success"), "Check if all jobs succeeded")["run"]

    assert 'if [[ "$expected" == "true" && "$result" != "success" ]]; then' in gate_script
    assert '[[ "$CHANGES_RESULT" == "success" ]] || FAILED=true' in gate_script
    assert _github_output_assignment("EXPECT_CORE_PYTHON", _CORE_PYTHON) in gate_script
    assert (
        _github_output_assignment(
            "EXPECT_DEPENDENCY_AUDIT",
            f"github.event_name == 'pull_request' && ({_DEPENDENCIES} || {_WORKFLOWS} || {_PYTHON} || {_PICKLESCAN})",
        )
        in gate_script
    )
    assert _github_output_assignment("EXPECT_OPTIONAL_DEPENDENCY_LANES", _OPTIONAL_DEPENDENCY_LANES) in gate_script
    assert _github_output_assignment("EXPECT_COVERAGE", f"{_INTEGRATION} || {_WORKFLOWS}") in gate_script
    assert 'require_success "$EXPECT_CORE_PYTHON" "$TEST_RESULT" "test"' in gate_script
    assert 'require_success "$EXPECT_COVERAGE" "$COVERAGE_RESULT" "coverage"' in gate_script
    assert (
        'require_success "$EXPECT_OPTIONAL_DEPENDENCY_LANES" "$NUMPY_RESULT" "test-numpy-compatibility"' in gate_script
    )
    assert 'require_success "$EXPECT_BUILD" "$BUILD_RESULT" "build"' in gate_script
    assert 'require_success "$EXPECT_PICKLESCAN" "$PICKLESCAN_RESULT" "picklescan-package"' in gate_script
    assert 'require_success "$EXPECT_OPTIONAL_DEPENDENCY_LANES" "$EXTRAS_RESULT" "test-extras-smoke"' in gate_script
