from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def _load_workflow(filename: str) -> dict[str, Any]:
    current_path = Path(__file__).resolve()
    workflow_path = next(
        (
            candidate_root / ".github" / "workflows" / filename
            for candidate_root in [current_path.parent, *current_path.parents]
            if (candidate_root / ".github" / "workflows" / filename).is_file()
        ),
        None,
    )
    if workflow_path is None:
        raise AssertionError(f"Could not locate .github/workflows/{filename} from test file path")
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _load_perf_workflow() -> dict[str, Any]:
    return _load_workflow("perf.yml")


def _benchmarks_job(workflow: dict[str, Any]) -> dict[str, Any]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = jobs["benchmarks"]
    assert isinstance(job, dict)
    return job


def _job_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    steps = _benchmarks_job(workflow)["steps"]
    assert isinstance(steps, list)
    return steps


def _step_by_name(steps: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for step in steps:
        if step.get("name") == name:
            return step
    raise AssertionError(f"Step {name!r} not found")


def test_perf_workflow_compares_against_detached_base_worktree() -> None:
    workflow = _load_perf_workflow()
    steps = _job_steps(workflow)

    prepare_step = _step_by_name(steps, "Prepare benchmark temp directories")
    prepare_run = prepare_step["run"]
    assert 'echo "BENCHMARK_ARTIFACT_DIR=$artifact_dir" >> "$GITHUB_ENV"' in prepare_run
    assert 'echo "BENCHMARK_BASE_WORKTREE=$base_worktree" >> "$GITHUB_ENV"' in prepare_run
    assert 'echo "artifact_dir=$artifact_dir" >> "$GITHUB_OUTPUT"' in prepare_run

    base_step = _step_by_name(steps, "Benchmark base commit")
    assert base_step["if"] == "github.event_name == 'pull_request'"
    base_run = base_step["run"]
    assert 'git worktree add --detach "$BENCHMARK_BASE_WORKTREE" "$BASE_SHA"' in base_run
    assert 'if [ ! -f "$BENCHMARK_BASE_WORKTREE/tests/benchmarks/test_scan_benchmarks.py" ]; then' in base_run
    assert (
        'uv run --directory "$BENCHMARK_BASE_WORKTREE" --python 3.11 --locked --with pytest-benchmark pytest'
        in base_run
    )
    assert '--benchmark-json="$BENCHMARK_ARTIFACT_DIR/benchmark-base.json"' in base_run


def test_perf_workflow_reports_regressions_without_blocking_prs() -> None:
    workflow = _load_perf_workflow()
    compare_step = _step_by_name(_job_steps(workflow), "Compare against base")

    assert compare_step["if"] == "github.event_name == 'pull_request'"
    compare_run = compare_step["run"]
    assert '--current "$BENCHMARK_ARTIFACT_DIR/benchmark-head.json"' in compare_run
    assert '--baseline "$BENCHMARK_ARTIFACT_DIR/benchmark-base.json"' in compare_run
    assert "--threshold 0.15" in compare_run
    assert "--fail-on-regression" not in compare_run
    assert "--fail-on-missing" not in compare_run
    assert 'if [ -f "$BENCHMARK_ARTIFACT_DIR/benchmark-base.json" ]; then' in compare_run
    assert "Base branch does not include the benchmark suite yet; showing current results only." in compare_run


def test_perf_workflow_comments_only_on_same_repo_prs() -> None:
    workflow = _load_perf_workflow()

    permissions = workflow["permissions"]
    assert isinstance(permissions, dict)
    assert permissions["pull-requests"] == "write"

    comment_step = _step_by_name(_job_steps(workflow), "Comment benchmark summary on PR")
    assert "github.event_name == 'pull_request'" in comment_step["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in comment_step["if"]

    env = comment_step["env"]
    assert isinstance(env, dict)
    assert env["COMMENT_BODY_PATH"] == "${{ steps.paths.outputs.artifact_dir }}/benchmark-comment.md"

    script = comment_step["with"]["script"]
    assert "<!-- modelaudit-perf-benchmarks -->" in script
    assert "github.rest.issues.updateComment" in script
    assert "github.rest.issues.createComment" in script


def test_nightly_windows_lane_defers_performance_benchmarks_to_linux() -> None:
    workflow = _load_workflow("nightly.yml")
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)

    linux_steps = jobs["full-matrix"]["steps"]
    assert isinstance(linux_steps, list)
    linux_run = _step_by_name(linux_steps, "Run all tests (fast + slow + integration + performance)")["run"]
    assert '-m "not performance"' not in linux_run

    windows_steps = jobs["windows-full"]["steps"]
    assert isinstance(windows_steps, list)
    windows_run = _step_by_name(windows_steps, "Run all Windows tests except performance benchmarks")["run"]
    assert '-m "not performance"' in windows_run
