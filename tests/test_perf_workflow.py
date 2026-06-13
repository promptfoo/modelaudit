from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
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


def _jobs(workflow: dict[str, Any]) -> dict[str, Any]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def _benchmarks_job(workflow: dict[str, Any]) -> dict[str, Any]:
    job = _jobs(workflow)["benchmarks"]
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


def _node_script(step: dict[str, Any]) -> str:
    run = step["run"]
    assert isinstance(run, str)
    prefix = "node <<'NODE'\n"
    suffix = "\nNODE\n"
    assert run.startswith(prefix)
    assert run.endswith(suffix)
    return run[len(prefix) : -len(suffix)]


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _init_test_repository(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "ModelAudit Tests")
    _git(repo, "config", "user.email", "tests@example.com")
    (repo / "README.md").write_text("# Base\n", encoding="utf-8")
    (repo / "deleted.md").write_text("# Deleted\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", "base")
    return repo, _git(repo, "rev-parse", "HEAD")


def _run_node_script(script: str, repo: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["node", "-e", script],
        cwd=repo,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
    )


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


def test_perf_workflow_runs_retained_memory_guard_as_blocking_step() -> None:
    workflow = _load_perf_workflow()
    guard_step = _step_by_name(_job_steps(workflow), "Run retained-memory stability guard")

    assert guard_step.get("continue-on-error") is None
    env = guard_step["env"]
    assert isinstance(env, dict)
    assert env["PROMPTFOO_DISABLE_TELEMETRY"] == "1"

    run = guard_step["run"]
    assert "uv run --locked --with psutil pytest" in run
    assert "tests/test_performance_benchmarks.py::TestPerformanceBenchmarks::test_memory_usage_stability" in run


def test_nightly_windows_lane_defers_performance_benchmarks_to_linux() -> None:
    workflow = _load_workflow("nightly.yml")
    jobs = _jobs(workflow)

    linux_steps = jobs["full-matrix"]["steps"]
    assert isinstance(linux_steps, list)
    linux_run = _step_by_name(linux_steps, "Run all tests (fast + slow + integration + performance)")["run"]
    assert '-m "not performance"' not in linux_run

    windows_steps = jobs["windows-full"]["steps"]
    assert isinstance(windows_steps, list)
    windows_run = _step_by_name(windows_steps, "Run all Windows tests except performance benchmarks")["run"]
    assert '-m "not performance"' in windows_run


def test_docs_workflow_passes_changed_files_to_prettier_as_json() -> None:
    workflow = _load_workflow("docs-check.yml")
    raw_workflow = cast(dict[Any, Any], workflow)
    triggers = raw_workflow.get("on", raw_workflow.get(True))
    assert isinstance(triggers, dict)
    assert triggers["pull_request"] is None
    push_trigger = triggers["push"]
    assert isinstance(push_trigger, dict)
    assert push_trigger["branches"] == ["main"]
    assert "paths" not in push_trigger

    job = _jobs(workflow)["format-check"]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)

    checkout_step = _step_by_name(steps, "Checkout repo")
    assert checkout_step["with"]["fetch-depth"] == 0

    changed_files_step = _step_by_name(steps, "Collect changed documentation files")
    assert changed_files_step["env"]["BASE_SHA"].startswith("${{ github.event_name == 'pull_request'")
    assert changed_files_step["env"]["HEAD_SHA"] == "${{ github.sha }}"
    assert changed_files_step["env"]["CHANGED_FILES_JSON_PATH"].startswith("${{ runner.temp }}")
    changed_files_run = changed_files_step["run"]
    assert '["diff", "--name-only", "-z", "--diff-filter=ACMRTUX"' in changed_files_run
    assert "writeFileSync(process.env.CHANGED_FILES_JSON_PATH" in changed_files_run
    assert "Changed filename is not valid UTF-8" in changed_files_run
    assert '["hash-object", "-t", "tree", "--stdin"]' in changed_files_run
    assert "any_changed=" in changed_files_run

    prettier_step = _step_by_name(steps, "Check markdown formatting with prettier")
    assert prettier_step["env"]["CHANGED_FILES_JSON_PATH"].startswith("${{ runner.temp }}")
    run = prettier_step["run"]
    assert 'JSON.parse(readFileSync(process.env.CHANGED_FILES_JSON_PATH, "utf8"))' in run
    assert '["prettier", "--check", "--", ...changedFiles]' in run
    assert "console.log(JSON.stringify(file))" in run
    assert "spawnSync" in run
    assert "${{" not in run


@pytest.mark.skipif(os.name == "nt", reason="Git filename edge cases require POSIX filesystem semantics")
def test_docs_workflow_preserves_unusual_filenames_end_to_end(tmp_path: Path) -> None:
    workflow = _load_workflow("docs-check.yml")
    steps = _jobs(workflow)["format-check"]["steps"]
    assert isinstance(steps, list)
    collect_script = _node_script(_step_by_name(steps, "Collect changed documentation files"))
    prettier_script = _node_script(_step_by_name(steps, "Check markdown formatting with prettier"))

    repo, base_sha = _init_test_repository(tmp_path)
    changed_files = [
        "space name.md",
        "-leading.md",
        "docs/line\n::add-mask::masked-value\nname.md",
        "docs/unicode-\u00e9.md",
        "docs/$(touch injected).md",
        "config.JSON",
        "workflow.YML",
    ]
    for filename in changed_files:
        path = repo / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Changed\n", encoding="utf-8")
    (repo / "ignored.txt").write_text("ignored\n", encoding="utf-8")
    (repo / "deleted.md").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", "head")
    head_sha = _git(repo, "rev-parse", "HEAD")

    changed_json = tmp_path / "changed.json"
    github_output = tmp_path / "github-output"
    collect_result = _run_node_script(
        collect_script,
        repo,
        {
            "BASE_SHA": base_sha,
            "HEAD_SHA": head_sha,
            "CHANGED_FILES_JSON_PATH": str(changed_json),
            "GITHUB_OUTPUT": str(github_output),
        },
    )
    assert collect_result.returncode == 0, collect_result.stderr
    collected_files = json.loads(changed_json.read_text(encoding="utf-8"))
    assert set(collected_files) == set(changed_files)
    assert "deleted.md" not in collected_files
    assert "ignored.txt" not in collected_files
    assert github_output.read_text(encoding="utf-8") == "any_changed=true\n"

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_npx = fake_bin / "npx"
    fake_npx.write_text(
        "#!/usr/bin/env node\n"
        'require("node:fs").writeFileSync(process.env.ARGS_PATH, JSON.stringify(process.argv.slice(2)));\n',
        encoding="utf-8",
    )
    fake_npx.chmod(0o755)
    args_path = tmp_path / "npx-args.json"
    prettier_result = _run_node_script(
        prettier_script,
        repo,
        {
            "ARGS_PATH": str(args_path),
            "CHANGED_FILES_JSON_PATH": str(changed_json),
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        },
    )
    assert prettier_result.returncode == 0, prettier_result.stderr
    assert json.loads(args_path.read_text(encoding="utf-8")) == [
        "prettier",
        "--check",
        "--",
        *collected_files,
    ]
    assert "\n::add-mask::" not in prettier_result.stdout
    assert "\\n::add-mask::masked-value\\n" in prettier_result.stdout


@pytest.mark.skipif(os.name == "nt", reason="Invalid UTF-8 filenames require POSIX filesystem semantics")
def test_docs_workflow_rejects_invalid_utf8_and_invalid_revisions(tmp_path: Path) -> None:
    workflow = _load_workflow("docs-check.yml")
    steps = _jobs(workflow)["format-check"]["steps"]
    assert isinstance(steps, list)
    collect_script = _node_script(_step_by_name(steps, "Collect changed documentation files"))

    repo, base_sha = _init_test_repository(tmp_path)
    bad_path = os.fsencode(repo) + b"/invalid-\xff.md"
    descriptor = os.open(bad_path, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(descriptor, b"# Invalid\n")
    os.close(descriptor)
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", "invalid filename")
    head_sha = _git(repo, "rev-parse", "HEAD")

    changed_json = tmp_path / "invalid.json"
    github_output = tmp_path / "invalid-output"
    invalid_utf8_result = _run_node_script(
        collect_script,
        repo,
        {
            "BASE_SHA": base_sha,
            "HEAD_SHA": head_sha,
            "CHANGED_FILES_JSON_PATH": str(changed_json),
            "GITHUB_OUTPUT": str(github_output),
        },
    )
    assert invalid_utf8_result.returncode != 0
    assert "Changed filename is not valid UTF-8" in invalid_utf8_result.stderr
    assert not changed_json.exists()

    invalid_revision_result = _run_node_script(
        collect_script,
        repo,
        {
            "BASE_SHA": "not-a-revision",
            "HEAD_SHA": head_sha,
            "CHANGED_FILES_JSON_PATH": str(changed_json),
            "GITHUB_OUTPUT": str(github_output),
        },
    )
    assert invalid_revision_result.returncode != 0
    assert "Invalid workflow diff boundary" in invalid_revision_result.stderr
    assert not changed_json.exists()


@pytest.mark.skipif(os.name == "nt", reason="Git empty-tree behavior is covered on POSIX CI")
def test_docs_workflow_zero_base_scans_the_full_tree(tmp_path: Path) -> None:
    workflow = _load_workflow("docs-check.yml")
    steps = _jobs(workflow)["format-check"]["steps"]
    assert isinstance(steps, list)
    collect_script = _node_script(_step_by_name(steps, "Collect changed documentation files"))

    repo, _ = _init_test_repository(tmp_path)
    head_sha = _git(repo, "rev-parse", "HEAD")
    changed_json = tmp_path / "zero-base.json"
    github_output = tmp_path / "zero-base-output"
    result = _run_node_script(
        collect_script,
        repo,
        {
            "BASE_SHA": "0" * 40,
            "HEAD_SHA": head_sha,
            "CHANGED_FILES_JSON_PATH": str(changed_json),
            "GITHUB_OUTPUT": str(github_output),
        },
    )
    assert result.returncode == 0, result.stderr
    assert set(json.loads(changed_json.read_text(encoding="utf-8"))) == {"README.md", "deleted.md"}


def test_dependency_audit_runs_for_source_reachability_changes() -> None:
    workflow = _load_workflow("test.yml")
    job = _jobs(workflow)["dependency-audit"]
    assert isinstance(job, dict)

    condition = job["if"]
    assert "github.event_name == 'pull_request'" in condition
    assert "needs.changes.outputs.dependencies == 'true'" in condition
    assert "needs.changes.outputs.workflows == 'true'" in condition
    assert "needs.changes.outputs.python == 'true'" in condition
    assert "needs.changes.outputs.picklescan == 'true'" in condition


def test_python_ci_requires_successful_coverage_when_scheduled() -> None:
    workflow = _load_workflow("test.yml")
    jobs = _jobs(workflow)

    coverage_job = jobs["coverage"]
    assert isinstance(coverage_job, dict)
    assert coverage_job["if"] == ("github.ref == 'refs/heads/main' || needs.changes.outputs.workflows == 'true'")
    assert coverage_job["strategy"]["matrix"]["shard"] == [0, 1, 2, 3, 4]
    coverage_steps = coverage_job["steps"]
    assert isinstance(coverage_steps, list)
    upload_step = _step_by_name(coverage_steps, "Upload coverage to Codecov")
    assert upload_step["with"]["fail_ci_if_error"] is True

    ci_success_job = jobs["ci-success"]
    assert isinstance(ci_success_job, dict)
    assert "coverage" in ci_success_job["needs"]
    ci_success_steps = ci_success_job["steps"]
    assert isinstance(ci_success_steps, list)
    gate_script = _step_by_name(ci_success_steps, "Check if all jobs succeeded")["run"]
    assert 'if [[ "$ON_MAIN_BRANCH" == "true" || "$WORKFLOWS_CHANGED" == "true" ]]; then' in gate_script
    assert '[[ "$COVERAGE_RESULT" != "success" ]] && FAILED=true' in gate_script
