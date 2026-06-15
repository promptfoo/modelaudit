# GitHub Actions Workflows

| Workflow                   | File                    | Triggers                                  |
| -------------------------- | ----------------------- | ----------------------------------------- |
| **Python CI**              | `test.yml`              | Python, workflow, and dependency changes  |
| **Performance Benchmarks** | `perf.yml`              | PRs, pushes to main, manual dispatch      |
| **Documentation Check**    | `docs-check.yml`        | Markdown/text/RST/license changes         |
| **Docker Image CI**        | `docker-image-test.yml` | Dockerfile or Python code changes         |
| **Validate PR Title**      | `validate-pr-title.yml` | PR open/edit events                       |
| **CodeQL**                 | `codeql.yml`            | Pushes, PRs, weekly schedule, manual runs |
| **Nightly CI**             | `nightly.yml`           | Nightly schedule and manual dispatch      |
| **Release**                | `release-please.yml`    | Pushes to main and manual dispatch        |
| **Docker Publish**         | `docker-publish.yml`    | Published releases and manual dispatch    |

Python CI ignores documentation-only PRs, which are handled by the documentation check workflow. Code PRs run fail-fast root tests on Python 3.10, 3.12, and 3.13, Windows tests on Python 3.11, and the standalone pickle package matrix on Python 3.10-3.13. Workflow-changing PRs run exhaustive sharded root tests across Python 3.10-3.13. Merge queue candidates and pushes to `main` also run the slow/integration suite and full NumPy compatibility matrix.

The performance workflow compares workload-oriented benchmarks between the PR
base and head, posts a sticky summary comment on same-repo PRs, uploads JSON and
Markdown artifacts, and reports comparative regressions without blocking the
PR. It separately runs the cache-disabled retained-memory stability guard from
`tests/test_performance_benchmarks.py`, which fails the workflow if repeat scans
retain excessive memory.
