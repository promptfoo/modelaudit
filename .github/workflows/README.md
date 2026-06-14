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

Python CI ignores documentation-only PRs, which are handled by the documentation check workflow. Code PRs use GitHub's default merge-ref checkout and keep the fast lanes reduced: quick feedback on Python 3.12, one fast-test shard each for Python 3.10 and 3.13, a single Windows shard, the reduced NumPy compatibility lane on Python 3.10 and 3.11, and the standalone pickle package matrix on Python 3.10-3.13. Dependency audit runs on dependency-relevant PR merge refs and again on `merge_group` candidate SHAs, while the optional `run-slow-tests` label remains PR-only because merge-group payloads do not carry pull request label context.

Pushes to `main` and `merge_group` runs validate the exact integration SHA with the full sharded fast-test matrices across Linux and Windows, the dedicated Python 3.12 slow/integration lane, 10-way coverage sharding, the full NumPy compatibility lane, and the build/package lanes. Merge-group runs intentionally fail closed: they are treated as integration events instead of depending on changed-path classification to decide whether required lanes should run, so `CI Success` cannot go green from skipped or setup-only jobs on the merge queue candidate SHA.

The performance workflow compares workload-oriented benchmarks between the PR
base and head, posts a sticky summary comment on same-repo PRs, uploads JSON and
Markdown artifacts, and reports comparative regressions without blocking the
PR. It separately runs the cache-disabled retained-memory stability guard from
`tests/test_performance_benchmarks.py`, which fails the workflow if repeat scans
retain excessive memory.
