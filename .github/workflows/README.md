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

Python CI ignores documentation-only PRs, which are handled by the documentation check workflow. Code PRs run fast feedback on Python 3.12, root matrix coverage on Python 3.10 and 3.13, the NumPy compatibility lane on Python 3.10 and 3.11, Windows tests on Python 3.11, and the standalone pickle package matrix on Python 3.10-3.13. Pushes to `main` run the full root and NumPy matrices across Python 3.10-3.13.

The performance workflow compares workload-oriented benchmarks between the PR
base and head, posts a sticky summary comment on same-repo PRs, uploads JSON and
Markdown artifacts, and reports regressions without blocking the PR.
