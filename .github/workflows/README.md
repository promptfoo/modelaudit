# GitHub Actions Workflows

| Workflow                | File                    | Triggers                              |
| ----------------------- | ----------------------- | ------------------------------------- |
| **Python CI**           | `test.yml`              | PRs and pushes to main (Python files) |
| **Documentation Check** | `docs-check.yml`        | Changes to `*.md`, `*.txt`, `LICENSE` |
| **Docker Image CI**     | `docker-image-test.yml` | Dockerfile or Python code changes     |
| **Validate PR Title**   | `validate-pr-title.yml` | PR open/edit events                   |
| **Release**             | `release-please.yml`    | Pushes to main                        |
| **Docker Publish**      | `docker-publish.yml`    | Releases and manual dispatch          |

PRs run a reduced test matrix (Python 3.10 + 3.13). Main branch runs the full matrix (3.10–3.13). Documentation-only changes skip the full test suite.
