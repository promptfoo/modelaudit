# GitHub Actions Workflows

| Workflow                   | File                    | Triggers                                  |
| -------------------------- | ----------------------- | ----------------------------------------- |
| **Python CI**              | `test.yml`              | PRs, pushes to main, merge groups, manual |
| **Performance Benchmarks** | `perf.yml`              | PRs, pushes to main, manual dispatch      |
| **Documentation Check**    | `docs-check.yml`        | Markdown/text/RST/license changes         |
| **Docker Image CI**        | `docker-image-test.yml` | Dockerfile or Python code changes         |
| **Validate PR Title**      | `validate-pr-title.yml` | PR open/edit events                       |
| **CodeQL**                 | `codeql.yml`            | Pushes, PRs, weekly schedule, manual runs |
| **Nightly CI**             | `nightly.yml`           | Nightly, PRs editing the workflow, manual |
| **Release**                | `release-please.yml`    | Pushes to main and manual dispatch        |
| **Docker Publish**         | `docker-publish.yml`    | Published releases and manual dispatch    |

CodeQL runs the default and `security-extended` queries for Python and GitHub Actions. Pull requests from forks run the analysis without uploading results.

Every PR validates both packages’ release notes before reporting `CI Success`. Documentation-only PRs skip the code and package matrices. Release fragments alone skip Docker builds and automatic benchmarks. The documentation workflow checks formatting and links.

Code PRs test GitHub's merge ref. Linux runs fail-fast root tests on Python 3.10 and 3.12–3.15. Windows runs one Python 3.11 shard. PRs also run the reduced NumPy lane and the Python 3.10–3.15 standalone pickle matrix. macOS and Windows smoke-test native pickle and ONNX scanning on Python 3.14 and 3.15, and H5 scanning on 3.14. Linux nightly runs also install the HDF5 development libraries and the explicit `h5` extra on Python 3.15. Workflow changes trigger the full sharded root matrix. Dependency changes trigger an audit on the PR merge ref and again on the merge-group candidate. The optional `run-slow-tests` label applies only to PRs.

Pushes to `main` and `merge_group` runs validate the exact integration SHA with the full sharded fast-test matrices across Linux and Windows, the dedicated Python 3.12 slow/integration lane, 10-way coverage sharding, the full NumPy compatibility lane, and the build/package lanes. Merge-group runs intentionally fail closed: they are treated as integration events instead of depending on changed-path classification to decide whether required lanes should run, so `CI Success` cannot go green from skipped or setup-only jobs on the merge queue candidate SHA.

The performance workflow compares workload-oriented benchmarks between the PR
base and head, posts a sticky summary comment on same-repo PRs, uploads JSON and
Markdown artifacts, and reports comparative regressions without blocking the
PR. It separately runs the cache-disabled retained-memory stability guard from
`tests/test_performance_benchmarks.py`, which fails the workflow if repeat scans
retain excessive memory.
