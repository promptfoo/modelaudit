# Release Process

This repo is a monorepo with **two independently versioned PyPI packages**:

| PyPI name               | Path                              | Version source                  | Git tag format                   |
| ----------------------- | --------------------------------- | ------------------------------- | -------------------------------- |
| `modelaudit`            | `./` (root)                       | `pyproject.toml` + `uv.lock`    | `v{X.Y.Z}`                       |
| `modelaudit-picklescan` | `packages/modelaudit-picklescan/` | `pyproject.toml` + `Cargo.toml` | `modelaudit-picklescan-v{X.Y.Z}` |

Both packages are driven by a single [release-please](https://github.com/googleapis/release-please) workflow (`.github/workflows/release-please.yml`) with two components declared in `release-please-config.json` and current versions pinned in `.release-please-manifest.json`.

The root release intentionally omits `package-name` and `component`. Release-please reads `project.name` from `pyproject.toml` for Python updates, while the empty branch component lets a root-only grouped Release PR match `release-please--branches--main` and keeps the existing `v{X.Y.Z}` tags. Restoring a non-empty `package-name` or `component` makes root-only releases look like a different component and silently skips publication after merge.

The root `modelaudit` wheel declares a **hard dependency** on `modelaudit-picklescan>=0.1.13,<0.2.0` in `pyproject.toml`. When the sibling version crosses `0.2.0`, the constraint must be bumped in the same PR.

## Normal flow

1. **Write Conventional Commits** — `feat:`, `fix:`, `docs:`, etc. Release Please uses these to compute the next version and build the pull request inventory.
2. **Merge to `main`** — Release Please creates or updates a grouped release PR for the components being released. Commits that only touch `packages/modelaudit-picklescan/` feed the picklescan component; everything else feeds the root component.
3. **Review and merge the Release PR** — release-please tags the release and the workflow runs the matching publish jobs:
   - **For `modelaudit`** — `build` produces sdist+wheel → `publish-pypi` uploads via OIDC → `verify-pypi` confirms the published package → `provenance` attests and uploads SBOM.
   - **For `modelaudit-picklescan`** — `build-picklescan-package` matrix builds 5 native wheels (Linux x86_64, Linux aarch64, macOS arm64, macOS x86_64, Windows x64) + sdist → `publish-picklescan-pypi` uploads → `picklescan-provenance` attests.
   - **When both release together** — the sibling package is published and verified on PyPI before the dependent root package is uploaded.

## Release notes

Add one Towncrier fragment in `changes/` for ModelAudit or `packages/modelaudit-picklescan/changes/` for standalone PickleScan. Each file is plain Markdown and describes the effect on that package’s users. Internal-only changes can skip the fragment. When converting an open PR that already edits a shared changelog, move its new notes into a fragment and restore the shared changelog from the current base.

Use `<issue-or-PR>.<type>.md`. The type is `highlight` for a major user-facing improvement, `upgrade` for compatibility or action users need to take, `security` for a security fix, or `other` for a secondary change. Towncrier supplies the section heading, list marker, and link to the issue or PR. If you have no issue or PR number yet, use a unique filename such as `+cli-triage.upgrade.md`. For a second note in the same category for the same issue, Towncrier also accepts a counter, such as `1924.upgrade.1.md`.

The following upgrade note belongs in `changes/1924.upgrade.md`.

```markdown
When an OpenAI API key is set, documentation triage can send eligible findings and document text to OpenAI. Use `--no-triage` to keep the scan local.
```

From the repository root, run `python scripts/release_notes.py check` to validate pending fragments and detect edits to shipped files. Run `python scripts/release_notes.py pending --package modelaudit` or `--package modelaudit-picklescan` to preview one package’s source fragments. These commands use uv and the pinned Towncrier environment in `scripts/release-tools/`. Shipped fragment files stay in Git, so give later notes new filenames.

On the rolling release branch, both commands use the merge base with `origin/main` to find the last published versions. For a detached release PR checkout, pass `--base <PR-base-SHA>` to either command. If a package tag is missing locally, the error names the tag to fetch. To see wording supplied by reviewers, read the generated changelog on the release PR.

Each generated version section records the reviewed `main` commit and the number of rendered notes in hidden Markdown comments. Identical notes grouped by Towncrier count as one entry. If another fragment lands or a pending fragment changes before the release PR merges, the next release picks up that addition or revision. Older tags without a source comment keep their original cutoff. If an open release PR is missing these comments, refresh its metadata using the command below.

### Reviewing the rolling release PR

Inspect the versioned section in each changed changelog. CI checks that it follows **Unreleased**, includes the pending categories and numbered issue links, and points to the component’s tag comparison under **All changes**. Later merges refresh the same release PR. To change the wording of a fragment on that PR, a maintainer with repository write access can post a comment with its exact path on the first line, followed by the complete replacement fragment.

```markdown
<!-- release-note: changes/1924.upgrade.md -->

When an OpenAI API key is set, use `--no-triage` to keep documentation findings and document text local.
```

The most recently updated matching comment from a current writer wins for that filename. Edit that comment to revise the wording, or remove its marker and any earlier overrides for the same file to restore the fragment. New fragments appear independently. To apply edits before the next automatic refresh, run the existing metadata retry and check the resulting changelog diff before merging.

```bash
gh api repos/promptfoo/modelaudit/dispatches -f event_type=release-metadata-retry \
  -f 'client_payload[pr_branch]=release-please--branches--main'
```

The publisher uses the approved versioned section from the matching tag for the public GitHub Release. The comparison link and generated pull request inventory are available under **All changes**. A manual retry of an existing historical release retains its release page.

## Version scheme (0ver)

Both packages follow [0ver](https://0ver.org/) — we stay in `0.x.y` indefinitely:

- `fix:` commits bump **patch**
- `feat:` commits bump **patch**
- `feat!:` or `BREAKING CHANGE:` bumps **minor**

The two components bump independently: a picklescan-only `fix:` bumps only `modelaudit-picklescan`.

## Manual version override

To force a specific version on the release PR:

```
feat: major new feature

Release-As: 1.0.0
```

## Manual recovery path (workflow_dispatch)

The release-please workflow accepts inputs to re-run the publish step for an already-tagged release without cutting a new tag. Use when:

- A prior release tagged successfully but the publish job failed (e.g. transient PyPI outage, runner misconfiguration).
- You need to re-publish an existing version to a package that was registered on PyPI after the fact.

```bash
# Re-publish modelaudit at an already-tagged version
gh workflow run release-please.yml -f root_version=<X.Y.Z>

# Re-publish modelaudit-picklescan at an already-tagged version
gh workflow run release-please.yml -f picklescan_version=<X.Y.Z>
```

The workflow's `Resolve manual release inputs` step flips `manual_release=true`, skips the release-please action, uses the existing tag and restores a missing GitHub Release from its tagged changelog section. If the tag itself is missing, the workflow verifies that the requested version is in the dispatch commit’s component manifest and changelog and creates the tag at that commit. It then feeds `release_created=true` / `picklescan_release_created=true` into the publish jobs. `uv build` always reads from `pyproject.toml` at the current `HEAD`, so the tagged commit must already contain the target version; dispatching a version that does not match what's in `HEAD` will fail the PyPI upload.

If root publication and PyPI verification succeeded but `provenance` was skipped or failed, do **not** re-run the publish path: PyPI filenames are immutable and a rebuilt artifact may not match the published bytes. Recover provenance from the original verified publish run instead:

```bash
gh workflow run release-please.yml --ref main \
  -f root_version=<X.Y.Z> \
  -f root_provenance_run_id=<original-run-id>
```

This provenance-only path skips release creation, builds, and publication. It checks out the fully qualified `refs/tags/v<X.Y.Z>` ref, verifies that the source is a completed release-please push or manual run from this repository with successful `build`, `publish-pypi`, and `verify-pypi` jobs, and requires both the source run's immutable head commit and the checked-out tag commit to be ancestors of the protected `main` branch before downloading the original `dist` artifact. The tag must also be an ancestor of the source run; only `.github/workflows/release-please.yml` and `tests/test_release_workflow.py` may differ, including both sides of any rename, accommodating a release-build repair without allowing runtime source drift. This prevents a branch-dispatched workflow with fabricated release jobs or a moved tag from being signed as trusted. An overall `failure` conclusion is accepted so a failed `provenance` job can be recovered; cancelled, incomplete, or diverged source runs and tags are rejected. The wheel and sdist are hashed in bounded chunks and must exactly match the non-yanked PyPI SHA256 digests. The bounded sdist may contain only regular files and directories with safe paths; links, special files, duplicate paths, case or Unicode aliases, and file/directory conflicts are rejected, and it must contain exactly one `pyproject.toml` and `uv.lock` whose bytes match the tag. The workflow then generates a recovery-integrity attestation recording both immutable commits and an SBOM from the frozen lockfile, and uploads the files to the matching GitHub Release. The recovery attestation does **not** claim original SLSA build provenance; the original PyPI publish attestations remain the publisher record. The source run ID must be numeric, `root_version` must use `X.Y.Z`, and `picklescan_version` cannot be combined with this recovery mode.

## PyPI trusted publishing (first-time setup)

Both packages publish via PyPI [Trusted Publishing](https://docs.pypi.org/trusted-publishers/). The `publish-pypi` and `publish-picklescan-pypi` jobs both use environment `pypi` and `id-token: write` permissions. PyPI is configured with an **active trusted publisher** on each project, scoped to owner `promptfoo`, repository `modelaudit`, workflow `release-please.yml`, environment `pypi`.

### Adding a new PyPI package

When you introduce a new PyPI package in this repo, register a **pending trusted publisher** on PyPI _before_ the first publish attempt, or the workflow will fail with `400 Non-user identities cannot create new projects`.

Steps:

1. Log in to PyPI → Your account → Publishing → **Add a new pending publisher**.
2. Fields: PyPI Project Name (hyphenated — PyPI normalizes), Owner (`promptfoo`), Repository (`modelaudit`), Workflow filename (`release-please.yml`), Environment (`pypi`).
3. The pending publisher is automatically promoted to an active one after the first successful publish.

## Commit conventions

- **NEVER commit directly to `main` branch** — always create a feature branch and PR.
- Use Conventional Commit format for ALL commit messages.
- Add a [release note fragment](#release-notes) for each affected package when the change is user-visible.
- PR titles must follow Conventional Commits (validated by CI).

Examples:

```
feat: add scanner for XYZ format
fix: handle corrupt pickle files gracefully
fix(modelaudit-picklescan): bound nested pickle expansion
```

## Pre-release checklist (maintainers)

Before merging a Release PR:

1. Review the versioned changelog in **Files changed** for each bumped package. Check upgrade actions, public APIs, exit codes, data sent off-device, toolchain requirements, and scanner coverage or severity changes as applicable. If a root note promises a sibling fix, ensure the published minimum delivers it or state exactly which sibling version users must install.
2. Verify `CI Success` on the latest metadata commit, along with the Docker, docs, CodeQL and applicable standalone package checks. A bot refresh can leave workflow runs waiting for approval. If GitHub shows **Action required**, review the latest diff, then use **Approve and run workflows** on the PR. Check the resulting jobs on that commit before merging.
3. Release-build validation green:
   - `twine check dist/*`
   - exactly one wheel + one sdist for `modelaudit`
   - 5 wheels + one sdist for `modelaudit-picklescan`, each matching the release version
   - clean-room install smoke tests from wheel and sdist
   - project URL metadata checks (`Bug Tracker`, `Changelog`)
   - standalone Rust gates: `cargo fmt --check`, `cargo check`, `cargo clippy -D warnings`, `cargo test`, wheel build, clean-room wheel smoke test
4. No unreviewed high-severity security findings outstanding.
5. After merging, verify GitHub Release exists and PyPI publish completed for each bumped component:

   ```bash
   # modelaudit
   curl -s https://pypi.org/pypi/modelaudit/json | jq .info.version

   # modelaudit-picklescan (simple index surfaces yank flags)
   curl -sH "Accept: application/vnd.pypi.simple.v1+json" \
     https://pypi.org/simple/modelaudit-picklescan/ | jq '.files[-1].filename'
   ```

## Rollback / recovery procedures

Use the least disruptive path.

### Release PR unmerged

- Close or update the Release PR and regenerate with new commits.

### GitHub release exists but PyPI publish failed

- Fix workflow / secrets issues, then **re-run the failed publish job** (`gh run rerun <run-id> --failed`) OR dispatch the manual recovery path:

  ```bash
  gh workflow run release-please.yml -f picklescan_version=<X.Y.Z>
  gh workflow run release-please.yml -f root_version=<X.Y.Z>
  ```

- Publish the sibling first when a root release raises its `modelaudit-picklescan` floor. Root publication checks the built wheel requirement against complete, non-yanked PyPI files and fails closed until a compatible sibling release is available.

### A published version is broken (e.g. unresolvable deps)

- **Yank** the affected version on PyPI. PyPI has no CLI/API for yanks — it must be done in the web UI:
  1. Open the PyPI releases page for the affected package, such as
     <https://pypi.org/manage/project/modelaudit/releases/> or
     <https://pypi.org/manage/project/modelaudit-picklescan/releases/>.
  2. Click the version → Options → **Yank**
  3. Provide a short reason (shown in the PyPI simple index).
  - Yanked versions remain installable if a user pins the exact version, but pip/uv resolvers skip them by default. Prefer yank + follow-up patch over deletion.
- Ship a follow-up patch release (`X.Y.Z+1`) with a clear changelog note explaining the yank.

### Broken monorepo version coupling

If `modelaudit` is published with a dependency on a `modelaudit-picklescan` version that is not on PyPI, **every dependent `modelaudit` release is unusable** — pip will either silently downgrade to an older `modelaudit` or fail resolution. Recovery:

1. Publish the missing `modelaudit-picklescan` version first (via the manual recovery path above).
2. Yank the affected `modelaudit` versions.
3. Cut a new `modelaudit` patch release pointing at the now-resolvable sibling.

### Release metadata / tagging incorrect

- Prefer a corrective follow-up release over rewriting public history. Do not force-push tags.
