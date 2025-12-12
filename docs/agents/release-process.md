# Release Process

Releases are automated via [release-please](https://github.com/googleapis/release-please).

## Workflow

1. **Write Conventional Commits** - Use `feat:`, `fix:`, `docs:`, etc. prefixes
2. **Merge to main** - Release-please creates/updates a "Release PR" automatically
3. **Review Release PR** - Contains auto-generated CHANGELOG and version bump
4. **Merge Release PR** - Triggers GitHub Release and PyPI publish

## Version Scheme (0ver)

This project uses [0ver](https://0ver.org/) - we stay in 0.x.y indefinitely:

- `fix:` commits bump **patch** (0.2.21 -> 0.2.22)
- `feat:` commits bump **patch** (0.2.21 -> 0.2.22)
- `feat!:` or `BREAKING CHANGE:` bumps **minor** (0.2.21 -> 0.3.0)

## Manual Version Override

To force a specific version, add to your commit message:

```
feat: major new feature

Release-As: 1.0.0
```

## Commit Conventions

- **NEVER commit directly to main branch** - always create a feature branch
- Use Conventional Commit format for ALL commit messages
- **Do NOT manually edit CHANGELOG.md** - release-please auto-generates it
- Keep commit messages concise and descriptive

Examples:

```
feat: add support for TensorFlow SavedModel scanning
fix: handle corrupt pickle files gracefully
test: add unit tests for ONNX scanner
chore: update dependencies to latest versions
```

## Pull Request Guidelines

- **Branch naming**: `feat/scanner-improvements`, `fix/pickle-parsing`, `chore/update-deps`
- Create PRs using GitHub CLI: `gh pr create`
- Keep PR bodies short and focused
- **PR titles must follow Conventional Commits format** (validated by CI)
- Include minimal test instructions in PR body:

```markdown
## Test Instructions

uv run pytest tests/test_affected_component.py
uv run modelaudit test-file.pkl
```
