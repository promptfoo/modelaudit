# Summary

Describe the change and user impact.

## Validation

- [ ] `uv run ruff format --check modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/`
- [ ] `uv run ruff check modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/`
- [ ] `uv run mypy modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/`
- [ ] `uv run pytest -n auto -m "not slow and not integration" --maxfail=1`

## Checklist

- [ ] I followed the security-first guidelines in `AGENTS.md`.
- [ ] I did not weaken detection behavior.
- [ ] I added/updated tests when behavior changed.
- [ ] I updated docs where needed.
- [ ] For user-visible changes, I added a Towncrier file such as `123.other.md` under the affected package’s `changes/` directory. [Release note examples](https://github.com/promptfoo/modelaudit/blob/main/docs/agents/release-process.md#release-notes)
