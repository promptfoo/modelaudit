# Summary

Describe the change and user impact.

## Validation

- [ ] `uv run ruff format --check modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/`
- [ ] `uv run ruff check modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/`
- [ ] `uv run mypy modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests`
- [ ] `uv run pytest -n auto -m "not slow and not integration" --maxfail=1`

## Checklist

- [ ] I followed the security-first guidelines in `AGENTS.md`.
- [ ] I did not weaken detection behavior.
- [ ] I added/updated tests when behavior changed.
- [ ] I updated docs where needed.
