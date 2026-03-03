# Summary

Describe the change and user impact.

## Validation

- [ ] `uv run ruff format --check modelaudit/ tests/`
- [ ] `uv run ruff check modelaudit/ tests/`
- [ ] `uv run mypy modelaudit/`
- [ ] `uv run pytest -n auto -m "not slow and not integration" --maxfail=1`

## Checklist

- [ ] I followed the security-first guidelines in `AGENTS.md`.
- [ ] I did not weaken detection behavior.
- [ ] I added/updated tests when behavior changed.
- [ ] I updated docs where needed.
