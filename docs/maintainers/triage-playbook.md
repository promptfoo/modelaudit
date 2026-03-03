# Issue Triage Playbook

This playbook standardizes issue and pull request triage for maintainers.

## Triage Flow

1. Confirm scope (`bug`, `enhancement`, `question`, `security`).
2. Confirm reproducibility details (version, Python version, command, expected/actual behavior).
3. Route to the right owner area and add labels.
4. Decide next action: `accept`, `needs-repro`, `needs-info`, `duplicate`, `won't-fix`.
5. Link related issues/PRs and add milestone when applicable.

## Label Taxonomy

### Type labels

- `bug` - Incorrect behavior.
- `enhancement` - New or improved capability.
- `documentation` - Docs-only changes.
- `security` - Security-impacting issue (non-sensitive/public-safe only).

### Status labels

- `needs-repro` - Cannot reproduce yet.
- `needs-info` - Reporter details missing.
- `blocked` - Waiting on dependency or external decision.
- `ready` - Ready for implementation/review.

### Priority labels

- `priority:P0` - Critical breakage or security risk.
- `priority:P1` - Important near-term work.
- `priority:P2` - Normal backlog.

### Contributor experience labels

- `good first issue` - Scoped and newcomer-friendly.
- `help wanted` - Maintainers welcome community contributions.

## Security-Specific Handling

- If a report may disclose a vulnerability, move it to private handling per `SECURITY.md`.
- Do not request exploit details in public threads.

## Pull Request Triage

1. Validate CI status and failing checks.
2. Ensure scope is focused and tests are present.
3. Check compatibility claims (Python 3.10-3.13).
4. Request follow-up changes or route to reviewer.
