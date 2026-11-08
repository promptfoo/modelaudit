# Optional AI triage

When `OPENAI_API_KEY` is set, `modelaudit scan` follows the scan with one advisory
OpenAI API request for warning/critical findings in README/model-card text files.
Without a key, scanning works as before. No additional dependencies are required.

```sh
# Uses OPENAI_API_KEY from your environment.
modelaudit scan ./model

# Keep this scan local even when a key is configured.
modelaudit scan ./model --no-triage

# Save the original report and the separate triage/diagnostic output.
modelaudit scan ./model --format json > scan.json 2> triage.txt
```

Triage sends selected raw findings and available document text to OpenAI. This may
include secrets present in those artifacts. It does not send weights or give the
model tools, shell access, or the ability to run ModelAudit. The API key is used
only for authentication. Requests use `store: false`.

The default model is `gpt-6-sol`; set `MODELAUDIT_TRIAGE_MODEL` to use another
Responses API model supporting structured outputs.

Advice appears on stderr as `likely_benign`, `needs_attention`, or `inconclusive`,
with the issue's JSON pointer, location, and explanation. Nothing is filtered or
downgraded: scan output, JSON/SARIF reports, caches, verdicts, and exit codes remain
the scanner's. API errors, malformed replies, and interrupted requests do not
replace a completed scan's exit code.
Cancelled scans skip triage. Local API error diagnostics retain the HTTP status and
bounded response body, with terminal control characters escaped.

One request considers at most 20 eligible findings and 256 KiB of evidence.
Complete UTF-8 documents up to 32 KiB are included when they remain available as
regular local files. Symlinks and platforms without no-follow directory reads
provide findings only; so do documents already removed by streaming/acquisition
cleanup. Text scans record `text_content_sha256` from the bytes inspected; triage
includes a document only when it matches that hash. Changed documents and older
reports without this hash provide findings only.
Missing context or incomplete scan coverage prevents `likely_benign`
advice. Output says how many eligible findings were submitted. Network connect/read
timeouts are 5/30 seconds, with no retries and at most 4,096 output tokens.

The regression corpus in `tests/assets/agent_review_pr1913.json` retains 18 cases
and original scanner reports from [#1913](https://github.com/promptfoo/modelaudit/pull/1913),
including routine setup, execution across code fences, unsafe loaders, credentials,
lookalike domains, and prompt injection. Unit tests use mocked API responses;
passing them establishes integration behavior, not model accuracy.
