# Optional Codex review prototype

This experimental command helps triage warning/critical network findings in README and model-card
files. It writes advisory assessments alongside the original scan. Existing `modelaudit scan`,
JSON/SARIF reports, severity, suppressions, caching, and exit-code logic are unchanged.

```sh
# Local scan and evidence bundle only; no Codex or API call.
python -I -m modelaudit.review ./model --output-dir ./review-run --prepare-only

# Advisory review using the isolated worker described below.
python -I -m modelaudit.review ./model --output-dir ./review-run-with-agent \
  --worker-image sha256:<local-worker-image-id> \
  --worker-network modelaudit-review \
  --proxy-url http://172.30.0.2:8080/v1 \
  --codex-model <explicit-model-id>
```

Use the installed package with Python's `-I` flag so files in an untrusted working directory cannot
shadow imports before isolation starts. The output directory must be new and outside the input tree.
This prototype accepts local model directories or individual README/model-card documents on POSIX
hosts. For model artifacts, supply a directory containing all required companion files; individual
model files are rejected before scanning. Acquire remote models separately and retain their immutable
upstream revision.
Recognized model formats are rejected as individual inputs even when renamed to a document filename.
Supported document names are `README` and `model_card`, with an optional `.md`, `.markdown`, `.rst`,
or `.txt` extension, plus `modelcard` with one of those extensions (case-insensitive).
Other names, including `model-card.md`, are outside this prototype's review scope.
It copies regular files into a bounded snapshot (2 GiB and 10,000 entries by default), rejects
symlinks/special files, and scans the copy with the installed ModelAudit CLI. Input paths, including
parent directories, must not contain symlink aliases; use physical paths such as `/private/tmp`
in place of macOS `/tmp`. The snapshot opens each path component without following symlinks. Use
`--max-snapshot-bytes` to set a larger explicit budget for weights. No model is loaded for inference.
The initial scanner runs locally with `--verbose --quiet --no-cache --format json`; its exact
arguments, timeout, versions, source path, and coverage metadata are recorded. Scanner stderr and
stdout are saved. Host API-key environment variables are not passed to the scanner subprocess.

Once scanning finishes, the command returns **that scanner process's exit code**, including when
review fails. `0`, `1`, and `2` retain their scanner meanings. Preparation errors before the scan
return `2`. Signal-terminated scanners also return `2`, with the signal recorded in scanner stderr.
Handled interruption stops the worker and preserves a captured scanner exit; interruption
before a scanner exit is captured returns `2`. An exit of `0` does **not** establish that
review completed: consumers that require review must also inspect `review_status` in `review.json`.

## Evidence and output

| File                                    | Contents                                                                                                 |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `scan.json`                             | Original scanner JSON bytes, made read-only; never rewritten by review                                   |
| `scan.stdout.txt`, `scan.stderr.txt`    | Original scanner diagnostics                                                                             |
| `manifest.json`                         | Scanner exit/digest, arguments, versions, coverage, artifact hashes/sizes, policy/prompt/schema versions |
| `artifacts/`                            | Copied input files, including weights; mounted read-only to the worker                                   |
| `findings.json`                         | Original issue and failed-check records with IDs derived from report digest + JSON pointer               |
| `evidence/index.json`, `evidence/*.bin` | Byte ranges, SHA-256 digests, derived line ranges, decoding/completeness flags, raw excerpts             |
| `group-NNNN/`                           | One finding batch's request, exact invocation, bounded Codex JSONL trace and stderr                      |
| `review.json`, `review.md`              | Separate validated advisory output, retained findings, errors, original exit/counts                      |

Issue/check duplicates retain separate identities. All original issues and failed checks remain
visible; unrelated findings and existing INFO/DEBUG records receive `not_reviewed`. The complete
scanner report also retains passed/skipped checks and coverage information.
Snapshot roles are filename hints. Review additionally requires per-file scanner evidence of a
text-only format; executable formats disguised as documents, mixed formats, and missing format
provenance remain outside the review scope.

Review uses the entire relevant UTF-8 document, up to 256 KiB per document and 2 MiB across documents.
This preserves cross-fence and prose context. Oversized/undecodable documents, changed hashes,
malformed responses, unknown/duplicate/missing finding IDs, and invalid citations
fail closed: retain the findings and report a review failure. Incomplete scanner coverage also
prevents de-emphasis. Review status is `complete`, `partial`, `failed`, `not_needed`, or
`not_requested`; complete may include `inconclusive` assessments.

Each assessment has a finding ID, classification (`benign_context`, `false_positive`, `actionable`,
or `inconclusive`), context, execution trigger, explanation, evidence IDs, execution implications,
and limitations. Only the supervisor chooses `retain` or `de_emphasize`. No assessment suppresses a
finding or changes its severity. Schema and citation checks establish structure and provenance;
they cannot establish that the model's interpretation is correct.

Routine setup instructions may be `benign_context` while still executing third-party code when
followed. Familiar domains alone are insufficient. Download-and-execute chains, unsafe loaders,
credential URLs, lookalike domains, opaque commands, and missing context should be retained.

## Isolated worker

Run this experiment on a disposable Linux VM with a trusted Docker engine and support for Codex's
command sandbox. The normal scanner remains a local subprocess; run the whole command inside that
VM when scanning hostile artifacts. The worker adapter never falls back to running an agent on the
host and never disables the Codex sandbox if nested sandboxing is unavailable.

The Linux runtime must permit Codex's required bubblewrap operations while retaining the worker's
resource, mount, privilege, and command-network restrictions. An ordinary Docker installation may
block these operations. Legacy Landlock is not a supported fallback for this policy; see the
[Codex enforcement requirements](https://learn.chatgpt.com/docs/permissions#how-enforcement-works).
The image alone does not provision or certify a compatible VM/engine configuration.

The worker requires a trusted immutable image containing this branch and Codex CLI **0.163.0**.
Build the ordinary repository Docker image first. Obtain the matching architecture's
`codex-package-<target>.tar.gz` from the
[official 0.163.0 release](https://github.com/openai/codex/releases/tag/rust-v0.163.0), verify its
published checksum, and extract it into a temporary build context's `codex-package/` directory.
Preserve the package layout, including `bin/`, `codex-resources/`, `codex-path/`, and
`codex-package.json`; the standalone executable omits required sandbox resources. Then build:

```sh
docker build -t modelaudit-review-scanner:prototype .
docker image inspect --format '{{.Id}}' modelaudit-review-scanner:prototype
docker build --build-arg MODELAUDIT_IMAGE=modelaudit-review-scanner:prototype \
  -f modelaudit/review/Dockerfile -t modelaudit-review-worker /path/to/codex-build-context
docker image inspect --format '{{.Id}}' modelaudit-review-worker
```

This recipe uses the default local Docker builder and a dedicated scanner tag. Record the scanner
image ID and keep that tag unchanged during the worker build. For a remote/container builder,
publish the scanner image to a trusted registry and use its repository-qualified manifest digest
(`registry.example/modelaudit@sha256:...`). BuildKit does not accept a bare local image ID in `FROM`.
Run reviewers only with the resulting immutable worker image ID/digest.

Each batch starts a fresh container with an unprivileged UID, read-only root and input mounts,
all capabilities dropped, no new privileges, 2 CPUs, 4 GiB RAM, no swap, 128 processes, and 512 MiB
of temporary storage across work/home/tmp. The supervisor imposes a five-minute deadline and a
4 MiB combined output limit, kills subprocess groups, and explicitly removes daemon-owned containers.
Only the request and artifact snapshot are mounted. The original report and supervisor output
directory, host home, credentials, and Docker socket are not mounted.
Docker-injected proxy variables are cleared so the harness connects directly to the private gateway.

Each batch contains at most eight findings from one document, with the full document context,
leaving room for concise explanations within the output allowance. The supervisor starts at most
eight sessions per run by default (`--max-review-groups`); a document can use multiple sessions.
Remaining findings stay visible as `not_reviewed`, with a partial/failed review status. This bounds
agent sessions separately from the per-session deadline and gateway request budget.

Codex runs with approvals disabled, workspace writes limited to scratch, command networking
disabled, a fresh home, ephemeral state, user config/rules ignored, project instructions disabled,
and hooks/plugins/apps/browser/memory/subagents/skill discovery disabled. It can inspect files,
write scratch analysis code, and invoke the installed ModelAudit for additional static evidence.
Additional scans cannot replace the initial report. The policy prohibits running examples,
deserializing weights, importing artifact code, or installing dependencies. Treat arbitrary agent
commands as hostile anyway: those policy instructions are not the security boundary.

Before any model request, a runtime probe verifies scratch writes, protected mount denials, and
denied command connections to both a listening harness socket and the reachable API gateway.
A failed probe stops review. Validate these boundaries on the deployment's actual kernel/runtime;
do not relax isolation flags to make an unsupported Docker setup work.

## Credential gateway

The Codex harness needs model API access; its commands must not have that access. A separate gateway
container owns the existing `OPENAI_API_KEY`. The worker receives neither that variable nor an auth
file. `modelaudit.review.gateway` is a small optional relay restricted to OpenAI's Responses endpoint,
one explicit model, client-side tools, bounded requests, 4,096 output tokens per response, and no
stored/background responses. It forwards streaming responses and does not log credentials or bodies.
Request/token limits are not an exact dollar cap.

The following operator setup uses a private network and a dedicated gateway. Pick an unused subnet.
The gateway binds only its private-network IP; **do not publish its port**. The private network must
contain only trusted gateway containers and disposable reviewers. Never connect a worker to an
external network. The gateway alone receives a second network for upstream API access.

```sh
docker network create --internal --subnet 172.30.0.0/24 modelaudit-review
# OPENAI_API_KEY is already configured in the operator's environment. Do not put its value in argv.
docker create --name modelaudit-review-gateway \
  --network modelaudit-review --ip 172.30.0.2 \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --user 10001:10001 --memory=256m --pids-limit=32 \
  --env OPENAI_API_KEY --entrypoint python sha256:<worker-image-id> \
  -m modelaudit.review.gateway --bind 172.30.0.2 --model <explicit-model-id> --max-requests 16
docker network connect bridge modelaudit-review-gateway
docker start modelaudit-review-gateway
# Run the review command shown above, then remove the dedicated gateway and network.
docker rm --force modelaudit-review-gateway
docker network rm modelaudit-review
```

Local bundles preserve raw evidence, including any secrets contained in artifacts. Enabling review
sends selected findings and full document context to the configured model. Agent commands can read
the mounted input snapshot and may include its contents in model requests. Supply only artifacts
approved for that provider. The gateway key is unrelated to those artifact contents and remains
outside the worker's filesystem, process namespace, and environment.

## #1913 evaluation

`tests/assets/agent_review_pr1913.json` records 18 synthetic README/model-card cases scanned using
the pre-PR source at `80294cd6620c3eeccdbc0ece233939a6e48c1cc2`. The fixture records runtime provenance
and actual exit codes; only source-directory strings were normalized. It includes routine clones,
localhost clients, package indexes, user-data URLs, builds, and adversarial execution/loader variants
from the [#1913 discussion](https://github.com/promptfoo/modelaudit/pull/1913).

```sh
python -I -m modelaudit.review.evaluate \
  --cases tests/assets/agent_review_pr1913.json --output-dir ./review-evaluation --runs 3 \
  --worker-image sha256:<worker-image-id> --worker-network modelaudit-review \
  --proxy-url http://172.30.0.2:8080/v1 --codex-model <explicit-model-id>
```

Provision a suitable bounded request allowance on the dedicated gateway for repeated runs. Each
case gets a fresh worker. The agent sees ordinal paths, original findings, and document evidence;
case names, expected labels, and PR commentary stay with the evaluator. The scorer reports unsafe
de-emphasis, benign resolutions, and incomplete reviews. Existing informational detections do not
count as agent successes. Human review must judge execution explanations, especially ordinary
build/install cases. Evaluation exit codes are separate from scanner exit codes.

Unit tests use fake reviewers and assert preservation/failure behavior and scorer sensitivity.
They do not measure model accuracy. Live evaluation is opt-in and requires a working isolated
runtime. The corpus is an initial development set; reserve new families/mutations for holdout
evaluation before using these suggestions to reduce human review.
