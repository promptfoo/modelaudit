"""Deterministic pickle payloads shared by parity tests and QA harnesses."""

from __future__ import annotations

import base64
import binascii
import os
import pickle
import random
import string

from .options import ScanOptions

ParityPayload = tuple[str, bytes, ScanOptions | None]


class MaliciousReducePayload:
    """Pickle fixture that reduces to a harmless shell command."""

    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo rust parity",))


def malicious_reduce_payload() -> bytes:
    """Return a malicious reduce payload without requiring pickle imports in callers."""
    return pickle.dumps(MaliciousReducePayload(), protocol=4)


def raw_os_system_reduce_payload() -> bytes:
    """Return a compact protocol-4 os.system REDUCE payload used by corpus QA."""
    return b"\x80\x04cos\nsystem\n\x8c\x0cecho qa-noop\x85R."


def raw_stack_global_eval_reduce_payload() -> bytes:
    """Return a compact STACK_GLOBAL eval REDUCE payload used by corpus QA."""
    return b"\x80\x04\x8c\x08builtins\x8c\x04eval\x93\x8c\x031+1\x85R."


def generated_parity_payloads() -> list[ParityPayload]:
    """Build deterministic payloads that stress Python-vs-Rust report parity."""
    rng = random.Random(1337)
    generated: list[ParityPayload] = []
    suspicious_literals = [
        "",
        "plain",
        "__1__",
        "__a__",
        " __a__ ",
        "a__b__c",
        "é__a__",
        "__a__é",
        'getattr(x, "system")',
        'getattr (x, "system")',
        "getattr(x, 'system')",
        'getattr(x,"exec")',
        'getattr(x, "eval")',
        'getattr(x, "popen")',
        'getattr(x, "spawn")',
        'getattr(x, "call")',
        'getattr(x, "run")',
        'getattr(getattr(x,"y"),"z")',
        'getattr ( getattr ( x, "y" ), "z" )',
        "import os",
        "ximport os",
        "importlib",
        '__import__("os")',
        "eval (1)",
        "exec (x)",
        "subprocess.Popen",
        "commands.getstatusoutput",
        "os.system",
        "os.popen",
        "os.spawnlp",
        "\\x41",
    ]
    for index, literal in enumerate(suspicious_literals):
        for protocol in range(6):
            generated.append(
                (
                    f"string-{index}-protocol-{protocol}",
                    pickle.dumps({"s": literal}, protocol=protocol),
                    None,
                )
            )

    alphabet = string.ascii_letters + string.digits + "_ ()\"'.,\\xé"
    for index in range(80):
        literal = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 120)))
        protocol = rng.randrange(6)
        generated.append((f"random-string-{index}", pickle.dumps({"s": literal}, protocol=protocol), None))
    generated.append(("long-base64like-benign-string", pickle.dumps({"s": "A" * (1024 * 1024)}, protocol=4), None))

    nested_safe = pickle.dumps({"inner": "data"}, protocol=4)
    nested_malicious = malicious_reduce_payload()
    nested_blobs = [b"", b"notpickle", nested_safe, nested_malicious, nested_safe + b"JUNK"]
    for index, blob in enumerate(nested_blobs):
        generated.extend(
            [
                (f"bytes-{index}", pickle.dumps({"b": blob}, protocol=4), None),
                (
                    f"bytes-small-limit-{index}",
                    pickle.dumps({"b": blob}, protocol=4),
                    ScanOptions(max_nested_pickle_bytes=8),
                ),
                (
                    f"base64-{index}",
                    pickle.dumps({"s": base64.b64encode(blob).decode("ascii") if blob else ""}, protocol=4),
                    None,
                ),
                (
                    f"hex-{index}",
                    pickle.dumps({"s": binascii.hexlify(blob).decode("ascii") if blob else ""}, protocol=4),
                    None,
                ),
            ]
        )

    raw_payloads = [
        b"S'\\x5cx41'\n.",
        b"S'\\134x41'\n.",
        b"S'\\x41'\n.",
        b"cbuiltins\nlen\n.",
        b"cos\nsystem\n.",
        b"cos\nsystem\n)R.",
        b"\x80\x04\x8c\x05posix\x94\x8c\x06system\x94\x93.",
        b"\x80\x04\x8c\x05posix\x94\x8c\x06system\x94\x93)R.",
        b"\x80\x04K\x01K\x02\x93.",
        b"\x80\x04))\x93.",
        b"\x80\x04h\x01h\x02\x93.",
        b"\x80\x04j\x01\x00\x00\x00j\x02\x00\x00\x00\x93.",
        b"\x80\x04K\x01q\x00K\x02q\x01h\x00h\x01\x93.",
        b"\x80\x05\x97.",
        b"\x80\x05\x97\x98.",
        b"\x80\x05\x97\x97\x93.",
        b"\x80\x05\x97\x98\x93.",
        b"\x82\x01.",
        b"\x83\x01\x00.",
        b"\x84\x01\x00\x00\x00.",
        b"\x80\x04\x82\x01)R.",
        b"\x80\x04cos\nsystem\n." + b"\x80\x04cos\nsystem\n)R.",
    ]
    for index, payload in enumerate(raw_payloads):
        generated.append((f"raw-{index}", payload, None))

    no_stop_payloads = [
        b"(",
        b"(d",
        b"(dp0\n",
        b"\x80\x04",
        b"\x80\x04N",
        b"\x80\x04}",
    ]
    for index, payload in enumerate(no_stop_payloads):
        generated.append((f"missing-stop-{index}", payload, None))

    truncated_line_payloads = [
        b"p",
        b"(dp",
        b"Vabc",
        b"S'abc'",
        b"cos\n",
        b"imod\n",
    ]
    for index, payload in enumerate(truncated_line_payloads):
        generated.append((f"truncated-line-{index}", payload, None))

    for max_opcodes in [1, 2, 3, 5, 10]:
        generated.append((f"budget-{max_opcodes}", b"\x80\x04cos\nsystem\n)R.", ScanOptions(max_opcodes=max_opcodes)))
    generated.append(("budget-ext-boundary", b"\x80\x04\x82\x01.", ScanOptions(max_opcodes=2)))

    return generated


def prefix_truncation_payloads() -> list[ParityPayload]:
    """Build payloads whose every byte prefix should remain stable."""
    return [
        ("proto0-dict", pickle.dumps({"weights": [1, 2, 3]}, protocol=0), None),
        ("proto1-dict", pickle.dumps({"weights": [1, 2, 3]}, protocol=1), None),
        ("proto2-dict", pickle.dumps({"weights": [1, 2, 3]}, protocol=2), None),
        ("proto3-dict", pickle.dumps({"weights": [1, 2, 3]}, protocol=3), None),
        ("proto4-dict", pickle.dumps({"weights": [1, 2, 3]}, protocol=4), None),
        ("proto5-dict", pickle.dumps({"weights": [1, 2, 3]}, protocol=5), None),
        ("malicious", malicious_reduce_payload(), None),
        ("proto0-string", pickle.dumps({"s": 'exec("x")'}, protocol=0), None),
        ("proto4-string", pickle.dumps({"s": 'exec("x")'}, protocol=4), None),
        ("nested-malicious", pickle.dumps({"b": malicious_reduce_payload()}, protocol=4), None),
        ("global-call", b"cos\nsystem\n)R.", None),
        ("stack-global-call", b"\x80\x04\x8c\x05posix\x94\x8c\x06system\x94\x93)R.", None),
        ("binbytes", b"B\x08\x00\x00\x00abcdefghi.", None),
        ("short-binunicode", b"\x8c\x08abcdefgh.", None),
        ("frame", b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00N.", None),
    ]
