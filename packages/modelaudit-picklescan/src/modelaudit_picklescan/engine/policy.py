"""Security policy tables for standalone pickle analysis."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from ..report import Severity


@dataclass(frozen=True, slots=True)
class _GlobalRef:
    module: str
    name: str
    position: int
    malformed: bool = False

    @property
    def symbol(self) -> str:
        return f"{self.module}.{self.name}"


_BUILTIN_MODULES = frozenset({"builtins", "__builtin__", "__builtins__"})

_BUILTIN_DANGEROUS_NAMES = frozenset(
    {
        "__import__",
        "breakpoint",
        "compile",
        "delattr",
        "dir",
        "eval",
        "exec",
        "execfile",
        "getattr",
        "globals",
        "input",
        "locals",
        "open",
        "raw_input",
        "reload",
        "setattr",
        "vars",
    }
)

_DANGEROUS_WILDCARD_MODULES = frozenset(
    {
        "_ctypes",
        "_pickle",
        "_signal",
        "_sqlite3",
        "_thread",
        "aiohttp",
        "asyncio",
        "bdb",
        "cloudpickle",
        "code",
        "codeop",
        "commands",
        "compileall",
        "cProfile",
        "ctypes",
        "dill._dill",
        "distutils",
        "doctest",
        "ensurepip",
        "filecmp",
        "fileinput",
        "ftplib",
        "http",
        "httplib",
        "idlelib",
        "importlib",
        "lib2to3",
        "marshal",
        "mmap",
        "multiprocessing",
        "nt",
        "os",
        "pdb",
        "pexpect",
        "pickle",
        "pip",
        "posix",
        "profile",
        "pty",
        "py_compile",
        "pydoc",
        "requests",
        "runpy",
        "select",
        "selectors",
        "shelve",
        "shutil",
        "signal",
        "smtplib",
        "socket",
        "socketserver",
        "sqlite3",
        "ssl",
        "subprocess",
        "sys",
        "syslog",
        "tarfile",
        "telnetlib",
        "threading",
        "timeit",
        "trace",
        "urllib",
        "urllib2",
        "venv",
        "webbrowser",
        "zipfile",
        "zipimport",
    }
)

_DANGEROUS_GLOBALS = frozenset(
    {
        ("_aix_support", "_read_cmd_output"),
        ("_operator", "attrgetter"),
        ("_operator", "itemgetter"),
        ("_operator", "methodcaller"),
        ("_osx_support", "_read_output"),
        ("_pyrepl.pager", "pipe_pager"),
        ("collections", "eval"),
        ("dill", "load"),
        ("dill", "loads"),
        ("functools", "reduce"),
        ("joblib", "_pickle_load"),
        ("joblib", "load"),
        ("logging.config", "listen"),
        ("numpy", "load"),
        ("numpy.testing._private.utils", "runstring"),
        ("operator", "attrgetter"),
        ("operator", "itemgetter"),
        ("operator", "methodcaller"),
        ("pip", "main"),
        ("pip._internal", "main"),
        ("pip._internal.cli.main", "main"),
        ("pip._vendor.distlib.scripts", "ScriptMaker"),
        ("pkgutil", "resolve_name"),
        ("site", "main"),
        ("test.support.script_helper", "assert_python_ok"),
        ("torch", "compile"),
        ("torch", "load"),
        ("torch._inductor.codecache", "compile_file"),
        ("torch.hub", "load"),
        ("torch.hub", "load_state_dict_from_url"),
        ("torch.serialization", "load"),
        ("torch.storage", "_load_from_bytes"),
        ("types", "CodeType"),
        ("types", "FunctionType"),
        ("uuid", "_get_command_stdout"),
        ("uuid", "_popen"),
    }
)

_WARNING_GLOBALS: dict[str, frozenset[str] | None] = {
    "functools": frozenset({"partial", "partialmethod"}),
    "glob": None,
    "linecache": frozenset({"getline"}),
    "tempfile": frozenset({"mktemp"}),
}

_SUSPICIOUS_STRING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("magic method", re.compile(r"(?<!\w)__(?=[a-zA-Z])[a-zA-Z0-9_]*[a-zA-Z]__(?!\w)")),
    ("base64.b64decode", re.compile(r"base64\.b64decode", re.IGNORECASE)),
    ("eval(", re.compile(r"eval\s*\(", re.IGNORECASE)),
    ("exec(", re.compile(r"exec\s*\(", re.IGNORECASE)),
    ("os.system", re.compile(r"os\.system", re.IGNORECASE)),
    ("os.popen", re.compile(r"os\.popen", re.IGNORECASE)),
    ("os.spawn*", re.compile(r"os\.spawn[a-z]*", re.IGNORECASE)),
    (
        "subprocess call",
        re.compile(r"subprocess\.(?:Popen|call|check_output|run|check_call)", re.IGNORECASE),
    ),
    ("commands call", re.compile(r"commands\.(?:getoutput|getstatusoutput)", re.IGNORECASE)),
    ("import statement", re.compile(r"\bimport\s+[\w.]+", re.IGNORECASE)),
    ("importlib", re.compile(r"importlib", re.IGNORECASE)),
    ("__import__(", re.compile(r"__import__\s*\(", re.IGNORECASE)),
    ("hex escape", re.compile(r"\\x[0-9a-fA-F]{2}")),
    (
        "getattr system",
        re.compile(r"getattr\s*\(\s*\w+\s*,\s*['\"]system['\"]\s*\)", re.IGNORECASE),
    ),
    (
        "getattr exec",
        re.compile(r"getattr\s*\(\s*\w+\s*,\s*['\"]exec['\"]\s*\)", re.IGNORECASE),
    ),
    (
        "getattr eval",
        re.compile(r"getattr\s*\(\s*\w+\s*,\s*['\"]eval['\"]\s*\)", re.IGNORECASE),
    ),
    (
        "getattr popen",
        re.compile(r"getattr\s*\(\s*\w+\s*,\s*['\"]popen['\"]\s*\)", re.IGNORECASE),
    ),
    (
        "getattr process call",
        re.compile(r"getattr\s*\(\s*\w+\s*,\s*['\"](?:spawn|call|run|Popen)['\"]\s*\)", re.IGNORECASE),
    ),
    ("nested getattr", re.compile(r"getattr\s*\(\s*getattr\s*\(", re.IGNORECASE)),
)


def global_severity(module: str, name: str) -> Severity | None:
    """Return the severity for a pickle global reference, if it is unsafe."""
    warning_names = _WARNING_GLOBALS.get(module)
    if warning_names is None and module in _WARNING_GLOBALS:
        return Severity.WARNING
    if warning_names is not None and name in warning_names:
        return Severity.WARNING

    if module in _BUILTIN_MODULES:
        return Severity.CRITICAL if name in _BUILTIN_DANGEROUS_NAMES else None

    if (module, name) in _DANGEROUS_GLOBALS:
        return Severity.CRITICAL

    top_level_module = module.split(".", 1)[0]
    if module in _DANGEROUS_WILDCARD_MODULES or top_level_module in _DANGEROUS_WILDCARD_MODULES:
        return Severity.CRITICAL

    return None


def suspicious_string_matches(value: str) -> Iterator[str]:
    """Yield policy labels for suspicious code-like string content."""
    for label, pattern in _SUSPICIOUS_STRING_PATTERNS:
        if pattern.search(value):
            yield label
