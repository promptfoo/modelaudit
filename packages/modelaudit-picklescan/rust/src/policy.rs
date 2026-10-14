const MAX_DOTTED_GLOBAL_BYTES: usize = 4096;
const MAX_DOTTED_GLOBAL_SEGMENTS: usize = 64;

pub(crate) fn global_severity(module: &str, name: &str) -> Option<&'static str> {
    let direct = direct_global_severity(module, name);
    if direct == Some("critical") {
        return direct;
    }
    let tail = dotted_global_tail_severity(name);
    if tail == Some("critical") {
        return tail;
    }
    direct.or(tail)
}

pub(crate) fn callable_severity(module: &str, name: &str) -> Option<&'static str> {
    global_severity(module, name).or_else(|| pathlib_callable_severity(module, name))
}

pub(crate) fn global_import_requires_review(module: &str, name: &str) -> bool {
    !global_import_is_allowlisted(module, name) && global_severity(module, name).is_none()
}

pub(crate) fn global_import_is_allowlisted(module: &str, name: &str) -> bool {
    IMPORT_ONLY_GLOBAL_ALLOWLIST_MODULES.contains(&module)
        || legacy_pickle_compat_reference_is_allowlisted(module, name)
}

fn legacy_pickle_compat_reference_is_allowlisted(module: &str, name: &str) -> bool {
    (module == "copy_reg" && name == "_reconstructor")
        || (module == "exceptions" && LEGACY_BUILTIN_EXCEPTION_NAMES.contains(&name))
}

fn pathlib_callable_severity(module: &str, name: &str) -> Option<&'static str> {
    let mut candidate = name;
    loop {
        if pathlib_concrete_path_alias_is_dangerous(module, candidate) {
            return Some("critical");
        }
        let stripped = strip_wrapper_global_suffix(candidate)?;
        candidate = stripped;
    }
}

fn direct_global_severity(module: &str, name: &str) -> Option<&'static str> {
    direct_global_severity_without_wrapper_alias(module, name)
        .or_else(|| wrapper_global_alias_severity(module, name))
        .or_else(|| dangerous_global_prefix_severity(module, name))
        .or_else(|| dotted_global_policy_budget_exceeded(name).then_some("warning"))
}

fn wrapper_global_alias_severity(module: &str, name: &str) -> Option<&'static str> {
    let mut candidate = name;
    while let Some(stripped) = strip_wrapper_global_suffix(candidate) {
        candidate = stripped;
        if let Some(severity) = direct_global_severity_without_wrapper_alias(module, candidate) {
            return Some(severity);
        }
    }
    None
}

fn strip_wrapper_global_suffix(name: &str) -> Option<&str> {
    for suffix in [".__call__", ".__get__", ".__self__"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return Some(stripped);
        }
    }
    None
}

fn dangerous_global_prefix_severity(module: &str, name: &str) -> Option<&'static str> {
    for (segments_seen, (split, _)) in name.match_indices('.').enumerate() {
        if segments_seen >= MAX_DOTTED_GLOBAL_SEGMENTS || split > MAX_DOTTED_GLOBAL_BYTES {
            break;
        }
        let tail = &name[split + 1..];
        if is_inert_global_metadata_tail(tail) {
            continue;
        }
        let candidate = &name[..split];
        if let Some(severity) = direct_global_severity_without_wrapper_alias(module, candidate)
            .or_else(|| wrapper_global_alias_severity(module, candidate))
        {
            return Some(severity);
        }
    }
    None
}

fn is_inert_global_metadata_tail(tail: &str) -> bool {
    matches!(tail, "__doc__" | "__name__" | "__module__" | "__qualname__")
}

fn direct_global_severity_without_wrapper_alias(module: &str, name: &str) -> Option<&'static str> {
    if (module == "os" && name == "path") || module == "os.path" {
        return None;
    }

    if name_contains_component(name, &["__getattribute__", "__subclasses__"]) {
        return Some("critical");
    }

    if matches!(
        (module, name),
        ("functools", "partial" | "partialmethod")
            | ("glob", _)
            | ("linecache", "getline")
            | ("tempfile", "mktemp")
    ) {
        return Some("warning");
    }

    if namespace_global_is_dangerous(name) {
        return Some("critical");
    }

    if BUILTIN_MODULES.contains(&module) {
        return if BUILTIN_DANGEROUS_NAMES.binary_search(&name).is_ok() {
            Some("critical")
        } else {
            None
        };
    }

    if operator_container_mutator_is_target_aware(module, name) {
        return None;
    }

    if dangerous_global_is_listed(module, name) {
        return Some("critical");
    }

    let top_level_module = module.split('.').next().unwrap_or(module);
    if DANGEROUS_WILDCARD_MODULES.contains(&module)
        || DANGEROUS_WILDCARD_MODULES.contains(&top_level_module)
    {
        return Some("critical");
    }

    None
}

fn dotted_global_tail_severity(name: &str) -> Option<&'static str> {
    if !name.contains('.') {
        return None;
    }

    let parts = bounded_leading_dotted_parts(name);
    let mut warning = None;
    for start in 0..parts.len().saturating_sub(1) {
        for split in start + 1..parts.len() {
            let candidate_module = parts[start..split].join(".");
            let candidate_name = parts[split..].join(".");
            if let Some(severity) = direct_global_severity(&candidate_module, &candidate_name) {
                if severity == "critical" {
                    return Some(severity);
                }
                warning = Some(severity);
            }
        }
    }
    warning.or_else(|| dotted_global_policy_budget_exceeded(name).then_some("warning"))
}

fn dotted_global_policy_budget_exceeded(name: &str) -> bool {
    name.len() > MAX_DOTTED_GLOBAL_BYTES
        || name.split('.').take(MAX_DOTTED_GLOBAL_SEGMENTS + 1).count() > MAX_DOTTED_GLOBAL_SEGMENTS
}

fn bounded_leading_dotted_parts(name: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut bytes: usize = 0;
    for part in name.split('.') {
        let separator_bytes = usize::from(!parts.is_empty());
        let Some(next_bytes) = bytes
            .checked_add(separator_bytes)
            .and_then(|total| total.checked_add(part.len()))
        else {
            break;
        };
        if parts.len() >= MAX_DOTTED_GLOBAL_SEGMENTS || next_bytes > MAX_DOTTED_GLOBAL_BYTES {
            break;
        }
        parts.push(part);
        bytes = next_bytes;
    }
    parts
}

fn dangerous_global_is_listed(module: &str, name: &str) -> bool {
    DANGEROUS_GLOBALS.binary_search(&(module, name)).is_ok()
}

fn operator_container_mutator_is_target_aware(module: &str, name: &str) -> bool {
    matches!(module, "operator" | "_operator")
        && matches!(name, "delitem" | "iadd" | "imul" | "ior" | "setitem")
}

fn pathlib_concrete_path_alias_is_dangerous(module: &str, name: &str) -> bool {
    if !PATHLIB_MODULES.contains(&module) {
        return false;
    }
    let Some((class_name, method_name)) = name.rsplit_once('.') else {
        return false;
    };
    PATHLIB_CONCRETE_PATH_CLASSES.contains(&class_name)
        && PATHLIB_FILESYSTEM_ACCESS_METHODS.contains(&method_name)
}

fn namespace_global_is_dangerous(name: &str) -> bool {
    name_contains_component(name, &["__builtins__", "__dict__", "__globals__"])
}

fn name_contains_component(name: &str, blocked_components: &[&str]) -> bool {
    name.split('.')
        .any(|component| blocked_components.contains(&component))
}

const BUILTIN_MODULES: &[&str] = &["builtins", "__builtin__", "__builtins__"];
const IMPORT_ONLY_GLOBAL_ALLOWLIST_MODULES: &[&str] = &[
    "__builtin__",
    "__builtins__",
    "_operator",
    "_pytest",
    "_pytest._py.path",
    "_tkinter",
    "array",
    "builtins",
    "click",
    "collections",
    "collections.abc",
    "copyreg",
    "datetime",
    "decimal",
    "enum",
    "fractions",
    "functools",
    "heapq",
    "itertools",
    "joblib",
    "joblib.numpy_pickle",
    "logging",
    "mailbox",
    "math",
    "numpy",
    "numpy._core.multiarray",
    "numpy.core.multiarray",
    "operator",
    "pathlib",
    "pathlib._local",
    "random",
    "re",
    "torch",
    "torch._utils",
    "types",
    "uuid",
];
const LEGACY_BUILTIN_EXCEPTION_NAMES: &[&str] = &[
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BaseException",
    "BufferError",
    "BytesWarning",
    "DeprecationWarning",
    "EOFError",
    "EnvironmentError",
    "Exception",
    "FloatingPointError",
    "FutureWarning",
    "GeneratorExit",
    "IOError",
    "ImportError",
    "ImportWarning",
    "IndentationError",
    "IndexError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "NameError",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PendingDeprecationWarning",
    "ReferenceError",
    "RuntimeError",
    "RuntimeWarning",
    "StandardError",
    "StopIteration",
    "SyntaxError",
    "SyntaxWarning",
    "SystemError",
    "SystemExit",
    "TabError",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "UnicodeWarning",
    "UserWarning",
    "ValueError",
    "VMSError",
    "Warning",
    "WindowsError",
    "ZeroDivisionError",
];
const BUILTIN_DANGEROUS_NAMES: &[&str] = &[
    "__import__",
    "breakpoint",
    "classmethod.__get__",
    "compile",
    "delattr",
    "dir",
    "eval",
    "exec",
    "execfile",
    "exit",
    "filter",
    "getattr",
    "globals",
    "hasattr",
    "input",
    "locals",
    "map",
    "open",
    "property.__get__",
    "quit",
    "raw_input",
    "reload",
    "setattr",
    "staticmethod",
    "vars",
];
const PATHLIB_MODULES: &[&str] = &["pathlib", "pathlib._local"];
const PATHLIB_CONCRETE_PATH_CLASSES: &[&str] = &["Path", "PosixPath", "WindowsPath"];
const PATHLIB_FILESYSTEM_ACCESS_METHODS: &[&str] = &[
    "chmod",
    "exists",
    "glob",
    "hardlink_to",
    "is_dir",
    "is_file",
    "iterdir",
    "lchmod",
    "lstat",
    "mkdir",
    "open",
    "read_bytes",
    "read_text",
    "readlink",
    "rename",
    "replace",
    "rglob",
    "rmdir",
    "stat",
    "symlink_to",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
];
const DANGEROUS_WILDCARD_MODULES: &[&str] = &[
    "_ctypes",
    "_operator",
    "_pickle",
    "_posixsubprocess",
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
    "httpx",
    "idlelib",
    "imaplib",
    "importlib",
    "lib2to3",
    "marshal",
    "mmap",
    "multiprocessing",
    "nntplib",
    "nt",
    "ntpath",
    "os",
    "pdb",
    "pexpect",
    "pickle",
    "pip",
    "poplib",
    "posix",
    "posixpath",
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
    "telnetlib",
    "threading",
    "timeit",
    "trace",
    "urllib",
    "urllib2",
    "venv",
    "webbrowser",
    "xmlrpc",
    "xmlrpc.client",
    "xmlrpc.server",
    "zipimport",
];
const DANGEROUS_GLOBALS: &[(&str, &str)] = &[
    ("_aix_support", "_read_cmd_output"),
    ("_functools", "partial"),
    ("_functools", "reduce"),
    ("_io", "FileIO"),
    ("_io", "FileIO.write"),
    ("_io", "TextIOWrapper.write"),
    ("_io", "open"),
    ("_operator", "attrgetter"),
    ("_operator", "itemgetter"),
    ("_operator", "methodcaller"),
    ("_osx_support", "_read_output"),
    ("_posixsubprocess", "fork_exec"),
    ("_pyrepl.pager", "pipe_pager"),
    ("_tkinter", "TkappType.call"),
    ("_tkinter", "TkappType.eval"),
    ("_xxsubinterpreters", "run_string"),
    ("aifc", "open"),
    ("argparse", "FileType"),
    ("atexit", "register"),
    ("base64", "b64decode"),
    ("base64", "b64encode"),
    ("base64", "decode"),
    ("bz2", "open"),
    ("codecs", "StreamReaderWriter.write"),
    ("codecs", "decode"),
    ("codecs", "encode"),
    ("codecs", "open"),
    ("collections", "eval"),
    ("concurrent.futures", "ProcessPoolExecutor.map"),
    ("concurrent.futures", "ProcessPoolExecutor.shutdown"),
    ("concurrent.futures", "ProcessPoolExecutor.submit"),
    ("concurrent.futures", "ThreadPoolExecutor.map"),
    ("concurrent.futures", "ThreadPoolExecutor.shutdown"),
    ("concurrent.futures", "ThreadPoolExecutor.submit"),
    ("configparser", "ConfigParser.read"),
    ("configparser", "RawConfigParser.read"),
    ("contextlib", "ExitStack.__exit__"),
    ("contextlib", "ExitStack.callback"),
    ("contextlib", "ExitStack.close"),
    ("contextlib", "ExitStack.enter_context"),
    ("contextvars", "Context.run"),
    ("copyreg", "add_extension"),
    ("copyreg", "pickle"),
    ("copyreg", "remove_extension"),
    ("csv", "DictWriter.writerow"),
    ("csv", "DictWriter.writerows"),
    ("dataclasses", "_create_fn"),
    ("dbm", "open"),
    ("decimal", "setcontext"),
    ("dill", "load"),
    ("dill", "load_module"),
    ("dill", "load_module_asdict"),
    ("dill", "load_session"),
    ("dill", "loads"),
    ("dotenv", "set_key"),
    ("dotenv.cli", "set_key"),
    ("dotenv.main", "set_key"),
    ("faulthandler", "_fatal_error_c_thread"),
    ("faulthandler", "_read_null"),
    ("faulthandler", "_sigabrt"),
    ("faulthandler", "_sigfpe"),
    ("faulthandler", "_sigsegv"),
    ("faulthandler", "_stack_overflow"),
    ("faulthandler", "disable"),
    ("functools", "cache"),
    ("functools", "cached_property.__get__"),
    ("functools", "cmp_to_key"),
    ("functools", "lru_cache"),
    ("functools", "reduce"),
    ("functools", "singledispatch"),
    ("gc", "disable"),
    ("gc", "get_objects"),
    ("gc", "get_referents"),
    ("gc", "get_referrers"),
    ("gzip", "open"),
    ("inspect", "currentframe"),
    ("inspect", "getmembers"),
    ("io", "FileIO"),
    ("io", "FileIO.write"),
    ("io", "TextIOWrapper.write"),
    ("io", "open"),
    ("itertools", "accumulate"),
    ("itertools", "dropwhile"),
    ("itertools", "filterfalse"),
    ("itertools", "groupby"),
    ("itertools", "starmap"),
    ("itertools", "takewhile"),
    ("joblib", "_pickle_load"),
    ("joblib", "load"),
    ("logging", "FileHandler"),
    ("logging", "FileHandler.emit"),
    ("logging", "Filterer.filter"),
    ("logging", "Handler.handle"),
    ("logging", "Logger._log"),
    ("logging", "Logger.addHandler"),
    ("logging", "Logger.callHandlers"),
    ("logging", "Logger.critical"),
    ("logging", "Logger.debug"),
    ("logging", "Logger.error"),
    ("logging", "Logger.exception"),
    ("logging", "Logger.handle"),
    ("logging", "Logger.info"),
    ("logging", "Logger.log"),
    ("logging", "Logger.warn"),
    ("logging", "Logger.warning"),
    ("logging", "StreamHandler"),
    ("logging", "StreamHandler.emit"),
    ("logging", "captureWarnings"),
    ("logging", "critical"),
    ("logging", "debug"),
    ("logging", "disable"),
    ("logging", "error"),
    ("logging", "exception"),
    ("logging", "info"),
    ("logging", "log"),
    ("logging", "warn"),
    ("logging", "warning"),
    ("logging.config", "dictConfig"),
    ("logging.config", "fileConfig"),
    ("logging.config", "listen"),
    ("logging.handlers", "RotatingFileHandler"),
    ("logging.handlers", "TimedRotatingFileHandler"),
    ("logging.handlers", "WatchedFileHandler"),
    ("lzma", "open"),
    ("mailbox", "Babyl.add"),
    ("mailbox", "MMDF.add"),
    ("mailbox", "Maildir"),
    ("mailbox", "_singlefileMailbox.add"),
    ("mailbox", "mbox.add"),
    ("mailcap", "findmatch"),
    ("numpy", "load"),
    ("numpy", "savetxt"),
    ("numpy.f2py.crackfortran", "getlincoef"),
    ("numpy.lib._npyio_impl", "savetxt"),
    ("numpy.testing._private.utils", "runstring"),
    ("operator", "attrgetter"),
    ("operator", "call"),
    ("operator", "itemgetter"),
    ("operator", "methodcaller"),
    ("pip", "main"),
    ("pip._internal", "main"),
    ("pip._internal.cli.main", "main"),
    ("pip._vendor.distlib.scripts", "ScriptMaker"),
    ("pipes", "Template.copy"),
    ("pipes", "Template.open"),
    ("pipes", "Template.open_r"),
    ("pipes", "Template.open_w"),
    ("pkgutil", "get_importer"),
    ("pkgutil", "resolve_name"),
    ("pkgutil", "walk_packages"),
    ("resource", "setrlimit"),
    ("sched", "scheduler.enter"),
    ("sched", "scheduler.enterabs"),
    ("sched", "scheduler.run"),
    ("setuptools._distutils.spawn", "spawn"),
    ("site", "addpackage"),
    ("site", "addsitedir"),
    ("site", "main"),
    ("string", "Formatter.get_field"),
    ("sunau", "open"),
    ("tarfile", "open"),
    ("tempfile", "NamedTemporaryFile"),
    ("tempfile", "TemporaryDirectory"),
    ("tempfile", "mkdtemp"),
    ("tempfile", "mkstemp"),
    ("test.support.script_helper", "assert_python_ok"),
    ("torch", "compile"),
    ("torch", "load"),
    ("torch._dynamo.guards.GuardBuilder", "get"),
    ("torch._inductor.codecache", "compile_file"),
    (
        "torch.fx.experimental.symbolic_shapes.ShapeEnv",
        "evaluate_guards_expression",
    ),
    ("torch.hub", "download_url_to_file"),
    ("torch.hub", "load"),
    ("torch.hub", "load_state_dict_from_url"),
    ("torch.serialization", "load"),
    ("torch.storage", "_load_from_bytes"),
    ("torch.utils._config_module.ConfigModule", "load_config"),
    ("torch.utils.bottleneck.__main__", "run_autograd_prof"),
    ("torch.utils.bottleneck.__main__", "run_cprofile"),
    ("torch.utils.collect_env", "run"),
    ("torch.utils.data.datapipes.utils.decoder", "basichandlers"),
    ("types", "ClassMethodDescriptorType.__get__"),
    ("types", "CodeType"),
    ("types", "DynamicClassAttribute.__get__"),
    ("types", "FrameType.f_builtins.__get__"),
    ("types", "FrameType.f_globals.__get__"),
    ("types", "FrameType.f_locals.__get__"),
    ("types", "FunctionType"),
    ("types", "GetSetDescriptorType.__get__"),
    ("types", "MemberDescriptorType.__get__"),
    ("types", "MethodDescriptorType.__get__"),
    ("types", "MethodType"),
    ("types", "WrapperDescriptorType.__get__"),
    ("typing", "_eval_type"),
    ("typing", "get_type_hints"),
    ("unittest", "TestLoader.discover"),
    ("unittest", "TestLoader.loadTestsFromName"),
    ("unittest", "TestLoader.loadTestsFromNames"),
    ("unittest", "defaultTestLoader.discover"),
    ("unittest", "defaultTestLoader.loadTestsFromName"),
    ("unittest", "defaultTestLoader.loadTestsFromNames"),
    ("unittest.loader", "TestLoader.discover"),
    ("unittest.loader", "TestLoader.loadTestsFromName"),
    ("unittest.loader", "TestLoader.loadTestsFromNames"),
    ("unittest.loader", "defaultTestLoader.discover"),
    ("unittest.loader", "defaultTestLoader.loadTestsFromName"),
    ("unittest.loader", "defaultTestLoader.loadTestsFromNames"),
    ("unittest.mock", "MagicMock"),
    ("unittest.mock", "Mock"),
    ("unittest.mock", "_get_target"),
    ("unittest.mock", "_patch.__enter__"),
    ("unittest.mock", "_patch.start"),
    ("unittest.mock", "patch"),
    ("unittest.mock", "patch.dict"),
    ("unittest.mock", "patch.multiple"),
    ("uuid", "_arp_getnode"),
    ("uuid", "_get_command_stdout"),
    ("uuid", "_ifconfig_getnode"),
    ("uuid", "_ip_getnode"),
    ("uuid", "_lanscan_getnode"),
    ("uuid", "_netstat_getnode"),
    ("uuid", "_popen"),
    ("uuid", "getnode"),
    ("warnings", "filterwarnings"),
    ("warnings", "resetwarnings"),
    ("warnings", "simplefilter"),
    ("wave", "open"),
    ("weakref", "finalize"),
    ("yaml", "CLoader"),
    ("yaml", "CUnsafeLoader"),
    ("yaml", "Loader"),
    ("yaml", "UnsafeLoader"),
    ("yaml", "load"),
    ("yaml", "load_all"),
    ("yaml", "unsafe_load"),
    ("yaml", "unsafe_load_all"),
    ("yaml.cyaml", "CLoader"),
    ("yaml.cyaml", "CUnsafeLoader"),
    ("yaml.loader", "Loader"),
    ("yaml.loader", "UnsafeLoader"),
    ("zipfile", "PyZipFile"),
    ("zipfile", "ZipFile"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn assert_critical_globals(cases: &[(&str, &str)]) {
        for (module, name) in cases {
            assert_eq!(
                global_severity(module, name),
                Some("critical"),
                "{module}.{name}"
            );
        }
    }

    #[test]
    fn dangerous_global_table_is_sorted_for_binary_search() {
        for pair in DANGEROUS_GLOBALS.windows(2) {
            assert!(pair[0] < pair[1], "DANGEROUS_GLOBALS must stay sorted");
        }
    }

    #[test]
    fn builtin_dangerous_names_are_sorted_for_binary_search() {
        for pair in BUILTIN_DANGEROUS_NAMES.windows(2) {
            assert!(
                pair[0] < pair[1],
                "BUILTIN_DANGEROUS_NAMES must stay sorted"
            );
        }
    }

    #[test]
    fn dangerous_global_lookup_uses_sorted_table() {
        assert_critical_globals(&[
            ("joblib", "load"),
            ("mailcap", "findmatch"),
            ("atexit", "register"),
            ("setuptools._distutils.spawn", "spawn"),
            ("pipes", "Template.copy"),
            ("pipes", "Template.open"),
            ("operator", "call"),
        ]);
        assert_eq!(global_severity("operator", "setitem"), None);
        assert_critical_globals(&[
            ("site", "os.system"),
            ("sysconfig", "prefix.os.system"),
            ("site", "logging.config.dictConfig"),
            ("site", "logging.config.dictConfig.__call__"),
            ("site", "logging.config.dictConfig.__get__.__self__"),
            ("site", "logging.config.dictConfig.__repr__.__self__"),
        ]);
        for module in BUILTIN_MODULES {
            for name in [
                "__dict__",
                "__dict__.get",
                "__dict__.__getitem__",
                "__builtins__",
                "__builtins__.get",
                "__globals__",
                "__globals__.get",
                "object.__getattribute__",
                "object.__subclasses__",
            ] {
                assert_eq!(global_severity(module, name), Some("critical"));
            }
        }
        assert_critical_globals(&[
            ("statistics", "__getattribute__"),
            ("statistics", "mean.__getattribute__"),
            ("statistics", "mean.__globals__"),
            ("collections", "Counter.__subclasses__"),
        ]);
        for name in ["__getattribute__", "__subclasses__"] {
            assert_eq!(global_severity("glob", name), Some("critical"));
            assert_eq!(global_severity("os.path", name), None);
            assert_eq!(global_severity("safe", &format!("x{name}")), None);
            assert_eq!(global_severity("safe", &format!("{name}x")), None);
        }
        for (module, name) in [
            ("statistics", "mean.__name__"),
            ("statistics", "mean.__name__.__call__"),
            ("statistics", "mean.__get__"),
            ("statistics", "mean.__get__.__self__"),
            ("statistics", "mean.__repr__.__self__"),
            ("statistics", "mean.__self__"),
            ("statistics", "mean.subclasses"),
        ] {
            assert_eq!(global_severity(module, name), None, "{module}.{name}");
        }
        for name in [
            "eval.__doc__",
            "eval.__name__",
            "eval.__module__",
            "eval.__qualname__",
        ] {
            assert_eq!(global_severity("builtins", name), None);
        }
        assert_eq!(
            global_severity("builtins", "eval.__repr__.__self__"),
            Some("critical")
        );
        assert_eq!(global_severity("os.path", "__call__"), None);
        assert_eq!(global_severity("os.path", "__get__"), None);
        assert_eq!(global_severity("os.path", "__get__.__self__"), None);
        assert_eq!(global_severity("os.path", "__repr__.__self__"), None);
        assert_critical_globals(&[
            ("builtins", "filter"),
            ("builtins", "hasattr"),
            ("builtins", "map"),
            ("builtins", "staticmethod"),
            ("builtins", "property.__get__"),
            ("builtins", "classmethod.__get__"),
            ("codecs", "StreamReaderWriter.write"),
            ("codecs", "open"),
            ("_functools", "partial"),
            ("_functools", "reduce"),
        ]);
        for name in ["FileIO", "FileIO.write", "TextIOWrapper.write", "open"] {
            assert_eq!(global_severity("_io", name), Some("critical"));
        }
        for name in ["TkappType.call", "TkappType.eval"] {
            assert_eq!(global_severity("_tkinter", name), Some("critical"));
        }
        assert_critical_globals(&[
            ("_xxsubinterpreters", "run_string"),
            ("argparse", "FileType"),
            ("functools", "cache"),
            ("functools", "cached_property.__get__"),
            ("functools", "cmp_to_key"),
            ("functools", "lru_cache"),
            ("functools", "singledispatch"),
        ]);
        for name in ["get_objects", "get_referents", "get_referrers"] {
            assert_eq!(global_severity("gc", name), Some("critical"));
        }
        assert_critical_globals(&[
            ("inspect", "currentframe"),
            ("inspect", "currentframe.__call__"),
            ("inspect", "currentframe.__call__.__call__"),
            ("inspect", "currentframe.__get__"),
            ("inspect", "currentframe.__get__.__self__"),
            ("inspect", "currentframe.__get__.__self__.__call__"),
            ("inspect", "currentframe.__repr__"),
            ("inspect", "currentframe.__repr__.__self__"),
            ("inspect", "currentframe.__str__.__self__"),
            ("inspect", "currentframe.__reduce__.__self__"),
            ("inspect", "getmembers"),
            ("itertools", "accumulate"),
            ("itertools", "dropwhile"),
            ("itertools", "filterfalse"),
            ("itertools", "groupby"),
            ("itertools", "starmap"),
            ("itertools", "takewhile"),
            ("typing", "_eval_type"),
            ("typing", "get_type_hints"),
            ("logging", "Filterer.filter"),
        ]);
        for name in [
            "FileHandler",
            "FileHandler.emit",
            "Handler.handle",
            "Logger._log",
            "Logger.addHandler",
            "Logger.callHandlers",
            "Logger.critical",
            "Logger.debug",
            "Logger.error",
            "Logger.exception",
            "Logger.handle",
            "Logger.info",
            "Logger.log",
            "Logger.warn",
            "Logger.warning",
            "StreamHandler",
            "StreamHandler.emit",
            "critical",
            "debug",
            "error",
            "exception",
            "info",
            "log",
            "warn",
            "warning",
        ] {
            assert_eq!(global_severity("logging", name), Some("critical"));
        }
        for name in [
            "RotatingFileHandler",
            "TimedRotatingFileHandler",
            "WatchedFileHandler",
        ] {
            assert_eq!(global_severity("logging.handlers", name), Some("critical"));
        }
        for name in [
            "Babyl.add",
            "MMDF.add",
            "_singlefileMailbox.add",
            "mbox.add",
        ] {
            assert_eq!(global_severity("mailbox", name), Some("critical"));
        }
        for name in ["FileIO", "FileIO.write", "TextIOWrapper.write", "open"] {
            assert_eq!(global_severity("io", name), Some("critical"));
        }
        assert_critical_globals(&[("numpy", "savetxt"), ("numpy.lib._npyio_impl", "savetxt")]);
        for name in ["Path.open", "Path.write_bytes", "Path.write_text"] {
            assert_eq!(global_severity("pathlib", name), None);
            assert_eq!(callable_severity("pathlib", name), Some("critical"));
        }
        for class_name in ["PosixPath", "WindowsPath"] {
            for method_name in ["open", "write_bytes", "write_text"] {
                assert_eq!(
                    global_severity("pathlib", &format!("{class_name}.{method_name}")),
                    None
                );
                assert_eq!(
                    callable_severity("pathlib", &format!("{class_name}.{method_name}")),
                    Some("critical")
                );
            }
        }
        for name in [
            "__dict__",
            "__dict__.get",
            "__dict__.__getitem__",
            "__builtins__",
            "__builtins__.get",
        ] {
            assert_eq!(global_severity("site", name), Some("critical"));
            assert_eq!(global_severity("pathlib", name), Some("critical"));
            assert_eq!(global_severity("sysconfig", name), Some("critical"));
        }
        assert_eq!(global_severity("os.path", "__dict__"), None);
        assert_critical_globals(&[
            ("unittest", "TestLoader.discover"),
            ("unittest", "defaultTestLoader.discover"),
            ("unittest.loader", "TestLoader.discover"),
            ("unittest.loader", "defaultTestLoader.discover"),
            ("unittest.loader", "TestLoader.loadTestsFromName"),
            ("unittest.loader", "TestLoader.loadTestsFromNames"),
        ]);
        assert_critical_globals(&[
            ("unittest.mock", "Mock"),
            ("unittest.mock", "MagicMock"),
            ("unittest.mock", "_get_target"),
        ]);
        for name in [
            "_patch.__enter__",
            "_patch.start",
            "patch",
            "patch.dict",
            "patch.multiple",
        ] {
            assert_eq!(global_severity("unittest.mock", name), Some("critical"));
        }
        assert_critical_globals(&[("copyreg", "add_extension"), ("copyreg", "pickle")]);
        assert_eq!(global_severity("builtins", "dict.__setitem__"), None);
        assert_eq!(global_severity("builtins", "dict.update"), None);
        assert_eq!(global_severity("builtins", "list.append"), None);
        assert_eq!(global_severity("builtins", "list.clear"), None);
        assert_eq!(global_severity("operator", "setitem"), None);
        assert_eq!(global_severity("operator", "imul"), None);
        assert_eq!(global_severity("_operator", "setitem"), None);
        assert_eq!(global_severity("_operator", "imul"), None);
        assert_critical_globals(&[
            ("operator", "call"),
            ("io", "open"),
            ("logging", "FileHandler"),
            ("logging.handlers", "RotatingFileHandler"),
            ("dbm", "open"),
            ("mailbox", "Maildir"),
            ("argparse", "FileType"),
            ("codecs", "open"),
            ("gzip", "open"),
            ("bz2", "open"),
            ("lzma", "open"),
            ("wave", "open"),
            ("aifc", "open"),
            ("sunau", "open"),
            ("decimal", "setcontext"),
            ("gc", "disable"),
            ("logging", "disable"),
            ("logging", "captureWarnings"),
            ("warnings", "simplefilter"),
            ("warnings", "filterwarnings"),
            ("warnings", "resetwarnings"),
            ("faulthandler", "disable"),
            ("configparser", "ConfigParser.read"),
            ("configparser", "RawConfigParser.read"),
            ("site", "addpackage"),
            ("site", "addsitedir"),
            ("site", "main"),
            ("csv", "DictWriter.writerow"),
            ("csv", "DictWriter.writerows"),
            ("concurrent.futures", "ProcessPoolExecutor.submit"),
            ("concurrent.futures", "ProcessPoolExecutor.map"),
            ("concurrent.futures", "ProcessPoolExecutor.shutdown"),
            ("concurrent.futures", "ThreadPoolExecutor.submit"),
            ("concurrent.futures", "ThreadPoolExecutor.map"),
            ("concurrent.futures", "ThreadPoolExecutor.shutdown"),
            ("contextlib", "ExitStack.callback"),
            ("contextlib", "ExitStack.close"),
            ("contextlib", "ExitStack.__exit__"),
            ("contextlib", "ExitStack.enter_context"),
            ("contextvars", "Context.run"),
            ("weakref", "finalize"),
        ]);
        for name in [
            "CLoader",
            "CUnsafeLoader",
            "Loader",
            "UnsafeLoader",
            "load",
            "load_all",
            "unsafe_load",
            "unsafe_load_all",
        ] {
            assert_eq!(global_severity("yaml", name), Some("critical"));
        }
        assert_critical_globals(&[
            ("yaml.cyaml", "CLoader"),
            ("yaml.cyaml", "CUnsafeLoader"),
            ("yaml.loader", "Loader"),
            ("yaml.loader", "UnsafeLoader"),
        ]);
        for name in ["CFullLoader", "CSafeLoader", "FullLoader", "SafeLoader"] {
            assert_eq!(global_severity("yaml", name), None);
        }
        assert_critical_globals(&[
            ("sched", "scheduler.enter"),
            ("sched", "scheduler.enterabs"),
            ("sched", "scheduler.run"),
            ("dataclasses", "_create_fn"),
        ]);
        for module in ["dotenv", "dotenv.cli", "dotenv.main"] {
            assert_eq!(global_severity(module, "set_key"), Some("critical"));
            assert_eq!(global_severity(module, "unset_key"), None);
        }
        assert_critical_globals(&[
            ("tempfile", "NamedTemporaryFile"),
            ("types", "MethodType"),
            ("types", "ClassMethodDescriptorType.__get__"),
            ("types", "DynamicClassAttribute.__get__"),
        ]);
        for name in [
            "FrameType.f_builtins.__get__",
            "FrameType.f_globals.__get__",
            "FrameType.f_locals.__get__",
        ] {
            for suffix in [
                "",
                ".__call__",
                ".__call__.__call__",
                ".__self__",
                ".__self__.__get__",
                ".__self__.__get__.__call__",
                ".__repr__",
                ".__repr__.__self__",
                ".__str__.__self__",
            ] {
                assert_eq!(
                    global_severity("types", &format!("{name}{suffix}")),
                    Some("critical"),
                    "{name}{suffix}"
                );
            }
        }
        assert_critical_globals(&[
            ("types", "GetSetDescriptorType.__get__"),
            ("types", "MemberDescriptorType.__get__"),
            ("types", "MethodDescriptorType.__get__"),
            ("types", "WrapperDescriptorType.__get__"),
            ("site", "addsitedir"),
            ("site", "addpackage"),
            ("string", "Formatter.get_field"),
        ]);
        assert_eq!(global_severity("custom", "load"), None);
        assert_eq!(global_severity("configparser", "ConfigParser"), None);
        assert_eq!(global_severity("configparser", "ConfigParser.get"), None);
        assert_eq!(global_severity("logging", "getLogger"), None);
        assert_eq!(global_severity("tempfile", "gettempdir"), None);
    }

    #[test]
    fn import_only_global_review_policy_preserves_allowlisted_modules() {
        for module in [
            "builtins",
            "click",
            "collections",
            "collections.abc",
            "numpy._core.multiarray",
            "numpy.core.multiarray",
            "pathlib._local",
            "joblib.numpy_pickle",
            "torch._utils",
            "logging",
            "mailbox",
            "_pytest._py.path",
            "_tkinter",
            "random",
        ] {
            assert!(!global_import_requires_review(module, "KnownSafe"));
        }
        assert!(!global_import_requires_review(
            "_xxsubinterpreters",
            "run_string"
        ));
        assert!(!global_import_requires_review("dotenv.main", "set_key"));
        assert!(global_import_requires_review(
            "_xxsubinterpreters",
            "create"
        ));
        assert!(global_import_requires_review(
            "_xxsubinterpreters",
            "Gadget"
        ));
        assert!(global_import_requires_review("dotenv.main", "Gadget"));
        assert!(global_import_requires_review(
            "modelaudit_custom_payload",
            "Gadget"
        ));
        assert!(global_import_requires_review("numpy.evil", "Gadget"));
        assert!(global_import_requires_review("torch.evil", "Gadget"));
        assert!(global_import_requires_review("vendor.package", "Gadget"));
        assert!(!global_import_requires_review("copy_reg", "_reconstructor"));
        assert!(global_import_requires_review("copy_reg", "Gadget"));
        assert!(!global_import_requires_review("exceptions", "ValueError"));
        assert!(global_import_requires_review("exceptions", "Gadget"));
        assert_eq!(global_severity("commands", "getoutput"), Some("critical"));
        assert_eq!(global_severity("urllib2", "urlopen"), Some("critical"));
    }

    #[test]
    fn warning_global_matching_uses_explicit_any_name_policy() {
        assert_eq!(global_severity("glob", "anything"), Some("warning"));
        assert_eq!(global_severity("functools", "partial"), Some("warning"));
        assert_eq!(global_severity("functools", "reduce"), Some("critical"));
        assert_eq!(global_severity("linecache", "clearcache"), None);
        assert_eq!(
            global_severity("functools", "partialmethod"),
            Some("warning")
        );
        assert_eq!(global_severity("linecache", "getline"), Some("warning"));
        assert_eq!(global_severity("tempfile", "mktemp"), Some("warning"));
        assert_eq!(global_severity("FUNCTOOLS", "partial"), None);
        assert_eq!(global_severity("functools", "Partial"), None);
        assert_eq!(global_severity("linecache", "getline_extra"), None);
        assert_eq!(global_severity("glob", ""), Some("warning"));
        assert_eq!(global_severity("glob", "__dict__"), Some("warning"));
        assert_eq!(global_severity("glob", "__globals__"), Some("warning"));
    }

    #[test]
    fn dotted_global_lookup_is_segment_bounded() {
        let long_dotted_name = (0..(MAX_DOTTED_GLOBAL_SEGMENTS + 4))
            .map(|index| format!("part{index}"))
            .collect::<Vec<_>>()
            .join(".");

        assert_eq!(global_severity("safe", &long_dotted_name), Some("warning"));
        assert_eq!(
            global_severity("os", &format!("system.{long_dotted_name}")),
            Some("critical")
        );
        let long_dotted_tail = format!("pkg.os.system.{long_dotted_name}");
        let bounded_tail = bounded_leading_dotted_parts(&long_dotted_tail);
        assert_eq!(&bounded_tail[..3], &["pkg", "os", "system"]);
        assert_eq!(
            direct_global_severity("os", &bounded_tail[2..].join(".")),
            Some("critical")
        );
        assert_eq!(
            global_severity("safe", &format!("pkg.os.system.{long_dotted_name}")),
            Some("critical")
        );
        assert_eq!(
            global_severity("safe", "wrapper.os.system"),
            Some("critical")
        );
        assert_eq!(global_severity("safe", "wrapper.custom.loader"), None);
    }

    #[test]
    fn pathlib_filesystem_access_methods_are_dangerous_without_wildcarding_pathlib() {
        for (module, name) in [
            ("pathlib", "PosixPath.touch"),
            ("pathlib", "PosixPath.read_text"),
            ("pathlib", "WindowsPath.read_bytes"),
            ("pathlib", "PosixPath.iterdir"),
            ("pathlib._local", "PosixPath.iterdir"),
            ("pathlib._local", "PosixPath.read_text"),
            ("pathlib", "Path.glob"),
            ("pathlib", "Path.rglob"),
            ("pathlib", "Path.stat"),
            ("pathlib", "Path.readlink"),
            ("pathlib", "Path.exists"),
            ("pathlib", "Path.is_file"),
            ("pathlib", "Path.is_dir"),
            ("pathlib", "WindowsPath.write_text"),
            ("pathlib", "Path.open"),
        ] {
            assert_eq!(
                callable_severity(module, name),
                Some("critical"),
                "{module}.{name}"
            );
        }
        assert_eq!(global_severity("pathlib", "Path.touch"), None);
        assert_eq!(
            global_severity("pathlib._local", "PosixPath.read_text"),
            None
        );
        assert_eq!(global_severity("pathlib", "PosixPath"), None);
        assert_eq!(callable_severity("pathlib", "PurePosixPath.touch"), None);
        assert_eq!(callable_severity("pathlib", "PosixPath.as_posix"), None);
        assert_eq!(
            callable_severity("pathlib._local", "PosixPath.as_posix"),
            None
        );
        assert_eq!(callable_severity("pathlib.extra", "PosixPath.touch"), None);
    }
}
