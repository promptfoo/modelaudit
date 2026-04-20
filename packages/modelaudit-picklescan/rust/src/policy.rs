pub(crate) fn global_severity(module: &str, name: &str) -> Option<&'static str> {
    direct_global_severity(module, name).or_else(|| dotted_global_tail_severity(name))
}

fn direct_global_severity(module: &str, name: &str) -> Option<&'static str> {
    direct_global_severity_without_callable_alias(module, name)
        .or_else(|| callable_global_alias_severity(module, name))
}

fn callable_global_alias_severity(module: &str, name: &str) -> Option<&'static str> {
    let mut candidate = name;
    while let Some(stripped) = candidate.strip_suffix(".__call__") {
        candidate = stripped;
        if let Some(severity) = direct_global_severity_without_callable_alias(module, candidate) {
            return Some(severity);
        }
    }
    None
}

fn direct_global_severity_without_callable_alias(module: &str, name: &str) -> Option<&'static str> {
    if (module == "os" && name == "path") || module == "os.path" {
        return None;
    }

    if attribute_access_source_method_is_dangerous(name) {
        return Some("critical");
    }

    if object_graph_source_method_is_dangerous(name) {
        return Some("critical");
    }

    if warning_globals(module).is_some_and(|warning_match| warning_match.matches(name)) {
        return Some("warning");
    }

    if pathlib_concrete_path_alias_is_dangerous(module, name) || namespace_global_is_dangerous(name)
    {
        return Some("critical");
    }

    if BUILTIN_MODULES.contains(&module) {
        return if builtin_global_is_dangerous(name) {
            Some("critical")
        } else {
            None
        };
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

    let parts = name.split('.').collect::<Vec<_>>();
    for start in 0..parts.len().saturating_sub(1) {
        for split in start + 1..parts.len() {
            let candidate_module = parts[start..split].join(".");
            let candidate_name = parts[split..].join(".");
            if let Some(severity) = direct_global_severity(&candidate_module, &candidate_name) {
                return Some(severity);
            }
        }
    }
    None
}

#[derive(Clone, Copy)]
enum WarningGlobalMatch {
    AnyName,
    OneOf(&'static [&'static str]),
}

impl WarningGlobalMatch {
    fn matches(self, name: &str) -> bool {
        match self {
            Self::AnyName => true,
            Self::OneOf(names) => names.contains(&name),
        }
    }
}

fn dangerous_global_is_listed(module: &str, name: &str) -> bool {
    DANGEROUS_GLOBALS
        .binary_search_by(|&(candidate_module, candidate_name)| {
            match candidate_module.cmp(module) {
                std::cmp::Ordering::Equal => candidate_name.cmp(name),
                ordering => ordering,
            }
        })
        .is_ok()
}

fn warning_globals(module: &str) -> Option<WarningGlobalMatch> {
    match module {
        "functools" => Some(WarningGlobalMatch::OneOf(&["partial", "partialmethod"])),
        "glob" => Some(WarningGlobalMatch::AnyName),
        "linecache" => Some(WarningGlobalMatch::OneOf(&["getline"])),
        "tempfile" => Some(WarningGlobalMatch::OneOf(&["mktemp"])),
        _ => None,
    }
}

fn builtin_global_is_dangerous(name: &str) -> bool {
    BUILTIN_DANGEROUS_NAMES.contains(&name) || namespace_global_is_dangerous(name)
}

fn pathlib_concrete_path_alias_is_dangerous(module: &str, name: &str) -> bool {
    if module != "pathlib" {
        return false;
    }
    let Some((class_name, method_name)) = name.split_once('.') else {
        return false;
    };
    matches!(class_name, "PosixPath" | "WindowsPath")
        && matches!(method_name, "open" | "write_bytes" | "write_text")
}

fn namespace_global_is_dangerous(name: &str) -> bool {
    name_contains_component(name, &["__builtins__", "__dict__", "__globals__"])
}

fn attribute_access_source_method_is_dangerous(name: &str) -> bool {
    name_contains_component(name, &["__getattribute__"])
}

fn object_graph_source_method_is_dangerous(name: &str) -> bool {
    name_contains_component(name, &["__subclasses__"])
}

fn name_contains_component(name: &str, blocked_components: &[&str]) -> bool {
    name.split('.')
        .any(|component| blocked_components.contains(&component))
}

const BUILTIN_MODULES: &[&str] = &["builtins", "__builtin__", "__builtins__"];
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
    ("argparse", "FileType"),
    ("atexit", "register"),
    ("base64", "b64decode"),
    ("base64", "b64encode"),
    ("base64", "decode"),
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
    ("contextlib", "ExitStack.__exit__"),
    ("contextlib", "ExitStack.callback"),
    ("contextlib", "ExitStack.close"),
    ("contextlib", "ExitStack.enter_context"),
    ("contextvars", "Context.run"),
    ("copyreg", "add_extension"),
    ("copyreg", "remove_extension"),
    ("csv", "DictWriter.writerow"),
    ("csv", "DictWriter.writerows"),
    ("dataclasses", "_create_fn"),
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
    ("functools", "cache"),
    ("functools", "cached_property.__get__"),
    ("functools", "cmp_to_key"),
    ("functools", "lru_cache"),
    ("functools", "reduce"),
    ("functools", "singledispatch"),
    ("gc", "get_objects"),
    ("gc", "get_referents"),
    ("gc", "get_referrers"),
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
    ("logging", "critical"),
    ("logging", "debug"),
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
    ("mailbox", "Babyl.add"),
    ("mailbox", "MMDF.add"),
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
    ("pathlib", "Path.open"),
    ("pathlib", "Path.write_bytes"),
    ("pathlib", "Path.write_text"),
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
    ("tarfile", "open"),
    ("tempfile", "NamedTemporaryFile"),
    ("test.support.script_helper", "assert_python_ok"),
    ("torch", "compile"),
    ("torch", "load"),
    ("torch._dynamo.guards.GuardBuilder", "get"),
    ("torch._inductor.codecache", "compile_file"),
    (
        "torch.fx.experimental.symbolic_shapes.ShapeEnv",
        "evaluate_guards_expression",
    ),
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

    #[test]
    fn dangerous_global_table_is_sorted_for_binary_search() {
        for pair in DANGEROUS_GLOBALS.windows(2) {
            assert!(pair[0] < pair[1], "DANGEROUS_GLOBALS must stay sorted");
        }
    }

    #[test]
    fn dangerous_global_lookup_uses_sorted_table() {
        assert_eq!(global_severity("joblib", "load"), Some("critical"));
        assert_eq!(global_severity("mailcap", "findmatch"), Some("critical"));
        assert_eq!(global_severity("atexit", "register"), Some("critical"));
        assert_eq!(
            global_severity("setuptools._distutils.spawn", "spawn"),
            Some("critical")
        );
        assert_eq!(global_severity("pipes", "Template.copy"), Some("critical"));
        assert_eq!(global_severity("pipes", "Template.open"), Some("critical"));
        assert_eq!(global_severity("operator", "call"), Some("critical"));
        assert_eq!(global_severity("site", "os.system"), Some("critical"));
        assert_eq!(
            global_severity("sysconfig", "prefix.os.system"),
            Some("critical")
        );
        assert_eq!(
            global_severity("site", "logging.config.dictConfig"),
            Some("critical")
        );
        assert_eq!(
            global_severity("site", "logging.config.dictConfig.__call__"),
            Some("critical")
        );
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
        for (module, name) in [
            ("statistics", "__getattribute__"),
            ("statistics", "mean.__getattribute__"),
            ("statistics", "mean.__globals__"),
            ("collections", "Counter.__subclasses__"),
        ] {
            assert_eq!(global_severity(module, name), Some("critical"));
        }
        assert_eq!(global_severity("statistics", "mean.__name__"), None);
        assert_eq!(
            global_severity("statistics", "mean.__name__.__call__"),
            None
        );
        assert_eq!(global_severity("statistics", "mean.subclasses"), None);
        assert_eq!(global_severity("os.path", "__call__"), None);
        assert_eq!(global_severity("builtins", "filter"), Some("critical"));
        assert_eq!(global_severity("builtins", "hasattr"), Some("critical"));
        assert_eq!(global_severity("builtins", "map"), Some("critical"));
        assert_eq!(
            global_severity("builtins", "staticmethod"),
            Some("critical")
        );
        assert_eq!(
            global_severity("builtins", "property.__get__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("builtins", "classmethod.__get__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("codecs", "StreamReaderWriter.write"),
            Some("critical")
        );
        assert_eq!(global_severity("codecs", "open"), Some("critical"));
        assert_eq!(global_severity("_functools", "partial"), Some("critical"));
        assert_eq!(global_severity("_functools", "reduce"), Some("critical"));
        for name in ["FileIO", "FileIO.write", "TextIOWrapper.write", "open"] {
            assert_eq!(global_severity("_io", name), Some("critical"));
        }
        for name in ["TkappType.call", "TkappType.eval"] {
            assert_eq!(global_severity("_tkinter", name), Some("critical"));
        }
        assert_eq!(
            global_severity("_xxsubinterpreters", "run_string"),
            Some("critical")
        );
        assert_eq!(global_severity("argparse", "FileType"), Some("critical"));
        assert_eq!(global_severity("functools", "cache"), Some("critical"));
        assert_eq!(
            global_severity("functools", "cached_property.__get__"),
            Some("critical")
        );
        assert_eq!(global_severity("functools", "cmp_to_key"), Some("critical"));
        assert_eq!(global_severity("functools", "lru_cache"), Some("critical"));
        assert_eq!(
            global_severity("functools", "singledispatch"),
            Some("critical")
        );
        for name in ["get_objects", "get_referents", "get_referrers"] {
            assert_eq!(global_severity("gc", name), Some("critical"));
        }
        assert_eq!(global_severity("inspect", "currentframe"), Some("critical"));
        assert_eq!(
            global_severity("inspect", "currentframe.__call__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("inspect", "currentframe.__call__.__call__"),
            Some("critical")
        );
        assert_eq!(global_severity("inspect", "getmembers"), Some("critical"));
        assert_eq!(global_severity("itertools", "accumulate"), Some("critical"));
        assert_eq!(global_severity("itertools", "dropwhile"), Some("critical"));
        assert_eq!(
            global_severity("itertools", "filterfalse"),
            Some("critical")
        );
        assert_eq!(global_severity("itertools", "groupby"), Some("critical"));
        assert_eq!(global_severity("itertools", "starmap"), Some("critical"));
        assert_eq!(global_severity("itertools", "takewhile"), Some("critical"));
        assert_eq!(global_severity("typing", "_eval_type"), Some("critical"));
        assert_eq!(
            global_severity("typing", "get_type_hints"),
            Some("critical")
        );
        assert_eq!(
            global_severity("logging", "Filterer.filter"),
            Some("critical")
        );
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
        assert_eq!(global_severity("numpy", "savetxt"), Some("critical"));
        assert_eq!(
            global_severity("numpy.lib._npyio_impl", "savetxt"),
            Some("critical")
        );
        for name in ["Path.open", "Path.write_bytes", "Path.write_text"] {
            assert_eq!(global_severity("pathlib", name), Some("critical"));
        }
        for class_name in ["PosixPath", "WindowsPath"] {
            for method_name in ["open", "write_bytes", "write_text"] {
                assert_eq!(
                    global_severity("pathlib", &format!("{class_name}.{method_name}")),
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
        for (module, name) in [
            ("unittest", "TestLoader.discover"),
            ("unittest", "defaultTestLoader.discover"),
            ("unittest.loader", "TestLoader.discover"),
            ("unittest.loader", "defaultTestLoader.discover"),
            ("unittest.loader", "TestLoader.loadTestsFromName"),
            ("unittest.loader", "TestLoader.loadTestsFromNames"),
        ] {
            assert_eq!(global_severity(module, name), Some("critical"));
        }
        assert_eq!(global_severity("unittest.mock", "Mock"), Some("critical"));
        assert_eq!(
            global_severity("unittest.mock", "MagicMock"),
            Some("critical")
        );
        assert_eq!(
            global_severity("unittest.mock", "_get_target"),
            Some("critical")
        );
        for name in [
            "_patch.__enter__",
            "_patch.start",
            "patch",
            "patch.dict",
            "patch.multiple",
        ] {
            assert_eq!(global_severity("unittest.mock", name), Some("critical"));
        }
        assert_eq!(
            global_severity("copyreg", "add_extension"),
            Some("critical")
        );
        assert_eq!(
            global_severity("csv", "DictWriter.writerow"),
            Some("critical")
        );
        assert_eq!(
            global_severity("csv", "DictWriter.writerows"),
            Some("critical")
        );
        assert_eq!(
            global_severity("concurrent.futures", "ProcessPoolExecutor.submit"),
            Some("critical")
        );
        assert_eq!(
            global_severity("concurrent.futures", "ProcessPoolExecutor.map"),
            Some("critical")
        );
        assert_eq!(
            global_severity("concurrent.futures", "ProcessPoolExecutor.shutdown"),
            Some("critical")
        );
        assert_eq!(
            global_severity("concurrent.futures", "ThreadPoolExecutor.submit"),
            Some("critical")
        );
        assert_eq!(
            global_severity("concurrent.futures", "ThreadPoolExecutor.map"),
            Some("critical")
        );
        assert_eq!(
            global_severity("concurrent.futures", "ThreadPoolExecutor.shutdown"),
            Some("critical")
        );
        assert_eq!(
            global_severity("contextlib", "ExitStack.callback"),
            Some("critical")
        );
        assert_eq!(
            global_severity("contextlib", "ExitStack.close"),
            Some("critical")
        );
        assert_eq!(
            global_severity("contextlib", "ExitStack.__exit__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("contextlib", "ExitStack.enter_context"),
            Some("critical")
        );
        assert_eq!(
            global_severity("contextvars", "Context.run"),
            Some("critical")
        );
        assert_eq!(global_severity("weakref", "finalize"), Some("critical"));
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
        for (module, name) in [
            ("yaml.cyaml", "CLoader"),
            ("yaml.cyaml", "CUnsafeLoader"),
            ("yaml.loader", "Loader"),
            ("yaml.loader", "UnsafeLoader"),
        ] {
            assert_eq!(global_severity(module, name), Some("critical"));
        }
        for name in ["CFullLoader", "CSafeLoader", "FullLoader", "SafeLoader"] {
            assert_eq!(global_severity("yaml", name), None);
        }
        assert_eq!(
            global_severity("sched", "scheduler.enter"),
            Some("critical")
        );
        assert_eq!(
            global_severity("sched", "scheduler.enterabs"),
            Some("critical")
        );
        assert_eq!(global_severity("sched", "scheduler.run"), Some("critical"));
        assert_eq!(
            global_severity("dataclasses", "_create_fn"),
            Some("critical")
        );
        for module in ["dotenv", "dotenv.cli", "dotenv.main"] {
            assert_eq!(global_severity(module, "set_key"), Some("critical"));
            assert_eq!(global_severity(module, "unset_key"), None);
        }
        assert_eq!(
            global_severity("tempfile", "NamedTemporaryFile"),
            Some("critical")
        );
        assert_eq!(global_severity("types", "MethodType"), Some("critical"));
        assert_eq!(
            global_severity("types", "ClassMethodDescriptorType.__get__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("types", "DynamicClassAttribute.__get__"),
            Some("critical")
        );
        for name in [
            "FrameType.f_builtins.__get__",
            "FrameType.f_globals.__get__",
            "FrameType.f_locals.__get__",
        ] {
            assert_eq!(global_severity("types", name), Some("critical"));
            assert_eq!(
                global_severity("types", &format!("{name}.__call__")),
                Some("critical")
            );
            assert_eq!(
                global_severity("types", &format!("{name}.__call__.__call__")),
                Some("critical")
            );
        }
        assert_eq!(
            global_severity("types", "GetSetDescriptorType.__get__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("types", "MemberDescriptorType.__get__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("types", "MethodDescriptorType.__get__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("types", "WrapperDescriptorType.__get__"),
            Some("critical")
        );
        assert_eq!(global_severity("site", "addsitedir"), Some("critical"));
        assert_eq!(global_severity("site", "addpackage"), Some("critical"));
        assert_eq!(
            global_severity("string", "Formatter.get_field"),
            Some("critical")
        );
        assert_eq!(global_severity("custom", "load"), None);
    }

    #[test]
    fn warning_global_matching_uses_explicit_any_name_policy() {
        assert_eq!(global_severity("glob", "anything"), Some("warning"));
        assert_eq!(global_severity("functools", "partial"), Some("warning"));
        assert_eq!(global_severity("functools", "reduce"), Some("critical"));
        assert_eq!(global_severity("linecache", "clearcache"), None);
    }
}
