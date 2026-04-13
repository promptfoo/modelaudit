pub(crate) fn global_severity(module: &str, name: &str) -> Option<&'static str> {
    if (module == "os" && name == "path") || module == "os.path" {
        return None;
    }

    if warning_globals(module).is_some_and(|warning_match| warning_match.matches(name)) {
        return Some("warning");
    }

    if BUILTIN_MODULES.contains(&module) {
        return if BUILTIN_DANGEROUS_NAMES.contains(&name) {
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

const BUILTIN_MODULES: &[&str] = &["builtins", "__builtin__", "__builtins__"];
const BUILTIN_DANGEROUS_NAMES: &[&str] = &[
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
];
const DANGEROUS_WILDCARD_MODULES: &[&str] = &[
    "_ctypes",
    "_operator",
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
    ("_operator", "attrgetter"),
    ("_operator", "itemgetter"),
    ("_operator", "methodcaller"),
    ("_osx_support", "_read_output"),
    ("_pyrepl.pager", "pipe_pager"),
    ("base64", "b64decode"),
    ("base64", "b64encode"),
    ("base64", "decode"),
    ("codecs", "decode"),
    ("codecs", "encode"),
    ("collections", "eval"),
    ("copyreg", "add_extension"),
    ("copyreg", "remove_extension"),
    ("dill", "load"),
    ("dill", "load_module"),
    ("dill", "load_module_asdict"),
    ("dill", "load_session"),
    ("dill", "loads"),
    ("functools", "reduce"),
    ("joblib", "_pickle_load"),
    ("joblib", "load"),
    ("logging.config", "dictConfig"),
    ("logging.config", "fileConfig"),
    ("logging.config", "listen"),
    ("numpy", "load"),
    ("numpy.f2py.crackfortran", "getlincoef"),
    ("numpy.testing._private.utils", "runstring"),
    ("operator", "attrgetter"),
    ("operator", "itemgetter"),
    ("operator", "methodcaller"),
    ("pip", "main"),
    ("pip._internal", "main"),
    ("pip._internal.cli.main", "main"),
    ("pip._vendor.distlib.scripts", "ScriptMaker"),
    ("pkgutil", "get_importer"),
    ("pkgutil", "resolve_name"),
    ("pkgutil", "walk_packages"),
    ("site", "main"),
    ("tarfile", "open"),
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
    ("types", "CodeType"),
    ("types", "FunctionType"),
    ("uuid", "_arp_getnode"),
    ("uuid", "_get_command_stdout"),
    ("uuid", "_ifconfig_getnode"),
    ("uuid", "_ip_getnode"),
    ("uuid", "_lanscan_getnode"),
    ("uuid", "_netstat_getnode"),
    ("uuid", "_popen"),
    ("uuid", "getnode"),
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
        assert_eq!(
            global_severity("copyreg", "add_extension"),
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
