pub(crate) fn global_severity(module: &str, name: &str) -> Option<&'static str> {
    if (module == "os" && name == "path") || module == "os.path" {
        return None;
    }

    if warning_globals(module).is_some_and(|warning_match| warning_match.matches(name)) {
        return Some("warning");
    }

    if BUILTIN_MODULES.contains(&module) {
        return if builtin_dangerous_name_is_listed(name) {
            Some("critical")
        } else {
            None
        };
    }

    if dangerous_pathlib_method_is_listed(module, name) {
        return Some("critical");
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

fn builtin_dangerous_name_is_listed(name: &str) -> bool {
    BUILTIN_DANGEROUS_NAMES.binary_search(&name).is_ok()
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

fn dangerous_pathlib_method_is_listed(module: &str, name: &str) -> bool {
    if !PATHLIB_MODULES.contains(&module) {
        return false;
    }
    let Some((path_class, method)) = name.rsplit_once('.') else {
        return false;
    };
    PATHLIB_CONCRETE_PATH_CLASSES.contains(&path_class)
        && PATHLIB_FILESYSTEM_ACCESS_METHODS.contains(&method)
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
    "dict.__delitem__",
    "dict.__ior__",
    "dict.__setitem__",
    "dict.clear",
    "dict.pop",
    "dict.popitem",
    "dict.setdefault",
    "dict.update",
    "dir",
    "eval",
    "exec",
    "execfile",
    "exit",
    "getattr",
    "globals",
    "input",
    "list.__delitem__",
    "list.__iadd__",
    "list.__imul__",
    "list.__setitem__",
    "list.append",
    "list.clear",
    "list.extend",
    "list.insert",
    "list.pop",
    "list.remove",
    "list.reverse",
    "list.sort",
    "locals",
    "open",
    "quit",
    "raw_input",
    "reload",
    "setattr",
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
    ("_posixsubprocess", "fork_exec"),
    ("_pyrepl.pager", "pipe_pager"),
    ("aifc", "open"),
    ("argparse", "FileType"),
    ("base64", "b64decode"),
    ("base64", "b64encode"),
    ("base64", "decode"),
    ("bz2", "open"),
    ("codecs", "decode"),
    ("codecs", "encode"),
    ("codecs", "open"),
    ("collections", "eval"),
    ("configparser", "ConfigParser.read"),
    ("configparser", "RawConfigParser.read"),
    ("copyreg", "add_extension"),
    ("copyreg", "pickle"),
    ("copyreg", "remove_extension"),
    ("dbm", "open"),
    ("decimal", "setcontext"),
    ("dill", "load"),
    ("dill", "load_module"),
    ("dill", "load_module_asdict"),
    ("dill", "load_session"),
    ("dill", "loads"),
    ("faulthandler", "_fatal_error_c_thread"),
    ("faulthandler", "_read_null"),
    ("faulthandler", "_sigabrt"),
    ("faulthandler", "_sigfpe"),
    ("faulthandler", "_sigsegv"),
    ("faulthandler", "_stack_overflow"),
    ("faulthandler", "disable"),
    ("functools", "reduce"),
    ("gc", "disable"),
    ("gzip", "open"),
    ("io", "open"),
    ("joblib", "_pickle_load"),
    ("joblib", "load"),
    ("logging", "FileHandler"),
    ("logging", "captureWarnings"),
    ("logging", "disable"),
    ("logging.config", "dictConfig"),
    ("logging.config", "fileConfig"),
    ("logging.config", "listen"),
    ("logging.handlers", "RotatingFileHandler"),
    ("logging.handlers", "TimedRotatingFileHandler"),
    ("logging.handlers", "WatchedFileHandler"),
    ("lzma", "open"),
    ("mailbox", "Maildir"),
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
    ("resource", "setrlimit"),
    ("site", "addpackage"),
    ("site", "addsitedir"),
    ("site", "main"),
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
    ("warnings", "filterwarnings"),
    ("warnings", "resetwarnings"),
    ("warnings", "simplefilter"),
    ("wave", "open"),
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
        assert_eq!(global_severity("joblib", "load"), Some("critical"));
        assert_eq!(
            global_severity("copyreg", "add_extension"),
            Some("critical")
        );
        assert_eq!(global_severity("copyreg", "pickle"), Some("critical"));
        assert_eq!(
            global_severity("builtins", "dict.__setitem__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("builtins", "dict.__delitem__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("builtins", "dict.__ior__"),
            Some("critical")
        );
        assert_eq!(global_severity("builtins", "dict.clear"), Some("critical"));
        assert_eq!(global_severity("builtins", "dict.pop"), Some("critical"));
        assert_eq!(
            global_severity("builtins", "dict.popitem"),
            Some("critical")
        );
        assert_eq!(
            global_severity("builtins", "dict.setdefault"),
            Some("critical")
        );
        assert_eq!(global_severity("builtins", "dict.update"), Some("critical"));
        assert_eq!(
            global_severity("builtins", "list.__delitem__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("builtins", "list.__iadd__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("builtins", "list.__imul__"),
            Some("critical")
        );
        assert_eq!(
            global_severity("builtins", "list.__setitem__"),
            Some("critical")
        );
        assert_eq!(global_severity("builtins", "list.append"), Some("critical"));
        assert_eq!(global_severity("builtins", "list.clear"), Some("critical"));
        assert_eq!(global_severity("builtins", "list.extend"), Some("critical"));
        assert_eq!(global_severity("builtins", "list.insert"), Some("critical"));
        assert_eq!(global_severity("builtins", "list.pop"), Some("critical"));
        assert_eq!(global_severity("builtins", "list.remove"), Some("critical"));
        assert_eq!(
            global_severity("builtins", "list.reverse"),
            Some("critical")
        );
        assert_eq!(global_severity("builtins", "list.sort"), Some("critical"));
        assert_eq!(global_severity("io", "open"), Some("critical"));
        assert_eq!(global_severity("logging", "FileHandler"), Some("critical"));
        assert_eq!(
            global_severity("logging.handlers", "RotatingFileHandler"),
            Some("critical")
        );
        assert_eq!(global_severity("dbm", "open"), Some("critical"));
        assert_eq!(global_severity("mailbox", "Maildir"), Some("critical"));
        assert_eq!(global_severity("argparse", "FileType"), Some("critical"));
        assert_eq!(global_severity("codecs", "open"), Some("critical"));
        assert_eq!(global_severity("gzip", "open"), Some("critical"));
        assert_eq!(global_severity("bz2", "open"), Some("critical"));
        assert_eq!(global_severity("lzma", "open"), Some("critical"));
        assert_eq!(global_severity("wave", "open"), Some("critical"));
        assert_eq!(global_severity("aifc", "open"), Some("critical"));
        assert_eq!(global_severity("sunau", "open"), Some("critical"));
        assert_eq!(global_severity("decimal", "setcontext"), Some("critical"));
        assert_eq!(global_severity("gc", "disable"), Some("critical"));
        assert_eq!(global_severity("logging", "disable"), Some("critical"));
        assert_eq!(
            global_severity("logging", "captureWarnings"),
            Some("critical")
        );
        assert_eq!(
            global_severity("warnings", "simplefilter"),
            Some("critical")
        );
        assert_eq!(
            global_severity("warnings", "filterwarnings"),
            Some("critical")
        );
        assert_eq!(
            global_severity("warnings", "resetwarnings"),
            Some("critical")
        );
        assert_eq!(global_severity("faulthandler", "disable"), Some("critical"));
        assert_eq!(
            global_severity("configparser", "ConfigParser.read"),
            Some("critical")
        );
        assert_eq!(
            global_severity("configparser", "RawConfigParser.read"),
            Some("critical")
        );
        assert_eq!(global_severity("site", "addpackage"), Some("critical"));
        assert_eq!(global_severity("site", "addsitedir"), Some("critical"));
        assert_eq!(global_severity("site", "main"), Some("critical"));
        assert_eq!(
            global_severity("tempfile", "NamedTemporaryFile"),
            Some("critical")
        );
        assert_eq!(global_severity("custom", "load"), None);
        assert_eq!(global_severity("configparser", "ConfigParser"), None);
        assert_eq!(global_severity("configparser", "ConfigParser.get"), None);
        assert_eq!(global_severity("logging", "getLogger"), None);
        assert_eq!(global_severity("tempfile", "gettempdir"), None);
    }

    #[test]
    fn warning_global_matching_uses_explicit_any_name_policy() {
        assert_eq!(global_severity("glob", "anything"), Some("warning"));
        assert_eq!(global_severity("functools", "partial"), Some("warning"));
        assert_eq!(global_severity("functools", "reduce"), Some("critical"));
        assert_eq!(global_severity("linecache", "clearcache"), None);
    }

    #[test]
    fn pathlib_filesystem_access_methods_are_dangerous_without_wildcarding_pathlib() {
        assert_eq!(
            global_severity("pathlib", "PosixPath.touch"),
            Some("critical")
        );
        assert_eq!(
            global_severity("pathlib", "PosixPath.read_text"),
            Some("critical")
        );
        assert_eq!(
            global_severity("pathlib", "WindowsPath.read_bytes"),
            Some("critical")
        );
        assert_eq!(
            global_severity("pathlib", "PosixPath.iterdir"),
            Some("critical")
        );
        assert_eq!(
            global_severity("pathlib._local", "PosixPath.iterdir"),
            Some("critical")
        );
        assert_eq!(
            global_severity("pathlib._local", "PosixPath.read_text"),
            Some("critical")
        );
        assert_eq!(global_severity("pathlib", "Path.glob"), Some("critical"));
        assert_eq!(global_severity("pathlib", "Path.rglob"), Some("critical"));
        assert_eq!(global_severity("pathlib", "Path.stat"), Some("critical"));
        assert_eq!(
            global_severity("pathlib", "Path.readlink"),
            Some("critical")
        );
        assert_eq!(global_severity("pathlib", "Path.exists"), Some("critical"));
        assert_eq!(global_severity("pathlib", "Path.is_file"), Some("critical"));
        assert_eq!(global_severity("pathlib", "Path.is_dir"), Some("critical"));
        assert_eq!(
            global_severity("pathlib", "WindowsPath.write_text"),
            Some("critical")
        );
        assert_eq!(global_severity("pathlib", "Path.open"), Some("critical"));
        assert_eq!(global_severity("pathlib", "PosixPath"), None);
        assert_eq!(global_severity("pathlib", "PurePosixPath.touch"), None);
        assert_eq!(global_severity("pathlib", "PosixPath.as_posix"), None);
        assert_eq!(
            global_severity("pathlib._local", "PosixPath.as_posix"),
            None
        );
        assert_eq!(global_severity("pathlib.extra", "PosixPath.touch"), None);
    }
}
