pub(crate) fn global_severity(module: &str, name: &str) -> Option<&'static str> {
    if let Some(warning_names) = warning_globals(module) {
        if warning_names.is_empty() || warning_names.contains(&name) {
            return Some("warning");
        }
    }

    if BUILTIN_MODULES.contains(&module) {
        return if BUILTIN_DANGEROUS_NAMES.contains(&name) {
            Some("critical")
        } else {
            None
        };
    }

    if DANGEROUS_GLOBALS.contains(&(module, name)) {
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

fn warning_globals(module: &str) -> Option<&'static [&'static str]> {
    match module {
        "functools" => Some(&["partial", "partialmethod"]),
        "glob" => Some(&[]),
        "linecache" => Some(&["getline"]),
        "tempfile" => Some(&["mktemp"]),
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
    "telnetlib",
    "threading",
    "timeit",
    "trace",
    "urllib",
    "urllib2",
    "venv",
    "webbrowser",
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
    ("dill", "load"),
    ("dill", "loads"),
    ("functools", "reduce"),
    ("joblib", "_pickle_load"),
    ("joblib", "load"),
    ("logging.config", "dictConfig"),
    ("logging.config", "fileConfig"),
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
    ("tarfile", "open"),
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
