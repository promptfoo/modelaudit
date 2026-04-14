pub(crate) const MAX_BASE64_TEXT_TOKENS: usize = 32;
pub(crate) const MIN_BASE64_TEXT_TOKEN_CHARS: usize = 12;
pub(crate) const MAX_BASE64_TEXT_TOKEN_CHARS: usize = 16 * 1024;
pub(crate) const MIN_LITERAL_PADDING_BOUNDARY_CHARS: usize = 16;

pub(crate) const BASE64_DANGEROUS_SEEDS: &[&str] = &[
    "b3Muc3lzdGVt",   // os.system
    "ZXZh",           // eval prefix; the following base64 chars depend on the next bytes
    "ZXhl",           // exec prefix; the following base64 chars depend on the next bytes
    "X19p",           // __import__ prefix
    "c3VicHJvY2Vzcw", // subprocess
];

pub(crate) struct ModuleAttrPattern {
    pub(crate) module: &'static str,
    pub(crate) attr: &'static str,
    pub(crate) label: &'static str,
    pub(crate) prefix: bool,
}

pub(crate) const SIMPLE_SUBSTRING_PATTERNS: &[(&str, &str)] =
    &[("base64.b64decode", "base64.b64decode")];

pub(crate) const CALL_LIKE_PATTERNS: &[(&str, &str)] = &[
    ("compile", "compile("),
    ("eval", "eval("),
    ("exec", "exec("),
];

pub(crate) const MODULE_ATTR_PATTERNS: &[ModuleAttrPattern] = &[
    ModuleAttrPattern {
        module: "os",
        attr: "system",
        label: "os.system",
        prefix: false,
    },
    ModuleAttrPattern {
        module: "os",
        attr: "popen",
        label: "os.popen",
        prefix: false,
    },
    ModuleAttrPattern {
        module: "os",
        attr: "spawn",
        label: "os.spawn*",
        prefix: true,
    },
];

pub(crate) const SUBPROCESS_CALL_NEEDLES: &[&str] = &[
    "subprocess.popen",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.run",
    "subprocess.check_call",
];

pub(crate) const COMMANDS_CALL_NEEDLES: &[&str] =
    &["commands.getoutput", "commands.getstatusoutput"];

pub(crate) const PICKLE_LOADER_NEEDLES: &[&str] = &[
    "joblib.load",
    "joblib._pickle_load",
    "cloudpickle.load",
    "cloudpickle.loads",
];

pub(crate) const COPYREG_EXTENSION_NEEDLES: &[&str] =
    &["copyreg.add_extension", "copyreg.remove_extension"];

pub(crate) const GETATTR_TARGET_PATTERNS: &[(&str, &str)] = &[
    ("system", "getattr system"),
    ("exec", "getattr exec"),
    ("eval", "getattr eval"),
    ("popen", "getattr popen"),
];

pub(crate) const GETATTR_PROCESS_TARGETS: &[&str] = &["spawn", "call", "run", "popen"];
