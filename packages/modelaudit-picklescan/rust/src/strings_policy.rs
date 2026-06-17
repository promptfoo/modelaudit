pub(crate) const MIN_BASE64_TEXT_TOKEN_CHARS: usize = 12;
pub(crate) const MAX_BASE64_TEXT_CANDIDATES: usize = 256;
pub(crate) const MAX_BASE64_TEXT_TOKEN_CHARS: usize = 16 * 1024;
pub(crate) const MIN_LITERAL_PADDING_BOUNDARY_CHARS: usize = 16;

// Complete base64 quartets that remain stable for each possible byte alignment.
pub(crate) const BASE64_DANGEROUS_SEEDS: &[&str] = &[
    // Encoded fragments for each byte alignment.
    "b3Mu", "LnN5", "cy5z", // os.system
    "ZXZh", "YWwo", "YWwg", "YWwJ", "YWwN", "YWwK", "YWxc", "dmFs", // eval
    "ZXhl", "ZWMo", "ZWMg", "ZWMJ", "ZWMN", "ZWMK", "ZWNc", "eGVj", // exec
    "X19p", "aW1w", "X2lt", // __import__
    "c3Vi", "YnBy", "dWJw", // subprocess
    "c3lz", "c3Rl", "eXN0", // system
    "Z2V0", "dGF0", "ZXRh", // getattr
];

// Four decoded bytes fit inside overlapping two-quartet windows for every
// alignment. Case-folding these fragments keeps the prefilter in parity with
// the case-insensitive dangerous-call classifier.
pub(crate) const BASE64_CASEFOLD_DANGEROUS_SEEDS: &[&[u8]] = &[
    b"os.s", b"eval", b"exec", b"__im", b"subp", b"syst", b"geta",
];

pub(crate) struct ModuleAttrPattern {
    pub(crate) module: &'static str,
    pub(crate) attr: &'static str,
    pub(crate) label: &'static str,
    pub(crate) prefix: bool,
}

pub(crate) const CALL_LIKE_PATTERNS: &[(&str, &str)] = &[
    ("base64.b64decode", "base64.b64decode"),
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
