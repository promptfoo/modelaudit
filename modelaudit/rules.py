"""
Rule system for ModelAudit - Simple, centralized rule definitions and management.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Pattern, Tuple


class Severity(str, Enum):
    """Severity levels for rules."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Rule:
    """Single rule definition."""
    code: str
    name: str
    default_severity: Severity
    description: str
    message_patterns: List[Pattern[str]]
    
    def matches_message(self, message: str) -> bool:
        """Check if this rule matches a given message."""
        return any(pattern.search(message) for pattern in self.message_patterns)


class RuleRegistry:
    """Central registry for all security rules."""
    
    _rules: Dict[str, Rule] = {}
    _initialized = False
    
    @classmethod
    def initialize(cls):
        """Initialize all rules. Called once at startup."""
        if cls._initialized:
            return
        
        # S100-S199: Code Execution
        cls._add_rule("S101", "os module import", Severity.CRITICAL,
                     "Operating system command execution via os module",
                     [r"import\s+os\b", r"from\s+os\s+import", r"__import__\(['\"]os['\"]"])
        
        cls._add_rule("S102", "sys module import", Severity.CRITICAL,
                     "System manipulation via sys module",
                     [r"import\s+sys\b", r"from\s+sys\s+import", r"__import__\(['\"]sys['\"]"])
        
        cls._add_rule("S103", "subprocess module import", Severity.CRITICAL,
                     "Process spawning via subprocess module",
                     [r"import\s+subprocess", r"from\s+subprocess\s+import", r"__import__\(['\"]subprocess['\"]"])
        
        cls._add_rule("S104", "eval/exec usage", Severity.CRITICAL,
                     "Dynamic code execution via eval or exec",
                     [r"\beval\s*\(", r"\bexec\s*\(", r"eval.*exec"])
        
        cls._add_rule("S105", "compile usage", Severity.CRITICAL,
                     "Code compilation at runtime",
                     [r"\bcompile\s*\(", r"compile.*function"])
        
        cls._add_rule("S106", "__import__ usage", Severity.CRITICAL,
                     "Dynamic module importing",
                     [r"__import__\s*\(", r"__import__"])
        
        cls._add_rule("S107", "importlib usage", Severity.HIGH,
                     "Dynamic import machinery via importlib",
                     [r"import\s+importlib", r"from\s+importlib\s+import", r"importlib\.import_module"])
        
        cls._add_rule("S108", "runpy module usage", Severity.CRITICAL,
                     "Running Python modules as scripts",
                     [r"import\s+runpy", r"from\s+runpy\s+import", r"runpy\.run_"])
        
        cls._add_rule("S109", "webbrowser module usage", Severity.CRITICAL,
                     "Opening web browsers programmatically",
                     [r"import\s+webbrowser", r"from\s+webbrowser\s+import", r"webbrowser\.open"])
        
        cls._add_rule("S110", "ctypes module usage", Severity.HIGH,
                     "Foreign function interface via ctypes",
                     [r"import\s+ctypes", r"from\s+ctypes\s+import", r"ctypes\."])
        
        # S200-S299: Pickle & Deserialization
        cls._add_rule("S201", "Pickle REDUCE opcode", Severity.CRITICAL,
                     "Arbitrary callable execution via pickle REDUCE",
                     [r"pickle.*REDUCE", r"REDUCE.*opcode", r"dangerous.*REDUCE"])
        
        cls._add_rule("S202", "Pickle INST opcode", Severity.CRITICAL,
                     "Class instantiation via pickle INST",
                     [r"pickle.*INST", r"INST.*opcode", r"dangerous.*INST"])
        
        cls._add_rule("S203", "Pickle OBJ opcode", Severity.CRITICAL,
                     "Object construction via pickle OBJ",
                     [r"pickle.*OBJ", r"OBJ.*opcode", r"dangerous.*OBJ"])
        
        cls._add_rule("S204", "Pickle NEWOBJ opcode", Severity.CRITICAL,
                     "New-style class construction via pickle NEWOBJ",
                     [r"pickle.*NEWOBJ", r"NEWOBJ.*opcode", r"dangerous.*NEWOBJ"])
        
        cls._add_rule("S205", "Pickle STACK_GLOBAL opcode", Severity.HIGH,
                     "Stack-based global retrieval via pickle",
                     [r"pickle.*STACK_GLOBAL", r"STACK_GLOBAL.*opcode"])
        
        cls._add_rule("S206", "Pickle GLOBAL opcode", Severity.HIGH,
                     "Global name resolution via pickle",
                     [r"pickle.*GLOBAL", r"GLOBAL.*opcode", r"imports.*module"])
        
        cls._add_rule("S207", "Pickle BUILD opcode", Severity.MEDIUM,
                     "Object building operations via pickle",
                     [r"pickle.*BUILD", r"BUILD.*opcode"])
        
        cls._add_rule("S208", "Pickle SETATTR opcode", Severity.HIGH,
                     "Attribute setting via pickle SETATTR",
                     [r"pickle.*SETATTR", r"SETATTR.*opcode"])
        
        cls._add_rule("S209", "Pickle SETITEM opcode", Severity.MEDIUM,
                     "Item assignment via pickle",
                     [r"pickle.*SETITEM", r"SETITEM.*opcode"])
        
        cls._add_rule("S210", "Pickle SETITEMS opcode", Severity.MEDIUM,
                     "Multiple item assignment via pickle",
                     [r"pickle.*SETITEMS", r"SETITEMS.*opcode"])
        
        # S300-S399: Network & Communication
        cls._add_rule("S301", "socket module usage", Severity.HIGH,
                     "Low-level networking via socket module",
                     [r"import\s+socket", r"from\s+socket\s+import", r"socket\."])
        
        cls._add_rule("S302", "requests/urllib usage", Severity.MEDIUM,
                     "HTTP client operations",
                     [r"import\s+requests", r"import\s+urllib", r"urllib\.request", r"requests\."])
        
        cls._add_rule("S303", "http.client usage", Severity.MEDIUM,
                     "HTTP protocol handling",
                     [r"import\s+http\.client", r"from\s+http\.client", r"http\.client"])
        
        cls._add_rule("S304", "ftplib usage", Severity.HIGH,
                     "FTP operations",
                     [r"import\s+ftplib", r"from\s+ftplib", r"ftplib\."])
        
        cls._add_rule("S305", "telnetlib usage", Severity.HIGH,
                     "Telnet protocol usage",
                     [r"import\s+telnetlib", r"from\s+telnetlib", r"telnetlib\."])
        
        cls._add_rule("S306", "smtplib usage", Severity.MEDIUM,
                     "Email sending capabilities",
                     [r"import\s+smtplib", r"from\s+smtplib", r"smtplib\."])
        
        cls._add_rule("S307", "DNS lookups", Severity.MEDIUM,
                     "Domain name resolution detected",
                     [r"socket\.gethostby", r"dns\.", r"getaddrinfo"])
        
        cls._add_rule("S308", "Hardcoded IP addresses", Severity.LOW,
                     "Static IP addresses found",
                     [r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"])
        
        cls._add_rule("S309", "Hardcoded URLs", Severity.LOW,
                     "Static URLs found",
                     [r"https?://", r"ftp://", r"ws://"])
        
        cls._add_rule("S310", "Data exfiltration patterns", Severity.HIGH,
                     "Potential data theft patterns",
                     [r"send.*data", r"post.*sensitive", r"upload.*file", r"exfiltrat"])
        
        # S400-S499: File System Operations
        cls._add_rule("S401", "open() for write/append", Severity.MEDIUM,
                     "File write operations detected",
                     [r"open\([^)]*['\"][wax]", r"open\([^)]*mode\s*=\s*['\"][wax]"])
        
        cls._add_rule("S402", "pathlib write operations", Severity.MEDIUM,
                     "Path-based file writes",
                     [r"Path.*write", r"\.write_text", r"\.write_bytes"])
        
        cls._add_rule("S403", "shutil operations", Severity.MEDIUM,
                     "File/directory operations via shutil",
                     [r"import\s+shutil", r"shutil\.", r"copy.*file", r"move.*file"])
        
        cls._add_rule("S404", "tempfile operations", Severity.LOW,
                     "Temporary file creation",
                     [r"import\s+tempfile", r"tempfile\.", r"NamedTemporaryFile"])
        
        cls._add_rule("S405", "Path traversal attempts", Severity.CRITICAL,
                     "Directory escape attempts detected",
                     [r"\.\./", r"\.\.\\", r"parent/parent", r"traversal"])
        
        cls._add_rule("S406", "Symlink to external location", Severity.HIGH,
                     "Symbolic link pointing outside scope",
                     [r"symlink.*external", r"link.*outside", r"symlink"])
        
        cls._add_rule("S407", "Hidden file access", Severity.LOW,
                     "Dotfile operations detected",
                     [r"/\.", r"\\\.", r"hidden.*file"])
        
        cls._add_rule("S408", "/etc or system file access", Severity.HIGH,
                     "System configuration file access",
                     [r"/etc/", r"\\system32\\", r"/usr/bin/", r"/Windows/"])
        
        cls._add_rule("S409", "Home directory access", Severity.MEDIUM,
                     "User directory operations",
                     [r"~/", r"home/", r"Users/", r"expanduser"])
        
        cls._add_rule("S410", "Archive bomb detected", Severity.HIGH,
                     "Excessive compression ratio",
                     [r"compression.*bomb", r"zip.*bomb", r"excessive.*ratio"])
        
        # S500-S599: Embedded Code & Executables
        cls._add_rule("S501", "Windows PE executable", Severity.CRITICAL,
                     "Windows binary embedded",
                     [r"PE.*executable", r"Windows.*executable", r"\.exe", r"MZ.*header"])
        
        cls._add_rule("S502", "Linux ELF executable", Severity.CRITICAL,
                     "Linux binary embedded",
                     [r"ELF.*executable", r"Linux.*executable", r"ELF.*header"])
        
        cls._add_rule("S503", "macOS Mach-O executable", Severity.CRITICAL,
                     "macOS binary embedded",
                     [r"Mach-O.*executable", r"macOS.*executable", r"Mach-O.*header"])
        
        cls._add_rule("S504", "Shell script", Severity.CRITICAL,
                     "Shell script embedded",
                     [r"#!/bin/sh", r"#!/bin/bash", r"shell.*script"])
        
        cls._add_rule("S505", "Batch script", Severity.CRITICAL,
                     "Windows batch script embedded",
                     [r"\.bat\b", r"\.cmd\b", r"batch.*script", r"@echo off"])
        
        cls._add_rule("S506", "PowerShell script", Severity.CRITICAL,
                     "PowerShell code embedded",
                     [r"\.ps1\b", r"PowerShell", r"Invoke-Expression"])
        
        cls._add_rule("S507", "Python script embedded", Severity.HIGH,
                     "Python code as string data",
                     [r"python.*script", r"embedded.*python", r"exec.*python"])
        
        cls._add_rule("S508", "JavaScript code", Severity.HIGH,
                     "JavaScript code embedded",
                     [r"javascript:", r"\.js\b", r"<script"])
        
        cls._add_rule("S509", "WebAssembly module", Severity.HIGH,
                     "WASM binary embedded",
                     [r"\.wasm\b", r"WebAssembly", r"wasm.*module"])
        
        cls._add_rule("S510", "JIT/TorchScript code", Severity.MEDIUM,
                     "JIT compiled code detected",
                     [r"TorchScript", r"JIT.*code", r"torch\.jit"])
        
        # S600-S699: Encoding & Obfuscation
        cls._add_rule("S601", "Base64 encoded payload", Severity.MEDIUM,
                     "Base64 encoded data detected",
                     [r"base64", r"b64decode", r"base64\.b64"])
        
        cls._add_rule("S602", "Hex encoded payload", Severity.MEDIUM,
                     "Hexadecimal encoded data",
                     [r"hex.*decode", r"fromhex", r"unhexlify"])
        
        cls._add_rule("S603", "zlib compressed data", Severity.LOW,
                     "Compressed content detected",
                     [r"zlib", r"compress", r"decompress"])
        
        cls._add_rule("S604", "Encrypted/obfuscated code", Severity.HIGH,
                     "Encrypted or obfuscated payloads",
                     [r"encrypt", r"obfuscat", r"cipher"])
        
        cls._add_rule("S605", "Unicode encoding tricks", Severity.MEDIUM,
                     "Unicode obfuscation detected",
                     [r"unicode.*escape", r"\\u[0-9a-f]{4}", r"unicode.*trick"])
        
        cls._add_rule("S606", "ROT13/Caesar cipher", Severity.LOW,
                     "Simple cipher detected",
                     [r"rot13", r"rot-13", r"caesar"])
        
        cls._add_rule("S607", "XOR obfuscation", Severity.MEDIUM,
                     "XOR encrypted data",
                     [r"xor.*encrypt", r"xor.*obfuscat", r"\^.*key"])
        
        # S700-S799: Secrets & Credentials
        cls._add_rule("S701", "API key pattern", Severity.MEDIUM,
                     "API key detected",
                     [r"api[_-]?key", r"apikey", r"api_secret"])
        
        cls._add_rule("S702", "Password/credential", Severity.HIGH,
                     "Password or credential detected",
                     [r"password", r"passwd", r"credential", r"secret"])
        
        cls._add_rule("S703", "Private key", Severity.HIGH,
                     "Private cryptographic key detected",
                     [r"BEGIN.*PRIVATE", r"private[_-]?key", r"ssh-rsa"])
        
        cls._add_rule("S704", "AWS credentials", Severity.HIGH,
                     "AWS access keys detected",
                     [r"AKIA[0-9A-Z]{16}", r"aws[_-]?access", r"aws[_-]?secret"])
        
        cls._add_rule("S705", "GCP/Azure credentials", Severity.HIGH,
                     "Cloud provider credentials",
                     [r"azure.*key", r"gcp.*credential", r"google.*api"])
        
        cls._add_rule("S706", "Database connection string", Severity.HIGH,
                     "Database connection URL detected",
                     [r"mongodb://", r"postgresql://", r"mysql://", r"sqlite://"])
        
        cls._add_rule("S707", "JWT token", Severity.MEDIUM,
                     "JSON Web Token detected",
                     [r"eyJ[A-Za-z0-9_-]+\.", r"jwt", r"bearer.*token"])
        
        cls._add_rule("S708", "OAuth token", Severity.MEDIUM,
                     "OAuth token detected",
                     [r"oauth", r"access[_-]?token", r"refresh[_-]?token"])
        
        cls._add_rule("S709", "Webhook URL", Severity.LOW,
                     "Webhook endpoint detected",
                     [r"webhook", r"hook.*url", r"callback.*url"])
        
        cls._add_rule("S710", "High entropy strings", Severity.LOW,
                     "Random-looking string detected",
                     [r"entropy.*high", r"random.*string", r"suspicious.*entropy"])
        
        # S800-S899: Model Architecture & Weights
        cls._add_rule("S801", "Suspicious weight distribution", Severity.LOW,
                     "Statistical anomalies in weights",
                     [r"weight.*distribution", r"suspicious.*weight", r"anomal.*weight"])
        
        cls._add_rule("S802", "Outlier neurons", Severity.LOW,
                     "Extreme weight values detected",
                     [r"outlier.*neuron", r"extreme.*weight", r"sigma.*deviation"])
        
        cls._add_rule("S803", "Dissimilar weight vectors", Severity.LOW,
                     "Inconsistent weight patterns",
                     [r"dissimilar.*weight", r"inconsistent.*pattern", r"weight.*vector"])
        
        cls._add_rule("S804", "Excessive model dimensions", Severity.LOW,
                     "Unusually large layer dimensions",
                     [r"excessive.*dimension", r"large.*layer", r"dimension.*exceed"])
        
        cls._add_rule("S805", "Unusual layer configuration", Severity.LOW,
                     "Non-standard architecture detected",
                     [r"unusual.*layer", r"non-standard.*architecture", r"strange.*config"])
        
        cls._add_rule("S806", "Hidden layers in manifest", Severity.MEDIUM,
                     "Undocumented layers found",
                     [r"hidden.*layer", r"undocumented.*layer", r"missing.*manifest"])
        
        cls._add_rule("S807", "Backdoor trigger patterns", Severity.HIGH,
                     "Potential backdoor detected",
                     [r"backdoor", r"trigger.*pattern", r"trojan"])
        
        cls._add_rule("S808", "Weight manipulation signs", Severity.MEDIUM,
                     "Signs of tampered weights",
                     [r"weight.*manipulat", r"tamper.*weight", r"modif.*weight"])
        
        cls._add_rule("S809", "Non-standard activations", Severity.LOW,
                     "Custom activation functions",
                     [r"custom.*activation", r"non-standard.*activation", r"unknown.*activation"])
        
        cls._add_rule("S810", "Custom layers with code", Severity.MEDIUM,
                     "Layers containing executable code",
                     [r"custom.*layer.*code", r"lambda.*layer", r"layer.*function"])
        
        # S900-S999: File Integrity & Format
        cls._add_rule("S901", "File type mismatch", Severity.LOW,
                     "Extension doesn't match content",
                     [r"type.*mismatch", r"extension.*mismatch", r"format.*conflict"])
        
        cls._add_rule("S902", "Corrupted file structure", Severity.LOW,
                     "Invalid file format detected",
                     [r"corrupt", r"invalid.*structure", r"malformed"])
        
        cls._add_rule("S903", "Invalid magic bytes", Severity.LOW,
                     "Wrong file signature",
                     [r"magic.*bytes", r"invalid.*signature", r"wrong.*header"])
        
        cls._add_rule("S904", "Excessive file size", Severity.LOW,
                     "File exceeds size limits",
                     [r"file.*too.*large", r"excessive.*size", r"size.*limit"])
        
        cls._add_rule("S905", "Suspicious file metadata", Severity.LOW,
                     "Unusual metadata detected",
                     [r"suspicious.*metadata", r"unusual.*metadata", r"metadata.*anomaly"])
        
        cls._add_rule("S906", "Non-standard file extension", Severity.LOW,
                     "Uncommon file extension",
                     [r"unknown.*extension", r"non-standard.*extension", r"unusual.*extension"])
        
        cls._add_rule("S907", "Multiple format markers", Severity.MEDIUM,
                     "Multiple file format indicators",
                     [r"multiple.*format", r"polyglot.*indicator", r"dual.*format"])
        
        cls._add_rule("S908", "Polyglot file detected", Severity.HIGH,
                     "File valid as multiple formats",
                     [r"polyglot", r"multiple.*valid.*format", r"dual.*purpose"])
        
        # S1000-S1099: Supply Chain & Dependencies
        cls._add_rule("S1001", "Blacklisted model name", Severity.CRITICAL,
                     "Known malicious model name",
                     [r"blacklist", r"malicious.*model", r"banned.*name"])
        
        cls._add_rule("S1002", "Known malicious hash", Severity.CRITICAL,
                     "File matches malware signature",
                     [r"malicious.*hash", r"malware.*signature", r"virus.*detect"])
        
        cls._add_rule("S1003", "Typosquatting detection", Severity.HIGH,
                     "Name similar to popular model",
                     [r"typosquat", r"similar.*name", r"confusing.*name"])
        
        cls._add_rule("S1004", "Unsigned model", Severity.LOW,
                     "Model lacks digital signature",
                     [r"unsigned", r"no.*signature", r"missing.*signature"])
        
        cls._add_rule("S1005", "Invalid signature", Severity.HIGH,
                     "Digital signature verification failed",
                     [r"invalid.*signature", r"bad.*signature", r"signature.*fail"])
        
        cls._add_rule("S1006", "Expired certificate", Severity.LOW,
                     "Signing certificate has expired",
                     [r"expired.*cert", r"outdated.*cert", r"cert.*expired"])
        
        cls._add_rule("S1007", "Untrusted repository", Severity.MEDIUM,
                     "Model from unknown source",
                     [r"untrusted.*source", r"unknown.*repository", r"unverified.*origin"])
        
        cls._add_rule("S1008", "License incompatibility", Severity.LOW,
                     "License conflicts detected",
                     [r"license.*incompatib", r"license.*conflict", r"license.*violation"])
        
        cls._add_rule("S1009", "GPL in proprietary use", Severity.LOW,
                     "GPL license in commercial context",
                     [r"GPL.*proprietary", r"GPL.*commercial", r"copyleft.*violation"])
        
        cls._add_rule("S1010", "Missing provenance", Severity.LOW,
                     "No source tracking information",
                     [r"missing.*provenance", r"no.*source.*track", r"unknown.*origin"])
        
        # S1100-S1199: Framework-Specific
        cls._add_rule("S1101", "PyTorch unsafe load", Severity.HIGH,
                     "torch.load without weights_only=True",
                     [r"torch\.load", r"unsafe.*pytorch", r"pickle.*pytorch"])
        
        cls._add_rule("S1102", "TensorFlow SavedModel risks", Severity.MEDIUM,
                     "TensorFlow SavedModel security issues",
                     [r"savedmodel", r"tensorflow.*risk", r"tf\.saved_model"])
        
        cls._add_rule("S1103", "Keras Lambda layers", Severity.MEDIUM,
                     "Keras Lambda layers with code",
                     [r"Lambda.*layer", r"keras.*lambda", r"custom.*keras.*function"])
        
        cls._add_rule("S1104", "ONNX opset version", Severity.LOW,
                     "ONNX version compatibility issue",
                     [r"onnx.*version", r"opset.*version", r"onnx.*compatibility"])
        
        cls._add_rule("S1105", "JAX compilation risks", Severity.MEDIUM,
                     "JAX JIT compilation security",
                     [r"jax.*compilation", r"jax\.jit", r"jax.*security"])
        
        cls._add_rule("S1106", "MXNet custom operators", Severity.MEDIUM,
                     "MXNet custom operator risks",
                     [r"mxnet.*custom", r"mxnet.*operator", r"mxnet.*op"])
        
        cls._add_rule("S1107", "PaddlePaddle dynamic graph", Severity.MEDIUM,
                     "PaddlePaddle dynamic mode risks",
                     [r"paddle.*dynamic", r"paddlepaddle", r"paddle.*graph"])
        
        cls._add_rule("S1108", "CoreML custom layers", Severity.MEDIUM,
                     "CoreML custom layer risks",
                     [r"coreml.*custom", r"coreml.*layer", r"mlmodel.*custom"])
        
        cls._add_rule("S1109", "TensorRT plugins", Severity.MEDIUM,
                     "TensorRT plugin security",
                     [r"tensorrt.*plugin", r"trt.*plugin", r"tensorrt.*custom"])
        
        cls._add_rule("S1110", "GGUF/GGML format risks", Severity.LOW,
                     "GGUF/GGML format security issues",
                     [r"gguf", r"ggml", r"llama.*format"])
        
        cls._initialized = True
    
    @classmethod
    def _add_rule(cls, code: str, name: str, severity: Severity, 
                  description: str, patterns: List[str]):
        """Add a rule to the registry."""
        compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        cls._rules[code] = Rule(code, name, severity, description, compiled_patterns)
    
    @classmethod
    def get_rule(cls, code: str) -> Optional[Rule]:
        """Get a rule by its code."""
        cls.initialize()
        return cls._rules.get(code)
    
    @classmethod
    def find_matching_rule(cls, message: str) -> Optional[Tuple[str, Rule]]:
        """Find the first rule that matches a message."""
        cls.initialize()
        for code, rule in cls._rules.items():
            if rule.matches_message(message):
                return code, rule
        return None
    
    @classmethod
    def get_all_rules(cls) -> Dict[str, Rule]:
        """Get all registered rules."""
        cls.initialize()
        return cls._rules.copy()
    
    @classmethod
    def get_rules_by_range(cls, start: int, end: int) -> Dict[str, Rule]:
        """Get rules in a numeric range (e.g., S100-S199)."""
        cls.initialize()
        result = {}
        for code, rule in cls._rules.items():
            if code.startswith('S'):
                try:
                    num = int(code[1:])
                    if start <= num <= end:
                        result[code] = rule
                except ValueError:
                    continue
        return result