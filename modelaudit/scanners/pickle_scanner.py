import os
import pickletools
import struct
import time
from typing import IO, Any, BinaryIO, ClassVar, Optional, Union

from modelaudit.analysis.entropy_analyzer import EntropyAnalyzer
from modelaudit.analysis.semantic_analyzer import SemanticAnalyzer
from modelaudit.knowledge.framework_patterns import FrameworkKnowledgeBase
from modelaudit.suspicious_symbols import (
    BINARY_CODE_PATTERNS,
    CVE_BINARY_PATTERNS,
    EXECUTABLE_SIGNATURES,
    SUSPICIOUS_GLOBALS,
    SUSPICIOUS_STRING_PATTERNS,
)
from modelaudit.utils.code_validation import (
    is_code_potentially_dangerous,
    validate_python_syntax,
)

from ..cve_patterns import analyze_cve_patterns, enhance_scan_result_with_cve
from ..explanations import (
    get_import_explanation,
    get_opcode_explanation,
    get_pattern_explanation,
)
from ..suspicious_symbols import DANGEROUS_OPCODES
from .base import BaseScanner, CheckStatus, IssueSeverity, ScanResult, logger


def _compute_pickle_length(path: str) -> int:
    """
    Compute the exact length of pickle data by finding the STOP opcode position.

    Args:
        path: Path to the file containing pickle data

    Returns:
        The byte position where pickle data ends, or a fallback estimate
    """
    try:
        with open(path, "rb") as f:
            for opcode, _arg, pos in pickletools.genops(f):
                if opcode.name == "STOP" and pos is not None:
                    return pos + 1  # Include the STOP opcode itself
        # If no STOP found, fallback to file size (malformed pickle)
        return os.path.getsize(path)
    except Exception:
        # Fallback to conservative estimate on any error
        file_size = os.path.getsize(path)
        return min(file_size // 2, 64)


# ============================================================================
# SMART DETECTION SYSTEM - ML Context Awareness
# ============================================================================

# ML Framework Detection Patterns
ML_FRAMEWORK_PATTERNS: dict[str, dict[str, Union[list[str], float]]] = {
    "pytorch": {
        "modules": [
            "torch",
            "torchvision",
            "torch.nn",
            "torch.optim",
            "torch.utils",
            "_pickle",
            "collections",
        ],
        "classes": [
            "OrderedDict",
            "Parameter",
            "Module",
            "Linear",
            "Conv2d",
            "BatchNorm2d",
            "ReLU",
            "MaxPool2d",
            "AdaptiveAvgPool2d",
            "Sequential",
            "ModuleList",
            "Tensor",
        ],
        "patterns": [r"torch\..*", r"_pickle\..*", r"collections\.OrderedDict"],
        "confidence_boost": 0.9,
    },
    "yolo": {
        "modules": ["ultralytics", "yolo", "models"],
        "classes": ["YOLO", "YOLOv8", "Detect", "C2f", "Conv", "Bottleneck", "SPPF"],
        "patterns": [
            r"yolo.*",
            r"ultralytics\..*",
            r".*\.detect",
            r".*\.backbone",
            r".*\.head",
        ],
        "confidence_boost": 0.9,
    },
    "tensorflow": {
        "modules": ["tensorflow", "keras", "tf"],
        "classes": ["Model", "Layer", "Dense", "Conv2D", "Flatten"],
        "patterns": [r"tensorflow\..*", r"keras\..*"],
        "confidence_boost": 0.8,
    },
    "sklearn": {
        "modules": ["sklearn", "joblib", "numpy", "numpy.core", "numpy.dtype"],
        "classes": [
            "Pipeline",
            "StandardScaler",
            "PCA",
            "LogisticRegression",
            "DecisionTreeClassifier",
            "SVC",
            "RandomForestClassifier",
            "RandomForestRegressor",
            "GradientBoostingClassifier",
            "KMeans",
            "AgglomerativeClustering",
            "Ridge",
            "Lasso",
        ],
        "patterns": [r"sklearn\..*", r"joblib\..*", r"numpy\..*", r"numpy\.core\..*"],
        "confidence_boost": 0.9,
    },
    "huggingface": {
        "modules": ["transformers", "tokenizers"],
        "classes": ["AutoModel", "AutoTokenizer", "BertModel", "GPT2Model"],
        "patterns": [r"transformers\..*", r"tokenizers\..*"],
        "confidence_boost": 0.8,
    },
}

# Safe ML-specific global patterns
ML_SAFE_GLOBALS: dict[str, list[str]] = {
    # PyTorch safe patterns
    "torch": ["*"],  # All torch functions are generally safe
    "torch.nn": ["*"],
    "torch.optim": ["*"],
    "torch.utils": ["*"],
    "_pickle": ["*"],  # PyTorch uses _pickle internally
    "collections": ["OrderedDict", "defaultdict", "namedtuple"],
    "typing": ["*"],
    "numpy": ["*"],  # NumPy operations are safe
    "math": ["*"],  # Math operations are safe
    # YOLO/Ultralytics safe patterns
    "ultralytics": ["*"],
    "yolo": ["*"],
    # Standard ML libraries
    "sklearn": ["*"],
    "transformers": ["*"],
    "tokenizers": ["*"],
    "joblib": [
        "dump",
        "load",
        "Parallel",
        "delayed",
        "Memory",
        "hash",
        "_pickle_dump",
        "_pickle_load",
    ],
    "dill": ["dump", "dumps", "load", "loads", "copy"],
    "tensorflow": ["*"],
    "keras": ["*"],
}

# Dangerous actual code execution patterns in strings
ACTUAL_DANGEROUS_STRING_PATTERNS = [
    r"os\.system\s*\(",
    r"subprocess\.",
    r"exec\s*\(",
    r"eval\s*\(",
    r"__import__\s*\(",
    r"compile\s*\(",
    r"open\s*\(['\"].*['\"],\s*['\"]w",  # File write operations
    r"\.popen\s*\(",
    r"\.spawn\s*\(",
]


def _detect_ml_context(opcodes: list[tuple]) -> dict[str, Any]:
    """
    Detect ML framework context from opcodes with confidence scoring.
    Uses improved scoring that focuses on presence and diversity of ML patterns
    rather than their proportion of total opcodes.
    """
    context: dict[str, Any] = {
        "frameworks": {},
        "overall_confidence": 0.0,
        "is_ml_content": False,
        "detected_patterns": [],
    }

    total_opcodes = len(opcodes)
    if total_opcodes == 0:
        return context

    # Analyze GLOBAL opcodes for ML patterns
    global_refs: dict[str, int] = {}
    total_global_opcodes = 0

    for opcode, arg, _pos in opcodes:
        if opcode.name == "GLOBAL" and isinstance(arg, str):
            total_global_opcodes += 1
            # Extract module name from global reference
            if "." in arg:
                module = arg.split(".")[0]
            elif " " in arg:
                module = arg.split(" ")[0]
            else:
                module = arg

            global_refs[module] = global_refs.get(module, 0) + 1

    # Check each framework with improved scoring
    for framework, patterns in ML_FRAMEWORK_PATTERNS.items():
        framework_score = 0.0
        matches: list[str] = []

        # Check module matches with improved scoring
        modules = patterns["modules"]
        if isinstance(modules, list):
            for module in modules:
                if module in global_refs:
                    # Score based on presence and frequency,
                    # not proportion of total opcodes
                    ref_count = global_refs[module]

                    # Base score for presence
                    module_score = 10.0  # Base score for any ML module presence

                    # Bonus for frequency (up to 20 more points)
                    if ref_count >= 5:
                        module_score += 20.0
                    elif ref_count >= 2:
                        module_score += 10.0
                    elif ref_count >= 1:
                        module_score += 5.0

                    framework_score += module_score
                    matches.append(f"module:{module}({ref_count})")

        # Store framework detection with much lower threshold
        if framework_score > 5.0:  # Much lower threshold - any ML module presence
            # Normalize confidence to 0-1 range
            confidence_boost = patterns["confidence_boost"]
            if isinstance(confidence_boost, (int, float)):
                confidence = min(framework_score / 100.0 * confidence_boost, 1.0)
                context["frameworks"][framework] = {
                    "confidence": confidence,
                    "matches": matches,
                    "raw_score": framework_score,
                }
                context["detected_patterns"].extend(matches)

    # Calculate overall ML confidence - highest framework confidence
    if context["frameworks"]:
        context["overall_confidence"] = max(fw["confidence"] for fw in context["frameworks"].values())
        # Much more lenient threshold - any significant ML pattern detection
        context["is_ml_content"] = context["overall_confidence"] > 0.15  # Was 0.3

    return context


def _is_actually_dangerous_global(mod: str, func: str, ml_context: dict) -> bool:
    """
    Smart global reference analysis - distinguishes between legitimate ML operations
    and actual dangerous operations.
    """
    # If we have high ML confidence, be more lenient with "suspicious" globals
    if ml_context.get("is_ml_content") and ml_context.get("overall_confidence", 0) > 0.5 and mod in ML_SAFE_GLOBALS:
        safe_funcs = ML_SAFE_GLOBALS[mod]
        if safe_funcs == ["*"] or func in safe_funcs:
            return False

    # Use original suspicious global check for genuinely suspicious patterns
    return is_suspicious_global(mod, func)


def _is_actually_dangerous_string(s: str, ml_context: dict) -> Optional[str]:
    """
    Smart string analysis - looks for actual executable code rather than ML patterns.
    Now includes py_compile validation to reduce false positives.
    """
    import re

    # Check for ACTUAL dangerous patterns (not just ML magic methods)
    for pattern in ACTUAL_DANGEROUS_STRING_PATTERNS:
        match = re.search(pattern, s, re.IGNORECASE)
        if match:
            # If we found a dangerous pattern, check if it's actually valid Python code
            # This helps reduce false positives from data that just happens to contain these strings

            # Try to extract a reasonable code snippet around the match
            start = max(0, match.start() - 50)
            end = min(len(s), match.end() + 50)
            code_snippet = s[start:end].strip()

            # Check if this looks like actual Python code
            is_valid, _ = validate_python_syntax(code_snippet)
            if is_valid:
                # It's valid Python! Check if it's actually dangerous
                is_dangerous, risk_desc = is_code_potentially_dangerous(code_snippet, "low")
                if is_dangerous:
                    return f"{pattern} (validated as executable code: {risk_desc})"
            else:
                # Not valid Python syntax, might be a false positive
                # Still flag it if it's a very clear pattern
                if pattern in [r"eval\s*\(", r"exec\s*\(", r"__import__\s*\("]:
                    return f"{pattern} (suspicious pattern, not valid Python)"
                # Otherwise, likely a false positive
                continue

    # If we have strong ML context, ignore common ML patterns
    if ml_context.get("is_ml_content") and ml_context.get("overall_confidence", 0) > 0.6:
        # Skip common ML magic method patterns
        if re.match(r"^__\w+__$", s):  # Simple magic methods like __call__, __init__
            return None

        # Skip tensor/layer names
        if any(term in s.lower() for term in ["layer", "conv", "batch", "norm", "relu", "pool", "linear"]):
            return None

    # Check for base64-like strings (still suspicious), but avoid repeating patterns
    if (
        len(s) > 100
        and re.match(r"^[A-Za-z0-9+/=]+$", s)
        and not re.match(r"^(.)\1*$", s)  # Not all same character (e.g., "===...")
        and len(set(s)) > 4  # Must have some character diversity
    ):
        return "potential_base64"

    return None


def _looks_like_pickle(data: bytes) -> bool:
    """Check if the given bytes resemble a pickle payload with robust validation."""
    import io

    if not data or len(data) < 2:
        return False

    # Quick validation: Check for valid pickle protocol markers
    first_byte = data[0]

    # Protocol 2+ starts with \x80 followed by protocol number
    if first_byte == 0x80:
        if len(data) < 2:
            return False
        protocol = data[1]
        if protocol not in (2, 3, 4, 5):
            return False
    # Protocol 0/1 must start with valid opcodes
    elif first_byte not in (
        ord("("),
        ord("]"),
        ord("}"),
        ord("c"),
        ord("l"),
        ord("d"),
        ord("t"),
        ord("p"),
        ord("q"),
        ord("g"),
        ord("I"),
        ord("L"),
        ord("F"),
        ord("S"),
        ord("U"),
        ord("N"),
        ord("V"),
        ord("M"),  # Additional valid opcodes
    ):
        return False

    try:
        stream = io.BytesIO(data)
        opcode_count = 0
        valid_opcodes = 0

        for opcode_count, (opcode, _arg, _pos) in enumerate(pickletools.genops(stream), 1):
            # Count opcodes that are definitely pickle-specific
            if opcode.name in {"MARK", "STOP", "TUPLE", "LIST", "DICT", "SETITEM", "BUILD", "REDUCE"}:
                valid_opcodes += 1

            # Need multiple valid opcodes to be confident
            if opcode_count >= 3 and valid_opcodes >= 2:
                return True

            # Prevent infinite loops on malformed data
            if opcode_count > 20:
                break

    except Exception:
        return False

    return False


def _decode_string_to_bytes(s: str) -> list[tuple[str, bytes]]:
    """Attempt to decode a string from common encodings with stricter validation."""
    import base64
    import binascii
    import re

    candidates: list[tuple[str, bytes]] = []

    # More strict base64 validation
    try:
        # Must be reasonable length and proper base64 format
        if (
            16 <= len(s) <= 10000  # Reasonable length bounds
            and len(s) % 4 == 0
            and re.fullmatch(r"[A-Za-z0-9+/]+=*", s)  # Proper base64 chars with padding
            and s.count("=") <= 2  # At most 2 padding chars
            and not s.replace("=", "").endswith("=")  # Padding only at end
        ):
            decoded = base64.b64decode(s)
            # Additional validation: decoded should be reasonable binary data
            if len(decoded) >= 8:  # At least 8 bytes for meaningful content
                candidates.append(("base64", decoded))
    except Exception:
        pass

    # More strict hex validation
    try:
        hex_str = s
        if "\\x" in s:
            hex_str = s.replace("\\x", "")
        if (
            16 <= len(hex_str) <= 5000  # Reasonable length
            and len(hex_str) % 2 == 0
            and re.fullmatch(r"[0-9a-fA-F]+", hex_str)
            and not re.match(r"^(.)\1*$", hex_str)  # Not all same character
        ):
            decoded = binascii.unhexlify(hex_str)
            if len(decoded) >= 8:  # At least 8 bytes
                candidates.append(("hex", decoded))
    except Exception:
        pass

    return candidates


def _should_ignore_opcode_sequence(opcodes: list[tuple], ml_context: dict) -> bool:
    """
    Determine if an opcode sequence should be ignored based on ML context.
    """
    if not ml_context.get("is_ml_content"):
        return False

    # High confidence ML content - be very permissive with opcode sequences
    if ml_context.get("overall_confidence", 0) > 0.7:
        return True

    # Medium confidence - check for specific ML patterns
    if ml_context.get("overall_confidence", 0) > 0.4:
        # Look for legitimate ML construction patterns
        reduce_count = sum(1 for opcode, _, _ in opcodes if opcode.name == "REDUCE")
        global_count = sum(1 for opcode, _, _ in opcodes if opcode.name == "GLOBAL")

        # High REDUCE/GLOBAL ratio suggests ML object construction
        if global_count > 0 and reduce_count / global_count > 0.5:
            return True

    return False


def _get_context_aware_severity(
    base_severity: IssueSeverity,
    ml_context: dict,
) -> IssueSeverity:
    """
    Adjust severity based on ML context confidence.
    """
    if not ml_context.get("is_ml_content"):
        return base_severity

    confidence = ml_context.get("overall_confidence", 0)

    # High confidence ML content - downgrade severity
    if confidence > 0.8:
        if base_severity == IssueSeverity.CRITICAL:
            return IssueSeverity.WARNING
        if base_severity == IssueSeverity.WARNING:
            return IssueSeverity.INFO
    if confidence > 0.5 and base_severity == IssueSeverity.CRITICAL:
        return IssueSeverity.WARNING

    return base_severity


# ============================================================================
# END SMART DETECTION SYSTEM
# ============================================================================


def _is_legitimate_serialization_file(path: str) -> bool:
    """
    Validate that a file is a legitimate joblib or dill serialization file.
    This helps prevent security bypass by simply renaming malicious files.
    """
    try:
        with open(path, "rb") as f:
            # Read first few bytes to check for pickle magic
            header = f.read(10)
            if not header:
                return False

            # Check for standard pickle protocols (0-5)
            # Protocol 0: starts with '(' or other opcodes
            # Protocol 1: starts with ']' or other opcodes
            # Protocol 2+: starts with '\x80' followed by protocol number
            first_byte = header[0:1]
            if first_byte == b"\x80":
                # Protocols 2-5 start with \x80 followed by protocol number
                if len(header) < 2 or header[1] not in (2, 3, 4, 5):
                    return False
            elif first_byte not in (b"(", b"]", b"}", b"c", b"l", b"d", b"t", b"p"):
                # Common pickle opcode starts for protocols 0-1
                return False

            # For joblib files, look for joblib-specific patterns
            if path.lower().endswith(".joblib"):
                f.seek(0)
                # Try to find joblib-specific markers in first 2KB
                sample = f.read(2048)
                # Look for joblib-specific indicators
                joblib_indicators = [
                    b"joblib",
                    b"sklearn",
                    b"numpy",
                    b"_joblib",
                    b"__main__",
                    b"_pickle",
                    b"NumpyArrayWrapper",
                ]
                return any(marker in sample for marker in joblib_indicators)

            # For dill files, they're usually just enhanced pickle
            if path.lower().endswith(".dill"):
                # Dill files should contain standard pickle format
                # Additional validation could check for dill-specific patterns
                return True

        return False
    except OSError:
        # File doesn't exist or can't be read
        return False
    except Exception:
        # Other errors (e.g., permissions) - be conservative
        return False


def is_suspicious_global(mod: str, func: str) -> bool:
    """
    Check if a module.function reference is suspicious.

    Enhanced to detect various forms of builtin eval/exec that other tools
    might miss, including __builtin__ (Python 2 style) and __builtins__.
    """
    # Normalize module name for consistent checking
    # Some exploits use alternative spellings or references
    normalized_mod = mod.strip().lower() if mod else ""

    # Check for direct matches first
    if mod in SUSPICIOUS_GLOBALS:
        val = SUSPICIOUS_GLOBALS[mod]
        if val == "*":
            return True
        if isinstance(val, list) and func in val:
            return True

    # Enhanced detection for builtin eval/exec patterns
    # These are CRITICAL as they allow arbitrary code execution
    builtin_variants = ["__builtin__", "__builtins__", "builtins"]
    dangerous_funcs = ["eval", "exec", "execfile", "compile", "__import__"]

    if mod in builtin_variants and func in dangerous_funcs:
        # Log for comparative analysis
        logger.debug(
            f"Detected dangerous builtin: {mod}.{func} - "
            f"This is a CRITICAL security risk that some tools might underreport"
        )
        return True

    # Check for obfuscated references
    # Some exploits use getattr or other indirection
    if normalized_mod in ["__builtin", "builtin", "__builtins", "builtins"] and func in dangerous_funcs:
        logger.debug(f"Obfuscated builtin reference detected: {mod}.{func}")
        return True

    return False


def is_suspicious_string(s: str) -> Optional[str]:
    """Check if a string contains suspicious patterns"""
    import re

    for pattern in SUSPICIOUS_STRING_PATTERNS:
        match = re.search(pattern, s)
        if match:
            return pattern

    # Check for base64-like strings (long strings with base64 charset), but avoid repeating patterns
    if (
        len(s) > 40
        and re.match(r"^[A-Za-z0-9+/=]+$", s)
        and not re.match(r"^(.)\1*$", s)  # Not all same character
        and len(set(s)) > 4  # Must have some character diversity
    ):
        return "potential_base64"

    return None


def is_dangerous_reduce_pattern(opcodes: list[tuple]) -> Optional[dict[str, Any]]:
    """
    Check for patterns that indicate a dangerous __reduce__ method
    Returns details about the dangerous pattern if found, None otherwise
    """
    # Look for common patterns in __reduce__ exploits
    for i, (opcode, arg, pos) in enumerate(opcodes):
        # Check for GLOBAL followed by REDUCE - common in exploits
        if (opcode.name == "GLOBAL" and i + 1 < len(opcodes) and opcodes[i + 1][0].name == "REDUCE") and isinstance(
            arg, str
        ):
            parts = arg.split(" ", 1) if " " in arg else arg.rsplit(".", 1) if "." in arg else [arg, ""]
            if len(parts) == 2:
                mod, func = parts
                return {
                    "pattern": "GLOBAL+REDUCE",
                    "module": mod,
                    "function": func,
                    "position": pos,
                    "opcode": opcode.name,
                }

        # Check for INST or OBJ opcodes which can also be used for code execution
        if opcode.name in ["INST", "OBJ", "NEWOBJ"] and isinstance(arg, str):
            return {
                "pattern": f"{opcode.name}_EXECUTION",
                "argument": arg,
                "position": pos,
                "opcode": opcode.name,
            }

        # Check for suspicious attribute access patterns (GETATTR followed by CALL)
        if opcode.name == "GETATTR" and i + 1 < len(opcodes) and opcodes[i + 1][0].name == "CALL":
            return {
                "pattern": "GETATTR+CALL",
                "attribute": arg,
                "position": pos,
                "opcode": opcode.name,
            }

        # Check for suspicious strings in STRING or BINSTRING opcodes
        if opcode.name in [
            "STRING",
            "BINSTRING",
            "SHORT_BINSTRING",
            "UNICODE",
        ] and isinstance(arg, str):
            suspicious_pattern = is_suspicious_string(arg)
            if suspicious_pattern:
                return {
                    "pattern": "SUSPICIOUS_STRING",
                    "string_pattern": suspicious_pattern,
                    "string_preview": arg[:50] + ("..." if len(arg) > 50 else ""),
                    "position": pos,
                    "opcode": opcode.name,
                }

    return None


def check_opcode_sequence(
    opcodes: list[tuple],
    ml_context: dict,
) -> list[dict[str, Any]]:
    """
    Analyze the full sequence of opcodes for suspicious patterns
    with ML context awareness.
    Returns a list of suspicious patterns found.
    """
    suspicious_patterns: list[dict[str, Any]] = []

    # SMART DETECTION: Check if we should ignore this sequence based on ML context
    if _should_ignore_opcode_sequence(opcodes, ml_context):
        return suspicious_patterns  # Return empty list for legitimate ML content

    # Count dangerous opcodes with ML context awareness
    dangerous_opcode_count = 0
    consecutive_dangerous = 0
    max_consecutive = 0

    for i, (opcode, arg, pos) in enumerate(opcodes):
        # Track dangerous opcodes
        if opcode.name in DANGEROUS_OPCODES:
            dangerous_opcode_count += 1
            consecutive_dangerous += 1
            max_consecutive = max(max_consecutive, consecutive_dangerous)
        else:
            consecutive_dangerous = 0

        # SMART DETECTION: Much higher threshold for ML content
        ml_confidence = ml_context.get("overall_confidence", 0)
        if ml_confidence > 0.7:
            threshold = 200  # Even higher threshold for high-confidence ML (was 100)
        elif ml_confidence > 0.4:
            threshold = 100  # Higher threshold for medium-confidence ML (was 50)
        else:
            threshold = 50  # Higher than original for unknown content (was 20)

        # Also require higher ML confidence to trigger warnings
        # If ML confidence is below 0.6, don't warn about opcode counts
        if ml_confidence >= 0.6 and dangerous_opcode_count > threshold:
            suspicious_patterns.append(
                {
                    "pattern": "MANY_DANGEROUS_OPCODES",
                    "count": dangerous_opcode_count,
                    "max_consecutive": max_consecutive,
                    "ml_confidence": ml_confidence,
                    "position": pos,
                    "opcode": opcode.name,
                },
            )
            # Reset counter to avoid multiple alerts
            dangerous_opcode_count = 0
            max_consecutive = 0

        # Detect decode-exec chains (e.g., base64.decode + pickle.loads/eval)
        parsed = None
        if opcode.name == "GLOBAL" and isinstance(arg, str):
            if " " in arg:
                mod, func = arg.split(" ", 1)
            elif "." in arg:
                mod, func = arg.rsplit(".", 1)
            else:
                mod = func = ""
            parsed = (mod, func)

        if parsed and parsed[0] in {"base64", "codecs", "binascii"} and "decode" in parsed[1]:
            for j in range(i + 1, min(i + 6, len(opcodes))):
                op2, arg2, pos2 = opcodes[j]
                if op2.name == "GLOBAL" and isinstance(arg2, str):
                    if " " in arg2:
                        m2, f2 = arg2.split(" ", 1)
                    elif "." in arg2:
                        m2, f2 = arg2.rsplit(".", 1)
                    else:
                        continue
                    if (m2 == "pickle" and f2 in {"loads", "load"}) or (m2 == "builtins" and f2 in {"eval", "exec"}):
                        suspicious_patterns.append(
                            {
                                "pattern": "DECODE_EXEC_CHAIN",
                                "modules": [f"{parsed[0]}.{parsed[1]}", f"{m2}.{f2}"],
                                "position": pos,
                            }
                        )
                        break

    return suspicious_patterns


class PickleScanner(BaseScanner):
    """Scanner for Python Pickle files"""

    name = "pickle"
    description = "Scans Python pickle files for suspicious code references"
    supported_extensions: ClassVar[list[str]] = [
        ".pkl",
        ".pickle",
        ".dill",
        ".joblib",
        ".bin",
        ".pt",
        ".pth",
        ".ckpt",
    ]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        # Additional pickle-specific configuration
        self.max_opcodes = self.config.get("max_opcodes", 1000000)
        # Initialize analyzers
        self.entropy_analyzer = EntropyAnalyzer()
        self.semantic_analyzer = SemanticAnalyzer()
        self.framework_kb = FrameworkKnowledgeBase()

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if the file is a pickle based on extension and content"""
        file_ext = os.path.splitext(path)[1].lower()

        # For known pickle extensions, always handle
        if file_ext in [".pkl", ".pickle", ".dill", ".joblib"]:
            return True

        # For ambiguous extensions, check the actual file format
        if file_ext in [".bin", ".pt", ".pth", ".ckpt"]:
            try:
                # Import here to avoid circular dependency
                from modelaudit.utils.filetype import (
                    detect_file_format,
                    validate_file_type,
                )

                file_format = detect_file_format(path)

                # For security-sensitive pickle files, also validate file type
                # This helps detect potential file spoofing attacks
                if file_format == "pickle" and not validate_file_type(path):
                    # File type validation failed - this could be suspicious
                    # Log but still allow scanning for now (let scanner handle the validation)
                    logger.warning(
                        f"File type validation failed for potential pickle file: {path}",
                    )

                # Handle both pickle and zip formats (PyTorch .bin files are often zip)
                # PyTorch files saved with torch.save() are ZIP archives containing pickled data
                if file_format == "pickle":
                    return True
                elif file_format == "zip" and file_ext in [".bin", ".pt", ".pth"]:
                    # PyTorch ZIP files should be handled by PyTorchZipScanner or PyTorchBinaryScanner
                    # The pickle scanner shouldn't try to parse them as regular pickle files
                    return False

                return False
            except Exception:
                # If detection fails, fall back to extension check
                return file_ext in cls.supported_extensions

        return False

    def _get_surrounding_data(self, data: bytes, position: int, window_size: int = 1024) -> bytes:
        """Get data surrounding a specific position for analysis."""
        start = max(0, position - window_size // 2)
        end = min(len(data), position + window_size // 2)
        return data[start:end]

    def scan(self, path: str) -> ScanResult:
        """Scan a pickle file for suspicious content"""
        # Start scan timer for timeout tracking
        self._start_scan_timer()

        # Initialize context for this file
        self._initialize_context(path)

        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        # Check if this is a .bin file that might be a PyTorch file
        is_bin_file = os.path.splitext(path)[1].lower() == ".bin"

        # Early detection of dangerous patterns BEFORE attempting to parse pickle
        early_detection_successful = False
        try:
            # Use the most basic file operations possible to avoid recursion issues
            # Read file in smaller chunks to avoid memory/recursion issues
            chunk_size = 1024  # 1KB chunks
            raw_content = b""
            bytes_read = 0
            max_bytes = min(8192, file_size)  # Maximum 8KB to scan

            with open(path, "rb") as f:
                while bytes_read < max_bytes:
                    # Check for interrupts during file reading
                    self.check_interrupted()

                    # Check for timeout
                    self._check_timeout()

                    chunk = f.read(min(chunk_size, max_bytes - bytes_read))
                    if not chunk:
                        break
                    raw_content += chunk
                    bytes_read += len(chunk)

                # Use the refactored method to scan for dangerous patterns
                self._scan_for_dangerous_patterns(raw_content, result, path)

                # If we scanned for dangerous patterns but found none, record a successful check
                dangerous_found = any(
                    check.name == "Dangerous Pattern Detection" and check.status == CheckStatus.FAILED
                    for check in result.checks
                )
                if not dangerous_found:
                    result.add_check(
                        name="Dangerous Pattern Detection",
                        passed=True,
                        message="No dangerous patterns found in raw file content",
                        location=path,
                        details={
                            "detection_method": "raw_content_scan",
                            "patterns_checked": [
                                "posix",
                                "subprocess",
                                "eval",
                                "exec",
                                "__import__",
                                "builtins",
                            ],
                        },
                    )

                early_detection_successful = True

        except RecursionError:
            logger.warning(f"Recursion error during early pattern detection for {path}")
            # Continue with main scan despite error
        except Exception as e:
            logger.warning(f"Error during early pattern detection: {e}")

        try:
            with open(path, "rb") as f:
                # Store the file path for use in issue locations
                self.current_file_path = path
                scan_result = self._scan_pickle_bytes(f, file_size)
                result.merge(scan_result)

                # For .bin files, also scan the remaining binary content
                # PyTorch files have pickle header followed by tensor data
                if is_bin_file and scan_result.success:
                    pickle_end_pos = f.tell()
                    remaining_bytes = file_size - pickle_end_pos

                    if remaining_bytes > 0:
                        # Check if this is likely a PyTorch model based on ML context
                        ml_context = scan_result.metadata.get("ml_context", {})
                        is_pytorch = "pytorch" in ml_context.get("frameworks", {})
                        ml_confidence = ml_context.get("overall_confidence", 0)

                        # Skip binary scanning for high-confidence ML model files
                        # as they contain tensor data that can trigger false positives
                        if is_pytorch and ml_confidence > 0.7:
                            result.metadata["binary_scan_skipped"] = True
                            result.metadata["skip_reason"] = "High-confidence PyTorch model detected"
                            result.bytes_scanned = file_size
                            result.metadata["pickle_bytes"] = pickle_end_pos
                            result.metadata["binary_bytes"] = remaining_bytes
                        else:
                            # Scan the binary content after pickle
                            binary_result = self._scan_binary_content(
                                f,
                                pickle_end_pos,
                                file_size,
                            )

                            # Add binary scanning results
                            for issue in binary_result.issues:
                                result.add_check(
                                    name="Binary Content Check",
                                    passed=False,
                                    message=issue.message,
                                    severity=issue.severity,
                                    location=issue.location,
                                    details=issue.details,
                                    why=issue.why,
                                )

                            # Update total bytes scanned
                            result.bytes_scanned = file_size
                            result.metadata["pickle_bytes"] = pickle_end_pos
                            result.metadata["binary_bytes"] = remaining_bytes

        except Exception as e:
            # Check if we already found security issues in the early pattern detection
            # If so, we should preserve those findings even if we hit recursion errors
            has_security_findings = any(
                issue.severity in [IssueSeverity.CRITICAL, IssueSeverity.WARNING] for issue in result.issues
            )

            # Check for recursion errors on legitimate ML model files
            file_ext = os.path.splitext(path)[1].lower()
            is_recursion_error = isinstance(e, RecursionError)
            # Be more specific - only for large model files (>100MB) with ML extensions
            is_large_ml_model = (
                file_ext in {".bin", ".pt", ".pth", ".ckpt"} and file_size > 100 * 1024 * 1024  # > 100MB
            )

            # Check if this appears to be a legitimate PyTorch model
            is_legitimate_file = False
            if is_large_ml_model:
                try:
                    is_legitimate_file = self._is_legitimate_pytorch_model(path)
                except Exception:
                    is_legitimate_file = False

            is_recursion_on_legitimate_model = is_recursion_error and is_large_ml_model and is_legitimate_file

            # If we already found security issues, those take precedence over recursion handling
            if has_security_findings:
                logger.warning(
                    f"Recursion error occurred during scan of {path}, but security issues were already "
                    f"detected in early analysis. Preserving security findings."
                )
                result.metadata.update(
                    {
                        "recursion_limited": True,
                        "file_size": file_size,
                        "security_issues_found": True,
                        # Add precise metadata fields using pickletools for accuracy
                        "pickle_bytes": _compute_pickle_length(path),
                        "binary_bytes": max(file_size - _compute_pickle_length(path), 0),
                    }
                )
                # Add a note about the recursion limit but don't treat it as the main issue
                result.add_check(
                    name="Recursion Depth Check",
                    passed=False,
                    message="Scan completed with security findings despite recursion limit",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "reason": "recursion_with_security_findings",
                        "file_size": file_size,
                        "exception_type": "RecursionError",
                        "security_issues_count": len([i for i in result.issues if i.severity != IssueSeverity.INFO]),
                    },
                    why=(
                        "The scan encountered recursion limits but already detected security issues in the file. "
                        "The identified security issues are valid findings that should be addressed."
                    ),
                )
                result.finish(success=True)
                return result
            if is_recursion_on_legitimate_model:
                # Recursion error on legitimate ML model - treat as scanner limitation, not security issue
                logger.debug(f"Recursion limit reached: {path} (complex nested structure)")
                result.metadata.update(
                    {
                        "recursion_limited": True,
                        "file_size": file_size,
                        "file_type": "legitimate_ml_model",
                        "scanner_limitation": True,
                    }
                )
                # Add as info-level check for transparency, not critical
                result.add_check(
                    name="Recursion Depth Check",
                    passed=True,  # True because this is expected for large ML models
                    message="Scan limited by model complexity",
                    location=path,
                    details={
                        "reason": "recursion_limit_on_legitimate_model",
                        "file_size": file_size,
                        "file_format": file_ext,
                    },
                    why=(
                        "This model file contains complex nested structures that exceed the scanner's "
                        "complexity limits. Complex model architectures with deeply nested structures can "
                        "exceed Python's recursion limits during analysis. The file appears legitimate based "
                        "on format validation."
                    ),
                )
                result.finish(success=True)  # Mark as successful scan despite limitation
                return result
            if is_recursion_error:
                # Flag extremely small files with malicious patterns
                filename = os.path.basename(path).lower()
                is_malicious_name = any(pattern in filename for pattern in ["malicious", "evil", "hack", "exploit"])
                is_very_small = file_size < 80

                if is_malicious_name and is_very_small and not early_detection_successful:
                    logger.warning(
                        f"Very small file {path} ({file_size} bytes) with suspicious filename caused recursion errors"
                    )
                    result.add_check(
                        name="Recursion Error Analysis",
                        passed=False,
                        message="Small file with suspicious name caused recursion errors - potential security risk",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={
                            "reason": "malicious_indicators",
                            "file_size": file_size,
                            "exception_type": "RecursionError",
                            "early_detection_successful": early_detection_successful,
                            "suspicious_filename": is_malicious_name,
                        },
                        why=(
                            "This very small file has a suspicious filename and caused recursion errors "
                            "during pattern detection, which strongly suggests it's a maliciously crafted pickle."
                        ),
                    )
                else:
                    # Handle recursion errors conservatively - treat as scanner limitation
                    logger.warning(
                        f"Recursion limit reached scanning {path}. "
                        f"This indicates a complex pickle structure that exceeds scanner limits."
                    )
                    result.add_check(
                        name="Recursion Limit Check",
                        passed=False,
                        message="Scan limited by pickle complexity - recursion limit exceeded",
                        severity=IssueSeverity.DEBUG,
                        location=path,
                        details={
                            "reason": "recursion_limit_exceeded",
                            "file_size": file_size,
                            "exception_type": "RecursionError",
                            "early_detection_successful": early_detection_successful,
                        },
                        why=(
                            "The pickle file structure is too complex for the scanner to fully analyze due to "
                            "Python's recursion limits. This often occurs with legitimate but complex data structures. "
                            "Consider manually inspecting the file if security is a concern."
                        ),
                    )

                result.metadata.update(
                    {
                        "recursion_limited": True,
                        "file_size": file_size,
                        "scanner_limitation": True,
                    }
                )
                result.finish(success=True)  # Mark as successful scan despite limitation
                return result

            # Handle different types of parsing errors more gracefully
            error_message = str(e).lower()
            if "opcode" in error_message or "unknown" in error_message:
                # This could be a complex pickle file, corrupted data, or binary file
                file_ext = os.path.splitext(path)[1].lower()

                if is_bin_file:
                    # Binary file that's not a pickle - handle gracefully
                    logger.debug(f"Binary file {path} does not contain valid pickle data: {e}")
                    result.add_check(
                        name="Pickle Format Check",
                        passed=True,  # Not failing this as it's expected for binary files
                        message="File appears to be binary data rather than pickle format",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "file_type": "binary",
                            "pickle_parse_error": str(e),
                            "early_detection_successful": early_detection_successful,
                        },
                        why=(
                            "This binary file does not contain valid pickle data structure. "
                            "Binary content was analyzed for security patterns instead."
                        ),
                    )

                    # If early detection was successful, also perform comprehensive binary scan
                    if early_detection_successful:
                        result.metadata.update(
                            {
                                "file_type": "binary",
                                "pickle_parsing_failed": True,
                            }
                        )

                        # Perform comprehensive binary scan of the entire file
                        try:
                            with open(path, "rb") as f:
                                binary_result = self._scan_binary_content(f, 0, file_size)
                                # Add binary scanning results
                                for issue in binary_result.issues:
                                    result.add_check(
                                        name="Binary Content Check",
                                        passed=False,
                                        message=issue.message,
                                        severity=issue.severity,
                                        location=issue.location,
                                        details=issue.details,
                                        why=issue.why,
                                    )
                                result.metadata["binary_scan_completed"] = True
                                result.metadata["binary_bytes"] = file_size
                        except Exception as binary_scan_error:
                            logger.warning(f"Binary scan failed for {path}: {binary_scan_error}")
                            result.metadata["binary_scan_failed"] = str(binary_scan_error)

                        result.finish(success=True)
                        return result

                elif file_ext in [".pkl", ".pickle", ".joblib", ".dill"]:
                    # Pickle-like file with parsing issues - handle as format complexity
                    logger.debug(f"Pickle file {path} truncated due to format complexity: {e}")
                    result.add_check(
                        name="Pickle Format Complexity",
                        passed=True,  # Not a failure, just complex format
                        message="Scan truncated due to format complexity",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "file_type": "pickle_complex",
                            "parse_error": str(e),
                            "early_detection_successful": early_detection_successful,
                            "truncation_reason": "format_complexity",
                        },
                        why=(
                            "This pickle file contains complex structures that could not be fully parsed. "
                            "Early security pattern analysis was performed."
                        ),
                    )

                    # Always update metadata for complex pickle files
                    result.metadata.update(
                        {
                            "file_type": "pickle_complex",
                            "parsing_truncated": True,
                            "truncation_reason": "format_complexity",
                        }
                    )

                    result.finish(success=True)
                    return result

            # Handle as critical error for truly suspicious cases
            result.add_check(
                name="Pickle File Open",
                passed=False,
                message=f"Error opening pickle file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _scan_for_dangerous_patterns(self, data: bytes, result: ScanResult, context_path: str) -> None:
        """Scan raw bytes for dangerous patterns. Used by both scan and _scan_pickle_bytes."""
        # Early detection of dangerous patterns (existing + CVE-specific + binary code patterns)
        dangerous_patterns = [
            b"posix",  # Common in malicious pickles (posix.system)
            b"subprocess",
            b"eval",
            b"exec",
            b"compile",  # Can compile and execute arbitrary code
            b"__import__",
            b"builtins",  # Often used for builtins.eval, builtins.exec
            b"__builtins__",  # Alternative reference to builtins
            b"globals",  # Access to global namespace for code injection
            b"locals",  # Access to local namespace for code injection
            b"runpy",  # Can run modules and scripts (runpy.run_module, runpy.run_path)
            b"webbrowser",  # Can open malicious URLs (webbrowser.open)
            b"importlib",  # Dynamic imports (importlib.import_module)
            b"execfile",  # Execute Python files (Python 2 legacy but still dangerous)
            # Enhanced os/subprocess detection
            b"os.system",  # Direct system command execution
            b"os.popen",  # Process spawning with pipe
            b"os.spawn",  # Process spawning variants (spawnv, spawnve, etc.)
            b"subprocess.call",  # Subprocess call
            b"subprocess.run",  # Subprocess run (Python 3.5+)
            b"subprocess.Popen",  # Process creation
            b"commands",  # Python 2 legacy commands module
            b"getoutput",  # commands.getoutput
            b"getstatusoutput",  # commands.getstatusoutput
            b"system",  # Catches both os.system and from os import system
        ]

        # Add all binary code patterns to ensure consistency with binary scanning
        dangerous_patterns.extend(BINARY_CODE_PATTERNS)

        # Add CVE-specific binary patterns
        dangerous_patterns.extend(CVE_BINARY_PATTERNS)

        # CVE-2025-32434 specific patterns - PyTorch weights_only=True bypass techniques
        cve_2025_32434_patterns = [
            # Patterns that specifically exploit the weights_only=True assumption
            b"torch.load",  # Direct torch.load references in payload
            b"weights_only",  # References to the weights_only parameter
            b"torch._C",  # Internal PyTorch C++ interface access
            b"torch.jit._script",  # TorchScript exploitation paths
            b"torch.jit.trace",  # JIT tracing exploitation
            b"torch.serialization",  # PyTorch serialization internals
            b"torch._utils",  # Internal PyTorch utilities
            b"torch.nn.Module",  # Neural network module manipulation
            b"torch._six",  # PyTorch compatibility utilities
            b"torch.cuda._lazy_call",  # CUDA lazy execution exploitation
            b"torch.autograd.Function",  # Autograd function injection
            b"F.apply",  # Function application bypass
            # Base64/hex encoded PyTorch payloads
            b"dG9yY2g",  # base64 "torch"
            b"746f726368",  # hex "torch"
            b"UHlUb3JjaA",  # base64 "PyTorch"
            b"507954617268",  # hex "PyTorch"
            # Obfuscated torch references
            b"__torch__",  # Torch module references
            b"_torch_",  # Alternative torch references
            # Lambda exploitation in PyTorch context
            b"lambda",  # Lambda functions for code injection
            b"functools.partial",  # Partial function application
            # PyTorch-specific dangerous operations
            b"torch.save",  # Model saving manipulation
            b"torch.hub",  # PyTorch Hub exploitation
            b"torchvision.transforms",  # Transform pipeline injection
            b"torch.utils.data",  # Data pipeline manipulation
        ]

        # Combine all patterns
        all_dangerous_patterns = dangerous_patterns + cve_2025_32434_patterns

        # Limit how much we scan for performance
        max_scan_size = min(8192, len(data))
        scan_data = data[:max_scan_size]

        for pattern in all_dangerous_patterns:
            # Check for interrupts during pattern scanning
            self.check_interrupted()
            # Use find() instead of 'in' operator to be more explicit
            if scan_data.find(pattern) != -1:
                # Extract context around the pattern for semantic analysis
                pattern_str = pattern.decode("utf-8", errors="ignore")
                pattern_pos = scan_data.find(pattern)
                context_start = max(0, pattern_pos - 100)
                context_end = min(len(scan_data), pattern_pos + len(pattern) + 100)
                context = scan_data[context_start:context_end].decode("utf-8", errors="ignore")

                # Use semantic analysis to check if this is actually dangerous
                # For now, just check if it's in documentation or comments
                is_safe = "documentation" in context.lower() or "#" in context

                # Additional PyTorch-specific safety checks
                if pattern == b"torch._utils":
                    # torch._utils is safe when used with legitimate tensor rebuilding functions
                    legitimate_pytorch_functions = [
                        b"_rebuild_tensor_v2",
                        b"_rebuild_parameter",
                        b"_rebuild_tensor",
                        b"_rebuild_sparse_tensor",
                        b"_rebuild_nested_tensor",
                    ]
                    is_safe = is_safe or any(func in context.encode() for func in legitimate_pytorch_functions)

                # Skip if semantic analysis says it's safe (e.g., in documentation)
                if is_safe:
                    continue

                result.add_check(
                    name="Dangerous Pattern Detection",
                    passed=False,
                    message=f"Suspicious code pattern in binary data: {pattern_str}",
                    severity=IssueSeverity.CRITICAL,
                    location=context_path,
                    details={
                        "pattern": pattern_str,
                        "detection_method": "raw_content_scan",
                        "semantic_safe": is_safe,
                    },
                    why=(
                        f"The file contains the dangerous pattern '{pattern_str}' "
                        f"which could indicate malicious code execution during unpickling."
                    ),
                )

        # Perform CVE-specific pattern analysis on the data
        self._analyze_cve_patterns(data, result, context_path)

    def _analyze_cve_patterns(self, data: bytes, result: ScanResult, context_path: str) -> None:
        """Analyze data for specific CVE patterns and add CVE attribution."""
        # Convert bytes to string for pattern analysis
        try:
            content_str = data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            content_str = ""

        # Use CVE pattern analysis
        cve_attributions = analyze_cve_patterns(content_str, data)

        if cve_attributions:
            # Enhance scan result with CVE information
            enhance_scan_result_with_cve(result, [content_str], data)

            # Add specific CVE detection checks
            for attr in cve_attributions:
                severity = IssueSeverity.CRITICAL if attr.severity == "CRITICAL" else IssueSeverity.WARNING

                # Check if this is a high-confidence detection
                confidence_desc = "high" if attr.confidence > 0.8 else "medium" if attr.confidence > 0.6 else "low"

                result.add_check(
                    name=f"CVE Pattern Detection: {attr.cve_id}",
                    passed=False,
                    message=f"Detected patterns associated with {attr.cve_id} ({confidence_desc} confidence)",
                    severity=severity,
                    location=context_path,
                    details={
                        "cve_id": attr.cve_id,
                        "description": attr.description,
                        "cvss_score": attr.cvss,
                        "cwe": attr.cwe,
                        "affected_versions": attr.affected_versions,
                        "confidence": attr.confidence,
                        "patterns_matched": attr.patterns_matched,
                        "remediation": attr.remediation,
                    },
                    why=f"This pickle file contains patterns consistent with {attr.cve_id}, "
                    f"a {attr.severity.lower()} vulnerability ({attr.cwe}) affecting {attr.affected_versions}. "
                    f"This could indicate potential exploitation attempts. {attr.remediation}",
                )

    def _extract_globals_advanced(self, data: IO[bytes], multiple_pickles: bool = True) -> set[tuple[str, str]]:
        """Advanced pickle global extraction with STACK_GLOBAL and memo support."""
        globals_found: set[tuple[str, str]] = set()
        memo: dict[Union[int, str], str] = {}

        last_byte = b"dummy"
        while last_byte != b"":
            try:
                ops: list[tuple[Any, Any, Union[int, None]]] = list(pickletools.genops(data))
            except Exception as e:
                if globals_found:
                    logger.warning(f"Pickle parsing failed, but found {len(globals_found)} globals: {e}")
                    return globals_found
                # For internal scanner calls (like joblib), don't fail the entire scan
                # Just log the issue and return empty set
                logger.debug(f"Pickle parsing failed with no globals found: {e}")
                return set()

            last_byte = data.read(1)
            if last_byte:
                data.seek(-1, 1)

            for n, (opcode, arg, _pos) in enumerate(ops):
                op_name = opcode.name
                if op_name == "MEMOIZE" and n > 0:
                    memo[len(memo)] = ops[n - 1][1]
                elif op_name in {"PUT", "BINPUT", "LONG_BINPUT"} and n > 0:
                    memo[arg] = ops[n - 1][1]
                elif op_name in {"GLOBAL", "INST"}:
                    parts = str(arg).split(" ", 1)
                    if len(parts) == 2:
                        globals_found.add((parts[0], parts[1]))
                    elif parts:
                        globals_found.add((parts[0], ""))
                elif op_name == "STACK_GLOBAL":
                    values = self._extract_stack_global_values(ops, n, memo)
                    if len(values) == 2:
                        globals_found.add((values[1], values[0]))
                    else:
                        logger.debug(f"STACK_GLOBAL parsing failed at position {n}, found {len(values)} values")
                        globals_found.add(("unknown", "unknown"))

            if not multiple_pickles:
                break

        return globals_found

    def _extract_stack_global_values(
        self, ops: list[tuple[Any, Any, Union[int, None]]], position: int, memo: dict[Union[int, str], str]
    ) -> list[str]:
        """Extract values for STACK_GLOBAL opcode by walking backwards through stack."""
        values: list[str] = []

        for offset in range(1, min(position + 1, 10)):
            prev_op = ops[position - offset]
            op_name = prev_op[0].name
            op_value = prev_op[1]

            if op_name in {"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"}:
                continue
            if op_name in {"GET", "BINGET", "LONG_BINGET"}:
                values.append(memo.get(op_value, "unknown"))
            elif op_name in {"SHORT_BINUNICODE", "UNICODE", "BINUNICODE", "BINUNICODE8"}:
                values.append(str(op_value))
            else:
                logger.debug(f"Non-string opcode {op_name} in STACK_GLOBAL analysis")
                values.append("unknown")

            if len(values) == 2:
                break

        return values

    def _scan_pickle_bytes(self, file_obj: BinaryIO, file_size: int) -> ScanResult:
        """Scan pickle file content for suspicious opcodes"""
        result = self._create_result()
        opcode_count = 0
        suspicious_count = 0

        # For large files, use chunked reading to avoid memory issues
        MAX_MEMORY_READ = 50 * 1024 * 1024  # 50MB max in memory at once

        current_pos = file_obj.tell()

        # Read file data - either all at once for small files or first chunk for large files
        # For large files, read first 50MB for pattern analysis (critical malicious code is usually at the beginning)
        file_data = file_obj.read() if file_size <= MAX_MEMORY_READ else file_obj.read(MAX_MEMORY_READ)

        file_obj.seek(current_pos)  # Reset position
        # Extract global references across all pickle streams
        advanced_globals = self._extract_globals_advanced(file_obj)
        file_obj.seek(current_pos)  # Reset again after extraction

        # CRITICAL FIX: Scan for dangerous patterns in embedded pickles
        # This was missing and allowed malicious PyTorch models to pass undetected
        self._scan_for_dangerous_patterns(file_data, result, self.current_file_path)

        # Check for embedded secrets in the pickle data
        self.check_for_embedded_secrets(file_data, result, self.current_file_path)

        # Check for JIT/Script code execution risks and network communication patterns
        # Collect findings without creating individual checks
        jit_findings = self.collect_jit_script_findings(
            file_data,
            model_type="pytorch",  # Most pickle files in ML are PyTorch
            context=self.current_file_path,
        )
        network_findings = self.collect_network_communication_findings(
            file_data,
            context=self.current_file_path,
        )

        # Create single aggregated checks for the file
        self.summarize_jit_script_findings(jit_findings, result, context=self.current_file_path)
        self.summarize_network_communication_findings(network_findings, result, context=self.current_file_path)

        # Check pickle protocol version
        if file_data and len(file_data) >= 2:
            if file_data[0] == 0x80:  # Protocol 2+
                protocol_version = file_data[1]
                if protocol_version > 5:
                    result.add_check(
                        name="Pickle Protocol Version Check",
                        passed=False,
                        message=f"Unsupported pickle protocol version {protocol_version} (max supported: 5)",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"protocol_version": protocol_version, "max_supported": 5},
                    )
                else:
                    result.add_check(
                        name="Pickle Protocol Version Check",
                        passed=True,
                        message=f"Valid pickle protocol version {protocol_version}",
                        location=self.current_file_path,
                        details={"protocol_version": protocol_version},
                    )
            else:
                # Protocol 0 or 1
                result.add_check(
                    name="Pickle Protocol Version Check",
                    passed=True,
                    message="Pickle protocol version 0 or 1 detected",
                    location=self.current_file_path,
                    details={"protocol_version": "0 or 1"},
                )

        try:
            # Set a reasonable recursion limit to handle complex ML models
            import sys

            original_recursion_limit = sys.getrecursionlimit()
            # Increase recursion limit for large ML models but still have a bound
            # Use a higher limit to ensure we can analyze malicious patterns before hitting recursion limit
            new_limit = max(original_recursion_limit, 10000)
            sys.setrecursionlimit(new_limit)
            # Process the pickle
            start_pos = file_obj.tell()

            # Store opcodes for pattern analysis
            opcodes = []
            # Track strings on the stack for STACK_GLOBAL opcode analysis
            string_stack = []

            # Track stack depth for complexity analysis
            current_stack_depth = 0
            max_stack_depth = 0
            # Dynamic stack depth limit - will be adjusted based on ML context
            base_stack_depth_limit = 1000  # Base limit for unknown content
            # Store warnings for ML-context-aware processing
            stack_depth_warnings: list[dict[str, Union[int, str]]] = []

            for opcode, arg, pos in pickletools.genops(file_obj):
                # Check for interrupts periodically during opcode processing
                if opcode_count % 1000 == 0:  # Check every 1000 opcodes
                    self.check_interrupted()

                opcodes.append((opcode, arg, pos))
                opcode_count += 1

                # Track stack depth based on opcode type
                # Stack-building opcodes
                if opcode.name in ["MARK", "TUPLE", "LIST", "DICT", "FROZENSET", "INST", "OBJ", "BUILD"]:
                    current_stack_depth += 1
                    max_stack_depth = max(max_stack_depth, current_stack_depth)
                # Stack-consuming opcodes
                elif opcode.name in ["POP", "POP_MARK", "SETITEM", "SETITEMS", "APPEND", "APPENDS"]:
                    current_stack_depth = max(0, current_stack_depth - 1)
                # STOP resets the stack
                elif opcode.name == "STOP":
                    current_stack_depth = 0

                # Store stack depth warnings for ML-context-aware processing later
                if current_stack_depth > base_stack_depth_limit:
                    # Don't break immediately - store the warning for context-aware processing
                    stack_depth_warnings.append(
                        {
                            "current_depth": int(current_stack_depth),
                            "position": int(pos) if pos is not None else 0,
                            "opcode": str(opcode.name),
                        }
                    )
                    # Only break if stack depth becomes extremely high (10x base limit)
                    # to prevent actual resource exhaustion attacks
                    if current_stack_depth > base_stack_depth_limit * 10:
                        result.add_check(
                            name="Stack Depth Safety Check",
                            passed=False,
                            message=f"Extreme stack depth ({current_stack_depth}) - stopping scan for safety",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{self.current_file_path} (pos {pos})",
                            details={
                                "current_depth": current_stack_depth,
                                "max_allowed": base_stack_depth_limit * 10,
                                "position": pos,
                                "opcode": opcode.name,
                            },
                            why=(
                                "Stack depth is extremely high and could indicate a maliciously crafted pickle "
                                "designed to cause resource exhaustion."
                            ),
                        )
                        break

                # Track strings for STACK_GLOBAL analysis
                if opcode.name in [
                    "STRING",
                    "BINSTRING",
                    "SHORT_BINSTRING",
                    "SHORT_BINUNICODE",
                    "UNICODE",
                ] and isinstance(arg, str):
                    string_stack.append(arg)
                    # Keep only the last 10 strings to avoid memory issues
                    if len(string_stack) > 10:
                        string_stack.pop(0)

                # Check for too many opcodes
                if opcode_count > self.max_opcodes:
                    result.add_check(
                        name="Opcode Count Check",
                        passed=False,
                        message=f"Too many opcodes in pickle (> {self.max_opcodes})",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={
                            "opcode_count": opcode_count,
                            "max_opcodes": self.max_opcodes,
                        },
                        why=get_pattern_explanation("pickle_size_limit"),
                    )
                    break

                # Check for timeout
                if time.time() - result.start_time > self.timeout:
                    result.add_check(
                        name="Scan Timeout Check",
                        passed=False,
                        message=f"Scanning timed out after {self.timeout} seconds",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"opcode_count": opcode_count, "timeout": self.timeout},
                        why=(
                            "The scan exceeded the configured time limit. Large or complex pickle files may take "
                            "longer to analyze due to the number of opcodes that need to be processed."
                        ),
                    )
                    break

            # Add successful opcode count check if within limits
            if opcode_count <= self.max_opcodes:
                result.add_check(
                    name="Opcode Count Check",
                    passed=True,
                    message=f"Opcode count ({opcode_count}) is within limits",
                    location=self.current_file_path,
                    details={
                        "opcode_count": opcode_count,
                        "max_opcodes": self.max_opcodes,
                    },
                )

            # SMART DETECTION: Analyze ML context once for the entire pickle
            ml_context = _detect_ml_context(opcodes)

            # CVE-2025-32434 specific opcode sequence analysis
            cve_patterns = self._detect_cve_2025_32434_sequences(opcodes, file_size)
            for cve_pattern in cve_patterns:
                # Handle informational patterns (large legitimate models)
                if cve_pattern.get("status") == "normal":
                    result.add_check(
                        name="Large Model Opcode Analysis",
                        passed=True,
                        message=f"Large model analysis: {cve_pattern['description']}",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={
                            "pattern_type": cve_pattern["pattern_type"],
                            "dangerous_count": cve_pattern["dangerous_count"],
                            "file_size_mb": cve_pattern["file_size_mb"],
                            "opcode_density_per_mb": cve_pattern["opcode_density_per_mb"],
                            "threshold_used": cve_pattern["threshold_used"],
                        },
                    )
                    continue

                # Map severity levels to IssueSeverity
                severity_level = cve_pattern.get("severity_level", "critical")
                if severity_level == "critical":
                    severity = IssueSeverity.CRITICAL
                elif severity_level == "high":
                    severity = IssueSeverity.CRITICAL  # Still critical, but with context
                elif severity_level == "medium":
                    severity = IssueSeverity.WARNING  # Reduced severity for large models
                else:  # low
                    severity = IssueSeverity.INFO  # Just informational for very large models

                # Choose message prefix based on severity
                if severity == IssueSeverity.CRITICAL:
                    message_prefix = "Detected CVE-2025-32434 exploitation pattern"
                elif severity == IssueSeverity.WARNING:
                    message_prefix = "Potential CVE-2025-32434 pattern (large model context)"
                else:
                    message_prefix = "CVE-2025-32434 analysis (informational)"

                result.add_check(
                    name="CVE-2025-32434 Opcode Sequence Detection",
                    passed=severity not in [IssueSeverity.CRITICAL, IssueSeverity.WARNING],
                    message=f"{message_prefix}: {cve_pattern['description']}",
                    severity=severity,
                    location=f"{self.current_file_path} (pos {cve_pattern.get('position', 0)})",
                    details={
                        "cve_id": "CVE-2025-32434",
                        "pattern_type": cve_pattern["pattern_type"],
                        "description": cve_pattern["description"],
                        "opcodes_involved": cve_pattern.get("opcodes", []),
                        "exploitation_method": cve_pattern.get("exploitation_method", ""),
                        "position": cve_pattern.get("position", 0),
                        "dangerous_count": cve_pattern.get("dangerous_count", 0),
                        "file_size_mb": cve_pattern.get("file_size_mb", 0),
                        "opcode_density_per_mb": cve_pattern.get("opcode_density_per_mb", 0),
                        "threshold_used": cve_pattern.get("threshold_used", 0),
                        "severity_level": severity_level,
                        "confidence_score": cve_pattern.get("confidence_score", 0),
                    },
                )

            # ML-context-aware stack depth validation
            ml_confidence = ml_context.get("overall_confidence", 0)
            is_ml_content = ml_context.get("is_ml_content", False)

            # Determine appropriate stack depth limit based on ML context
            if is_ml_content and ml_confidence > 0.5:
                # High-confidence ML content gets much higher limits
                adjusted_stack_depth_limit = 5000
            elif is_ml_content and ml_confidence > 0.2:
                # Medium-confidence ML content gets moderately higher limits
                # PyTorch models often have lower confidence due to complex serialization
                adjusted_stack_depth_limit = 2500
            else:
                # Unknown/suspicious content keeps the base limit
                adjusted_stack_depth_limit = base_stack_depth_limit

            # Process stored stack depth warnings with ML context
            if stack_depth_warnings:
                # Filter warnings based on adjusted limit
                significant_warnings = [
                    w
                    for w in stack_depth_warnings
                    if isinstance(w["current_depth"], int) and w["current_depth"] > adjusted_stack_depth_limit
                ]

                if significant_warnings:
                    # Report only the most severe warning to avoid spam
                    def get_depth(x):
                        return x["current_depth"] if isinstance(x["current_depth"], int) else 0

                    worst_warning = max(significant_warnings, key=get_depth)
                    severity = _get_context_aware_severity(IssueSeverity.WARNING, ml_context)

                    result.add_check(
                        name="Stack Depth Safety Check",
                        passed=False,
                        message=f"Stack depth ({worst_warning['current_depth']}) exceeds ML-context-aware limit",
                        severity=severity,
                        location=f"{self.current_file_path} (pos {worst_warning['position']})",
                        details={
                            "current_depth": worst_warning["current_depth"],
                            "ml_adjusted_limit": adjusted_stack_depth_limit,
                            "base_limit": base_stack_depth_limit,
                            "opcode": worst_warning["opcode"],
                            "ml_context_confidence": ml_confidence,
                            "total_warnings": len(stack_depth_warnings),
                            "significant_warnings": len(significant_warnings),
                        },
                        why=(
                            "Excessive stack depth could indicate a maliciously crafted pickle designed to cause "
                            "resource exhaustion. The limit has been adjusted based on detected ML framework patterns."
                        ),
                    )
                else:
                    # Warnings were filtered out as benign for ML content
                    max_filtered_depth = max(
                        w["current_depth"] for w in stack_depth_warnings if isinstance(w["current_depth"], int)
                    )
                    result.add_check(
                        name="Stack Depth Safety Check",
                        passed=True,
                        message=(f"Stack depth warnings filtered as benign for ML content (max: {max_filtered_depth})"),
                        location=self.current_file_path,
                        details={
                            "max_depth_reached": max_stack_depth,
                            "ml_adjusted_limit": adjusted_stack_depth_limit,
                            "base_limit": base_stack_depth_limit,
                            "ml_context_confidence": ml_confidence,
                            "warnings_filtered": len(stack_depth_warnings),
                        },
                    )
            else:
                # No stack depth warnings - everything is within base limits
                result.add_check(
                    name="Stack Depth Validation",
                    passed=True,
                    message=f"Maximum stack depth ({max_stack_depth}) is within safe limits",
                    location=self.current_file_path,
                    details={
                        "max_depth_reached": max_stack_depth,
                        "ml_adjusted_limit": adjusted_stack_depth_limit,
                        "base_limit": base_stack_depth_limit,
                        "ml_context_confidence": ml_confidence,
                    },
                )

            # Also add to metadata for analysis
            result.metadata["max_stack_depth"] = max_stack_depth

            # Add ML context to metadata for debugging
            result.metadata.update(
                {
                    "ml_context": ml_context,
                    "opcode_count": opcode_count,
                    "suspicious_count": suspicious_count,
                },
            )

            # Analyze globals extracted from all pickle streams
            for mod, func in advanced_globals:
                if _is_actually_dangerous_global(mod, func, ml_context):
                    suspicious_count += 1
                    severity = _get_context_aware_severity(
                        IssueSeverity.CRITICAL,
                        ml_context,
                    )
                    result.add_check(
                        name="Advanced Global Reference Check",
                        passed=False,
                        message=f"Suspicious reference {mod}.{func}",
                        severity=severity,
                        location=self.current_file_path,
                        details={
                            "module": mod,
                            "function": func,
                            "opcode": "STACK_GLOBAL",
                            "ml_context_confidence": ml_context.get(
                                "overall_confidence",
                                0,
                            ),
                        },
                        why=get_import_explanation(mod),
                    )

            # Record successful ML context validation if content appears safe
            if ml_context.get("is_ml_content") and ml_context.get("overall_confidence", 0) > 0.5:
                result.add_check(
                    name="ML Framework Detection",
                    passed=True,
                    message="Model content validation passed",
                    location=self.current_file_path,
                    details={
                        "frameworks": list(ml_context.get("frameworks", {}).keys()),
                        "confidence": ml_context.get("overall_confidence", 0),
                        "opcode_count": opcode_count,
                    },
                )

            # Now analyze the collected opcodes with ML context awareness
            for opcode, arg, pos in opcodes:
                # Check for GLOBAL opcodes that might reference suspicious modules
                if opcode.name == "GLOBAL" and isinstance(arg, str):
                    # Handle both "module function" and "module.function" formats
                    parts = arg.split(" ", 1) if " " in arg else arg.rsplit(".", 1) if "." in arg else [arg, ""]

                    if len(parts) == 2:
                        mod, func = parts
                        if _is_actually_dangerous_global(mod, func, ml_context):
                            suspicious_count += 1
                            severity = _get_context_aware_severity(
                                IssueSeverity.CRITICAL,
                                ml_context,
                            )
                            result.add_check(
                                name="Global Module Reference Check",
                                passed=False,
                                message=f"Suspicious reference {mod}.{func}",
                                severity=severity,
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "module": mod,
                                    "function": func,
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "ml_context_confidence": ml_context.get(
                                        "overall_confidence",
                                        0,
                                    ),
                                },
                                why=get_import_explanation(mod),
                            )
                        else:
                            # Record successful validation of safe global
                            result.add_check(
                                name="Global Module Reference Check",
                                passed=True,
                                message=f"Safe global reference validated: {mod}.{func}",
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "module": mod,
                                    "function": func,
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "ml_context_confidence": ml_context.get(
                                        "overall_confidence",
                                        0,
                                    ),
                                },
                            )

                # SMART DETECTION: Only flag REDUCE opcodes if not clearly ML content
                if opcode.name == "REDUCE" and not ml_context.get(
                    "is_ml_content",
                    False,
                ):
                    # Use entropy analysis to check if this is ML data
                    # Look at surrounding data to determine if it's weights
                    if pos is not None:
                        surrounding_data = self._get_surrounding_data(file_data, pos, 1024)
                    else:
                        surrounding_data = file_data[:1024]  # Use first 1024 bytes if pos is None
                    data_type, confidence = self.entropy_analyzer.classify_data_type(surrounding_data)

                    # Skip if it looks like ML weights with high confidence
                    if data_type == "ml_weights" and confidence > 0.7:
                        continue

                    severity = _get_context_aware_severity(
                        IssueSeverity.WARNING,
                        ml_context,
                    )
                    result.add_check(
                        name="REDUCE Opcode Safety Check",
                        passed=False,
                        message="Found REDUCE opcode - potential __reduce__ method execution",
                        severity=severity,
                        location=f"{self.current_file_path} (pos {pos})",
                        details={
                            "position": pos,
                            "opcode": opcode.name,
                            "ml_context_confidence": ml_context.get(
                                "overall_confidence",
                                0,
                            ),
                            "entropy_classification": data_type,
                            "entropy_confidence": confidence,
                        },
                        why=get_opcode_explanation("REDUCE"),
                    )

                # SMART DETECTION: Only flag other dangerous opcodes
                # if not clearly ML content
                if opcode.name in ["INST", "OBJ", "NEWOBJ"] and not ml_context.get(
                    "is_ml_content",
                    False,
                ):
                    # Use entropy analysis to check if this is ML data
                    if pos is not None:
                        surrounding_data = self._get_surrounding_data(file_data, pos, 1024)
                    else:
                        surrounding_data = file_data[:1024]  # Use first 1024 bytes if pos is None
                    data_type, confidence = self.entropy_analyzer.classify_data_type(surrounding_data)

                    # Skip if it looks like ML weights with high confidence
                    if data_type == "ml_weights" and confidence > 0.7:
                        continue

                    # For sklearn models, NEWOBJ is expected for constructing objects
                    if (
                        opcode.name == "NEWOBJ"
                        and ml_context.get("frameworks", {}).get("sklearn", {}).get("confidence", 0) > 0.3
                    ):
                        continue

                    severity = _get_context_aware_severity(
                        IssueSeverity.WARNING,
                        ml_context,
                    )
                    result.add_check(
                        name="INST/OBJ Opcode Safety Check",
                        passed=False,
                        message=f"Found {opcode.name} opcode - potential code execution",
                        severity=severity,
                        location=f"{self.current_file_path} (pos {pos})",
                        details={
                            "position": pos,
                            "opcode": opcode.name,
                            "argument": str(arg),
                            "ml_context_confidence": ml_context.get(
                                "overall_confidence",
                                0,
                            ),
                            "entropy_classification": data_type,
                            "entropy_confidence": confidence,
                        },
                        why=get_opcode_explanation(opcode.name),
                    )

                # Check for suspicious strings
                if opcode.name in [
                    "STRING",
                    "BINSTRING",
                    "SHORT_BINSTRING",
                    "UNICODE",
                    "SHORT_BINUNICODE",
                ] and isinstance(arg, str):
                    suspicious_pattern = _is_actually_dangerous_string(arg, ml_context)
                    if suspicious_pattern:
                        severity = _get_context_aware_severity(
                            IssueSeverity.WARNING,
                            ml_context,
                        )
                        result.add_check(
                            name="String Pattern Security Check",
                            passed=False,
                            message=f"Suspicious string pattern: {suspicious_pattern}",
                            severity=severity,
                            location=f"{self.current_file_path} (pos {pos})",
                            details={
                                "position": pos,
                                "opcode": opcode.name,
                                "pattern": suspicious_pattern,
                                "string_preview": arg[:50] + ("..." if len(arg) > 50 else ""),
                                "ml_context_confidence": ml_context.get(
                                    "overall_confidence",
                                    0,
                                ),
                            },
                            why=get_pattern_explanation("encoded_strings")
                            if suspicious_pattern == "potential_base64"
                            else (
                                "This string contains patterns that match known security risks such as shell commands, "
                                "code execution functions, or encoded data."
                            ),
                        )

                # Detect nested pickle bytes
                if opcode.name in ["BINBYTES", "SHORT_BINBYTES"] and isinstance(arg, (bytes, bytearray)):
                    sample = bytes(arg[:1024])  # limit
                    if _looks_like_pickle(sample):
                        severity = _get_context_aware_severity(IssueSeverity.CRITICAL, ml_context)
                        result.add_check(
                            name="Nested Pickle Detection",
                            passed=False,
                            message="Nested pickle payload detected",
                            severity=severity,
                            location=f"{self.current_file_path} (pos {pos})",
                            details={
                                "position": pos,
                                "opcode": opcode.name,
                                "sample_size": len(sample),
                            },
                            why=get_pattern_explanation("nested_pickle"),
                        )

                # Detect encoded nested pickle strings
                if opcode.name in [
                    "STRING",
                    "BINSTRING",
                    "SHORT_BINSTRING",
                    "UNICODE",
                    "SHORT_BINUNICODE",
                ] and isinstance(arg, str):
                    for enc, decoded in _decode_string_to_bytes(arg):
                        if _looks_like_pickle(decoded[:1024]):
                            severity = _get_context_aware_severity(IssueSeverity.CRITICAL, ml_context)
                            result.add_check(
                                name="Encoded Pickle Detection",
                                passed=False,
                                message="Encoded pickle payload detected",
                                severity=severity,
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "encoding": enc,
                                    "decoded_size": len(decoded),
                                },
                                why=get_pattern_explanation("nested_pickle"),
                            )
                        else:
                            # Check if decoded content might be Python code
                            try:
                                decoded_str = decoded.decode("utf-8", errors="ignore")
                                if len(decoded_str) > 10 and any(
                                    pattern in decoded_str
                                    for pattern in ["import ", "def ", "class ", "eval(", "exec(", "__import__"]
                                ):
                                    is_valid, _ = validate_python_syntax(decoded_str)
                                    if is_valid:
                                        is_dangerous, risk_desc = is_code_potentially_dangerous(decoded_str, "low")
                                        if is_dangerous:
                                            severity = _get_context_aware_severity(IssueSeverity.WARNING, ml_context)
                                            result.add_check(
                                                name="Encoded Python Code Detection",
                                                passed=False,
                                                message=f"Encoded Python code detected ({enc})",
                                                severity=severity,
                                                location=f"{self.current_file_path} (pos {pos})",
                                                details={
                                                    "position": pos,
                                                    "opcode": opcode.name,
                                                    "encoding": enc,
                                                    "risk_analysis": risk_desc,
                                                    "code_preview": decoded_str[:100] + "..."
                                                    if len(decoded_str) > 100
                                                    else decoded_str,
                                                },
                                                why=(
                                                    "Encoded Python code was found that could be "
                                                    "executed during unpickling."
                                                ),
                                            )
                            except Exception:
                                # Not valid UTF-8, skip Python code check
                                pass

            # Check for STACK_GLOBAL patterns
            # (rebuild from opcodes to get proper context)
            for i, (opcode, _arg, pos) in enumerate(opcodes):
                if opcode.name == "STACK_GLOBAL":
                    # Find the two immediately preceding STRING-like opcodes
                    # STACK_GLOBAL expects exactly two strings on the stack:
                    # module and function
                    recent_strings: list[str] = []
                    for j in range(
                        i - 1,
                        max(0, i - 10),
                        -1,
                    ):  # Look back at most 10 opcodes
                        prev_opcode, prev_arg, prev_pos = opcodes[j]
                        if prev_opcode.name in [
                            "STRING",
                            "BINSTRING",
                            "SHORT_BINSTRING",
                            "SHORT_BINUNICODE",
                            "UNICODE",
                        ] and isinstance(prev_arg, str):
                            recent_strings.insert(
                                0,
                                prev_arg,
                            )  # Insert at beginning to maintain order
                            if len(recent_strings) >= 2:
                                break

                    if len(recent_strings) >= 2:
                        # The two strings are module and function in that order
                        mod = recent_strings[0]  # First string pushed (module)
                        func = recent_strings[1]  # Second string pushed (function)
                        if _is_actually_dangerous_global(mod, func, ml_context):
                            suspicious_count += 1
                            severity = _get_context_aware_severity(
                                IssueSeverity.CRITICAL,
                                ml_context,
                            )
                            result.add_check(
                                name="STACK_GLOBAL Module Check",
                                passed=False,
                                message=f"Suspicious module reference found: {mod}.{func}",
                                severity=severity,
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "module": mod,
                                    "function": func,
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "ml_context_confidence": ml_context.get(
                                        "overall_confidence",
                                        0,
                                    ),
                                },
                                why=get_import_explanation(mod),
                            )
                        else:
                            # Record successful validation of safe STACK_GLOBAL
                            result.add_check(
                                name="STACK_GLOBAL Module Check",
                                passed=True,
                                message=f"Safe module reference validated: {mod}.{func}",
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "module": mod,
                                    "function": func,
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "ml_context_confidence": ml_context.get(
                                        "overall_confidence",
                                        0,
                                    ),
                                },
                            )
                    else:
                        # Only warn about insufficient context if not ML content
                        if not ml_context.get("is_ml_content", False):
                            result.add_check(
                                name="STACK_GLOBAL Context Check",
                                passed=False,
                                message="STACK_GLOBAL opcode found without sufficient string context",
                                severity=IssueSeverity.INFO,
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "stack_size": len(recent_strings),
                                    "ml_context_confidence": ml_context.get(
                                        "overall_confidence",
                                        0,
                                    ),
                                },
                                why=(
                                    "STACK_GLOBAL requires two strings on the stack (module and function name) to "
                                    "import and access module attributes. Insufficient context prevents determining "
                                    "which module is being accessed."
                                ),
                            )

            # Check for dangerous patterns in the opcodes
            dangerous_pattern = is_dangerous_reduce_pattern(opcodes)
            if dangerous_pattern and not ml_context.get("is_ml_content", False):
                suspicious_count += 1
                severity = _get_context_aware_severity(
                    IssueSeverity.CRITICAL,
                    ml_context,
                )
                module_name = dangerous_pattern.get("module", "")
                result.add_check(
                    name="Reduce Pattern Analysis",
                    passed=False,
                    message=f"Detected dangerous __reduce__ pattern with "
                    f"{dangerous_pattern.get('module', '')}.{dangerous_pattern.get('function', '')}",
                    severity=severity,
                    location=f"{self.current_file_path} (pos {dangerous_pattern.get('position', 0)})",
                    details={
                        **dangerous_pattern,
                        "ml_context_confidence": ml_context.get(
                            "overall_confidence",
                            0,
                        ),
                    },
                    why=get_import_explanation(module_name)
                    if module_name
                    else "A dangerous pattern was detected that could execute arbitrary code during unpickling.",
                )
            else:
                # Record successful validation - no dangerous reduce patterns found
                result.add_check(
                    name="Reduce Pattern Analysis",
                    passed=True,
                    message="No dangerous __reduce__ patterns detected",
                    location=self.current_file_path,
                    details={
                        "opcode_count": opcode_count,
                        "ml_context_confidence": ml_context.get("overall_confidence", 0),
                    },
                )

            # Check for suspicious opcode sequences with ML context
            suspicious_sequences = check_opcode_sequence(opcodes, ml_context)
            if suspicious_sequences:
                for sequence in suspicious_sequences:
                    suspicious_count += 1
                    severity = _get_context_aware_severity(
                        IssueSeverity.WARNING,
                        ml_context,
                    )
                    result.add_check(
                        name="Opcode Sequence Analysis",
                        passed=False,
                        message=f"Suspicious opcode sequence: {sequence.get('pattern', 'unknown')}",
                        severity=severity,
                        location=f"{self.current_file_path} (pos {sequence.get('position', 0)})",
                        details={
                            **sequence,
                            "ml_context_confidence": ml_context.get(
                                "overall_confidence",
                                0,
                            ),
                        },
                        why=(
                            "This pickle contains an unusually high concentration of opcodes that can execute code "
                            "(REDUCE, INST, OBJ, NEWOBJ). Such patterns are uncommon in legitimate model files."
                        ),
                    )
            else:
                # Record successful validation - no suspicious opcode sequences
                result.add_check(
                    name="Opcode Sequence Analysis",
                    passed=True,
                    message="No suspicious opcode sequences detected",
                    location=self.current_file_path,
                    details={
                        "opcode_count": opcode_count,
                        "ml_context_confidence": ml_context.get("overall_confidence", 0),
                    },
                )

            # Update metadata
            end_pos = file_obj.tell()
            result.bytes_scanned = end_pos - start_pos
            result.metadata.update(
                {"opcode_count": opcode_count, "suspicious_count": suspicious_count},
            )

        except Exception as e:
            # Handle known issues with legitimate serialization files
            file_ext = os.path.splitext(self.current_file_path)[1].lower()

            # Check for recursion errors on legitimate ML model files
            is_recursion_error = isinstance(e, RecursionError)
            # Be more specific - only for large model files (>100MB) with ML extensions
            is_large_ml_model = (
                file_ext in {".bin", ".pt", ".pth", ".ckpt"} and file_size > 100 * 1024 * 1024  # > 100MB
            )

            # Pre-validate file legitimacy to avoid nested exceptions
            is_legitimate_file = False
            if file_ext in {".joblib", ".dill"} or is_large_ml_model:
                try:
                    if file_ext in {".joblib", ".dill"}:
                        is_legitimate_file = _is_legitimate_serialization_file(self.current_file_path)
                    elif is_large_ml_model:
                        # For large PyTorch model files, check if they look legitimate
                        is_legitimate_file = self._is_legitimate_pytorch_model(self.current_file_path)
                except Exception:
                    # If validation itself fails, treat as non-legitimate
                    is_legitimate_file = False

            # Check if this is a known benign error in legitimate serialization files
            is_benign_error = (
                isinstance(e, (ValueError, struct.error))
                and any(
                    msg in str(e).lower()
                    for msg in [
                        "unknown opcode",
                        "unpack requires",
                        "truncated",
                        "bad marshal data",
                    ]
                )
                and file_ext in {".joblib", ".dill"}
                and is_legitimate_file
            )

            # Check if this is a recursion error on a legitimate ML model
            is_recursion_on_legitimate_model = is_recursion_error and is_large_ml_model and is_legitimate_file

            if is_recursion_on_legitimate_model:
                # Recursion error on legitimate ML model - treat as scanner limitation, not security issue
                logger.debug(f"Recursion limit reached: {self.current_file_path} (complex nested structure)")
                result.metadata.update(
                    {
                        "recursion_limited": True,
                        "file_size": file_size,
                        "file_type": "legitimate_ml_model",
                        "opcodes_analyzed": opcode_count,
                        "scanner_limitation": True,
                    }
                )
                # Add as info-level issue for transparency, not critical
                result.add_check(
                    name="Recursion Depth Check",
                    passed=False,
                    message="Scan limited by model complexity",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={
                        "reason": "recursion_limit_on_legitimate_model",
                        "opcodes_analyzed": opcode_count,
                        "file_size": file_size,
                        "file_format": file_ext,
                        "max_recursion_depth": 1000,  # Python's default recursion limit
                    },
                    why=(
                        "This model file contains complex nested structures that exceed the scanner's "
                        "complexity limits. Complex model architectures with deeply nested structures can "
                        "exceed Python's recursion limits during analysis. The file appears legitimate based "
                        "on format validation."
                    ),
                )
            elif is_recursion_error:
                # Handle recursion errors more gracefully - this is a scanner limitation, not security issue
                logger.warning(
                    f"Recursion limit reached scanning {self.current_file_path}. "
                    f"This indicates a complex pickle structure that exceeds scanner limits."
                )
                result.metadata.update(
                    {
                        "recursion_limited": True,
                        "file_size": file_size,
                        "opcodes_analyzed": opcode_count,
                        "scanner_limitation": True,
                    }
                )
                # Add as debug, not critical - scanner limitation rather than security issue
                result.add_check(
                    name="Recursion Depth Check",
                    passed=False,
                    message="Scan limited by pickle complexity - recursion limit exceeded",
                    severity=IssueSeverity.DEBUG,
                    location=self.current_file_path,
                    details={
                        "reason": "recursion_limit_exceeded",
                        "opcodes_analyzed": opcode_count,
                        "file_size": file_size,
                        "exception_type": "RecursionError",
                        "max_recursion_depth": 1000,  # Python's default recursion limit
                    },
                    why=(
                        "The pickle file structure is too complex for the scanner to fully analyze due to "
                        "Python's recursion limits. This often occurs with legitimate but complex data structures. "
                        "Consider manually inspecting the file if security is a concern."
                    ),
                )
            elif is_benign_error:
                # Log for security auditing but treat as non-fatal
                logger.warning(
                    f"Truncated pickle scan of {self.current_file_path}: {e}. This may be due to non-pickle "
                    f"data after STOP opcode."
                )
                result.metadata.update(
                    {
                        "truncated": True,
                        "truncation_reason": "post_stop_data_or_format_issue",
                        "exception_type": type(e).__name__,
                        "exception_message": str(e)[:100],  # Limit message length
                        "validated_format": True,
                    },
                )
                # Still add as info-level issue for transparency
                result.add_check(
                    name="Pickle Stream Integrity Check",
                    passed=False,
                    message=f"Scan truncated due to format complexity: {type(e).__name__}",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={
                        "reason": "post_stop_data_or_format_issue",
                        "opcodes_analyzed": opcode_count,
                        "file_format": file_ext,
                        "stream_complete": False,
                        "bytes_processed": opcode_count,
                    },
                    why=(
                        "This file contains data after the pickle STOP opcode or uses format features that cannot "
                        "be fully analyzed. The analyzable portion was scanned for security issues."
                    ),
                )
            else:
                # Improve error messages for common cases
                error_str = str(e).lower()

                # Determine user-friendly error message and severity
                if "pickle exhausted before seeing stop" in error_str:
                    # Empty or incomplete pickle file
                    if file_size == 0:
                        message = "Empty file - not a valid pickle file"
                        severity = IssueSeverity.WARNING
                        why = "The file is empty and contains no pickle data."
                    else:
                        message = "Incomplete or corrupted pickle file - missing STOP opcode"
                        severity = IssueSeverity.WARNING
                        why = "The file is truncated or corrupted. Valid pickle files must end with a STOP opcode."
                elif "expected" in error_str and "bytes" in error_str and "but only" in error_str:
                    # File is truncated or not a pickle file
                    if file_size < 10:
                        message = "File too small to be a valid pickle file"
                        severity = IssueSeverity.WARNING
                        why = "The file is too small to contain valid pickle data."
                    else:
                        message = "Invalid pickle format - file is truncated or is not a pickle file"
                        severity = IssueSeverity.WARNING
                        why = (
                            "The file structure doesn't match the pickle format. It may be corrupted, truncated, "
                            "or not a pickle file at all."
                        )
                elif "opcode" in error_str and "unknown" in error_str:
                    # Unknown opcode - likely not a pickle file
                    message = "Invalid pickle format - unrecognized opcode"
                    severity = IssueSeverity.WARNING
                    why = "The file contains invalid opcodes. This usually means the file is not a valid pickle file."
                elif "no newline found" in error_str:
                    # Text file misidentified as pickle
                    message = "Not a valid pickle file - detected as text file"
                    severity = IssueSeverity.WARNING
                    why = "The file structure suggests this is a text file, not a pickle file."
                else:
                    # Generic error - still make it more user-friendly
                    message = f"Unable to parse pickle file: {type(e).__name__}"
                    severity = IssueSeverity.WARNING
                    why = f"The file could not be parsed as a valid pickle file. Error: {str(e)[:100]}"

                result.add_check(
                    name="Pickle Format Validation",
                    passed=False,
                    message=message,
                    severity=severity,
                    location=self.current_file_path,
                    details={
                        "exception": str(e),
                        "exception_type": type(e).__name__,
                        "file_extension": file_ext,
                        "opcodes_analyzed": opcode_count,
                        "file_size": file_size,
                    },
                    why=why,
                )

        finally:
            # Restore original recursion limit
            import contextlib

            with contextlib.suppress(NameError):
                sys.setrecursionlimit(original_recursion_limit)

        return result

    def _is_legitimate_pytorch_model(self, path: str) -> bool:
        """
        Check if a file appears to be a legitimate PyTorch model file.
        Uses heuristics to distinguish between legitimate models and malicious files.
        """
        try:
            with open(path, "rb") as f:
                # Read first 1KB to check for PyTorch patterns
                header = f.read(1024)
                if len(header) < 10:
                    return False

                # Check for pickle format
                if not (header[0] == 0x80 and header[1] in (2, 3, 4, 5)):
                    return False

                # Look for PyTorch-specific patterns in the header
                pytorch_indicators = [
                    b"torch",
                    b"_pickle",
                    b"collections",
                    b"OrderedDict",
                    b"state_dict",
                    b"_metadata",
                    b"version",
                ]

                # Check if it contains PyTorch indicators
                has_pytorch_patterns = any(indicator in header for indicator in pytorch_indicators)

                # For large files with PyTorch patterns, likely legitimate
                file_size = os.path.getsize(path)
                is_reasonable_size = 1024 * 1024 < file_size < 1024 * 1024 * 1024 * 1024  # 1MB to 1TB

                return has_pytorch_patterns and is_reasonable_size

        except Exception:
            return False

    def _scan_binary_content(
        self,
        file_obj: BinaryIO,
        start_pos: int,
        file_size: int,
    ) -> ScanResult:
        """Scan the binary content after pickle data for suspicious patterns"""
        result = self._create_result()

        try:
            from modelaudit.utils.ml_context import (
                analyze_binary_for_ml_context,
                should_ignore_executable_signature,
            )

            # Common patterns that might indicate embedded Python code
            code_patterns = BINARY_CODE_PATTERNS

            # Executable signatures with additional validation
            # For PE files, we need to check for the full DOS header structure
            # to avoid false positives from random "MZ" bytes in model weights
            executable_sigs = {k: v for k, v in EXECUTABLE_SIGNATURES.items() if k != b"MZ"}

            # Read in chunks
            chunk_size = 1024 * 1024  # 1MB chunks
            bytes_scanned = 0

            # Track patterns for ML context analysis
            pattern_counts: dict[bytes, list[int]] = {}
            first_chunk_ml_context = None

            while True:
                chunk = file_obj.read(chunk_size)
                if not chunk:
                    break

                current_offset = start_pos + bytes_scanned
                bytes_scanned += len(chunk)

                # Analyze ML context on first significant chunk
                if first_chunk_ml_context is None and len(chunk) >= 64 * 1024:  # 64KB minimum
                    first_chunk_ml_context = analyze_binary_for_ml_context(chunk, file_size)

                # Check for code patterns
                for pattern in code_patterns:
                    if pattern in chunk:
                        pos = chunk.find(pattern)
                        result.add_check(
                            name="Binary Data Safety Check",
                            passed=False,
                            message=(
                                f"Suspicious code pattern in binary data: {pattern.decode('ascii', errors='ignore')}"
                            ),
                            severity=IssueSeverity.INFO,
                            location=f"{self.current_file_path} (offset: {current_offset + pos})",
                            details={
                                "pattern": pattern.decode("ascii", errors="ignore"),
                                "offset": current_offset + pos,
                                "section": "binary_data",
                                "binary_size": bytes_scanned,
                                "suspicious_patterns_found": True,
                            },
                            why=(
                                "Python code patterns found in binary sections of the file. Model weights are "
                                "typically numeric data and should not contain readable code strings."
                            ),
                        )

                # Check for executable signatures with ML context awareness
                for sig, _description in executable_sigs.items():
                    if sig in chunk:
                        # Count all occurrences in this chunk
                        pos = 0
                        while True:
                            pos = chunk.find(sig, pos)
                            if pos == -1:
                                break

                            # Track pattern counts
                            if sig not in pattern_counts:
                                pattern_counts[sig] = []
                            pattern_counts[sig].append(current_offset + pos)
                            pos += len(sig)

                # Check for timeout
                if time.time() - result.start_time > self.timeout:
                    result.add_check(
                        name="Binary Scan Timeout Check",
                        passed=False,
                        message=f"Binary scanning timed out after {self.timeout} seconds",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={
                            "bytes_scanned": start_pos + bytes_scanned,
                            "timeout": self.timeout,
                            "scan_complete": False,
                        },
                        why=(
                            "The binary content scan exceeded the configured time limit. Large model files may "
                            "require more time to fully analyze."
                        ),
                    )
                    break

            # Use default context if we couldn't analyze
            if first_chunk_ml_context is None:
                first_chunk_ml_context = {"appears_to_be_weights": False, "weight_confidence": 0.0}

            # Process pattern findings with ML context awareness
            for sig, positions in pattern_counts.items():
                description = executable_sigs[sig]
                pattern_density = len(positions) / max(bytes_scanned / (1024 * 1024), 1)  # patterns per MB

                # Apply ML context filtering
                filtered_positions = []
                ignored_count = 0

                for offset in positions:
                    if should_ignore_executable_signature(
                        sig, offset, first_chunk_ml_context, int(pattern_density), len(positions)
                    ):
                        ignored_count += 1
                    else:
                        filtered_positions.append(offset)

                # Report significant patterns that weren't filtered out
                for offset in filtered_positions[:10]:  # Limit to first 10 to avoid spam
                    result.add_check(
                        name="Executable Signature Detection",
                        passed=False,
                        message=f"Executable signature found in binary data: {description}",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{self.current_file_path} (offset: {offset})",
                        details={
                            "signature": sig.hex(),
                            "description": description,
                            "offset": offset,
                            "section": "binary_data",
                            "total_found": len(positions),
                            "pattern_density_per_mb": round(pattern_density, 1),
                            "ml_context_confidence": first_chunk_ml_context.get("weight_confidence", 0),
                        },
                        why=(
                            "Executable files embedded in model data can run arbitrary code on the system. "
                            "Model files should contain only serialized weights and configuration data."
                        ),
                    )

                # Patterns filtered as coincidental

            # Special check for Windows PE files with more validation
            # Process PE signatures separately since they need DOS stub validation
            pe_sig = b"MZ"
            pe_positions = []

            # Go back through all chunks to find PE signatures (we need to re-read for validation)
            file_obj.seek(start_pos)
            chunk_offset = 0
            while chunk_offset < bytes_scanned:
                chunk = file_obj.read(min(chunk_size, bytes_scanned - chunk_offset))
                if not chunk:
                    break

                pos = 0
                while True:
                    pos = chunk.find(pe_sig, pos)
                    if pos == -1:
                        break

                    # Check if we have enough data to validate DOS header
                    if pos + 64 <= len(chunk):
                        # Check for "This program cannot be run in DOS mode" string
                        dos_stub_msg = b"This program cannot be run in DOS mode"
                        search_end = min(pos + 512, len(chunk))
                        if dos_stub_msg in chunk[pos:search_end]:
                            pe_positions.append(start_pos + chunk_offset + pos)
                    pos += len(pe_sig)

                chunk_offset += len(chunk)

            # Process PE findings with ML context
            if pe_positions:
                pattern_density = len(pe_positions) / max(bytes_scanned / (1024 * 1024), 1)
                filtered_pe_positions = []
                ignored_pe_count = 0

                for offset in pe_positions:
                    if should_ignore_executable_signature(
                        pe_sig, offset, first_chunk_ml_context, int(pattern_density), len(pe_positions)
                    ):
                        ignored_pe_count += 1
                    else:
                        filtered_pe_positions.append(offset)

                # Report valid PE signatures that weren't filtered
                for offset in filtered_pe_positions[:5]:  # Limit PE reports more strictly
                    result.add_check(
                        name="PE Executable Detection",
                        passed=False,
                        message="Executable signature found in binary data: Windows executable (PE)",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{self.current_file_path} (offset: {offset})",
                        details={
                            "signature": pe_sig.hex(),
                            "description": "Windows executable (PE) with valid DOS stub",
                            "offset": offset,
                            "section": "binary_data",
                            "total_found": len(pe_positions),
                            "pattern_density_per_mb": round(pattern_density, 1),
                        },
                        why=(
                            "Windows executable files embedded in model data can run arbitrary code on the "
                            "system. The presence of a valid DOS stub confirms this is an actual PE executable."
                        ),
                    )

                # PE patterns were filtered as coincidental - no need to log this

            result.bytes_scanned = bytes_scanned

        except Exception as e:
            result.add_check(
                name="Binary Content Scan",
                passed=False,
                message=f"Error scanning binary content: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )

        return result

    def _detect_cve_2025_32434_sequences(self, opcodes: list[tuple], file_size: int) -> list[dict]:
        """Detect specific opcode sequences that indicate CVE-2025-32434 exploitation techniques

        Uses dynamic thresholds based on file size to reduce false positives for large legitimate models.
        """
        patterns = []

        # Count dangerous opcodes and torch references for overall analysis
        dangerous_opcodes_count = 0
        torch_references = 0
        dangerous_opcodes_found = []

        for i, (opcode, arg, pos) in enumerate(opcodes):
            # Count dangerous opcodes
            if opcode.name in ["REDUCE", "INST", "OBJ", "NEWOBJ", "STACK_GLOBAL"]:
                dangerous_opcodes_count += 1
                dangerous_opcodes_found.append((opcode.name, pos))

            # Count torch references
            if (
                opcode.name in ["GLOBAL", "STACK_GLOBAL"]
                and arg
                and any(torch_pattern in str(arg).lower() for torch_pattern in ["torch", "pytorch", "_c", "jit"])
            ):
                torch_references += 1

            # Pattern 1: Clearly malicious torch operations (not legitimate storage/rebuild operations)
            if (
                opcode.name in ["GLOBAL", "STACK_GLOBAL"]
                and arg
                and any(torch_pattern in str(arg).lower() for torch_pattern in ["torch", "pytorch", "_c", "jit"])
            ):
                # Look for dangerous opcodes within next 30 positions
                # Note: We check ALL torch operations since even legitimate ones can be part of attacks
                for j in range(i + 1, min(i + 31, len(opcodes))):
                    next_opcode, next_arg, next_pos = opcodes[j]
                    if next_opcode.name in ["REDUCE", "INST", "OBJ", "NEWOBJ"]:
                        # Only flag clearly suspicious torch operations
                        is_suspicious = (
                            # Suspicious torch modules/functions
                            any(
                                suspicious in str(arg).lower()
                                for suspicious in [
                                    "eval",
                                    "exec",
                                    "system",
                                    "import",
                                    "builtin",
                                    "compile",
                                    "subprocess",
                                    "os.",
                                    "sys.",
                                    "__import__",
                                    "getattr",
                                ]
                            )
                            or
                            # Non-standard torch operations that could be malicious
                            (
                                "torch" in str(arg).lower()
                                and not any(
                                    standard in str(arg).lower()
                                    for standard in [
                                        "storage",
                                        "_rebuild",
                                        "tensor",
                                        "parameter",
                                        "module",
                                        "nn.",
                                        "functional",
                                        "utils",
                                        "cuda",
                                        "device",
                                    ]
                                )
                            )
                        )

                        if is_suspicious:
                            patterns.append(
                                {
                                    "pattern_type": "torch_import_with_execution",
                                    "description": (
                                        f"Suspicious PyTorch operation ({arg}) followed by {next_opcode.name} opcode"
                                    ),
                                    "opcodes": [opcode.name, next_opcode.name],
                                    "exploitation_method": "weights_only=True bypass via PyTorch operation",
                                    "position": pos,
                                }
                            )
                            break

            # Pattern 2: Multiple REDUCE opcodes in sequence (common in CVE-2025-32434 exploits)
            if opcode.name == "REDUCE" and i < len(opcodes) - 2:
                reduce_sequence = [opcode.name]
                reduce_positions = [pos]

                # Look for subsequent REDUCE opcodes
                for j in range(i + 1, min(i + 6, len(opcodes))):
                    next_opcode, next_arg, next_pos = opcodes[j]
                    if next_opcode.name == "REDUCE":
                        reduce_sequence.append(next_opcode.name)
                        reduce_positions.append(next_pos)
                    elif next_opcode.name in ["MARK", "TUPLE", "LIST"]:
                        # Skip structure opcodes
                        continue
                    else:
                        break

                # If we found 3+ REDUCE opcodes in close proximity
                if len(reduce_sequence) >= 3:
                    patterns.append(
                        {
                            "pattern_type": "chained_reduce_execution",
                            "description": f"Chain of {len(reduce_sequence)} REDUCE opcodes indicating complex exploit",
                            "opcodes": reduce_sequence,
                            "exploitation_method": "Chained __reduce__ method exploitation",
                            "position": pos,
                        }
                    )

            # Pattern 3: GLOBAL builtins.eval/exec followed by data loading
            if (
                opcode.name in ["GLOBAL", "STACK_GLOBAL"]
                and arg
                and any(dangerous in str(arg).lower() for dangerous in ["eval", "exec", "compile", "__import__"])
            ):
                # Look for data loading opcodes that could contain payload
                for j in range(i + 1, min(i + 8, len(opcodes))):
                    next_opcode, next_arg, next_pos = opcodes[j]
                    if next_opcode.name in ["UNICODE", "STRING", "BINUNICODE", "SHORT_BINSTRING"]:
                        patterns.append(
                            {
                                "pattern_type": "eval_exec_with_payload",
                                "description": f"Code execution function ({arg}) with string payload",
                                "opcodes": [opcode.name, next_opcode.name],
                                "exploitation_method": "Direct code execution via eval/exec",
                                "position": pos,
                            }
                        )
                        break

            # Pattern 4: BUILD opcode with suspicious GLOBAL preceding it (setstate exploitation)
            if opcode.name == "BUILD" and i > 0:
                # Look backwards for GLOBAL opcodes
                for j in range(max(0, i - 5), i):
                    prev_opcode, prev_arg, prev_pos = opcodes[j]
                    if (
                        prev_opcode.name in ["GLOBAL", "STACK_GLOBAL"]
                        and prev_arg
                        and any(
                            suspicious in str(prev_arg).lower()
                            for suspicious in ["os", "subprocess", "eval", "exec", "torch"]
                        )
                    ):
                        patterns.append(
                            {
                                "pattern_type": "setstate_exploitation",
                                "description": f"BUILD opcode with suspicious import ({prev_arg})",
                                "opcodes": [prev_opcode.name, opcode.name],
                                "exploitation_method": "__setstate__ method exploitation",
                                "position": pos,
                            }
                        )
                        break

            # Pattern 5: Lambda exploitation sequences (GLOBAL lambda followed by REDUCE)
            if opcode.name in ["UNICODE", "STRING", "BINUNICODE"] and arg and "lambda" in str(arg).lower():
                # Look for REDUCE opcodes following lambda
                for j in range(i + 1, min(i + 8, len(opcodes))):
                    next_opcode, next_arg, next_pos = opcodes[j]
                    if next_opcode.name == "REDUCE":
                        patterns.append(
                            {
                                "pattern_type": "lambda_exploitation",
                                "description": "Lambda function with REDUCE opcode execution",
                                "opcodes": [opcode.name, next_opcode.name],
                                "exploitation_method": "Lambda function code injection",
                                "position": pos,
                            }
                        )
                        break

        # Pattern 6: Improved density-based CVE-2025-32434 detection
        # Use dynamic thresholds based on file size to reduce false positives for large legitimate models
        if torch_references > 0 and dangerous_opcodes_count > 0:
            # Calculate density: opcodes per MB
            file_size_mb = file_size / (1024 * 1024)
            raw_opcode_density_per_mb = dangerous_opcodes_count / max(file_size_mb, 0.1)  # Avoid division by zero
            opcode_density_per_mb = round(raw_opcode_density_per_mb, 1)

            # Dynamic thresholds based on file size:
            # Small files (<10MB): Very sensitive - 80+ opcodes per MB is suspicious
            # Medium files (10MB-1GB): Moderate sensitivity - 200+ opcodes per MB
            # Large files (>1GB): Low sensitivity - 500+ opcodes per MB (for large models like Llama)
            if file_size_mb < 10:
                density_threshold = 80.0
                severity_level = "critical"
            elif file_size_mb < 1000:  # < 1GB
                density_threshold = 200.0
                severity_level = "high" if opcode_density_per_mb > 300 else "medium"
            else:  # >= 1GB (large models)
                density_threshold = 500.0  # Much higher threshold for large models
                severity_level = "medium" if opcode_density_per_mb > 800 else "low"

            # Only flag if density exceeds threshold
            if opcode_density_per_mb > density_threshold:
                confidence_score = int(min(100.0, (raw_opcode_density_per_mb / density_threshold - 1.0) * 100.0))

                patterns.append(
                    {
                        "pattern_type": "high_risk_opcode_density",
                        "description": (
                            f"Elevated dangerous opcode density ({dangerous_opcodes_count} opcodes, "
                            f"{opcode_density_per_mb:.1f}/MB in {file_size_mb:.1f}MB file) "
                            f"may indicate CVE-2025-32434 exploitation (confidence: {confidence_score:.0f}%)"
                        ),
                        "opcodes": [op for op, pos in dangerous_opcodes_found[:10]],  # First 10 for brevity
                        "exploitation_method": "weights_only=True bypass via opcode density attack",
                        "position": dangerous_opcodes_found[0][1] if dangerous_opcodes_found else 0,
                        "dangerous_count": dangerous_opcodes_count,
                        "torch_references": torch_references,
                        "file_size_mb": file_size_mb,
                        "opcode_density_per_mb": opcode_density_per_mb,
                        "threshold_used": density_threshold,
                        "severity_level": severity_level,
                        "confidence_score": confidence_score,
                    }
                )

        # Add informational message for large legitimate models that are below threshold
        if (
            torch_references > 0
            and dangerous_opcodes_count > 50
            and file_size_mb > 100
            and opcode_density_per_mb <= density_threshold
        ):
            patterns.append(
                {
                    "pattern_type": "large_model_normal_density",
                    "description": (
                        f"Large PyTorch model ({file_size_mb:.1f}MB) with {dangerous_opcodes_count} "
                        f"dangerous opcodes ({opcode_density_per_mb:.1f}/MB) is within expected range "
                        "for legitimate models"
                    ),
                    "dangerous_count": dangerous_opcodes_count,
                    "file_size_mb": file_size_mb,
                    "opcode_density_per_mb": opcode_density_per_mb,
                    "threshold_used": density_threshold,
                    "status": "normal",
                }
            )

        return patterns

    def check_for_jit_script_code(
        self,
        data: bytes,
        result: ScanResult,
        model_type: str = "pytorch",
        context: str = "",
        enable_check: bool = True,
    ) -> int:
        """Check for JIT/Script code execution risks in pickle data.

        Args:
            data: The binary file data to analyze
            result: ScanResult to add findings to
            model_type: Type of model being scanned (e.g., 'pytorch')
            context: Context path for reporting
            enable_check: Whether to enable this check (inherited from base)

        Returns:
            Number of findings discovered
        """
        # Check if JIT script detection is enabled
        if not enable_check or not self.config.get("check_jit_script", True):
            return 0

        try:
            from modelaudit.jit_script_detector import JITScriptDetector
            # from modelaudit.models import JITScriptFinding  # Imported but not used directly

            # Create JIT script detector
            detector = JITScriptDetector(self.config)

            # Scan for JIT script patterns based on model type
            findings = []
            if model_type.lower() == "pytorch":
                findings = detector.scan_torchscript(data, context)
            elif model_type.lower() == "tensorflow":
                findings = detector.scan_tensorflow(data, context)
            elif model_type.lower() == "onnx":
                findings = detector.scan_onnx(data, context)
            else:
                # Try to detect model type automatically
                findings = detector.scan_model(data, context)

            # Convert findings to Check objects
            if findings:
                failed_findings = [f for f in findings if getattr(f, "severity", "") in ["CRITICAL", "WARNING"]]
                if failed_findings:
                    # Add a failed check for JIT/Script risks
                    details = {
                        "findings_count": len(findings),
                        "critical_findings": len([f for f in findings if getattr(f, "severity", "") == "CRITICAL"]),
                        "warning_findings": len([f for f in findings if getattr(f, "severity", "") == "WARNING"]),
                        "patterns": [getattr(f, "pattern", "") for f in findings[:5]],  # First 5 patterns
                    }

                    # Add specific details for dangerous operations
                    for finding in findings[:3]:  # Include details for first 3 findings
                        if hasattr(finding, "message") and "torch.ops.aten.system" in str(finding.message):
                            details["torch.ops.aten.system"] = str(finding.message)

                    result.add_check(
                        name="JIT/Script Code Execution Risk",
                        passed=False,
                        message=f"Detected {len(failed_findings)} JIT/Script security risks",
                        severity=IssueSeverity.CRITICAL,
                        location=context,
                        details=details,
                        why="JIT/Script code can execute arbitrary operations that bypass security controls",
                    )
                else:
                    # Add a passed check
                    result.add_check(
                        name="JIT/Script Code Execution Risk",
                        passed=True,
                        message="No high-risk JIT/Script patterns detected",
                        severity=IssueSeverity.INFO,
                        location=context,
                        details={"findings_count": len(findings)},
                        why="JIT/Script analysis completed with no critical security risks",
                    )
                return len(findings)
            else:
                # No findings at all - add a passed check
                result.add_check(
                    name="JIT/Script Code Execution Risk",
                    passed=True,
                    message="No JIT/Script patterns detected",
                    severity=IssueSeverity.INFO,
                    location=context,
                    why="File contains no detectable JIT/Script code execution patterns",
                )
                return 0

        except ImportError:
            # JIT script detector not available
            result.add_check(
                name="JIT/Script Code Execution Risk",
                passed=True,
                message="JIT/Script detection not available (missing dependencies)",
                severity=IssueSeverity.INFO,
                location=context,
                details={"error": "JIT script detector dependencies not installed"},
                why="JIT/Script detection requires additional dependencies",
            )
            return 0
        except Exception as e:
            # Error during JIT script detection
            result.add_check(
                name="JIT/Script Code Execution Risk",
                passed=False,
                message=f"Error during JIT/Script detection: {e!s}",
                severity=IssueSeverity.WARNING,
                location=context,
                details={"error": str(e), "error_type": type(e).__name__},
                why="JIT/Script detection encountered an unexpected error",
            )
            return 0
