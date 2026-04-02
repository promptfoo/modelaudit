"""Scanner for Python pickle serialized files (.pkl, .pickle)."""

import io
import os
import pickletools
import reprlib
import struct
import time
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, field
from typing import Any, BinaryIO, ClassVar, Literal, TypedDict, TypeGuard

from modelaudit.analysis.enhanced_pattern_detector import EnhancedPatternDetector, PatternMatch
from modelaudit.analysis.entropy_analyzer import EntropyAnalyzer
from modelaudit.analysis.framework_patterns import FrameworkKnowledgeBase
from modelaudit.analysis.ml_context_analyzer import MLContextAnalyzer
from modelaudit.analysis.opcode_sequence_analyzer import OpcodeSequenceAnalyzer
from modelaudit.analysis.semantic_analyzer import SemanticAnalyzer
from modelaudit.detectors.suspicious_symbols import (
    BINARY_CODE_PATTERNS,
    CVE_BINARY_PATTERNS,
    EXECUTABLE_SIGNATURES,
    SUSPICIOUS_GLOBALS,
    SUSPICIOUS_STRING_PATTERNS,
)
from modelaudit.utils.helpers.code_validation import (
    is_code_potentially_dangerous,
    validate_python_syntax,
)
from modelaudit.utils.helpers.ml_context import get_ml_context_explanation

from ..config.explanations import (
    get_import_explanation,
    get_opcode_explanation,
    get_pattern_explanation,
)
from ..detectors.cve_patterns import analyze_cve_patterns, enhance_scan_result_with_cve
from ..detectors.suspicious_symbols import DANGEROUS_OPCODES
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult, logger
from .rule_mapper import (
    get_embedded_code_rule_code,
    get_encoding_rule_code,
    get_generic_rule_code,
    get_import_rule_code,
    get_pickle_opcode_rule_code,
)

_RESYNC_BUDGET = 8192  # Max bytes to scan forward when resyncing after an unknown opcode
COPYREG_EXTENSION_MODULE = "__copyreg_extension__"
COPYREG_EXTENSION_PREFIX = "code_"
_STACK_GLOBAL_OPERAND_PREVIEW_MAX = 128
_STACK_GLOBAL_BINARY_PREVIEW_BYTES = 8
_STACK_GLOBAL_OPERAND_PREVIEWER = reprlib.Repr()
_STACK_GLOBAL_OPERAND_PREVIEWER.maxstring = _STACK_GLOBAL_OPERAND_PREVIEW_MAX
_STACK_GLOBAL_OPERAND_PREVIEWER.maxother = _STACK_GLOBAL_OPERAND_PREVIEW_MAX
_STACK_GLOBAL_OPERAND_PREVIEWER.maxlist = 4
_STACK_GLOBAL_OPERAND_PREVIEWER.maxtuple = 4
_STACK_GLOBAL_OPERAND_PREVIEWER.maxset = 4
_STACK_GLOBAL_OPERAND_PREVIEWER.maxfrozenset = 4
_STACK_GLOBAL_OPERAND_PREVIEWER.maxdict = 4
_RAW_PATTERN_SCAN_LIMIT_BYTES = 10 * 1024 * 1024
_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES = 64 * 1024
_NESTED_PICKLE_VALIDATION_WINDOW_BYTES = 8 * 1024
_POST_BUDGET_GLOBAL_SCAN_LIMIT_BYTES = 100 * 1024 * 1024
_POST_BUDGET_GLOBAL_CONTEXT_BYTES = 4096
_POST_BUDGET_GLOBAL_MEMO_LIMIT_ENTRIES = 4096
_POST_BUDGET_GLOBAL_MAX_REFERENCE_FINDINGS = 4096
_POST_BUDGET_GLOBAL_DEADLINE_CHECK_INTERVAL_BYTES = 4096
_POST_BUDGET_EXPANSION_SCAN_LIMIT_BYTES = 8 * 1024 * 1024
_POST_BUDGET_OPCODE_SCAN_LIMIT_OPCODES = 500_000
_MEMO_WRITE_OPCODES = frozenset({"PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE"})
_MEMO_READ_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})
_EXPANSION_EVENT_WINDOW = 6
_EXPANSION_GROWTH_BUILDERS = frozenset({"TUPLE", "TUPLE1", "TUPLE2", "TUPLE3", "LIST", "APPENDS", "APPEND"})
_EXPANSION_DUP_COUNT_THRESHOLD = 128
_EXPANSION_DUP_DENSITY_THRESHOLD = 0.10
_EXPANSION_GET_PUT_RATIO_THRESHOLD = 32.0
_EXPANSION_GET_PUT_MIN_READS = 128
_EXPANSION_MEMO_GROWTH_MIN_WRITES = 64
_EXPANSION_MEMO_GROWTH_STEPS_THRESHOLD = 32
_EXPANSION_RATIO_SUPPORTING_DUP_THRESHOLD = 64
_EXPANSION_RATIO_SUPPORTING_GROWTH_THRESHOLD = 16
_EXPANSION_TRIGGER_LABELS = {
    "suspicious_get_put_ratio": "high memo GET/PUT ratio",
    "excessive_dup_usage": "dense DUP usage",
    "memo_growth_chain": "iterative memo growth chain",
}
_BINARY_PICKLE_PROTOCOLS = frozenset({2, 3, 4, 5})
_PICKLE_OPCODE_BYTES = frozenset(ord(op.code) for op in pickletools.opcodes)


StackGlobalOperandKind = Literal["string", "missing_memo", "unknown", "non_string"]
MalformedStackGlobalReason = Literal["insufficient_context", "missing_memo", "mixed_or_non_string"]


class MalformedStackGlobalDetails(TypedDict):
    module_kind: StackGlobalOperandKind
    module: str
    function_kind: StackGlobalOperandKind
    function: str
    reason: MalformedStackGlobalReason


class _GenopsBudgetExceeded(Exception):
    """Signal that opcode iteration stopped due to an explicit resource budget."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class _NestedPickleMatch:
    offset: int
    sample_size: int
    searched_bytes: int


def _mark_inconclusive_scan_result(result: ScanResult, reason: str) -> None:
    """Mark a scan result as inconclusive when analysis could not complete."""
    existing_reasons = result.metadata.get("scan_outcome_reasons")
    reasons = existing_reasons if isinstance(existing_reasons, list) else []

    if reason not in reasons:
        reasons.append(reason)

    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    result.metadata["scan_outcome_reasons"] = reasons
    result.metadata["analysis_incomplete"] = True


def _scan_result_has_security_findings(result: ScanResult) -> bool:
    """Return True when the result includes WARNING/CRITICAL findings."""
    return any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def _finish_with_inconclusive_contract(
    result: ScanResult,
    *,
    default_success: bool,
    allow_security_findings_override: bool = False,
) -> None:
    """Finalize success so inconclusive/no-finding scans fail closed."""
    has_security_findings = _scan_result_has_security_findings(result)
    if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME and not has_security_findings:
        result.finish(success=False)
        return

    result.finish(success=default_success or (allow_security_findings_override and has_security_findings))


def _format_stack_global_string_preview(value: str) -> str:
    """Return a bounded preview for malformed STACK_GLOBAL string operands."""
    preview = _STACK_GLOBAL_OPERAND_PREVIEWER.repr(value)
    if len(preview) >= 2 and preview[0] == preview[-1] and preview[0] in {"'", '"'}:
        preview = preview[1:-1]
    return preview


def _format_stack_global_operand_preview(value: Any) -> str:
    """Return a bounded diagnostic preview for malformed STACK_GLOBAL operands."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        value_len = value.nbytes if isinstance(value, memoryview) else len(value)
        prefix_bytes = bytes(value[:_STACK_GLOBAL_BINARY_PREVIEW_BYTES])
        suffix = "..." if value_len > _STACK_GLOBAL_BINARY_PREVIEW_BYTES else ""
        return f"{type(value).__name__}(len={value_len}, hex=0x{prefix_bytes.hex()}{suffix})"

    preview = _STACK_GLOBAL_OPERAND_PREVIEWER.repr(value)
    if len(preview) > _STACK_GLOBAL_OPERAND_PREVIEW_MAX:
        preview = preview[:_STACK_GLOBAL_OPERAND_PREVIEW_MAX] + "...<truncated>"

    preview_value_len: int | None
    try:
        preview_value_len = len(value)
    except Exception:
        preview_value_len = None

    length_suffix = f" (len={preview_value_len})" if preview_value_len is not None else ""
    return f"{type(value).__name__}:{preview}{length_suffix}"


def _scan_structural_tamper_findings(file_data: bytes) -> list[dict[str, Any]]:
    """Detect structurally suspicious pickle stream patterns.

    This scanner intentionally focuses on true pickle-structure violations and keeps
    severity low so malformed/truncated payloads are visible without overshadowing
    direct code-execution signals.
    """

    findings: list[dict[str, Any]] = []
    if not file_data:
        return findings

    offset = 0
    max_separator_skip = 256

    while offset < len(file_data):
        stream = file_data[offset:]
        bio = io.BytesIO(stream)
        stream_opcode_count = 0
        stream_had_stop = False
        seen_proto_version: int | None = None

        try:
            for opcode, arg, pos in pickletools.genops(bio):
                stream_opcode_count += 1
                opcode_pos = int(pos) if pos is not None else 0
                absolute_pos = offset + opcode_pos

                if opcode.name == "PROTO":
                    if stream_opcode_count > 1:
                        findings.append(
                            {
                                "kind": "misplaced_proto",
                                "stream_offset": offset,
                                "position": absolute_pos,
                                "protocol": arg,
                            }
                        )

                    if seen_proto_version is not None:
                        findings.append(
                            {
                                "kind": "duplicate_proto",
                                "stream_offset": offset,
                                "position": absolute_pos,
                                "protocol": arg,
                                "previous_protocol": seen_proto_version,
                            }
                        )
                    seen_proto_version = int(arg) if isinstance(arg, int) else None

                if opcode.name == "STOP":
                    stream_had_stop = True
                    offset = absolute_pos + 1
                    break
        except ValueError:
            # Do not emit standalone invalid-opcode findings here. Legitimate
            # pickle-adjacent formats can contain binary tails or protocol/
            # opcode mismatches that trigger parser errors after a valid
            # prefix, and surfacing those as tamper findings is too noisy.
            # Instead, resync to the next likely binary pickle stream and
            # continue looking for true structural violations.
            probe_start = min(offset + 1, len(file_data))
            probe_end = min(offset + _RESYNC_BUDGET, len(file_data))
            next_offset = -1
            for idx in range(probe_start, probe_end - 1):
                if file_data[idx] == 0x80 and file_data[idx + 1] in (2, 3, 4, 5):
                    next_offset = idx
                    break

            if next_offset >= 0:
                offset = next_offset
                continue

            # If there is no next stream candidate, treat remaining bytes as non-pickle tail.
            break
        except Exception:
            # Structural tamper detection is opportunistic and must not change
            # the scanner's existing error-handling behavior for parse limits
            # or framework-specific edge cases.
            break

        if stream_had_stop:
            skipped = 0
            while offset < len(file_data) and skipped < max_separator_skip:
                if file_data[offset] == 0x80 and offset + 1 < len(file_data) and file_data[offset + 1] in (2, 3, 4, 5):
                    break
                offset += 1
                skipped += 1
            if skipped >= max_separator_skip and offset < len(file_data):
                break
            continue

        # No STOP and no exception means empty parse; advance to avoid infinite loop.
        offset += 1

    return findings


def _genops_with_fallback(
    file_obj: BinaryIO,
    *,
    multi_stream: bool = False,
    max_items: int | None = None,
    deadline: float | None = None,
) -> Any:
    """
    Wrapper around pickletools.genops that handles protocol mismatches.

    Some files (especially joblib) may declare protocol 4 but use protocol 5 opcodes
    like READONLY_BUFFER (0x0f). This function attempts to parse as much as possible
    before hitting unknown opcodes, then tries to resync and continue scanning
    rather than terminating on partial stream errors.

    When *multi_stream* is True the generator continues parsing after the first STOP
    opcode so that malicious payloads hidden in a second pickle stream are not missed.
    Non-pickle separator bytes between streams are skipped (up to a limit) so that a
    single junk byte cannot bypass detection.

    Yields: (opcode, arg, pos) tuples from pickletools.genops
    """
    # Maximum number of consecutive non-pickle bytes to skip when resyncing
    _MAX_RESYNC_BYTES = 256
    resync_skipped = 0
    # Track whether we've successfully parsed at least one complete stream
    parsed_any_stream = False
    yielded_items = 0

    def _check_budget(*, pending_items: int = 0) -> None:
        if max_items is not None and (yielded_items + pending_items) >= max_items:
            raise _GenopsBudgetExceeded("max_items")
        if deadline is not None and time.time() > deadline:
            raise _GenopsBudgetExceeded("deadline")

    while True:
        stream_start = file_obj.tell()
        had_opcodes = False
        stream_error = False

        if not parsed_any_stream:
            # First stream: yield opcodes directly (no buffering needed)
            try:
                op_iter = pickletools.genops(file_obj)
                while True:
                    _check_budget()
                    try:
                        item = next(op_iter)
                    except StopIteration:
                        break
                    had_opcodes = True
                    yield item
                    yielded_items += 1
            except ValueError as e:
                error_str = str(e).lower()
                is_unknown_opcode = "opcode" in error_str and "unknown" in error_str
                is_decode_or_text_error = (
                    isinstance(e, UnicodeDecodeError)
                    or "unicode" in error_str
                    or "codec can't decode" in error_str
                    or "no newline found" in error_str
                )

                if is_unknown_opcode or is_decode_or_text_error:
                    if had_opcodes:
                        logger.info(
                            "Pickle stream parsing interrupted after partial opcode extraction; "
                            "continuing with partial security analysis"
                        )
                        stream_error = True
                    elif is_unknown_opcode:
                        # Keep prior behavior for joblib-style protocol/opcode mismatches.
                        logger.info(
                            f"Protocol mismatch in pickle (joblib may use protocol 5 opcodes in protocol 4 files): {e}"
                        )
                    else:
                        # No opcodes were parsed; allow outer error handling to report
                        # malformed payloads instead of silently treating as empty.
                        raise
                else:
                    raise
        else:
            # Subsequent streams: buffer opcodes so that partial streams
            # (e.g. binary tensor data misinterpreted as opcodes) don't
            # produce false positives.
            buffered: list[Any] = []
            try:
                op_iter = pickletools.genops(file_obj)
                while True:
                    # Do not emit buffered follow-on stream opcodes until the
                    # stream has completed successfully. If the budget expires
                    # here, let the caller surface the analysis truncation.
                    _check_budget(pending_items=len(buffered))
                    try:
                        item = next(op_iter)
                    except StopIteration:
                        break
                    had_opcodes = True
                    buffered.append(item)
            except ValueError:
                # Any ValueError on a subsequent stream means we hit
                # non-pickle data or a junk separator byte.
                stream_error = True

            if stream_error and had_opcodes:
                # Partial stream: binary data was misinterpreted as opcodes.
                # Discard the buffer but keep scanning — a valid malicious
                # stream may follow.
                if multi_stream:
                    continue
                return

            if not stream_error:
                # Stream completed successfully — yield buffered opcodes
                for buffered_item in buffered:
                    _check_budget()
                    yield buffered_item
                    yielded_items += 1

        if stream_error and had_opcodes:
            # First stream parse interruption after yielding some opcodes.
            if multi_stream:
                # Mark as parsed so subsequent streams are buffered, and
                # keep scanning — a malicious payload may follow.
                parsed_any_stream = True
                continue
            # Single-stream mode: return the parsed prefix for security analysis.
            return

        if not multi_stream:
            return

        if had_opcodes and not stream_error:
            parsed_any_stream = True

        if not had_opcodes:
            # Resync: the current byte was not a valid pickle start.
            # Skip one byte and keep searching for the next stream, up to a limit.
            file_obj.seek(stream_start, 0)
            if not file_obj.read(1):
                return  # EOF
            resync_skipped += 1
            if resync_skipped >= _MAX_RESYNC_BYTES:
                # Fast-forward search for the next likely protocol header so
                # large padding blocks cannot terminate multi-stream scanning.
                previous_tail = b""
                while True:
                    _check_budget()
                    probe_start = file_obj.tell()
                    probe = file_obj.read(64 * 1024)
                    if not probe:
                        return
                    search_window = previous_tail + probe
                    candidate = next(
                        (
                            idx
                            for idx in range(len(search_window) - 1)
                            if search_window[idx] == 0x80 and search_window[idx + 1] in (2, 3, 4, 5)
                        ),
                        -1,
                    )
                    if candidate >= 0:
                        file_obj.seek(probe_start - len(previous_tail) + candidate, 0)
                        resync_skipped = 0
                        break
                    previous_tail = probe[-1:]
            continue

        # Found a valid stream — reset resync counter
        resync_skipped = 0
        # Check if there is another pickle stream after STOP
        next_byte = file_obj.read(1)
        if not next_byte:
            return  # EOF
        file_obj.seek(-1, 1)  # put the byte back for the next genops call


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
# ML CONTEXT FILTERING SYSTEM
# ============================================================================

# ML Framework Detection Patterns
ML_FRAMEWORK_PATTERNS: dict[str, dict[str, list[str] | float]] = {
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
        "modules": ["sklearn", "joblib", "numpy", "numpy.core", "numpy._core", "numpy.dtype", "scipy.sparse"],
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
        "patterns": [
            r"sklearn\..*",
            r"joblib\..*",
            r"numpy\..*",
            r"numpy\.core\..*",
            r"numpy\._core\..*",
            r"scipy\.sparse\..*",
        ],
        "confidence_boost": 0.9,
    },
    "huggingface": {
        "modules": ["transformers", "tokenizers"],
        "classes": ["AutoModel", "AutoTokenizer", "BertModel", "GPT2Model"],
        "patterns": [r"transformers\..*", r"tokenizers\..*"],
        "confidence_boost": 0.8,
    },
    "xgboost": {
        "modules": ["xgboost", "xgboost.core", "xgboost.sklearn"],
        "classes": [
            "Booster",
            "DMatrix",
            "XGBClassifier",
            "XGBRegressor",
            "XGBRanker",
            "XGBRFClassifier",
            "XGBRFRegressor",
        ],
        "patterns": [r"xgboost\..*"],
        "confidence_boost": 0.9,
    },
}

# SECURITY: ALWAYS flag these as dangerous, regardless of ML context
# These functions can execute arbitrary code and should NEVER be whitelisted
# Based on Fickling analysis and security best practices
ALWAYS_DANGEROUS_FUNCTIONS: set[str] = {
    # System commands
    "os.system",
    "os.popen",
    "os.popen2",
    "os.popen3",
    "os.popen4",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawn",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    # Subprocess
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.run",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    # Code execution
    "eval",
    "exec",
    "compile",
    "__import__",
    "importlib.import_module",
    # File operations (can be dangerous in wrong context)
    "open",
    "file",
    "io.open",
    "builtins.open",
    # Dynamic attribute access (Fickling: operator module)
    "getattr",
    "setattr",
    "delattr",
    "operator.getitem",
    "operator.attrgetter",
    "operator.itemgetter",
    "operator.methodcaller",
    # Code objects
    "code",
    "types.CodeType",
    "types.FunctionType",
    # Other dangerous operations
    "pickle.loads",
    "pickle.load",
    "joblib.load",
    "joblib._pickle_load",
    "marshal.loads",
    "marshal.load",
    # Torch dangerous functions (Fickling)
    "torch.load",
    "torch.hub.load",
    "torch.hub.load_state_dict_from_url",
    "torch.storage._load_from_bytes",
    # CVE-2024-5480 / CVE-2024-48063: PyTorch RPC functions
    "torch.distributed.rpc.rpc_sync",
    "torch.distributed.rpc.rpc_async",
    "torch.distributed.rpc.remote",
    "torch.distributed.rpc.RemoteModule",
    # NumPy dangerous functions (Fickling)
    "numpy.testing._private.utils.runstring",
    "numpy.load",
    # pip as callable (CVE-2025-1716: picklescan bypass via pip.main)
    "pip.main",
    "pip._internal.main",
    "pip._internal.cli.main.main",
    "pip._vendor.distlib.scripts.ScriptMaker",
    # Shell utilities
    "shutil.rmtree",
    "shutil.move",
    "shutil.copy",
    "shutil.copytree",
    # Dynamic resolution trampolines (can resolve arbitrary callables)
    "pkgutil.resolve_name",
    # uuid internal functions that call subprocess.Popen
    "uuid._get_command_stdout",
    "uuid._popen",
    # Profiling/debugging modules that execute arbitrary Python code
    "cProfile.run",
    "cProfile.runctx",
    "profile.run",
    "profile.runctx",
    "pdb.run",
    "pdb.runeval",
    "pdb.runcall",
    "pdb.runctx",
    "timeit.timeit",
    "timeit.repeat",
    # Native code execution
    "ctypes.CDLL",
    "ctypes.WinDLL",
    "ctypes.OleDLL",
    "ctypes.PyDLL",
    "ctypes.cdll",
    "ctypes.windll",
    "ctypes.oledll",
    "ctypes.pydll",
    "ctypes.pythonapi",
    "ctypes.cast",
    "ctypes.CFUNCTYPE",
    "ctypes.WINFUNCTYPE",
    # Expanded exact dangerous primitives validated against PickleScan
    "site.main",
    "_io.FileIO",
    "test.support.script_helper.assert_python_ok",
    "_osx_support._read_output",
    "_aix_support._read_cmd_output",
    "_pyrepl.pager.pipe_pager",
    "torch.serialization.load",
    "torch._inductor.codecache.compile_file",
}

# Module prefixes that are always dangerous (Fickling-based + additional)
# This must be a superset of fickling's 68-module blocklist (PR #215)
ALWAYS_DANGEROUS_MODULES: set[str] = {
    # Original modules
    "__builtin__",
    "__builtins__",
    "builtins",
    "os",
    "posix",
    "nt",
    "subprocess",
    "sys",
    "socket",
    "urllib",
    "urllib2",
    "http",
    "httplib",
    "ftplib",
    "telnetlib",
    "pty",
    "commands",
    "shutil",
    "code",
    "torch.hub",
    # Native code execution (ctypes)
    "ctypes",
    "ctypes.util",
    "_ctypes",
    # Profiling/debugging - can execute arbitrary Python code via run()
    "cProfile",
    "profile",
    "pdb",
    "timeit",
    "bdb",
    "trace",
    # Thread/process spawning
    "_thread",
    "multiprocessing",
    "signal",
    "_signal",
    "threading",
    # Package manager as callable (CVE-2025-1716: picklescan bypass)
    "pip",
    "pip._internal",
    "pip._internal.cli",
    "pip._internal.cli.main",
    "pip._vendor",
    "pip._vendor.distlib",
    "pip._vendor.distlib.scripts",
    # Module loading from untrusted sources
    "zipimport",
    "importlib",
    "runpy",
    # Dynamic resolution / import trampolines
    "pkgutil",
    # Network / exfiltration
    "smtplib",
    "imaplib",
    "poplib",
    "nntplib",
    "xmlrpc",
    "socketserver",
    "ssl",
    "requests",
    "aiohttp",
    # Code execution / compilation
    "codeop",
    "marshal",
    "types",
    "compileall",
    "py_compile",
    # Operator / functools bypasses
    "_operator",
    "functools",
    # Pickle recursion
    "pickle",
    "_pickle",
    "dill",
    "cloudpickle",
    "joblib",
    # Filesystem / shell
    "tempfile",
    "filecmp",
    "fileinput",
    "glob",
    "distutils",
    "pydoc",
    "pexpect",
    # Virtual environments / package install
    "venv",
    "ensurepip",
    # Other dangerous
    "webbrowser",
    "asyncio",
    "mmap",
    "select",
    "selectors",
    "logging",
    "syslog",
    "tarfile",
    "zipfile",
    "shelve",
    "sqlite3",
    "_sqlite3",
    "doctest",
    "idlelib",
    "lib2to3",
    # uuid — _get_command_stdout internally calls subprocess.Popen
    "uuid",
    # NOTE: linecache and logging.config are intentionally NOT in this set.
    # - linecache.getline: file read (not code execution), flagged as WARNING
}

# Modules that are suspicious but should only be flagged at WARNING severity.
# These modules appear frequently in legitimate ML pipelines and cannot directly
# execute arbitrary code, so CRITICAL would cause too many false positives.
WARNING_SEVERITY_MODULES: dict[str, set[str] | None] = {
    # functools.partial/partialmethod are heavily used in PyTorch models and
    # should remain WARNING-level noise reducers. functools.reduce is excluded
    # so reduce-driven execution chains stay CRITICAL.
    "functools": {"partial", "partialmethod"},
    # glob.glob / glob.iglob are common in dataset loading pipelines and
    # cannot directly execute code.
    "glob": None,
}

# Risky ML-specific import surfaces that must be flagged even when they appear
# as import-only GLOBAL/STACK_GLOBAL references (without immediate REDUCE).
RISKY_ML_MODULE_PREFIXES: tuple[str, ...] = (
    "torch.jit",
    "torch._dynamo",
    "torch._inductor",
    "numpy.f2py",
    "numpy.distutils",
)

RISKY_ML_EXACT_REFS: set[tuple[str, str]] = {
    ("torch", "compile"),
    ("torch.storage", "_load_from_bytes"),
}
RISKY_ML_EXACT_FULL_REFS: frozenset[str] = frozenset(f"{module}.{name}" for module, name in RISKY_ML_EXACT_REFS)


def _split_parent_child_ref(prefix: str) -> tuple[str, str]:
    parent, _separator, child = prefix.rpartition(".")
    return parent, child


RISKY_ML_PARENT_CHILD_REFS: frozenset[tuple[str, str]] = frozenset(
    _split_parent_child_ref(prefix) for prefix in RISKY_ML_MODULE_PREFIXES
)


def _is_dangerous_module(mod: str) -> bool:
    """Check if module is in ALWAYS_DANGEROUS_MODULES (exact or prefix match).

    Prefix matching ensures deeper sub-modules like pip._internal.cli.main_parser
    are still caught when their parent (pip) is in the blocklist.
    """
    if mod in ALWAYS_DANGEROUS_MODULES:
        return True
    return any(mod.startswith(f"{m}.") for m in ALWAYS_DANGEROUS_MODULES)


# String opcodes that push text onto the pickle stack.
# Used for STACK_GLOBAL reconstruction and suspicious string detection.
STRING_OPCODES: frozenset[str] = frozenset(
    {
        "STRING",
        "BINSTRING",
        "SHORT_BINSTRING",
        "UNICODE",
        "SHORT_BINUNICODE",
        "BINUNICODE",
        "BINUNICODE8",
    }
)

# Safe ML-specific global patterns (SECURITY: NO WILDCARDS - explicit lists only)
ML_SAFE_GLOBALS: dict[str, list[str]] = {
    # PyTorch - explicit functions only (no wildcards)
    "torch": [
        "Tensor",
        "FloatTensor",
        "LongTensor",
        "IntTensor",
        "DoubleTensor",
        "HalfTensor",
        "BFloat16Tensor",
        "ByteTensor",
        "CharTensor",
        "ShortTensor",
        "BoolTensor",
        # Storage types (used in PyTorch serialization)
        "FloatStorage",
        "LongStorage",
        "IntStorage",
        "DoubleStorage",
        "HalfStorage",
        "BFloat16Storage",
        "ByteStorage",
        "CharStorage",
        "ShortStorage",
        "BoolStorage",
        "Size",
        "device",
        "dtype",
        "storage",
        "_utils",
        "nn",
        "optim",
        "jit",
        "cuda",
        "distributed",
        "multiprocessing",
        "autograd",
        "save",
        "load",
        "no_grad",
        "enable_grad",
        "set_grad_enabled",
        "inference_mode",
        # PyTorch dtypes (safe built-in types)
        "bfloat16",
    ],
    "torch.nn": [
        "Module",
        "Parameter",
        "Linear",
        "Conv1d",
        "Conv2d",
        "Conv3d",
        "ConvTranspose1d",
        "ConvTranspose2d",
        "ConvTranspose3d",
        "BatchNorm1d",
        "BatchNorm2d",
        "BatchNorm3d",
        "GroupNorm",
        "LayerNorm",
        "InstanceNorm1d",
        "InstanceNorm2d",
        "InstanceNorm3d",
        "ReLU",
        "LeakyReLU",
        "PReLU",
        "ELU",
        "GELU",
        "Sigmoid",
        "Tanh",
        "Softmax",
        "LogSoftmax",
        "Dropout",
        "Dropout2d",
        "Dropout3d",
        "MaxPool1d",
        "MaxPool2d",
        "MaxPool3d",
        "AvgPool1d",
        "AvgPool2d",
        "AvgPool3d",
        "AdaptiveMaxPool1d",
        "AdaptiveMaxPool2d",
        "AdaptiveMaxPool3d",
        "AdaptiveAvgPool1d",
        "AdaptiveAvgPool2d",
        "AdaptiveAvgPool3d",
        "Sequential",
        "ModuleList",
        "ModuleDict",
        "ParameterList",
        "ParameterDict",
        "functional",
        "Embedding",
        "EmbeddingBag",
        "RNN",
        "LSTM",
        "GRU",
        "Transformer",
        "TransformerEncoder",
        "TransformerDecoder",
        "MultiheadAttention",
    ],
    "torch.optim": [
        "Adam",
        "AdamW",
        "SGD",
        "RMSprop",
        "Adagrad",
        "Adadelta",
        "Adamax",
        "ASGD",
        "LBFGS",
        "Optimizer",
    ],
    "torch.utils": [
        "data",
        "checkpoint",
        "tensorboard",
    ],
    "torch.utils.data": [
        "Dataset",
        "DataLoader",
        "TensorDataset",
        "ConcatDataset",
        "Subset",
        "random_split",
    ],
    "torch.nn.functional": [
        "relu",
    ],
    # torch._utils - internal PyTorch utilities used in serialization
    "torch._utils": [
        "_rebuild_tensor",
        "_rebuild_tensor_v2",
        "_rebuild_parameter",
        "_rebuild_parameter_v2",
        "_rebuild_device_tensor_from_numpy",
        "_rebuild_qtensor",
        "_rebuild_sparse_tensor",
    ],
    # Python builtins - safe built-in types and functions
    # NOTE: eval, exec, compile, __import__, open, file are NOT in this list (they remain dangerous)
    # NOTE: getattr, setattr, delattr, hasattr are NOT in this list
    # because attribute-access primitives must never be allowlisted.
    "__builtin__": [  # Python 2 builtins
        "set",
        "frozenset",
        "dict",
        "list",
        "tuple",
        "int",
        "float",
        "str",
        "bytes",
        "bytearray",
        "bool",
        "object",
        "type",
        "range",
        "slice",
        "enumerate",
        "zip",
        "map",
        "filter",
        "reversed",
        "sorted",
        "len",
        "min",
        "max",
        "sum",
        "abs",
        "round",
        "divmod",
        "pow",
        "hash",
        "id",
        "isinstance",
        "issubclass",
        "callable",
        "repr",
        "ascii",
        "bin",
        "hex",
        "oct",
        "chr",
        "ord",
        "all",
        "any",
        "iter",
        "next",
        # Python 2 type names used by frameworks like fastai during serialization
        "long",
        "unicode",
        "print",
        "basestring",
        "xrange",
        "complex",
        "memoryview",
        "property",
        "staticmethod",
        "classmethod",
        "super",
    ],
    "builtins": [  # Python 3 builtins
        "set",
        "frozenset",
        "dict",
        "list",
        "tuple",
        "int",
        "float",
        "str",
        "bytes",
        "bytearray",
        "bool",
        "object",
        "type",
        "range",
        "slice",
        "enumerate",
        "zip",
        "map",
        "filter",
        "reversed",
        "sorted",
        "len",
        "min",
        "max",
        "sum",
        "abs",
        "round",
        "divmod",
        "pow",
        "hash",
        "id",
        "isinstance",
        "issubclass",
        "callable",
        "repr",
        "ascii",
        "bin",
        "hex",
        "oct",
        "chr",
        "ord",
        "all",
        "any",
        "iter",
        "next",
    ],
    "collections": ["OrderedDict", "defaultdict", "namedtuple", "Counter", "deque"],
    # _codecs is used by NumPy/PyTorch for binary data serialization (e.g., RNG states)
    # encode() only transforms string encodings, it cannot execute code
    "_codecs": ["encode"],
    "typing": [
        "Any",
        "Union",
        "Optional",
        "List",
        "Dict",
        "Tuple",
        "Set",
        "Callable",
    ],
    "numpy": [
        "ndarray",
        "array",
        "zeros",
        "ones",
        "empty",
        "arange",
        "linspace",
        "dtype",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "float16",
        "float32",
        "float64",
        "complex64",
        "complex128",
        "bool_",
    ],
    "numpy.core": [
        "multiarray",
        "numeric",
        "_internal",
    ],
    "numpy.core.multiarray": [
        "_reconstruct",
        "scalar",
    ],
    "numpy.core.numeric": [
        "_frombuffer",
    ],
    # numpy._core is the internal path used in NumPy 2.x+
    "numpy._core": [
        "multiarray",
        "numeric",
        "_internal",
    ],
    "numpy._core.multiarray": [
        "_reconstruct",
        "scalar",
    ],
    "numpy._core.numeric": [
        "_frombuffer",
    ],
    "numpy.random._pickle": [
        "__randomstate_ctor",
        "__generator_ctor",
        "__bit_generator_ctor",
    ],
    "numpy.random.mtrand": [
        "RandomState",
    ],
    "numpy.random._common": [
        "BitGenerator",
    ],
    "numpy.random._generator": [
        "Generator",
    ],
    "numpy.random._bounded_integers": [
        "_bounded_integers",
    ],
    "numpy.random._mt19937": [
        "MT19937",
    ],
    # SciPy sparse matrix types — common in sklearn TF-IDF / NLP pipelines
    "scipy.sparse": [
        "csr_matrix",
        "csc_matrix",
        "coo_matrix",
        "lil_matrix",
        "bsr_matrix",
        "dia_matrix",
        "dok_matrix",
        "csr_array",
        "csc_array",
        "coo_array",
    ],
    "scipy.sparse._csr": [
        "csr_matrix",
        "csr_array",
    ],
    "scipy.sparse._csc": [
        "csc_matrix",
        "csc_array",
    ],
    "scipy.sparse._coo": [
        "coo_matrix",
        "coo_array",
    ],
    "scipy.sparse._bsr": ["bsr_matrix", "bsr_array"],
    "scipy.sparse._dia": ["dia_matrix", "dia_array"],
    "scipy.sparse._lil": ["lil_matrix", "lil_array"],
    "scipy.sparse._dok": ["dok_matrix", "dok_array"],
    "math": [
        "sqrt",
        "pow",
        "exp",
        "log",
        "sin",
        "cos",
        "tan",
        "pi",
        "e",
    ],
    # NOTE: operator module (methodcaller, itemgetter, attrgetter, getitem) is
    # intentionally NOT allowlisted here.  These functions are in
    # ALWAYS_DANGEROUS_FUNCTIONS because they enable dynamic attribute access
    # and arbitrary method invocation -- a well-known pickle deserialization
    # attack vector (see Fickling research).  Even in ML contexts, they must
    # remain flagged to prevent bypasses.
    # Truncated numpy module references from pickle opcode resolution.
    # The pickle scanner sometimes resolves module names incompletely
    # (e.g., "_reconstruct" instead of "numpy.core.multiarray._reconstruct").
    #
    # SECURITY NOTE: These short/generic module names carry bypass risk -- an
    # attacker could craft a pickle with a custom module named "C" that exports
    # "dtype".  We accept this risk because:
    #   1. These only skip the SUSPICIOUS_GLOBAL check; ALWAYS_DANGEROUS still fires.
    #   2. The function names are narrow and specific to numpy internals.
    #   3. Removing them causes widespread FPs on legitimate sklearn/joblib models.
    "_reconstruct": ["ndarray", "scalar"],
    "C": ["dtype", "ndarray", "scalar"],
    "multiarray": ["_reconstruct", "scalar"],
    "numpy_pickle": ["NumpyArrayWrapper", "NDArrayWrapper"],
    # Truncated sklearn class names from joblib opcode resolution.
    # When joblib serializes sklearn objects it sometimes resolves class names
    # without the full module path, e.g. "LabelEncoder" instead of
    # "sklearn.preprocessing._label.LabelEncoder".
    "LabelEncoder": ["dtype"],
    "OrdinalEncoder": ["dtype"],
    "OneHotEncoder": ["dtype"],
    "MT19937": ["__bit_generator_ctor"],
    # Old-style scipy paths (without underscore, used in older scipy versions)
    "scipy.sparse.csr": ["csr_matrix", "csr_array"],
    "scipy.sparse.csc": ["csc_matrix", "csc_array"],
    "scipy.sparse.coo": ["coo_matrix", "coo_array"],
    "scipy.sparse.bsr": ["bsr_matrix", "bsr_array"],
    "scipy.sparse.dia": ["dia_matrix", "dia_array"],
    "scipy.sparse.lil": ["lil_matrix", "lil_array"],
    "scipy.sparse.dok": ["dok_matrix", "dok_array"],
    # YOLO/Ultralytics safe patterns
    "ultralytics": [
        "YOLO",
        "NAS",
        "SAM",
        "RTDETR",
        "FastSAM",
        "utils",
        "nn",
    ],
    "yolo": [
        "v5",
        "v8",
        "Detect",
        "Segment",
        "Classify",
    ],
    # Standard ML libraries - sklearn
    # SECURITY: Use exact module.function matching (no prefix wildcards)
    # Each submodule must list specific safe classes/functions to prevent
    # arbitrary function execution under allowed prefixes.
    "sklearn.base": [
        "BaseEstimator",
        "ClassifierMixin",
        "RegressorMixin",
        "TransformerMixin",
        "ClusterMixin",
        "BiclusterMixin",
        "DensityMixin",
        "OutlierMixin",
        "MetaEstimatorMixin",
        "MultiOutputMixin",
        "_clone_parametrized",
    ],
    "sklearn.ensemble": [
        "RandomForestClassifier",
        "RandomForestRegressor",
        "GradientBoostingClassifier",
        "GradientBoostingRegressor",
        "AdaBoostClassifier",
        "AdaBoostRegressor",
        "BaggingClassifier",
        "BaggingRegressor",
        "ExtraTreesClassifier",
        "ExtraTreesRegressor",
        "VotingClassifier",
        "VotingRegressor",
        "StackingClassifier",
        "StackingRegressor",
        "IsolationForest",
        "HistGradientBoostingClassifier",
        "HistGradientBoostingRegressor",
    ],
    "sklearn.ensemble._forest": [
        "RandomForestClassifier",
        "RandomForestRegressor",
        "ExtraTreesClassifier",
        "ExtraTreesRegressor",
    ],
    "sklearn.ensemble._gb": [
        "GradientBoostingClassifier",
        "GradientBoostingRegressor",
    ],
    "sklearn.ensemble._weight_boosting": [
        "AdaBoostClassifier",
        "AdaBoostRegressor",
    ],
    "sklearn.ensemble._bagging": [
        "BaggingClassifier",
        "BaggingRegressor",
    ],
    "sklearn.ensemble._voting": [
        "VotingClassifier",
        "VotingRegressor",
    ],
    "sklearn.ensemble._stacking": [
        "StackingClassifier",
        "StackingRegressor",
    ],
    "sklearn.ensemble._iforest": [
        "IsolationForest",
    ],
    "sklearn.ensemble._hist_gradient_boosting.gradient_boosting": [
        "HistGradientBoostingClassifier",
        "HistGradientBoostingRegressor",
    ],
    "sklearn.ensemble._hist_gradient_boosting.binning": [
        "_BinMapper",
    ],
    "sklearn.ensemble._hist_gradient_boosting.predictor": [
        "TreePredictor",
    ],
    "sklearn.ensemble._hist_gradient_boosting._predictor": [
        "TreePredictor",
    ],
    "sklearn.ensemble._hist_gradient_boosting.grower": [
        "TreeGrower",
        "TreeNode",
    ],
    "sklearn.ensemble._hist_gradient_boosting.splitting": [
        "Splitter",
        "SplitInfo",
    ],
    "sklearn.ensemble._hist_gradient_boosting.common": [
        "MonotonicConstraint",
        "X_DTYPE",
        "X_BINNED_DTYPE",
        "Y_DTYPE",
        "G_H_DTYPE",
        "X_BITSET_INNER_DTYPE",
    ],
    "sklearn.linear_model": [
        "LinearRegression",
        "LogisticRegression",
        "Ridge",
        "Lasso",
        "ElasticNet",
        "SGDClassifier",
        "SGDRegressor",
        "Perceptron",
        "PassiveAggressiveClassifier",
        "PassiveAggressiveRegressor",
        "BayesianRidge",
        "ARDRegression",
        "Lars",
        "LassoLars",
        "OrthogonalMatchingPursuit",
        "HuberRegressor",
        "RANSACRegressor",
        "TheilSenRegressor",
    ],
    "sklearn.linear_model._logistic": [
        "LogisticRegression",
    ],
    "sklearn.linear_model._base": [
        "LinearRegression",
    ],
    "sklearn.linear_model._ridge": [
        "Ridge",
        "RidgeClassifier",
    ],
    "sklearn.linear_model._coordinate_descent": [
        "Lasso",
        "ElasticNet",
    ],
    "sklearn.linear_model._stochastic_gradient": [
        "SGDClassifier",
        "SGDRegressor",
    ],
    "sklearn.tree": [
        "DecisionTreeClassifier",
        "DecisionTreeRegressor",
        "ExtraTreeClassifier",
        "ExtraTreeRegressor",
    ],
    "sklearn.tree._classes": [
        "DecisionTreeClassifier",
        "DecisionTreeRegressor",
        "ExtraTreeClassifier",
        "ExtraTreeRegressor",
    ],
    "sklearn.tree._tree": [
        "Tree",
    ],
    "sklearn.svm": [
        "SVC",
        "SVR",
        "LinearSVC",
        "LinearSVR",
        "NuSVC",
        "NuSVR",
        "OneClassSVM",
    ],
    "sklearn.svm._classes": [
        "SVC",
        "SVR",
        "LinearSVC",
        "LinearSVR",
        "NuSVC",
        "NuSVR",
        "OneClassSVM",
    ],
    "sklearn.neighbors": [
        "KNeighborsClassifier",
        "KNeighborsRegressor",
        "RadiusNeighborsClassifier",
        "RadiusNeighborsRegressor",
        "NearestNeighbors",
        "NearestCentroid",
        "LocalOutlierFactor",
        "KernelDensity",
    ],
    "sklearn.neighbors._classification": [
        "KNeighborsClassifier",
        "RadiusNeighborsClassifier",
    ],
    "sklearn.neighbors._regression": [
        "KNeighborsRegressor",
        "RadiusNeighborsRegressor",
    ],
    "sklearn.neighbors._unsupervised": [
        "NearestNeighbors",
    ],
    "sklearn.neighbors._kde": [
        "KernelDensity",
    ],
    "sklearn.neighbors._lof": [
        "LocalOutlierFactor",
    ],
    "sklearn.cluster": [
        "KMeans",
        "MiniBatchKMeans",
        "AgglomerativeClustering",
        "DBSCAN",
        "OPTICS",
        "SpectralClustering",
        "Birch",
        "MeanShift",
        "AffinityPropagation",
    ],
    "sklearn.cluster._kmeans": [
        "KMeans",
        "MiniBatchKMeans",
    ],
    "sklearn.cluster._agglomerative": [
        "AgglomerativeClustering",
    ],
    "sklearn.cluster._dbscan": [
        "DBSCAN",
    ],
    "sklearn.cluster._optics": [
        "OPTICS",
    ],
    "sklearn.decomposition": [
        "PCA",
        "IncrementalPCA",
        "KernelPCA",
        "TruncatedSVD",
        "NMF",
        "LatentDirichletAllocation",
        "FastICA",
    ],
    "sklearn.decomposition._pca": [
        "PCA",
    ],
    "sklearn.decomposition._incremental_pca": [
        "IncrementalPCA",
    ],
    "sklearn.decomposition._truncated_svd": [
        "TruncatedSVD",
    ],
    "sklearn.decomposition._nmf": [
        "NMF",
    ],
    "sklearn.preprocessing": [
        "StandardScaler",
        "MinMaxScaler",
        "MaxAbsScaler",
        "RobustScaler",
        "Normalizer",
        "Binarizer",
        "LabelEncoder",
        "LabelBinarizer",
        "OneHotEncoder",
        "OrdinalEncoder",
        "PolynomialFeatures",
        "PowerTransformer",
        "QuantileTransformer",
        "FunctionTransformer",
        "KBinsDiscretizer",
        "SplineTransformer",
    ],
    "sklearn.preprocessing._data": [
        "StandardScaler",
        "MinMaxScaler",
        "MaxAbsScaler",
        "RobustScaler",
        "Normalizer",
        "Binarizer",
        "PolynomialFeatures",
        "PowerTransformer",
        "QuantileTransformer",
        "KBinsDiscretizer",
        "SplineTransformer",
    ],
    "sklearn.preprocessing._label": [
        "LabelEncoder",
        "LabelBinarizer",
    ],
    "sklearn.preprocessing._encoders": [
        "OneHotEncoder",
        "OrdinalEncoder",
    ],
    "sklearn.preprocessing._function_transformer": [
        "FunctionTransformer",
    ],
    "sklearn.pipeline": [
        "Pipeline",
        "FeatureUnion",
        "make_pipeline",
        "make_union",
    ],
    "sklearn.pipeline._pipeline": [
        "Pipeline",
        "FeatureUnion",
    ],
    "sklearn.compose": [
        "ColumnTransformer",
        "TransformedTargetRegressor",
    ],
    "sklearn.compose._column_transformer": [
        "ColumnTransformer",
        "make_column_selector",
    ],
    "sklearn.model_selection": [
        "GridSearchCV",
        "RandomizedSearchCV",
    ],
    "sklearn.model_selection._search": [
        "GridSearchCV",
        "RandomizedSearchCV",
    ],
    "sklearn.feature_extraction.text": [
        "CountVectorizer",
        "TfidfVectorizer",
        "TfidfTransformer",
        "HashingVectorizer",
    ],
    "sklearn.feature_extraction._text": [
        "CountVectorizer",
        "TfidfVectorizer",
        "TfidfTransformer",
        "HashingVectorizer",
    ],
    "sklearn.feature_extraction._dict_vectorizer": [
        "DictVectorizer",
    ],
    "sklearn.naive_bayes": [
        "GaussianNB",
        "MultinomialNB",
        "BernoulliNB",
        "ComplementNB",
    ],
    "sklearn.metrics": [
        "make_scorer",
    ],
    "sklearn.multiclass": [
        "OneVsRestClassifier",
        "OneVsOneClassifier",
    ],
    "sklearn.multioutput": [
        "MultiOutputClassifier",
        "MultiOutputRegressor",
    ],
    "sklearn.impute": [
        "SimpleImputer",
        "IterativeImputer",
        "KNNImputer",
        "MissingIndicator",
    ],
    "sklearn.impute._base": [
        "SimpleImputer",
        "MissingIndicator",
    ],
    "sklearn.impute._iterative": [
        "IterativeImputer",
    ],
    "sklearn.impute._knn": [
        "KNNImputer",
    ],
    "sklearn.dummy": [
        "DummyClassifier",
        "DummyRegressor",
    ],
    "sklearn.ensemble._gb_losses": [
        "LeastSquaresError",
        "BinomialDeviance",
        "MultinomialDeviance",
        "ExponentialLoss",
        "HuberLossFunction",
        "QuantileLossFunction",
        "LeastAbsoluteError",
    ],
    "sklearn.utils._tags": [
        "Tags",
    ],
    "sklearn.neural_network": [
        "MLPClassifier",
        "MLPRegressor",
        "BernoulliRBM",
    ],
    "sklearn.neural_network._multilayer_perceptron": [
        "MLPClassifier",
        "MLPRegressor",
    ],
    "sklearn.calibration": [
        "CalibratedClassifierCV",
    ],
    "sklearn.discriminant_analysis": [
        "LinearDiscriminantAnalysis",
        "QuadraticDiscriminantAnalysis",
    ],
    "sklearn.gaussian_process": [
        "GaussianProcessClassifier",
        "GaussianProcessRegressor",
    ],
    "sklearn.isotonic": [
        "IsotonicRegression",
    ],
    "sklearn.kernel_ridge": [
        "KernelRidge",
    ],
    "sklearn.mixture": [
        "GaussianMixture",
        "BayesianGaussianMixture",
    ],
    "sklearn.semi_supervised": [
        "LabelPropagation",
        "LabelSpreading",
        "SelfTrainingClassifier",
    ],
    # sklearn loss functions (used by HistGradientBoosting regressors)
    "sklearn._loss.loss": [
        "HalfSquaredError",
        "HalfBinomialLoss",
        "HalfMultinomialLoss",
        "HalfPoissonLoss",
        "HalfGammaLoss",
        "HalfTweedieLoss",
        "HalfTweedieLossIdentity",
        "AbsoluteError",
        "PinballLoss",
        "HuberLoss",
        "ExponentialLoss",
        "CyHalfSquaredError",
        "CyHalfBinomialLoss",
        "CyHalfMultinomialLoss",
        "CyHalfPoissonLoss",
        "CyHalfGammaLoss",
        "CyHalfTweedieLoss",
        "CyHalfTweedieLossIdentity",
        "CyAbsoluteError",
        "CyPinballLoss",
        "CyHuberLoss",
        "CyExponentialLoss",
    ],
    "sklearn._loss.link": [
        "IdentityLink",
        "LogLink",
        "LogitLink",
        "HalfLogitLink",
        "MultinomialLogit",
        "Interval",
    ],
    # Truncated _loss module name (joblib opcode resolution) + Cython unpickle functions
    "_loss": [
        "CyHalfSquaredError",
        "CyHalfBinomialLoss",
        "CyHalfMultinomialLoss",
        "CyHalfPoissonLoss",
        "CyHalfGammaLoss",
        "CyAbsoluteError",
        "CyPinballLoss",
        "CyHuberLoss",
        "CyExponentialLoss",
        "CyHalfTweedieLoss",
        "CyHalfTweedieLossIdentity",
        # Cython __pyx_unpickle_* reconstruction functions
        "__pyx_unpickle_CyHalfSquaredError",
        "__pyx_unpickle_CyHalfBinomialLoss",
        "__pyx_unpickle_CyHalfMultinomialLoss",
        "__pyx_unpickle_CyHalfPoissonLoss",
        "__pyx_unpickle_CyHalfGammaLoss",
        "__pyx_unpickle_CyAbsoluteError",
        "__pyx_unpickle_CyPinballLoss",
        "__pyx_unpickle_CyHuberLoss",
        "__pyx_unpickle_CyExponentialLoss",
        "__pyx_unpickle_CyHalfTweedieLoss",
        "__pyx_unpickle_CyHalfTweedieLossIdentity",
    ],
    # Old sklearn module paths (pre-underscore convention, used in older models)
    "sklearn.linear_model.stochastic_gradient": [
        "SGDClassifier",
        "SGDRegressor",
    ],
    # LightGBM
    "lightgbm.sklearn": [
        "LGBMClassifier",
        "LGBMRegressor",
        "LGBMRanker",
    ],
    "lightgbm.basic": [
        "Booster",
        "Dataset",
    ],
    # numpy masked arrays (used by older sklearn models)
    "numpy.ma.core": [
        "_mareconstruct",
        "MaskedArray",
        "MaskedConstant",
    ],
    "numpy.ma": [
        "core",
        "MaskedArray",
    ],
    "transformers": [
        "AutoModel",
        "AutoTokenizer",
        "PreTrainedModel",
        "PreTrainedTokenizer",
        "BertModel",
        "GPT2Model",
    ],
    "tokenizers": [
        "Tokenizer",
        "BertWordPieceTokenizer",
        "ByteLevelBPETokenizer",
    ],
    "joblib": [
        "dump",
        "Parallel",
        "delayed",
        "Memory",
        "hash",
        "_pickle_dump",
    ],
    "joblib.numpy_pickle": [
        "NumpyArrayWrapper",
        "NDArrayWrapper",
        "ZNDArrayWrapper",
        "read_array",
        "write_array",
    ],
    "dtype": [
        "dtype",  # numpy.dtype().dtype pattern
    ],
    # dill.load/dill.loads recursively deserialize attacker-controlled byte streams
    # and must be treated as dangerous pickle entry points.
    "dill": ["dump", "dumps", "copy"],
    "tensorflow": [
        "Tensor",
        "Variable",
        "constant",
        "keras",
        "nn",
        "function",
        "Module",
    ],
    "keras": [
        "Model",
        "Sequential",
        "layers",
        "optimizers",
        "losses",
        "metrics",
    ],
    # XGBoost safe patterns
    "xgboost": [
        "Booster",
        "DMatrix",
        "XGBClassifier",
        "XGBRegressor",
        "XGBRanker",
        "XGBRFClassifier",
        "XGBRFRegressor",
        "train",
        "cv",
        "plot_importance",
        "plot_tree",
    ],
    "xgboost.core": [
        "Booster",
        "DMatrix",
        "DataIter",
    ],
    "xgboost.sklearn": [
        "XGBClassifier",
        "XGBRegressor",
        "XGBRanker",
        "XGBRFClassifier",
        "XGBRFRegressor",
    ],
    # HuggingFace Transformers - Training utilities (Enums and config classes)
    "transformers.trainer_utils": [
        "HubStrategy",  # Enum for hub push strategy
        "SchedulerType",  # Enum for learning rate schedulers
        "IntervalStrategy",  # Enum for save/eval intervals
    ],
    "transformers.training_args": [
        "OptimizerNames",  # Enum for optimizer selection
    ],
    "transformers.integrations.deepspeed": [
        "HfDeepSpeedConfig",  # DeepSpeed config wrapper
        "HfTrainerDeepSpeedConfig",  # Trainer-specific DeepSpeed config
    ],
    "transformers.trainer_pt_utils": [
        "AcceleratorConfig",  # Dataclass for accelerator configuration
    ],
    # HuggingFace Accelerate - Distributed training utilities
    "accelerate.utils.dataclasses": [
        "DistributedType",  # Enum for distributed training types
        "DeepSpeedPlugin",  # Dataclass for DeepSpeed plugin config
    ],
    "accelerate.state": [
        "PartialState",  # Singleton class for distributed state
    ],
    # Alignment/TRL - Training config classes
    "alignment.configs": [
        "DPOConfig",  # Dataclass for DPO training configuration
    ],
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


def _detect_ml_context(
    opcodes: list[tuple],
    stack_global_refs: dict[int, tuple[str, str]] | None = None,
) -> dict[str, Any]:
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

    # Analyze GLOBAL and STACK_GLOBAL opcodes for ML patterns. STACK_GLOBAL
    # refs come from symbolic stack resolution so POP/STOP/memo behavior is
    # respected and decoy strings cannot skew confidence gating.
    global_refs: dict[str, int] = {}
    resolved_stack_globals = stack_global_refs if stack_global_refs is not None else {}
    if stack_global_refs is None and any(opcode.name == "STACK_GLOBAL" for opcode, _arg, _pos in opcodes):
        resolved_stack_globals = _build_symbolic_reference_maps(opcodes)[0]

    for idx, (opcode, arg, _pos) in enumerate(opcodes):
        if opcode.name == "GLOBAL" and isinstance(arg, str):
            # Extract module name from global reference
            if "." in arg:
                module = arg.split(".")[0]
            elif " " in arg:
                module = arg.split(" ")[0]
            else:
                module = arg

            global_refs[module] = global_refs.get(module, 0) + 1

        elif opcode.name == "STACK_GLOBAL":
            resolved = resolved_stack_globals.get(idx)
            if resolved is not None:
                module, name = resolved
                full_ref = f"{module}.{name}"
                global_refs[module] = global_refs.get(module, 0) + 1

                # Also track the full reference for pattern matching
                global_refs[full_ref] = global_refs.get(full_ref, 0) + 1

    # Check each framework with improved scoring
    for framework, patterns in ML_FRAMEWORK_PATTERNS.items():
        framework_score = 0.0
        matches: list[str] = []

        # Check module matches with improved scoring
        # Uses prefix matching so that e.g. module pattern "sklearn" matches
        # global refs like "sklearn.pipeline", "sklearn.ensemble._iforest", etc.
        modules = patterns["modules"]
        counted_modules: set[str] = set()
        if isinstance(modules, list):
            for module in modules:
                # Aggregate counts from all global_refs that match this module
                # either exactly or as a prefix (e.g. "sklearn" matches "sklearn.pipeline").
                # Use counted_modules to prevent double-counting: for STACK_GLOBAL flows
                # both the module key (e.g. "sklearn") and the full ref
                # (e.g. "sklearn.ensemble") are stored in global_refs, so a prefix
                # match could count one logical reference more than once.
                ref_count = 0
                for ref_key, ref_cnt in global_refs.items():
                    base_module = ref_key.split(".")[0] if "." in ref_key else ref_key
                    if base_module in counted_modules:
                        continue
                    if ref_key == module or ref_key.startswith(module + "."):
                        ref_count += ref_cnt
                        counted_modules.add(base_module)

                if ref_count > 0:
                    # Score based on presence and frequency,
                    # not proportion of total opcodes
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
            if isinstance(confidence_boost, int | float):
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
        # Special case: collections.OrderedDict is the standard PyTorch state_dict container
        has_collections_ordered_dict = "collections.OrderedDict" in global_refs
        context["is_ml_content"] = (
            context["overall_confidence"] > 0.15  # Was 0.3
            or has_collections_ordered_dict
        )  # Special case for PyTorch state_dict

    return context


def _is_plausible_python_module(name: str) -> bool:
    """
    Check whether *name* looks like a real Python module/package path.

    Legitimate module names follow Python identifier rules:
    - Each dotted segment is an ASCII Python identifier.
    - Segments normally contain lowercase characters, may be all-uppercase
      ASCII names, or appear in a short explicit allowlist for case-sensitive
      imports such as ``PIL``.

    Keep obviously malformed names rejected so arbitrary data strings are less
    likely to be treated as imports, while still allowing valid mixed-case
    segments such as ``EvilPkg`` and ``MyOrg.InternalPkg``.

    Returns:
        True if *name* plausibly refers to a real Python module.
    """
    if not name:
        return False

    # Fast reject: real module paths never contain whitespace.
    if " " in name or "\t" in name:
        return False

    # Split on dots; each segment must be an ASCII Python identifier.
    segments = name.split(".")
    if not segments or any(s == "" or not s.isascii() or not s.isidentifier() for s in segments):
        return False

    return all(
        any(char.islower() for char in seg)
        or seg in _CASE_SENSITIVE_IMPORT_SEGMENTS
        or (seg.isupper() and seg.isalpha())
        for seg in segments
    )


_CASE_SENSITIVE_IMPORT_SEGMENTS: frozenset[str] = frozenset({"PIL", "Cython"})
IMPORT_ONLY_ALWAYS_DANGEROUS_GLOBALS = frozenset(
    {
        ("dill", "load"),
        ("dill", "loads"),
        ("joblib", "load"),
        ("joblib", "_pickle_load"),
    }
)
IMPORT_ONLY_SAFE_GLOBALS: dict[str, frozenset[str]] = {
    "__builtin__": frozenset({"set", "slice", "tuple"}),
    "builtins": frozenset({"set", "slice", "tuple"}),
    "datetime": frozenset({"date", "datetime", "time", "timedelta", "timezone"}),
    "_io": frozenset({"BytesIO"}),
    "site": frozenset({"addsitedir"}),
    "numpy.f2py.crackfortran": frozenset({"markinnerspaces"}),
    "torch.fx.experimental.symbolic_shapes.ShapeEnv": frozenset({"create_symbol"}),
    "torch.utils._config_module": frozenset({"install_config_module"}),
    "torch.utils.collect_env": frozenset({"get_env_info"}),
    "torch.utils.data.datapipes.utils.decoder": frozenset({"handle_extension"}),
}


def _is_safe_ml_global(mod: str, func: str) -> bool:
    """
    Check if a module.function is in the ML_SAFE_GLOBALS allowlist.

    Uses strict exact matching on both module path and function/class name.
    Every allowed module must explicitly list its safe functions/classes.

    Returns:
        True if the global is in the safe list, False otherwise
    """
    if mod in ML_SAFE_GLOBALS:
        safe_funcs = ML_SAFE_GLOBALS[mod]
        if func in safe_funcs:
            return True

    if "." not in func:
        return False

    current_mod = mod
    for part in func.split("."):
        nested_safe_funcs = ML_SAFE_GLOBALS.get(current_mod)
        if nested_safe_funcs is None or part not in nested_safe_funcs:
            return False
        current_mod = f"{current_mod}.{part}"

    return True


def _is_safe_import_only_global(mod: str, func: str, ml_context: dict[str, Any] | None = None) -> bool:
    """Return True when an import-only target is explicitly safe to treat as benign."""
    if _is_actually_dangerous_global(mod, func, ml_context or {}):
        return False

    if not _is_dangerous_module(mod) and _is_safe_ml_global(mod, func):
        return True

    return func in IMPORT_ONLY_SAFE_GLOBALS.get(mod, frozenset())


def _normalize_import_reference(mod: str, func: str) -> tuple[str, str]:
    """Normalize import references for denylist checks without changing reporting."""
    return mod.strip().lower(), func.strip().lower()


def _is_warning_severity_ref(normalized_mod: str, normalized_func: str) -> bool:
    """Return True when a dangerous ref should be downgraded to WARNING severity."""
    if normalized_mod not in WARNING_SEVERITY_MODULES:
        return False
    warning_funcs = WARNING_SEVERITY_MODULES[normalized_mod]
    if warning_funcs is None:
        return True
    return normalized_func in warning_funcs


def _dangerous_ref_base_severity(
    normalized_mod: str,
    normalized_func: str,
    *,
    origin_is_ext: bool = False,
) -> IssueSeverity:
    """Return the base severity for a resolved dangerous import reference."""
    if origin_is_ext or _is_copyreg_extension_ref(normalized_mod):
        return IssueSeverity.CRITICAL
    return (
        IssueSeverity.WARNING if _is_warning_severity_ref(normalized_mod, normalized_func) else IssueSeverity.CRITICAL
    )


def _is_resolved_import_target(mod: str, func: str) -> bool:
    """Return True when module/function look like concrete Python import targets."""
    if not mod or not func:
        return False

    module_parts = mod.split(".")
    if not all(part.isidentifier() for part in module_parts):
        return False

    return all(part.isidentifier() for part in func.split("."))


def _is_plausible_import_only_module(mod: str) -> bool:
    """Return True when a module path looks importable without matching common data labels."""
    return _is_plausible_python_module(mod)


def _classify_import_reference(
    mod: str, func: str, ml_context: dict[str, Any], *, is_import_only: bool
) -> tuple[bool, IssueSeverity | None, str]:
    """Classify a resolved GLOBAL/STACK_GLOBAL import target.

    Returns (is_failure, severity, classification) where classification is one of
    safe_allowlisted, dangerous, unknown_third_party, or unresolved.
    """
    if not _is_resolved_import_target(mod, func):
        return False, None, "unresolved"

    normalized_mod, normalized_func = _normalize_import_reference(mod, func)
    if is_import_only and (normalized_mod, normalized_func) in IMPORT_ONLY_ALWAYS_DANGEROUS_GLOBALS:
        base_sev = _dangerous_ref_base_severity(normalized_mod, normalized_func)
        return True, base_sev, "dangerous"

    if _is_actually_dangerous_global(mod, func, ml_context):
        base_sev = _dangerous_ref_base_severity(normalized_mod, normalized_func)
        return True, base_sev, "dangerous"

    if _is_safe_ml_global(mod, func):
        return False, None, "safe_allowlisted"

    if is_import_only and _is_safe_import_only_global(mod, func, ml_context):
        return False, None, "safe_allowlisted"

    if not _is_plausible_import_only_module(mod):
        return False, None, "implausible"

    return True, IssueSeverity.WARNING, "unknown_third_party"


def _is_risky_ml_import(mod: str, func: str) -> bool:
    """Return True when module/function matches risky ML import policy."""
    full_ref = f"{mod}.{func}" if func else mod
    parts = full_ref.split(".")

    for i in range(1, len(parts) + 1):
        candidate_full_ref = ".".join(parts[:i])
        if candidate_full_ref in RISKY_ML_EXACT_FULL_REFS:
            return True

    for i in range(1, len(parts)):
        candidate_mod = ".".join(parts[:i])
        candidate_func = ".".join(parts[i:])
        if (candidate_mod, candidate_func) in RISKY_ML_EXACT_REFS:
            return True
        if (candidate_mod, candidate_func) in RISKY_ML_PARENT_CHILD_REFS:
            return True
        if any(
            candidate_mod == prefix or candidate_mod.startswith(f"{prefix}.") for prefix in RISKY_ML_MODULE_PREFIXES
        ):
            return True

    return False


def _is_risky_ml_module_prefix(mod: str) -> bool:
    """Return True when a module hint falls under a risky ML import prefix."""
    return any(mod == prefix or mod.startswith(f"{prefix}.") for prefix in RISKY_ML_MODULE_PREFIXES)


def _is_copyreg_extension_ref(mod: str) -> bool:
    """Return True when a reference came from an EXT opcode extension lookup."""
    return mod == COPYREG_EXTENSION_MODULE


@dataclass(frozen=True)
class _ResolvedImportRef:
    module: str
    function: str
    origin_index: int
    origin_is_ext: bool = False


@dataclass(frozen=True)
class _MutationTargetRef:
    kind: Literal["dict", "object"]
    callable_ref: tuple[str, str] | None = None


@dataclass
class _ExpansionHeuristicStreamState:
    stream_id: int
    opcode_count: int = 0
    memo_reads: int = 0
    memo_writes: int = 0
    dup_count: int = 0
    memo_growth_steps: int = 0
    max_memo_index: int = -1
    next_memo_index: int = 0
    last_written_index: int | None = None
    last_position: int = 0
    event_window: list[tuple[str, int | str]] = field(default_factory=list)


@dataclass(frozen=True)
class _ExpansionHeuristicFinding:
    stream_id: int
    position: int
    opcode_count: int
    memo_reads: int
    memo_writes: int
    get_put_ratio: float
    dup_count: int
    dup_density: float
    memo_growth_steps: int
    memo_slots_used: int
    triggers: tuple[str, ...]


@dataclass
class _PrimaryRefFinding:
    check_index: int
    issue_index: int


@dataclass
class _PickleOpcodeAnalysis:
    opcodes: list[tuple[Any, Any, int | None]] = field(default_factory=list)
    globals_found: set[tuple[str, str, str]] = field(default_factory=set)
    sequence_results: list[Any] = field(default_factory=list)
    stack_global_refs: dict[int, tuple[str, str]] = field(default_factory=dict)
    callable_refs: dict[int, tuple[str, str]] = field(default_factory=dict)
    callable_origin_refs: dict[int, int] = field(default_factory=dict)
    callable_origin_is_ext: dict[int, bool] = field(default_factory=dict)
    malformed_stack_globals: dict[int, MalformedStackGlobalDetails] = field(default_factory=dict)
    mutation_target_refs: dict[int, _MutationTargetRef] = field(default_factory=dict)
    executed_import_origins: set[int] = field(default_factory=set)
    executed_ref_keys: set[tuple[str, str]] = field(default_factory=set)
    max_analyzed_end_offset: int = 0
    max_analyzed_offset: int = -1
    first_pickle_end_pos: int | None = None
    opcode_count: int = 0
    max_stack_depth: int = 0
    stack_depth_warnings: list[dict[str, int | str]] = field(default_factory=list)
    extreme_stack_depth_event: dict[str, int | str] | None = None
    opcode_budget_exceeded: bool = False
    timeout_exceeded: bool = False
    error: Exception | None = None


_SEVERITY_PRIORITY = {
    IssueSeverity.DEBUG: 0,
    IssueSeverity.INFO: 1,
    IssueSeverity.WARNING: 2,
    IssueSeverity.CRITICAL: 3,
}


def _severity_priority(severity: IssueSeverity | None) -> int:
    """Return an ordering key for failed-check severity comparisons."""
    if severity is None:
        return -1
    return _SEVERITY_PRIORITY.get(severity, -1)


def _resolve_copyreg_extension(code: Any, origin_index: int) -> _ResolvedImportRef:
    """
    Resolve EXT opcode codes through copyreg when available.

    Returns a sentinel module/function pair for unresolved extension codes so
    downstream REDUCE analysis can still flag them as dangerous.
    """
    if isinstance(code, int):
        try:
            import copyreg

            inverted_registry = getattr(copyreg, "_inverted_registry", None)
            if isinstance(inverted_registry, dict):
                resolved = inverted_registry.get(code)
                if (
                    isinstance(resolved, tuple)
                    and len(resolved) == 2
                    and isinstance(resolved[0], str)
                    and isinstance(resolved[1], str)
                ):
                    return _ResolvedImportRef(resolved[0], resolved[1], origin_index, origin_is_ext=True)
        except Exception:
            pass

    return _ResolvedImportRef(
        COPYREG_EXTENSION_MODULE,
        f"{COPYREG_EXTENSION_PREFIX}{code}",
        origin_index,
        origin_is_ext=True,
    )


def _is_actually_dangerous_global(mod: str, func: str, ml_context: dict) -> bool:
    """
    Context-aware global reference analysis - distinguishes between legitimate ML operations
    and actual dangerous operations.

    Security-first approach: Always flag dangerous functions, then check ML context
    for less critical operations.
    """
    normalized_mod, normalized_func = _normalize_import_reference(mod, func)
    full_ref = f"{mod}.{func}"
    normalized_full_ref = f"{normalized_mod}.{normalized_func}"

    # STEP 0: EXT opcodes (copyreg extension registry) are always suspicious.
    # They resolve callables indirectly via process-global state and can bypass
    # explicit GLOBAL/STACK_GLOBAL references.
    if _is_copyreg_extension_ref(mod) or (
        (normalized_mod, normalized_func) != (mod, func) and _is_copyreg_extension_ref(normalized_mod)
    ):
        logger.warning(f"Extension-registry callable detected via EXT opcode: {full_ref}")
        return True

    # STEP 0.5: Risky ML imports should be flagged even in import-only payloads.
    # These are intentionally separate from the broad ML safe allowlist because
    # they map to runtime loading/compilation pathways with elevated risk.
    if _is_risky_ml_import(mod, func) or (
        (normalized_mod, normalized_func) != (mod, func) and _is_risky_ml_import(normalized_mod, normalized_func)
    ):
        logger.warning(f"Risky ML import detected: {full_ref}")
        return True

    # STEP 1: ALWAYS flag dangerous functions first (no exceptions, no allowlist override)
    # This MUST come before the ML_SAFE_GLOBALS check to prevent bypass attacks
    # where an attacker places dangerous functions (e.g., operator.attrgetter) in a
    # pickle stream alongside ML references to trick the allowlist.
    if (
        full_ref in ALWAYS_DANGEROUS_FUNCTIONS
        or func in ALWAYS_DANGEROUS_FUNCTIONS
        or normalized_full_ref in ALWAYS_DANGEROUS_FUNCTIONS
        or normalized_func in ALWAYS_DANGEROUS_FUNCTIONS
    ):
        logger.warning(
            f"Always-dangerous function detected: {full_ref} "
            f"(flagged regardless of ML context confidence={ml_context.get('overall_confidence', 0):.2f})"
        )
        return True

    # STEP 2: Flag dangerous modules, but allow explicitly safe-listed functions.
    # The truly dangerous functions from these modules (eval, exec, open, getattr,
    # setattr, delattr, __import__, compile, etc.) are already caught in STEP 1 via
    # ALWAYS_DANGEROUS_FUNCTIONS, so any function reaching this point that is in the
    # ML_SAFE_GLOBALS allowlist (e.g., builtins.slice, builtins.set) is genuinely safe.
    if _is_dangerous_module(mod) or (
        (normalized_mod, normalized_func) != (mod, func) and _is_dangerous_module(normalized_mod)
    ):
        if _is_safe_ml_global(mod, func):
            logger.debug(
                f"Safe function from dangerous module: {mod}.{func} (explicitly allowlisted in ML_SAFE_GLOBALS)"
            )
            return False
        logger.warning(f"Always-dangerous module detected: {mod}.{func} (flagged regardless of ML context)")
        return True

    # STEP 3: Check ML_SAFE_GLOBALS allowlist (after dangerous checks)
    # This prevents false positives for safe functions that passed the dangerous checks.
    # E.g., __builtin__.set (Python 2) or builtins.set (Python 3) are safe.
    # NOTE: This comes AFTER dangerous checks so that ALWAYS_DANGEROUS items
    # can never be overridden by the allowlist.
    if _is_safe_ml_global(mod, func):
        logger.debug(f"Allowlisted safe global: {mod}.{func}")
        return False

    # STEP 4: Use original suspicious global check for all other cases
    # Removed ML confidence-based whitelisting to prevent bypass attacks
    if is_suspicious_global(mod, func):
        return True

    if (normalized_mod, normalized_func) != (mod, func):
        return is_suspicious_global(normalized_mod, normalized_func)

    return False


def _parse_module_function(arg: str) -> tuple[str, str] | None:
    """
    Parse module.function format from a string argument.

    Handles both space-separated and dot-separated formats:
    - "module function" -> ("module", "function")
    - "module.submodule.Class" -> ("module.submodule", "Class")

    Returns:
        Tuple of (module, function/class) or None if parsing fails
    """
    parts = arg.split(" ", 1) if " " in arg else arg.rsplit(".", 1) if "." in arg else [arg, ""]

    if len(parts) == 2 and parts[0] and parts[1]:
        return parts[0], parts[1]
    return None


def _simulate_symbolic_reference_maps(
    opcodes: list[tuple],
) -> tuple[
    dict[int, tuple[str, str]],
    dict[int, tuple[str, str]],
    dict[int, int],
    dict[int, bool],
    dict[int, MalformedStackGlobalDetails],
    dict[int, _MutationTargetRef],
]:
    """Simulate callable resolution and retain import origins plus malformed STACK_GLOBAL details."""
    stack_global_refs: dict[int, tuple[str, str]] = {}
    callable_refs: dict[int, tuple[str, str]] = {}
    callable_origin_refs: dict[int, int] = {}
    callable_origin_is_ext: dict[int, bool] = {}
    malformed_stack_globals: dict[int, MalformedStackGlobalDetails] = {}
    mutation_target_refs: dict[int, _MutationTargetRef] = {}

    marker = object()
    unknown = object()
    missing_memo = object()
    stack: list[Any] = []
    memo: dict[int | str, Any] = {}
    next_memo_index = 0

    def _pop(default: Any = unknown) -> Any:
        return stack.pop() if stack else default

    def _peek(default: Any = unknown) -> Any:
        return stack[-1] if stack else default

    def _peek_setitems_target() -> Any:
        for index in range(len(stack) - 1, -1, -1):
            if stack[index] is marker:
                if index > 0:
                    return stack[index - 1]
                return unknown
        return unknown

    def _pop_to_mark() -> list[Any]:
        popped: list[Any] = []
        while stack:
            item = stack.pop()
            if item is marker:
                break
            popped.append(item)
        return popped

    def _is_ref(value: Any) -> TypeGuard[_ResolvedImportRef]:
        return isinstance(value, _ResolvedImportRef)

    def _classify_stack_global_operand(value: Any) -> tuple[StackGlobalOperandKind, str]:
        if isinstance(value, str):
            return "string", _format_stack_global_string_preview(value)
        if value is missing_memo:
            return "missing_memo", "unknown"
        if value is unknown:
            return "unknown", "unknown"
        return "non_string", _format_stack_global_operand_preview(value)

    for i, (opcode, arg, _pos) in enumerate(opcodes):
        name = opcode.name

        if name == "STOP":
            stack.clear()
            memo.clear()
            next_memo_index = 0
            continue

        if name in STRING_OPCODES and isinstance(arg, str):
            stack.append(arg)
            continue

        if name == "GLOBAL" and isinstance(arg, str):
            parsed = _parse_module_function(arg)
            if parsed:
                stack.append(_ResolvedImportRef(parsed[0], parsed[1], i))
            else:
                stack.append(unknown)
            continue

        if name in {"EXT1", "EXT2", "EXT4"}:
            stack.append(_resolve_copyreg_extension(arg, i))
            continue

        if name == "STACK_GLOBAL":
            func_name = _pop()
            mod_name = _pop()
            if isinstance(mod_name, str) and isinstance(func_name, str):
                ref = _ResolvedImportRef(mod_name, func_name, i)
                stack_global_refs[i] = (mod_name, func_name)
                stack.append(ref)
            else:
                module_kind, module_value = _classify_stack_global_operand(mod_name)
                function_kind, function_value = _classify_stack_global_operand(func_name)
                reason: MalformedStackGlobalReason = "insufficient_context"
                if "missing_memo" in {module_kind, function_kind}:
                    reason = "missing_memo"
                elif "non_string" in {module_kind, function_kind}:
                    reason = "mixed_or_non_string"
                malformed_stack_globals[i] = {
                    "module_kind": module_kind,
                    "module": module_value,
                    "function_kind": function_kind,
                    "function": function_value,
                    "reason": reason,
                }
                stack.append(unknown)
            continue

        if name == "INST" and isinstance(arg, str):
            parsed = _parse_module_function(arg)
            if parsed:
                callable_refs[i] = parsed
                callable_origin_refs[i] = i
            _pop_to_mark()
            stack.append(_MutationTargetRef("object", parsed))
            continue

        if name in {"PUT", "BINPUT", "LONG_BINPUT"}:
            memo[arg] = _peek()
            if isinstance(arg, int):
                next_memo_index = max(next_memo_index, arg + 1)
            continue

        if name == "MEMOIZE":
            memo[next_memo_index] = _peek()
            next_memo_index += 1
            continue

        if name in {"GET", "BINGET", "LONG_BINGET"}:
            stack.append(memo.get(arg, missing_memo))
            continue

        if name == "MARK":
            stack.append(marker)
            continue

        if name == "POP":
            _pop()
            continue

        if name == "DUP":
            stack.append(_peek())
            continue

        if name == "POP_MARK":
            _pop_to_mark()
            continue

        if name in {"TUPLE", "LIST", "DICT", "SET", "FROZENSET"}:
            _pop_to_mark()
            stack.append(_MutationTargetRef("dict") if name == "DICT" else unknown)
            continue

        if name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
            size = {"TUPLE1": 1, "TUPLE2": 2, "TUPLE3": 3}[name]
            for _ in range(size):
                _pop()
            stack.append(unknown)
            continue

        if name in {"EMPTY_TUPLE", "EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET"}:
            stack.append(_MutationTargetRef("dict") if name == "EMPTY_DICT" else unknown)
            continue

        if name in {"APPEND", "SETITEM"}:
            if name == "SETITEM" and len(stack) >= 3:
                target = stack[-3]
                if isinstance(target, _MutationTargetRef):
                    mutation_target_refs[i] = target
            _pop()
            if name == "SETITEM":
                _pop()
            continue

        if name in {"APPENDS", "SETITEMS", "ADDITEMS"}:
            if name == "SETITEMS":
                target = _peek_setitems_target()
                if isinstance(target, _MutationTargetRef):
                    mutation_target_refs[i] = target
            _pop_to_mark()
            continue

        if name == "BUILD":
            if len(stack) >= 2:
                target = stack[-2]
                if isinstance(target, _MutationTargetRef):
                    mutation_target_refs[i] = target
            _pop()
            continue

        if name == "REDUCE":
            reduce_args = _pop()
            callable_item = _pop()
            del reduce_args
            if _is_ref(callable_item):
                callable_refs[i] = (callable_item.module, callable_item.function)
                callable_origin_refs[i] = callable_item.origin_index
                if callable_item.origin_is_ext:
                    callable_origin_is_ext[i] = True
                stack.append(_MutationTargetRef("object", (callable_item.module, callable_item.function)))
            else:
                stack.append(_MutationTargetRef("object"))
            continue

        if name == "NEWOBJ":
            newobj_args = _pop()
            class_item = _pop()
            del newobj_args
            if _is_ref(class_item):
                callable_refs[i] = (class_item.module, class_item.function)
                callable_origin_refs[i] = class_item.origin_index
                if class_item.origin_is_ext:
                    callable_origin_is_ext[i] = True
                stack.append(_MutationTargetRef("object", (class_item.module, class_item.function)))
            else:
                stack.append(_MutationTargetRef("object"))
            continue

        if name == "NEWOBJ_EX":
            kwargs = _pop()
            args = _pop()
            class_item = _pop()
            del kwargs, args
            if _is_ref(class_item):
                callable_refs[i] = (class_item.module, class_item.function)
                callable_origin_refs[i] = class_item.origin_index
                if class_item.origin_is_ext:
                    callable_origin_is_ext[i] = True
                stack.append(_MutationTargetRef("object", (class_item.module, class_item.function)))
            else:
                stack.append(_MutationTargetRef("object"))
            continue

        if name == "OBJ":
            items = _pop_to_mark()
            class_item = items[-1] if items else unknown
            if _is_ref(class_item):
                callable_refs[i] = (class_item.module, class_item.function)
                callable_origin_refs[i] = class_item.origin_index
                if class_item.origin_is_ext:
                    callable_origin_is_ext[i] = True
                stack.append(_MutationTargetRef("object", (class_item.module, class_item.function)))
            else:
                stack.append(_MutationTargetRef("object"))
            continue

        if name in {"BINPERSID"}:
            _pop()
            stack.append(unknown)
            continue

        if name in {"NONE", "NEWTRUE", "NEWFALSE"}:
            stack.append(None if name == "NONE" else name == "NEWTRUE")
            continue

        if name in {
            "PERSID",
            "INT",
            "BININT",
            "BININT1",
            "BININT2",
            "LONG",
            "LONG1",
            "LONG4",
            "FLOAT",
            "BINFLOAT",
            "BINBYTES",
            "SHORT_BINBYTES",
            "BINBYTES8",
            "BYTEARRAY8",
            "UNICODE",
            "SHORT_BINUNICODE",
            "BINUNICODE",
            "BINUNICODE8",
        }:
            stack.append(arg)
            continue

        if name == "NEXT_BUFFER":
            stack.append(unknown)
            continue

        if name == "READONLY_BUFFER":
            continue

        stack_before = getattr(opcode, "stack_before", None)
        stack_after = getattr(opcode, "stack_after", None)
        if isinstance(stack_before, list) and isinstance(stack_after, list):
            if stack_before == [] and stack_after == []:
                logger.debug(f"Simulator: ignoring stack-neutral opcode {opcode.name} at pos {_pos}")
                continue

            logger.debug(f"Simulator: applying generic stack effect for opcode {opcode.name} at pos {_pos}")
            for stack_effect in reversed(stack_before):
                effect_name = repr(stack_effect)
                if effect_name == "stackslice":
                    continue
                if effect_name == "mark":
                    _pop_to_mark()
                    continue
                _pop()

            for _ in stack_after:
                stack.append(unknown)
            continue

        # Unknown opcode - push a sentinel to keep stack in sync.
        # This handles future protocol versions gracefully.
        logger.debug(f"Simulator: unhandled opcode {opcode.name} at pos {_pos}")
        stack.append(unknown)

    return (
        stack_global_refs,
        callable_refs,
        callable_origin_refs,
        callable_origin_is_ext,
        malformed_stack_globals,
        mutation_target_refs,
    )


def _build_expansion_heuristic_finding(
    state: _ExpansionHeuristicStreamState,
) -> _ExpansionHeuristicFinding | None:
    """Summarize stream-local memo/DUP behavior into a bounded expansion heuristic finding."""
    if state.opcode_count == 0:
        return None

    get_put_ratio = (state.memo_reads / state.memo_writes) if state.memo_writes else 0.0
    dup_density = state.dup_count / state.opcode_count

    triggers: list[str] = []
    if (
        state.memo_writes >= _EXPANSION_MEMO_GROWTH_MIN_WRITES
        and state.memo_growth_steps >= _EXPANSION_MEMO_GROWTH_STEPS_THRESHOLD
    ):
        triggers.append("memo_growth_chain")

    if state.dup_count >= _EXPANSION_DUP_COUNT_THRESHOLD and dup_density >= _EXPANSION_DUP_DENSITY_THRESHOLD:
        triggers.append("excessive_dup_usage")

    if (
        state.memo_reads >= _EXPANSION_GET_PUT_MIN_READS
        and get_put_ratio >= _EXPANSION_GET_PUT_RATIO_THRESHOLD
        and (
            state.dup_count >= _EXPANSION_RATIO_SUPPORTING_DUP_THRESHOLD
            or state.memo_growth_steps >= _EXPANSION_RATIO_SUPPORTING_GROWTH_THRESHOLD
        )
    ):
        triggers.append("suspicious_get_put_ratio")

    if not triggers:
        return None

    memo_slots_used = state.max_memo_index + 1 if state.max_memo_index >= 0 else 0
    return _ExpansionHeuristicFinding(
        stream_id=state.stream_id,
        position=state.last_position,
        opcode_count=state.opcode_count,
        memo_reads=state.memo_reads,
        memo_writes=state.memo_writes,
        get_put_ratio=round(get_put_ratio, 2),
        dup_count=state.dup_count,
        dup_density=round(dup_density, 4),
        memo_growth_steps=state.memo_growth_steps,
        memo_slots_used=memo_slots_used,
        triggers=tuple(triggers),
    )


def _detect_pickle_expansion_heuristics(opcodes: list[tuple[Any, Any, int | None]]) -> list[_ExpansionHeuristicFinding]:
    """Detect memo expansion and DUP-heavy pickle-bomb patterns on a per-stream basis."""
    findings: list[_ExpansionHeuristicFinding] = []
    state = _ExpansionHeuristicStreamState(stream_id=0)

    for opcode, arg, pos in opcodes:
        name = opcode.name
        state.opcode_count += 1
        if pos is not None:
            state.last_position = int(pos)

        if name == "DUP":
            state.dup_count += 1

        if name in _MEMO_READ_OPCODES:
            state.memo_reads += 1
        elif name in _MEMO_WRITE_OPCODES:
            state.memo_writes += 1
            memo_index: int | None
            if name == "MEMOIZE":
                memo_index = state.next_memo_index
                state.next_memo_index += 1
            else:
                memo_index = int(arg) if isinstance(arg, int) else None
                if memo_index is not None:
                    state.next_memo_index = max(state.next_memo_index, memo_index + 1)

            lookback = state.event_window[-_EXPANSION_EVENT_WINDOW:]
            previous_memo_index = state.last_written_index
            read_indices = [value for kind, value in lookback if kind == "READ" and isinstance(value, int)]
            repeated_previous_read = previous_memo_index is not None and read_indices.count(previous_memo_index) >= 2
            has_growth_builder = any(kind == "OP" and value in _EXPANSION_GROWTH_BUILDERS for kind, value in lookback)
            is_sequential_growth = (
                previous_memo_index is not None and memo_index is not None and memo_index == previous_memo_index + 1
            )
            if is_sequential_growth and repeated_previous_read and has_growth_builder:
                state.memo_growth_steps += 1

            if memo_index is not None:
                state.max_memo_index = max(state.max_memo_index, memo_index)
                state.last_written_index = memo_index

        if name in _MEMO_READ_OPCODES:
            state.event_window.append(("READ", int(arg) if isinstance(arg, int) else -1))
        else:
            state.event_window.append(("OP", name))
        if len(state.event_window) > _EXPANSION_EVENT_WINDOW:
            del state.event_window[:-_EXPANSION_EVENT_WINDOW]

        if name == "STOP":
            finding = _build_expansion_heuristic_finding(state)
            if finding is not None:
                findings.append(finding)
            state = _ExpansionHeuristicStreamState(stream_id=state.stream_id + 1)

    final_finding = _build_expansion_heuristic_finding(state)
    if final_finding is not None:
        findings.append(final_finding)

    return findings


def _build_symbolic_reference_maps(
    opcodes: list[tuple],
) -> tuple[dict[int, tuple[str, str]], dict[int, tuple[str, str]], dict[int, MalformedStackGlobalDetails]]:
    """
    Build symbolic maps of callable references in an opcode stream.

    Returns:
        Tuple of:
        - stack_global_refs: opcode index -> (module, function) for STACK_GLOBAL
        - callable_refs: opcode index -> (module, function) for REDUCE/NEWOBJ/OBJ/INST call targets
    """
    (
        stack_global_refs,
        callable_refs,
        _callable_origin_refs,
        _callable_origin_is_ext,
        malformed_stack_globals,
        _mutation_target_refs,
    ) = _simulate_symbolic_reference_maps(opcodes)
    return stack_global_refs, callable_refs, malformed_stack_globals


def _find_stack_global_strings(
    opcodes: list,
    start_index: int,
    lookback: int = 10,
    stack_global_refs: dict[int, tuple[str, str]] | None = None,
) -> tuple[str, str] | None:
    """
    Resolve module/function used by STACK_GLOBAL from symbolic stack state.

    Args:
        opcodes: List of (opcode, arg, pos) tuples
        start_index: Index of the STACK_GLOBAL opcode
        lookback: Unused (kept for backward compatibility)
        stack_global_refs: Optional precomputed STACK_GLOBAL map

    Returns:
        Tuple of (module, function/class) or None if not resolved
    """
    del lookback
    refs = stack_global_refs if stack_global_refs is not None else _build_symbolic_reference_maps(opcodes)[0]
    return refs.get(start_index)


def _find_associated_global_or_class(
    opcodes: list,
    current_index: int,
    lookback: int = 10,
    stack_global_refs: dict[int, tuple[str, str]] | None = None,
    callable_refs: dict[int, tuple[str, str]] | None = None,
) -> tuple[str | None, str | None, str | None]:
    """
    Look backward to find the associated GLOBAL or STACK_GLOBAL for an opcode.

    This is used by REDUCE, NEWOBJ, OBJ, and INST opcodes to determine what
    class or function they're operating on.

    Args:
        opcodes: List of (opcode, arg, pos) tuples
        current_index: Current opcode index
        lookback: Maximum number of opcodes to search back
        stack_global_refs: Optional precomputed STACK_GLOBAL map
        callable_refs: Optional precomputed callable map (for REDUCE/NEWOBJ/OBJ/INST)

    Returns:
        Tuple of (module, function/class, full_name) or (None, None, None)
    """
    callable_map = callable_refs if callable_refs is not None else _build_symbolic_reference_maps(opcodes)[1]
    direct_ref = callable_map.get(current_index)
    if direct_ref:
        mod, func = direct_ref
        return mod, func, f"{mod}.{func}"

    for j in range(current_index - 1, max(0, current_index - lookback), -1):
        prev_opcode, prev_arg, _prev_pos = opcodes[j]

        if prev_opcode.name == "GLOBAL" and isinstance(prev_arg, str):
            # Parse GLOBAL opcode argument
            parsed = _parse_module_function(prev_arg)
            if parsed:
                mod, func = parsed
                return mod, func, f"{mod}.{func}"

        elif prev_opcode.name == "STACK_GLOBAL":
            # Find two strings before STACK_GLOBAL
            strings = _find_stack_global_strings(
                opcodes,
                j,
                lookback=lookback,
                stack_global_refs=stack_global_refs,
            )
            if strings:
                mod, func = strings
                return mod, func, f"{mod}.{func}"

    return None, None, None


def _is_actually_dangerous_string(s: str, ml_context: dict) -> str | None:
    """
    Context-aware string analysis - looks for actual executable code rather than ML patterns.
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

    # Check for base64-like strings, but avoid common benign model metadata such
    # as repeated tokens and hex digests. Encoded nested payloads are handled
    # separately by decoding and validating the content.
    if (
        len(s) > 100
        and re.match(r"^[A-Za-z0-9+/=]+$", s)
        and not re.match(r"^(.)\1*$", s)  # Not all same character (e.g., "===...")
        and len(set(s)) > 4  # Must have some character diversity
        and not re.fullmatch(r"[0-9a-fA-F]+", s)
        and not _is_short_period_repetition(s)
        and re.search(r"[A-Z]", s)
        and re.search(r"[a-z]", s)
        and re.search(r"[0-9]", s)
    ):
        if any(ch in s for ch in "+/="):
            return "potential_base64"

        # Preserve padding-stripped base64 blobs that are otherwise well-formed.
        padding_needed = (-len(s)) % 4
        if padding_needed in (0, 1, 2) and len(s) <= 10000:
            padded = s + ("=" * padding_needed)
            if any(encoding == "base64" for encoding, _decoded in _decode_string_to_bytes(padded)):
                return "potential_base64"

    return None


def _is_short_period_repetition(s: str, max_period: int = 16) -> bool:
    """Return True for strings made by repeating a short token like ``ABCD1234``."""
    if len(s) < max_period * 2:
        return False
    if len(s) > 10 * 1024 * 1024:
        return False

    for period in range(2, min(max_period, len(s) // 2) + 1):
        if len(s) % period == 0:
            unit = s[:period]
            if all(s[i : i + period] == unit for i in range(0, len(s), period)):
                return True

    return False


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

    except Exception as e:
        logger.debug("Error analyzing pickle structure: %s", e)
        return False

    return False


def _find_nested_pickle_match(data: bytes | bytearray) -> _NestedPickleMatch | None:
    """Find a nested pickle within a bounded search window.

    The scanner previously only checked the first 1024 bytes of embedded blobs,
    which let attackers hide inner pickle streams behind padding. This helper
    keeps the work bounded while scanning for plausible binary pickle headers
    within the first search window.
    """
    data_bytes = bytes(data)
    if len(data_bytes) < 2:
        return None

    search_limit = min(len(data_bytes), _NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES)
    validation_limit = min(len(data_bytes), _NESTED_PICKLE_VALIDATION_WINDOW_BYTES)

    # Fast path: payload starts with a pickle stream (also covers protocol 0/1).
    if _looks_like_pickle(data_bytes[:validation_limit]):
        return _NestedPickleMatch(
            offset=0,
            sample_size=validation_limit,
            searched_bytes=search_limit,
        )

    if search_limit < 3:
        return None

    cursor = 0
    # Binary pickle headers need three readable bytes: PROTO, protocol, opcode.
    max_header_start = search_limit - 3

    # Scan the full bounded window. A fixed candidate cap is bypassable because
    # valid-looking header triplets can be packed densely ahead of the real stream.
    while cursor <= max_header_start:
        header_offset = data_bytes.find(b"\x80", cursor, max_header_start + 1)
        if header_offset == -1:
            break
        cursor = header_offset + 1

        protocol = data_bytes[header_offset + 1]
        next_opcode = data_bytes[header_offset + 2]
        if protocol not in _BINARY_PICKLE_PROTOCOLS or next_opcode not in _PICKLE_OPCODE_BYTES:
            continue

        sample_end = min(len(data_bytes), header_offset + _NESTED_PICKLE_VALIDATION_WINDOW_BYTES)
        if _looks_like_pickle(data_bytes[header_offset:sample_end]):
            return _NestedPickleMatch(
                offset=header_offset,
                sample_size=sample_end - header_offset,
                searched_bytes=search_limit,
            )

    return None


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
    except Exception as e:
        logger.debug("Failed to decode potential base64 string: %s", e)

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
    except Exception as e:
        logger.debug("Failed to decode potential hex string: %s", e)

    return candidates


def _should_ignore_opcode_sequence(opcodes: list[tuple], ml_context: dict) -> bool:
    """
    Determine if an opcode sequence should be ignored based on ML context.

    SECURITY: Never skip opcode analysis entirely. ML context can reduce
    sensitivity but critical security checks must always run.
    """
    # NEVER skip opcode analysis, regardless of ML confidence
    # Opcode sequence analysis is a critical security check
    return False


def _get_context_aware_severity(
    base_severity: IssueSeverity,
    ml_context: dict,
    issue_type: str = "",
) -> IssueSeverity:
    """
    Return base severity without adjustments.

    Confidence-based severity downgrading has been removed to prevent security bypasses.
    All issues are reported at their base severity level.
    """
    return base_severity


# ============================================================================
# END ML CONTEXT FILTERING SYSTEM
# ============================================================================


def _is_legitimate_serialization_file(path: str) -> bool:
    """
    Validate that a file is a legitimate joblib or dill serialization file.
    This helps prevent security bypass by simply renaming malicious files.
    """

    def _analyze_sample_globals(sample: bytes) -> tuple[bool, bool]:
        if not sample:
            return False, False

        validation_context = {"is_ml_content": False, "overall_confidence": 0.0, "frameworks": {}}
        has_dangerous_global = False
        has_joblib_like_global = False

        def _record_global(mod: str, func: str) -> None:
            nonlocal has_dangerous_global, has_joblib_like_global
            if mod in {"joblib", "sklearn", "numpy"} or mod.startswith(("joblib.", "sklearn.", "numpy.")):
                has_joblib_like_global = True
            if _is_actually_dangerous_global(mod, func, validation_context):
                has_dangerous_global = True

        # Raw protocol 0/1 GLOBAL parsing keeps this heuristic usable even when
        # pickletools itself is the code path that hits MemoryError.
        cursor = 0
        max_global_len = 256
        while cursor < len(sample):
            global_pos = sample.find(b"c", cursor)
            if global_pos == -1:
                break

            module_end = sample.find(b"\n", global_pos + 1, global_pos + 1 + max_global_len)
            if module_end == -1:
                cursor = global_pos + 1
                continue

            function_end = sample.find(b"\n", module_end + 1, module_end + 1 + max_global_len)
            if function_end == -1:
                cursor = global_pos + 1
                continue

            try:
                module = sample[global_pos + 1 : module_end].decode("utf-8")
                function = sample[module_end + 1 : function_end].decode("utf-8")
            except UnicodeDecodeError:
                cursor = global_pos + 1
                continue

            if module and function:
                _record_global(module, function)
            cursor = function_end + 1

        try:
            opcodes = list(_genops_with_fallback(io.BytesIO(sample), max_items=128))
        except (_GenopsBudgetExceeded, ValueError, struct.error, UnicodeDecodeError, EOFError):
            return has_dangerous_global, has_joblib_like_global
        except Exception:
            return has_dangerous_global, has_joblib_like_global

        (
            stack_global_refs,
            _callable_refs,
            _origin_refs,
            _origin_is_ext,
            _malformed,
            _mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)

        for idx, (opcode, arg, _pos) in enumerate(opcodes):
            op_name = getattr(opcode, "name", "")
            if op_name in {"GLOBAL", "INST"} and isinstance(arg, str):
                parsed = _parse_module_function(arg)
                if parsed:
                    _record_global(parsed[0], parsed[1])
            elif op_name == "STACK_GLOBAL":
                stack_ref = stack_global_refs.get(idx)
                if stack_ref:
                    _record_global(stack_ref[0], stack_ref[1])

        return has_dangerous_global, has_joblib_like_global

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

            f.seek(0)
            sample = f.read(64 * 1024)
            has_dangerous_global, has_joblib_like_global = _analyze_sample_globals(sample)
            if has_dangerous_global:
                return False

            # For joblib files and extensionless cache blobs, require opcode-level
            # framework evidence instead of marker strings. Extension/substring
            # checks alone are too easy to spoof.
            ext_lower = os.path.splitext(path)[1].lower()
            if ext_lower == ".joblib" or not ext_lower:
                return bool(has_joblib_like_global)

            # Dill can serialize plain pickle-compatible objects without
            # embedding obvious dill globals near the front of the stream, so
            # a .dill extension remains a legitimacy signal after bounded
            # dangerous-global rejection above.
            if ext_lower == ".dill":
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

    First checks against ML_SAFE_GLOBALS allowlist to reduce false positives
    for legitimate ML framework operations.
    """
    # STEP 0: Always flag risky ML imports before any allowlist checks.
    if _is_risky_ml_import(mod, func):
        return True

    # STEP 1: Check ML_SAFE_GLOBALS allowlist first
    # If the module.function is in the safe list, it's not suspicious
    if mod in ML_SAFE_GLOBALS:
        safe_funcs = ML_SAFE_GLOBALS[mod]
        if func in safe_funcs:
            logger.debug(f"Allowlisted ML global: {mod}.{func}")
            return False

    # Normalize module name for consistent checking
    # Some exploits use alternative spellings or references
    normalized_mod = mod.strip().lower() if mod else ""

    # Check for direct matches in suspicious globals
    if mod in SUSPICIOUS_GLOBALS:
        val = SUSPICIOUS_GLOBALS[mod]
        if val == "*":
            return True
        if isinstance(val, list):
            # Handle ["*"] wildcard (all functions in module are suspicious)
            if "*" in val:
                return True
            if func in val:
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


def is_suspicious_string(s: str) -> str | None:
    """Check if a string contains suspicious patterns"""
    import re

    for pattern in SUSPICIOUS_STRING_PATTERNS:
        match = re.search(pattern, s)
        if match:
            return pattern

    # Check for base64-like strings (long strings with base64 charset), but avoid repeating patterns
    # and TF-IDF vocabulary strings (which are long alphanumeric but all lowercase words)
    if (
        len(s) > 40
        and re.match(r"^[A-Za-z0-9+/=]+$", s)
        and not re.match(r"^(.)\1*$", s)  # Not all same character
        and len(set(s)) > 4  # Must have some character diversity
        # Require characteristics of actual base64: mixed case AND digits present
        # This avoids matching TF-IDF vocabulary (all lowercase concatenated words)
        and re.search(r"[A-Z]", s)
        and re.search(r"[a-z]", s)
        and re.search(r"[0-9]", s)
    ):
        return "potential_base64"

    return None


def is_dangerous_reduce_pattern(
    opcodes: list[tuple],
    stack_global_refs: dict[int, tuple[str, str]] | None = None,
    callable_refs: dict[int, tuple[str, str]] | None = None,
    callable_origin_is_ext: dict[int, bool] | None = None,
    mutation_target_refs: dict[int, _MutationTargetRef] | None = None,
    minimum_position: int | None = None,
) -> dict[str, Any] | None:
    """
    Check for patterns that indicate a dangerous __reduce__ method.
    Returns details about the dangerous pattern if found, None otherwise.

    Only flags GLOBAL/STACK_GLOBAL+REDUCE patterns where the module/function
    is actually dangerous or suspicious. Safe ML globals and unknown non-dangerous
    modules are handled by the individual GLOBAL/REDUCE checks in the main loop.
    """

    def _is_dangerous_ref(mod: str, func: str, *, origin_is_ext: bool = False) -> bool:
        """Check if a module.function reference is dangerous enough to flag."""
        if origin_is_ext or _is_copyreg_extension_ref(mod):
            return True

        if _is_risky_ml_import(mod, func):
            return True

        full_ref = f"{mod}.{func}"
        # Check ALWAYS_DANGEROUS functions FIRST (before allowlist to prevent bypass)
        if full_ref in ALWAYS_DANGEROUS_FUNCTIONS or func in ALWAYS_DANGEROUS_FUNCTIONS:
            return True
        # Check dangerous modules, but allow explicitly safe-listed functions
        # (truly dangerous functions like eval/exec/open are caught above)
        if _is_dangerous_module(mod):
            return not _is_safe_ml_global(mod, func)
        # Safe ML globals (checked after dangerous lists)
        if _is_safe_ml_global(mod, func):
            return False
        # Check SUSPICIOUS_GLOBALS (the fallback)
        return is_suspicious_global(mod, func)

    def _position_in_scope(position: int | None) -> bool:
        if minimum_position is None:
            return True
        return position is not None and int(position) >= minimum_position

    if (
        stack_global_refs is None
        or callable_refs is None
        or callable_origin_is_ext is None
        or mutation_target_refs is None
    ):
        (
            computed_stack_refs,
            computed_callable_refs,
            _computed_callable_origin_refs,
            computed_callable_origin_is_ext,
            _computed_malformed_stack_globals,
            computed_mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)
    else:
        computed_stack_refs, computed_callable_refs, computed_callable_origin_is_ext, computed_mutation_target_refs = (
            stack_global_refs,
            callable_refs,
            callable_origin_is_ext,
            mutation_target_refs,
        )

    resolved_stack_globals = stack_global_refs if stack_global_refs is not None else computed_stack_refs
    resolved_callables = callable_refs if callable_refs is not None else computed_callable_refs
    resolved_callable_origin_is_ext = (
        callable_origin_is_ext if callable_origin_is_ext is not None else computed_callable_origin_is_ext
    )
    resolved_mutation_targets = (
        mutation_target_refs if mutation_target_refs is not None else computed_mutation_target_refs
    )

    # Look for common patterns in __reduce__ exploits
    for i, (opcode, arg, pos) in enumerate(opcodes):
        # Resolve REDUCE targets from symbolic stack state (handles BINGET/MEMOIZE indirection)
        if opcode.name == "REDUCE":
            reduce_ref = resolved_callables.get(i)
            if reduce_ref:
                mod, func = reduce_ref
                origin_is_ext = resolved_callable_origin_is_ext.get(i, False)
                if _is_dangerous_ref(mod, func, origin_is_ext=origin_is_ext) and _position_in_scope(pos):
                    return {
                        "pattern": "RESOLVED_REDUCE_CALL_TARGET",
                        "module": mod,
                        "function": func,
                        "position": pos,
                        "opcode": opcode.name,
                        "origin_is_ext": origin_is_ext,
                    }

        # BUILD mutates a previously-constructed object and may invoke
        # __setstate__ with attacker-controlled state.
        if opcode.name == "BUILD":
            target_ref = resolved_mutation_targets.get(i)
            if target_ref and target_ref.kind == "object" and target_ref.callable_ref:
                mod, func = target_ref.callable_ref
                if not _is_safe_ml_global(mod, func) and _position_in_scope(pos):
                    return {
                        "pattern": "BUILD_SETSTATE_NON_SAFE_GLOBAL",
                        "module": mod,
                        "function": func,
                        "associated_global": f"{mod}.{func}",
                        "position": pos,
                        "opcode": opcode.name,
                        "description": (
                            "BUILD applied state to object from non-safe global; potential __setstate__ exploitation"
                        ),
                    }

        # Check for GLOBAL followed by REDUCE - common in exploits
        if (opcode.name == "GLOBAL" and i + 1 < len(opcodes) and opcodes[i + 1][0].name == "REDUCE") and isinstance(
            arg, str
        ):
            parts = arg.split(" ", 1) if " " in arg else arg.rsplit(".", 1) if "." in arg else [arg, ""]
            if len(parts) == 2:
                mod, func = parts
                if _is_dangerous_ref(mod, func) and _position_in_scope(pos):
                    return {
                        "pattern": "GLOBAL+REDUCE",
                        "module": mod,
                        "function": func,
                        "position": pos,
                        "opcode": opcode.name,
                    }

        # Check for STACK_GLOBAL followed by REDUCE - protocol 4+ variant
        if opcode.name == "STACK_GLOBAL":
            # Check if next non-structural opcode leads to REDUCE
            for j in range(i + 1, min(i + 5, len(opcodes))):
                next_op = opcodes[j][0].name
                if next_op == "REDUCE":
                    resolved = resolved_stack_globals.get(i)
                    if resolved:
                        mod, func = resolved
                        if _is_dangerous_ref(mod, func) and _position_in_scope(pos):
                            return {
                                "pattern": "STACK_GLOBAL+REDUCE",
                                "module": mod,
                                "function": func,
                                "position": pos,
                                "opcode": opcode.name,
                            }
                    break
                elif next_op not in {
                    "TUPLE",
                    "TUPLE1",
                    "TUPLE2",
                    "TUPLE3",
                    "EMPTY_TUPLE",
                    "MARK",
                    "BINPUT",
                    "LONG_BINPUT",
                    "MEMOIZE",
                }:
                    break

        # Check for INST or OBJ opcodes which can also be used for code execution
        # Skip if the target class is in the ML_SAFE_GLOBALS allowlist
        if opcode.name in ["INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"] and isinstance(arg, str):
            parsed = _parse_module_function(arg)
            is_safe = False
            if parsed:
                inst_mod, inst_func = parsed
                is_safe = _is_safe_ml_global(inst_mod, inst_func)
            if not is_safe:
                # Also check via symbolic reference maps for NEWOBJ/OBJ
                ref = resolved_callables.get(i)
                if ref:
                    is_safe = _is_safe_ml_global(ref[0], ref[1])
            if not is_safe and _position_in_scope(pos):
                return {
                    "pattern": f"{opcode.name}_EXECUTION",
                    "argument": arg,
                    "position": pos,
                    "opcode": opcode.name,
                }

        # Check for OBJ/NEWOBJ/NEWOBJ_EX opcodes which produce arg=None;
        # use the resolved callable map to get the associated class reference.
        if opcode.name in {"OBJ", "NEWOBJ", "NEWOBJ_EX"}:
            ref = resolved_callables.get(i)
            if ref:
                mod, func = ref
                origin_is_ext = resolved_callable_origin_is_ext.get(i, False)
                if _is_dangerous_ref(mod, func, origin_is_ext=origin_is_ext) and _position_in_scope(pos):
                    return {
                        "pattern": f"{opcode.name}_EXECUTION",
                        "argument": f"{mod}.{func}",
                        "position": pos,
                        "opcode": opcode.name,
                        "origin_is_ext": origin_is_ext,
                    }

        # Check for suspicious attribute access patterns (GETATTR followed by CALL)
        if (
            opcode.name == "GETATTR"
            and i + 1 < len(opcodes)
            and opcodes[i + 1][0].name == "CALL"
            and _position_in_scope(pos)
        ):
            return {
                "pattern": "GETATTR+CALL",
                "attribute": arg,
                "position": pos,
                "opcode": opcode.name,
            }

    return None


def _build_opcode_check_finding(
    *,
    check_name: str,
    message: str,
    severity: IssueSeverity,
    position: int | None,
    rule_code: str | None,
    details: dict[str, Any],
    why: str | None,
) -> dict[str, Any]:
    """Create a reusable opcode-derived finding payload."""
    return {
        "check_name": check_name,
        "message": message,
        "severity": severity,
        "position": position,
        "rule_code": rule_code,
        "details": details,
        "why": why,
    }


def _serialize_opcode_check_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Convert opcode finding payloads into check-detail-friendly data."""
    severity = finding.get("severity")
    serialized = {
        "check_name": finding["check_name"],
        "message": finding["message"],
        "severity": severity.value if isinstance(severity, IssueSeverity) else severity,
        "position": finding.get("position"),
        "details": dict(finding.get("details", {})),
    }
    if finding.get("rule_code") is not None:
        serialized["rule_code"] = finding["rule_code"]
    if finding.get("why") is not None:
        serialized["why"] = finding["why"]
    return serialized


def _collect_nested_pickle_opcode_findings(
    opcode_name: str,
    arg: Any,
    pos: int | None,
    ml_context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return nested/encoded pickle findings for a single opcode payload."""
    findings: list[dict[str, Any]] = []

    if opcode_name in {"BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8"} and isinstance(arg, bytes | bytearray):
        nested_match = _find_nested_pickle_match(arg)
        if nested_match is not None:
            severity = _get_context_aware_severity(IssueSeverity.CRITICAL, ml_context)
            findings.append(
                _build_opcode_check_finding(
                    check_name="Nested Pickle Detection",
                    message="Nested pickle payload detected",
                    severity=severity,
                    position=pos,
                    rule_code="S213",
                    details={
                        "position": pos,
                        "opcode": opcode_name,
                        "nested_offset": nested_match.offset,
                        "sample_size": nested_match.sample_size,
                        "searched_bytes": nested_match.searched_bytes,
                    },
                    why=get_pattern_explanation("nested_pickle"),
                )
            )

    if opcode_name in {"BINSTRING", "SHORT_BINSTRING"} and isinstance(arg, str):
        try:
            nested_match = _find_nested_pickle_match(arg.encode("latin-1"))
            if nested_match is not None:
                severity = _get_context_aware_severity(IssueSeverity.CRITICAL, ml_context)
                findings.append(
                    _build_opcode_check_finding(
                        check_name="Nested Pickle Detection",
                        message="Nested pickle payload detected in legacy string opcode",
                        severity=severity,
                        position=pos,
                        rule_code="S213",
                        details={
                            "position": pos,
                            "opcode": opcode_name,
                            "nested_offset": nested_match.offset,
                            "sample_size": nested_match.sample_size,
                            "searched_bytes": nested_match.searched_bytes,
                        },
                        why=get_pattern_explanation("nested_pickle"),
                    )
                )
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

    if opcode_name in STRING_OPCODES and isinstance(arg, str):
        for enc, decoded in _decode_string_to_bytes(arg):
            nested_match = _find_nested_pickle_match(decoded)
            if nested_match is not None:
                severity = _get_context_aware_severity(IssueSeverity.CRITICAL, ml_context)
                findings.append(
                    _build_opcode_check_finding(
                        check_name="Encoded Pickle Detection",
                        message="Encoded pickle payload detected",
                        severity=severity,
                        position=pos,
                        rule_code=get_encoding_rule_code(enc),
                        details={
                            "position": pos,
                            "opcode": opcode_name,
                            "encoding": enc,
                            "decoded_size": len(decoded),
                            "nested_offset": nested_match.offset,
                            "sample_size": nested_match.sample_size,
                            "searched_bytes": nested_match.searched_bytes,
                        },
                        why=get_pattern_explanation("nested_pickle"),
                    )
                )

    return findings


def _collect_encoded_python_opcode_findings(
    opcode_name: str,
    arg: Any,
    pos: int | None,
    ml_context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return encoded-Python findings preserved from the main opcode loop."""
    if opcode_name not in STRING_OPCODES or not isinstance(arg, str):
        return []

    findings: list[dict[str, Any]] = []
    for enc, decoded in _decode_string_to_bytes(arg):
        if _find_nested_pickle_match(decoded) is not None:
            continue
        try:
            decoded_str = decoded.decode("utf-8", errors="ignore")
            if len(decoded_str) <= 10 or not any(
                pattern in decoded_str for pattern in ["import ", "def ", "class ", "eval(", "exec(", "__import__"]
            ):
                continue
            is_valid, _ = validate_python_syntax(decoded_str)
            if not is_valid:
                continue
            is_dangerous, risk_desc = is_code_potentially_dangerous(decoded_str, "low")
            if not is_dangerous:
                continue
            severity = _get_context_aware_severity(IssueSeverity.WARNING, ml_context)
            enc_rule = get_encoding_rule_code(enc) or "S507"
            findings.append(
                _build_opcode_check_finding(
                    check_name="Encoded Python Code Detection",
                    message=f"Encoded Python code detected ({enc})",
                    severity=severity,
                    position=pos,
                    rule_code=enc_rule,
                    details={
                        "position": pos,
                        "opcode": opcode_name,
                        "encoding": enc,
                        "risk_analysis": risk_desc,
                        "code_preview": decoded_str[:100] + "..." if len(decoded_str) > 100 else decoded_str,
                    },
                    why="Encoded Python code was found that could be executed during unpickling.",
                )
            )
        except Exception:
            continue

    return findings


def _build_malformed_stack_global_finding(
    *,
    pos: int | None,
    malformed: MalformedStackGlobalDetails,
    ml_context: dict[str, Any],
) -> dict[str, Any]:
    """Build the fail-closed STACK_GLOBAL finding shared by main and tail scans."""
    module_hint = malformed["module"]
    function_hint = malformed["function"]
    module_kind = malformed["module_kind"]
    function_kind = malformed["function_kind"]
    reason = malformed["reason"]
    module_looks_high_risk = (
        module_kind == "string"
        and module_hint not in {"", "unknown"}
        and (_is_dangerous_module(module_hint) or _is_risky_ml_module_prefix(module_hint))
    )
    severity = IssueSeverity.CRITICAL if module_looks_high_risk else IssueSeverity.WARNING
    if reason == "missing_memo":
        message = (
            "STACK_GLOBAL references missing or invalid memoized operand(s): "
            f"module={module_hint} ({module_kind}), function={function_hint} ({function_kind})"
        )
    else:
        message = (
            "Malformed STACK_GLOBAL operand types can hide dangerous imports: "
            f"module={module_hint} ({module_kind}), function={function_hint} ({function_kind})"
        )

    return _build_opcode_check_finding(
        check_name="STACK_GLOBAL Context Check",
        message=message,
        severity=severity,
        position=pos,
        rule_code="S205",
        details={
            "position": pos,
            "opcode": "STACK_GLOBAL",
            "module": module_hint,
            "function": function_hint,
            "module_kind": module_kind,
            "function_kind": function_kind,
            "reason": reason,
            "ml_context_confidence": ml_context.get("overall_confidence", 0),
        },
        why=(
            "STACK_GLOBAL should be formed from two string operands. Non-string operands "
            "or missing memoized values indicate a malformed-by-design payload and are "
            "treated as a security finding under fail-closed handling."
        ),
    )


def _build_dangerous_reduce_pattern_finding(
    dangerous_pattern: dict[str, Any],
    ml_context: dict[str, Any],
) -> dict[str, Any]:
    """Build the shared check payload for dangerous reduce/call-target patterns."""
    normalized_pattern_mod, normalized_pattern_func = _normalize_import_reference(
        dangerous_pattern.get("module", ""),
        dangerous_pattern.get("function", ""),
    )
    is_build_setstate = dangerous_pattern.get("pattern") == "BUILD_SETSTATE_NON_SAFE_GLOBAL"
    dangerous_pattern_base_severity = (
        _dangerous_ref_base_severity(
            normalized_pattern_mod,
            normalized_pattern_func,
            origin_is_ext=bool(dangerous_pattern.get("origin_is_ext")),
        )
        if normalized_pattern_mod and normalized_pattern_func and not is_build_setstate
        else (IssueSeverity.WARNING if is_build_setstate else IssueSeverity.CRITICAL)
    )
    severity = _get_context_aware_severity(
        dangerous_pattern_base_severity,
        ml_context,
        issue_type="dangerous_import",
    )
    module_name = dangerous_pattern.get("module", "")
    func_name = dangerous_pattern.get("function", "")
    dangerous_pattern_rule_code = (
        get_pickle_opcode_rule_code("BUILD") if is_build_setstate else get_import_rule_code(module_name, func_name)
    )
    if not dangerous_pattern_rule_code:
        dangerous_pattern_rule_code = "S201"
    finding_name = "BUILD Opcode Analysis" if is_build_setstate else "Reduce Pattern Analysis"
    if is_build_setstate:
        finding_message = f"Detected potential __setstate__ exploitation via BUILD with {module_name}.{func_name}"
        dangerous_pattern_why: str | None = (
            "BUILD can invoke __setstate__ on the constructed object. "
            "When that object comes from a non-safe global, attacker-controlled state may execute code."
        )
    elif module_name and func_name:
        finding_message = f"Detected dangerous __reduce__ pattern with {module_name}.{func_name}"
        dangerous_pattern_why = get_import_explanation(f"{module_name}.{func_name}")
    else:
        finding_message = "Detected dangerous __reduce__ pattern"
        dangerous_pattern_why = "A dangerous pattern was detected that could execute arbitrary code during unpickling."
    details = {
        **dangerous_pattern,
        "ml_context_confidence": ml_context.get("overall_confidence", 0),
    }
    return _build_opcode_check_finding(
        check_name=finding_name,
        message=finding_message,
        severity=severity,
        position=dangerous_pattern.get("position"),
        rule_code=dangerous_pattern_rule_code,
        details=details,
        why=dangerous_pattern_why,
    )


def check_opcode_sequence(
    opcodes: list[tuple],
    ml_context: dict,
    stack_global_refs: dict[int, tuple[str, str]] | None = None,
    callable_refs: dict[int, tuple[str, str]] | None = None,
    callable_origin_is_ext: dict[int, bool] | None = None,
) -> list[dict[str, Any]]:
    """
    Analyze the full sequence of opcodes for suspicious patterns
    with ML context awareness.
    Returns a list of suspicious patterns found.
    """
    suspicious_patterns: list[dict[str, Any]] = []

    # ML CONTEXT FILTERING: Check if we should ignore this sequence based on ML context
    if _should_ignore_opcode_sequence(opcodes, ml_context):
        return suspicious_patterns  # Return empty list for legitimate ML content

    if stack_global_refs is None or callable_refs is None or callable_origin_is_ext is None:
        (
            computed_stack_refs,
            computed_callable_refs,
            _computed_callable_origin_refs,
            computed_callable_origin_is_ext,
            _computed_malformed_stack_globals,
            _computed_mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)
    else:
        computed_stack_refs, computed_callable_refs, computed_callable_origin_is_ext = (
            stack_global_refs,
            callable_refs,
            callable_origin_is_ext,
        )

    resolved_stack_globals = stack_global_refs if stack_global_refs is not None else computed_stack_refs
    resolved_callables = callable_refs if callable_refs is not None else computed_callable_refs
    resolved_callable_origin_is_ext = (
        callable_origin_is_ext if callable_origin_is_ext is not None else computed_callable_origin_is_ext
    )

    # Memo and framing opcodes are structural (data storage/retrieval, not code
    # execution).  They appear in every non-trivial pickle stream and counting
    # them inflates the dangerous-opcode metric for legitimate ML models.
    _STRUCTURAL_OPCODES = frozenset({"BINPUT", "LONG_BINPUT", "BINGET", "LONG_BINGET", "FRAME"})

    # Count dangerous opcodes with ML context awareness
    dangerous_opcode_count = 0
    consecutive_dangerous = 0
    max_consecutive = 0
    # Track whether the last object construction used a safe ML global.
    # BUILD opcodes restore state on the previously-constructed object via
    # __setstate__ and are benign when the object comes from a safe ML class.
    last_construction_safe = False

    # Track pickle memo: maps memo index -> True if the stored value is a safe
    # ML global.  This lets us recognise BINGET → REDUCE patterns where the
    # callable was stored once via GLOBAL + BINPUT and then recalled many times.
    _safe_memo: dict[int, bool] = {}
    # Track next auto-assigned memo index for MEMOIZE opcodes (protocol 4+)
    _next_memo_idx = 0

    # Fixed baseline threshold for dangerous opcode detection.
    # Only execution-related opcodes are counted (memo/framing excluded),
    # and safe ML globals are skipped for REDUCE/GLOBAL/STACK_GLOBAL/NEWOBJ.
    default_threshold = 50

    # Track stream membership and stream lengths so thresholding can be applied
    # per stream. Counters reset at STOP boundaries, so thresholds must align
    # with those same boundaries to avoid cross-stream dilution.
    stream_id_by_index: list[int] = []
    stream_lengths: dict[int, int] = {}
    current_stream_id = 0
    current_stream_length = 0

    for op, _arg, _pos in opcodes:
        stream_id_by_index.append(current_stream_id)
        current_stream_length += 1
        if op.name == "STOP":
            stream_lengths[current_stream_id] = current_stream_length
            current_stream_id += 1
            current_stream_length = 0

    if current_stream_length > 0:
        stream_lengths[current_stream_id] = current_stream_length
    elif not stream_lengths:
        stream_lengths[0] = 0

    # In high-confidence ML contexts with tree-ensemble models (e.g. sklearn
    # RandomForest, xgboost, lightgbm), tree-based models legitimately produce
    # hundreds of REDUCE/NEWOBJ/BUILD opcodes for each estimator node. A Random
    # Forest with 100 trees can easily produce 5000+ BUILD opcodes from
    # __setstate__ calls on tree nodes.
    # Raise the threshold significantly to suppress false positives, but ONLY
    # when tree-ensemble markers are present -- not for all sklearn/xgboost refs.
    _ml_frameworks = {str(name).lower() for name in ml_context.get("frameworks", {})}
    _tree_ensemble_frameworks = {"sklearn", "xgboost", "lightgbm"}
    _tree_ensemble_markers = {
        "RandomForest",
        "ExtraTrees",
        "GradientBoosting",
        "HistGradientBoosting",
        "DecisionTree",
        "XGB",
        "LGBM",
        "CatBoost",
        "IsolationForest",
        "AdaBoost",
        # NOTE: BaggingClassifier/BaggingRegressor intentionally excluded --
        # they are meta-estimators that can wrap any base estimator, not
        # strictly tree-ensembles. Threshold escalation should only apply
        # when we are confident the model is tree-based.
    }

    # Compute per-stream thresholds so appended streams are analyzed
    # independently even when the file contains mixed-size streams.
    stream_refs: dict[int, list[str]] = {stream_id: [] for stream_id in stream_lengths}
    stream_has_dangerous_globals: dict[int, bool] = dict.fromkeys(stream_lengths, False)

    for idx, (mod, func) in resolved_stack_globals.items():
        if 0 <= idx < len(stream_id_by_index):
            stream_id = stream_id_by_index[idx]
            stream_refs.setdefault(stream_id, []).append(f"{mod}.{func}")
            if _is_actually_dangerous_global(mod, func, ml_context):
                stream_has_dangerous_globals[stream_id] = True

    for idx, (mod, func) in resolved_callables.items():
        if 0 <= idx < len(stream_id_by_index):
            stream_id = stream_id_by_index[idx]
            stream_refs.setdefault(stream_id, []).append(f"{mod}.{func}")
            if resolved_callable_origin_is_ext.get(idx, False) or _is_actually_dangerous_global(mod, func, ml_context):
                stream_has_dangerous_globals[stream_id] = True

    for idx, (op, arg, _p) in enumerate(opcodes):
        if op.name == "GLOBAL" and isinstance(arg, str):
            stream_id = stream_id_by_index[idx]
            stream_refs.setdefault(stream_id, []).append(str(arg))
            parsed = _parse_module_function(arg)
            if parsed:
                mod, func = parsed
                if _is_actually_dangerous_global(mod, func, ml_context):
                    stream_has_dangerous_globals[stream_id] = True

    stream_thresholds: dict[int, int] = {}
    ml_confidence_val = float(ml_context.get("overall_confidence", 0) or 0)
    known_tree_frameworks = _tree_ensemble_frameworks & _ml_frameworks

    for stream_id, stream_length in stream_lengths.items():
        threshold = default_threshold
        refs_str = " ".join(stream_refs.get(stream_id, []))
        refs_str_lower = refs_str.lower()
        has_tree_framework = any(
            f"{framework}." in refs_str_lower
            or f"{framework} " in refs_str_lower
            or refs_str_lower.startswith(framework)
            for framework in known_tree_frameworks
        )
        has_tree_markers = any(marker in refs_str for marker in _tree_ensemble_markers)
        has_dangerous_globals = stream_has_dangerous_globals.get(stream_id, False)

        if (
            ml_context.get("is_ml_content", False)
            and has_tree_framework
            and has_tree_markers
            and not has_dangerous_globals
        ):
            # Tree-ensemble markers in-stream (e.g. RandomForest, DecisionTree)
            # are strong evidence of legitimate model reconstruction behavior.
            # Scale by stream size to handle large tree ensembles, with a
            # moderate fallback when confidence is very low.
            threshold = max(5000, stream_length // 2) if ml_confidence_val >= 0.15 else max(500, stream_length // 10)

        stream_thresholds[stream_id] = threshold

    current_stream_id = 0
    for i, (opcode, arg, pos) in enumerate(opcodes):
        # Reset counters at stream boundaries (STOP) so that multi-stream
        # analysis evaluates each pickle stream independently.  Without this,
        # legitimate ML models with many REDUCE calls spread across multiple
        # streams would accumulate past the threshold.
        if opcode.name == "STOP":
            dangerous_opcode_count = 0
            consecutive_dangerous = 0
            max_consecutive = 0
            last_construction_safe = False
            current_stream_id += 1
            continue

        # Track dangerous opcodes, skipping safe ML globals and structural opcodes
        is_dangerous_opcode = False

        if opcode.name in DANGEROUS_OPCODES:
            # Skip structural/memo opcodes — they cannot execute code on their own
            if opcode.name in _STRUCTURAL_OPCODES:
                pass

            # Special handling for REDUCE - check if it's using safe globals
            elif opcode.name == "REDUCE":
                # Default to dangerous if no associated GLOBAL/STACK_GLOBAL found
                is_dangerous_opcode = True
                last_construction_safe = False
                associated_ref = resolved_callables.get(i)
                if associated_ref:
                    mod, func = associated_ref
                    # Only skip if in safe globals
                    if _is_safe_ml_global(mod, func) and not resolved_callable_origin_is_ext.get(i, False):
                        is_dangerous_opcode = False
                        last_construction_safe = True

            # NEWOBJ/NEWOBJ_EX: check callable refs like REDUCE
            elif opcode.name in ("NEWOBJ", "NEWOBJ_EX"):
                is_dangerous_opcode = True
                last_construction_safe = False
                associated_ref = resolved_callables.get(i)
                if associated_ref:
                    mod, func = associated_ref
                    if _is_safe_ml_global(mod, func) and not resolved_callable_origin_is_ext.get(i, False):
                        is_dangerous_opcode = False
                        last_construction_safe = True

            # BUILD: restores object state via __setstate__.  When the
            # preceding construction used a safe ML global the BUILD is
            # benign — it just sets attributes on a known-safe object.
            elif opcode.name == "BUILD":
                if not last_construction_safe:
                    is_dangerous_opcode = True
                # BUILD does not reset last_construction_safe because
                # multiple BUILD opcodes can follow a single construction
                # (e.g. nested __setstate__ calls in sklearn trees).

            # GLOBAL/STACK_GLOBAL: only count when referencing non-safe modules
            # Also skip counting when the "module" name is not a plausible
            # Python module (e.g. DataFrame column names like "PEDRA_2020").
            elif opcode.name == "GLOBAL" and isinstance(arg, str):
                parts = arg.split(" ", 1) if " " in arg else arg.rsplit(".", 1) if "." in arg else [arg, ""]
                if len(parts) == 2:
                    mod, func = parts
                    if not _is_safe_ml_global(mod, func) and _is_plausible_python_module(mod):
                        is_dangerous_opcode = True
                else:
                    is_dangerous_opcode = True

            elif opcode.name == "STACK_GLOBAL":
                stack_ref = resolved_stack_globals.get(i)
                if stack_ref:
                    mod, func = stack_ref
                    if not _is_safe_ml_global(mod, func) and _is_plausible_python_module(mod):
                        is_dangerous_opcode = True
                else:
                    is_dangerous_opcode = True

            elif opcode.name in ("NEWOBJ", "NEWOBJ_EX"):
                # NEWOBJ/NEWOBJ_EX: check associated class via resolved_callables
                is_dangerous_opcode = True
                associated_ref = resolved_callables.get(i)
                if associated_ref:
                    mod, func = associated_ref
                    if _is_safe_ml_global(mod, func) and not resolved_callable_origin_is_ext.get(i, False):
                        is_dangerous_opcode = False

            else:
                # Other dangerous opcodes (INST, OBJ, EXT*)
                is_dangerous_opcode = True
                last_construction_safe = False

            if is_dangerous_opcode:
                dangerous_opcode_count += 1
                consecutive_dangerous += 1
                max_consecutive = max(max_consecutive, consecutive_dangerous)
            else:
                consecutive_dangerous = 0
        else:
            consecutive_dangerous = 0

        threshold = stream_thresholds.get(current_stream_id, default_threshold)
        if dangerous_opcode_count > threshold:
            suspicious_patterns.append(
                {
                    "pattern": "MANY_DANGEROUS_OPCODES",
                    "count": dangerous_opcode_count,
                    "max_consecutive": max_consecutive,
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
                op2, arg2, _pos2 = opcodes[j]
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

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Additional pickle-specific configuration
        self.max_opcodes = self.config.get("max_opcodes", 1000000)
        configured_post_budget_limit = self.config.get(
            "post_budget_global_scan_limit_bytes",
            _POST_BUDGET_GLOBAL_SCAN_LIMIT_BYTES,
        )
        try:
            parsed_post_budget_limit = int(configured_post_budget_limit)
        except (TypeError, ValueError):
            parsed_post_budget_limit = _POST_BUDGET_GLOBAL_SCAN_LIMIT_BYTES
        self.post_budget_global_scan_limit_bytes = max(0, parsed_post_budget_limit)
        configured_post_budget_global_memo_limit = self.config.get(
            "post_budget_global_memo_limit_entries",
            _POST_BUDGET_GLOBAL_MEMO_LIMIT_ENTRIES,
        )
        try:
            parsed_post_budget_global_memo_limit = int(configured_post_budget_global_memo_limit)
        except (TypeError, ValueError):
            parsed_post_budget_global_memo_limit = _POST_BUDGET_GLOBAL_MEMO_LIMIT_ENTRIES
        self.post_budget_global_memo_limit_entries = max(0, parsed_post_budget_global_memo_limit)
        configured_post_budget_global_max_findings = self.config.get(
            "post_budget_global_max_reference_findings",
            _POST_BUDGET_GLOBAL_MAX_REFERENCE_FINDINGS,
        )
        try:
            parsed_post_budget_global_max_findings = int(configured_post_budget_global_max_findings)
        except (TypeError, ValueError):
            parsed_post_budget_global_max_findings = _POST_BUDGET_GLOBAL_MAX_REFERENCE_FINDINGS
        self.post_budget_global_max_reference_findings = max(0, parsed_post_budget_global_max_findings)
        self._post_budget_global_memo_limit_exceeded = False
        self._post_budget_global_reference_limit_exceeded = False
        self._post_budget_global_scan_deadline_exceeded = False
        configured_post_budget_expansion_limit = self.config.get(
            "post_budget_expansion_scan_limit_bytes",
            min(self.post_budget_global_scan_limit_bytes, _POST_BUDGET_EXPANSION_SCAN_LIMIT_BYTES),
        )
        try:
            parsed_post_budget_expansion_limit = int(configured_post_budget_expansion_limit)
        except (TypeError, ValueError):
            parsed_post_budget_expansion_limit = min(
                self.post_budget_global_scan_limit_bytes,
                _POST_BUDGET_EXPANSION_SCAN_LIMIT_BYTES,
            )
        self.post_budget_expansion_scan_limit_bytes = max(0, parsed_post_budget_expansion_limit)
        # Initialize analyzers
        self.entropy_analyzer = EntropyAnalyzer()
        self.semantic_analyzer = SemanticAnalyzer()
        self.framework_kb = FrameworkKnowledgeBase()

        # Initialize enhanced analysis components
        self.opcode_sequence_analyzer = OpcodeSequenceAnalyzer()
        self.ml_context_analyzer = MLContextAnalyzer()
        self.enhanced_pattern_detector = EnhancedPatternDetector()

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if the file is a pickle based on extension and content"""
        file_ext = os.path.splitext(path)[1].lower()

        # For known pickle extensions, always handle
        if file_ext in [".pkl", ".pickle", ".dill", ".joblib"]:
            return True

        try:
            # Import here to avoid circular dependency
            from modelaudit.utils.file.detection import (
                detect_file_format,
                validate_file_type,
            )

            file_format = detect_file_format(path)
        except Exception:
            # If type detection fails, fall back to a bounded pickle probe
            # instead of routing ambiguous extensions on suffix alone.
            try:
                with open(path, "rb") as handle:
                    return _looks_like_pickle(handle.read(_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES))
            except OSError:
                return False

        # For security-sensitive pickle files, also validate file type.
        # Validation errors must not override a positive pickle detection.
        if file_format == "pickle":
            try:
                if not validate_file_type(path):
                    # File type validation failed - this could be suspicious
                    # Log but still allow scanning for now (let scanner handle the validation)
                    logger.warning(
                        f"File type validation failed for potential pickle file: {path}",
                    )
            except Exception as validation_error:
                logger.warning(
                    f"File type validation errored for potential pickle file {path}: {validation_error}",
                )
            return True

        # Handle both pickle and zip formats (PyTorch .bin files are often zip).
        # PyTorch files saved with torch.save() are ZIP archives containing pickled data.
        if file_format == "zip" and file_ext in [".bin", ".pt", ".pth"]:
            # PyTorch ZIP files should be handled by PyTorchZipScanner or PyTorchBinaryScanner
            # The pickle scanner shouldn't try to parse them as regular pickle files
            return False

        return False

    def _get_surrounding_data(self, data: bytes, position: int, window_size: int = 1024) -> bytes:
        """Get data surrounding a specific position for analysis."""
        start = max(0, position - window_size // 2)
        end = min(len(data), position + window_size // 2)
        return data[start:end]

    @staticmethod
    def _is_zip_backed_pytorch_container(path: str) -> bool:
        """Return whether the path is a ZIP-backed PyTorch-style container."""
        file_ext = os.path.splitext(path)[1].lower()
        if file_ext not in {".bin", ".pt", ".pth", ".ckpt", ".pkl"}:
            return False

        try:
            from modelaudit.utils.file.detection import detect_file_format

            return detect_file_format(path) == "zip"
        except Exception:
            return False

    def _scan_zip_backed_pytorch_container(self, path: str) -> ScanResult | None:
        """Delegate ZIP-backed PyTorch-style containers to the ZIP scanner."""
        if not self._is_zip_backed_pytorch_container(path):
            return None

        try:
            from .pytorch_zip_scanner import PyTorchZipScanner
        except Exception as e:
            logger.warning(f"Unable to load PyTorch ZIP scanner for {path}: {e}")
            return None

        logger.debug(f"Delegating ZIP-backed PyTorch container to PyTorchZipScanner: {path}")
        return PyTorchZipScanner(config=self.config).scan(path, timeout=self.timeout)

    def _record_pickle_operational_error(
        self,
        result: ScanResult,
        error: Exception,
        *,
        location: str,
        check_name: str,
        message: str,
        reason: str,
    ) -> None:
        """Record a pickle operational failure with an explicit classification."""
        result.add_check(
            name=check_name,
            passed=False,
            message=message,
            severity=IssueSeverity.CRITICAL,
            location=location,
            details={"exception": str(error), "exception_type": type(error).__name__},
        )
        result.metadata["operational_error"] = True
        result.metadata["operational_error_reason"] = reason

    def _record_pickle_open_error(self, result: ScanResult, error: Exception, *, location: str) -> None:
        """Record a file access failure while preparing the pickle scan."""
        self._record_pickle_operational_error(
            result,
            error,
            location=location,
            check_name="Pickle File Open",
            message=f"Error opening pickle file: {error!s}",
            reason="pickle_file_open_failed",
        )

    def _record_pickle_runtime_error(self, result: ScanResult, error: Exception, *, location: str) -> None:
        """Record an unexpected runtime failure during pickle analysis."""
        self._record_pickle_operational_error(
            result,
            error,
            location=location,
            check_name="Pickle Scanner Runtime Error",
            message=f"Scanner runtime failure while analyzing pickle file: {error!s}",
            reason="pickle_scan_runtime_failed",
        )

    def scan(self, path: str) -> ScanResult:
        """Scan a pickle file for suspicious content"""
        # Start scan timer for timeout tracking
        self._start_scan_timer()

        # Initialize context for this file
        self._initialize_context(path)

        # Reset analyzers for clean state
        if hasattr(self, "opcode_sequence_analyzer"):
            self.opcode_sequence_analyzer.reset()

        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        zip_container_result = self._scan_zip_backed_pytorch_container(path)
        if zip_container_result is not None:
            return zip_container_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        # Check if this is a .bin file that might be a PyTorch file
        is_bin_file = os.path.splitext(path)[1].lower() == ".bin"

        # Run a bounded raw scan before pickle parsing. Track completion only,
        # not a synthetic "clean" sentinel check.
        early_pattern_scan_completed = False
        pickle_file_opened = False

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

            # Use the refactored method to scan for dangerous patterns.
            self._scan_for_dangerous_patterns(raw_content, result, path)
            early_pattern_scan_completed = True

        except RecursionError:
            logger.warning(f"Recursion error during early pattern detection for {path}")
            # Continue with main scan despite error
        except Exception as e:
            logger.warning(f"Error during early pattern detection: {e}")

        try:
            with open(path, "rb") as f:
                pickle_file_opened = True
                # Store the file path for use in issue locations
                self.current_file_path = path
                scan_result = self._scan_pickle_bytes(f, file_size)
                result.merge(scan_result)
                if (
                    not scan_result.success
                    and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
                    and not result.metadata.get("operational_error")
                    and not _scan_result_has_security_findings(result)
                ):
                    fallback_reason = (
                        "scan_timeout"
                        if any(
                            check.name == "Scan Timeout Check" and check.status == CheckStatus.FAILED
                            for check in result.checks
                        )
                        else "incomplete_analysis"
                    )
                    _mark_inconclusive_scan_result(result, fallback_reason)

                # For .bin files, also scan the remaining binary content after
                # the first pickle stream when we have a trusted boundary.
                self._scan_remaining_bin_tail_if_needed(
                    f,
                    result,
                    file_size=file_size,
                    scan_bin_tail=is_bin_file,
                )

        except Exception as e:
            # Check if we already found security issues in the early pattern detection
            # If so, we should preserve those findings even if we hit recursion errors
            has_security_findings = _scan_result_has_security_findings(result)

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
            if has_security_findings and is_recursion_error:
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
                _mark_inconclusive_scan_result(result, "recursion_limit_exceeded")
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
                        "analysis_incomplete": True,
                    },
                    why=(
                        "The scan encountered recursion limits but already detected security issues in the file. "
                        "The identified security issues are valid findings that should be addressed."
                    ),
                )
                _finish_with_inconclusive_contract(result, default_success=True)
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
                _mark_inconclusive_scan_result(result, "recursion_limit_exceeded")
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
                        "scanner_limitation": True,
                        "analysis_incomplete": True,
                    },
                    why=(
                        "This model file contains complex nested structures that exceed the scanner's "
                        "complexity limits. Complex model architectures with deeply nested structures can "
                        "exceed Python's recursion limits during analysis. The file appears legitimate based "
                        "on format validation."
                    ),
                    rule_code=None,  # Passing check
                )
                _finish_with_inconclusive_contract(result, default_success=True)
                return result
            if is_recursion_error:
                # Flag extremely small files with malicious patterns
                filename = os.path.basename(path).lower()
                is_malicious_name = any(pattern in filename for pattern in ["malicious", "evil", "hack", "exploit"])
                is_very_small = file_size < 80

                if is_malicious_name and is_very_small and not early_pattern_scan_completed:
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
                            "early_detection_successful": early_pattern_scan_completed,
                            "suspicious_filename": is_malicious_name,
                            "analysis_incomplete": True,
                        },
                        why=(
                            "This very small file has a suspicious filename and caused recursion errors "
                            "during pattern detection, which strongly suggests it's a maliciously crafted pickle."
                        ),
                        rule_code="S902",
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
                            "early_detection_successful": early_pattern_scan_completed,
                            "scanner_limitation": True,
                            "analysis_incomplete": True,
                        },
                        why=(
                            "The pickle file structure is too complex for the scanner to fully analyze due to "
                            "Python's recursion limits. This often occurs with legitimate but complex data structures. "
                            "Consider manually inspecting the file if security is a concern."
                        ),
                        rule_code="S201",
                    )

                result.metadata.update(
                    {
                        "recursion_limited": True,
                        "file_size": file_size,
                        "scanner_limitation": True,
                    }
                )
                _mark_inconclusive_scan_result(result, "recursion_limit_exceeded")
                _finish_with_inconclusive_contract(result, default_success=True)
                return result

            # Handle different types of parsing errors more gracefully
            if self._is_pickle_parse_failure(e):
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
                            "early_detection_successful": early_pattern_scan_completed,
                        },
                        why=(
                            "This binary file does not contain valid pickle data structure. "
                            "Binary content was analyzed for security patterns instead."
                        ),
                    )

                    result.metadata.update(
                        {
                            "file_type": "binary",
                            "pickle_parsing_failed": True,
                        }
                    )
                    self._scan_binary_content_from_path(path, result, file_size)
                    result.finish(success=True)
                    return result

                elif file_ext in [".pkl", ".pickle", ".joblib", ".dill", ".pt", ".pth", ".ckpt"]:
                    # Pickle-like files must fail closed when parsing aborts on unknown opcodes.
                    logger.warning(f"Pickle parse failed for {path}: {e}")
                    result.add_check(
                        name="Pickle Format Check",
                        passed=False,
                        message="Pickle parsing failed before full scan completion",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "file_type": "pickle",
                            "parse_error": str(e),
                            "early_detection_successful": early_pattern_scan_completed,
                            "parsing_failed": True,
                            "failure_reason": "unknown_opcode_or_format_error",
                        },
                        why=(
                            "The scanner could not fully parse this pickle file due to an opcode/format error. "
                            "Because full opcode analysis did not complete, the file is treated as unsafe."
                        ),
                    )

                    # Fail closed metadata for parse failures on pickle-like files.
                    result.metadata.update(
                        {
                            "file_type": "pickle",
                            "parsing_failed": True,
                            "failure_reason": "unknown_opcode_or_format_error",
                        }
                    )

                    result.finish(success=False)
                    return result

            if pickle_file_opened:
                self._record_pickle_runtime_error(result, e, location=path)
            else:
                self._record_pickle_open_error(result, e, location=path)
            result.finish(success=False)
            return result

        has_critical_post_budget_failure = any(
            check.name in {"Post-Budget Global Reference Scan", "Post-Budget Opcode Detection"}
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            for check in result.checks
        )
        if has_critical_post_budget_failure:
            _finish_with_inconclusive_contract(result, default_success=False)
        else:
            _finish_with_inconclusive_contract(
                result,
                default_success=scan_result.success,
                allow_security_findings_override=True,
            )
        return result

    def _is_pickle_parse_failure(self, error: Exception) -> bool:
        """Return whether an exception looks like a pickle/format parse failure."""
        if not isinstance(error, (EOFError, ValueError, struct.error)):
            return False

        error_message = str(error).lower()
        return (
            "opcode" in error_message
            or "unknown" in error_message
            or "pickle exhausted before seeing stop" in error_message
            or ("expected" in error_message and "bytes" in error_message and "but only" in error_message)
            or "truncated" in error_message
            or "unpack requires" in error_message
            or "bad marshal data" in error_message
            or "no newline found" in error_message
        )

    def _merge_binary_content_findings(self, result: ScanResult, binary_result: ScanResult) -> None:
        """Copy binary scan findings into the primary scan result."""
        for issue in binary_result.issues:
            result.add_check(
                name="Binary Content Check",
                passed=False,
                message=issue.message,
                severity=issue.severity,
                location=issue.location,
                details=issue.details,
                why=issue.why,
                rule_code=issue.rule_code,
            )

    def _scan_binary_payload(
        self,
        file_obj: BinaryIO,
        result: ScanResult,
        *,
        start_pos: int,
        file_size: int,
        full_file: bool = False,
    ) -> None:
        """Scan binary bytes either after the first pickle stream or across the full file."""
        file_obj.seek(start_pos)
        binary_result = self._scan_binary_content(file_obj, start_pos, file_size)
        self._merge_binary_content_findings(result, binary_result)
        expected_binary_bytes = file_size if full_file else max(file_size - start_pos, 0)
        actual_binary_bytes = max(0, min(binary_result.bytes_scanned, expected_binary_bytes))
        total_scanned = actual_binary_bytes if full_file else start_pos + actual_binary_bytes
        result.bytes_scanned = max(result.bytes_scanned, total_scanned)
        result.metadata["binary_scan_completed"] = actual_binary_bytes >= expected_binary_bytes
        result.metadata["binary_scan_bytes_scanned"] = actual_binary_bytes
        result.metadata["binary_scan_total_bytes"] = expected_binary_bytes
        if full_file:
            result.metadata["binary_bytes"] = file_size
        else:
            result.metadata["pickle_bytes"] = start_pos
            result.metadata["binary_bytes"] = expected_binary_bytes

    def _scan_remaining_bin_tail_if_needed(
        self,
        file_obj: BinaryIO,
        result: ScanResult,
        *,
        file_size: int,
        scan_bin_tail: bool,
    ) -> None:
        """Scan trailing bytes in .bin containers after the first pickle stream completes."""
        if not scan_bin_tail:
            return

        pickle_end_pos = result.metadata.get("first_pickle_end_pos")
        if not isinstance(pickle_end_pos, int):
            return

        remaining_bytes = file_size - pickle_end_pos
        if remaining_bytes <= 0:
            return

        self._scan_binary_payload(
            file_obj,
            result,
            start_pos=pickle_end_pos,
            file_size=file_size,
        )

    def _scan_binary_content_from_path(self, path: str, result: ScanResult, file_size: int, start_pos: int = 0) -> None:
        """Scan file bytes directly when pickle parsing did not yield a trusted boundary."""
        try:
            with open(path, "rb") as f:
                self._scan_binary_payload(
                    f,
                    result,
                    start_pos=start_pos,
                    file_size=file_size,
                    full_file=start_pos == 0,
                )
        except Exception as binary_scan_error:
            logger.warning(f"Binary scan failed for {path}: {binary_scan_error}")
            result.metadata["binary_scan_failed"] = str(binary_scan_error)
            return

    def _scan_for_dangerous_patterns(self, data: bytes, result: ScanResult, context_path: str) -> None:
        """Enhanced scan for dangerous patterns with ML context awareness and obfuscation detection."""
        # Use enhanced pattern detector with context
        context = {
            "file_path": context_path,
            "stack_state": getattr(self.opcode_sequence_analyzer, "stack_simulation", []),
        }

        # Detect patterns using enhanced analyzer
        pattern_matches = self.enhanced_pattern_detector.detect_patterns(data, context)

        # Process matches and create appropriate checks
        if pattern_matches:
            # Group matches by pattern type for better reporting
            pattern_groups: dict[str, list[PatternMatch]] = {}
            for match in pattern_matches:
                pattern_name = match.pattern_name
                if pattern_name not in pattern_groups:
                    pattern_groups[pattern_name] = []
                pattern_groups[pattern_name].append(match)

            # Create checks for each pattern group
            for _pattern_name, matches in pattern_groups.items():
                self._create_enhanced_pattern_check(matches, result, context_path)

        # Legacy pattern detection for backwards compatibility
        self._scan_legacy_patterns(data, result, context_path)

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

        # Fallback heuristic for CVE-2020-13092 if analyzer missed it (e.g., partial pickle bytes)
        content_lower = content_str.lower()
        if (
            not cve_attributions
            and "joblib" in content_lower
            and "__reduce__" in content_lower
            and ("os.system" in content_lower or "subprocess" in content_lower)
        ):
            from modelaudit.detectors.cve_patterns import CVEAttribution

            cve_attributions.append(
                CVEAttribution(
                    cve_id="CVE-2020-13092",
                    description="scikit-learn/joblib deserialization RCE via __reduce__ and os.system",
                    severity="CRITICAL",
                    cvss=9.8,
                    cwe="CWE-502",
                    affected_versions="sklearn <=0.23.0",
                    remediation="Upgrade scikit-learn/joblib; avoid untrusted pickles",
                    confidence=0.6,
                    patterns_matched=["heuristic joblib + __reduce__ + os/system"],
                )
            )

        if cve_attributions:
            # Enhance scan result with CVE information
            enhance_scan_result_with_cve(result, [content_str], data)

            # Add specific CVE detection checks
            for attr in cve_attributions:
                severity = IssueSeverity.CRITICAL if attr.severity == "CRITICAL" else IssueSeverity.WARNING

                # Check if this is a high-confidence detection
                confidence_desc = "high" if attr.confidence > 0.8 else "medium" if attr.confidence > 0.6 else "low"

                # Determine rule code based on the dangerous pattern
                pattern_rule_code = None
                pattern_str = attr.patterns_matched[0] if attr.patterns_matched else ""
                if pattern_str == "posix":
                    pattern_rule_code = "S101"  # os/posix module
                elif pattern_str == "system":
                    pattern_rule_code = "S101"  # os.system
                elif pattern_str == "subprocess":
                    pattern_rule_code = "S103"
                elif pattern_str == "eval" or pattern_str == "exec":
                    pattern_rule_code = "S104"
                elif pattern_str == "__import__":
                    pattern_rule_code = "S106"
                elif pattern_str == "compile":
                    pattern_rule_code = "S105"
                elif pattern_str in ["__builtin__", "__builtins__", "builtins"]:
                    pattern_rule_code = "S115"

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
                    rule_code=pattern_rule_code,
                )

    def _create_enhanced_pattern_check(self, matches: Any, result: ScanResult, context_path: str) -> None:
        """Create a check for enhanced pattern matches with ML context awareness."""
        if not matches:
            return

        # Use the first match as representative (they're all the same pattern type)
        representative = matches[0]
        pattern_name = representative.pattern_name
        severity = representative.severity

        # Calculate effective risk considering ML context and confidence
        max_confidence = max(match.confidence for match in matches)
        min_ml_adjustment = min(match.ml_context_adjustment for match in matches)
        effective_severity = self._calculate_effective_severity(severity, min_ml_adjustment, max_confidence)

        # Create detailed message
        if len(matches) == 1:
            match = matches[0]
            if match.deobfuscated_text:
                message = f"Detected {pattern_name} pattern in deobfuscated content: '{match.matched_text}'"
            else:
                message = f"Detected {pattern_name} pattern: '{match.matched_text}'"

            # Add ML context explanation if significant adjustment
            if match.ml_context_adjustment < 0.7:
                ml_explanation = match.context.get("ml_explanation", "")
                if ml_explanation:
                    message += f" (Risk reduced due to ML context: {ml_explanation})"
        else:
            # Get unique matched texts for better specificity
            unique_matches = list({match.matched_text for match in matches})
            if len(unique_matches) <= 3:
                match_text = ", ".join(f"'{m}'" for m in unique_matches)
                message = f"Detected {pattern_name} pattern: {match_text}"
            else:
                message = f"Detected {len(matches)} instances of {pattern_name} pattern"

            ml_adjusted_count = sum(1 for m in matches if m.ml_context_adjustment < 0.9)
            if ml_adjusted_count > 0:
                message += f" ({ml_adjusted_count} with reduced risk due to ML context)"

        # Collect details
        details = {
            "pattern_type": pattern_name,
            "matches_found": len(matches),
            "confidence": max_confidence,
            "ml_risk_adjustment": min_ml_adjustment,
            "effective_severity": effective_severity,
            "detection_method": "enhanced_pattern_detection",
        }

        # Add obfuscation details if any matches were deobfuscated
        deobfuscated_matches = [m for m in matches if m.deobfuscated_text]
        if deobfuscated_matches:
            details["obfuscation_detected"] = True
            details["deobfuscated_samples"] = [m.deobfuscated_text for m in deobfuscated_matches[:3]]

        # Add ML context details if available
        if matches[0].context.get("ml_framework"):
            details["ml_framework"] = matches[0].context["ml_framework"]
            details["ml_confidence"] = matches[0].context.get("ml_confidence", 0)

        # Create the check with appropriate severity
        result.add_check(
            name=f"Enhanced Pattern Detection: {pattern_name.replace('_', ' ').title()}",
            passed=False,
            message=message,
            severity=effective_severity,
            location=context_path,
            details=details,
            why=self._generate_pattern_explanation(representative, min_ml_adjustment),
        )

    def _calculate_effective_severity(
        self, base_severity: str, ml_adjustment: float, confidence: float = 1.0
    ) -> IssueSeverity:
        """Calculate effective severity considering ML context adjustment and confidence."""
        # If confidence is very low, reduce severity
        if confidence < 0.3:  # Very low confidence
            if base_severity == "critical":
                return IssueSeverity.WARNING
            elif base_severity == "warning":
                return IssueSeverity.INFO

        # If ML context reduces risk significantly, lower severity
        if ml_adjustment < 0.3:  # 70%+ risk reduction
            if base_severity == "critical":
                return IssueSeverity.WARNING
            elif base_severity == "warning":
                return IssueSeverity.INFO
        elif ml_adjustment < 0.6 and base_severity == "critical":  # 40%+ risk reduction
            return IssueSeverity.WARNING

        # Map base severity to IssueSeverity enum
        severity_map = {
            "critical": IssueSeverity.CRITICAL,
            "warning": IssueSeverity.WARNING,
            "info": IssueSeverity.INFO,
        }

        return severity_map.get(base_severity, IssueSeverity.WARNING)

    def _generate_pattern_explanation(self, match: Any, ml_adjustment: float) -> str:
        """Generate explanation for why a pattern is dangerous."""
        base_explanation = (
            f"The pattern '{match.pattern_name}' indicates potential {match.context.get('category', 'security')} risks."
        )

        if match.deobfuscated_text:
            base_explanation += (
                " The pattern was detected after deobfuscating encoded content, "
                "which is often used to hide malicious intent."
            )

        if ml_adjustment < 0.7:
            base_explanation += (
                " However, this appears to be in the context of legitimate ML framework operations, "
                "which reduces the risk significantly."
            )

        return base_explanation

    def _scan_legacy_patterns(self, data: bytes, result: ScanResult, context_path: str) -> None:
        """Legacy pattern detection for backwards compatibility."""
        # Keep existing pattern detection logic for patterns not covered by enhanced detector
        dangerous_patterns = [
            # CVE-2025-32434 specific patterns - PyTorch weights_only=True bypass techniques
            b"torch.load",  # Direct torch.load references in payload
            b"weights_only",  # References to the weights_only parameter
        ]

        # Add all binary code patterns to ensure consistency with binary scanning
        dangerous_patterns.extend(BINARY_CODE_PATTERNS)
        dangerous_patterns.extend(CVE_BINARY_PATTERNS)

        # Simple pattern matching for legacy compatibility
        for pattern in dangerous_patterns:
            if pattern in data:
                pattern_str = pattern.decode("utf-8", errors="replace")
                result.add_check(
                    name="Legacy Pattern Detection",
                    passed=False,
                    message=f"Legacy dangerous pattern detected: {pattern_str}",
                    severity=IssueSeverity.WARNING,
                    location=context_path,
                    details={"pattern": pattern_str, "detection_method": "legacy_pattern_matching"},
                )

    def _create_opcode_sequence_check(self, sequence_result: Any, result: ScanResult) -> None:
        """Create a check for detected dangerous opcode sequences."""
        # Map severity to IssueSeverity enum
        severity_map = {
            "critical": IssueSeverity.CRITICAL,
            "warning": IssueSeverity.WARNING,
            "info": IssueSeverity.INFO,
        }
        severity = severity_map.get(sequence_result.severity, IssueSeverity.WARNING)

        # Create detailed message
        message = f"Dangerous opcode sequence detected: {' → '.join(sequence_result.matched_opcodes)}"

        # Add stack context if available
        stack_info = ""
        if sequence_result.evidence.get("stack_state"):
            stack_context = sequence_result.evidence["stack_state"]
            if stack_context:
                # Show the most relevant stack items
                relevant_items = [str(item) for item in stack_context[-3:] if item]
                if relevant_items:
                    stack_info = f" (Stack context: {' → '.join(relevant_items)})"
                    message += stack_info

        # Create the check
        result.add_check(
            name=f"Opcode Sequence Analysis: {sequence_result.pattern_name.replace('_', ' ').title()}",
            passed=False,
            message=message,
            severity=severity,
            location=f"{self.current_file_path} (pos {sequence_result.position})"
            if sequence_result.position
            else self.current_file_path,
            details={
                "pattern_name": sequence_result.pattern_name,
                "matched_opcodes": sequence_result.matched_opcodes,
                "confidence": sequence_result.confidence,
                "evidence": sequence_result.evidence,
                "detection_method": "opcode_sequence_analysis",
            },
            why=(
                f"{sequence_result.description}. This sequence of opcodes can be used to execute "
                "arbitrary code during unpickling."
            ),
        )

    def _build_pickle_opcode_analysis(
        self,
        data: BinaryIO,
        *,
        multiple_pickles: bool,
        scan_start_time: float | None = None,
        include_sequence_analysis: bool,
        include_stack_metrics: bool,
        probe_for_budget_exceeded: bool,
        skip_symbolic_postprocessing_on_timeout: bool = False,
    ) -> _PickleOpcodeAnalysis:
        """Walk pickle opcodes once and retain the shared analysis state."""

        effective_scan_start_time = scan_start_time if scan_start_time is not None else self.scan_start_time
        deadline = effective_scan_start_time + self.timeout if effective_scan_start_time is not None else None
        opcode_limit = self.max_opcodes
        analysis = _PickleOpcodeAnalysis(max_analyzed_end_offset=data.tell())
        max_items = opcode_limit + 1 if probe_for_budget_exceeded else opcode_limit

        current_stack_depth = 0
        base_stack_depth_limit = 3000

        try:
            for opcode, arg, pos in _genops_with_fallback(
                data,
                multi_stream=multiple_pickles,
                max_items=max_items,
                deadline=deadline,
            ):
                if include_sequence_analysis and analysis.opcode_count % 1000 == 0:
                    self.check_interrupted()

                analysis.opcodes.append((opcode, arg, pos))
                analysis.max_analyzed_end_offset = max(analysis.max_analyzed_end_offset, data.tell())
                analysis.opcode_count += 1

                op_name = opcode.name
                if op_name in {"GLOBAL", "INST"} and isinstance(arg, str):
                    parsed = _parse_module_function(arg)
                    if parsed is not None:
                        analysis.globals_found.add((*parsed, op_name))

                if include_sequence_analysis:
                    sequence_results = self.opcode_sequence_analyzer.analyze_opcode(op_name, arg, pos)
                    if sequence_results:
                        analysis.sequence_results.extend(sequence_results)

                if include_stack_metrics:
                    if op_name in {"MARK", "TUPLE", "LIST", "DICT", "FROZENSET", "INST", "OBJ", "BUILD"}:
                        current_stack_depth += 1
                        analysis.max_stack_depth = max(analysis.max_stack_depth, current_stack_depth)
                    elif op_name in {"POP", "POP_MARK", "SETITEM", "SETITEMS", "APPEND", "APPENDS"}:
                        current_stack_depth = max(0, current_stack_depth - 1)
                    elif op_name == "STOP":
                        current_stack_depth = 0

                    if current_stack_depth > base_stack_depth_limit:
                        analysis.stack_depth_warnings.append(
                            {
                                "current_depth": int(current_stack_depth),
                                "position": int(pos) if pos is not None else 0,
                                "opcode": str(op_name),
                            }
                        )
                        if current_stack_depth > base_stack_depth_limit * 10:
                            analysis.extreme_stack_depth_event = {
                                "current_depth": int(current_stack_depth),
                                "position": int(pos) if pos is not None else 0,
                                "opcode": str(op_name),
                                "max_allowed": base_stack_depth_limit * 10,
                            }
                            break

                if op_name == "STOP" and analysis.first_pickle_end_pos is None and pos is not None:
                    analysis.first_pickle_end_pos = int(pos) + 1

                if probe_for_budget_exceeded and analysis.opcode_count > opcode_limit:
                    analysis.opcode_budget_exceeded = True
                    break

                if deadline is not None and time.time() > deadline:
                    analysis.timeout_exceeded = True
                    break

        except _GenopsBudgetExceeded as e:
            if e.reason == "max_items":
                analysis.opcode_budget_exceeded = True
            else:
                analysis.timeout_exceeded = True
        except Exception as e:
            analysis.error = e

        if analysis.opcodes and not (skip_symbolic_postprocessing_on_timeout and analysis.timeout_exceeded):
            (
                analysis.stack_global_refs,
                analysis.callable_refs,
                analysis.callable_origin_refs,
                analysis.callable_origin_is_ext,
                analysis.malformed_stack_globals,
                analysis.mutation_target_refs,
            ) = _simulate_symbolic_reference_maps(analysis.opcodes)

            for index, resolved in analysis.stack_global_refs.items():
                analysis.globals_found.add((*resolved, analysis.opcodes[index][0].name))

            analysis.executed_import_origins = set(analysis.callable_origin_refs.values())
            analysis.executed_ref_keys = {
                _normalize_import_reference(mod, func) for mod, func in analysis.callable_refs.values()
            }

        analysis.max_analyzed_offset = max(
            (int(pos) for _opcode, _arg, pos in analysis.opcodes if pos is not None),
            default=-1,
        )
        return analysis

    def _extract_globals_advanced(
        self,
        data: BinaryIO,
        multiple_pickles: bool = True,
        scan_start_time: float | None = None,
    ) -> set[tuple[str, str, str]]:
        """Advanced pickle global extraction with STACK_GLOBAL and memo support."""
        analysis = self._build_pickle_opcode_analysis(
            data,
            multiple_pickles=multiple_pickles,
            scan_start_time=scan_start_time,
            include_sequence_analysis=False,
            include_stack_metrics=False,
            probe_for_budget_exceeded=False,
            skip_symbolic_postprocessing_on_timeout=True,
        )

        if analysis.opcode_budget_exceeded:
            logger.warning(f"Advanced global extraction stopped after reaching max_opcodes ({self.max_opcodes})")
        elif analysis.timeout_exceeded:
            logger.warning(f"Advanced global extraction stopped after exceeding timeout ({self.timeout}s)")
        elif analysis.error is not None:
            if analysis.globals_found:
                logger.warning(
                    f"Pickle parsing failed, but found {len(analysis.globals_found)} globals: {analysis.error}"
                )
            else:
                logger.debug(f"Pickle parsing failed during advanced global extraction: {analysis.error}")

        return analysis.globals_found

    def _extract_stack_global_values(
        self, ops: list[tuple[Any, Any, int | None]], position: int, memo: dict[int | str, str]
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
            elif op_name in STRING_OPCODES:
                values.append(str(op_value))
            else:
                logger.debug(f"Non-string opcode {op_name} in STACK_GLOBAL analysis")
                values.append("unknown")

            if len(values) == 2:
                break

        return values

    def _read_post_budget_window(
        self,
        file_obj: BinaryIO,
        *,
        file_size: int,
        minimum_offset: int,
        scan_limit_bytes: int,
        context_bytes: int | None = None,
    ) -> tuple[bytes, int, int]:
        """Read a bounded post-budget window, optionally rewinding for lookback context."""
        minimum_offset = max(0, minimum_offset)
        resolved_context_bytes = min(
            minimum_offset,
            _POST_BUDGET_GLOBAL_CONTEXT_BYTES if context_bytes is None else max(0, int(context_bytes)),
        )
        tail_scan_bytes = min(max(file_size - minimum_offset, 0), scan_limit_bytes)
        if tail_scan_bytes <= 0:
            return b"", 0, 0

        scan_start = max(0, minimum_offset - resolved_context_bytes)
        read_size = resolved_context_bytes + tail_scan_bytes

        original_pos = file_obj.tell()
        try:
            file_obj.seek(scan_start)
            data = file_obj.read(read_size)
        finally:
            file_obj.seek(original_pos)

        return data, scan_start, tail_scan_bytes

    def _select_post_budget_opcode_context(
        self,
        analyzed_opcodes: list[tuple[Any, Any, int | None]],
        *,
        minimum_offset: int,
    ) -> list[tuple[Any, Any, int | None]]:
        """Return the already-parsed opcode suffix that overlaps the lookback window."""
        if not analyzed_opcodes:
            return []

        lookback_start = max(0, minimum_offset - _POST_BUDGET_GLOBAL_CONTEXT_BYTES)
        context_start = len(analyzed_opcodes)
        next_offset = minimum_offset

        for index in range(len(analyzed_opcodes) - 1, -1, -1):
            _opcode, _arg, pos = analyzed_opcodes[index]
            if next_offset <= lookback_start:
                break
            context_start = index
            if pos is not None:
                next_offset = int(pos)

        return analyzed_opcodes[context_start:]

    def _collect_post_budget_opcodes(
        self,
        data: bytes,
        *,
        scan_start: int,
        deadline: float | None,
        scan_label: str,
        opcode_limit: int | None = None,
    ) -> list[tuple[Any, Any, int | None]]:
        """Decode a tail window without retaining an unbounded opcode list."""
        resolved_opcode_limit = (
            _POST_BUDGET_OPCODE_SCAN_LIMIT_OPCODES if opcode_limit is None else max(0, int(opcode_limit))
        )
        if not data or resolved_opcode_limit <= 0:
            return []

        opcodes: list[tuple[Any, Any, int | None]] = []
        tail_stream = io.BytesIO(data)
        try:
            for opcode, arg, pos in _genops_with_fallback(
                tail_stream,
                multi_stream=True,
                max_items=min(len(data), resolved_opcode_limit),
                deadline=deadline,
            ):
                shifted_pos = scan_start + int(pos) if pos is not None else None
                opcodes.append((opcode, arg, shifted_pos))
        except _GenopsBudgetExceeded as exc:
            if exc.reason == "deadline":
                logger.debug(
                    "Post-budget %s scan stopped after exceeding timeout (%ss)",
                    scan_label,
                    self.timeout,
                )
            elif exc.reason == "max_items":
                logger.debug(
                    "Post-budget %s scan stopped after reaching opcode cap (%s)",
                    scan_label,
                    min(len(data), resolved_opcode_limit),
                )
        except Exception as exc:
            logger.debug("Post-budget %s scan failed: %s", scan_label, exc)

        return opcodes

    def _scan_global_references_unbounded(
        self,
        file_obj: BinaryIO,
        *,
        file_size: int,
        minimum_offset: int,
        ml_context: dict[str, Any],
        deadline: float | None = None,
    ) -> list[dict[str, Any]]:
        """Perform a post-budget raw byte scan for GLOBAL/INST/STACK_GLOBAL references."""
        findings: list[dict[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        classified_refs: OrderedDict[str, tuple[bool, IssueSeverity | None, str]] = OrderedDict()
        classification_cache_limit = max(1, self.post_budget_global_max_reference_findings)
        recorded_critical_reference = False
        self._post_budget_global_memo_limit_exceeded = False
        self._post_budget_global_reference_limit_exceeded = False
        self._post_budget_global_scan_deadline_exceeded = False

        minimum_offset = max(0, minimum_offset)
        data, scan_start, _tail_scan_bytes = self._read_post_budget_window(
            file_obj,
            file_size=file_size,
            minimum_offset=minimum_offset,
            scan_limit_bytes=self.post_budget_global_scan_limit_bytes,
        )
        if not data:
            return findings
        data_len = len(data)

        def _might_be_critical_reference(module: str, function: str) -> bool:
            if not _is_resolved_import_target(module, function):
                return False

            normalized_mod, normalized_func = _normalize_import_reference(module, function)
            if _is_safe_ml_global(module, function) or (
                (normalized_mod, normalized_func) != (module, function)
                and _is_safe_ml_global(normalized_mod, normalized_func)
            ):
                return False
            if (normalized_mod, normalized_func) in IMPORT_ONLY_ALWAYS_DANGEROUS_GLOBALS:
                return True
            if _is_copyreg_extension_ref(module) or (
                (normalized_mod, normalized_func) != (module, function) and _is_copyreg_extension_ref(normalized_mod)
            ):
                return True
            if _is_risky_ml_import(module, function) or (
                (normalized_mod, normalized_func) != (module, function)
                and _is_risky_ml_import(normalized_mod, normalized_func)
            ):
                return True

            if (
                f"{module}.{function}" in ALWAYS_DANGEROUS_FUNCTIONS
                or function in ALWAYS_DANGEROUS_FUNCTIONS
                or f"{normalized_mod}.{normalized_func}" in ALWAYS_DANGEROUS_FUNCTIONS
                or normalized_func in ALWAYS_DANGEROUS_FUNCTIONS
            ):
                return True

            if is_suspicious_global(module, function) or (
                (normalized_mod, normalized_func) != (module, function)
                and is_suspicious_global(normalized_mod, normalized_func)
            ):
                return not _is_warning_severity_ref(normalized_mod, normalized_func)

            return (
                _is_dangerous_module(module)
                or ((normalized_mod, normalized_func) != (module, function) and _is_dangerous_module(normalized_mod))
            ) and not _is_warning_severity_ref(normalized_mod, normalized_func)

        def _cache_classification(
            import_reference: str,
            classification_result: tuple[bool, IssueSeverity | None, str],
        ) -> None:
            classified_refs[import_reference] = classification_result
            classified_refs.move_to_end(import_reference)
            while len(classified_refs) > classification_cache_limit:
                classified_refs.popitem(last=False)

        def _record_reference(module: str, function: str, offset: int, opcode_name: str) -> None:
            nonlocal recorded_critical_reference

            if offset < minimum_offset:
                return
            if not module or not function or not _is_plausible_python_module(module):
                return

            import_reference = f"{module}.{function}"
            dedupe_key = (offset, import_reference)
            if dedupe_key in seen:
                return

            if len(findings) >= self.post_budget_global_max_reference_findings and recorded_critical_reference:
                self._post_budget_global_reference_limit_exceeded = True
                return
            if len(findings) >= self.post_budget_global_max_reference_findings and not _might_be_critical_reference(
                module, function
            ):
                self._post_budget_global_reference_limit_exceeded = True
                return

            classification_result = classified_refs.get(import_reference)
            if classification_result is None:
                classification_result = _classify_import_reference(
                    module,
                    function,
                    ml_context,
                    is_import_only=True,
                )
                _cache_classification(import_reference, classification_result)
            else:
                classified_refs.move_to_end(import_reference)
            is_failure, severity, classification = classification_result
            if not is_failure:
                return
            if severity is None:
                return

            if len(findings) >= self.post_budget_global_max_reference_findings and severity != IssueSeverity.CRITICAL:
                self._post_budget_global_reference_limit_exceeded = True
                return
            seen.add(dedupe_key)
            if len(findings) >= self.post_budget_global_max_reference_findings:
                self._post_budget_global_reference_limit_exceeded = True

            findings.append(
                {
                    "module": module,
                    "function": function,
                    "import_reference": import_reference,
                    "offset": offset,
                    "opcode": opcode_name,
                    "classification": classification,
                    "severity": severity.value,
                    "rule_code": get_import_rule_code(module, function) or "S206",
                }
            )
            if severity == IssueSeverity.CRITICAL:
                recorded_critical_reference = True

        def _decode_string_push_at(start: int) -> tuple[str, int] | None:
            if start < 0 or start >= data_len:
                return None

            opcode = data[start]
            if opcode == 0x56:  # UNICODE
                value_start = start + 1
                value_end = data.find(b"\n", value_start, min(data_len, value_start + 4097))
                if value_end == -1:
                    return None
                value = data[value_start:value_end].decode("utf-8", errors="ignore").strip()
                return value, value_end + 1
            if opcode == 0x8C:  # SHORT_BINUNICODE
                if start + 2 > data_len:
                    return None
                string_len = data[start + 1]
                value_start = start + 2
            elif opcode == 0x58:  # BINUNICODE
                if start + 5 > data_len:
                    return None
                string_len = int.from_bytes(data[start + 1 : start + 5], "little")
                value_start = start + 5
            elif opcode == 0x8D:  # BINUNICODE8
                if start + 9 > data_len:
                    return None
                string_len = int.from_bytes(data[start + 1 : start + 9], "little")
                value_start = start + 9
            else:
                return None

            value_end = value_start + string_len
            if value_end > data_len or string_len < 0:
                return None

            value = data[value_start:value_end].decode("utf-8", errors="ignore").strip()
            return value, value_end

        def _parse_text_memo_index(start: int) -> tuple[int, int] | None:
            if start + 2 > data_len:
                return None
            end = data.find(b"\n", start + 1, min(data_len, start + 22))
            if end == -1:
                return None
            digits = data[start + 1 : end]
            if not digits or any(ch not in b"0123456789" for ch in digits):
                return None
            return int(digits.decode("ascii")), end + 1

        value_end_to_info: dict[int, tuple[str, int]] = {}
        value_end_history: deque[int] = deque()
        memo_values: OrderedDict[int, tuple[str, int]] = OrderedDict()
        next_memo_index = 0
        parse_cursor = 0
        last_value_info: tuple[str, int] | None = None
        last_value_end = -1
        next_deadline_check_cursor = 0

        def _track_value_info(value_end: int, value_info: tuple[str, int]) -> None:
            value_end_to_info[value_end] = value_info
            value_end_history.append(value_end)

            stale_before_or_at = value_end - _POST_BUDGET_GLOBAL_CONTEXT_BYTES
            while value_end_history and value_end_history[0] <= stale_before_or_at:
                stale_value_end = value_end_history.popleft()
                value_end_to_info.pop(stale_value_end, None)

        def _extract_stack_global_values(stack_global_index: int) -> list[str]:
            values: list[str] = []
            cursor = stack_global_index
            lookback_start = max(0, stack_global_index - _POST_BUDGET_GLOBAL_CONTEXT_BYTES)

            while len(values) < 2 and cursor > lookback_start:
                resolved_value = value_end_to_info.get(cursor)
                if resolved_value is None:
                    break

                found_value, found_start = resolved_value
                if found_start < lookback_start or found_start >= cursor:
                    break
                values.append(found_value)
                cursor = found_start

            return list(reversed(values))

        def _track_memo_value(memo_index: int, value_info: tuple[str, int]) -> None:
            memo_values[memo_index] = value_info
            memo_values.move_to_end(memo_index)

            while len(memo_values) > self.post_budget_global_memo_limit_entries:
                memo_values.popitem(last=False)
                self._post_budget_global_memo_limit_exceeded = True

        def _resolve_memo_value(memo_index: int) -> tuple[str, int] | None:
            resolved_value = memo_values.get(memo_index)
            if resolved_value is not None:
                memo_values.move_to_end(memo_index)
            return resolved_value

        def _deadline_exceeded(cursor: int) -> bool:
            nonlocal next_deadline_check_cursor

            if deadline is None or cursor < next_deadline_check_cursor:
                return False

            next_deadline_check_cursor = cursor + _POST_BUDGET_GLOBAL_DEADLINE_CHECK_INTERVAL_BYTES
            if time.time() <= deadline:
                return False

            self._post_budget_global_scan_deadline_exceeded = True
            logger.debug(
                "Post-budget global scan stopped after exceeding timeout (%ss)",
                self.timeout,
            )
            return True

        while parse_cursor < data_len:
            if _deadline_exceeded(parse_cursor):
                break

            opcode_value = data[parse_cursor]
            parsed_string = _decode_string_push_at(parse_cursor)
            if parsed_string is not None:
                value, value_end = parsed_string
                last_value_info = (value, parse_cursor)
                last_value_end = value_end
                _track_value_info(value_end, last_value_info)
                parse_cursor = value_end
                continue

            if opcode_value == 0x94:  # MEMOIZE
                if last_value_info is not None and last_value_end == parse_cursor:
                    _track_memo_value(next_memo_index, last_value_info)
                    _track_value_info(parse_cursor + 1, last_value_info)
                    last_value_end = parse_cursor + 1
                    next_memo_index += 1
                else:
                    last_value_info = None
                    last_value_end = -1
                parse_cursor += 1
                continue

            if opcode_value == 0x71 and parse_cursor + 2 <= data_len:  # BINPUT
                if last_value_info is not None and last_value_end == parse_cursor:
                    _track_memo_value(data[parse_cursor + 1], last_value_info)
                    _track_value_info(parse_cursor + 2, last_value_info)
                    last_value_end = parse_cursor + 2
                else:
                    last_value_info = None
                    last_value_end = -1
                parse_cursor += 2
                continue

            if opcode_value == 0x72 and parse_cursor + 5 <= data_len:  # LONG_BINPUT
                if last_value_info is not None and last_value_end == parse_cursor:
                    _track_memo_value(
                        int.from_bytes(data[parse_cursor + 1 : parse_cursor + 5], "little"),
                        last_value_info,
                    )
                    _track_value_info(parse_cursor + 5, last_value_info)
                    last_value_end = parse_cursor + 5
                else:
                    last_value_info = None
                    last_value_end = -1
                parse_cursor += 5
                continue

            if opcode_value == 0x70:  # PUT
                parsed_index = _parse_text_memo_index(parse_cursor)
                if parsed_index is not None:
                    memo_index, memo_end = parsed_index
                    if last_value_info is not None and last_value_end == parse_cursor:
                        _track_memo_value(memo_index, last_value_info)
                        _track_value_info(memo_end, last_value_info)
                        last_value_end = memo_end
                    else:
                        last_value_info = None
                        last_value_end = -1
                    parse_cursor = memo_end
                    continue

            if opcode_value == 0x68 and parse_cursor + 2 <= data_len:  # BINGET
                resolved_value = _resolve_memo_value(data[parse_cursor + 1])
                if resolved_value is not None:
                    _track_value_info(parse_cursor + 2, resolved_value)
                    last_value_info = resolved_value
                    last_value_end = parse_cursor + 2
                else:
                    last_value_info = None
                    last_value_end = -1
                parse_cursor += 2
                continue

            if opcode_value == 0x6A and parse_cursor + 5 <= data_len:  # LONG_BINGET
                resolved_value = _resolve_memo_value(
                    int.from_bytes(data[parse_cursor + 1 : parse_cursor + 5], "little")
                )
                if resolved_value is not None:
                    _track_value_info(parse_cursor + 5, resolved_value)
                    last_value_info = resolved_value
                    last_value_end = parse_cursor + 5
                else:
                    last_value_info = None
                    last_value_end = -1
                parse_cursor += 5
                continue

            if opcode_value == 0x67:  # GET
                parsed_index = _parse_text_memo_index(parse_cursor)
                if parsed_index is not None:
                    memo_index, memo_end = parsed_index
                    resolved_value = _resolve_memo_value(memo_index)
                    if resolved_value is not None:
                        _track_value_info(memo_end, resolved_value)
                        last_value_info = resolved_value
                        last_value_end = memo_end
                    else:
                        last_value_info = None
                        last_value_end = -1
                    parse_cursor = memo_end
                    continue

            if opcode_value == 0x93:  # STACK_GLOBAL
                values = _extract_stack_global_values(parse_cursor)
                if len(values) == 2:
                    module, function = values
                    _record_reference(module, function, scan_start + parse_cursor, "STACK_GLOBAL")
                last_value_info = None
                last_value_end = -1
                parse_cursor += 1
                continue
            elif opcode_value == 0x95 and parse_cursor + 9 <= data_len:  # FRAME
                parse_cursor += 9
                continue

            last_value_info = None
            last_value_end = -1
            parse_cursor += 1

        next_deadline_check_cursor = 0
        cursor = 0
        while cursor < data_len:
            if _deadline_exceeded(cursor):
                break

            opcode_value = data[cursor]
            if opcode_value in (ord("c"), ord("i")):
                module_end = data.find(b"\n", cursor + 1, min(data_len, cursor + 257))
                if module_end != -1 and module_end - cursor <= 256:
                    function_end = data.find(b"\n", module_end + 1, min(data_len, module_end + 257))
                    if function_end != -1 and function_end - module_end <= 256:
                        module = data[cursor + 1 : module_end].decode("utf-8", errors="ignore").strip()
                        function = data[module_end + 1 : function_end].decode("utf-8", errors="ignore").strip()
                        opcode_name = "GLOBAL" if opcode_value == ord("c") else "INST"
                        _record_reference(module, function, scan_start + cursor, opcode_name)
                        cursor = function_end + 1
                        continue
            cursor += 1

        return findings

    def _scan_post_budget_opcode_findings_unbounded(
        self,
        file_obj: BinaryIO,
        *,
        file_size: int,
        minimum_offset: int,
        ml_context: dict[str, Any],
        deadline: float | None,
        prefix_context_opcodes: list[tuple[Any, Any, int | None]] | None = None,
    ) -> list[dict[str, Any]]:
        """Run a bounded tail opcode pass for findings that only exist in the main opcode loop."""
        minimum_offset = max(0, minimum_offset)
        data, scan_start, _tail_scan_bytes = self._read_post_budget_window(
            file_obj,
            file_size=file_size,
            minimum_offset=minimum_offset,
            scan_limit_bytes=self.post_budget_global_scan_limit_bytes,
            context_bytes=0,
        )
        if not data:
            return []

        tail_opcodes = self._collect_post_budget_opcodes(
            data,
            scan_start=scan_start,
            deadline=deadline,
            scan_label="opcode",
        )
        if not tail_opcodes:
            return []

        opcodes = [*(prefix_context_opcodes or []), *tail_opcodes]

        (
            stack_global_refs,
            callable_refs,
            _callable_origin_refs,
            callable_origin_is_ext,
            malformed_stack_globals,
            mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)

        findings: list[dict[str, Any]] = []
        for index, (opcode, arg, pos) in enumerate(opcodes):
            absolute_pos = int(pos) if pos is not None else None
            if absolute_pos is None or absolute_pos < minimum_offset:
                continue

            findings.extend(_collect_nested_pickle_opcode_findings(opcode.name, arg, absolute_pos, ml_context))
            findings.extend(_collect_encoded_python_opcode_findings(opcode.name, arg, absolute_pos, ml_context))

            if opcode.name == "STACK_GLOBAL":
                malformed = malformed_stack_globals.get(index)
                if malformed and malformed["reason"] != "insufficient_context":
                    findings.append(
                        _build_malformed_stack_global_finding(
                            pos=absolute_pos,
                            malformed=malformed,
                            ml_context=ml_context,
                        )
                    )

        dangerous_pattern = is_dangerous_reduce_pattern(
            opcodes,
            stack_global_refs=stack_global_refs,
            callable_refs=callable_refs,
            callable_origin_is_ext=callable_origin_is_ext,
            mutation_target_refs=mutation_target_refs,
            minimum_position=minimum_offset,
        )
        if dangerous_pattern is not None:
            findings.append(_build_dangerous_reduce_pattern_finding(dangerous_pattern, ml_context))

        return findings

    def _scan_expansion_heuristics_unbounded(
        self,
        file_obj: BinaryIO,
        *,
        file_size: int,
        minimum_offset: int,
        deadline: float | None,
    ) -> list[_ExpansionHeuristicFinding]:
        """Perform a bounded post-budget opcode scan for expansion-style pickle bombs."""
        minimum_offset = max(0, minimum_offset)
        tail_scan_bytes = min(max(file_size - minimum_offset, 0), self.post_budget_expansion_scan_limit_bytes)
        if tail_scan_bytes <= 0:
            return []

        original_pos = file_obj.tell()
        try:
            file_obj.seek(minimum_offset)
            tail_data = file_obj.read(tail_scan_bytes)
        finally:
            file_obj.seek(original_pos)
        if not tail_data:
            return []

        opcodes = self._collect_post_budget_opcodes(
            tail_data,
            scan_start=minimum_offset,
            deadline=deadline,
            scan_label="expansion",
        )
        return _detect_pickle_expansion_heuristics(opcodes)

    def _scan_pickle_bytes(self, file_obj: BinaryIO, file_size: int) -> ScanResult:
        """Scan pickle file content for suspicious opcodes"""
        result = self._create_result()
        opcode_count = 0
        suspicious_count = 0
        advanced_globals: set[tuple[str, str, str]] = set()

        current_pos = file_obj.tell()
        timeout_exceeded = False
        timed_out = False

        # Read file data - either all at once for small files or first chunk for large files.
        # For large files, read only the first 10MB for in-memory string/pattern analysis to cap
        # embedded-pickle memory usage while still inspecting the most security-
        # relevant prefix.
        file_data = (
            file_obj.read()
            if file_size <= _RAW_PATTERN_SCAN_LIMIT_BYTES
            else file_obj.read(_RAW_PATTERN_SCAN_LIMIT_BYTES)
        )

        file_obj.seek(current_pos)  # Reset position

        raw_pattern_scan_complete = file_size <= _RAW_PATTERN_SCAN_LIMIT_BYTES
        result.metadata.update(
            {
                "raw_pattern_scan_complete": raw_pattern_scan_complete,
                "raw_pattern_scan_bytes": len(file_data),
                "raw_pattern_total_bytes": file_size,
            }
        )
        if not raw_pattern_scan_complete:
            result.add_check(
                name="Raw Pattern Coverage Check",
                passed=False,
                message=(
                    "Raw byte-pattern analysis covered only the first 10 MB of this pickle; "
                    "opcode analysis continued beyond that prefix but may still stop early if timeout "
                    "or opcode-budget limits are reached; heuristic string matches beyond that prefix "
                    "were not evaluated"
                ),
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "reason": "raw_pattern_prefix_limit",
                    "raw_pattern_analysis_limited": True,
                    "raw_pattern_scan_bytes": len(file_data),
                    "raw_pattern_scan_limit_bytes": _RAW_PATTERN_SCAN_LIMIT_BYTES,
                    "raw_pattern_total_bytes": file_size,
                },
                why=(
                    "To bound memory usage, raw byte/string heuristic checks analyze only a leading prefix of large "
                    "pickle files. Opcode-level analysis proceeds separately and may itself stop early due to "
                    "timeout or opcode budgets, but suspicious strings located entirely beyond the scanned prefix "
                    "are not evaluated by this heuristic layer."
                ),
                rule_code="S902",
            )

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

        # Emit explicit checks for the file (only if checks are enabled)
        check_jit = self._get_bool_config("check_jit_script", True)
        if check_jit:
            self.add_jit_script_findings(
                jit_findings,
                result,
                model_type="pytorch",
                context=self.current_file_path,
            )
        else:
            result.metadata.setdefault("disabled_checks", []).append("JIT/Script Code Execution Detection")

        check_net = self._get_bool_config("check_network_comm", True)
        if check_net:
            self.add_network_communication_findings(
                network_findings,
                result,
                context=self.current_file_path,
            )
        else:
            result.metadata.setdefault("disabled_checks", []).append("Network Communication Detection")

        structural_findings = _scan_structural_tamper_findings(file_data)
        for finding in structural_findings:
            kind = finding["kind"]
            position = finding.get("position")
            stream_offset = finding.get("stream_offset")
            if kind == "duplicate_proto":
                prev_protocol = finding.get("previous_protocol")
                protocol = finding.get("protocol")
                result.add_check(
                    name="Pickle Structural Tamper Check",
                    passed=False,
                    message=(
                        "Duplicate PROTO opcode in pickle stream "
                        f"at byte position {position} (previous={prev_protocol}, current={protocol})"
                    ),
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path} (pos {position})",
                    details={
                        "tamper_type": kind,
                        "position": position,
                        "stream_offset": stream_offset,
                        "protocol": protocol,
                        "previous_protocol": prev_protocol,
                    },
                    why=(
                        "Multiple protocol declarations inside one pickle stream are structurally unusual and can be "
                        "used to probe parser differences between tools."
                    ),
                    rule_code="S902",
                )
            elif kind == "misplaced_proto":
                result.add_check(
                    name="Pickle Structural Tamper Check",
                    passed=False,
                    message=f"Misplaced PROTO opcode in pickle stream at byte position {position}",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path} (pos {position})",
                    details={
                        "tamper_type": kind,
                        "position": position,
                        "stream_offset": stream_offset,
                        "protocol": finding.get("protocol"),
                    },
                    why=(
                        "Binary protocol declarations are expected at the beginning of a stream. A later PROTO opcode "
                        "indicates structural tampering or malformed serialization."
                    ),
                    rule_code="S902",
                )
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
                        rule_code="S902",
                    )
                else:
                    result.add_check(
                        name="Pickle Protocol Version Check",
                        passed=True,
                        message=f"Valid pickle protocol version {protocol_version}",
                        location=self.current_file_path,
                        details={"protocol_version": protocol_version},
                        rule_code=None,  # Passing check
                    )
            else:
                # Protocol 0 or 1
                result.add_check(
                    name="Pickle Protocol Version Check",
                    passed=True,
                    message="Pickle protocol version 0 or 1 detected",
                    location=self.current_file_path,
                    details={"protocol_version": "0 or 1"},
                    rule_code=None,  # Passing check
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
            base_stack_depth_limit = 3000
            warning_stack_depth_limit = 5000
            scan_start_time = self.scan_start_time if self.scan_start_time is not None else result.start_time
            deadline = scan_start_time + self.timeout
            analysis = self._build_pickle_opcode_analysis(
                file_obj,
                multiple_pickles=True,
                scan_start_time=scan_start_time,
                include_sequence_analysis=True,
                include_stack_metrics=True,
                probe_for_budget_exceeded=True,
            )
            advanced_globals = analysis.globals_found
            opcodes = analysis.opcodes
            opcode_count = analysis.opcode_count
            timeout_exceeded = analysis.timeout_exceeded
            opcode_budget_exceeded = analysis.opcode_budget_exceeded
            max_analyzed_end_offset = analysis.max_analyzed_end_offset
            first_pickle_end_pos = analysis.first_pickle_end_pos
            max_stack_depth = analysis.max_stack_depth
            stack_depth_warnings = analysis.stack_depth_warnings

            for sequence_result in analysis.sequence_results:
                self._create_opcode_sequence_check(sequence_result, result)

            if analysis.extreme_stack_depth_event is not None:
                result.add_check(
                    name="Stack Depth Safety Check",
                    passed=False,
                    message=(
                        "Extreme stack depth "
                        f"({analysis.extreme_stack_depth_event['current_depth']}) - stopping scan for safety"
                    ),
                    severity=IssueSeverity.CRITICAL,
                    location=f"{self.current_file_path} (pos {analysis.extreme_stack_depth_event['position']})",
                    details=analysis.extreme_stack_depth_event,
                    why=(
                        "Stack depth is extremely high and could indicate a maliciously crafted pickle designed to "
                        "cause resource exhaustion."
                    ),
                )

            if analysis.error is not None:
                if not advanced_globals:
                    file_obj.seek(start_pos)
                    advanced_globals = self._extract_globals_advanced(
                        file_obj,
                        scan_start_time=scan_start_time,
                    )
                    file_obj.seek(start_pos)
                raise analysis.error

            timed_out = timeout_exceeded or time.time() > deadline

            if opcode_budget_exceeded:
                _mark_inconclusive_scan_result(result, "opcode_budget_exceeded")

            if timed_out:
                _mark_inconclusive_scan_result(result, "scan_timeout")

            if opcode_budget_exceeded:
                result.add_check(
                    name="Opcode Count Check",
                    passed=False,
                    message=f"Scanning stopped after reaching opcode budget ({self.max_opcodes})",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={
                        "opcode_count": opcode_count,
                        "max_opcodes": self.max_opcodes,
                        "analysis_incomplete": True,
                    },
                    why=get_pattern_explanation("pickle_size_limit"),
                    rule_code="S902",
                )

            if timed_out and not any(
                check.name == "Scan Timeout Check" and check.status == CheckStatus.FAILED for check in result.checks
            ):
                result.add_check(
                    name="Scan Timeout Check",
                    passed=False,
                    message=f"Scanning timed out after {self.timeout} seconds",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={
                        "opcode_count": opcode_count,
                        "timeout": self.timeout,
                        "analysis_incomplete": True,
                    },
                    why=(
                        "The scan exceeded the configured time limit. Large or complex pickle files may take "
                        "longer to analyze due to the number of opcodes that need to be processed."
                    ),
                    rule_code="S902",
                )

            # Add successful opcode count check if within limits
            if opcode_count <= self.max_opcodes and not opcode_budget_exceeded:
                result.add_check(
                    name="Opcode Count Check",
                    passed=True,
                    message=f"Opcode count ({opcode_count}) is within limits",
                    location=self.current_file_path,
                    rule_code=None,  # Passing check
                    details={
                        "opcode_count": opcode_count,
                        "max_opcodes": self.max_opcodes,
                    },
                )

            # ML CONTEXT FILTERING: Analyze ML context once for the entire pickle
            ml_context = _detect_ml_context(opcodes, stack_global_refs=analysis.stack_global_refs)
            stack_global_refs = analysis.stack_global_refs
            callable_refs = analysis.callable_refs
            callable_origin_is_ext = analysis.callable_origin_is_ext
            malformed_stack_globals = analysis.malformed_stack_globals
            executed_import_origins = analysis.executed_import_origins
            executed_ref_keys = analysis.executed_ref_keys
            max_analyzed_offset = analysis.max_analyzed_offset
            post_budget_minimum_offset = max(max_analyzed_end_offset, max_analyzed_offset + 1, 0)

            should_run_post_budget_scan = opcode_budget_exceeded and not timed_out
            if timed_out:
                result.metadata["post_budget_global_scan_skipped_due_to_timeout"] = True

            if should_run_post_budget_scan:
                post_budget_scan_bytes = min(
                    max(file_size - post_budget_minimum_offset, 0),
                    self.post_budget_global_scan_limit_bytes,
                )
                post_budget_global_findings = self._scan_global_references_unbounded(
                    file_obj,
                    file_size=file_size,
                    minimum_offset=post_budget_minimum_offset,
                    ml_context=ml_context,
                    deadline=deadline,
                )
                if self._post_budget_global_memo_limit_exceeded:
                    _mark_inconclusive_scan_result(result, "post_budget_global_memo_limit_exceeded")
                    result.add_check(
                        name="Post-Budget Global Memo Tracking Check",
                        passed=False,
                        message=(
                            "Stopped retaining memoized string context during the post-budget global scan after "
                            f"reaching {self.post_budget_global_memo_limit_entries} memo entries"
                        ),
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={
                            "max_memo_entries": self.post_budget_global_memo_limit_entries,
                            "minimum_offset": post_budget_minimum_offset,
                            "analysis_incomplete": True,
                        },
                        why=(
                            "The post-budget fallback bounds memo-table state to avoid attacker-controlled memory "
                            "growth. Older memoized string references may be unavailable once this limit is reached, "
                            "so the scan result is marked inconclusive."
                        ),
                        rule_code="S902",
                    )

                if self._post_budget_global_reference_limit_exceeded:
                    _mark_inconclusive_scan_result(result, "post_budget_global_reference_limit_exceeded")
                    result.add_check(
                        name="Post-Budget Global Reference Tracking Check",
                        passed=False,
                        message=(
                            "Stopped retaining post-budget import references after reaching "
                            f"{self.post_budget_global_max_reference_findings} findings"
                        ),
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={
                            "max_reference_findings": self.post_budget_global_max_reference_findings,
                            "minimum_offset": post_budget_minimum_offset,
                            "analysis_incomplete": True,
                        },
                        why=(
                            "The post-budget fallback caps retained GLOBAL/INST/STACK_GLOBAL findings so crafted "
                            "tails cannot force unbounded result growth. The scan result is marked inconclusive "
                            "because additional references may have been omitted after the cap was reached."
                        ),
                        rule_code="S902",
                    )

                if post_budget_global_findings:
                    critical_findings = [
                        finding
                        for finding in post_budget_global_findings
                        if finding["severity"] == IssueSeverity.CRITICAL.value
                    ]
                    highest_severity = IssueSeverity.CRITICAL if critical_findings else IssueSeverity.WARNING
                    representative_finding = (
                        critical_findings[0] if critical_findings else post_budget_global_findings[0]
                    )
                    additional = len(post_budget_global_findings) - 1
                    additional_note = f" (+{additional} more)" if additional > 0 else ""
                    suspicious_count += len(post_budget_global_findings)
                    result.add_check(
                        name="Post-Budget Global Reference Scan",
                        passed=False,
                        message=(
                            (
                                "Dangerous reference found beyond opcode budget: "
                                if highest_severity == IssueSeverity.CRITICAL
                                else "Suspicious import reference found beyond opcode budget: "
                            )
                            + f"{representative_finding['import_reference']} at byte offset "
                            + f"{representative_finding['offset']}"
                            f"{additional_note}"
                        ),
                        severity=highest_severity,
                        location=self.current_file_path,
                        rule_code=representative_finding["rule_code"],
                        details={
                            "scan_limit_bytes": self.post_budget_global_scan_limit_bytes,
                            "scan_bytes": post_budget_scan_bytes,
                            "scan_total_bytes": file_size,
                            "minimum_offset": post_budget_minimum_offset,
                            "references": post_budget_global_findings,
                            "dangerous_references": critical_findings,
                        },
                        why=(
                            "The opcode pass stopped at the configured budget, so a separate byte-level import scan "
                            "checked the remaining payload and found "
                            + ("dangerous" if highest_severity == IssueSeverity.CRITICAL else "suspicious")
                            + " GLOBAL/INST/STACK_GLOBAL references."
                        ),
                    )
                    if highest_severity == IssueSeverity.CRITICAL:
                        result.success = False

                if self._post_budget_global_scan_deadline_exceeded:
                    _mark_inconclusive_scan_result(result, "scan_timeout")
                    result.metadata["post_budget_global_scan_stopped_due_to_timeout"] = True
                    if not any(
                        check.name == "Scan Timeout Check" and check.status == CheckStatus.FAILED
                        for check in result.checks
                    ):
                        result.add_check(
                            name="Scan Timeout Check",
                            passed=False,
                            message=f"Scanning timed out after {self.timeout} seconds",
                            severity=IssueSeverity.INFO,
                            location=self.current_file_path,
                            details={
                                "opcode_count": opcode_count,
                                "timeout": self.timeout,
                                "analysis_incomplete": True,
                                "post_budget_global_scan": True,
                                "minimum_offset": post_budget_minimum_offset,
                            },
                            why=(
                                "The post-budget fallback exceeded the configured time limit while scanning the "
                                "remaining payload after opcode-budget truncation."
                            ),
                            rule_code="S902",
                        )
                    should_run_post_budget_scan = False

            if should_run_post_budget_scan:
                post_budget_opcode_findings = self._scan_post_budget_opcode_findings_unbounded(
                    file_obj,
                    file_size=file_size,
                    minimum_offset=post_budget_minimum_offset,
                    ml_context=ml_context,
                    deadline=deadline,
                    prefix_context_opcodes=self._select_post_budget_opcode_context(
                        analysis.opcodes,
                        minimum_offset=post_budget_minimum_offset,
                    ),
                )
                if post_budget_opcode_findings:
                    suspicious_count += len(post_budget_opcode_findings)
                    representative_finding = max(
                        post_budget_opcode_findings,
                        key=lambda finding: _severity_priority(finding["severity"]),
                    )
                    highest_severity = representative_finding["severity"]
                    additional = len(post_budget_opcode_findings) - 1
                    additional_note = f" (+{additional} more)" if additional > 0 else ""
                    representative_position = representative_finding.get("position")
                    representative_location = (
                        f"{self.current_file_path} (pos {representative_position})"
                        if representative_position is not None
                        else self.current_file_path
                    )
                    serialized_findings = [
                        _serialize_opcode_check_finding(finding) for finding in post_budget_opcode_findings
                    ]
                    result.add_check(
                        name="Post-Budget Opcode Detection",
                        passed=False,
                        message=(
                            representative_finding["message"]
                            + (
                                f" at byte offset {representative_position}"
                                if representative_position is not None
                                else ""
                            )
                            + " (beyond opcode budget)"
                            + additional_note
                        ),
                        severity=highest_severity,
                        location=representative_location,
                        rule_code=representative_finding["rule_code"],
                        details={
                            "scan_limit_bytes": self.post_budget_global_scan_limit_bytes,
                            "scan_bytes": post_budget_scan_bytes,
                            "scan_total_bytes": file_size,
                            "minimum_offset": post_budget_minimum_offset,
                            "findings": serialized_findings,
                            "critical_findings": [
                                finding
                                for finding in serialized_findings
                                if finding["severity"] == IssueSeverity.CRITICAL.value
                            ],
                        },
                        why=(
                            "The opcode pass stopped at the configured budget, so a bounded tail opcode scan "
                            "reused the main opcode detectors on the remaining payload window and found "
                            "security-relevant opcode findings beyond the analyzed prefix."
                        ),
                    )

                post_budget_expansion_findings = self._scan_expansion_heuristics_unbounded(
                    file_obj,
                    file_size=file_size,
                    minimum_offset=post_budget_minimum_offset,
                    deadline=deadline,
                )
                if post_budget_expansion_findings:
                    suspicious_count += len(post_budget_expansion_findings)
                    primary_finding = post_budget_expansion_findings[0]
                    trigger_labels = ", ".join(
                        _EXPANSION_TRIGGER_LABELS.get(trigger, trigger.replace("_", " "))
                        for trigger in primary_finding.triggers
                    )
                    additional_streams = len(post_budget_expansion_findings) - 1
                    additional_note = (
                        f" (+{additional_streams} more stream{'s' if additional_streams != 1 else ''})"
                        if additional_streams > 0
                        else ""
                    )
                    post_budget_expansion_scan_bytes = min(
                        max(file_size - post_budget_minimum_offset, 0),
                        self.post_budget_expansion_scan_limit_bytes,
                    )
                    result.add_check(
                        name="Post-Budget Pickle Expansion Heuristic Check",
                        passed=False,
                        message=(
                            "Suspicious pickle expansion/resource-exhaustion pattern found beyond opcode budget: "
                            f"{trigger_labels}{additional_note}"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (pos {primary_finding.position})",
                        rule_code="S902",
                        details={
                            "scan_limit_bytes": self.post_budget_expansion_scan_limit_bytes,
                            "scan_bytes": post_budget_expansion_scan_bytes,
                            "scan_total_bytes": file_size,
                            "minimum_offset": post_budget_minimum_offset,
                            "findings": [asdict(finding) for finding in post_budget_expansion_findings],
                            "suspicious_streams": len(post_budget_expansion_findings),
                        },
                        why=(
                            "The opcode pass stopped at the configured budget, so a targeted tail scan continued "
                            "looking for memo/DUP expansion patterns in the remaining payload. "
                            + (get_pattern_explanation("pickle_expansion_attack") or "")
                        ),
                    )

            # CVE-2025-32434 is surfaced through the live REDUCE/global checks above.
            # Keep a single active path rather than a parallel heuristic sequence pass.

            # CVE-2026-24747: Context-aware SETITEM/SETITEMS abuse detection
            cve_2026_patterns = self._detect_cve_2026_24747_sequences(
                opcodes,
                file_size,
                stack_global_refs=stack_global_refs,
                mutation_target_refs=analysis.mutation_target_refs,
            )
            if cve_2026_patterns:
                for pattern in cve_2026_patterns:
                    result.add_check(
                        name="CVE-2026-24747 SETITEM Abuse Detection",
                        passed=False,
                        message=pattern["description"],
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (pos {pattern['position']})",
                        details=pattern,
                        why=(
                            "CVE-2026-24747 exploits SETITEM/SETITEMS opcodes applied to non-dict "
                            "objects (particularly tensor reconstruction results) to bypass the "
                            "weights_only=True restricted unpickler in PyTorch < 2.10.0, enabling "
                            "heap layout manipulation and control flow hijacking."
                        ),
                    )

            # Stack depth validation with tiered limits
            # Tiered approach: 0-3000 (OK), 3000-5000 (INFO), 5000-10000 (WARNING), 10000+ (CRITICAL)
            # This prevents false positives for legitimate large models while maintaining security
            warning_stack_depth_limit = 5000  # Concerning but not critical

            # Process stored stack depth warnings with tiered severity
            if stack_depth_warnings:
                # Get the worst (highest) stack depth
                def get_depth(x):
                    return x["current_depth"] if isinstance(x["current_depth"], int) else 0

                worst_warning = max(stack_depth_warnings, key=get_depth)
                worst_depth = worst_warning["current_depth"]

                # All stack depth warnings are now INFO severity
                # Stack depth alone is not a reliable security indicator - large legitimate models
                # commonly have depths of 1000-7000. Always show as INFO for visibility.
                severity = IssueSeverity.INFO
                if isinstance(worst_depth, int) and worst_depth > warning_stack_depth_limit:
                    # Very high stack depth - still INFO but with stronger warning message
                    message = f"Very high stack depth ({worst_depth}) detected in pickle file"
                    why_text = (
                        "Stack depth is very high. While this can occur in large legitimate models, "
                        "it may also indicate a maliciously crafted pickle. Verify model source and "
                        "monitor for resource exhaustion if loading from untrusted sources."
                    )
                else:
                    # 3000-5000: Normal for large models
                    message = f"Elevated stack depth ({worst_depth}) in pickle file"
                    why_text = (
                        "Stack depth is elevated but within range seen in large legitimate ML models. "
                        "This is informational - large models commonly have complex nested structures."
                    )

                # Filter warnings based on base limit for details
                significant_warnings = [
                    w
                    for w in stack_depth_warnings
                    if isinstance(w["current_depth"], int) and w["current_depth"] > base_stack_depth_limit
                ]

                if significant_warnings:
                    result.add_check(
                        name="Stack Depth Safety Check",
                        passed=False,
                        message=message,
                        severity=severity,
                        location=f"{self.current_file_path} (pos {worst_warning['position']})",
                        details={
                            "current_depth": worst_warning["current_depth"],
                            "base_limit": base_stack_depth_limit,
                            "warning_limit": warning_stack_depth_limit,
                            "opcode": worst_warning["opcode"],
                            "total_warnings": len(stack_depth_warnings),
                            "significant_warnings": len(significant_warnings),
                        },
                        why=why_text,
                    )
                else:
                    # Warnings were filtered out as within safe limits
                    max_filtered_depth = max(
                        w["current_depth"] for w in stack_depth_warnings if isinstance(w["current_depth"], int)
                    )
                    result.add_check(
                        name="Stack Depth Safety Check",
                        passed=True,
                        message=f"Stack depth within safe limits (max: {max_filtered_depth})",
                        location=self.current_file_path,
                        details={
                            "max_depth_reached": max_stack_depth,
                            "base_limit": base_stack_depth_limit,
                            "warnings_filtered": len(stack_depth_warnings),
                        },
                    )
            else:
                # No stack depth warnings - everything is within base limits
                result.add_check(
                    name="Stack Depth Validation",
                    passed=True,
                    message=f"Maximum stack depth ({max_stack_depth}) is within safe limits",
                    rule_code=None,  # Passing check
                    location=self.current_file_path,
                    details={
                        "max_depth_reached": max_stack_depth,
                        "base_limit": base_stack_depth_limit,
                    },
                )

            # Also add to metadata for analysis
            result.metadata["max_stack_depth"] = max_stack_depth

            expansion_findings = _detect_pickle_expansion_heuristics(opcodes)
            if expansion_findings:
                suspicious_count += len(expansion_findings)
                primary_finding = expansion_findings[0]
                trigger_labels = ", ".join(
                    _EXPANSION_TRIGGER_LABELS.get(trigger, trigger.replace("_", " "))
                    for trigger in primary_finding.triggers
                )
                additional_streams = len(expansion_findings) - 1
                additional_streams_note = (
                    f" (+{additional_streams} more stream{'s' if additional_streams != 1 else ''})"
                    if additional_streams > 0
                    else ""
                )
                result.add_check(
                    name="Pickle Expansion Heuristic Check",
                    passed=False,
                    message=(
                        "Suspicious pickle expansion/resource-exhaustion pattern detected: "
                        f"{trigger_labels}{additional_streams_note}"
                    ),
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (pos {primary_finding.position})",
                    details={
                        "findings": [asdict(finding) for finding in expansion_findings],
                        "suspicious_streams": len(expansion_findings),
                    },
                    why=get_pattern_explanation("pickle_expansion_attack"),
                    rule_code="S902",
                )
            else:
                result.add_check(
                    name="Pickle Expansion Heuristic Check",
                    passed=True,
                    message="No suspicious expansion/resource-exhaustion pickle patterns detected",
                    location=self.current_file_path,
                    details={"opcode_count": opcode_count},
                )

            # Add ML context to metadata for debugging
            result.metadata.update(
                {
                    "ml_context": ml_context,
                    "opcode_count": opcode_count,
                    "suspicious_count": suspicious_count,
                },
            )
            if first_pickle_end_pos is not None:
                result.metadata["first_pickle_end_pos"] = first_pickle_end_pos

            primary_ref_findings: dict[tuple[str, str], _PrimaryRefFinding] = {}
            pending_supporting_imports: dict[tuple[str, str], list[dict[str, Any]]] = {}

            def _build_supporting_evidence(
                *,
                name: str,
                message: str,
                location: str,
                details: dict[str, Any],
                severity: IssueSeverity | None = None,
                rule_code: str | None = None,
            ) -> dict[str, Any]:
                evidence = {
                    "check_name": name,
                    "message": message,
                    "location": location,
                    "details": dict(details),
                }
                if severity is not None:
                    evidence["severity"] = severity.value
                if rule_code is not None:
                    evidence["rule_code"] = rule_code
                return evidence

            def _resolve_promoted_rule_code(message: str, rule_code: str | None, fallback: str | None) -> str | None:
                if rule_code is not None:
                    return rule_code
                if fallback is not None:
                    return fallback

                from ..rules import RuleRegistry

                match = RuleRegistry.find_matching_rule(message)
                if match:
                    return match[0]
                return None

            def _append_supporting_evidence(record: _PrimaryRefFinding, evidence: dict[str, Any]) -> None:
                for details_dict in (
                    result.checks[record.check_index].details,
                    result.issues[record.issue_index].details,
                ):
                    supporting = details_dict.setdefault("supporting_evidence", [])
                    supporting.append(evidence)
                    details_dict["supporting_evidence_count"] = len(supporting)

            def _record_reference_primary(
                ref_key: tuple[str, str],
                *,
                name: str,
                message: str,
                severity: IssueSeverity,
                location: str,
                details: dict[str, Any],
                why: str | None,
                rule_code: str | None,
            ) -> bool:
                evidence = _build_supporting_evidence(
                    name=name,
                    message=message,
                    location=location,
                    details=details,
                    severity=severity,
                    rule_code=rule_code,
                )
                existing = primary_ref_findings.get(ref_key)
                if existing is not None:
                    existing_check = result.checks[existing.check_index]
                    existing_issue = result.issues[existing.issue_index]
                    if _severity_priority(severity) > _severity_priority(existing_check.severity):
                        promoted_rule_code = _resolve_promoted_rule_code(
                            message,
                            rule_code,
                            existing_check.rule_code,
                        )
                        existing_details = dict(existing_check.details)
                        previous_supporting = list(existing_details.pop("supporting_evidence", []))
                        existing_details.pop("supporting_evidence_count", None)
                        previous_primary = _build_supporting_evidence(
                            name=existing_check.name,
                            message=existing_check.message,
                            location=existing_check.location or location,
                            details=existing_details,
                            severity=existing_check.severity,
                            rule_code=existing_check.rule_code,
                        )
                        promoted_details = dict(details)
                        if previous_supporting:
                            promoted_details["supporting_evidence"] = previous_supporting
                            promoted_details["supporting_evidence_count"] = len(previous_supporting)
                        existing_check.name = name
                        existing_check.message = message
                        existing_check.severity = severity
                        existing_check.location = location
                        existing_check.details = promoted_details
                        existing_check.why = why
                        existing_check.rule_code = promoted_rule_code
                        existing_issue.message = message
                        existing_issue.severity = severity
                        existing_issue.location = location
                        existing_issue.details = dict(promoted_details)
                        existing_issue.why = why
                        existing_issue.rule_code = promoted_rule_code
                        _append_supporting_evidence(existing, previous_primary)
                        return False
                    _append_supporting_evidence(existing, evidence)
                    return False

                checks_before = len(result.checks)
                issues_before = len(result.issues)
                result.add_check(
                    name=name,
                    passed=False,
                    message=message,
                    severity=severity,
                    location=location,
                    rule_code=rule_code,
                    details=details,
                    why=why,
                )
                if len(result.checks) == checks_before or len(result.issues) == issues_before:
                    return False

                record = _PrimaryRefFinding(len(result.checks) - 1, len(result.issues) - 1)
                primary_ref_findings[ref_key] = record
                for pending in pending_supporting_imports.pop(ref_key, []):
                    _append_supporting_evidence(record, pending)
                return True

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
            for i, (opcode, arg, pos) in enumerate(opcodes):
                # Check for GLOBAL opcodes that might reference suspicious modules
                if opcode.name == "GLOBAL" and isinstance(arg, str):
                    parsed = _parse_module_function(arg)
                    if parsed:
                        is_import_only = i not in executed_import_origins
                        mod, func = parsed
                        is_failure, base_sev_global, classification = _classify_import_reference(
                            mod,
                            func,
                            ml_context,
                            is_import_only=is_import_only,
                        )
                        if is_failure and base_sev_global is not None:
                            ref_key = _normalize_import_reference(mod, func)
                            severity_level_global: IssueSeverity = base_sev_global
                            severity = _get_context_aware_severity(
                                severity_level_global,
                                ml_context,
                                issue_type="dangerous_global",
                            )
                            rule_code = get_import_rule_code(mod, func) or "S206"
                            message = (
                                f"Suspicious import-only reference {mod}.{func}"
                                if classification == "unknown_third_party" and is_import_only
                                else f"Suspicious reference {mod}.{func}"
                            )
                            location = f"{self.current_file_path} (pos {pos})"
                            details = {
                                "module": mod,
                                "function": func,
                                "position": pos,
                                "opcode": opcode.name,
                                "import_reference": f"{mod}.{func}",
                                "import_only": is_import_only,
                                "classification": classification,
                                "ml_context_confidence": ml_context.get("overall_confidence", 0),
                            }
                            if ref_key in executed_ref_keys:
                                supporting_import_evidence = {
                                    "check_name": "Global Module Reference Check",
                                    "message": message,
                                    "location": location,
                                    "details": dict(details),
                                }
                                existing = primary_ref_findings.get(ref_key)
                                if existing is not None:
                                    _append_supporting_evidence(existing, supporting_import_evidence)
                                else:
                                    pending_supporting_imports.setdefault(ref_key, []).append(
                                        supporting_import_evidence,
                                    )
                            elif _record_reference_primary(
                                ref_key,
                                name="Global Module Reference Check",
                                message=message,
                                severity=severity,
                                location=location,
                                details=details,
                                why=get_import_explanation(f"{mod}.{func}"),
                                rule_code=rule_code,
                            ):
                                suspicious_count += 1
                        elif classification == "safe_allowlisted":
                            result.add_check(
                                name="Global Module Reference Check",
                                passed=True,
                                message=f"Safe global reference validated: {mod}.{func}",
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "module": mod,
                                    "function": func,
                                    "import_reference": f"{mod}.{func}",
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "import_only": is_import_only,
                                    "classification": classification,
                                    "ml_context_confidence": ml_context.get("overall_confidence", 0),
                                },
                                rule_code=None,
                            )

                # Check REDUCE opcodes for potential security issues
                # Flag as WARNING if not in safe globals, INFO if in safe globals
                if opcode.name == "REDUCE":
                    # Look back to find the associated GLOBAL or STACK_GLOBAL
                    reduce_mod, reduce_func, associated_global = _find_associated_global_or_class(
                        opcodes,
                        i,
                        stack_global_refs=stack_global_refs,
                        callable_refs=callable_refs,
                    )
                    reduce_origin_is_ext = callable_origin_is_ext.get(i, False)
                    is_safe_global = (
                        _is_safe_ml_global(reduce_mod, reduce_func)
                        if reduce_mod and reduce_func and not reduce_origin_is_ext
                        else False
                    )

                    # Report REDUCE based on safe globals check
                    if associated_global is not None:
                        if is_safe_global:
                            # Safe REDUCE (in ML_SAFE_GLOBALS) - show as INFO
                            result.add_check(
                                name="REDUCE Opcode Safety Check",
                                passed=True,
                                message=f"REDUCE opcode with safe ML framework global: {associated_global}",
                                severity=IssueSeverity.INFO,
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "associated_global": associated_global,
                                    "security_note": (
                                        "This REDUCE operation uses a safe ML framework function and is "
                                        "expected in model files. However, if the Python environment is "
                                        "tampered with (e.g., malicious monkey-patching), it could potentially "
                                        "be exploited. Ensure the execution environment is trusted."
                                    ),
                                    "ml_context_confidence": ml_context.get(
                                        "overall_confidence",
                                        0,
                                    ),
                                },
                            )
                        else:
                            # NOT in safe globals - check if it's actually dangerous
                            # Use _is_actually_dangerous_global to determine severity (CRITICAL vs WARNING)
                            if reduce_mod and reduce_func:
                                normalized_reduce_mod, normalized_reduce_func = _normalize_import_reference(
                                    reduce_mod,
                                    reduce_func,
                                )
                                dangerous_base_severity = _dangerous_ref_base_severity(
                                    normalized_reduce_mod,
                                    normalized_reduce_func,
                                    origin_is_ext=reduce_origin_is_ext,
                                )
                                is_actually_dangerous = reduce_origin_is_ext or _is_actually_dangerous_global(
                                    reduce_mod, reduce_func, ml_context
                                )
                                if is_actually_dangerous:
                                    # Dangerous global (e.g., os.system) - CRITICAL unless
                                    # the dangerous ref is explicitly configured as WARNING.
                                    severity = _get_context_aware_severity(
                                        dangerous_base_severity,
                                        ml_context,
                                        issue_type="dangerous_global",
                                    )
                                else:
                                    # Non-allowlisted but not explicitly dangerous.
                                    # Before flagging, check if the "module" name
                                    # actually looks like a real Python module.
                                    # Pickle GLOBAL args can contain arbitrary data
                                    # strings (e.g. DataFrame column names like
                                    # "PEDRA_2020") that are not real modules.
                                    if not _is_plausible_python_module(reduce_mod):
                                        # Not a real module -- record as safe (INFO)
                                        result.add_check(
                                            name="REDUCE Opcode Safety Check",
                                            passed=True,
                                            message=(
                                                f"REDUCE opcode with implausible module name "
                                                f"'{reduce_mod}' (likely data, not a real import): "
                                                f"{associated_global}"
                                            ),
                                            severity=IssueSeverity.INFO,
                                            location=f"{self.current_file_path} (pos {pos})",
                                            details={
                                                "position": pos,
                                                "opcode": opcode.name,
                                                "associated_global": associated_global,
                                                "implausible_module": True,
                                                "ml_context_confidence": ml_context.get(
                                                    "overall_confidence",
                                                    0,
                                                ),
                                            },
                                        )
                                        continue
                                    # Non-allowlisted but not explicitly dangerous - WARNING
                                    severity = _get_context_aware_severity(
                                        IssueSeverity.WARNING,
                                        ml_context,
                                    )

                                if is_actually_dangerous:
                                    _reduce_msg = f"Found REDUCE opcode invoking dangerous global: {associated_global}"
                                    _reduce_details: dict[str, Any] = {
                                        "position": pos,
                                        "opcode": opcode.name,
                                        "associated_global": associated_global,
                                        "origin_is_ext": reduce_origin_is_ext,
                                        "ml_context_confidence": ml_context.get(
                                            "overall_confidence",
                                            0,
                                        ),
                                    }
                                else:
                                    # CVE-2025-32434 is specific to torch.load() and
                                    # should only be referenced for PyTorch file formats
                                    _ext = os.path.splitext(self.current_file_path)[1].lower()
                                    _is_pytorch_file = _ext in {".pt", ".pth"} or (
                                        _ext == ".bin" and "pytorch" in ml_context.get("frameworks", {})
                                    )
                                    if _is_pytorch_file:
                                        _reduce_msg = (
                                            f"Found REDUCE opcode with non-allowlisted global: {associated_global}. "
                                            f"This may indicate CVE-2025-32434 exploitation (RCE via torch.load)"
                                        )
                                        _reduce_details = {
                                            "position": pos,
                                            "opcode": opcode.name,
                                            "associated_global": associated_global,
                                            "origin_is_ext": reduce_origin_is_ext,
                                            "cve_id": "CVE-2025-32434",
                                            "cvss": 9.8,
                                            "cwe": "CWE-502",
                                            "description": (
                                                "RCE when loading models with torch.load(weights_only=True)"
                                            ),
                                            "remediation": (
                                                "Upgrade to PyTorch 2.6.0 or later, and avoid "
                                                "torch.load(weights_only=True) with untrusted models."
                                            ),
                                            "ml_context_confidence": ml_context.get(
                                                "overall_confidence",
                                                0,
                                            ),
                                        }
                                    else:
                                        _reduce_msg = (
                                            f"Found REDUCE opcode with non-allowlisted global: {associated_global}"
                                        )
                                        _reduce_details = {
                                            "position": pos,
                                            "opcode": opcode.name,
                                            "associated_global": associated_global,
                                            "origin_is_ext": reduce_origin_is_ext,
                                            "ml_context_confidence": ml_context.get(
                                                "overall_confidence",
                                                0,
                                            ),
                                        }

                                location = f"{self.current_file_path} (pos {pos})"
                                reduce_why = (
                                    get_import_explanation(associated_global) if associated_global is not None else None
                                ) or get_opcode_explanation("REDUCE")
                                if (
                                    reduce_mod
                                    and reduce_func
                                    and _record_reference_primary(
                                        _normalize_import_reference(reduce_mod, reduce_func),
                                        name="REDUCE Opcode Safety Check",
                                        message=_reduce_msg,
                                        severity=severity,
                                        location=location,
                                        details=_reduce_details,
                                        why=reduce_why,
                                        rule_code=None,
                                    )
                                ):
                                    suspicious_count += 1

                # Check NEWOBJ/NEWOBJ_EX/OBJ/INST opcodes for potential security issues
                # Apply same logic as REDUCE: check if class is in ML_SAFE_GLOBALS
                if opcode.name in ["INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"]:
                    # Look back to find the associated class (GLOBAL or STACK_GLOBAL)
                    class_mod, class_name, associated_class = _find_associated_global_or_class(
                        opcodes,
                        i,
                        stack_global_refs=stack_global_refs,
                        callable_refs=callable_refs,
                    )
                    class_origin_is_ext = callable_origin_is_ext.get(i, False)
                    is_safe_class = (
                        _is_safe_ml_global(class_mod, class_name)
                        if class_mod and class_name and not class_origin_is_ext
                        else False
                    )

                    # Report based on safe class check (same logic as REDUCE)
                    if associated_class is not None:
                        if is_safe_class:
                            # Safe class (in ML_SAFE_GLOBALS) - show as INFO
                            result.add_check(
                                name="INST/OBJ/NEWOBJ/NEWOBJ_EX Opcode Safety Check",
                                passed=True,
                                message=f"{opcode.name} opcode with safe ML class: {associated_class}",
                                severity=IssueSeverity.INFO,
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "associated_class": associated_class,
                                    "security_note": (
                                        f"This {opcode.name} operation instantiates a safe ML framework class "
                                        "and is expected in model files. The class is in the ML_SAFE_GLOBALS allowlist."
                                    ),
                                    "ml_context_confidence": ml_context.get(
                                        "overall_confidence",
                                        0,
                                    ),
                                },
                            )
                        else:
                            # NOT in safe classes - check if actually dangerous
                            if class_mod and class_name:
                                normalized_class_mod, normalized_class_name = _normalize_import_reference(
                                    class_mod,
                                    class_name,
                                )
                                dangerous_base_severity = _dangerous_ref_base_severity(
                                    normalized_class_mod,
                                    normalized_class_name,
                                    origin_is_ext=class_origin_is_ext,
                                )
                                is_actually_dangerous = class_origin_is_ext or _is_actually_dangerous_global(
                                    class_mod, class_name, ml_context
                                )
                                if is_actually_dangerous:
                                    # Dangerous class (e.g., os.system wrapper) - CRITICAL unless
                                    # the dangerous ref is explicitly configured as WARNING.
                                    severity = _get_context_aware_severity(
                                        dangerous_base_severity,
                                        ml_context,
                                        issue_type="dangerous_global",
                                    )
                                else:
                                    # Skip if module name is not a plausible Python module
                                    # (e.g. DataFrame column names like "PEDRA_2020")
                                    if not _is_plausible_python_module(class_mod):
                                        result.add_check(
                                            name="INST/OBJ/NEWOBJ/NEWOBJ_EX Opcode Safety Check",
                                            passed=True,
                                            message=(
                                                f"{opcode.name} opcode with implausible module name "
                                                f"'{class_mod}' (likely data, not a real import): "
                                                f"{associated_class}"
                                            ),
                                            severity=IssueSeverity.INFO,
                                            location=f"{self.current_file_path} (pos {pos})",
                                            details={
                                                "position": pos,
                                                "opcode": opcode.name,
                                                "associated_class": associated_class,
                                                "implausible_module": True,
                                                "ml_context_confidence": ml_context.get(
                                                    "overall_confidence",
                                                    0,
                                                ),
                                            },
                                        )
                                        continue
                                    # Non-allowlisted but not explicitly dangerous - WARNING
                                    severity = _get_context_aware_severity(
                                        IssueSeverity.WARNING,
                                        ml_context,
                                    )

                                location = f"{self.current_file_path} (pos {pos})"
                                details = {
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "associated_class": associated_class,
                                    "origin_is_ext": class_origin_is_ext,
                                    "ml_context_confidence": ml_context.get(
                                        "overall_confidence",
                                        0,
                                    ),
                                }
                                if _record_reference_primary(
                                    _normalize_import_reference(class_mod, class_name),
                                    name="INST/OBJ/NEWOBJ/NEWOBJ_EX Opcode Safety Check",
                                    message=(
                                        f"Found {opcode.name} opcode with non-allowlisted class: {associated_class}"
                                    ),
                                    severity=severity,
                                    location=location,
                                    details=details,
                                    why=get_opcode_explanation(opcode.name),
                                    rule_code=None,
                                ):
                                    suspicious_count += 1
                    else:
                        # No associated class found via backward search
                        # Try fallback: INST in protocol 0 encodes class info directly in arg
                        if opcode.name == "INST" and isinstance(arg, str):
                            # Parse arg using helper function
                            parsed = _parse_module_function(arg)
                            if parsed:
                                class_mod, class_name = parsed
                                associated_class = f"{class_mod}.{class_name}"
                                is_safe_class = _is_safe_ml_global(class_mod, class_name)

                                if is_safe_class:
                                    # Safe class found via arg parsing - INFO
                                    result.add_check(
                                        name="INST/OBJ/NEWOBJ/NEWOBJ_EX Opcode Safety Check",
                                        passed=True,
                                        message=f"{opcode.name} opcode with safe ML class: {associated_class}",
                                        severity=IssueSeverity.INFO,
                                        location=f"{self.current_file_path} (pos {pos})",
                                        details={
                                            "position": pos,
                                            "opcode": opcode.name,
                                            "associated_class": associated_class,
                                            "security_note": (
                                                f"This {opcode.name} operation instantiates a safe ML framework class "
                                                "and is expected in model files. "
                                                "The class is in the ML_SAFE_GLOBALS allowlist."
                                            ),
                                            "ml_context_confidence": ml_context.get(
                                                "overall_confidence",
                                                0,
                                            ),
                                        },
                                    )
                                    continue  # Skip unknown-class WARNING below

                        # Still no class found, or class not safe - gate WARNING on ml_context
                        # Only emit WARNING if not in ML context or low confidence
                        is_ml_content = ml_context.get("is_ml_content", False)
                        ml_confidence = ml_context.get("overall_confidence", 0)

                        if not is_ml_content or ml_confidence < 0.3:
                            # Not ML content or low confidence - emit WARNING
                            severity = _get_context_aware_severity(
                                IssueSeverity.WARNING,
                                ml_context,
                            )
                            result.add_check(
                                name="INST/OBJ/NEWOBJ/NEWOBJ_EX Opcode Safety Check",
                                passed=False,
                                message=f"Found {opcode.name} opcode - potential code execution (class unknown)",
                                severity=severity,
                                location=f"{self.current_file_path} (pos {pos})",
                                rule_code=get_pickle_opcode_rule_code(opcode.name),
                                details={
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "argument": str(arg),
                                    "ml_context_confidence": ml_confidence,
                                },
                                why=get_opcode_explanation(opcode.name),
                            )

                # Check for suspicious strings
                if opcode.name in STRING_OPCODES and isinstance(arg, str):
                    suspicious_pattern = _is_actually_dangerous_string(arg, ml_context)
                    if suspicious_pattern:
                        severity = (
                            IssueSeverity.INFO
                            if suspicious_pattern == "potential_base64"
                            else _get_context_aware_severity(
                                IssueSeverity.WARNING,
                                ml_context,
                            )
                        )
                        # Determine rule code based on pattern
                        string_rule_code: str | None = None
                        if "eval" in suspicious_pattern or "exec" in suspicious_pattern:
                            string_rule_code = "S104"
                        elif "os.system" in suspicious_pattern:
                            string_rule_code = "S101"
                        elif "subprocess" in suspicious_pattern:
                            string_rule_code = "S103"
                        elif "__import__" in suspicious_pattern:
                            string_rule_code = "S106"
                        elif "compile" in suspicious_pattern:
                            string_rule_code = "S105"
                        else:
                            string_rule_code = get_generic_rule_code(suspicious_pattern)

                        result.add_check(
                            name="String Pattern Security Check",
                            passed=False,
                            message=f"Suspicious string pattern: {suspicious_pattern}",
                            severity=severity,
                            location=f"{self.current_file_path} (pos {pos})",
                            rule_code=string_rule_code,
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

                for nested_finding in _collect_nested_pickle_opcode_findings(opcode.name, arg, pos, ml_context):
                    result.add_check(
                        name=nested_finding["check_name"],
                        passed=False,
                        message=nested_finding["message"],
                        severity=nested_finding["severity"],
                        location=f"{self.current_file_path} (pos {pos})",
                        rule_code=nested_finding["rule_code"],
                        details=nested_finding["details"],
                        why=nested_finding["why"],
                    )

                for encoded_python_finding in _collect_encoded_python_opcode_findings(
                    opcode.name,
                    arg,
                    pos,
                    ml_context,
                ):
                    result.add_check(
                        name=encoded_python_finding["check_name"],
                        passed=False,
                        message=encoded_python_finding["message"],
                        severity=encoded_python_finding["severity"],
                        location=f"{self.current_file_path} (pos {pos})",
                        rule_code=encoded_python_finding["rule_code"],
                        details=encoded_python_finding["details"],
                        why=encoded_python_finding["why"],
                    )

            # Check for STACK_GLOBAL patterns
            # (rebuild from opcodes to get proper context)
            for i, (opcode, _arg, pos) in enumerate(opcodes):
                if opcode.name == "STACK_GLOBAL":
                    resolved = stack_global_refs.get(i)
                    if resolved:
                        is_import_only = i not in executed_import_origins
                        mod, func = resolved
                        is_failure, base_sev_stack, classification = _classify_import_reference(
                            mod,
                            func,
                            ml_context,
                            is_import_only=is_import_only,
                        )
                        if is_failure and base_sev_stack is not None:
                            ref_key = _normalize_import_reference(mod, func)
                            severity_level_stack: IssueSeverity = base_sev_stack
                            severity = _get_context_aware_severity(
                                severity_level_stack,
                                ml_context,
                                issue_type="dangerous_global",
                            )
                            rule_code = get_import_rule_code(mod, func) or "S205"
                            message = (
                                f"Suspicious import-only module reference found: {mod}.{func}"
                                if classification == "unknown_third_party" and is_import_only
                                else f"Suspicious module reference found: {mod}.{func}"
                            )
                            location = f"{self.current_file_path} (pos {pos})"
                            details = {
                                "module": mod,
                                "function": func,
                                "position": pos,
                                "opcode": opcode.name,
                                "import_reference": f"{mod}.{func}",
                                "import_only": is_import_only,
                                "classification": classification,
                                "ml_context_confidence": ml_context.get("overall_confidence", 0),
                            }
                            if ref_key in executed_ref_keys:
                                supporting_import_evidence = {
                                    "check_name": "STACK_GLOBAL Module Check",
                                    "message": message,
                                    "location": location,
                                    "details": dict(details),
                                }
                                existing = primary_ref_findings.get(ref_key)
                                if existing is not None:
                                    _append_supporting_evidence(existing, supporting_import_evidence)
                                else:
                                    pending_supporting_imports.setdefault(ref_key, []).append(
                                        supporting_import_evidence,
                                    )
                            elif _record_reference_primary(
                                ref_key,
                                name="STACK_GLOBAL Module Check",
                                message=message,
                                severity=severity,
                                location=location,
                                details=details,
                                why=get_import_explanation(f"{mod}.{func}"),
                                rule_code=rule_code,
                            ):
                                suspicious_count += 1
                        elif classification == "safe_allowlisted":
                            result.add_check(
                                name="STACK_GLOBAL Module Check",
                                passed=True,
                                message=f"Safe module reference validated: {mod}.{func}",
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "module": mod,
                                    "function": func,
                                    "import_reference": f"{mod}.{func}",
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "import_only": is_import_only,
                                    "classification": classification,
                                    "ml_context_confidence": ml_context.get("overall_confidence", 0),
                                },
                                rule_code=None,
                            )
                    else:
                        malformed = malformed_stack_globals.get(i)
                        if malformed and malformed["reason"] != "insufficient_context":
                            suspicious_count += 1
                            malformed_finding = _build_malformed_stack_global_finding(
                                pos=pos,
                                malformed=malformed,
                                ml_context=ml_context,
                            )
                            result.add_check(
                                name=malformed_finding["check_name"],
                                passed=False,
                                message=malformed_finding["message"],
                                severity=malformed_finding["severity"],
                                location=f"{self.current_file_path} (pos {pos})",
                                rule_code=malformed_finding["rule_code"],
                                details=malformed_finding["details"],
                                why=malformed_finding["why"],
                            )
                        elif not ml_context.get("is_ml_content", False):
                            result.add_check(
                                name="STACK_GLOBAL Context Check",
                                passed=False,
                                message="STACK_GLOBAL opcode found without sufficient string context",
                                severity=IssueSeverity.INFO,
                                location=f"{self.current_file_path} (pos {pos})",
                                rule_code="S902",
                                details={
                                    "position": pos,
                                    "opcode": opcode.name,
                                    "stack_size": "unknown",
                                    "ml_context_confidence": ml_context.get("overall_confidence", 0),
                                },
                                why=(
                                    "STACK_GLOBAL requires two strings on the stack (module and function name) to "
                                    "import and access module attributes. Insufficient context prevents determining "
                                    "which module is being accessed."
                                ),
                            )

            # Check for dangerous patterns in the opcodes
            # SECURITY: Always run reduce pattern analysis regardless of ML context.
            # ML context must not suppress security-critical pattern detection.
            dangerous_pattern = is_dangerous_reduce_pattern(
                opcodes,
                stack_global_refs=stack_global_refs,
                callable_refs=callable_refs,
                callable_origin_is_ext=callable_origin_is_ext,
                mutation_target_refs=analysis.mutation_target_refs,
            )
            if dangerous_pattern:
                dangerous_pattern_finding = _build_dangerous_reduce_pattern_finding(
                    dangerous_pattern,
                    ml_context,
                )
                normalized_pattern_mod, normalized_pattern_func = _normalize_import_reference(
                    dangerous_pattern.get("module", ""),
                    dangerous_pattern.get("function", ""),
                )
                is_build_setstate = dangerous_pattern.get("pattern") == "BUILD_SETSTATE_NON_SAFE_GLOBAL"
                location = f"{self.current_file_path} (pos {dangerous_pattern.get('position', 0)})"
                if is_build_setstate:
                    suspicious_count += 1
                    result.add_check(
                        name=dangerous_pattern_finding["check_name"],
                        passed=False,
                        message=dangerous_pattern_finding["message"],
                        severity=dangerous_pattern_finding["severity"],
                        rule_code=dangerous_pattern_finding["rule_code"],
                        location=location,
                        details=dangerous_pattern_finding["details"],
                        why=dangerous_pattern_finding["why"],
                    )
                elif dangerous_pattern.get("module") and dangerous_pattern.get("function"):
                    if _record_reference_primary(
                        (normalized_pattern_mod, normalized_pattern_func),
                        name=dangerous_pattern_finding["check_name"],
                        message=dangerous_pattern_finding["message"],
                        severity=dangerous_pattern_finding["severity"],
                        location=location,
                        details=dangerous_pattern_finding["details"],
                        why=dangerous_pattern_finding["why"],
                        rule_code=dangerous_pattern_finding["rule_code"],
                    ):
                        suspicious_count += 1
                else:
                    suspicious_count += 1
                    result.add_check(
                        name=dangerous_pattern_finding["check_name"],
                        passed=False,
                        message=dangerous_pattern_finding["message"],
                        severity=dangerous_pattern_finding["severity"],
                        rule_code=dangerous_pattern_finding["rule_code"],
                        location=location,
                        details=dangerous_pattern_finding["details"],
                        why=dangerous_pattern_finding["why"],
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
            suspicious_sequences = check_opcode_sequence(
                opcodes,
                ml_context,
                stack_global_refs=stack_global_refs,
                callable_refs=callable_refs,
                callable_origin_is_ext=callable_origin_is_ext,
            )
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
                        rule_code="S902",
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
                            "(REDUCE, INST, OBJ, NEWOBJ, NEWOBJ_EX). "
                            "Such patterns are uncommon in legitimate model files."
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
            is_pytorch_like_ext = file_ext in {".bin", ".pt", ".pth", ".ckpt"}
            is_serialization_ext = file_ext in {".joblib", ".dill"}

            # Detect joblib/sklearn content from parsed globals for extensionless files
            # (e.g. HuggingFace cache stores files as hash blobs without extensions)
            has_joblib_globals = any(
                mod in {"joblib", "sklearn", "numpy"} or mod.startswith(("joblib.", "sklearn.", "numpy."))
                for mod, _func, _opcode in advanced_globals
            )
            has_dill_globals = any(
                mod in {"dill", "_dill"} or mod.startswith(("dill.", "_dill.", "dill._dill"))
                for mod, _func, _opcode in advanced_globals
            )
            is_joblib_content = is_serialization_ext or (not file_ext and has_joblib_globals)

            # Check for recursion errors on legitimate ML model files
            is_recursion_error = isinstance(e, RecursionError)
            # Be more specific - only for large model files (>100MB) with ML extensions
            is_large_ml_model = (
                file_ext in {".bin", ".pt", ".pth", ".ckpt"} and file_size > 100 * 1024 * 1024  # > 100MB
            )

            # Pre-validate file legitimacy to avoid nested exceptions
            is_legitimate_file = False
            if is_joblib_content or is_large_ml_model or is_pytorch_like_ext:
                try:
                    if is_joblib_content:
                        is_legitimate_file = _is_legitimate_serialization_file(self.current_file_path)
                    elif is_pytorch_like_ext:
                        # For PyTorch model files, check if they look legitimate.
                        is_legitimate_file = self._is_legitimate_pytorch_model(self.current_file_path)
                except Exception:
                    # If validation itself fails, treat as non-legitimate
                    is_legitimate_file = False

            # Tighten MemoryError downgrade: only allow when parsed globals look like
            # legitimate PyTorch structures and no dangerous global references appear.
            global_validation_context = {"is_ml_content": False, "overall_confidence": 0.0, "frameworks": {}}
            has_dangerous_advanced_global = any(
                _is_actually_dangerous_global(mod, func, global_validation_context)
                for mod, func, _opcode in advanced_globals
            )
            has_pytorch_advanced_global = any(
                mod == "torch" or mod.startswith("torch.") for mod, _func, _opcode in advanced_globals
            )
            has_ordereddict_global = any(
                mod == "collections" and func == "OrderedDict" for mod, func, _opcode in advanced_globals
            ) or any(mod == "torch" and func == "OrderedDict" for mod, func, _opcode in advanced_globals)
            has_legitimate_pytorch_globals = (
                bool(advanced_globals)
                and (has_pytorch_advanced_global or has_ordereddict_global)
                and not has_dangerous_advanced_global
            )
            # Require positive opcode-level framework globals for .joblib files;
            # marker bytes and extensions alone are too weak. Dill stays more
            # permissive because legitimate plain-object dill payloads may not
            # expose dill globals before a resource limit hits.
            has_extension_based_serialization_globals = (
                file_ext == ".joblib" and bool(advanced_globals) and has_joblib_globals
            ) or (file_ext == ".dill" and (has_dill_globals or not advanced_globals))
            has_legitimate_serialization_globals = (
                has_extension_based_serialization_globals
                or (not file_ext and bool(advanced_globals) and has_joblib_globals)
            ) and not has_dangerous_advanced_global
            passes_global_gate = (
                has_legitimate_pytorch_globals
                if file_ext == ".bin"
                else has_legitimate_serialization_globals
                if is_joblib_content
                else not has_dangerous_advanced_global
            )

            has_non_info_findings = any(
                issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues
            )
            has_minimum_bin_size = file_ext != ".bin" or file_size >= 128 * 1024
            is_memory_limit_on_legitimate_model = (
                isinstance(e, MemoryError)
                and (is_pytorch_like_ext or is_joblib_content)
                and is_legitimate_file
                and passes_global_gate
                and has_minimum_bin_size
                and not has_non_info_findings
            )

            # Check if this is a known benign error in legitimate serialization files
            is_benign_error = (
                isinstance(e, ValueError | struct.error)
                and any(
                    msg in str(e).lower()
                    for msg in [
                        "unknown opcode",
                        "unpack requires",
                        "truncated",
                        "bad marshal data",
                    ]
                )
                and is_joblib_content
                and is_legitimate_file
            )

            # Check if this is a recursion error on a legitimate ML model
            is_recursion_on_legitimate_model = is_recursion_error and is_large_ml_model and is_legitimate_file

            if is_memory_limit_on_legitimate_model:
                file_type_label = "serialization" if is_joblib_content else "PyTorch"
                file_type_meta = "legitimate_serialization_file" if is_joblib_content else "legitimate_pytorch_model"
                logger.info(
                    f"Memory limit reached scanning {self.current_file_path}. "
                    f"Treating as scanner limitation for legitimate {file_type_label} pickle."
                )
                result.metadata.update(
                    {
                        "memory_limited": True,
                        "file_size": file_size,
                        "file_type": file_type_meta,
                        "opcodes_analyzed": opcode_count,
                        "scanner_limitation": True,
                        "analysis_incomplete": True,
                    }
                )
                _mark_inconclusive_scan_result(result, "memory_limit")
                result.add_check(
                    name="Pickle Parse Resource Limit",
                    passed=False,
                    message="Scan limited by model complexity and memory budget",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={
                        "reason": "memory_limit_on_legitimate_model",
                        "opcodes_analyzed": opcode_count,
                        "file_size": file_size,
                        "file_format": file_ext,
                        "exception_type": "MemoryError",
                        "scanner_limitation": True,
                        "analysis_incomplete": True,
                    },
                    why=(
                        f"This file appears to be a legitimate {file_type_label} pickle, but analysis hit memory "
                        "limits while walking complex object graphs. The analyzable portion was scanned for "
                        "security issues."
                    ),
                )
            elif is_recursion_on_legitimate_model:
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
                _mark_inconclusive_scan_result(result, "recursion_limit_exceeded")
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
                        "scanner_limitation": True,
                        "analysis_incomplete": True,
                    },
                    why=(
                        "This model file contains complex nested structures that exceed the scanner's "
                        "complexity limits. Complex model architectures with deeply nested structures can "
                        "exceed Python's recursion limits during analysis. The file appears legitimate based "
                        "on format validation."
                    ),
                    rule_code="S902",
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
                if first_pickle_end_pos is not None:
                    result.metadata["first_pickle_end_pos"] = first_pickle_end_pos
                    result.metadata["pickle_bytes"] = first_pickle_end_pos
                    result.metadata["binary_bytes"] = max(file_size - first_pickle_end_pos, 0)
                _mark_inconclusive_scan_result(result, "recursion_limit_exceeded")
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
                        "scanner_limitation": True,
                        "analysis_incomplete": True,
                    },
                    why=(
                        "The pickle file structure is too complex for the scanner to fully analyze due to "
                        "Python's recursion limits. This often occurs with legitimate but complex data structures. "
                        "Consider manually inspecting the file if security is a concern."
                    ),
                    rule_code="S902",
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
                _mark_inconclusive_scan_result(result, "stream_integrity_limited")
                # Still add as info-level issue for transparency
                result.add_check(
                    name="Pickle Stream Integrity Check",
                    passed=False,
                    message=f"Scan truncated due to format complexity: {type(e).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={
                        "reason": "post_stop_data_or_format_issue",
                        "opcodes_analyzed": opcode_count,
                        "file_format": file_ext,
                        "stream_complete": False,
                        "bytes_processed": opcode_count,
                        "analysis_incomplete": True,
                    },
                    why=(
                        "This file contains data after the pickle STOP opcode or uses format features that cannot "
                        "be fully analyzed. The analyzable portion was scanned for security issues."
                    ),
                )
            else:
                # Improve error messages for common cases
                error_str = str(e).lower()
                is_parse_failure = self._is_pickle_parse_failure(e)
                is_bin_file = file_ext == ".bin"

                if is_parse_failure and is_bin_file:
                    logger.debug(f"Binary file {self.current_file_path} does not contain valid pickle data: {e}")
                    result.add_check(
                        name="Pickle Format Check",
                        passed=True,
                        message="File appears to be binary data rather than pickle format",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={
                            "file_type": "binary",
                            "pickle_parse_error": str(e),
                        },
                        why=(
                            "This binary file does not contain valid pickle data structure. "
                            "Binary content was analyzed for security patterns instead."
                        ),
                    )
                    result.metadata.update(
                        {
                            "file_type": "binary",
                            "pickle_parsing_failed": True,
                        }
                    )
                    self._scan_binary_payload(
                        file_obj,
                        result,
                        start_pos=0,
                        file_size=file_size,
                        full_file=True,
                    )
                    result.finish(success=True)
                    return result

                if is_parse_failure and file_ext in [
                    ".pkl",
                    ".pickle",
                    ".joblib",
                    ".dill",
                    ".pt",
                    ".pth",
                    ".ckpt",
                ]:
                    logger.warning(f"Pickle parse failed for {self.current_file_path}: {e}")
                    result.add_check(
                        name="Pickle Format Check",
                        passed=False,
                        message="Pickle parsing failed before full scan completion",
                        severity=IssueSeverity.CRITICAL,
                        location=self.current_file_path,
                        details={
                            "file_type": "pickle",
                            "parse_error": str(e),
                            "parsing_failed": True,
                            "failure_reason": "unknown_opcode_or_format_error",
                        },
                        why=(
                            "The scanner could not fully parse this pickle file due to an opcode/format error. "
                            "Because full opcode analysis did not complete, the file is treated as unsafe."
                        ),
                    )
                    result.metadata.update(
                        {
                            "file_type": "pickle",
                            "parsing_failed": True,
                            "failure_reason": "unknown_opcode_or_format_error",
                        }
                    )
                    result.finish(success=False)
                    return result

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
                    rule_code="S901",
                    why=why,
                )

        finally:
            # Restore original recursion limit
            import contextlib

            with contextlib.suppress(NameError):
                sys.setrecursionlimit(original_recursion_limit)  # type: ignore[possibly-unresolved-reference]

        _finish_with_inconclusive_contract(result, default_success=not timed_out)
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

                # For large-enough files with multiple PyTorch indicators, likely legitimate.
                # Keep lower bound modest so small public checkpoints (e.g., tiny HF models)
                # do not trigger parser-limit false positives.
                file_size = os.path.getsize(path)
                is_reasonable_size = 128 * 1024 <= file_size < 1024 * 1024 * 1024 * 1024  # 128KB to 1TB
                indicator_count = sum(1 for indicator in pytorch_indicators if indicator in header)
                has_strong_pytorch_signature = indicator_count >= 2

                return has_pytorch_patterns and has_strong_pytorch_signature and is_reasonable_size

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
            from modelaudit.utils.helpers.ml_context import (
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
                        # Determine rule code based on pattern
                        pattern_str = pattern.decode("ascii", errors="ignore")
                        rule_code = None
                        if "eval" in pattern_str or "exec" in pattern_str:
                            rule_code = "S104"
                        elif "os.system" in pattern_str or "os.popen" in pattern_str:
                            rule_code = "S101"
                        elif "subprocess" in pattern_str:
                            rule_code = "S103"
                        else:
                            rule_code = get_generic_rule_code(pattern_str)

                        result.add_check(
                            name="Binary Data Safety Check",
                            passed=False,
                            message=(
                                f"Suspicious code pattern in binary data: {pattern.decode('ascii', errors='ignore')}"
                            ),
                            rule_code=rule_code,
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
                        rule_code="S902",
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
                    # Get rule code for executable type
                    exec_rule = get_embedded_code_rule_code(description)
                    result.add_check(
                        name="Executable Signature Detection",
                        passed=False,
                        message=f"Executable signature found in binary data: {description}",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{self.current_file_path} (offset: {offset})",
                        rule_code=exec_rule,
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

                # Add debug note about ignored patterns if significant (only shown in verbose mode)
                if ignored_count > 0 and len(positions) > 10:
                    explanation = get_ml_context_explanation(first_chunk_ml_context, len(positions))
                    result.add_check(
                        name="ML Context Filtering",
                        passed=True,
                        message=(
                            f"Ignored {ignored_count} likely false positive {description} patterns in ML weight data"
                        ),
                        location=f"{self.current_file_path}",
                        details={
                            "signature": sig.hex(),
                            "ignored_count": ignored_count,
                            "total_found": len(positions),
                            "pattern_density_per_mb": round(pattern_density, 1),
                            "ml_context_explanation": explanation,
                            "ml_context_confidence": first_chunk_ml_context.get("weight_confidence", 0),
                        },
                        rule_code=None,  # Passing check
                    )

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
                        rule_code="S501",
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

                # Note about ignored PE patterns (only shown in verbose mode)
                if ignored_pe_count > 0:
                    explanation = get_ml_context_explanation(first_chunk_ml_context, len(pe_positions))
                    result.add_check(
                        name="PE Pattern ML Filtering",
                        passed=True,
                        message=(
                            f"Ignored {ignored_pe_count} likely false positive PE executable patterns in ML weight data"
                        ),
                        location=f"{self.current_file_path}",
                        details={
                            "signature": pe_sig.hex(),
                            "ignored_count": ignored_pe_count,
                            "total_found": len(pe_positions),
                            "ml_context_explanation": explanation,
                        },
                        rule_code=None,  # Passing check
                    )

            result.bytes_scanned = bytes_scanned

        except Exception as e:
            result.add_check(
                name="Binary Content Scan",
                passed=False,
                message=f"Error scanning binary content: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                rule_code="S999",
                details={"exception": str(e), "exception_type": type(e).__name__},
            )

        return result

    def _detect_cve_2026_24747_sequences(
        self,
        opcodes: list[tuple],
        file_size: int,
        *,
        stack_global_refs: dict[int, tuple[str, str]] | None = None,
        mutation_target_refs: dict[int, _MutationTargetRef] | None = None,
    ) -> list[dict]:
        """Detect opcode sequences indicating CVE-2026-24747 exploitation.

        CVE-2026-24747 bypasses PyTorch's weights_only=True restricted unpickler
        via SETITEM/SETITEMS applied to non-dict objects (particularly after
        _rebuild_tensor operations) and tensor metadata mismatches.

        Uses context-aware analysis: SETITEM on dicts is normal and skipped.
        Only SETITEM in suspicious contexts (after tensor rebuild, near dangerous
        globals) is flagged.
        """
        patterns: list[dict] = []
        # Pre-compute symbolic references and mutation targets.
        # This handles BINUNICODE8, memoized strings (BINGET/LONG_BINGET),
        # and indirect stack flows that a narrow lookback would miss.
        if stack_global_refs is None or mutation_target_refs is None:
            (
                computed_stack_global_refs,
                _callable_refs,
                _callable_origin_refs,
                _callable_origin_is_ext,
                _malformed_stack_globals,
                computed_mutation_target_refs,
            ) = _simulate_symbolic_reference_maps(opcodes)
            if stack_global_refs is None:
                stack_global_refs = computed_stack_global_refs
            if mutation_target_refs is None:
                mutation_target_refs = computed_mutation_target_refs

        for i, (opcode, _arg, pos) in enumerate(opcodes):
            if opcode.name not in ("SETITEM", "SETITEMS"):
                continue

            # Look backward to determine context
            has_rebuild_tensor = False
            has_dangerous_global = False
            context_details: list[str] = []

            target_ref = mutation_target_refs.get(i)
            if target_ref and target_ref.kind == "dict":
                continue

            if target_ref and target_ref.callable_ref:
                target_global = f"{target_ref.callable_ref[0]}.{target_ref.callable_ref[1]}"
                arg_str = target_global.lower()
                if "_rebuild_tensor" in arg_str or "_rebuild_parameter" in arg_str:
                    has_rebuild_tensor = True
                    context_details.append(f"_rebuild operation: {target_global}")
                if any(
                    d in arg_str
                    for d in [
                        "os.",
                        "subprocess",
                        "eval",
                        "exec",
                        "__import__",
                        "builtins",
                        "ctypes",
                        "socket",
                    ]
                ):
                    has_dangerous_global = True
                    context_details.append(f"dangerous global: {target_global}")

            lookback = min(i, 30)
            # Track whether a dict DIRECTLY produces the object that SETITEM targets.
            # Only suppress when the dict is the most recent container-producing op.
            most_recent_container: str | None = None
            for j in range(i - 1, max(0, i - lookback) - 1, -1):
                prev_op, prev_arg, _prev_pos = opcodes[j]

                # Track the most recent container-producing op
                if prev_op.name in ("EMPTY_DICT", "DICT") and most_recent_container is None:
                    most_recent_container = "dict"
                if prev_op.name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX") and most_recent_container is None:
                    most_recent_container = "object"

                # Resolve STACK_GLOBAL args using pre-computed symbolic map
                # (handles BINUNICODE8, memoized strings via BINGET/LONG_BINGET,
                # and indirect stack flows)
                resolved_arg = prev_arg
                if prev_op.name == "STACK_GLOBAL" and not prev_arg:
                    ref = stack_global_refs.get(j)
                    if ref:
                        resolved_arg = f"{ref[0]}.{ref[1]}"

                # Check for _rebuild_tensor context (suspicious with SETITEM)
                if prev_op.name in ("GLOBAL", "STACK_GLOBAL") and resolved_arg:
                    arg_str = str(resolved_arg).lower()
                    if "_rebuild_tensor" in arg_str or "_rebuild_parameter" in arg_str:
                        has_rebuild_tensor = True
                        context_details.append(f"_rebuild operation: {resolved_arg}")

                    # Check for dangerous modules near SETITEM
                    if any(
                        d in arg_str
                        for d in [
                            "os.",
                            "subprocess",
                            "eval",
                            "exec",
                            "__import__",
                            "builtins",
                            "ctypes",
                            "socket",
                        ]
                    ):
                        has_dangerous_global = True
                        context_details.append(f"dangerous global: {resolved_arg}")

            # Skip only when the dict is the most recent container-producing op,
            # meaning the SETITEM is directly targeting a dict (legitimate).
            # If a REDUCE/NEWOBJ is more recent, the dict is unrelated.
            if target_ref is None and most_recent_container == "dict":
                continue

            if has_rebuild_tensor:
                patterns.append(
                    {
                        "pattern_type": "setitem_on_tensor_object",
                        "description": (
                            f"{opcode.name} applied after tensor reconstruction ({', '.join(context_details)})"
                        ),
                        "opcodes": [opcode.name],
                        "exploitation_method": (
                            "CVE-2026-24747: SETITEM abuse on reconstructed tensor object "
                            "bypasses weights_only=True restricted unpickler"
                        ),
                        "position": pos,
                        "cve_id": "CVE-2026-24747",
                    }
                )

            if has_dangerous_global:
                patterns.append(
                    {
                        "pattern_type": "setitem_near_dangerous_global",
                        "description": (
                            f"{opcode.name} near dangerous global reference ({', '.join(context_details)})"
                        ),
                        "opcodes": [opcode.name],
                        "exploitation_method": ("CVE-2026-24747: SETITEM used to inject into dangerous context"),
                        "position": pos,
                        "cve_id": "CVE-2026-24747",
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
            from modelaudit.detectors.jit_script import JITScriptDetector
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

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract pickle file metadata."""
        metadata = super().extract_metadata(file_path)

        allow_deserialization = bool(self.config.get("allow_metadata_deserialization"))
        metadata_read_cap = 10 * 1024 * 1024

        try:
            import pickle
            import pickletools
            from io import BytesIO

            max_metadata_read_size = int(self.config.get("max_metadata_pickle_read_size", metadata_read_cap))

            if max_metadata_read_size <= 0:
                raise ValueError(
                    f"Invalid pickle metadata read limit: {max_metadata_read_size} (must be greater than 0)"
                )
            max_metadata_read_size = min(max_metadata_read_size, metadata_read_cap)

            file_size = self.get_file_size(file_path)
            if file_size > max_metadata_read_size:
                raise ValueError(
                    f"Pickle metadata read limit exceeded: {file_size} bytes (max: {max_metadata_read_size})"
                )

            with open(file_path, "rb") as f:
                pickle_data = f.read(max_metadata_read_size + 1)

            if len(pickle_data) > max_metadata_read_size:
                raise ValueError(
                    f"Pickle metadata read limit exceeded: {len(pickle_data)} bytes (max: {max_metadata_read_size})"
                )

            # Analyze pickle structure
            metadata.update(
                {
                    "pickle_size": len(pickle_data),
                    "pickle_protocol": self._detect_pickle_protocol(pickle_data),
                }
            )

            # Analyze opcodes
            try:
                # Count different opcode types
                opcode_counts: dict[str, int] = {}
                dangerous_opcodes = []

                # Use pickletools to analyze opcodes
                bio = BytesIO(pickle_data)
                opcodes_info = []
                for opcode, _arg, _pos in pickletools.genops(bio):
                    opcode_name = opcode.name
                    opcode_counts[opcode_name] = opcode_counts.get(opcode_name, 0) + 1
                    opcodes_info.append(opcode_name)

                    # Check for dangerous opcodes (any opcode that can trigger code execution)
                    if opcode_name in [
                        "REDUCE",
                        "INST",
                        "OBJ",
                        "NEWOBJ",
                        "NEWOBJ_EX",
                        "STACK_GLOBAL",
                        "GLOBAL",
                        "BUILD",
                    ]:
                        dangerous_opcodes.append(opcode_name)

                metadata.update(
                    {
                        "opcode_counts": opcode_counts,
                        "dangerous_opcodes": list(set(dangerous_opcodes)),
                        "total_opcodes": len(opcodes_info),
                        "has_dangerous_opcodes": len(dangerous_opcodes) > 0,
                    }
                )

            except Exception:
                pass

            # Try to load and analyze content (safely) only if explicitly allowed
            if allow_deserialization:
                try:
                    # Only try to load if it looks safe (no dangerous opcodes)
                    if not metadata.get("dangerous_opcodes"):
                        with open(file_path, "rb") as f:
                            try:
                                obj = pickle.load(f)
                                metadata.update(
                                    {
                                        "object_type": type(obj).__name__,
                                        "object_module": getattr(type(obj), "__module__", "unknown"),
                                    }
                                )

                                # Analyze object structure
                                if isinstance(obj, dict):
                                    metadata.update(
                                        {
                                            "dict_keys": list(obj.keys())[:10],  # First 10 keys
                                            "dict_size": len(obj),
                                        }
                                    )
                                elif hasattr(obj, "__dict__"):
                                    attrs = list(obj.__dict__.keys())[:10]
                                    metadata.update(
                                        {
                                            "object_attributes": attrs,
                                            "attribute_count": len(obj.__dict__),
                                        }
                                    )

                            except Exception:
                                metadata["safe_loading"] = False
                    else:
                        metadata["safe_loading"] = False

                except Exception:
                    metadata["safe_loading"] = False
            else:
                metadata["safe_loading"] = False
                metadata["deserialization_skipped"] = True
                metadata["reason"] = "Deserialization disabled for metadata extraction"

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata

    def _detect_pickle_protocol(self, data: bytes) -> int:
        """Detect pickle protocol version."""
        if not data:
            return 0

        # Binary protocols start with PROTO opcode (0x80) followed by protocol number.
        # Any non-binary opener is protocol 0/1 ASCII style; report as 0 for scanner logic.
        if data[0] == 0x80 and len(data) > 1:
            return data[1]

        return 0
