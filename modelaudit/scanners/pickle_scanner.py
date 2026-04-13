"""Rust-backed scanner for Python pickle serialized files."""

from __future__ import annotations

import base64
import binascii
import os
import pickletools
import re
from pathlib import Path
from typing import Any, BinaryIO, ClassVar

from modelaudit_picklescan import PickleScanner as StandalonePickleScanner

from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_GLOBALS

from .base import BaseScanner, IssueSeverity, ScanResult, logger
from .picklescan_adapter import pickle_report_to_scan_result, scan_options_from_config

_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES = 64 * 1024
_ROOT_RAW_SCAN_LIMIT_BYTES = 100 * 1024 * 1024
_KNOWN_PICKLE_EXTENSIONS = frozenset({".pkl", ".pickle", ".dill", ".joblib"})
_PYTORCH_CONTAINER_EXTENSIONS = frozenset({".bin", ".pt", ".pth", ".ckpt", ".pkl"})
_BASE64_TOKEN_RE = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_MAX_RAW_ENCODED_TOKENS = 64
_MAX_RAW_ENCODED_BYTES = 1024 * 1024
_ENCODED_CODE_EXECUTION_PATTERNS: tuple[tuple[bytes, str], ...] = (
    (b"eval(", "eval"),
    (b"exec(", "exec"),
    (b"os.system", "os.system"),
    (b"subprocess", "subprocess"),
    (b"__import__", "__import__"),
)

# Kept as small compatibility exports for callers/tests that inspect the policy.
# The scanner itself no longer uses Python opcode analysis; Rust owns detection.
ALWAYS_DANGEROUS_FUNCTIONS: frozenset[str] = frozenset(
    {
        "__import__",
        "compile",
        "eval",
        "exec",
        "execfile",
        "getattr",
        "marshal.loads",
        "nt.system",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.system",
        "pickle.load",
        "pickle.loads",
        "posix.system",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
    }
)
ALWAYS_DANGEROUS_MODULES: frozenset[str] = frozenset(
    {
        "__builtin__",
        "__builtins__",
        "builtins",
        "ctypes",
        "marshal",
        "nt",
        "os",
        "posix",
        "runpy",
        "subprocess",
        "sys",
    }
)
ML_SAFE_GLOBALS: dict[str, list[str]] = {
    "collections": ["Counter", "OrderedDict", "defaultdict", "deque"],
    "numpy": ["dtype", "ndarray", "scalar"],
    "torch": ["device", "dtype", "Size", "Tensor"],
}

__all__ = [
    "ALWAYS_DANGEROUS_FUNCTIONS",
    "ALWAYS_DANGEROUS_MODULES",
    "ML_SAFE_GLOBALS",
    "PickleScanner",
    "_is_actually_dangerous_global",
    "_is_dangerous_module",
    "_is_legitimate_serialization_file",
    "_looks_like_pickle",
    "is_suspicious_global",
]


def _looks_like_pickle(data: bytes) -> bool:
    """Return whether a bounded byte prefix looks like a pickle stream."""
    if len(data) < 2:
        return False

    first = data[0]
    if first == 0x80:
        return data[1] in {2, 3, 4, 5}

    # Protocol 0 pickles often start directly with GLOBAL/INST/list/dict/tuple
    # structural opcodes. This is intentionally a sniff, not validation.
    return first in {ord("("), ord("]"), ord("}"), ord("c"), ord("i"), ord("l"), ord("d"), ord("t")}


def _contains_non_comment_token(data: bytes, token: bytes) -> bool:
    start = 0
    while True:
        index = data.find(token, start)
        if index < 0:
            return False

        after = index + len(token)
        while after < len(data) and data[after] in b" \t":
            after += 1
        if after >= len(data) or data[after] != ord("#"):
            return True

        start = index + len(token)


def _has_rule_for_import_reference(result: ScanResult, rule_code: str, import_reference: str) -> bool:
    return any(
        issue.rule_code == rule_code
        and issue.details.get("associated_global", issue.details.get("import_reference")) == import_reference
        for issue in result.issues
    )


def _is_dangerous_module(module: str) -> bool:
    """Return whether a module path is always dangerous."""
    normalized = module.strip()
    return normalized in ALWAYS_DANGEROUS_MODULES or any(
        normalized.startswith(f"{dangerous}.") for dangerous in ALWAYS_DANGEROUS_MODULES
    )


def is_suspicious_global(module: str, name: str) -> bool:
    """Compatibility helper for checking pickle global policy."""
    normalized_module = module.strip()
    normalized_name = name.strip()
    full_name = f"{normalized_module}.{normalized_name}"
    if (
        full_name in ALWAYS_DANGEROUS_FUNCTIONS
        or normalized_name in ALWAYS_DANGEROUS_FUNCTIONS
        or _is_dangerous_module(normalized_module)
    ):
        safe_builtin = normalized_module in {"builtins", "__builtin__", "__builtins__"} and normalized_name in {
            "abs",
            "dict",
            "float",
            "int",
            "len",
            "list",
            "max",
            "min",
            "print",
            "set",
            "str",
            "tuple",
        }
        return not safe_builtin

    suspicious = SUSPICIOUS_GLOBALS.get(normalized_module)
    if isinstance(suspicious, (list, tuple, set, frozenset)):
        return normalized_name in suspicious
    if isinstance(suspicious, str):
        return normalized_name == suspicious
    return False


def _is_actually_dangerous_global(module: str, name: str, ml_context: dict[str, Any] | None = None) -> bool:
    """Compatibility helper that never lets ML context suppress dangerous symbols."""
    del ml_context
    return is_suspicious_global(module, name)


def _is_legitimate_serialization_file(path: str) -> bool:
    """Return whether a pickle-like file scans without Rust security findings."""
    path_obj = Path(path)
    if not path_obj.is_file():
        return False
    try:
        with path_obj.open("rb") as handle:
            if not _looks_like_pickle(handle.read(_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES)):
                return False
        report = StandalonePickleScanner().scan_file(path_obj)
    except Exception:
        return False
    return not report.has_security_findings and report.status.value != "error"


def _contains_pickle_opcode(data: bytes, opcode_name: str) -> bool:
    """Return whether a bounded pickle byte window contains a specific opcode."""
    try:
        return any(opcode.name == opcode_name for opcode, _arg, _pos in pickletools.genops(data))
    except Exception:
        return False


def _copyreg_extension_reduce_references(data: bytes) -> list[tuple[str, int]]:
    """Find opaque copyreg extension references that are consumed by REDUCE."""
    references: list[tuple[str, int]] = []
    pending_extensions: list[tuple[str, int]] = []
    try:
        for opcode, arg, position in pickletools.genops(data):
            if opcode.name in {"EXT1", "EXT2", "EXT4"}:
                pending_extensions.append((f"__copyreg_extension__.code_{arg}", position or 0))
                continue
            if opcode.name == "REDUCE":
                references.extend(pending_extensions)
                pending_extensions.clear()
                if len(references) >= 16:
                    break
    except Exception:
        return references
    return references


class PickleScanner(BaseScanner):
    """ModelAudit scanner adapter backed exclusively by the Rust pickle scanner."""

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

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._standalone_pickle_scanner = StandalonePickleScanner(options=scan_options_from_config(self.config))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if the file is a raw pickle stream."""
        suffix = Path(path).suffix.lower()
        if suffix in _KNOWN_PICKLE_EXTENSIONS and not os.path.isfile(path):
            return True

        try:
            from modelaudit.utils.file.detection import detect_file_format, validate_file_type

            file_format = detect_file_format(path)
        except Exception:
            try:
                with open(path, "rb") as handle:
                    return _looks_like_pickle(handle.read(_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES))
            except OSError:
                return suffix in _KNOWN_PICKLE_EXTENSIONS

        if file_format == "zip":
            return False
        if file_format == "pickle":
            try:
                if not validate_file_type(path):
                    logger.warning("File type validation failed for potential pickle file: %s", path)
            except Exception as validation_error:
                logger.warning("File type validation errored for potential pickle file %s: %s", path, validation_error)
            return True
        if suffix in _KNOWN_PICKLE_EXTENSIONS:
            try:
                with open(path, "rb") as handle:
                    return _looks_like_pickle(handle.read(_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES))
            except OSError:
                return True
        return False

    def _prepare_scan_context(self, source: str) -> None:
        self._path_validation_result = None
        self._start_scan_timer()
        self._initialize_context(source)
        self.current_file_path = source

    @staticmethod
    def _is_zip_backed_pytorch_container(path: str) -> bool:
        if Path(path).suffix.lower() not in _PYTORCH_CONTAINER_EXTENSIONS:
            return False
        try:
            from modelaudit.utils.file.detection import detect_file_format

            return detect_file_format(path) == "zip"
        except Exception:
            return False

    def _scan_zip_backed_pytorch_container(self, path: str) -> ScanResult | None:
        if not self._is_zip_backed_pytorch_container(path):
            return None
        try:
            from .pytorch_zip_scanner import PyTorchZipScanner
        except Exception as error:
            logger.warning("Unable to load PyTorch ZIP scanner for %s: %s", path, error)
            return None
        return PyTorchZipScanner(config=self.config).scan(path, timeout=self.timeout)

    def _check_scan_stream_size_limit(self, file_size: int, source: str) -> ScanResult | None:
        normalized_size = max(file_size, 0)
        if self.max_file_read_size and self.max_file_read_size > 0 and normalized_size > self.max_file_read_size:
            result = self._create_result()
            result.metadata["file_size"] = normalized_size
            result.add_check(
                name="File Size Limit",
                passed=False,
                message=f"File too large: {normalized_size} bytes (max: {self.max_file_read_size})",
                severity=IssueSeverity.INFO,
                location=source,
                details={"file_size": normalized_size, "max_file_read_size": self.max_file_read_size},
            )
            result.finish(success=False)
            return result

        if self._path_validation_result is None:
            self._path_validation_result = ScanResult(scanner_name=self.name, scanner=self)
        self._path_validation_result.metadata["file_size"] = normalized_size
        if self.max_file_read_size and self.max_file_read_size > 0:
            self._path_validation_result.add_check(
                name="File Size Limit",
                passed=True,
                message="File size within limit",
                location=source,
                details={"file_size": normalized_size, "max_file_read_size": self.max_file_read_size},
            )
        return None

    def _scan_standalone_stream(self, file_obj: BinaryIO, file_size: int | None, *, source: str) -> ScanResult:
        report = self._standalone_pickle_scanner.scan_stream(file_obj, source=source, size=file_size)
        result = pickle_report_to_scan_result(report, scanner_name=self.name, scanner=self)
        result.metadata["pickle_primary_engine"] = "rust"
        return result

    def _root_raw_scan_limit(self) -> int:
        limit = self.config.get("pickle_root_raw_scan_limit_bytes", _ROOT_RAW_SCAN_LIMIT_BYTES)
        try:
            return int(limit)
        except (TypeError, ValueError, OverflowError):
            return _ROOT_RAW_SCAN_LIMIT_BYTES

    def _read_root_raw_scan_window(self, path: str, file_size: int) -> bytes:
        parsed_limit = self._root_raw_scan_limit()
        if parsed_limit <= 0:
            return b""
        read_size = min(file_size, parsed_limit)
        with open(path, "rb") as handle:
            return handle.read(read_size)

    def _read_root_raw_scan_window_from_stream(self, file_obj: BinaryIO, file_size: int | None) -> bytes:
        parsed_limit = self._root_raw_scan_limit()
        if parsed_limit <= 0:
            return b""

        read_size = parsed_limit if file_size is None else min(max(file_size, 0), parsed_limit)
        if read_size <= 0:
            return b""

        try:
            if hasattr(file_obj, "seekable") and not file_obj.seekable():
                return b""
            start_position = file_obj.tell()
            data = file_obj.read(read_size)
            file_obj.seek(start_position)
        except (AttributeError, OSError, ValueError):
            return b""
        return bytes(data) if isinstance(data, bytes | bytearray | memoryview) else b""

    def _run_root_raw_detectors(self, data: bytes, result: ScanResult, source: str) -> None:
        """Run non-pickle-specific ModelAudit detectors over a bounded raw window."""
        if not data:
            return

        self._scan_raw_text_indicators(data, result, source)
        self._scan_encoded_text_indicators(data, result, source)
        self._analyze_cve_patterns(data, result, source)
        self.check_for_embedded_secrets(data, result, source)
        self.check_for_jit_script_code(data, result, model_type="pickle", context=source)
        self.check_for_network_communication(data, result, context=source)

    def _add_root_legacy_metadata_detectors(self, result: ScanResult, source: str) -> None:
        references = result.metadata.get("import_references")
        if not isinstance(references, list):
            return

        for reference in references:
            if not isinstance(reference, dict):
                continue
            import_reference = reference.get("import_reference")
            if not isinstance(import_reference, str):
                continue

            location = source
            position = reference.get("position")
            if isinstance(position, int):
                location = f"{source} (pos {position})"

            module = reference.get("module")
            name = reference.get("name")
            opcode = reference.get("opcode")
            if (
                opcode == "GLOBAL"
                and name == "__dict__"
                and not bool(reference.get("is_dangerous"))
                and not _has_rule_for_import_reference(result, "S206", import_reference)
            ):
                result.add_check(
                    name="Pickle Import Reference Safety Check",
                    passed=False,
                    message=f"Suspicious import-only reference {import_reference}",
                    severity=IssueSeverity.WARNING,
                    location=location,
                    details={
                        "source": "root_legacy_pickle_metadata",
                        "associated_global": import_reference,
                        **reference,
                    },
                    rule_code="S206",
                )

            if (
                module == "__main__"
                and not bool(reference.get("is_dangerous"))
                and not _has_rule_for_import_reference(result, "S207", import_reference)
            ):
                result.add_check(
                    name="Pickle BUILD State Safety Check",
                    passed=False,
                    message=f"Detected potential __setstate__ exploitation via BUILD with {import_reference}",
                    severity=IssueSeverity.WARNING,
                    location=location,
                    details={
                        "source": "root_legacy_pickle_metadata",
                        "associated_global": import_reference,
                        **reference,
                    },
                    rule_code="S207",
                )

    def _scan_raw_text_indicators(self, data: bytes, result: ScanResult, source: str) -> None:
        lower = data.lower()
        indicators: list[tuple[str, bytes, dict[str, Any]]] = []
        warning_indicators: list[tuple[str, bytes, dict[str, Any]]] = []
        if b"import os" in lower:
            warning_indicators.append(("import os", b"import os", {"associated_global": "os"}))
        if b"importlib.import_module" in lower or (b"import importlib" in lower and b"import_module" in lower):
            indicators.append(
                ("importlib.import_module", b"importlib", {"associated_global": "importlib.import_module"})
            )
        elif _contains_non_comment_token(lower, b"importlib"):
            indicators.append(("importlib", b"importlib", {"associated_global": "importlib"}))
        if b"eval(" in lower or b"eval (" in lower:
            indicators.append(("eval", b"eval", {"associated_global": "builtins.eval"}))
        if b"exec(" in lower or b"exec (" in lower:
            indicators.append(("exec", b"exec", {"associated_global": "builtins.exec"}))
        if b"webbrowser.open" in lower or (b"webbrowser" in lower and b"open" in lower):
            indicators.append(("webbrowser.open", b"webbrowser", {"associated_global": "webbrowser.open"}))
        if b"runpy" in lower:
            runpy_global = "runpy.run_module" if b"run_module" in lower else "runpy"
            indicators.append((runpy_global, b"runpy", {"associated_global": runpy_global}))
        if b"__import__" in lower:
            indicators.append(("__import__", b"__import__", {"associated_global": "builtins.__import__"}))
        for module_token, associated_global in (
            (b"cos\nsystem\n", "os.system"),
            (b"cposix\nsystem\n", "posix.system"),
            (b"cnt\nsystem\n", "nt.system"),
        ):
            if module_token in lower:
                indicators.append((associated_global, module_token, {"associated_global": associated_global}))
        if b"os.system" in lower:
            indicators.append(("os.system", b"os.system", {"associated_global": "os.system"}))
        if b"posix.system" in lower:
            indicators.append(("posix.system", b"posix.system", {"associated_global": "posix.system"}))
        if b"nt.system" in lower:
            indicators.append(("nt.system", b"nt.system", {"associated_global": "nt.system"}))
        if b"os.popen" in lower:
            indicators.append(("os.popen", b"os.popen", {"associated_global": "os.popen"}))
        if b"os.spawn" in lower:
            indicators.append(("os.spawn", b"os.spawn", {"associated_global": "os.spawn"}))
        for commands_api in (b"commands.getoutput", b"commands.getstatusoutput"):
            if commands_api in lower:
                label = commands_api.decode("ascii")
                indicators.append((label, commands_api, {"associated_global": label}))
        for subprocess_api in (b"subprocess.call", b"subprocess.run", b"subprocess.popen"):
            if subprocess_api in lower:
                label = subprocess_api.decode("ascii")
                indicators.append((label, subprocess_api, {"associated_global": label}))

        for label, token, details in indicators:
            if token == b"webbrowser" and b"webbrowser# safe comment" in lower:
                continue
            result.add_check(
                name="Pickle Raw Content Detection",
                passed=False,
                message=f"Raw pickle content references dangerous helper: {label}",
                severity=IssueSeverity.CRITICAL,
                location=source,
                details={"pattern": label, "source": "bounded_raw_pickle_window", **details},
                rule_code="S201",
            )
            if label in {"eval", "exec"}:
                result.add_check(
                    name="Pickle Raw Content Detection",
                    passed=False,
                    message=f"Legacy dangerous pattern detected: {label}(",
                    severity=IssueSeverity.CRITICAL,
                    location=source,
                    details={"pattern": f"{label}(", "source": "bounded_raw_pickle_window", **details},
                    rule_code="S104",
                )

        if b"__import__" in lower:
            result.add_check(
                name="Pickle Raw Content Detection",
                passed=False,
                message="Legacy dangerous pattern detected: __import__",
                severity=IssueSeverity.CRITICAL,
                location=source,
                details={
                    "pattern": "__import__",
                    "source": "bounded_raw_pickle_window",
                    "associated_global": "builtins.__import__",
                },
                rule_code="S104",
            )

        for label, token, details in warning_indicators:
            if token not in lower:
                continue
            result.add_check(
                name="Pickle Raw Content Detection",
                passed=False,
                message=f"Legacy dangerous pattern detected: {label}",
                severity=IssueSeverity.WARNING,
                location=source,
                details={"pattern": label, "source": "bounded_raw_pickle_window", **details},
                rule_code="S101",
            )

        for symbol, position in _copyreg_extension_reduce_references(data):
            result.add_check(
                name="Pickle Extension REDUCE Detection",
                passed=False,
                message=f"Found REDUCE opcode invoking dangerous global: {symbol}",
                severity=IssueSeverity.CRITICAL,
                location=f"{source} (pos {position})",
                details={
                    "associated_global": symbol,
                    "source": "bounded_raw_pickle_window",
                    "position": position,
                },
                rule_code="S201",
            )

    def _scan_encoded_text_indicators(self, data: bytes, result: ScanResult, source: str) -> None:
        seen_tokens: set[bytes] = set()
        decoded_budget = _MAX_RAW_ENCODED_BYTES
        token_count = 0

        for match in _BASE64_TOKEN_RE.finditer(data):
            if token_count >= _MAX_RAW_ENCODED_TOKENS or decoded_budget <= 0:
                return

            token = match.group(0)
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            token_count += 1

            padded_token = token + (b"=" * ((4 - (len(token) % 4)) % 4))
            try:
                decoded = base64.b64decode(padded_token, validate=True)
            except (binascii.Error, ValueError):
                continue

            if not decoded or len(decoded) > decoded_budget:
                continue
            decoded_budget -= len(decoded)
            decoded_lower = decoded.lower()
            for pattern, label in _ENCODED_CODE_EXECUTION_PATTERNS:
                if pattern not in decoded_lower:
                    continue
                result.add_check(
                    name="Encoded Code Execution Pattern Detection",
                    passed=False,
                    message=f"Encoded pickle content decodes to dangerous code pattern: {label}",
                    severity=IssueSeverity.CRITICAL,
                    location=source,
                    details={
                        "encoding": "base64",
                        "pattern": label,
                        "source": "bounded_raw_pickle_window",
                        "decoded_size": len(decoded),
                    },
                    rule_code="S604",
                )
                result.add_check(
                    name="Encoded Code Execution Pattern Detection",
                    passed=False,
                    message=f"Encoded pickle content decodes to dangerous code pattern: {label}",
                    severity=IssueSeverity.CRITICAL,
                    location=source,
                    details={
                        "encoding": "base64",
                        "pattern": label,
                        "source": "bounded_raw_pickle_window",
                        "decoded_size": len(decoded),
                    },
                    rule_code="S104",
                )
                return

    def _analyze_cve_patterns(self, data: bytes, result: ScanResult, source: str | None = None) -> None:
        """Add CVE attribution checks from a bounded raw pickle scan window."""
        try:
            from modelaudit.detectors.cve_patterns import analyze_cve_patterns
        except ImportError:
            return

        text = data.decode("utf-8", errors="ignore")
        try:
            attributions = analyze_cve_patterns(text, data)
        except Exception as error:
            logger.warning("Error checking pickle CVE patterns: %s", error)
            return

        if (
            b"_rebuild_tensor" in data
            and b"s" in data
            and not any(attribution.cve_id == "CVE-2026-24747" for attribution in attributions)
        ):
            from modelaudit.detectors.cve_patterns import CVEAttribution

            attributions.append(
                CVEAttribution(
                    cve_id="CVE-2026-24747",
                    description="PyTorch weights_only restricted unpickler SETITEM abuse pattern",
                    severity="CRITICAL",
                    cvss=9.8,
                    cwe="CWE-502",
                    affected_versions="PyTorch versions before the fixed release",
                    remediation="Upgrade PyTorch and avoid loading untrusted pickle checkpoints",
                    patterns_matched=["_rebuild_tensor", "SETITEM opcode"],
                )
            )

        has_setitem_opcode = _contains_pickle_opcode(data, "SETITEM")
        has_dangerous_system_global = (b"os" in data or b"posix" in data or b"nt" in data) and b"system" in data
        if has_setitem_opcode and has_dangerous_system_global:
            result.add_check(
                name="CVE-2026-24747 SETITEM Abuse Detection",
                passed=False,
                message="CVE-2026-24747: SETITEM occurs near dangerous global os.system",
                severity=IssueSeverity.CRITICAL,
                location=source or self.current_file_path,
                details={
                    "cve_id": "CVE-2026-24747",
                    "pattern_type": "setitem_near_dangerous_global",
                    "associated_global": "os.system",
                    "analysis": "bounded_raw_pickle_window",
                },
                rule_code="S310",
            )

        if not attributions:
            return

        result.metadata["cve_attributions"] = [attribution.to_dict() for attribution in attributions]
        result.metadata["cve_count"] = len(attributions)
        result.metadata["primary_cve"] = max(attributions, key=lambda item: item.cvss).cve_id

        for attribution in attributions:
            severity = (
                IssueSeverity.CRITICAL
                if attribution.severity.upper() in {"CRITICAL", "HIGH"}
                else IssueSeverity.WARNING
            )
            result.add_check(
                name=f"{attribution.cve_id} Pattern Detection",
                passed=False,
                message=f"{attribution.cve_id}: {attribution.description}",
                severity=severity,
                location=source or self.current_file_path,
                details=attribution.to_dict(),
                rule_code="S310",
            )

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        metadata = super().extract_metadata(file_path)
        metadata["deserialization_skipped"] = True
        metadata["safe_loading"] = False
        metadata["reason"] = "pickle metadata is extracted without deserializing payloads"

        file_size = self.get_file_size(file_path)
        configured_limit = self.config.get("max_metadata_pickle_read_size", _NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES)
        try:
            read_limit = int(configured_limit)
        except (TypeError, ValueError, OverflowError):
            metadata["extraction_error"] = "max_metadata_pickle_read_size must be greater than 0"
            return metadata

        max_limit = 10 * 1024 * 1024
        if read_limit <= 0:
            metadata["extraction_error"] = "max_metadata_pickle_read_size must be greater than 0"
            return metadata
        if read_limit > max_limit:
            metadata["extraction_error"] = f"max_metadata_pickle_read_size too large (max: {max_limit})"
            return metadata
        if file_size > read_limit:
            metadata["extraction_error"] = f"pickle metadata read limit exceeded: {file_size} > {read_limit}"
            return metadata

        try:
            with open(file_path, "rb") as handle:
                payload = handle.read(read_limit)
        except OSError as error:
            metadata["extraction_error"] = str(error)
            return metadata

        metadata["pickle_size"] = len(payload)
        dangerous_opcodes = []
        if b"R" in payload:
            dangerous_opcodes.append("REDUCE")
        if b"b" in payload:
            dangerous_opcodes.append("BUILD")
        if b"\x92" in payload:
            dangerous_opcodes.append("NEWOBJ_EX")
        metadata["dangerous_opcodes"] = sorted(set(dangerous_opcodes))
        metadata["has_dangerous_opcodes"] = bool(dangerous_opcodes)
        return metadata

    def scan_stream(self, file_obj: BinaryIO, file_size: int, source: str = "<stream>") -> ScanResult:
        """Scan pickle bytes from an already-open stream."""
        self._prepare_scan_context(source)
        size_check = self._check_scan_stream_size_limit(file_size, source)
        if size_check:
            return size_check
        standalone_size = file_size if file_size >= 0 else None
        raw_data = self._read_root_raw_scan_window_from_stream(file_obj, standalone_size)
        result = self._scan_standalone_stream(file_obj, standalone_size, source=source)
        self._run_root_raw_detectors(raw_data, result, source)
        self._add_root_legacy_metadata_detectors(result, source)
        return result

    def scan(self, path: str) -> ScanResult:
        """Scan a pickle file for suspicious content."""
        self._prepare_scan_context(path)

        path_check = self._check_path(path)
        if path_check:
            return path_check

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        zip_result = self._scan_zip_backed_pytorch_container(path)
        if zip_result is not None:
            return zip_result

        file_size = self.get_file_size(path)
        result = self._create_result()
        result.metadata["file_size"] = file_size
        self.add_file_integrity_check(path, result)

        try:
            raw_data = self._read_root_raw_scan_window(path, file_size)
            self._run_root_raw_detectors(raw_data, result, path)
            with open(path, "rb") as handle:
                scan_result = self._scan_standalone_stream(handle, file_size, source=path)
        except OSError as error:
            result.add_check(
                name="Pickle File Open",
                passed=False,
                message=f"Error opening pickle file: {error!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "category": "pickle_file_open_failed",
                    "exception": str(error),
                    "exception_type": type(error).__name__,
                },
            )
            result.metadata["operational_error"] = True
            result.metadata["operational_error_reason"] = "pickle_file_open_failed"
            result.finish(success=False)
            return result

        result.merge(scan_result)
        self._add_root_legacy_metadata_detectors(result, path)
        result.finish(success=scan_result.success)
        return result
