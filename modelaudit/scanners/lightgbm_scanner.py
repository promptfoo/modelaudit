"""Scanner for native LightGBM model artifacts."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any, ClassVar
from urllib.parse import urlparse, urlsplit, urlunsplit

from ..core_results import mark_operational_scan_error
from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from .base import BaseScanner, CheckStatus, IssueSeverity, ScanResult

_LIGHTGBM_HEADER_MARKERS: tuple[str, ...] = (
    "version=",
    "num_class=",
    "num_tree_per_iteration=",
    "max_feature_idx=",
    "feature_names=",
    "tree_sizes=",
)
_LIGHTGBM_TREE_MARKERS: tuple[str, ...] = (
    "tree=",
    "num_leaves=",
    "split_feature=",
    "leaf_value=",
)
_XGBOOST_JSON_MARKERS: tuple[str, ...] = (
    '"learner"',
    '"gradient_booster"',
    '"tree_param"',
)

_SAFE_LINE_PREFIXES: tuple[str, ...] = (
    "tree",
    "tree=",
    "version=",
    "num_class=",
    "num_tree_per_iteration=",
    "max_feature_idx=",
    "feature_names=",
    "feature_infos=",
    "tree_sizes=",
    "num_leaves=",
    "split_feature=",
    "split_gain=",
    "threshold=",
    "decision_type=",
    "left_child=",
    "right_child=",
    "leaf_value=",
    "leaf_weight=",
    "leaf_count=",
    "internal_value=",
    "internal_weight=",
    "internal_count=",
    "shrinkage=",
    "parameters:",
    "[",
)
_TRUSTED_URL_DOMAINS: set[str] = {
    "lightgbm.readthedocs.io",
    "github.com",
    "raw.githubusercontent.com",
    "microsoft.com",
}

_COMMAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bos\.system\s*\(", re.IGNORECASE), "os.system invocation"),
    (
        re.compile(r"\bsubprocess\.(?:popen|run|call|check_call|check_output)\s*\(", re.IGNORECASE),
        "subprocess invocation",
    ),
    (re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE), "dynamic code execution"),
    (re.compile(r"\b__import__\s*\(", re.IGNORECASE), "dynamic import invocation"),
    (
        re.compile(r"\b(?:cmd\.exe\s*/c|powershell(?:\.exe)?|bash\s+-c|sh\s+-c)\b", re.IGNORECASE),
        "shell interpreter invocation",
    ),
]
_EXECUTION_CONTEXT_PATTERN = re.compile(
    r"\b(?:system|exec|eval|subprocess|powershell|cmd(?:\.exe)?|bash|sh|curl|wget|rscript\s+-e|python\s+-c)\b",
    re.IGNORECASE,
)
_URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.IGNORECASE)
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ABSOLUTE_PATH_PATTERN = re.compile(r"(?:\b[A-Za-z]:\\|^/|^~[/\\])")
_TRAVERSAL_PATTERN = re.compile(r"(?:\.\./|\.\.\\)")
_BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{100,}={0,2})")
_HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_DEDICATED_LIGHTGBM_EXTENSIONS = {".lgb", ".lightgbm"}
_EXCERPT_OMITTED_REASON = "model_text_may_contain_sensitive_literals"
_SENSITIVE_HOST_LABEL_PATTERN = re.compile(
    r"(?i)^(?:"
    r"aiza[0-9a-z_-]{35}|"
    r"akia[0-9a-z]{16}|"
    r"gh[opusr]_[a-z0-9]{36}|"
    r"github_pat_[a-z0-9]{22}_[a-z0-9]{59}|"
    r"glpat-[a-z0-9_-]{20}|"
    r"hf_[a-z0-9_-]{20,}|"
    r"npm_[a-z0-9]{36}|"
    r"rg_[a-z0-9]{32}|"
    r"sk-(?:proj-)?[a-z0-9_-]{24,}|"
    r"sq0atp-[a-z0-9_-]{22}|"
    r"sq0csp-[a-z0-9_-]{43}|"
    r"(?:stripe_live|[rs]k_live)_[a-z0-9]{24}|"
    r"xox[baprs]-[0-9a-z-]{20,}|"
    r"az[a-z0-9]{34}|"
    r"[a-f0-9]{32,}"
    r")$"
)
_SENSITIVE_MULTILABEL_HOST_PATTERN = re.compile(
    r"(?i)(?<![a-z0-9_-])(?:"
    r"sg\.[a-z0-9_-]{22}\.[a-z0-9_-]{43}|"
    r"eyj[a-z0-9_-]{8,}\.eyj[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}|"
    r"[0-9]{17,19}\.[a-z0-9_-]{6}\.[a-z0-9_-]{27}"
    r")(?![a-z0-9_-])"
)


def _redact_sensitive_hostname_labels(hostname: str) -> str:
    """Redact credential-shaped hostname labels while preserving endpoint context."""
    hostname = _SENSITIVE_MULTILABEL_HOST_PATTERN.sub(
        "<redacted>",
        hostname,
    )
    return ".".join(
        "<redacted>" if _SENSITIVE_HOST_LABEL_PATTERN.fullmatch(label) else label for label in hostname.split(".")
    )


def _redact_url_for_display(url: str) -> str:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return "[invalid-url]"

    if not parsed.scheme or not parsed.hostname:
        return "[invalid-url]"

    hostname = _redact_sensitive_hostname_labels(parsed.hostname)
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    netloc = f"{hostname}:{port}" if port is not None else hostname
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


class LightGBMScanner(BaseScanner):
    """Security-focused static scanner for native LightGBM models."""

    name: ClassVar[str] = "lightgbm"
    description: ClassVar[str] = "Scans native LightGBM model files for suspicious metadata and payload indicators"
    supported_extensions: ClassVar[list[str]] = [".model", ".txt", ".lgb", ".lightgbm"]

    _SIGNATURE_READ_BYTES: ClassVar[int] = 64 * 1024

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.scan_budget = int(self.config.get("lightgbm_scan_budget", 8 * 1024 * 1024))
        self.max_line_count = int(self.config.get("lightgbm_max_line_count", 50_000))

    @classmethod
    def _normalize_preview(cls, data: bytes) -> str:
        return data.decode("utf-8", errors="ignore").replace("\x00", "\n").lower()

    @classmethod
    def _evaluate_signature(cls, preview: str) -> dict[str, int | bool]:
        stripped_preview = preview.lstrip()
        starts_with_tree = stripped_preview.startswith("tree")
        header_hits = sum(1 for marker in _LIGHTGBM_HEADER_MARKERS if marker in preview)
        tree_hits = sum(1 for marker in _LIGHTGBM_TREE_MARKERS if marker in preview)
        xgboost_like = all(marker in preview for marker in _XGBOOST_JSON_MARKERS)
        looks_like = (
            (starts_with_tree or "tree=" in preview) and header_hits >= 3 and tree_hits >= 2 and not xgboost_like
        )
        return {
            "looks_like": looks_like,
            "starts_with_tree": starts_with_tree,
            "header_hits": header_hits,
            "tree_hits": tree_hits,
            "xgboost_like": xgboost_like,
        }

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        try:
            with open(path, "rb") as file_obj:
                preview = file_obj.read(cls._SIGNATURE_READ_BYTES)
        except OSError:
            return os.path.splitext(path)[1].lower() in _DEDICATED_LIGHTGBM_EXTENSIONS

        signature = cls._evaluate_signature(cls._normalize_preview(preview))
        return bool(signature["looks_like"])

    @staticmethod
    def _is_unreadable_path_result(result: ScanResult) -> bool:
        return any(check.name == "Path Readable" and check.status == CheckStatus.FAILED for check in result.checks)

    @staticmethod
    def _finish_read_failure(result: ScanResult, path: str, error: OSError) -> ScanResult:
        mark_inconclusive_scan_result(result, "lightgbm_read_failed")
        mark_operational_scan_error(result, "lightgbm_read_failed")
        result.add_check(
            name="LightGBM File Read",
            passed=False,
            message=f"Unable to read LightGBM file: {error}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "error": str(error),
                "error_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "lightgbm_read_failed",
            },
        )
        result.finish(success=False)
        return result

    @staticmethod
    def _is_trusted_url(url: str) -> bool:
        try:
            host = urlparse(url).hostname or ""
        except ValueError:
            return False
        host = host.lower()
        if not host:
            return False
        if host in _TRUSTED_URL_DOMAINS:
            return True
        return any(host.endswith(f".{domain}") for domain in _TRUSTED_URL_DOMAINS)

    @staticmethod
    def _is_public_ip(candidate: str) -> bool:
        try:
            value = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return not (value.is_private or value.is_loopback or value.is_link_local or value.is_multicast)

    @staticmethod
    def _is_binary_like(data: bytes) -> bool:
        if not data:
            return False
        sample = data[: min(len(data), 2048)]
        non_printable = sum(1 for byte in sample if byte == 0 or byte < 9 or (13 < byte < 32))
        return (non_printable / len(sample)) > 0.15

    @staticmethod
    def _looks_like_external_reference(line: str) -> bool:
        lowered = line.lower()
        if "://" in lowered or _TRAVERSAL_PATTERN.search(line):
            return True
        return bool(_ABSOLUTE_PATH_PATTERN.search(line))

    def _analyze_lines(self, lines: list[str], result: ScanResult, path: str) -> None:
        critical_command_hits: list[dict[str, str]] = []
        warning_command_hits: list[dict[str, str]] = []
        network_hits: list[dict[str, str]] = []
        path_hits: list[dict[str, str]] = []
        encoded_hits: list[dict[str, str]] = []

        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            lowered = line.lower()
            is_comment = lowered.startswith("#")
            safe_prefix = any(lowered.startswith(prefix) for prefix in _SAFE_LINE_PREFIXES)

            for pattern, reason in _COMMAND_PATTERNS:
                if pattern.search(line):
                    hit = {
                        "line": str(line_number),
                        "reason": reason,
                        "excerpt_omitted": _EXCERPT_OMITTED_REASON,
                    }
                    if is_comment:
                        warning_command_hits.append(hit)
                    else:
                        critical_command_hits.append(hit)
                    break

            for url in _URL_PATTERN.findall(line):
                if not self._is_trusted_url(url):
                    network_hits.append(
                        {"line": str(line_number), "type": "url", "value": _redact_url_for_display(url)}
                    )

            for candidate_ip in _IP_PATTERN.findall(line):
                if self._is_public_ip(candidate_ip):
                    network_hits.append({"line": str(line_number), "type": "public_ip", "value": candidate_ip})

            if not safe_prefix and self._looks_like_external_reference(line):
                path_hits.append({"line": str(line_number), "excerpt_omitted": _EXCERPT_OMITTED_REASON})

            if (_BASE64_PATTERN.search(line) or _HEX_ESCAPE_PATTERN.search(line)) and _EXECUTION_CONTEXT_PATTERN.search(
                line
            ):
                encoded_hits.append({"line": str(line_number), "excerpt_omitted": _EXCERPT_OMITTED_REASON})

        if critical_command_hits:
            result.add_check(
                name="Command Indicator Check",
                passed=False,
                message="Suspicious command execution indicator(s) detected in LightGBM model text",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"hit_count": len(critical_command_hits), "examples": critical_command_hits[:5]},
                why=(
                    "Native LightGBM model files should not contain command execution snippets. "
                    "Treat this as high-risk untrusted content."
                ),
            )
        elif warning_command_hits:
            result.add_check(
                name="Command Indicator Check",
                passed=False,
                message="Command-like indicator(s) detected in comment/documentation context",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"hit_count": len(warning_command_hits), "examples": warning_command_hits[:5]},
            )
        else:
            result.add_check(
                name="Command Indicator Check",
                passed=True,
                message="No suspicious command execution indicators detected",
                location=path,
            )

        if network_hits:
            result.add_check(
                name="Network Indicator Check",
                passed=False,
                message=f"Detected {len(network_hits)} suspicious network indicator(s)",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"examples": network_hits[:10]},
                why=(
                    "Unexpected external endpoints in model text may support staged payload retrieval or exfiltration."
                ),
            )
        else:
            result.add_check(
                name="Network Indicator Check",
                passed=True,
                message="No suspicious network indicators detected",
                location=path,
            )

        if path_hits:
            result.add_check(
                name="External Reference Check",
                passed=False,
                message=f"Detected {len(path_hits)} suspicious path/reference indicator(s)",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"examples": path_hits[:10]},
                why="External path references can indicate unsafe file loading behavior in downstream workflows.",
            )
        else:
            result.add_check(
                name="External Reference Check",
                passed=True,
                message="No suspicious external path/reference indicators detected",
                location=path,
            )

        if encoded_hits:
            result.add_check(
                name="Encoded Payload Context Check",
                passed=False,
                message=f"Detected {len(encoded_hits)} encoded payload hint(s) in executable context",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"examples": encoded_hits[:5]},
                why="Encoded payload fragments with execution context can indicate obfuscated malicious content.",
            )
        else:
            result.add_check(
                name="Encoded Payload Context Check",
                passed=True,
                message="No encoded payload hints detected in executable context",
                location=path,
            )

        if critical_command_hits and network_hits:
            result.add_check(
                name="Command/Network Correlation Check",
                passed=False,
                message="Command and network indicators co-occur in LightGBM model text",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "command_examples": critical_command_hits[:3],
                    "network_examples": network_hits[:3],
                },
                why="Combined command execution and external endpoint indicators raise exploitation confidence.",
            )
        else:
            result.add_check(
                name="Command/Network Correlation Check",
                passed=True,
                message="No high-risk command/network correlation detected",
                location=path,
            )

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            if self._is_unreadable_path_result(path_check_result):
                return self._finish_read_failure(
                    self._create_result(),
                    path,
                    PermissionError(f"Path is not readable: {path}"),
                )
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        self.add_file_integrity_check(path, result)

        try:
            with open(path, "rb") as file_obj:
                payload = file_obj.read(self.scan_budget + 1)
        except OSError as error:
            return self._finish_read_failure(result, path, error)

        truncated = len(payload) > self.scan_budget
        inspected_payload = payload[: self.scan_budget]
        preview = self._normalize_preview(inspected_payload)
        signature = self._evaluate_signature(preview)

        if not bool(signature["looks_like"]):
            result.add_check(
                name="LightGBM Signature Validation",
                passed=False,
                message="File does not match strict LightGBM native model signature heuristics",
                severity=IssueSeverity.INFO,
                location=path,
                details=signature,
                why=("Strict signature checks reduce `.model` extension collisions and prevent scanner misrouting."),
            )
            result.finish(success=False)
            return result

        format_mode = "binary-like" if self._is_binary_like(inspected_payload) else "text"
        result.metadata["format_mode"] = format_mode
        result.add_check(
            name="LightGBM Signature Validation",
            passed=True,
            message="Strict LightGBM native model signature heuristics matched",
            location=path,
            details={**signature, "format_mode": format_mode},
        )

        if truncated:
            mark_inconclusive_scan_result(result, "lightgbm_bounded_read_incomplete")
            result.add_check(
                name="LightGBM Bounded Read",
                passed=False,
                message=f"Model analysis truncated at scan budget ({self.scan_budget} bytes)",
                severity=IssueSeverity.INFO,
                location=path,
                details={"scan_budget": self.scan_budget, "inspected_bytes": self.scan_budget},
            )
        else:
            result.add_check(
                name="LightGBM Bounded Read",
                passed=True,
                message="Model read completed within configured scan budget",
                location=path,
                details={"scan_budget": self.scan_budget, "inspected_bytes": len(inspected_payload)},
            )

        lines = [line for line in preview.splitlines() if line.strip()]
        if len(lines) > self.max_line_count:
            lines = lines[: self.max_line_count]
            mark_inconclusive_scan_result(result, "lightgbm_line_budget_incomplete")
            result.add_check(
                name="LightGBM Line Budget",
                passed=False,
                message=f"Line analysis truncated at configured limit ({self.max_line_count} lines)",
                severity=IssueSeverity.INFO,
                location=path,
                details={"max_line_count": self.max_line_count},
            )
        else:
            result.add_check(
                name="LightGBM Line Budget",
                passed=True,
                message="Line analysis completed within configured limit",
                location=path,
                details={"line_count": len(lines), "max_line_count": self.max_line_count},
            )

        result.bytes_scanned = len(inspected_payload)
        result.metadata["line_count"] = len(lines)
        self._analyze_lines(lines, result, path)

        result.finish(
            success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors,
        )
        return result
