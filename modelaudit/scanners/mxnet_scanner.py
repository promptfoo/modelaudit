"""Scanner for MXNet symbol/params model artifacts."""

from __future__ import annotations

import base64
import json
import re
from io import BytesIO
from pathlib import Path
from typing import Any, ClassVar

from modelaudit.detectors.suspicious_symbols import EXECUTABLE_SIGNATURES
from modelaudit.scanner_selection import add_scanner_selection_skip_check, policy_from_config
from modelaudit.utils.file.detection import (
    MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT,
    MXNET_SYMBOL_SIGNATURE_READ_BYTES,
    detect_mxnet_symbol_content_route,
    has_mxnet_symbol_graph_structure,
    inspect_mxnet_symbol_root_keys,
)

from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult

MAX_SYMBOL_READ_BYTES = MXNET_SYMBOL_SIGNATURE_READ_BYTES
MAX_PARAMS_READ_BYTES = 10 * 1024 * 1024
MIN_PARAMS_SIZE_BYTES = 16
MAX_PREVIEW_SIGNATURE_OFFSET = 4096

PARAMS_NAME_RE = re.compile(r"^(?P<prefix>.+)-(?P<epoch>\d{1,8})\.params$", re.IGNORECASE)
ABSOLUTE_PATH_RE = re.compile(r"^(?:[a-zA-Z]:[\\/]|/|~)")
PATH_TRAVERSAL_RE = re.compile(r"(^|[\\/])\.\.([\\/]|$)")
NETWORK_REFERENCE_RE = re.compile(r"(?i)^(?:https?|ftp|s3|gs|file)://")
COMMAND_INJECTION_RE = re.compile(r"[;&|`]")
PRINTABLE_TEXT_RE = re.compile(rb"[ -~]{24,}")
BASE64_BLOB_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
SUSPICIOUS_DECODED_PAYLOAD_RE = re.compile(
    r"(?i)(?:os\.system|subprocess\.(?:popen|run|call|check_output)|eval\(|exec\(|__import__|ctypes\.(?:cdll|windll)|dlopen\(|loadlibrary)"
)
MXNET_CVE_2022_24294_ID = "CVE-2022-24294"
MXNET_CVE_2022_24294_MIN_LENGTH = 1024
MXNET_CVE_2022_24294_MIN_META_CHARS = 128
MXNET_CVE_2022_24294_META_CHARS = frozenset("<>()[]{}*+?|\\")

# Keep this list conservative to avoid flagging normal graph attributes.
LOAD_AFFECTING_ATTR_KEYS = frozenset(
    {
        "library",
        "lib",
        "lib_path",
        "dll",
        "plugin",
        "module",
        "op_type",
        "path",
        "filename",
        "uri",
        "url",
        "symbol_file",
        "params_file",
        "config_path",
        "source",
    }
)

METADATA_ATTR_KEYS = frozenset(
    {
        "metadata",
        "description",
        "doc",
        "notes",
        "payload",
        "extra",
        "annotation",
    }
)

SAFE_MXNET_OPERATORS = frozenset(
    {
        "null",
        "convolution",
        "deconvolution",
        "batchnorm",
        "activation",
        "pooling",
        "fullyconnected",
        "flatten",
        "reshape",
        "softmaxoutput",
        "softmaxactivation",
        "dropout",
        "concat",
        "slicechannel",
        "slice_axis",
        "elemwise_add",
        "broadcast_add",
        "broadcast_mul",
        "broadcast_sub",
        "broadcast_div",
        "_plus_scalar",
        "_minus_scalar",
        "_mul_scalar",
        "_div_scalar",
        "relu",
        "leakyrelu",
        "sigmoid",
        "tanh",
        "embedding",
        "clip",
        "cast",
        "transpose",
        "upsampling",
        "pad",
        "mean",
        "sum",
        "max",
        "min",
        "expand_dims",
        "squeeze",
    }
)

SUSPICIOUS_TEXT_TOKENS = (
    "os.system",
    "subprocess.popen",
    "subprocess.call",
    "subprocess.run",
    "import os",
    "import subprocess",
    "__import__",
    "eval(",
    "exec(",
    "ctypes.cdll",
    "ctypes.windll",
    "dlopen(",
    "loadlibrary",
)


def _scan_result_has_security_findings(result: ScanResult) -> bool:
    """Return True when the result includes WARNING/CRITICAL findings."""
    return any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


class MXNetScanner(BaseScanner):
    """Scanner for MXNet symbol graph and params artifacts."""

    name = "mxnet"
    description = "Scans MXNet symbol/params artifacts for suspicious references and embedded payloads"
    supported_extensions: ClassVar[list[str]] = [".json", ".params"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        path_obj = Path(path)
        if not path_obj.is_file():
            return False

        suffix = path_obj.suffix.lower()
        if suffix == ".params":
            return cls._is_mxnet_params_filename(path_obj.name)

        # Content-routed renamed symbols are selected by trusted format detection.
        return suffix == ".json" and path_obj.name.lower().endswith("-symbol.json")

    @classmethod
    def _is_mxnet_params_filename(cls, filename: str) -> bool:
        return bool(PARAMS_NAME_RE.match(filename))

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path
        self.add_file_integrity_check(path, result)

        suffix = Path(path).suffix.lower()
        analysis_complete = True

        if suffix == ".params":
            symbol_route = detect_mxnet_symbol_content_route(path)
            if symbol_route in {"mxnet", MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT}:
                analysis_complete = self._scan_symbol_graph(path, result)
            else:
                analysis_complete = self._scan_params_blob(path, result)
        else:
            analysis_complete = self._scan_symbol_graph(path, result)

        self._finish_mxnet_result(result, analysis_complete=analysis_complete)
        return result

    def _mark_inconclusive_scan_result(self, result: ScanResult, reason: str) -> None:
        """Mark MXNet analysis as incomplete for aggregate exit-code handling."""
        existing_reasons = result.metadata.get("scan_outcome_reasons")
        reasons = existing_reasons if isinstance(existing_reasons, list) else []
        if reason not in reasons:
            reasons.append(reason)

        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata["scan_outcome_reasons"] = reasons
        result.metadata["analysis_incomplete"] = True

    def _finish_mxnet_result(self, result: ScanResult, *, analysis_complete: bool) -> None:
        """Fail closed for incomplete MXNet scans unless security findings were recovered."""
        has_security_findings = _scan_result_has_security_findings(result)
        if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME and not has_security_findings:
            result.finish(success=False)
            return

        result.finish(success=(not result.has_errors) and (analysis_complete or has_security_findings))

    def _scan_symbol_graph(self, path: str, result: ScanResult) -> bool:
        path_obj = Path(path)
        try:
            raw_bytes, truncated = self._read_bounded_bytes(path_obj, MAX_SYMBOL_READ_BYTES)
        except OSError as exc:
            result.add_check(
                name="MXNet Symbol Read",
                passed=False,
                message=f"Failed to read MXNet symbol graph: {exc!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "mxnet_symbol_read_failed",
                },
            )
            self._mark_inconclusive_scan_result(result, "mxnet_symbol_read_failed")
            return False

        result.bytes_scanned += len(raw_bytes)
        if truncated:
            result.add_check(
                name="MXNet Symbol Size Guard",
                passed=False,
                message=f"Symbol graph exceeded bounded read size ({MAX_SYMBOL_READ_BYTES} bytes); scanned prefix only",
                severity=IssueSeverity.INFO,
                location=path,
                details={"max_bytes": MAX_SYMBOL_READ_BYTES},
            )
            self._mark_inconclusive_scan_result(result, "mxnet_symbol_truncated")

        if not raw_bytes:
            result.add_check(
                name="MXNet Symbol Parse",
                passed=False,
                message="MXNet symbol graph is empty",
                severity=IssueSeverity.INFO,
                location=path,
            )
            self._mark_inconclusive_scan_result(result, "mxnet_symbol_empty")
            self._scan_filename_owned_json_overlap(path, result)
            return False

        duplicate_root_keys = inspect_mxnet_symbol_root_keys(BytesIO(raw_bytes))
        self._record_symbol_root_key_ambiguity(path, result, duplicate_root_keys)

        try:
            payload = json.loads(raw_bytes.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError, TypeError) as exc:
            result.add_check(
                name="MXNet Symbol Parse",
                passed=False,
                message=f"Invalid MXNet symbol JSON: {exc!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"exception": str(exc), "exception_type": type(exc).__name__},
            )
            self._mark_inconclusive_scan_result(result, "mxnet_symbol_parse_failed")
            self._scan_filename_owned_json_overlap(path, result)
            return False

        if not has_mxnet_symbol_graph_structure(payload):
            result.add_check(
                name="MXNet Symbol Structure",
                passed=False,
                message="Symbol file does not match expected MXNet graph contract",
                severity=IssueSeverity.INFO,
                location=path,
            )
            self._mark_inconclusive_scan_result(result, "mxnet_symbol_invalid_structure")
            self._scan_filename_owned_json_overlap(path, result)
            return False

        nodes = payload.get("nodes", [])
        result.metadata["node_count"] = len(nodes) if isinstance(nodes, list) else 0

        params_candidates = self._find_params_companions(path_obj)
        result.metadata["has_params_companion"] = bool(params_candidates)
        if params_candidates:
            result.metadata["params_companion"] = str(params_candidates[0])
            result.metadata["params_companion_count"] = len(params_candidates)
        else:
            result.add_check(
                name="MXNet Companion Artifact Check",
                passed=False,
                message="No matching MXNet params companion file found",
                severity=IssueSeverity.INFO,
                location=path,
                details={"expected_pattern": f"{path_obj.stem[:-7]}-<epoch>.params"},
            )

        self._scan_graph_references(path, payload, result)
        self._scan_operator_names_for_cve_2022_24294(path, payload, result)
        self._scan_graph_metadata_payloads(path, payload, result)
        self._scan_xgboost_overlap(path, payload, result)
        self._scan_filename_owned_json_overlap(path, result)
        return True

    def _record_symbol_root_key_ambiguity(
        self,
        path: str,
        result: ScanResult,
        duplicate_keys: set[str],
    ) -> None:
        """Fail closed when JSON decoding could hide MXNet graph root content."""
        if duplicate_keys:
            reason = "mxnet_symbol_duplicate_root_keys"
            result.add_check(
                name="MXNet Symbol JSON Analysis",
                passed=False,
                message="Symbol graph contains duplicate root graph keys; shadowed content cannot be safely analyzed",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                    "duplicate_root_keys": sorted(duplicate_keys),
                },
            )
            self._mark_inconclusive_scan_result(result, reason)

    def scan_parsed_symbol_security(self, path: str, payload: dict[str, Any], result: ScanResult) -> None:
        """Apply MXNet symbol-specific security checks to an already parsed overlap."""
        self._scan_graph_references(path, payload, result)
        self._scan_operator_names_for_cve_2022_24294(path, payload, result)
        self._scan_graph_metadata_payloads(path, payload, result)

    def _merge_filename_owned_result(self, result: ScanResult, owner_result: ScanResult) -> None:
        """Merge an owner scan without dropping existing incomplete-coverage reasons."""
        existing_reasons = list(result.metadata.get("scan_outcome_reasons", []))
        result.merge(owner_result)
        for reason in existing_reasons:
            self._mark_inconclusive_scan_result(result, reason)

    def _scan_filename_owned_json_overlap(self, path: str, result: ScanResult) -> None:
        """Preserve filename-owned JSON checks for symbol-shaped content."""
        from .jinja2_template_scanner import Jinja2TemplateScanner
        from .manifest_scanner import ManifestScanner

        scanner_selection = policy_from_config(self.config)
        manifest_covered_templates = False
        if ManifestScanner.can_handle(path):
            if scanner_selection.allows("manifest"):
                manifest_result = ManifestScanner(config=self.config).scan(path)
                self._merge_filename_owned_result(result, manifest_result)
                manifest_covered_templates = manifest_result.metadata.get("analysis_incomplete") is not True
            elif scanner_selection.active:
                add_scanner_selection_skip_check(
                    result,
                    path,
                    "manifest",
                    scanner_selection,
                    context="overlapping manifest JSON analysis",
                )
        if not manifest_covered_templates and Jinja2TemplateScanner.can_handle(path):
            if scanner_selection.allows("jinja2_template"):
                self._merge_filename_owned_result(result, Jinja2TemplateScanner(config=self.config).scan(path))
            elif scanner_selection.active:
                add_scanner_selection_skip_check(
                    result,
                    path,
                    "jinja2_template",
                    scanner_selection,
                    context="overlapping Jinja JSON analysis",
                )

    def _scan_xgboost_overlap(self, path: str, payload: dict[str, Any], result: ScanResult) -> None:
        """Run XGBoost checks when a filename-owned symbol is also XGBoost JSON."""
        from .xgboost_scanner import XGBoostScanner

        version = payload.get("version")
        learner = payload.get("learner")
        if not isinstance(version, list | tuple) or len(version) < 2 or not isinstance(learner, dict):
            return

        scanner_selection = policy_from_config(self.config)
        if scanner_selection.allows("xgboost"):
            XGBoostScanner(config=self.config).scan_parsed_json_security(path, payload, result)
        else:
            add_scanner_selection_skip_check(
                result,
                path,
                "xgboost",
                scanner_selection,
                context="overlapping JSON analysis",
            )

    def _scan_params_blob(self, path: str, result: ScanResult) -> bool:
        path_obj = Path(path)
        match = PARAMS_NAME_RE.match(path_obj.name)

        symbol_path: Path | None = None
        if match:
            symbol_path = path_obj.with_name(f"{match.group('prefix')}-symbol.json")
        else:
            result.add_check(
                name="MXNet Params Naming Check",
                passed=False,
                message="MXNet params filename does not match '<prefix>-<epoch>.params' pattern",
                severity=IssueSeverity.INFO,
                location=path,
            )

        has_symbol_companion = bool(symbol_path and symbol_path.is_file())
        result.metadata["has_symbol_companion"] = has_symbol_companion
        if symbol_path:
            result.metadata["symbol_companion"] = str(symbol_path)

        if symbol_path and not has_symbol_companion:
            result.add_check(
                name="MXNet Companion Artifact Check",
                passed=False,
                message="No matching MXNet symbol companion file found",
                severity=IssueSeverity.INFO,
                location=path,
                details={"expected_file": str(symbol_path)},
            )

        try:
            raw_bytes, truncated = self._read_bounded_bytes(path_obj, MAX_PARAMS_READ_BYTES)
        except OSError as exc:
            result.add_check(
                name="MXNet Params Read",
                passed=False,
                message=f"Failed to read MXNet params blob: {exc!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "mxnet_params_read_failed",
                },
            )
            self._mark_inconclusive_scan_result(result, "mxnet_params_read_failed")
            return False

        result.bytes_scanned += len(raw_bytes)

        if truncated:
            result.add_check(
                name="MXNet Params Size Guard",
                passed=False,
                message=f"Params blob exceeded bounded read size ({MAX_PARAMS_READ_BYTES} bytes); scanned prefix only",
                severity=IssueSeverity.INFO,
                location=path,
                details={"max_bytes": MAX_PARAMS_READ_BYTES},
            )
            self._mark_inconclusive_scan_result(result, "mxnet_params_truncated")

        if not raw_bytes:
            result.add_check(
                name="MXNet Params Corruption Check",
                passed=False,
                message="MXNet params blob is empty",
                severity=IssueSeverity.INFO,
                location=path,
            )
            self._mark_inconclusive_scan_result(result, "mxnet_params_empty")
            return False

        if len(raw_bytes) < MIN_PARAMS_SIZE_BYTES:
            result.add_check(
                name="MXNet Params Corruption Check",
                passed=False,
                message="MXNet params blob appears truncated (unexpectedly small payload)",
                severity=IssueSeverity.INFO,
                location=path,
                details={"size_bytes": len(raw_bytes), "minimum_expected_bytes": MIN_PARAMS_SIZE_BYTES},
            )
            self._mark_inconclusive_scan_result(result, "mxnet_params_truncated")

        self._scan_params_signatures(path, raw_bytes, result)
        self._scan_params_text_payloads(path, raw_bytes, result)
        return True

    def _scan_graph_references(self, path: str, payload: dict[str, Any], result: ScanResult) -> None:
        nodes = payload.get("nodes")
        if not isinstance(nodes, list):
            return

        for index, raw_node in enumerate(nodes):
            if not isinstance(raw_node, dict):
                continue
            node_name = str(raw_node.get("name", f"node_{index}"))
            op_name = str(raw_node.get("op", "")).strip()
            attrs = raw_node.get("attrs")
            if not isinstance(attrs, dict):
                continue

            for raw_key, raw_value in attrs.items():
                if not isinstance(raw_key, str):
                    continue
                key = raw_key.lower()
                if key not in LOAD_AFFECTING_ATTR_KEYS:
                    continue

                value = self._normalize_reference_value(raw_value)
                if not value:
                    continue

                reference_type = self._classify_reference(key, value)
                if reference_type is None:
                    continue

                severity = IssueSeverity.CRITICAL if reference_type == "command" else IssueSeverity.WARNING
                is_custom_operator = op_name.lower() not in SAFE_MXNET_OPERATORS
                check_name = (
                    "MXNet Custom Operator Reference Check" if is_custom_operator else "MXNet External Reference Check"
                )

                result.add_check(
                    name=check_name,
                    passed=False,
                    message=f"Suspicious {reference_type} reference in MXNet graph attributes",
                    severity=severity,
                    location=f"{path} (node: {node_name}, attr: {raw_key})",
                    details={
                        "node_name": node_name,
                        "op_name": op_name,
                        "attribute": raw_key,
                        "reference": value,
                        "reference_type": reference_type,
                    },
                )

    def _scan_operator_names_for_cve_2022_24294(
        self,
        path: str,
        payload: dict[str, Any],
        result: ScanResult,
    ) -> None:
        """Detect pathological MXNet operator names associated with CVE-2022-24294."""
        nodes = payload.get("nodes")
        if not isinstance(nodes, list):
            return

        findings: list[dict[str, Any]] = []
        for index, raw_node in enumerate(nodes):
            if not isinstance(raw_node, dict):
                continue

            op_name = str(raw_node.get("op", "")).strip()
            if not self._is_cve_2022_24294_operator_name(op_name):
                continue

            findings.append(
                {
                    "node_name": str(raw_node.get("name", f"node_{index}")),
                    "op_name_preview": op_name[:160],
                    "op_name_length": len(op_name),
                    "metacharacter_count": sum(1 for char in op_name if char in MXNET_CVE_2022_24294_META_CHARS),
                }
            )

        if not findings:
            return

        result.add_check(
            name="CVE-2022-24294: MXNet Operator Name ReDoS",
            passed=False,
            message=(
                "Detected MXNet operator name shape associated with CVE-2022-24294 "
                f"({len(findings)} node{'s' if len(findings) != 1 else ''} affected)"
            ),
            severity=IssueSeverity.WARNING,
            location=path,
            details={
                "cve_id": MXNET_CVE_2022_24294_ID,
                "cvss": 7.5,
                "cwe": "CWE-400",
                "description": (
                    "Apache MXNet versions before 1.9.1 used a vulnerable regular expression when loading "
                    "models with specially crafted operator names, causing excessive resource consumption."
                ),
                "remediation": (
                    "Upgrade MXNet to >= 1.9.1 and reject model graphs containing pathological operator names."
                ),
                "findings": findings[:10],
                "finding_count": len(findings),
            },
            why=(
                "The operator name is not merely long; it combines extreme length with a dense, regex-active "
                "delimiter pattern that matches the CVE-2022-24294 denial-of-service risk class."
            ),
        )

    @staticmethod
    def _is_cve_2022_24294_operator_name(op_name: str) -> bool:
        """Return True for pathological operator names, avoiding long benign names."""
        if len(op_name) < MXNET_CVE_2022_24294_MIN_LENGTH:
            return False

        metacharacter_count = sum(1 for char in op_name if char in MXNET_CVE_2022_24294_META_CHARS)
        if metacharacter_count < MXNET_CVE_2022_24294_MIN_META_CHARS:
            return False

        # Require repeated regex-active bracket/quantifier runs so long namespace-like
        # custom operator names do not become noisy findings.
        repeated_angle_runs = len(re.findall(r"(?:<[^<>]{0,64}){16,}", op_name))
        repeated_group_runs = len(re.findall(r"(?:\([^()]{0,64}){16,}", op_name))
        repeated_quantifier_runs = len(re.findall(r"[+*?]{16,}", op_name))
        return (repeated_angle_runs + repeated_group_runs + repeated_quantifier_runs) > 0

    def _scan_graph_metadata_payloads(self, path: str, payload: dict[str, Any], result: ScanResult) -> None:
        seen_payloads: set[str] = set()
        for context, text_value in self._collect_metadata_text(payload):
            normalized = text_value.strip()
            if not normalized:
                continue

            if SUSPICIOUS_DECODED_PAYLOAD_RE.search(normalized):
                if normalized in seen_payloads:
                    continue
                seen_payloads.add(normalized)
                result.add_check(
                    name="MXNet Metadata Payload Check",
                    passed=False,
                    message="Suspicious executable pattern found in MXNet metadata field",
                    severity=IssueSeverity.WARNING,
                    location=f"{path} ({context})",
                    details={"context": context},
                )
                continue

            if not self._looks_base64_blob(normalized):
                continue

            decoded = self._decode_base64_blob(normalized)
            if not decoded:
                continue

            if not SUSPICIOUS_DECODED_PAYLOAD_RE.search(decoded):
                continue

            if decoded in seen_payloads:
                continue
            seen_payloads.add(decoded)

            result.add_check(
                name="MXNet Encoded Metadata Payload Check",
                passed=False,
                message="Base64-encoded metadata decodes to suspicious executable content",
                severity=IssueSeverity.WARNING,
                location=f"{path} ({context})",
                details={"context": context, "decoded_preview": decoded[:200]},
            )

    def _scan_params_signatures(self, path: str, raw_bytes: bytes, result: ScanResult) -> None:
        reported: set[tuple[str, int]] = set()
        for signature, description in EXECUTABLE_SIGNATURES.items():
            position = raw_bytes.find(signature)
            if position == -1 or position > MAX_PREVIEW_SIGNATURE_OFFSET:
                continue

            marker = (description, position)
            if marker in reported:
                continue
            reported.add(marker)

            result.add_check(
                name="MXNet Params Embedded Signature Check",
                passed=False,
                message=f"Potential executable signature found in params blob: {description}",
                severity=IssueSeverity.WARNING,
                location=f"{path} (offset: {position})",
                details={
                    "signature_description": description,
                    "signature_hex": signature.hex(),
                    "offset": position,
                },
            )

    def _scan_params_text_payloads(self, path: str, raw_bytes: bytes, result: ScanResult) -> None:
        seen_tokens: set[str] = set()

        for match in PRINTABLE_TEXT_RE.finditer(raw_bytes):
            text = match.group().decode("ascii", errors="ignore")
            text_lower = text.lower()
            for token in SUSPICIOUS_TEXT_TOKENS:
                if token in seen_tokens:
                    continue
                if token not in text_lower:
                    continue

                seen_tokens.add(token)
                relative_offset = text_lower.index(token)
                absolute_offset = match.start() + relative_offset

                result.add_check(
                    name="MXNet Params Suspicious Text Check",
                    passed=False,
                    message="Suspicious executable token found in printable params content",
                    severity=IssueSeverity.WARNING,
                    location=f"{path} (offset: {absolute_offset})",
                    details={
                        "token": token,
                        "offset": absolute_offset,
                        "preview": text[:200],
                    },
                )

    @staticmethod
    def _read_bounded_bytes(path: Path, max_bytes: int) -> tuple[bytes, bool]:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            return data[:max_bytes], True
        return data, False

    @staticmethod
    def _normalize_reference_value(value: Any) -> str:
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, list | tuple) and value and isinstance(value[0], str):
            return value[0].strip()
        if isinstance(value, dict):
            for candidate_key in ("value", "path", "uri", "url"):
                candidate = value.get(candidate_key)
                if isinstance(candidate, str):
                    return candidate.strip()
        return ""

    @staticmethod
    def _classify_reference(attribute_key: str, reference: str) -> str | None:
        normalized = reference.strip()
        lowered = normalized.lower()

        if not normalized:
            return None

        if NETWORK_REFERENCE_RE.match(normalized):
            return "network"

        if COMMAND_INJECTION_RE.search(normalized) and any(
            indicator in lowered for indicator in ("bash", "powershell", "cmd", "python", "curl", "wget")
        ):
            return "command"

        is_library_key = attribute_key in {"library", "lib", "lib_path", "dll", "plugin"}
        has_library_suffix = lowered.endswith((".so", ".dll", ".dylib"))
        if is_library_key and (has_library_suffix or "/" in normalized or "\\" in normalized):
            return "library"

        if (
            PATH_TRAVERSAL_RE.search(normalized)
            or ABSOLUTE_PATH_RE.match(normalized)
            or normalized.startswith("$")
            or normalized.startswith("${")
        ):
            return "path"

        return None

    def _find_params_companions(self, symbol_path: Path) -> list[Path]:
        name_lower = symbol_path.name.lower()
        if not name_lower.endswith("-symbol.json"):
            return []

        prefix = symbol_path.name[: -len("-symbol.json")]
        candidates: list[tuple[int, Path]] = []
        for candidate in symbol_path.parent.glob(f"{prefix}-*.params"):
            match = PARAMS_NAME_RE.match(candidate.name)
            if not match:
                continue
            if match.group("prefix") != prefix:
                continue
            epoch = int(match.group("epoch"))
            candidates.append((epoch, candidate))

        candidates.sort(key=lambda item: item[0], reverse=True)
        return [path for _epoch, path in candidates]

    def _collect_metadata_text(self, payload: dict[str, Any]) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []

        graph_attrs = payload.get("attrs")
        if isinstance(graph_attrs, dict):
            for raw_key, raw_value in graph_attrs.items():
                if isinstance(raw_key, str) and raw_key.lower() in METADATA_ATTR_KEYS:
                    results.extend(self._flatten_text_values(raw_value, f"graph.attrs.{raw_key}"))

        nodes = payload.get("nodes")
        if isinstance(nodes, list):
            for index, raw_node in enumerate(nodes):
                if not isinstance(raw_node, dict):
                    continue
                node_name = str(raw_node.get("name", f"node_{index}"))
                attrs = raw_node.get("attrs")
                if not isinstance(attrs, dict):
                    continue
                for raw_key, raw_value in attrs.items():
                    if isinstance(raw_key, str) and raw_key.lower() in METADATA_ATTR_KEYS:
                        results.extend(self._flatten_text_values(raw_value, f"node:{node_name}.attrs.{raw_key}"))

        return results

    def _flatten_text_values(self, value: Any, context: str) -> list[tuple[str, str]]:
        if isinstance(value, str):
            return [(context, value)]

        if isinstance(value, list | tuple):
            flattened: list[tuple[str, str]] = []
            for index, item in enumerate(value):
                flattened.extend(self._flatten_text_values(item, f"{context}[{index}]"))
            return flattened

        if isinstance(value, dict):
            flattened_dict: list[tuple[str, str]] = []
            for key, item in value.items():
                flattened_dict.extend(self._flatten_text_values(item, f"{context}.{key}"))
            return flattened_dict

        return []

    @staticmethod
    def _looks_base64_blob(text: str) -> bool:
        normalized = re.sub(r"\s+", "", text)
        if len(normalized) < 24 or len(normalized) > 8192:
            return False
        if len(normalized) % 4 != 0:
            return False
        return bool(BASE64_BLOB_RE.fullmatch(normalized))

    @staticmethod
    def _decode_base64_blob(text: str) -> str | None:
        normalized = re.sub(r"\s+", "", text)
        try:
            decoded = base64.b64decode(normalized, validate=True)
        except (ValueError, TypeError):
            return None
        return decoded.decode("utf-8", errors="ignore")
