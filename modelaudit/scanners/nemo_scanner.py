"""Scanner for NVIDIA NeMo model files (.nemo).

NeMo files are tar archives containing YAML configuration and model weights.
CVE-2025-23304: Hydra _target_ fields in NeMo configs can specify arbitrary
Python callables, enabling RCE when loaded via hydra.utils.instantiate().
"""

import logging
import os
import posixpath
import re
import tarfile
import tempfile
from typing import Any, ClassVar

from ..utils import is_absolute_archive_path, sanitize_archive_path
from ..utils.file.detection import is_nemo_archive
from ._archive_locations import rewrite_extracted_member_location
from ._archive_outcomes import mark_archive_scan_incomplete
from .archive_member_security import (
    is_executable_archive_member_name,
    is_python_archive_member_name,
    scan_archive_member_for_known_risks,
)
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult
from .tar_scanner import (
    TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY,
    TarScanner,
)

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    yaml = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Safe _target_ prefixes that are expected in legitimate NeMo configs
_SAFE_TARGET_PREFIXES = (
    "nemo.",
    "nemo_toolkit.",
    "pytorch_lightning.",
    "lightning.",
    "torch.optim.",
    "torch.nn.",
    "torch.utils.",
    "transformers.",
    "omegaconf.",
    "hydra.",
    "megatron.",
    "apex.",
    "numpy.",
    "dataclasses.",
)

# Dangerous _target_ values that indicate exploitation
_DANGEROUS_TARGETS = {
    "os.system",
    "os.popen",
    "os.exec",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawn",
    "os.spawnl",
    "os.spawnle",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "builtins.eval",
    "builtins.exec",
    "builtins.__import__",
    "importlib.import_module",
    "pickle.loads",
    "pickle.load",
    "cloudpickle.loads",
    "cloudpickle.load",
    "dill.loads",
    "dill.load",
    "joblib.load",
    "sklearn.externals.joblib.load",
    "keras.models.load_model",
    "mlflow.pyfunc.load_model",
    "pandas.read_pickle",
    "tensorflow.keras.models.load_model",
    "tensorflow.saved_model.load",
    "tf.keras.models.load_model",
    "torch.hub.load",
    "torch.hub.load_state_dict_from_url",
    "torch.jit.load",
    "torch.load",
    "torch.package.PackageImporter",
    "torch.package.PackageImporter.load_pickle",
    "torch.serialization.load",
    "torch.utils.model_zoo.load_url",
    "shutil.rmtree",
    "pathlib.Path.unlink",
    "webbrowser.open",
    "ctypes.CDLL",
    "code.interact",
    "pty.spawn",
}

# Patterns in _target_ that are suspicious even if not exact matches
_SUSPICIOUS_TARGET_PATTERNS = (
    "eval",
    "exec",
    "system",
    "popen",
    "subprocess",
    "__import__",
    "pickle",
    "marshal",
    "compile",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
)
_TARGET_TOKEN_RE = re.compile(r"__import__|[A-Z]+(?=[A-Z][a-z0-9]|[0-9_]|$)|[A-Z]?[a-z0-9]+")

CVE_2025_23304_ID = "CVE-2025-23304"
CVE_2025_23304_CVSS = 7.6
CVE_2025_23304_CWE = "CWE-94"
CVE_2025_23304_DESCRIPTION = (
    "NeMo Hydra _target_ specifies a suspicious or dangerous callable that may enable RCE when instantiated"
)
CVE_2025_23304_REMEDIATION = (
    "Update to NeMo >= 2.3.2 which validates _target_ values. Do not load untrusted .nemo files."
)
NEMO_CHECKPOINT_MEMBER_EXTENSIONS = frozenset({".ckpt", ".pt", ".pth", ".pkl", ".pickle"})
NEMO_MAX_CHECKPOINT_SCAN_BYTES = 50 * 1024 * 1024
NEMO_MAX_PYTHON_ANALYSIS_BYTES = 10 * 1024 * 1024
NEMO_EXECUTABLE_INITIAL_PROBE_BYTES = 1024
NEMO_EXECUTABLE_PE_PROBE_BYTES = (1024 * 1024) + 4

_INCONCLUSIVE_METADATA_KEY = "scan_outcome"
_INCONCLUSIVE_REASONS_METADATA_KEY = "scan_outcome_reasons"


def _find_suspicious_target_pattern(target: str) -> str | None:
    """Return a suspicious identifier token if a target contains one."""
    for component in target.split("."):
        for token in _TARGET_TOKEN_RE.findall(component):
            token_lower = token.lower()
            if token_lower in _SUSPICIOUS_TARGET_PATTERNS:
                return token_lower
            for pattern in _SUSPICIOUS_TARGET_PATTERNS:
                if token_lower.startswith(pattern) and token_lower[len(pattern) :].isdigit():
                    return pattern
    return None


def _find_suspicious_safe_prefixed_target_pattern(target: str) -> str | None:
    """Return a suspicious safe-prefixed callable leaf, if present."""
    leaf = target.rsplit(".", maxsplit=1)[-1].lower()
    if leaf in _SUSPICIOUS_TARGET_PATTERNS:
        return leaf
    for pattern in _SUSPICIOUS_TARGET_PATTERNS:
        if leaf.startswith(pattern) and leaf[len(pattern) :].isdigit():
            return pattern
    return None


def _is_runtime_truthy(value: Any) -> bool:
    """Return whether a Hydra argument would be truthy when passed to Python."""
    return bool(value)


def _scan_result_has_security_findings(result: ScanResult) -> bool:
    return any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def _get_nested_scanner_for_file(path: str, *, config: dict[str, Any]) -> BaseScanner | None:
    """Resolve nested scanners lazily to avoid scanner registry import cycles."""
    from modelaudit.scanners import get_scanner_for_file

    return get_scanner_for_file(path, config=config)


class NemoScanner(BaseScanner):
    """Scanner for NVIDIA NeMo model files.

    Detects CVE-2025-23304: Hydra _target_ injection via malicious
    NeMo config metadata that enables remote code execution.
    """

    name = "nemo"
    description = "Scans NeMo files for Hydra _target_ injection (CVE-2025-23304)"
    supported_extensions: ClassVar[list[str]] = [".nemo"]

    # Maximum size for individual YAML configs to prevent YAML bombs
    MAX_CONFIG_SIZE: ClassVar[int] = 10 * 1024 * 1024  # 10MB

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            # Preserve legacy coverage for `.nemo` archives whose config is malformed or missing.
            return tarfile.is_tarfile(path)
        return is_nemo_archive(path)

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        is_declared_nemo = os.path.splitext(path)[1].lower() in self.supported_extensions

        tar_scanner = TarScanner(config=dict(self.config))
        try:
            archive_depth = max(int(self.config.get("_archive_depth", 0)), 0)
        except (TypeError, ValueError):
            archive_depth = 0
        if archive_depth >= tar_scanner.max_depth:
            result.merge(tar_scanner.scan(path))
            result.bytes_scanned = file_size
            self._finish_scan_result(result)
            return result

        preflight_result = ScanResult(scanner_name="tar")
        if not tar_scanner._preflight_tar_archive(path, preflight_result):
            mark_archive_scan_incomplete(preflight_result, "tar_analysis_incomplete")
            preflight_result.finish(success=False)
            result.merge(preflight_result)
            result.bytes_scanned = file_size
            self._finish_scan_result(result)
            return result

        if is_declared_nemo:
            preflight_result.finish(success=True)
            result.merge(preflight_result)

        nemo_owned_entries: set[str] = set()
        if not HAS_YAML:
            result.add_check(
                name="YAML Parser Availability",
                passed=False,
                message="PyYAML not available; cannot analyze NeMo config for Hydra _target_ injection",
                severity=IssueSeverity.WARNING,
                location=path,
            )
        else:
            try:
                self._scan_nemo_archive(
                    path,
                    result,
                    nemo_owned_entries,
                    inspect_embedded_members=is_declared_nemo,
                )
            except tarfile.TarError as e:
                result.add_check(
                    name="NeMo Archive Integrity",
                    passed=False,
                    message=f"Failed to open NeMo archive: {e}",
                    severity=IssueSeverity.WARNING,
                    location=path,
                )
                result.success = False

        if not is_declared_nemo:
            tar_config = dict(self.config)
            tar_config[TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY] = nemo_owned_entries
            # The enclosing NeMo result controls whether this artifact is
            # complete enough to cache; nested TAR dispatch must not persist partial results.
            tar_config["cache_enabled"] = False
            result.merge(TarScanner(config=tar_config).scan(path))

        result.bytes_scanned = file_size
        self._finish_scan_result(result)
        return result

    def _mark_inconclusive_scan_result(
        self,
        result: ScanResult,
        *,
        reason: str,
        check_name: str,
        message: str,
        location: str,
        details: dict[str, Any] | None = None,
        severity: IssueSeverity = IssueSeverity.INFO,
    ) -> None:
        reasons = result.metadata.get(_INCONCLUSIVE_REASONS_METADATA_KEY)
        if not isinstance(reasons, list):
            reasons = []
        if reason not in reasons:
            reasons.append(reason)

        result.metadata[_INCONCLUSIVE_METADATA_KEY] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata[_INCONCLUSIVE_REASONS_METADATA_KEY] = reasons
        result.add_check(
            name=check_name,
            passed=False,
            message=message,
            severity=severity,
            location=location,
            details={"scan_outcome_reason": reason, **(details or {})},
        )

    @staticmethod
    def _finish_scan_result(result: ScanResult) -> None:
        if result.metadata.get(
            _INCONCLUSIVE_METADATA_KEY
        ) == INCONCLUSIVE_SCAN_OUTCOME and not _scan_result_has_security_findings(result):
            result.finish(success=False)
            return

        result.finish(success=result.success and not result.has_errors)

    def _scan_nemo_archive(
        self,
        path: str,
        result: ScanResult,
        nemo_owned_entries: set[str],
        *,
        inspect_embedded_members: bool,
    ) -> None:
        """Extract and scan YAML configs from a NeMo tar archive."""
        yaml_configs_found = 0
        yaml_config_files_found = 0
        scanned_member_entries: set[str] = set()
        scanned_regular_checkpoint_sources: set[tuple[str, int]] = set()
        scanned_yaml_sources: set[tuple[str, int]] = set()

        with tarfile.open(path, "r:*") as tar:
            members_by_normalized_name: dict[str, list[tarfile.TarInfo]] = {}
            for archive_member in tar.getmembers():
                normalized_member_name = self._normalize_safe_archive_member_name(archive_member.name)
                if normalized_member_name is not None:
                    members_by_normalized_name.setdefault(normalized_member_name, []).append(archive_member)

            for member in tar:
                self.check_interrupted()

                temp_base = os.path.join(tempfile.gettempdir(), "extract_nemo")
                resolved_member, member_path_safe = sanitize_archive_path(member.name, temp_base)
                if not member_path_safe:
                    self._add_archive_path_traversal_check(
                        result,
                        archive_path=path,
                        entry=member.name,
                        target=None,
                    )
                    continue

                name_lower = member.name.lower()
                if member.issym() or member.islnk():
                    target_base = os.path.dirname(resolved_member)
                    _target_resolved, target_safe = sanitize_archive_path(member.linkname, target_base)
                    if not target_safe:
                        self._add_archive_path_traversal_check(
                            result,
                            archive_path=path,
                            entry=member.name,
                            target=member.linkname,
                        )
                    elif name_lower.endswith(tuple(NEMO_CHECKPOINT_MEMBER_EXTENSIONS)):
                        nemo_owned_entries.add(member.name)
                        if member.name in scanned_member_entries:
                            continue
                        link_target_name = self._resolve_archive_link_member_name(member)
                        if link_target_name is None:
                            self._mark_inconclusive_scan_result(
                                result,
                                reason="nemo_checkpoint_link_target_unresolved",
                                check_name="NeMo Checkpoint Nested Scan",
                                message=f"Could not resolve checkpoint link target: {member.name}",
                                location=f"{path}:{member.name}",
                                details={"entry": member.name, "target": member.linkname},
                            )
                        else:
                            target_members = members_by_normalized_name.get(link_target_name, [])
                            regular_target_members = [
                                target_member for target_member in target_members if target_member.isfile()
                            ]
                            if not target_members:
                                self._mark_inconclusive_scan_result(
                                    result,
                                    reason="nemo_checkpoint_link_target_missing",
                                    check_name="NeMo Checkpoint Nested Scan",
                                    message=f"Checkpoint link target not found: {member.name} -> {member.linkname}",
                                    location=f"{path}:{member.name}",
                                    details={"entry": member.name, "target": member.linkname},
                                )
                            elif regular_target_members:
                                for target_member in regular_target_members:
                                    self._scan_checkpoint_member(
                                        tar,
                                        target_member,
                                        path,
                                        result,
                                        entry_name=member.name,
                                    )
                            else:
                                self._mark_inconclusive_scan_result(
                                    result,
                                    reason="nemo_checkpoint_link_target_not_file",
                                    check_name="NeMo Checkpoint Nested Scan",
                                    message=f"Checkpoint link target is not a regular file: {member.name}",
                                    location=f"{path}:{member.name}",
                                    details={"entry": member.name, "target": member.linkname},
                                )
                    elif self._is_root_config_member_name(member.name):
                        link_target_name = self._resolve_archive_link_member_name(member)
                        if link_target_name is not None:
                            target_members = members_by_normalized_name.get(link_target_name, [])
                            for target_member in target_members:
                                target_identity = self._tar_member_identity(target_member)
                                if not target_member.isfile() or target_identity in scanned_yaml_sources:
                                    continue
                                yaml_config_files_found += 1
                                if self._scan_yaml_config_member(
                                    tar,
                                    target_member,
                                    member.name,
                                    path,
                                    result,
                                    nemo_owned_entries,
                                    scanned_member_entries,
                                    scanned_regular_checkpoint_sources,
                                ):
                                    yaml_configs_found += 1
                                scanned_yaml_sources.add(target_identity)
                    continue

                if not member.isfile():
                    continue

                if inspect_embedded_members:
                    self._scan_embedded_member_for_known_risks(tar, member, path, result)

                # Check for suspicious files in the archive
                if name_lower.endswith((".py", ".sh", ".bat", ".cmd", ".ps1")):
                    result.add_check(
                        name="Suspicious File in NeMo Archive",
                        passed=False,
                        message=(f"Executable file found in NeMo archive: {member.name}"),
                        severity=IssueSeverity.WARNING,
                        location=f"{path}:{member.name}",
                        details={"file": member.name},
                    )

                # Parse YAML config files
                if name_lower.endswith((".yaml", ".yml")):
                    member_identity = self._tar_member_identity(member)
                    if member_identity in scanned_yaml_sources:
                        continue
                    yaml_config_files_found += 1
                    if self._scan_yaml_config_member(
                        tar,
                        member,
                        member.name,
                        path,
                        result,
                        nemo_owned_entries,
                        scanned_member_entries,
                        scanned_regular_checkpoint_sources,
                    ):
                        yaml_configs_found += 1
                    scanned_yaml_sources.add(member_identity)

                if name_lower.endswith(tuple(NEMO_CHECKPOINT_MEMBER_EXTENSIONS)):
                    nemo_owned_entries.add(member.name)
                    member_identity = self._tar_member_identity(member)
                    if member.name in scanned_member_entries or member_identity in scanned_regular_checkpoint_sources:
                        continue
                    self._scan_checkpoint_member(tar, member, path, result)
                    scanned_regular_checkpoint_sources.add(member_identity)

        if yaml_configs_found == 0:
            message = (
                "No YAML configuration found in NeMo archive"
                if yaml_config_files_found == 0
                else "No analyzable YAML configuration found in NeMo archive"
            )
            if yaml_config_files_found == 0:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_config_missing",
                    check_name="NeMo Config Presence",
                    message=message,
                    location=path,
                )
            else:
                result.add_check(
                    name="NeMo Config Presence",
                    passed=False,
                    message=message,
                    severity=IssueSeverity.INFO,
                    location=path,
                )
        else:
            result.add_check(
                name="NeMo Config Presence",
                passed=True,
                message=f"Found {yaml_configs_found} YAML config(s)",
                location=path,
            )

    def _scan_embedded_member_for_known_risks(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        archive_path: str,
        result: ScanResult,
    ) -> None:
        """Apply bounded generic archive-member security checks inside NeMo files."""
        member_name_lower = member.name.lower()
        is_python_member = is_python_archive_member_name(member_name_lower)
        if is_executable_archive_member_name(member_name_lower):
            scan_archive_member_for_known_risks(
                archive_kind="NeMo",
                archive_path=archive_path,
                member_name=member.name,
                tmp_path=None,
                total_size=member.size,
                result=result,
                max_python_analysis_bytes=NEMO_MAX_PYTHON_ANALYSIS_BYTES,
                python_analysis_incomplete_reason="nemo_python_member_analysis_incomplete",
            )
            return

        if is_python_member and member.size > NEMO_MAX_PYTHON_ANALYSIS_BYTES:
            scan_archive_member_for_known_risks(
                archive_kind="NeMo",
                archive_path=archive_path,
                member_name=member.name,
                tmp_path=None,
                total_size=member.size,
                result=result,
                max_python_analysis_bytes=NEMO_MAX_PYTHON_ANALYSIS_BYTES,
                python_analysis_incomplete_reason="nemo_python_member_analysis_incomplete",
            )
            return

        max_bytes = None
        if not is_python_member:
            max_bytes = (
                NEMO_EXECUTABLE_PE_PROBE_BYTES
                if self._member_starts_with_portable_executable_magic(tar, member)
                else NEMO_EXECUTABLE_INITIAL_PROBE_BYTES
            )
        extracted_path = self._extract_member_to_tempfile(tar, member, max_bytes=max_bytes)
        if extracted_path is None:
            return

        try:
            scan_archive_member_for_known_risks(
                archive_kind="NeMo",
                archive_path=archive_path,
                member_name=member.name,
                tmp_path=extracted_path,
                total_size=member.size,
                result=result,
                max_python_analysis_bytes=NEMO_MAX_PYTHON_ANALYSIS_BYTES,
                python_analysis_incomplete_reason="nemo_python_member_analysis_incomplete",
            )
        finally:
            try:
                os.unlink(extracted_path)
            except OSError:
                logger.debug("Failed to remove temporary NeMo member security file: %s", extracted_path)

    @staticmethod
    def _member_starts_with_portable_executable_magic(tar: tarfile.TarFile, member: tarfile.TarInfo) -> bool:
        member_file = tar.extractfile(member)
        if member_file is None:
            return False
        with member_file:
            return member_file.read(2) == b"MZ"

    def _scan_yaml_config_member(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        config_file: str,
        archive_path: str,
        result: ScanResult,
        nemo_owned_entries: set[str],
        scanned_member_entries: set[str],
        scanned_regular_checkpoint_sources: set[tuple[str, int]],
    ) -> bool:
        """Analyze one YAML config entry, including a safe root-config link target."""
        if member.size > self.MAX_CONFIG_SIZE:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_config_size_limit",
                check_name="NeMo Config Size Check",
                message=f"Config file too large: {config_file} ({member.size} bytes)",
                location=f"{archive_path}:{config_file}",
                severity=IssueSeverity.WARNING,
                details={
                    "config_file": config_file,
                    "size_bytes": member.size,
                    "max_config_size": self.MAX_CONFIG_SIZE,
                },
            )
            return False

        member_file = tar.extractfile(member)
        if member_file is None:
            return False
        with member_file:
            try:
                raw = member_file.read(self.MAX_CONFIG_SIZE + 1)
                if len(raw) > self.MAX_CONFIG_SIZE:
                    self._mark_inconclusive_scan_result(
                        result,
                        reason="nemo_config_size_limit",
                        check_name="NeMo Config Size Check",
                        message=f"Config file too large: {config_file} ({len(raw)} bytes)",
                        location=f"{archive_path}:{config_file}",
                        severity=IssueSeverity.WARNING,
                        details={
                            "config_file": config_file,
                            "size_bytes": len(raw),
                            "max_config_size": self.MAX_CONFIG_SIZE,
                        },
                    )
                    return False
                config = yaml.safe_load(raw)
            except yaml.YAMLError:
                logger.debug("Failed to parse YAML config %s in %s", config_file, archive_path)
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_config_yaml_parse_failed",
                    check_name="NeMo Config YAML Parsing",
                    message=f"Failed to parse YAML config {config_file}",
                    location=f"{archive_path}:{config_file}",
                    details={"config_file": config_file},
                )
                return False

        if not isinstance(config, dict | list):
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_config_invalid_structure",
                check_name="NeMo Config Structure",
                message=f"YAML config {config_file} has unsupported top-level type: {type(config).__name__}",
                location=f"{archive_path}:{config_file}",
                details={
                    "config_file": config_file,
                    "expected_type": "dict_or_list",
                    "actual_type": type(config).__name__,
                },
            )
            return False

        self._check_hydra_targets(config, config_file, archive_path, result)
        for config_path, referenced_member_name in self._collect_nemo_member_references(config):
            nemo_owned_entries.add(referenced_member_name)
            if referenced_member_name in scanned_member_entries:
                continue
            referenced_member_scanned = self._scan_config_referenced_member(
                tar,
                referenced_member_name,
                archive_path,
                result,
                config_file=config_file,
                config_path=config_path,
                scanned_regular_checkpoint_sources=scanned_regular_checkpoint_sources,
            )
            if referenced_member_scanned:
                scanned_member_entries.add(referenced_member_name)
        return True

    @staticmethod
    def _is_root_config_member_name(member_name: str) -> bool:
        normalized_name = NemoScanner._normalize_safe_archive_member_name(member_name)
        return normalized_name is not None and normalized_name.lower() in {"model_config.yaml", "model_config.yml"}

    @staticmethod
    def _tar_member_identity(member: tarfile.TarInfo) -> tuple[str, int]:
        """Return an identity that distinguishes duplicate TAR entry headers."""
        return member.name, member.offset

    @staticmethod
    def _normalize_safe_archive_member_name(member_name: str) -> str | None:
        """Normalize an archive member path that cannot escape extraction root."""
        normalized_name = posixpath.normpath(member_name.replace("\\", "/"))
        if is_absolute_archive_path(normalized_name):
            return None
        if normalized_name in {"", ".", ".."} or normalized_name.startswith("../"):
            return None
        return normalized_name

    @staticmethod
    def _resolve_archive_link_member_name(member: tarfile.TarInfo) -> str | None:
        """Resolve a tar link target to a normalized archive member name."""
        linkname = member.linkname.replace("\\", "/")
        if is_absolute_archive_path(linkname):
            return None

        if member.islnk():
            candidate = linkname
        else:
            member_dir = posixpath.dirname(member.name.replace("\\", "/"))
            candidate = posixpath.join(member_dir, linkname)
        return NemoScanner._normalize_safe_archive_member_name(candidate)

    def _add_archive_path_traversal_check(
        self,
        result: ScanResult,
        *,
        archive_path: str,
        entry: str,
        target: str | None,
    ) -> None:
        """Report NeMo archive member paths that can escape extraction roots."""
        path_value = target or entry
        if is_absolute_archive_path(path_value):
            cve_id = "CVE-2025-23250"
            cvss = 7.6
            cwe = "CWE-22"
            description = (
                "NVIDIA NeMo Framework archive loading can improperly limit absolute or out-of-root paths, "
                "allowing arbitrary file writes from crafted model archives."
            )
            remediation = "Update NVIDIA NeMo Framework to release 25.02 or later and reject unsafe archive paths."
        else:
            cve_id = "CVE-2025-23360"
            cvss = 7.1
            cwe = "CWE-23"
            description = (
                "NVIDIA NeMo Framework archive loading can process relative path traversal entries, allowing "
                "crafted model archives to write files outside the intended extraction directory."
            )
            remediation = "Update NVIDIA NeMo Framework to release 24.12 or later and reject relative traversal paths."

        result.add_check(
            name=f"{cve_id}: NeMo Archive Path Traversal",
            passed=False,
            message=(
                f"{cve_id}: NeMo archive member '{entry}'"
                + (f" links to unsafe target '{target}'" if target is not None else " escapes extraction root")
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:{entry}",
            details={
                "entry": entry,
                "target": target,
                "cve_id": cve_id,
                "cvss": cvss,
                "cwe": cwe,
                "description": description,
                "remediation": remediation,
            },
            why=(
                "The .nemo file is a tar archive. This member path would escape the intended extraction "
                "directory in vulnerable NeMo loaders, creating an arbitrary file-write risk."
            ),
        )

    def _scan_checkpoint_member(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        archive_path: str,
        result: ScanResult,
        *,
        entry_name: str | None = None,
    ) -> None:
        """Run existing nested scanners over small NeMo checkpoint members."""
        report_entry = entry_name or member.name
        max_scan_bytes = self._normalize_positive_int_config(
            self.config.get("max_nemo_checkpoint_scan_bytes"),
            NEMO_MAX_CHECKPOINT_SCAN_BYTES,
        )
        if member.size > max_scan_bytes:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_checkpoint_scan_skipped_size_limit",
                check_name="NeMo Checkpoint Nested Scan",
                message=f"Checkpoint member exceeds nested scan limit: {report_entry}",
                location=f"{archive_path}:{report_entry}",
                details={
                    "entry": report_entry,
                    "source_entry": member.name,
                    "size_bytes": member.size,
                    "max_scan_bytes": max_scan_bytes,
                },
            )
            return

        extracted_path = self._extract_member_to_tempfile(tar, member, suffix_source=report_entry)
        if extracted_path is None:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_checkpoint_extract_failed",
                check_name="NeMo Checkpoint Nested Scan",
                message=f"Could not extract checkpoint member for nested scan: {report_entry}",
                location=f"{archive_path}:{report_entry}",
                details={"entry": report_entry, "source_entry": member.name},
            )
            return

        try:
            scanner = _get_nested_scanner_for_file(extracted_path, config=dict(self.config))
            if scanner is None:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_checkpoint_no_nested_scanner",
                    check_name="NeMo Checkpoint Nested Scan",
                    message=f"No nested scanner available for checkpoint member: {report_entry}",
                    location=f"{archive_path}:{report_entry}",
                    details={"entry": report_entry, "source_entry": member.name},
                )
                return

            try:
                nested_result = scanner.scan(extracted_path)
            except Exception as exc:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_checkpoint_nested_scan_failed",
                    check_name="NeMo Checkpoint Nested Scan",
                    message=f"Nested scan failed for checkpoint member {report_entry}: {exc!s}",
                    location=f"{archive_path}:{report_entry}",
                    details={
                        "entry": report_entry,
                        "source_entry": member.name,
                        "nested_scanner": scanner.name,
                        "exception_type": type(exc).__name__,
                    },
                )
                return

            self._merge_nested_security_findings(result, nested_result, extracted_path, archive_path, report_entry)
            critical_issues = [
                issue
                for issue in nested_result.issues
                if issue.severity == IssueSeverity.CRITICAL
                and self._is_nested_checkpoint_deserialization_issue(issue, nested_result.scanner_name)
            ]
            if critical_issues:
                self._add_checkpoint_deserialization_check(
                    result,
                    archive_path=archive_path,
                    entry=report_entry,
                    nested_scanner=nested_result.scanner_name,
                    critical_issues=critical_issues,
                )
        finally:
            try:
                os.unlink(extracted_path)
            except OSError:
                logger.debug("Failed to remove temporary NeMo checkpoint scan file: %s", extracted_path)

    def _scan_config_referenced_member(
        self,
        tar: tarfile.TarFile,
        referenced_member_name: str,
        archive_path: str,
        result: ScanResult,
        *,
        config_file: str,
        config_path: str,
        scanned_regular_checkpoint_sources: set[tuple[str, int]],
    ) -> bool:
        """Scan `nemo:`-referenced archive members through content-based nested dispatch."""
        try:
            member = tar.getmember(referenced_member_name)
        except KeyError:
            return False

        if (
            member.isfile()
            and referenced_member_name.lower().endswith(tuple(NEMO_CHECKPOINT_MEMBER_EXTENSIONS))
            and self._tar_member_identity(member) in scanned_regular_checkpoint_sources
        ):
            return True

        if member.issym() or member.islnk():
            resolved_name = self._resolve_archive_link_member_name(member)
            if resolved_name is None:
                return False
            try:
                member = tar.getmember(resolved_name)
            except KeyError:
                return False

        if not member.isfile():
            return False

        max_scan_bytes = self._normalize_positive_int_config(
            self.config.get("max_nemo_checkpoint_scan_bytes"),
            NEMO_MAX_CHECKPOINT_SCAN_BYTES,
        )
        if member.size > max_scan_bytes:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_checkpoint_scan_skipped_size_limit",
                check_name="NeMo Checkpoint Nested Scan",
                message=f"Referenced member exceeds nested scan limit: {referenced_member_name}",
                location=f"{archive_path}:{referenced_member_name}",
                details={
                    "entry": referenced_member_name,
                    "source_entry": member.name,
                    "config_file": config_file,
                    "config_path": config_path,
                    "size_bytes": member.size,
                    "max_scan_bytes": max_scan_bytes,
                },
            )
            return True

        extracted_path = self._extract_member_to_tempfile(tar, member, suffix_source=referenced_member_name)
        if extracted_path is None:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_checkpoint_extract_failed",
                check_name="NeMo Checkpoint Nested Scan",
                message=f"Could not extract referenced member for nested scan: {referenced_member_name}",
                location=f"{archive_path}:{referenced_member_name}",
                details={
                    "entry": referenced_member_name,
                    "source_entry": member.name,
                    "config_file": config_file,
                    "config_path": config_path,
                },
            )
            return True

        try:
            from .archive_dispatch import scan_nested_file

            try:
                nested_result = scan_nested_file(extracted_path, config=dict(self.config))
            except Exception as exc:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_referenced_nested_scan_failed",
                    check_name="NeMo Checkpoint Nested Scan",
                    message=f"Nested scan failed for referenced member {referenced_member_name}: {exc!s}",
                    location=f"{archive_path}:{referenced_member_name}",
                    details={
                        "entry": referenced_member_name,
                        "source_entry": member.name,
                        "config_file": config_file,
                        "config_path": config_path,
                        "exception_type": type(exc).__name__,
                        "exception_message": str(exc),
                    },
                )
                return True

            self._merge_nested_security_findings(
                result,
                nested_result,
                extracted_path,
                archive_path,
                referenced_member_name,
            )
            critical_issues = [
                issue
                for issue in nested_result.issues
                if issue.severity == IssueSeverity.CRITICAL
                and self._is_nested_checkpoint_deserialization_issue(issue, nested_result.scanner_name)
            ]
            if critical_issues:
                self._add_checkpoint_deserialization_check(
                    result,
                    archive_path=archive_path,
                    entry=referenced_member_name,
                    nested_scanner=nested_result.scanner_name,
                    critical_issues=critical_issues,
                    extra_details={
                        "config_file": config_file,
                        "config_path": config_path,
                        "source_entry": member.name,
                    },
                )
            return True
        finally:
            try:
                os.unlink(extracted_path)
            except OSError:
                logger.debug("Failed to remove temporary NeMo referenced scan file: %s", extracted_path)

    @staticmethod
    def _merge_nested_security_findings(
        result: ScanResult,
        nested_result: ScanResult,
        extracted_path: str,
        archive_path: str,
        entry_name: str,
    ) -> None:
        """Preserve actionable nested findings while NeMo adds CVE attribution."""
        archive_location = f"{archive_path}:{entry_name}"
        actionable_severities = {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in nested_result.checks:
            if check.status != CheckStatus.FAILED or check.severity not in actionable_severities:
                continue
            check.location = rewrite_extracted_member_location(
                check.location,
                extracted_path,
                archive_location,
                preserve_non_delimited_suffix=False,
            )
            result.checks.append(check)
        for issue in nested_result.issues:
            if issue.severity not in actionable_severities:
                continue
            issue.location = rewrite_extracted_member_location(
                issue.location,
                extracted_path,
                archive_location,
                preserve_non_delimited_suffix=False,
            )
            result.issues.append(issue)

    @classmethod
    def _collect_nemo_member_references(
        cls,
        config: Any,
        path_prefix: str = "",
    ) -> list[tuple[str, str]]:
        """Collect internal `nemo:` artifact references from a parsed config."""
        collected: list[tuple[str, str]] = []

        if isinstance(config, list):
            for index, item in enumerate(config):
                collected.extend(
                    cls._collect_nemo_member_references(
                        item,
                        f"{path_prefix}[{index}]" if path_prefix else f"[{index}]",
                    )
                )
            return collected

        if isinstance(config, dict):
            for key, value in config.items():
                current_path = f"{path_prefix}.{key}" if path_prefix else key
                collected.extend(cls._collect_nemo_member_references(value, current_path))
            return collected

        if isinstance(config, str):
            member_name = cls._extract_nemo_member_reference(config)
            if member_name is not None:
                return [(path_prefix or "$", member_name)]

        return []

    @staticmethod
    def _extract_nemo_member_reference(value: str) -> str | None:
        normalized = value.strip()
        if not normalized or ":" not in normalized:
            return None

        scheme, member_name = normalized.split(":", 1)
        if scheme.lower() != "nemo":
            return None

        member_name = member_name.strip().replace("\\", "/")
        if not member_name:
            return None

        normalized_member = os.path.normpath(member_name).replace("\\", "/")
        if (
            normalized_member in {"", ".", ".."}
            or normalized_member.startswith("../")
            or is_absolute_archive_path(normalized_member)
        ):
            return None

        return normalized_member.lstrip("./")

    @staticmethod
    def _is_nested_checkpoint_deserialization_issue(issue: Any, nested_scanner: str | None = None) -> bool:
        details = issue.details if isinstance(issue.details, dict) else {}
        if nested_scanner == "torch7" and details.get("signal") == "exec_with_network_shell_context":
            return True

        text = " ".join(
            str(part).lower()
            for part in (
                issue.message,
                issue.type,
                issue.rule_code,
                details.get("cve_id", ""),
                details.get("opcode", ""),
                details.get("symbol", ""),
                details.get("function", ""),
            )
        )
        return any(
            indicator in text
            for indicator in (
                "pickle",
                "unpickle",
                "deserial",
                "opcode",
                "global",
                "reduce",
                "torch.load",
                "arbitrary code",
                "cve-2020-13092",
                "cve-2025-1716",
                "cve-2025-32434",
            )
        )

    @staticmethod
    def _extract_member_to_tempfile(
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        *,
        suffix_source: str | None = None,
        max_bytes: int | None = None,
    ) -> str | None:
        member_file = tar.extractfile(member)
        if member_file is None:
            return None

        _root, suffix = os.path.splitext(suffix_source or member.name)
        with member_file, tempfile.NamedTemporaryFile(suffix=suffix or ".bin", delete=False) as temp_file:
            remaining = max_bytes
            while True:
                if remaining is not None and remaining <= 0:
                    break
                chunk = member_file.read(64 * 1024 if remaining is None else min(64 * 1024, remaining))
                if not chunk:
                    break
                temp_file.write(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
            return temp_file.name

    def _add_checkpoint_deserialization_check(
        self,
        result: ScanResult,
        *,
        archive_path: str,
        entry: str,
        nested_scanner: str,
        critical_issues: list[Any],
        extra_details: dict[str, Any] | None = None,
    ) -> None:
        result.add_check(
            name="CVE-2025-23249: NeMo Checkpoint Unsafe Deserialization",
            passed=False,
            message=(
                "CVE-2025-23249: NeMo checkpoint member contains unsafe deserialization payloads "
                f"detected by {nested_scanner}"
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:{entry}",
            details={
                "entry": entry,
                "nested_scanner": nested_scanner,
                "critical_issue_count": len(critical_issues),
                "sample_issue_messages": [issue.message for issue in critical_issues[:3]],
                "cve_id": "CVE-2025-23249",
                "cvss": 7.6,
                "cwe": "CWE-502",
                "description": (
                    "NVIDIA NeMo Framework contains unsafe deserialization paths for untrusted model data. "
                    "A crafted checkpoint inside a .nemo archive can trigger code execution when loaded."
                ),
                "related_cves": ["CVE-2025-33253", "CVE-2026-24157"],
                "remediation": (
                    "Update NVIDIA NeMo Framework to release 25.02 or later, keep current with subsequent "
                    "checkpoint-loading fixes, and reject untrusted checkpoint payloads."
                ),
                **(extra_details or {}),
            },
            why=(
                "A nested scanner found critical unsafe-deserialization behavior inside a checkpoint bundled "
                "in the .nemo archive. Vulnerable NeMo loaders may deserialize these checkpoints during model load."
            ),
        )

    def _check_hydra_targets(
        self,
        config: Any,
        config_name: str,
        archive_path: str,
        result: ScanResult,
        path_prefix: str = "",
    ) -> None:
        """Recursively check _target_ values in Hydra config."""
        if isinstance(config, list):
            for index, item in enumerate(config):
                if isinstance(item, dict | list):
                    self._check_hydra_targets(
                        item,
                        config_name,
                        archive_path,
                        result,
                        f"{path_prefix}[{index}]" if path_prefix else f"[{index}]",
                    )
            return

        if not isinstance(config, dict):
            return

        for key, value in config.items():
            current_path = f"{path_prefix}.{key}" if path_prefix else key

            if key == "_target_" and isinstance(value, str):
                self._evaluate_target(value, current_path, config_name, archive_path, result, config)
            elif isinstance(value, dict | list):
                self._check_hydra_targets(value, config_name, archive_path, result, current_path)

    def _evaluate_target(
        self,
        target: str,
        config_path: str,
        config_name: str,
        archive_path: str,
        result: ScanResult,
        target_config: dict[str, Any] | None = None,
    ) -> None:
        """Evaluate a single _target_ value for dangerous patterns."""
        # Check against known dangerous targets (always flag, even if safe prefix)
        if target in _DANGEROUS_TARGETS or (target == "numpy.load" and self._numpy_load_allows_pickle(target_config)):
            result.add_check(
                name=f"{CVE_2025_23304_ID}: Dangerous Hydra _target_",
                passed=False,
                message=(f"{CVE_2025_23304_ID}: Dangerous _target_ '{target}' at {config_path} in {config_name}"),
                severity=IssueSeverity.CRITICAL,
                location=f"{archive_path}:{config_name}",
                details={
                    "target": target,
                    "config_path": config_path,
                    "config_file": config_name,
                    "cve_id": CVE_2025_23304_ID,
                    "cvss": CVE_2025_23304_CVSS,
                    "cwe": CVE_2025_23304_CWE,
                    "description": CVE_2025_23304_DESCRIPTION,
                    "remediation": CVE_2025_23304_REMEDIATION,
                },
                why=(
                    f"The _target_ field '{target}' in this NeMo "
                    f"config specifies a dangerous Python callable. "
                    f"When hydra.utils.instantiate() processes this "
                    f"config, it will execute arbitrary code "
                    f"({CVE_2025_23304_ID})."
                ),
            )
            return

        # Trusted namespaces can still hide obviously dangerous leaf names.
        if any(target.startswith(prefix) for prefix in _SAFE_TARGET_PREFIXES):
            pattern = _find_suspicious_safe_prefixed_target_pattern(target)
            if pattern is not None:
                self._add_suspicious_target_check(
                    target,
                    pattern,
                    config_path,
                    config_name,
                    archive_path,
                    result,
                )
                return
            result.add_check(
                name="Hydra _target_ Safety Check",
                passed=True,
                message=(f"Safe _target_ '{target}' at {config_path} in {config_name}"),
                location=f"{archive_path}:{config_name}",
                details={"target": target, "config_path": config_path},
            )
            return

        # Check for suspicious patterns in target (only for non-safe targets)
        pattern = _find_suspicious_target_pattern(target)
        if pattern is not None:
            self._add_suspicious_target_check(target, pattern, config_path, config_name, archive_path, result)
            return

        # Unknown target - flag for review
        result.add_check(
            name="Hydra _target_ Review",
            passed=False,
            message=(f"Unknown _target_ '{target}' at {config_path} in {config_name} - requires manual review"),
            severity=IssueSeverity.INFO,
            location=f"{archive_path}:{config_name}",
            details={
                "target": target,
                "config_path": config_path,
                "config_file": config_name,
            },
        )

    def _add_suspicious_target_check(
        self,
        target: str,
        pattern: str,
        config_path: str,
        config_name: str,
        archive_path: str,
        result: ScanResult,
    ) -> None:
        result.add_check(
            name=f"{CVE_2025_23304_ID}: Suspicious Hydra _target_",
            passed=False,
            message=(
                f"{CVE_2025_23304_ID}: Suspicious _target_ "
                f"'{target}' (contains '{pattern}') at "
                f"{config_path} in {config_name}"
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:{config_name}",
            details={
                "target": target,
                "pattern": pattern,
                "config_path": config_path,
                "config_file": config_name,
                "cve_id": CVE_2025_23304_ID,
                "cvss": CVE_2025_23304_CVSS,
                "cwe": CVE_2025_23304_CWE,
                "description": CVE_2025_23304_DESCRIPTION,
                "remediation": CVE_2025_23304_REMEDIATION,
            },
        )

    @staticmethod
    def _numpy_load_allows_pickle(target_config: dict[str, Any] | None) -> bool:
        """Return whether a Hydra numpy.load target enables pickle loading."""
        if not isinstance(target_config, dict):
            return False

        if "allow_pickle" in target_config:
            return _is_runtime_truthy(target_config["allow_pickle"])

        positional_args = target_config.get("_args_")
        if isinstance(positional_args, list) and len(positional_args) >= 3:
            return _is_runtime_truthy(positional_args[2])

        return False
