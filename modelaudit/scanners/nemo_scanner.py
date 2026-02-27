"""Scanner for NVIDIA NeMo model files (.nemo).

NeMo files are tar archives containing YAML configuration and model weights.
CVE-2025-23304: Hydra _target_ fields in NeMo configs can specify arbitrary
Python callables, enabling RCE when loaded via hydra.utils.instantiate().
"""

import logging
import os
import tarfile
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

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

CVE_2025_23304_ID = "CVE-2025-23304"
CVE_2025_23304_CVSS = 7.6
CVE_2025_23304_CWE = "CWE-94"


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
        if ext not in cls.supported_extensions:
            return False
        # Verify it's actually a tar archive
        return tarfile.is_tarfile(path)

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        if not HAS_YAML:
            result.add_check(
                name="YAML Parser Availability",
                passed=False,
                message="PyYAML not available; cannot analyze NeMo config for Hydra _target_ injection",
                severity=IssueSeverity.WARNING,
                location=path,
            )
            result.bytes_scanned = file_size
            return result

        try:
            self._scan_nemo_archive(path, result)
        except tarfile.TarError as e:
            result.add_check(
                name="NeMo Archive Integrity",
                passed=False,
                message=f"Failed to open NeMo archive: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
            )
            result.success = False

        result.bytes_scanned = file_size
        return result

    def _scan_nemo_archive(self, path: str, result: ScanResult) -> None:
        """Extract and scan YAML configs from a NeMo tar archive."""
        yaml_configs_found = 0

        with tarfile.open(path, "r:*") as tar:
            for member in tar.getmembers():
                self.check_interrupted()

                if not member.isfile():
                    continue

                name_lower = member.name.lower()

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
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    with f:
                        try:
                            raw = f.read()
                            # Safety: limit size to avoid YAML bomb
                            if len(raw) > self.MAX_CONFIG_SIZE:
                                result.add_check(
                                    name="NeMo Config Size Check",
                                    passed=False,
                                    message=(f"Config file too large: {member.name} ({len(raw)} bytes)"),
                                    severity=IssueSeverity.WARNING,
                                    location=f"{path}:{member.name}",
                                )
                                continue
                            config = yaml.safe_load(raw)
                            if isinstance(config, dict):
                                yaml_configs_found += 1
                                self._check_hydra_targets(config, member.name, path, result)
                        except yaml.YAMLError:
                            logger.debug("Failed to parse YAML config %s in %s", member.name, path)

        if yaml_configs_found == 0:
            result.add_check(
                name="NeMo Config Presence",
                passed=False,
                message="No YAML configuration found in NeMo archive",
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

    def _check_hydra_targets(
        self,
        config: Any,
        config_name: str,
        archive_path: str,
        result: ScanResult,
        path_prefix: str = "",
    ) -> None:
        """Recursively check _target_ values in Hydra config."""
        if not isinstance(config, dict):
            return

        for key, value in config.items():
            current_path = f"{path_prefix}.{key}" if path_prefix else key

            if key == "_target_" and isinstance(value, str):
                self._evaluate_target(value, current_path, config_name, archive_path, result)
            elif isinstance(value, dict):
                self._check_hydra_targets(value, config_name, archive_path, result, current_path)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        self._check_hydra_targets(
                            item,
                            config_name,
                            archive_path,
                            result,
                            f"{current_path}[{i}]",
                        )

    def _evaluate_target(
        self,
        target: str,
        config_path: str,
        config_name: str,
        archive_path: str,
        result: ScanResult,
    ) -> None:
        """Evaluate a single _target_ value for dangerous patterns."""
        # Check against known dangerous targets (always flag, even if safe prefix)
        if target in _DANGEROUS_TARGETS:
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
                    "description": (
                        "NeMo Hydra _target_ specifies a dangerous callable that enables RCE when instantiated"
                    ),
                    "remediation": (
                        "Update to NeMo >= 2.3.2 which validates _target_ values. Do not load untrusted .nemo files."
                    ),
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

        # Check safe prefixes BEFORE suspicious patterns to avoid
        # false positives on legitimate targets like nemo.eval_utils
        if any(target.startswith(prefix) for prefix in _SAFE_TARGET_PREFIXES):
            result.add_check(
                name="Hydra _target_ Safety Check",
                passed=True,
                message=(f"Safe _target_ '{target}' at {config_path} in {config_name}"),
                location=f"{archive_path}:{config_name}",
                details={"target": target, "config_path": config_path},
            )
            return

        # Check for suspicious patterns in target (only for non-safe targets)
        target_lower = target.lower()
        for pattern in _SUSPICIOUS_TARGET_PATTERNS:
            if pattern in target_lower:
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
                    },
                )
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
