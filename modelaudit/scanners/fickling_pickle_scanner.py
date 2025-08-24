"""
Fickling-enhanced pickle scanner for comprehensive security analysis.

This scanner replaces the legacy pickle detection logic with fickling's
advanced static analysis capabilities, providing deeper threat detection
while simplifying the codebase.
"""

import os
import time
from typing import ClassVar, Optional

import fickling
from fickling.analysis import AnalysisResults, Severity, check_safety
from fickling.exception import UnsafeFileError
from fickling.fickle import Pickled

from ..explanations import get_import_explanation, get_opcode_explanation
from .base import BaseScanner, IssueSeverity, ScanResult, logger


class FicklingPickleScanner(BaseScanner):
    """Scanner for Python Pickle files using fickling's advanced analysis"""

    name = "fickling_pickle"
    description = "Scans Python pickle files using fickling's comprehensive security analysis"
    supported_extensions: ClassVar[list[str]] = [
        ".pkl",
        ".pickle",
        ".dill",
        ".joblib",
        ".bin",
        ".pth",  # PyTorch models
        ".pt",  # PyTorch tensors
        ".p",  # Short pickle extension
        ".data",  # Some models use .data
    ]

    @classmethod
    def can_handle(cls, file_path: str) -> bool:
        """Check if this scanner can handle the given file"""
        return any(file_path.lower().endswith(ext) for ext in cls.supported_extensions)

    def scan(self, file_path: str, timeout: Optional[float] = None) -> ScanResult:
        """Scan a pickle file using fickling's analysis engine"""
        start_time = time.time()
        result = ScanResult(scanner_name=self.name)
        result.metadata["file_path"] = file_path

        # Check if file exists
        if not os.path.exists(file_path):
            result.success = False
            result.add_issue(
                message=f"File not found: {file_path}",
                severity=IssueSeverity.CRITICAL,
            )
            return result

        try:
            # Load pickle file with fickling
            with open(file_path, "rb") as f:
                pickled = Pickled.load(f)

            # Check for timeout
            if timeout and (time.time() - start_time) > timeout:
                result.metadata["timeout_seconds"] = timeout
                result.success = False
                result.add_issue(
                    message="Scan timed out",
                    severity=IssueSeverity.CRITICAL,
                )
                return result

            # Run fickling's comprehensive analysis
            analysis_results = check_safety(pickled)

            # Add metadata first
            result.metadata.update(
                {
                    "fickling_severity": analysis_results.severity.name,
                    "fickling_safe": bool(analysis_results),
                    "scan_time_seconds": time.time() - start_time,
                    "file_size": self._get_file_size(file_path),
                    "opcodes_analyzed": len(list(pickled)),
                }
            )

            # Convert fickling results to ModelAudit issues
            self._convert_fickling_results(analysis_results, result)

        except UnsafeFileError as e:
            # Fickling detected unsafe content
            result.add_issue(
                message=f"Malicious Pickle Detected: Fickling detected unsafe content: {e}",
                severity=IssueSeverity.CRITICAL,
                details={
                    **getattr(e, "info", {}),
                    "recommendation": "Do not load this pickle file - it contains malicious code",
                },
            )
            result.metadata["fickling_unsafe"] = True

        except Exception as e:
            logger.warning(f"Fickling analysis failed for {file_path}: {e}")
            # Fallback to basic safety check
            try:
                if not fickling.is_likely_safe(file_path):
                    result.add_issue(
                        message="Potentially Unsafe Pickle: Basic safety check indicates this pickle may be unsafe",
                        severity=IssueSeverity.CRITICAL,
                        details={"recommendation": "Manual inspection recommended"},
                    )
            except Exception:
                result.success = False
                result.add_issue(
                    message=f"Analysis failed: {e}",
                    severity=IssueSeverity.CRITICAL,
                )

        return result

    def _get_file_size(self, file_path: str) -> int:
        """Get file size in bytes"""
        try:
            return os.path.getsize(file_path)
        except OSError:
            return 0

    def _convert_fickling_results(self, analysis_results: AnalysisResults, result: ScanResult) -> None:
        """Convert fickling analysis results to ModelAudit issues"""

        for fickling_result in analysis_results.results:
            # Map fickling severity to ModelAudit severity
            severity = self._map_fickling_severity(fickling_result.severity)

            # Skip likely safe results unless they have interesting details
            if fickling_result.severity == Severity.LIKELY_SAFE:
                continue

            # Create issue directly via add_issue method
            message = f"{self._generate_issue_title(fickling_result)}: {fickling_result!s}"
            details = {
                "fickling_analysis": fickling_result.analysis_name,
                "fickling_severity": fickling_result.severity.name,
                "trigger": fickling_result.trigger,
                "recommendation": self._generate_recommendation(fickling_result),
            }

            # Add explanations where available
            self._add_explanations(details, fickling_result)

            # Add issue using the method's expected parameters
            result.add_issue(message=message, severity=severity, details=details)

    def _map_fickling_severity(self, fickling_severity: Severity) -> IssueSeverity:
        """Map fickling severity levels to ModelAudit severity levels"""
        if fickling_severity == Severity.LIKELY_SAFE:
            return IssueSeverity.INFO
        elif fickling_severity == Severity.POSSIBLY_UNSAFE or fickling_severity == Severity.SUSPICIOUS:
            return IssueSeverity.WARNING
        elif fickling_severity in (
            Severity.LIKELY_UNSAFE,
            Severity.LIKELY_OVERTLY_MALICIOUS,
            Severity.OVERTLY_MALICIOUS,
        ):
            return IssueSeverity.CRITICAL
        else:
            return IssueSeverity.WARNING

    def _generate_issue_title(self, fickling_result) -> str:
        """Generate descriptive issue titles based on fickling analysis"""
        analysis_name = fickling_result.analysis_name or "Unknown"

        title_mapping = {
            "OvertlyBadEval": "Malicious Code Execution",
            "UnsafeImports": "Dangerous Module Import",
            "UnsafeImportsML": "ML-Unsafe Module Import",
            "NonStandardImports": "Non-Standard Module Import",
            "UnusedVariables": "Suspicious Unused Variables",
            "DuplicateProtoAnalysis": "Protocol Tampering",
            "MisplacedProtoAnalysis": "Malformed Protocol",
            "InvalidOpcode": "Invalid Pickle Opcodes",
            "BadCalls": "Dangerous Function Calls",
        }

        return title_mapping.get(analysis_name, f"Pickle Security Issue ({analysis_name})")

    def _generate_recommendation(self, fickling_result) -> str:
        """Generate security recommendations based on fickling analysis"""
        analysis_name = fickling_result.analysis_name or ""

        if "Eval" in analysis_name or "BadCalls" in analysis_name:
            return "Do not load this pickle - it contains code execution vulnerabilities"
        elif "Import" in analysis_name:
            return "Verify that imported modules are safe and necessary for the model"
        elif "Proto" in analysis_name or "InvalidOpcode" in analysis_name:
            return "This pickle may be tampered with or corrupted - verify integrity"
        elif "UnusedVariables" in analysis_name:
            return "Review unused variable assignments for hidden malicious code"
        else:
            return "Manual security review recommended before loading this pickle"

    def _add_explanations(self, details: dict, fickling_result) -> None:
        """Add detailed explanations to issue details where available"""
        trigger = fickling_result.trigger

        if not trigger:
            return

        # Handle string triggers
        if isinstance(trigger, str):
            # Add opcode explanations for dangerous opcodes
            if any(op in trigger.upper() for op in ["REDUCE", "INST", "OBJ", "NEWOBJ", "STACK_GLOBAL"]):
                explanation = get_opcode_explanation(trigger.upper())
                if explanation:
                    details["opcode_explanation"] = explanation

            # Add import explanations for dangerous imports
            if "import" in trigger.lower():
                # Extract module name from trigger
                parts = trigger.split()
                if len(parts) >= 2:
                    module = parts[1].strip("'\"()")
                    explanation = get_import_explanation(module)
                    if explanation:
                        details["import_explanation"] = explanation

        # Handle tuple triggers (e.g., from UnusedVariables analysis)
        elif isinstance(trigger, tuple) and len(trigger) >= 2:
            _, var_value = trigger[0], trigger[1]
            # Check if the value contains dangerous operations
            if isinstance(var_value, str) and any(
                op in var_value.upper() for op in ["REDUCE", "INST", "OBJ", "NEWOBJ", "STACK_GLOBAL"]
            ):
                explanation = get_opcode_explanation(var_value.upper())
                if explanation:
                    details["opcode_explanation"] = explanation
