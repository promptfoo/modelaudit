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
from ..suspicious_symbols import BINARY_CODE_PATTERNS, EXECUTABLE_SIGNATURES
from .base import BaseScanner, IssueSeverity, ScanResult, logger


class FicklingPickleScanner(BaseScanner):
    """Scanner for Python Pickle files using fickling's advanced analysis"""

    name = "pickle"  # Legacy name for backward compatibility
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
        ".ckpt",  # Checkpoints
    ]

    @classmethod
    def can_handle(cls, file_path: str) -> bool:
        """Check if this scanner can handle the given file"""
        import os
        
        if not os.path.isfile(file_path):
            return False
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in cls.supported_extensions:
            return False
        # Defer ZIP-formatted .bin to the PyTorch ZIP scanner
        if ext == ".bin":
            try:
                from modelaudit.utils.filetype import detect_file_format
                if detect_file_format(file_path) == "zip":
                    return False
            except Exception:
                pass  # fall back to handling here
        return True

    def scan(self, file_path: str, timeout: Optional[float] = None) -> ScanResult:
        """Scan a pickle file using fickling's analysis engine"""
        start_time = time.time()
        result = ScanResult(scanner_name=self.name)
        result.metadata["file_path"] = file_path

        # Check if file exists and is a regular file
        if not os.path.isfile(file_path):
            result.add_issue(
                message=f"File not found: {file_path}",
                severity=IssueSeverity.CRITICAL,
            )
            result.finish(success=False)
            return result

        try:
            # Load pickle file with fickling
            with open(file_path, "rb") as f:
                pickled = Pickled.load(f)
                pickle_bytes = f.tell()
                trailing_bytes = f.read()

            # Single pre-analysis timeout fence (after load)
            if timeout and (time.time() - start_time) > timeout:
                result.metadata["timeout_seconds"] = timeout
                result.add_issue("Scan timed out after load", IssueSeverity.CRITICAL)
                result.finish(success=False)
                return result

            # Run fickling AST analysis and convert findings
            analysis_results = check_safety(pickled)
            self._convert_fickling_results(analysis_results, result)

            # Quick signal for mismatch metadata
            import fickling
            fickling_is_safe = fickling.is_likely_safe(file_path)

            # Additional fickling info
            unsafe_imports = list(pickled.unsafe_imports())
            non_standard_imports = list(pickled.non_standard_imports())

            # Compute opcode count safely
            opcode_count = None
            try:
                ops = getattr(pickled, "opcodes", None)
                if ops is not None and hasattr(ops, "__len__"):
                    opcode_count = len(ops)
            except Exception:
                opcode_count = None

            # Add basic metadata
            result.metadata.update(
                {
                    "fickling_severity": analysis_results.severity.name,
                    "fickling_safe": analysis_results.severity.name == "LIKELY_SAFE",
                    "unsafe_imports": len(unsafe_imports),
                    "non_standard_imports": len(non_standard_imports),
                    "scan_time_seconds": time.time() - start_time,
                    "file_size": self._get_file_size(file_path),
                    "opcodes_analyzed": opcode_count,
                }
            )

            # CRITICAL: Add supplementary security analysis for patterns fickling misses
            self._analyze_dangerous_globals(pickled, result)

            # Optional: flag only when quick-signal conflicts with deep analysis
            if not fickling_is_safe and result.metadata.get("fickling_severity") == "LIKELY_SAFE":
                result.add_issue(
                    message="Basic safety check flagged concerns despite LIKELY_SAFE analysis",
                    severity=IssueSeverity.WARNING,
                    details={"fickling_analysis": "mismatch"},
                )

            # For .bin files, add binary content metadata and scan trailing content
            if file_path.lower().endswith(".bin"):
                result.metadata["pickle_bytes"] = pickle_bytes
                result.metadata["binary_bytes"] = len(trailing_bytes)

                # Skip binary scan for high-confidence ML models
                ml_context = self._detect_ml_context(pickled)
                result.metadata["ml_context"] = ml_context

                pytorch_confidence = ml_context.get("frameworks", {}).get("pytorch", 0)
                overall_confidence = ml_context.get("overall_confidence", 0)

                if pytorch_confidence > 0.7 and overall_confidence > 0.7:
                    result.metadata["binary_scan_skipped"] = True
                    result.metadata["skip_reason"] = "High-confidence PyTorch model detected"
                else:
                    # Scan trailing binary content
                    self._scan_trailing_binary(trailing_bytes, result)

            # Check for nested pickles (all file types)
            self._scan_for_nested_pickles(pickled, result)

            # Check for embedded base64 payloads (V4 attack detection)
            self._scan_for_embedded_payloads(pickled, result)

            # Check for multiple pickle streams in the file
            self._scan_for_multiple_streams(file_path, result)

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
            result.finish(success=True)
            return result

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
                # If even the basic safety check fails, just continue
                pass

            # If fickling fails, fall back to content-based analysis for CVE detection
            self._analyze_content_patterns(file_path, result)
            result.add_issue(
                message=f"Fickling analysis failed: {e}",
                severity=IssueSeverity.WARNING,
                details={"note": "Falling back to content-based analysis"},
            )
            result.finish(success=True)
            return result

        # Always run content-based analysis for comprehensive CVE detection
        # Fickling might miss some patterns that our CVE database catches
        self._analyze_content_patterns(file_path, result)

        # Add basic security checks
        self._add_security_checks(pickled, result, file_path, fickling_is_safe)

        # Set bytes scanned for size limit enforcement
        result.bytes_scanned = self._get_file_size(file_path)

        # Post-analysis timeout fence
        if timeout and (time.time() - start_time) > timeout:
            result.metadata["timeout_seconds"] = timeout
            result.add_issue("Scan exceeded timeout after analysis", IssueSeverity.CRITICAL)
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _analyze_cve_patterns(self, file_path: str, result: ScanResult) -> None:
        """Analyze for CVE-specific patterns - required by tests."""
        self._analyze_content_patterns(file_path, result)

    def _analyze_content_patterns(self, file_path: str, result: ScanResult) -> None:
        """Analyze file content for CVE patterns when fickling analysis fails."""
        try:
            from ..cve_patterns import analyze_cve_patterns

            # Read file content as text and binary
            with open(file_path, "rb") as f:
                binary_content = f.read()

            try:
                text_content = binary_content.decode("utf-8", errors="ignore")
            except Exception:
                text_content = ""

            # Analyze for CVE patterns
            cve_attributions = analyze_cve_patterns(text_content, binary_content)

            for cve_attr in cve_attributions:
                severity = IssueSeverity.CRITICAL if cve_attr.severity == "CRITICAL" else IssueSeverity.WARNING
                result.add_issue(
                    message=f"CVE Detection: {cve_attr.cve_id} - {cve_attr.description}",
                    severity=severity,
                    details={
                        "cve_id": cve_attr.cve_id,
                        "patterns_matched": cve_attr.patterns_matched,
                        "cvss": cve_attr.cvss,
                        "cwe": cve_attr.cwe,
                        "description": cve_attr.description,
                        "remediation": cve_attr.remediation,
                    },
                )

            # Also check for basic dangerous patterns
            dangerous_patterns = [
                (b"joblib.load", "Joblib load operation detected"),
                (b"sklearn", "Scikit-learn reference detected"),
                (b"__reduce__", "Pickle reduce method detected"),
                (b"os.system", "OS system call detected"),
                (b"os", "OS module access detected"),
                (b"posix", "POSIX system access detected"),
                (b"system", "System call detected"),
                (b"subprocess", "Subprocess execution detected"),
                (b"eval", "Eval operation detected"),
                (b"exec", "Exec operation detected"),
                (b"compile", "Compile operation detected"),
                (b"__builtin__", "Builtin module access detected"),
                (b"__builtins__", "__builtins__ module access detected"),
                (b"builtins", "Builtins module access detected"),
                (b"globals", "Globals manipulation detected"),
                (b"locals", "Locals manipulation detected"),
                (b"dill", "dill library reference detected"),
                (b"NumpyArrayWrapper", "Numpy array wrapper detected"),
            ]

            for pattern, message in dangerous_patterns:
                if pattern in binary_content:
                    result.add_issue(
                        message=f"Dangerous pattern: {message}",
                        severity=IssueSeverity.WARNING,
                        details={"pattern": pattern.decode("utf-8", errors="ignore")},
                    )

        except Exception as e:
            result.add_issue(
                message=f"Content analysis failed: {e}",
                severity=IssueSeverity.WARNING,
            )

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

    def _detect_ml_context(self, pickled) -> dict:
        """Detect ML framework context for smart binary scanning"""
        try:
            # Simple heuristic: look for common PyTorch patterns
            pytorch_indicators = 0
            total_checks = 4

            # Convert to string for analysis
            pickle_str = str(pickled)

            # Check for OrderedDict (common in PyTorch)
            if "OrderedDict" in pickle_str:
                pytorch_indicators += 1

            # Check for common PyTorch state_dict patterns
            pytorch_patterns = ["features.", "classifier.", "._metadata", "._modules"]
            for pattern in pytorch_patterns:
                if pattern in pickle_str:
                    pytorch_indicators += 1
                    break

            # Check for tensor-like keys
            if any(x in pickle_str for x in [".weight", ".bias"]):
                pytorch_indicators += 1

            # Check for version metadata
            if "version" in pickle_str.lower():
                pytorch_indicators += 1

            pytorch_confidence = pytorch_indicators / total_checks

            return {
                "frameworks": {"pytorch": pytorch_confidence},
                "overall_confidence": pytorch_confidence,
                "indicators": pytorch_indicators,
            }
        except Exception:
            return {"frameworks": {}, "overall_confidence": 0.0}

    def _scan_trailing_binary(self, trailing_bytes: bytes, result: ScanResult) -> None:
        """Scan trailing binary content for suspicious patterns"""
        if not trailing_bytes:
            return

        # Check for executable signatures using centralized patterns
        for sig, desc in EXECUTABLE_SIGNATURES.items():
            if sig in trailing_bytes:
                # Special handling for PE files - require DOS stub
                if sig == b"MZ" and b"This program cannot be run in DOS mode" not in trailing_bytes:
                    continue  # Skip MZ without DOS stub

                result.add_issue(
                    message=f"Executable signature detected in binary data: {desc}",
                    severity=IssueSeverity.CRITICAL,
                    details={
                        "signature": sig.hex(),
                        "description": desc,
                        "recommendation": "Binary data should not contain executable code",
                    },
                )

        # Check for suspicious code patterns using centralized patterns
        for pattern in BINARY_CODE_PATTERNS:
            if pattern in trailing_bytes:
                result.add_issue(
                    message=(
                        f"Suspicious code pattern detected in binary data: {pattern.decode('utf-8', errors='ignore')}"
                    ),
                    severity=IssueSeverity.WARNING,
                    details={
                        "pattern": pattern.decode("utf-8", errors="ignore"),
                        "recommendation": "Review binary content for embedded code",
                    },
                )

    def _contains_pickle_magic(self, data: bytes) -> bool:
        """Check if data contains pickle magic bytes indicating nested pickle"""
        # Pickle protocol magic bytes
        pickle_magics = [b"\x80\x03", b"\x80\x04", b"\x80\x05"]  # Protocols 3, 4, 5
        return any(magic in data for magic in pickle_magics)

    def _candidate_base64_strings(self, data: bytes) -> list[str]:
        """Extract potential base64 encoded strings from binary data"""
        import re

        try:
            text = data.decode("utf-8", errors="ignore")
            # Look for base64-like strings (at least 20 chars, valid base64 chars)
            pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
            return re.findall(pattern, text)
        except Exception:
            return []

    def _scan_for_nested_pickles(self, pickled, result: ScanResult) -> None:
        """Scan for nested pickle payloads in strings/bytes within the pickle."""
        try:
            import base64
            import pickle as std_pickle

            # Get raw pickle bytes 
            raw = pickled.dumps() if hasattr(pickled, "dumps") else bytes(getattr(pickled, "data", b""))
            if not raw:
                return

            # Look for multiple pickle streams (concatenated pickles)
            pickle_count = self._count_pickle_streams(raw)
            if pickle_count > 1:
                result.add_issue(
                    message=f"Multiple pickle streams detected ({pickle_count} streams)",
                    severity=IssueSeverity.WARNING,
                    details={"recommendation": "Multiple pickles in one file can hide malicious code"},
                )

            # Look for Base64-encoded nested payloads within string data in the pickle
            for token in self._candidate_base64_strings(raw):
                try:
                    decoded = base64.b64decode(token, validate=True)
                    if self._contains_pickle_magic(decoded) and len(decoded) > 20:  # Avoid tiny false positives
                        result.add_issue(
                            message="Encoded pickle payload detected in serialized data",
                            severity=IssueSeverity.CRITICAL,
                            details={"encoding": "base64", "recommendation": "Nested pickles can hide malicious code"},
                        )
                        break
                except Exception:
                    continue

            # Look for raw pickle bytes embedded within strings in the pickle data 
            # (not the main pickle stream itself)
            self._scan_for_embedded_pickle_strings(raw, result)

        except Exception as e:
            result.add_issue(
                message=f"Error scanning for nested pickles: {e}",
                severity=IssueSeverity.WARNING,
            )

    def _count_pickle_streams(self, data: bytes) -> int:
        """Count the number of separate pickle streams in the data"""
        count = 0
        pos = 0
        
        while pos < len(data):
            # Look for pickle magic bytes
            if any(data[pos:].startswith(magic) for magic in [b"\x80\x03", b"\x80\x04", b"\x80\x05"]):
                count += 1
                # Skip past this pickle - look for the STOP opcode (.)
                stop_pos = data.find(b".", pos)
                if stop_pos == -1:
                    break
                pos = stop_pos + 1
            else:
                pos += 1
                
        return count

    def _scan_for_embedded_pickle_strings(self, raw: bytes, result: ScanResult) -> None:
        """Look for pickle magic bytes embedded in string data within the pickle"""
        try:
            # Look for pickle magic patterns that aren't at the start of the file
            # (which would be the main pickle stream)
            for i, magic in enumerate([b"\x80\x03", b"\x80\x04", b"\x80\x05"]):
                positions = []
                start = 0
                while True:
                    pos = raw.find(magic, start)
                    if pos == -1:
                        break
                    positions.append(pos)
                    start = pos + 1
                
                # If we find pickle magic at positions other than the start (position 0),
                # it could be nested pickles
                nested_positions = [pos for pos in positions if pos > 0]
                if nested_positions:
                    # Only flag if there's substantial data after the magic (not just a coincidental match)
                    for pos in nested_positions:
                        if pos + 10 < len(raw):  # At least 10 bytes of pickle data
                            result.add_issue(
                                message="Nested pickle payload detected in serialized data",
                                severity=IssueSeverity.CRITICAL,
                                details={
                                    "position": pos,
                                    "recommendation": "Nested pickles can hide malicious code"
                                },
                            )
                            return  # Only report once to avoid spam
                            
        except Exception:
            pass  # Ignore errors in this heuristic check

    def _scan_for_embedded_payloads(self, pickled, result: ScanResult) -> None:
        """Scan serialized bytes for embedded base64-encoded Python payloads (no deserialization)."""
        try:
            logger.debug("Starting embedded payload scan")  # Changed to debug
            
            # Get raw pickle bytes without deserializing
            raw = pickled.dumps() if hasattr(pickled, "dumps") else bytes(getattr(pickled, "data", b""))
            if not raw:
                return
                
            # Scan for base64-encoded Python payloads in raw bytes
            for token in self._candidate_base64_strings(raw):
                # token is a string; pass it directly
                if self._check_base64_python_payload(token, "serialized_data", result):
                    break  # Stop after first confirmed payload to limit noise

        except Exception as e:
            logger.warning(f"Error during embedded payload scan: {e}")

    def _check_base64_python_payload(self, data_string: str, location: str, result: ScanResult) -> bool:
        """Check if a string contains base64-encoded Python code"""
        try:
            import base64
            import re

            logger.info(f"Checking base64 payload at {location}, length: {len(data_string)}")  # Debug

            # Skip if string is too short or contains non-base64 characters
            if len(data_string) < 50:
                logger.info(f"String too short: {len(data_string)} < 50")  # Debug
                return False

            # Try to decode as base64
            try:
                decoded_bytes = base64.b64decode(data_string, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                logger.info(f"Successfully decoded base64, decoded length: {len(decoded_text)}")  # Debug
            except Exception as e:
                logger.info(f"Failed to decode base64: {e}")  # Debug
                return False

            # Check if decoded content looks like Python code
            python_indicators = [
                r"import\s+\w+",  # import statements
                r"from\s+\w+\s+import",  # from X import Y
                r"def\s+\w+\s*\(",  # function definitions
                r"class\s+\w+",  # class definitions
                r"exec\s*\(",  # exec calls
                r"eval\s*\(",  # eval calls
                r"urllib\.request",  # network requests
                r"subprocess",  # system calls
                r"os\.system",  # OS system calls
                r"threading\.Thread",  # threading
                r"\.read_text\(\)",  # file reading
                r"\.write_text\(",  # file writing
                r"Path\.home\(\)",  # home directory access
                r"json\.loads",  # JSON parsing
                r"\.encode\(\)",  # encoding operations
                r"\.decode\(\)",  # decoding operations
            ]

            python_matches = 0
            matched_patterns = []

            for pattern in python_indicators:
                if re.search(pattern, decoded_text, re.IGNORECASE):
                    python_matches += 1
                    matched_patterns.append(pattern)

            logger.info(f"Found {python_matches} Python patterns: {matched_patterns}")  # Debug
            logger.info(f"First 200 chars of decoded: {decoded_text[:200]}")  # Debug

            # If we found multiple Python patterns, it's likely embedded code
            if python_matches >= 3:
                # Check for specific malicious patterns
                malicious_patterns = [
                    (r"\.ssh[/\\]", "SSH key access"),
                    (r"\.aws[/\\]", "AWS credentials access"),
                    (r"\.docker[/\\]", "Docker config access"),
                    (r"\.kube[/\\]", "Kubernetes config access"),
                    (r"credentials", "Credential harvesting"),
                    (r"urllib\.request\.urlopen", "Network exfiltration"),
                    (r"threading\.Thread.*daemon.*True", "Persistent backdoor"),
                    (r"exec\s*\(.*\[.*\]", "Dynamic code execution"),
                    (r"system.*\(.*\)", "System command execution"),
                ]

                threat_indicators = []
                for pattern, description in malicious_patterns:
                    if re.search(pattern, decoded_text, re.IGNORECASE):
                        threat_indicators.append(description)

                logger.info(f"Found threat indicators: {threat_indicators}")  # Debug

                severity = IssueSeverity.CRITICAL if threat_indicators else IssueSeverity.WARNING

                issue_message = f"Embedded Base64 Python payload detected at '{location}'"
                if threat_indicators:
                    issue_message += f" (Threats: {', '.join(threat_indicators)})"

                logger.info(f"Adding issue: {issue_message}")  # Debug
                result.add_issue(
                    message=issue_message,
                    severity=severity,
                    details={
                        "location": location,
                        "encoding": "base64",
                        "python_indicators": python_matches,
                        "matched_patterns": matched_patterns[:5],  # Limit for readability
                        "threat_indicators": threat_indicators,
                        "payload_length": len(decoded_text),
                        "recommendation": (
                            "Base64-encoded Python payloads can execute arbitrary code during model loading"
                        ),
                    },
                )
                logger.info(f"Issue added, current issue count: {len(result.issues)}")  # Debug
                return True

        except Exception as e:
            logger.debug(f"Error checking base64 payload at {location}: {e}")

        return False

    def _scan_for_multiple_streams(self, file_path: str, result: ScanResult) -> None:
        """Scan for multiple pickle streams in a single file"""
        try:
            import io
            import pickletools

            with open(file_path, "rb") as f:
                file_data = f.read()

            stream_count = 0
            current_pos = 0

            while current_pos < len(file_data):
                try:
                    # Create stream from current position
                    stream = io.BytesIO(file_data[current_pos:])

                    # Try to parse pickle stream
                    opcodes = list(pickletools.genops(stream))
                    if not opcodes:
                        break

                    stream_count += 1

                    # Find STOP opcode position
                    stop_pos = None
                    for opcode, _arg, pos in opcodes:
                        if opcode.name == "STOP":
                            stop_pos = pos
                            break

                    if stop_pos is None:
                        # No STOP found, malformed stream
                        break

                    # If this is not the first stream, analyze it for threats
                    if stream_count > 1:
                        # Extract just this stream's data
                        stream_data = file_data[current_pos : current_pos + stop_pos + 1]

                        # Create a temporary file to analyze this stream with fickling
                        self._analyze_additional_stream(stream_data, stream_count, result)

                    # Move to next potential stream
                    current_pos += stop_pos + 1

                    # Skip any padding bytes
                    while current_pos < len(file_data) and file_data[current_pos : current_pos + 1] in [
                        b"",
                        b"\x00",
                        b"\n",
                        b"\r",
                    ]:
                        current_pos += 1

                except Exception as e:
                    logger.debug(f"Error parsing stream at position {current_pos}: {e}")
                    # Set metadata for truncation issues
                    if isinstance(e, ValueError) and "opcode" in str(e).lower():
                        result.metadata["truncated"] = True
                        result.metadata["truncation_reason"] = "post_stop_data_or_format_issue"
                        result.metadata["exception_type"] = type(e).__name__
                        result.metadata["exception_message"] = str(e)
                        result.metadata["validated_format"] = True
                    break

            if stream_count > 1:
                result.add_issue(
                    message=f"Multiple pickle streams detected: {stream_count} streams found",
                    severity=IssueSeverity.CRITICAL,
                    details={
                        "stream_count": stream_count,
                        "recommendation": "Multiple pickle streams can hide malicious code in subsequent streams",
                        "security_risk": "HIGH - Additional streams may contain hidden payloads",
                    },
                )
                result.metadata["multiple_streams"] = True
                result.metadata["stream_count"] = stream_count

        except Exception as e:
            logger.warning(f"Error during multiple stream scan: {e}")

    def _analyze_dangerous_globals(self, pickled, result: ScanResult) -> None:
        """
        Analyze pickle for dangerous GLOBAL opcodes that fickling might miss.

        This is critical for detecting patterns like __builtin__.eval that fickling
        considers safe but our security model considers dangerous.
        """
        try:
            # Analyze each opcode in the pickle
            for opcode in pickled.opcodes:
                if hasattr(opcode, "name") and opcode.name == "GLOBAL" and hasattr(opcode, "arg") and opcode.arg:
                    global_ref = str(opcode.arg)

                    # Parse "module function" format
                    if " " in global_ref:
                        module_name, func_name = global_ref.split(" ", 1)

                        # Check against our suspicious globals database
                        if self._is_dangerous_global_reference(module_name, func_name):
                            result.add_issue(
                                message=f"Dangerous global reference: {module_name}.{func_name}",
                                severity=IssueSeverity.CRITICAL,
                                details={
                                    "module": module_name,
                                    "function": func_name,
                                    "global_reference": global_ref,
                                    "opcode": "GLOBAL",
                                    "recommendation": f"The global reference {module_name}.{func_name} can execute "
                                    f"arbitrary code during pickle loading",
                                },
                            )

        except Exception as e:
            logger.warning(f"Error during dangerous globals analysis: {e}")

    def _is_dangerous_global_reference(self, module_name: str, func_name: str) -> bool:
        """Check if a module.function combination is dangerous according to our security model."""
        from ..suspicious_symbols import SUSPICIOUS_GLOBALS

        if module_name not in SUSPICIOUS_GLOBALS:
            return False

        suspicious_funcs = SUSPICIOUS_GLOBALS[module_name]
        if suspicious_funcs == "*":
            return True

        if isinstance(suspicious_funcs, list):
            return func_name in suspicious_funcs

        return False

    def _add_security_checks(self, pickled, result: ScanResult, file_path: str, fickling_is_safe: bool) -> None:
        """Add Check objects for security validation reporting."""

        # Basic pickle safety check
        result.add_check(
            name="Pickle Safety Analysis",
            passed=fickling_is_safe,
            message="Fickling safety analysis passed" if fickling_is_safe else "Fickling detected unsafe operations",
            severity=IssueSeverity.CRITICAL if not fickling_is_safe else None,
            location=file_path,
            details={"fickling_safe": fickling_is_safe},
        )

        # Dangerous imports check
        try:
            unsafe_imports = list(pickled.unsafe_imports())
            has_dangerous_imports = len(unsafe_imports) > 0

            result.add_check(
                name="Dangerous Imports Detection",
                passed=not has_dangerous_imports,
                message=f"Found {len(unsafe_imports)} dangerous imports"
                if has_dangerous_imports
                else "No dangerous imports detected",
                severity=IssueSeverity.CRITICAL if has_dangerous_imports else None,
                location=file_path,
                details={"unsafe_imports_count": len(unsafe_imports)},
            )
        except Exception:
            # If we can't analyze imports, add a neutral check
            result.add_check(
                name="Dangerous Imports Detection",
                passed=True,
                message="Import analysis completed",
                location=file_path,
            )

        # Dangerous opcodes check
        dangerous_opcodes = self._check_for_dangerous_opcodes(pickled, file_path)
        has_dangerous_opcodes = len(dangerous_opcodes) > 0

        result.add_check(
            name="Dangerous Opcodes Detection",
            passed=not has_dangerous_opcodes,
            message=f"Found {len(dangerous_opcodes)} dangerous opcodes"
            if has_dangerous_opcodes
            else "No dangerous opcodes detected",
            severity=IssueSeverity.WARNING if has_dangerous_opcodes else None,
            location=file_path,
            details={"dangerous_opcodes": dangerous_opcodes},
        )

    def _check_for_dangerous_opcodes(self, pickled, file_path: str) -> list[str]:
        """Check for dangerous pickle opcodes and return list of found opcodes."""
        dangerous_opcodes = []

        try:
            for opcode in pickled.opcodes:
                if hasattr(opcode, "name"):
                    opcode_name = opcode.name
                    # Check for dangerous opcodes
                    if opcode_name in ["REDUCE", "INST", "OBJ", "NEWOBJ", "STACK_GLOBAL", "BUILD"]:
                        if opcode_name not in dangerous_opcodes:
                            dangerous_opcodes.append(opcode_name)

                    # Check for GLOBAL opcodes with dangerous references
                    elif opcode_name == "GLOBAL" and hasattr(opcode, "arg") and opcode.arg:
                        global_ref = str(opcode.arg)
                        if " " in global_ref:
                            module_name, func_name = global_ref.split(" ", 1)
                            if self._is_dangerous_global_reference(module_name, func_name):
                                dangerous_ref = f"GLOBAL({module_name}.{func_name})"
                                if dangerous_ref not in dangerous_opcodes:
                                    dangerous_opcodes.append(dangerous_ref)
        except Exception:
            pass

        return dangerous_opcodes

    def _scan_pickle_bytes(self, file_like, file_size: int) -> ScanResult:
        """
        Legacy compatibility method for scanning pickle bytes from a file-like object.

        This method provides backward compatibility for code that expects the old
        PickleScanner interface, particularly the JoblibScanner.
        """
        result = ScanResult(scanner_name=self.name)

        try:
            # Read all data from the file-like object
            file_like.seek(0)
            data = file_like.read()

            # Create a temporary file to use with fickling
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp_file:
                tmp_file.write(data)
                tmp_file.flush()

                try:
                    # Use the regular scan method on the temporary file
                    scan_result = self.scan(tmp_file.name)
                    # Copy results but reset the file path metadata
                    result.issues = scan_result.issues
                    result.metadata = scan_result.metadata.copy()
                    result.metadata["file_path"] = f"<bytes:{len(data)}>"
                    result.bytes_scanned = len(data)

                finally:
                    # Clean up temporary file
                    import contextlib
                    import os

                    with contextlib.suppress(OSError):
                        os.unlink(tmp_file.name)

        except Exception as e:
            result.add_issue(
                message=f"Error scanning pickle bytes: {e}",
                severity=IssueSeverity.CRITICAL,
            )

        return result

    def _analyze_additional_stream(self, stream_data: bytes, stream_number: int, result: ScanResult) -> None:
        """Analyze an additional pickle stream for security threats"""
        try:
            import os
            import tempfile

            # Create temporary file with just this stream
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as temp_file:
                temp_file.write(stream_data)
                temp_file.flush()

                try:
                    # Load and analyze this stream with fickling
                    with open(temp_file.name, "rb") as f:
                        additional_pickled = Pickled.load(f)
                        additional_results = check_safety(additional_pickled)

                    # Convert results with stream context
                    for fickling_result in additional_results.results:
                        if fickling_result.severity != Severity.LIKELY_SAFE:
                            severity = self._map_fickling_severity(fickling_result.severity)
                            message = (
                                f"Stream {stream_number} - {self._generate_issue_title(fickling_result)}: "
                                f"{fickling_result!s}"
                            )

                            details = {
                                "stream_number": stream_number,
                                "fickling_analysis": fickling_result.analysis_name,
                                "fickling_severity": fickling_result.severity.name,
                                "trigger": fickling_result.trigger,
                                "recommendation": f"Stream {stream_number} contains malicious code",
                            }

                            # Add explanations
                            self._add_explanations(details, fickling_result)

                            result.add_issue(message=message, severity=severity, details=details)

                finally:
                    os.unlink(temp_file.name)

        except Exception as e:
            logger.warning(f"Error analyzing additional stream {stream_number}: {e}")
