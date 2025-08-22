"""Pydantic models that match the exact current JSON output format.

These models provide type safety and validation while producing the exact same
JSON structure that ModelAudit currently outputs for backward compatibility.
"""

import time
from typing import Any, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class AssetModel(BaseModel):
    """Model for scanned assets"""

    path: str = Field(..., description="Path to the asset")
    type: str = Field(..., description="Type of asset (e.g., 'pickle')")
    size: Optional[int] = Field(None, description="Size of the asset in bytes")
    tensors: Optional[list[str]] = Field(None, description="List of tensor names (for safetensors)")
    keys: Optional[list[str]] = Field(None, description="List of keys (for JSON manifests)")
    contents: Optional[list[dict[str, Any]]] = Field(None, description="Contents list (for ZIP files)")

    # Dictionary-like access for backward compatibility
    def get(self, key: str, default: Any = None) -> Any:
        """Support dict-style get() method for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        return default

    def __getitem__(self, key: str) -> Any:
        """Support dict-style access for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"'{key}' not found in AssetModel")


class CheckModel(BaseModel):
    """Model for security checks matching current format"""

    model_config = ConfigDict(use_enum_values=True)

    name: str = Field(..., description="Name of the security check")
    status: str = Field(..., description="Check status (passed/failed/skipped)")
    message: str = Field(..., description="Check description or result message")
    location: Optional[str] = Field(None, description="File location where check was performed")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional check details")
    timestamp: float = Field(..., description="Unix timestamp when check was performed")
    severity: Optional[str] = Field(None, description="Severity for failed checks")
    why: Optional[str] = Field(None, description="Explanation for failed checks")

    # Dictionary-like access for backward compatibility
    def get(self, key: str, default: Any = None) -> Any:
        """Support dict-style get() method for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        return default

    def __getitem__(self, key: str) -> Any:
        """Support dict-style access for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"'{key}' not found in CheckModel")


class IssueModel(BaseModel):
    """Model for security issues matching current format"""

    model_config = ConfigDict(use_enum_values=True)

    message: str = Field(..., description="Issue description")
    severity: str = Field(..., description="Issue severity level")
    location: Optional[str] = Field(None, description="File location or line number")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional issue details")
    timestamp: float = Field(..., description="Unix timestamp when issue was detected")
    why: Optional[str] = Field(None, description="Explanation of why this is a security concern")
    type: Optional[str] = Field(None, description="Type of issue (e.g., 'license_warning')")

    # Dictionary-like access for backward compatibility
    def get(self, key: str, default: Any = None) -> Any:
        """Support dict-style get() method for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        return default

    def __getitem__(self, key: str) -> Any:
        """Support dict-style access for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"'{key}' not found in IssueModel")


class MLFrameworkInfo(BaseModel):
    """Model for individual ML framework detection info"""

    model_config = ConfigDict(validate_assignment=True)

    name: str = Field(..., description="Framework name (e.g., 'pytorch', 'tensorflow')")
    version: Optional[str] = Field(None, description="Detected version if available")
    confidence: float = Field(0.0, description="Confidence in detection (0.0 to 1.0)")
    indicators: list[str] = Field(default_factory=list, description="Patterns that indicated this framework")
    file_patterns: list[str] = Field(default_factory=list, description="File patterns that matched")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v


class WeightAnalysisModel(BaseModel):
    """Model for weight pattern analysis results"""

    model_config = ConfigDict(validate_assignment=True)

    appears_to_be_weights: bool = Field(False, description="Whether data appears to be ML weights")
    weight_confidence: float = Field(0.0, description="Confidence in weight detection")
    pattern_density: float = Field(0.0, description="Density of detected patterns")
    float_ratio: float = Field(0.0, description="Ratio of floating-point data")
    statistical_expectation: float = Field(0.0, description="Statistical expectation for patterns")
    file_size_factor: float = Field(0.0, description="File size influence factor")

    @field_validator(
        "weight_confidence", "pattern_density", "float_ratio",
        "statistical_expectation", "file_size_factor"
    )
    @classmethod
    def validate_ratios(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("ratio values must be between 0.0 and 1.0")
        return v


class MLContextModel(BaseModel):
    """Enhanced model for ML context metadata with comprehensive validation"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow"  # Allow additional framework-specific data
    )

    # Framework detection
    frameworks: dict[str, MLFrameworkInfo] = Field(
        default_factory=dict, description="Detected ML frameworks with details"
    )
    overall_confidence: float = Field(0.0, description="Overall ML content confidence score")
    is_ml_content: bool = Field(False, description="Whether content is ML-related")
    detected_patterns: list[str] = Field(default_factory=list, description="Detected ML patterns")

    # Weight analysis
    weight_analysis: Optional[WeightAnalysisModel] = Field(None, description="Analysis of potential weight data")

    # Model architecture hints
    model_type: Optional[str] = Field(None, description="Detected model type (e.g., 'transformer', 'cnn', 'rnn')")
    layer_count_estimate: Optional[int] = Field(None, description="Estimated number of layers")
    parameter_count_estimate: Optional[int] = Field(None, description="Estimated parameter count")

    # Training metadata
    training_framework: Optional[str] = Field(None, description="Framework likely used for training")
    precision_type: Optional[str] = Field(None, description="Detected precision (fp32, fp16, int8, etc.)")
    optimization_hints: list[str] = Field(default_factory=list, description="Detected optimization techniques")

    @field_validator("overall_confidence")
    @classmethod
    def validate_overall_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("overall_confidence must be between 0.0 and 1.0")
        return v

    @field_validator("layer_count_estimate", "parameter_count_estimate")
    @classmethod
    def validate_positive_counts(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 0:
            raise ValueError("count estimates must be non-negative")
        return v

    def add_framework(
        self,
        name: str,
        confidence: float,
        version: Optional[str] = None,
        indicators: Optional[list[str]] = None,
        file_patterns: Optional[list[str]] = None
    ) -> None:
        """Add framework detection with validation"""
        framework_info = MLFrameworkInfo(
            name=name,
            version=version,
            confidence=confidence,
            indicators=indicators or [],
            file_patterns=file_patterns or []
        )
        self.frameworks[name] = framework_info

        # Update overall confidence
        if self.frameworks:
            self.overall_confidence = max(fw.confidence for fw in self.frameworks.values())
            self.is_ml_content = self.overall_confidence > 0.5

    def set_weight_analysis(self, analysis_data: dict[str, Any]) -> None:
        """Set weight analysis from dictionary with validation"""
        self.weight_analysis = WeightAnalysisModel(**analysis_data)


class LicenseInfoModel(BaseModel):
    """Model for structured license information"""

    model_config = ConfigDict(validate_assignment=True)

    spdx_id: Optional[str] = Field(None, description="SPDX license identifier")
    name: Optional[str] = Field(None, description="License name")
    url: Optional[HttpUrl] = Field(None, description="License URL")
    text: Optional[str] = Field(None, description="License text content")
    confidence: float = Field(0.0, description="Confidence in license detection")
    source: Optional[str] = Field(None, description="Source of license detection (file, header, etc.)")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v


class CopyrightNoticeModel(BaseModel):
    """Model for copyright notice information"""

    model_config = ConfigDict(validate_assignment=True)

    holder: str = Field(..., description="Copyright holder name")
    years: Optional[str] = Field(None, description="Copyright years (e.g., '2020-2023')")
    notice_text: Optional[str] = Field(None, description="Full copyright notice text")
    confidence: float = Field(0.0, description="Confidence in copyright detection")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v


class FileHashesModel(BaseModel):
    """Model for file hash information with validation"""

    model_config = ConfigDict(validate_assignment=True)

    md5: Optional[str] = Field(None, description="MD5 hash", pattern=r"^[a-fA-F0-9]{32}$")
    sha1: Optional[str] = Field(None, description="SHA1 hash", pattern=r"^[a-fA-F0-9]{40}$")
    sha256: Optional[str] = Field(None, description="SHA256 hash", pattern=r"^[a-fA-F0-9]{64}$")
    sha512: Optional[str] = Field(None, description="SHA512 hash", pattern=r"^[a-fA-F0-9]{128}$")

    def has_any_hash(self) -> bool:
        """Check if any hash is present"""
        return any([self.md5, self.sha1, self.sha256, self.sha512])

    def get_strongest_hash(self) -> Optional[tuple[str, str]]:
        """Get the strongest available hash as (algorithm, hash) tuple"""
        if self.sha512:
            return ("sha512", self.sha512)
        elif self.sha256:
            return ("sha256", self.sha256)
        elif self.sha1:
            return ("sha1", self.sha1)
        elif self.md5:
            return ("md5", self.md5)
        return None


class FileMetadataModel(BaseModel):
    """Enhanced model for individual file metadata with structured validation"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow"  # Allow additional metadata fields
    )

    # Basic file information
    file_size: Optional[int] = Field(None, description="File size in bytes", ge=0)
    file_hashes: Optional[FileHashesModel] = Field(None, description="File hashes with validation")

    # Pickle-specific metadata
    max_stack_depth: Optional[int] = Field(None, description="Maximum stack depth for pickle files", ge=0)
    opcode_count: Optional[int] = Field(None, description="Number of opcodes for pickle files", ge=0)
    suspicious_count: Optional[int] = Field(None, description="Count of suspicious patterns", ge=0)

    # ML context analysis
    ml_context: Optional[MLContextModel] = Field(None, description="ML context information")

    # License and copyright information
    license: Optional[str] = Field(None, description="Legacy license field for backward compatibility")
    license_info: list[LicenseInfoModel] = Field(default_factory=list, description="Structured license information")
    copyright_notices: list[CopyrightNoticeModel] = Field(
        default_factory=list, description="Structured copyright notices"
    )
    license_files_nearby: list[str] = Field(default_factory=list, description="License files found nearby")

    # File classification
    is_dataset: Optional[bool] = Field(None, description="Whether file appears to be a dataset")
    is_model: Optional[bool] = Field(None, description="Whether file appears to be a model")

    # Security metadata
    risk_score: float = Field(default=0.0, description="Calculated risk score (0.0 to 1.0)")
    scan_timestamp: float = Field(default_factory=time.time, description="When this metadata was collected")

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("risk_score must be between 0.0 and 1.0")
        return v

    def add_license_info(
        self,
        spdx_id: Optional[str] = None,
        name: Optional[str] = None,
        url: Optional[str] = None,
        text: Optional[str] = None,
        confidence: float = 0.0,
        source: Optional[str] = None
    ) -> None:
        """Add license information with validation"""
        from pydantic import HttpUrl
        parsed_url = None
        if url:
            try:
                parsed_url = HttpUrl(url)
            except ValueError:
                parsed_url = None

        license_info = LicenseInfoModel(
            spdx_id=spdx_id,
            name=name,
            url=parsed_url,
            text=text,
            confidence=confidence,
            source=source
        )
        self.license_info.append(license_info)

    def add_copyright_notice(
        self,
        holder: str,
        years: Optional[str] = None,
        notice_text: Optional[str] = None,
        confidence: float = 0.0
    ) -> None:
        """Add copyright notice with validation"""
        copyright_notice = CopyrightNoticeModel(
            holder=holder,
            years=years,
            notice_text=notice_text,
            confidence=confidence
        )
        self.copyright_notices.append(copyright_notice)

    def set_file_hashes(self, hashes: dict[str, str]) -> None:
        """Set file hashes with validation"""
        self.file_hashes = FileHashesModel(**hashes)

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on metadata"""
        score = 0.0

        # ML context risk
        if self.ml_context and self.ml_context.overall_confidence > 0.7:
            score += 0.1  # ML content gets slight risk increase

        # Suspicious patterns
        if self.suspicious_count and self.suspicious_count > 0:
            score += min(self.suspicious_count * 0.1, 0.5)

        # Pickle complexity
        if self.max_stack_depth and self.max_stack_depth > 10:
            score += min((self.max_stack_depth - 10) * 0.02, 0.3)

        # License risk (missing or restrictive)
        if not self.license_info and not self.license:
            score += 0.1

        self.risk_score = min(score, 1.0)
        return self.risk_score

    # Dictionary-like access for backward compatibility
    def get(self, key: str, default: Any = None) -> Any:
        """Support dict-style get() method for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        return default

    def __getitem__(self, key: str) -> Any:
        """Support dict-style access for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"'{key}' not found in FileMetadataModel")


class ModelAuditResultModel(BaseModel):
    """Pydantic model matching the exact current ModelAudit JSON output format"""

    model_config = ConfigDict(
        use_enum_values=True,
        extra="allow",
        validate_assignment=False,  # Disable validation on assignment for performance
        frozen=False,  # Allow field mutations for efficient aggregation
    )

    # Core scan results
    bytes_scanned: int = Field(..., description="Total bytes scanned")
    issues: list[IssueModel] = Field(default_factory=list, description="List of security issues found")
    checks: list[CheckModel] = Field(default_factory=list, description="List of all checks performed")
    files_scanned: int = Field(..., description="Number of files scanned")
    assets: list[AssetModel] = Field(default_factory=list, description="List of scanned assets")
    has_errors: bool = Field(..., description="Whether any critical issues were found")
    scanner_names: list[str] = Field(default_factory=list, description="Names of scanners used")
    file_metadata: dict[str, FileMetadataModel] = Field(default_factory=dict, description="Metadata for each file")

    # Timing and performance
    start_time: float = Field(..., description="Scan start timestamp")
    duration: float = Field(..., description="Scan duration in seconds")

    # Check statistics
    total_checks: int = Field(..., description="Total number of checks performed")
    passed_checks: int = Field(..., description="Number of checks that passed")
    failed_checks: int = Field(..., description="Number of checks that failed")

    # Legacy compatibility
    success: bool = Field(default=True, description="Whether the scan completed successfully")

    def aggregate_scan_result(self, results: Union[dict[str, Any], "ModelAuditResultModel"]) -> None:
        """Efficiently aggregate scan results into this model.

        This method updates the current model in-place for performance.
        Accepts either a dict or another ModelAuditResultModel.
        """
        # Handle ModelAuditResultModel input by converting to dict
        results_dict = results.model_dump() if isinstance(results, ModelAuditResultModel) else results

        # Update scalar fields
        self.bytes_scanned += results_dict.get("bytes_scanned", 0)
        self.files_scanned += results_dict.get("files_scanned", 0)
        if results_dict.get("has_errors", False):
            self.has_errors = True

        # Update success status - only set to False for operational errors, not security findings
        # Only set success to False if there are actual operational errors (has_errors=True)
        # Security findings should not affect the success status
        if results_dict.get("success", True) is False and results_dict.get("has_errors", False):
            self.success = False

        # Convert and extend issues
        new_issues = convert_issues_to_models(results_dict.get("issues", []))
        self.issues.extend(new_issues)

        # Convert and extend checks
        new_checks = convert_checks_to_models(results_dict.get("checks", []))
        self.checks.extend(new_checks)

        # Convert and extend assets
        new_assets = convert_assets_to_models(results_dict.get("assets", []))
        self.assets.extend(new_assets)

        # Merge file metadata
        for path, metadata in results_dict.get("file_metadata", {}).items():
            if isinstance(metadata, dict):
                # Convert ml_context if present
                ml_context = metadata.get("ml_context")
                if ml_context and isinstance(ml_context, dict):
                    metadata = metadata.copy()
                    metadata["ml_context"] = MLContextModel(**ml_context)
                self.file_metadata[path] = FileMetadataModel(**metadata)
            else:
                self.file_metadata[path] = metadata

        # Track scanner names (avoid duplicates)
        for scanner in results_dict.get("scanners", []):
            if scanner and scanner not in self.scanner_names and scanner != "unknown":
                self.scanner_names.append(scanner)

    def aggregate_scan_result_direct(self, scan_result: Any) -> None:
        """Directly aggregate a ScanResult object into this model without dict conversion.

        This is more efficient than converting to dict first and provides better type safety.
        """
        # Import here to avoid circular import
        from ..scanners.base import ScanResult

        if not isinstance(scan_result, ScanResult):
            raise TypeError(f"Expected ScanResult, got {type(scan_result)}")

        # Update scalar fields directly from ScanResult properties
        self.bytes_scanned += scan_result.bytes_scanned
        self.files_scanned += 1  # Each ScanResult represents one file scan

        if scan_result.has_errors:
            self.has_errors = True

        # Update success status - only set to False for operational errors
        if not scan_result.success:
            self.success = False

        # Convert and extend issues directly from ScanResult objects
        for issue in scan_result.issues:
            self.issues.append(
                IssueModel(
                    message=issue.message,
                    severity=issue.severity.value,
                    location=issue.location,
                    details=issue.details,
                    timestamp=issue.timestamp,
                    why=issue.why,
                    type=getattr(issue, "type", None),  # Include type if available
                )
            )

        # Convert and extend checks directly from ScanResult objects
        for check in scan_result.checks:
            self.checks.append(
                CheckModel(
                    name=check.name,
                    status=check.status.value,
                    message=check.message,
                    location=check.location,
                    details=check.details,
                    timestamp=check.timestamp,
                    severity=check.severity.value if check.severity else None,
                    why=check.why,
                )
            )

        # Track scanner names
        if (
            scan_result.scanner_name
            and scan_result.scanner_name not in self.scanner_names
            and scan_result.scanner_name != "unknown"
        ):
            self.scanner_names.append(scan_result.scanner_name)

    def finalize_statistics(self) -> None:
        """Calculate final statistics after all scan results are aggregated."""
        self.duration = time.time() - self.start_time
        self._finalize_checks()

    # Dictionary-like access for backward compatibility
    def __getitem__(self, key: str) -> Any:
        """Support dict-style access for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"'{key}' not found in ModelAuditResultModel")

    def get(self, key: str, default: Any = None) -> Any:
        """Support dict-style get() method for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        return default

    def __contains__(self, key: str) -> bool:
        """Support 'in' operator for backward compatibility."""
        return hasattr(self, key)

    def _finalize_checks(self) -> None:
        """Calculate check statistics."""
        self.total_checks = len(self.checks)
        self.passed_checks = sum(1 for c in self.checks if c.status == "passed")
        self.failed_checks = sum(1 for c in self.checks if c.status == "failed")

    def deduplicate_issues(self) -> None:
        """Remove duplicate issues based on message, severity, and location."""
        seen_issues = set()
        deduplicated_issues = []
        for issue in self.issues:
            # Include location in the deduplication key to avoid hiding issues in different files
            issue_key = (issue.message, issue.severity, issue.location or "")
            if issue_key not in seen_issues:
                seen_issues.add(issue_key)
                deduplicated_issues.append(issue)
        self.issues = deduplicated_issues


def create_audit_result_model(aggregated_results: dict[str, Any]) -> ModelAuditResultModel:
    """Create a ModelAuditResultModel from aggregated scan results.

    This function converts the internal aggregated_results dict to a validated
    Pydantic model that matches the exact current JSON output format.
    """
    # Convert issues to IssueModel instances
    issues = []
    for issue in aggregated_results.get("issues", []):
        if isinstance(issue, dict):
            issues.append(IssueModel(**issue))
        elif hasattr(issue, "to_dict"):
            issues.append(IssueModel(**issue.to_dict()))

    # Convert checks to CheckModel instances
    checks = []
    for check in aggregated_results.get("checks", []):
        if isinstance(check, dict):
            checks.append(CheckModel(**check))
        elif hasattr(check, "to_dict"):
            checks.append(CheckModel(**check.to_dict()))

    # Convert assets to AssetModel instances
    assets = []
    for asset in aggregated_results.get("assets", []):
        if isinstance(asset, dict):
            assets.append(AssetModel(**asset))

    # Convert file_metadata to FileMetadataModel instances
    file_metadata = {}
    for path, metadata in aggregated_results.get("file_metadata", {}).items():
        if isinstance(metadata, dict):
            # Convert ml_context if present
            ml_context = metadata.get("ml_context")
            if ml_context and isinstance(ml_context, dict):
                metadata = metadata.copy()
                metadata["ml_context"] = MLContextModel(**ml_context)
            file_metadata[path] = FileMetadataModel(**metadata)

    # Create the result model with all fields from aggregated_results
    return ModelAuditResultModel(
        bytes_scanned=aggregated_results.get("bytes_scanned", 0),
        issues=issues,
        checks=checks,
        files_scanned=aggregated_results.get("files_scanned", 0),
        assets=assets,
        has_errors=aggregated_results.get("has_errors", False),
        scanner_names=aggregated_results.get("scanner_names", []),
        file_metadata=file_metadata,
        start_time=aggregated_results.get("start_time", 0.0),
        duration=aggregated_results.get("duration", 0.0),
        total_checks=aggregated_results.get("total_checks", 0),
        passed_checks=aggregated_results.get("passed_checks", 0),
        failed_checks=aggregated_results.get("failed_checks", 0),
    )


def convert_issues_to_models(issues: list[Any]) -> list[IssueModel]:
    """Convert list of issue dicts or objects to IssueModel instances."""
    import time

    result = []
    for issue in issues:
        if isinstance(issue, dict):
            # Ensure required fields are present
            issue_dict = issue.copy()
            if "timestamp" not in issue_dict:
                issue_dict["timestamp"] = time.time()
            result.append(IssueModel(**issue_dict))
        elif hasattr(issue, "to_dict"):
            result.append(IssueModel(**issue.to_dict()))
        elif isinstance(issue, IssueModel):
            result.append(issue)
        else:
            # Skip unknown issue types
            continue
    return result


def convert_checks_to_models(checks: list[Any]) -> list[CheckModel]:
    """Convert list of check dicts or objects to CheckModel instances."""
    import time

    result = []
    for check in checks:
        if isinstance(check, dict):
            # Ensure required fields are present
            check_dict = check.copy()
            if "timestamp" not in check_dict:
                check_dict["timestamp"] = time.time()
            result.append(CheckModel(**check_dict))
        elif hasattr(check, "to_dict"):
            result.append(CheckModel(**check.to_dict()))
        elif isinstance(check, CheckModel):
            result.append(check)
        else:
            # Skip unknown check types
            continue
    return result


def convert_assets_to_models(assets: list[Any]) -> list[AssetModel]:
    """Convert list of asset dicts to AssetModel instances."""
    result = []
    for asset in assets:
        if isinstance(asset, dict):
            result.append(AssetModel(**asset))
        elif isinstance(asset, AssetModel):
            result.append(asset)
        else:
            # Skip unknown asset types
            continue
    return result


def create_initial_audit_result() -> ModelAuditResultModel:
    """Create an initial ModelAuditResultModel for aggregating scan results."""
    return ModelAuditResultModel(
        bytes_scanned=0,
        issues=[],
        checks=[],
        files_scanned=0,
        assets=[],
        has_errors=False,
        scanner_names=[],
        file_metadata={},
        start_time=time.time(),
        duration=0.0,
        total_checks=0,
        passed_checks=0,
        failed_checks=0,
        success=True,
    )


class ScanConfigModel(BaseModel):
    """Pydantic model for scan configuration with validation"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",  # Allow extra configuration fields
        arbitrary_types_allowed=True
    )

    # Core scanning parameters
    timeout: int = Field(default=3600, description="Timeout in seconds for scanning operations")
    max_file_size: int = Field(default=0, description="Maximum file size to scan (0 = unlimited)")
    max_total_size: int = Field(default=0, description="Maximum total size to scan (0 = unlimited)")
    chunk_size: int = Field(default=8192, description="Chunk size for streaming operations")

    # Advanced options
    blacklist_patterns: Optional[list[str]] = Field(None, description="Patterns to blacklist during scanning")
    enable_large_model_support: bool = Field(True, description="Enable optimizations for large models")
    include_license_scan: bool = Field(True, description="Include license scanning in results")
    enable_network_detection: bool = Field(True, description="Enable network communication detection")

    # Progress and output options
    enable_progress: bool = Field(True, description="Enable progress reporting")
    verbose: bool = Field(False, description="Enable verbose output")

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("timeout must be a positive integer")
        return v

    @field_validator("max_file_size")
    @classmethod
    def validate_max_file_size(cls, v: int) -> int:
        if v < 0:
            raise ValueError("max_file_size must be a non-negative integer")
        return v

    @field_validator("max_total_size")
    @classmethod
    def validate_max_total_size(cls, v: int) -> int:
        if v < 0:
            raise ValueError("max_total_size must be a non-negative integer")
        return v

    @field_validator("chunk_size")
    @classmethod
    def validate_chunk_size(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("chunk_size must be a positive integer")
        return v

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for backward compatibility"""
        return self.model_dump(exclude_none=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanConfigModel":
        """Create from dictionary with validation"""
        return cls(**data)


class NetworkPatternModel(BaseModel):
    """Pydantic model for network communication pattern detection"""

    model_config = ConfigDict(
        validate_assignment=True,
        frozen=True  # Make patterns immutable for performance
    )

    pattern: str = Field(..., description="The regex pattern or string to match")
    category: str = Field(..., description="Category of pattern (url, ip, domain, library, function)")
    severity: str = Field(default="warning", description="Severity level for matches")
    description: str = Field(..., description="Human-readable description of what this pattern detects")

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        allowed_categories = ["url", "ip", "domain", "library", "function", "port", "protocol"]
        if v not in allowed_categories:
            raise ValueError(f"category must be one of {allowed_categories}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed_severities = ["debug", "info", "warning", "critical"]
        if v not in allowed_severities:
            raise ValueError(f"severity must be one of {allowed_severities}")
        return v


class NetworkDetectionResultModel(BaseModel):
    """Pydantic model for network detection results"""

    model_config = ConfigDict(validate_assignment=True)

    detected_patterns: list[str] = Field(default_factory=list, description="List of detected pattern strings")
    pattern_matches: list[NetworkPatternModel] = Field(default_factory=list, description="Matched pattern objects")
    urls_found: list[str] = Field(default_factory=list, description="URLs found in the content")
    ip_addresses_found: list[str] = Field(default_factory=list, description="IP addresses found")
    domains_found: list[str] = Field(default_factory=list, description="Domain names found")
    libraries_found: list[str] = Field(default_factory=list, description="Network libraries detected")
    functions_found: list[str] = Field(default_factory=list, description="Network functions detected")
    risk_score: float = Field(default=0.0, description="Overall risk score (0.0 to 1.0)")

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("risk_score must be between 0.0 and 1.0")
        return v

    def add_detection(
        self,
        pattern: str,
        category: str,
        matched_content: str,
        severity: str = "warning",
        description: str = ""
    ) -> None:
        """Add a detection result with validation"""
        pattern_model = NetworkPatternModel(
            pattern=pattern,
            category=category,
            severity=severity,
            description=description or f"Detected {category}: {matched_content}"
        )

        self.pattern_matches.append(pattern_model)
        self.detected_patterns.append(matched_content)

        # Categorize the finding
        if category == "url":
            self.urls_found.append(matched_content)
        elif category == "ip":
            self.ip_addresses_found.append(matched_content)
        elif category == "domain":
            self.domains_found.append(matched_content)
        elif category == "library":
            self.libraries_found.append(matched_content)
        elif category == "function":
            self.functions_found.append(matched_content)

    def calculate_risk_score(self) -> float:
        """Calculate risk score based on detected patterns"""
        score = 0.0

        # Weight different types of findings
        weights = {
            "critical": 0.3,
            "warning": 0.2,
            "info": 0.1,
            "debug": 0.05
        }

        for match in self.pattern_matches:
            score += weights.get(match.severity, 0.1)

        # Normalize to 0-1 range (cap at 1.0)
        self.risk_score = min(score, 1.0)
        return self.risk_score


class ScannerRegistryEntry(BaseModel):
    """Pydantic model for scanner registry entries with validation"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",  # Allow additional scanner-specific configuration
        frozen=True  # Registry entries should be immutable
    )

    # Core scanner identification
    scanner_id: str = Field(..., description="Unique scanner identifier")
    module: str = Field(..., description="Python module path for the scanner")
    class_name: str = Field(..., description="Scanner class name", alias="class")
    description: str = Field(..., description="Human-readable scanner description")

    # File handling
    extensions: list[str] = Field(..., description="File extensions this scanner handles")
    priority: int = Field(..., description="Scanner priority (lower numbers = higher priority)", ge=1)

    # Dependencies and compatibility
    dependencies: list[str] = Field(default_factory=list, description="Required dependencies")
    numpy_sensitive: bool = Field(default=False, description="Whether scanner is sensitive to NumPy version")

    # Performance characteristics
    max_file_size: Optional[int] = Field(None, description="Maximum file size this scanner can handle", ge=0)
    timeout_multiplier: float = Field(default=1.0, description="Timeout multiplier for this scanner", gt=0)
    memory_intensive: bool = Field(default=False, description="Whether this scanner uses significant memory")

    # Categorization
    scanner_category: str = Field(default="format_specific", description="Scanner category")
    security_focus: list[str] = Field(default_factory=list, description="Security aspects this scanner focuses on")

    @field_validator("scanner_category")
    @classmethod
    def validate_scanner_category(cls, v: str) -> str:
        allowed_categories = [
            "format_specific", "archive", "metadata", "security_analysis",
            "weight_analysis", "generic", "experimental"
        ]
        if v not in allowed_categories:
            raise ValueError(f"scanner_category must be one of {allowed_categories}")
        return v

    def handles_extension(self, ext: str) -> bool:
        """Check if this scanner handles the given extension"""
        return ext.lower() in [e.lower() for e in self.extensions]

    def is_compatible_with_file_size(self, file_size: int) -> bool:
        """Check if scanner can handle files of this size"""
        if self.max_file_size is None:
            return True
        return file_size <= self.max_file_size

    def get_estimated_timeout(self, base_timeout: int) -> int:
        """Calculate estimated timeout for this scanner"""
        return int(base_timeout * self.timeout_multiplier)


class ScannerCapabilities(BaseModel):
    """Model for scanner capability information"""

    model_config = ConfigDict(validate_assignment=True)

    can_stream: bool = Field(default=False, description="Can handle streaming analysis")
    can_partial_scan: bool = Field(default=False, description="Can perform partial file scans")
    supports_metadata_only: bool = Field(default=False, description="Can extract just metadata")
    parallel_safe: bool = Field(default=True, description="Safe to run in parallel")
    memory_efficient: bool = Field(default=True, description="Uses memory efficiently")

    # Analysis capabilities
    detects_malicious_code: bool = Field(default=True, description="Detects malicious code patterns")
    extracts_metadata: bool = Field(default=True, description="Extracts file metadata")
    validates_format: bool = Field(default=True, description="Validates file format")
    analyzes_structure: bool = Field(default=False, description="Performs structural analysis")


class ScannerPerformanceMetrics(BaseModel):
    """Model for scanner performance tracking"""

    model_config = ConfigDict(validate_assignment=True)

    total_scans: int = Field(default=0, description="Total number of scans performed", ge=0)
    successful_scans: int = Field(default=0, description="Number of successful scans", ge=0)
    failed_scans: int = Field(default=0, description="Number of failed scans", ge=0)
    average_scan_time: float = Field(default=0.0, description="Average scan time in seconds", ge=0.0)
    total_bytes_scanned: int = Field(default=0, description="Total bytes scanned", ge=0)

    def get_success_rate(self) -> float:
        """Calculate success rate as percentage"""
        if self.total_scans == 0:
            return 0.0
        return (self.successful_scans / self.total_scans) * 100.0

    def get_throughput_mbps(self) -> float:
        """Calculate throughput in MB/s"""
        if self.average_scan_time == 0.0 or self.total_bytes_scanned == 0:
            return 0.0
        avg_bytes_per_scan = self.total_bytes_scanned / max(self.total_scans, 1)
        return (avg_bytes_per_scan / (1024 * 1024)) / self.average_scan_time

    def record_scan_result(self, success: bool, scan_time: float, bytes_scanned: int) -> None:
        """Record a scan result and update metrics"""
        self.total_scans += 1
        self.total_bytes_scanned += bytes_scanned

        if success:
            self.successful_scans += 1
        else:
            self.failed_scans += 1

        # Update running average
        if self.total_scans == 1:
            self.average_scan_time = scan_time
        else:
            # Weighted average with decay factor
            decay_factor = 0.9
            self.average_scan_time = (
                decay_factor * self.average_scan_time +
                (1 - decay_factor) * scan_time
            )


class MLFrameworkPattern(BaseModel):
    """Model for ML framework detection patterns"""

    model_config = ConfigDict(
        validate_assignment=True,
        frozen=True  # Patterns should be immutable
    )

    pattern: str = Field(..., description="Pattern to match (string or regex)")
    pattern_type: str = Field(..., description="Type of pattern (string, regex, binary)")
    framework: str = Field(..., description="Associated ML framework")
    confidence_weight: float = Field(..., description="Weight for confidence calculation", ge=0.0, le=1.0)
    location: str = Field(..., description="Where to look for pattern (header, content, filename, extension)")
    required: bool = Field(default=False, description="Whether this pattern is required for framework detection")

    @field_validator("pattern_type")
    @classmethod
    def validate_pattern_type(cls, v: str) -> str:
        allowed_types = ["string", "regex", "binary", "magic_bytes"]
        if v not in allowed_types:
            raise ValueError(f"pattern_type must be one of {allowed_types}")
        return v

    @field_validator("location")
    @classmethod
    def validate_location(cls, v: str) -> str:
        allowed_locations = ["header", "content", "filename", "extension", "manifest", "metadata"]
        if v not in allowed_locations:
            raise ValueError(f"location must be one of {allowed_locations}")
        return v


class MLFrameworkSignature(BaseModel):
    """Complete signature for ML framework detection"""

    model_config = ConfigDict(validate_assignment=True)

    framework_name: str = Field(..., description="Framework name")
    display_name: str = Field(..., description="Human-readable framework name")
    patterns: list[MLFrameworkPattern] = Field(..., description="Detection patterns")
    minimum_confidence: float = Field(
        default=0.5, description="Minimum confidence for positive detection", ge=0.0, le=1.0
    )
    version_patterns: list[MLFrameworkPattern] = Field(
        default_factory=list, description="Patterns for version detection"
    )

    # Framework characteristics
    supports_versions: list[str] = Field(default_factory=list, description="Known supported versions")
    common_extensions: list[str] = Field(default_factory=list, description="Common file extensions")
    security_considerations: list[str] = Field(default_factory=list, description="Security aspects to consider")

    def calculate_detection_confidence(self, matched_patterns: list[str]) -> float:
        """Calculate confidence based on matched patterns"""
        total_weight = 0.0
        matched_weight = 0.0
        required_matched = True

        for pattern in self.patterns:
            total_weight += pattern.confidence_weight
            if pattern.pattern in matched_patterns:
                matched_weight += pattern.confidence_weight
            elif pattern.required:
                required_matched = False

        if not required_matched:
            return 0.0

        confidence = matched_weight / total_weight if total_weight > 0 else 0.0
        return min(confidence, 1.0)

    def detect_version(self, content: str, matched_patterns: list[str]) -> Optional[str]:
        """Attempt to detect framework version"""
        for version_pattern in self.version_patterns:
            if version_pattern.pattern in matched_patterns and version_pattern.pattern_type == "regex":
                import re
                match = re.search(version_pattern.pattern, content)
                if match and match.groups():
                    return match.group(1)
        return None


class MLFrameworkDetectionResult(BaseModel):
    """Result of ML framework detection"""

    model_config = ConfigDict(validate_assignment=True)

    detected_frameworks: dict[str, MLFrameworkInfo] = Field(default_factory=dict, description="Detected frameworks")
    all_matched_patterns: list[str] = Field(default_factory=list, description="All patterns that matched")
    scan_timestamp: float = Field(default_factory=time.time, description="When detection was performed")
    confidence_threshold: float = Field(default=0.5, description="Threshold used for detection")

    def add_detection(
        self,
        signature: MLFrameworkSignature,
        matched_patterns: list[str],
        version: Optional[str] = None
    ) -> None:
        """Add a framework detection result"""
        confidence = signature.calculate_detection_confidence(matched_patterns)

        if confidence >= self.confidence_threshold:
            framework_info = MLFrameworkInfo(
                name=signature.framework_name,
                version=version,
                confidence=confidence,
                indicators=matched_patterns,
                file_patterns=[p.pattern for p in signature.patterns if p.pattern in matched_patterns]
            )
            self.detected_frameworks[signature.framework_name] = framework_info
            self.all_matched_patterns.extend(matched_patterns)

    def get_primary_framework(self) -> Optional[MLFrameworkInfo]:
        """Get the framework with highest confidence"""
        if not self.detected_frameworks:
            return None
        return max(self.detected_frameworks.values(), key=lambda x: x.confidence)

    def has_framework_conflicts(self) -> bool:
        """Check if multiple frameworks were detected with high confidence"""
        high_confidence_frameworks = [
            fw for fw in self.detected_frameworks.values()
            if fw.confidence > 0.8
        ]
        return len(high_confidence_frameworks) > 1


class CloudCredentials(BaseModel):
    """Model for cloud service credentials with validation"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="forbid",  # Security: don't allow extra fields that might leak
        str_strip_whitespace=True  # Clean up credential strings
    )

    api_key: Optional[str] = Field(default=None, description="API key for cloud service")
    api_host: str = Field(default="https://api.promptfoo.app", description="API host URL")
    app_url: str = Field(default="https://www.promptfoo.app", description="Application URL")
    organization_id: Optional[str] = Field(default=None, description="Organization identifier")
    user_id: Optional[str] = Field(default=None, description="User identifier")

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v.strip()) == 0:
            return None  # Empty strings become None
        return v

    def is_configured(self) -> bool:
        """Check if credentials are properly configured"""
        return self.api_key is not None and len(self.api_key) > 0

    def get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers for API requests"""
        if not self.api_key:
            return {}
        return {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "ModelAudit/1.0"
        }


class AccountInfo(BaseModel):
    """Model for user account information"""

    model_config = ConfigDict(validate_assignment=True)

    user_id: Optional[str] = Field(default=None, description="User identifier")
    email: Optional[str] = Field(default=None, description="User email address")
    display_name: Optional[str] = Field(default=None, description="Display name")
    organization_id: Optional[str] = Field(default=None, description="Organization identifier")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            import re
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, v):
                raise ValueError("Invalid email address format")
        return v

    def is_authenticated(self) -> bool:
        """Check if user is authenticated (has user_id)"""
        return self.user_id is not None


class GlobalConfigModel(BaseModel):
    """Enhanced global configuration model with validation"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow"  # Allow additional configuration fields
    )

    # Core configuration
    config_id: str = Field(
        default_factory=lambda: str(__import__("uuid").uuid4()), description="Unique config identifier"
    )
    has_harmful_redteam_consent: bool = Field(default=False, description="Consent for harmful red team operations")

    # User and account info
    account: AccountInfo = Field(default_factory=lambda: AccountInfo(), description="User account information")
    cloud: CloudCredentials = Field(
        default_factory=lambda: CloudCredentials(), description="Cloud service configuration"
    )

    # Local settings
    telemetry_enabled: bool = Field(default=True, description="Whether telemetry is enabled")
    auto_update_check: bool = Field(default=True, description="Whether to check for updates automatically")
    default_scan_config: Optional[ScanConfigModel] = Field(None, description="Default scanning configuration")

    # Security settings
    require_confirmation_for_uploads: bool = Field(default=True, description="Require confirmation for cloud uploads")
    max_file_size_mb: int = Field(default=100, description="Maximum file size for processing (MB)", gt=0)

    def is_cloud_enabled(self) -> bool:
        """Check if cloud features are enabled"""
        return self.cloud.is_configured()

    def to_legacy_dict(self) -> dict[str, Any]:
        """Convert to legacy dictionary format for backward compatibility"""
        return {
            "id": self.config_id,
            "hasHarmfulRedteamConsent": self.has_harmful_redteam_consent,
            "account": self.account.model_dump(exclude_none=True),
            "cloud": {
                "apiHost": str(self.cloud.api_host),
                "appUrl": str(self.cloud.app_url),
                "apiKey": self.cloud.api_key,
            }
        }

    @classmethod
    def from_legacy_dict(cls, data: dict[str, Any]) -> "GlobalConfigModel":
        """Create from legacy dictionary format"""
        # Extract account info
        account_data = data.get("account", {})
        if account_data:
            account = AccountInfo(**{k: v for k, v in account_data.items() if v is not None})
        else:
            account = AccountInfo()

        # Extract cloud config
        cloud_data = data.get("cloud", {})
        cloud = CloudCredentials(
            api_host=cloud_data.get("apiHost", "https://api.promptfoo.app"),
            app_url=cloud_data.get("appUrl", "https://www.promptfoo.app"),
            api_key=cloud_data.get("apiKey"),
            organization_id=cloud_data.get("organizationId"),
            user_id=cloud_data.get("userId")
        )

        return cls(
            config_id=data.get("id", str(__import__("uuid").uuid4())),
            has_harmful_redteam_consent=data.get("hasHarmfulRedteamConsent", False),
            account=account,
            cloud=cloud,
            default_scan_config=None  # Initialize with None
        )


class CloudUploadRequest(BaseModel):
    """Model for cloud upload requests with validation"""

    model_config = ConfigDict(validate_assignment=True)

    file_path: str = Field(..., description="Path to file being uploaded")
    file_size: int = Field(..., description="File size in bytes", ge=0)
    file_hash: str = Field(..., description="File hash for integrity verification")
    scan_results: Optional[dict[str, Any]] = Field(None, description="Associated scan results")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    upload_purpose: str = Field(..., description="Purpose of upload")

    @field_validator("upload_purpose")
    @classmethod
    def validate_upload_purpose(cls, v: str) -> str:
        allowed_purposes = ["scan_sharing", "threat_intelligence", "research", "support"]
        if v not in allowed_purposes:
            raise ValueError(f"upload_purpose must be one of {allowed_purposes}")
        return v

    def get_upload_size_mb(self) -> float:
        """Get file size in MB"""
        return self.file_size / (1024 * 1024)

    def validate_upload_constraints(self, max_size_mb: int = 100) -> None:
        """Validate upload meets constraints"""
        if self.get_upload_size_mb() > max_size_mb:
            raise ValueError(f"File size {self.get_upload_size_mb():.1f}MB exceeds limit of {max_size_mb}MB")


class AuthenticationStatus(BaseModel):
    """Model for authentication status tracking"""

    model_config = ConfigDict(validate_assignment=True)

    is_authenticated: bool = Field(default=False, description="Whether user is authenticated")
    user_info: Optional[AccountInfo] = Field(None, description="Authenticated user information")
    token_expires_at: Optional[int] = Field(None, description="Token expiration timestamp")
    last_verified: Optional[float] = Field(None, description="Last verification timestamp")
    auth_method: Optional[str] = Field(None, description="Authentication method used")

    def is_token_expired(self) -> bool:
        """Check if authentication token is expired"""
        if not self.token_expires_at:
            return False
        import time
        return time.time() > self.token_expires_at

    def needs_refresh(self, refresh_threshold: int = 300) -> bool:
        """Check if authentication needs refresh (within threshold seconds of expiry)"""
        if not self.token_expires_at:
            return False
        import time
        return (self.token_expires_at - time.time()) < refresh_threshold

    def time_until_expiry(self) -> Optional[int]:
        """Get time until token expires in seconds"""
        if not self.token_expires_at:
            return None
        import time
        return max(0, int(self.token_expires_at - time.time()))
