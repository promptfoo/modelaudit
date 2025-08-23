"""Pydantic models that match the exact current JSON output format.

These models provide type safety and validation while producing the exact same
JSON structure that ModelAudit currently outputs for backward compatibility.
"""

import time
from typing import TYPE_CHECKING, Any, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

if TYPE_CHECKING:
    from .scanners.base import Check, Issue

# We'll use forward references and rebuild models after imports


class DetectorFinding(BaseModel):
    """Pydantic model for security detector findings"""

    model_config = ConfigDict(validate_assignment=True)

    message: str = Field(..., description="Description of the finding")
    severity: str = Field(..., description="Severity level (CRITICAL, WARNING, INFO, DEBUG)")
    context: str = Field(..., description="Context where finding was detected")
    pattern: Optional[str] = Field(None, description="Pattern that triggered the finding")
    recommendation: Optional[str] = Field(None, description="Recommended action")
    confidence: float = Field(1.0, description="Confidence in the finding", ge=0.0, le=1.0)
    details: dict[str, Any] = Field(default_factory=dict, description="Additional finding details")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for backward compatibility"""
        return self.model_dump(exclude_none=True)


class JITScriptFinding(DetectorFinding):
    """Pydantic model for JIT/Script detector findings"""

    framework: Optional[str] = Field(None, description="Framework where finding was detected")
    code_snippet: Optional[str] = Field(None, description="Relevant code snippet")
    type: Optional[str] = Field(None, description="Type of JIT/Script finding")
    operation: Optional[str] = Field(None, description="Detected operation or pattern")
    builtin: Optional[str] = Field(None, description="Detected builtin function")
    import_: Optional[str] = Field(None, description="Detected import statement", alias="import")


class NetworkCommFinding(DetectorFinding):
    """Pydantic model for network communication detector findings"""

    url: Optional[str] = Field(None, description="Detected URL")
    ip_address: Optional[str] = Field(None, description="Detected IP address")
    domain: Optional[str] = Field(None, description="Detected domain")
    protocol: Optional[str] = Field(None, description="Detected protocol")


class SecretsFinding(DetectorFinding):
    """Pydantic model for secrets detector findings"""

    secret_type: Optional[str] = Field(None, description="Type of secret detected")
    location: Optional[str] = Field(None, description="Location in file/data")
    masked_value: Optional[str] = Field(None, description="Masked version of detected secret")


class DictCompatMixin:
    """Mixin providing dictionary-like access to Pydantic models for backward compatibility."""

    def get(self, key: str, default: Any = None) -> Any:
        """Support dict-style get() method for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        return default

    def __getitem__(self, key: str) -> Any:
        """Support dict-style access for backward compatibility."""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"'{key}' not found in {self.__class__.__name__}")

    def __contains__(self, key: str) -> bool:
        """Support 'in' operator for backward compatibility."""
        return hasattr(self, key)


class AssetModel(BaseModel, DictCompatMixin):
    """Model for scanned assets"""

    path: str = Field(..., description="Path to the asset")
    type: str = Field(..., description="Type of asset (e.g., 'pickle')")
    size: Optional[int] = Field(None, description="Size of the asset in bytes")
    tensors: Optional[list[str]] = Field(None, description="List of tensor names (for safetensors)")
    keys: Optional[list[str]] = Field(None, description="List of keys (for JSON manifests)")
    contents: Optional[list[dict[str, Any]]] = Field(None, description="Contents list (for ZIP files)")

    # Dictionary-like access provided by DictCompatMixin


class MLFrameworkInfo(BaseModel):
    """Model for individual ML framework detection info"""

    model_config = ConfigDict(validate_assignment=True)

    name: Optional[str] = Field(None, description="Framework name (e.g., 'pytorch', 'tensorflow')")
    version: Optional[str] = Field(None, description="Detected version if available")
    confidence: float = Field(0.0, description="Confidence in detection (0.0 to 1.0)", ge=0.0, le=1.0)
    indicators: Optional[list[str]] = Field(default_factory=list, description="Patterns that indicated this framework")
    file_patterns: Optional[list[str]] = Field(default_factory=list, description="File patterns that matched")


class WeightAnalysisModel(BaseModel):
    """Model for weight pattern analysis results"""

    model_config = ConfigDict(validate_assignment=True)

    appears_to_be_weights: bool = Field(False, description="Whether data appears to be ML weights")
    weight_confidence: float = Field(0.0, description="Confidence in weight detection", ge=0.0, le=1.0)
    pattern_density: float = Field(0.0, description="Density of detected patterns", ge=0.0, le=1.0)
    float_ratio: float = Field(0.0, description="Ratio of floating-point data", ge=0.0, le=1.0)
    statistical_expectation: float = Field(0.0, description="Statistical expectation for patterns", ge=0.0, le=1.0)
    file_size_factor: float = Field(0.0, description="File size influence factor", ge=0.0, le=1.0)

    # Using built-in constraints instead of custom validator


class MLContextModel(BaseModel):
    """Enhanced model for ML context metadata with comprehensive validation"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",  # Allow additional framework-specific data
    )

    # Framework detection
    frameworks: dict[str, MLFrameworkInfo] = Field(
        default_factory=dict, description="Detected ML frameworks with details"
    )
    overall_confidence: float = Field(0.0, description="Overall ML content confidence score", ge=0.0, le=1.0)
    is_ml_content: bool = Field(False, description="Whether content is ML-related")
    detected_patterns: list[str] = Field(default_factory=list, description="Detected ML patterns")

    # Weight analysis
    weight_analysis: Optional[WeightAnalysisModel] = Field(None, description="Analysis of potential weight data")

    # Model architecture hints
    model_type: Optional[str] = Field(None, description="Detected model type (e.g., 'transformer', 'cnn', 'rnn')")
    layer_count_estimate: Optional[int] = Field(None, description="Estimated number of layers", ge=0)
    parameter_count_estimate: Optional[int] = Field(None, description="Estimated parameter count", ge=0)

    # Training metadata
    training_framework: Optional[str] = Field(None, description="Framework likely used for training")
    precision_type: Optional[str] = Field(None, description="Detected precision (fp32, fp16, int8, etc.)")
    optimization_hints: list[str] = Field(default_factory=list, description="Detected optimization techniques")

    def add_framework(
        self,
        name: str,
        confidence: float,
        version: Optional[str] = None,
        indicators: Optional[list[str]] = None,
        file_patterns: Optional[list[str]] = None,
    ) -> None:
        """Add framework detection with validation"""
        framework_info = MLFrameworkInfo(
            name=name,
            version=version,
            confidence=confidence,
            indicators=indicators or [],
            file_patterns=file_patterns or [],
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
    confidence: float = Field(0.0, description="Confidence in license detection", ge=0.0, le=1.0)
    source: Optional[str] = Field(None, description="Source of license detection (file, header, etc.)")
    commercial_allowed: Optional[bool] = Field(None, description="Whether commercial use is allowed")

    @field_validator("spdx_id")
    @classmethod
    def validate_spdx_id(cls, v: Optional[str]) -> Optional[str]:
        """Validate SPDX ID format"""
        if v is None:
            return v
        # Basic validation for common SPDX ID patterns
        if not v.replace("-", "").replace(".", "").replace("+", "").isalnum():
            raise ValueError("SPDX ID must contain only alphanumeric characters, hyphens, dots, and plus signs")
        return v


class CopyrightNoticeModel(BaseModel):
    """Model for copyright notice information"""

    model_config = ConfigDict(validate_assignment=True)

    holder: str = Field(..., description="Copyright holder name")
    year: Optional[str] = Field(None, description="Copyright year(s)")
    text: Optional[str] = Field(None, description="Full copyright notice text")
    confidence: float = Field(0.0, description="Confidence in copyright detection", ge=0.0, le=1.0)

    @field_validator("year")
    @classmethod
    def validate_year(cls, v: Optional[str]) -> Optional[str]:
        """Validate copyright year format (e.g., '2020', '2020-2023')"""
        if v is None:
            return v
        # Basic validation for year patterns
        import re

        if not re.match(r"^\d{4}(-\d{4})?$", v):
            raise ValueError("Year must be in format YYYY or YYYY-YYYY")
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


class FileMetadataModel(BaseModel, DictCompatMixin):
    """Enhanced model for individual file metadata with structured validation"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",  # Allow additional metadata fields
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
    risk_score: float = Field(default=0.0, description="Calculated risk score (0.0 to 1.0)", ge=0.0, le=1.0)
    scan_timestamp: float = Field(default_factory=time.time, description="When this metadata was collected")

    def add_license_info(
        self,
        spdx_id: Optional[str] = None,
        name: Optional[str] = None,
        url: Optional[str] = None,
        text: Optional[str] = None,
        confidence: float = 0.0,
        source: Optional[str] = None,
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
            source=source,
            commercial_allowed=None,
        )
        self.license_info.append(license_info)

    def add_copyright_notice(
        self, holder: str, years: Optional[str] = None, notice_text: Optional[str] = None, confidence: float = 0.0
    ) -> None:
        """Add copyright notice with validation"""
        copyright_notice = CopyrightNoticeModel(holder=holder, year=years, text=notice_text, confidence=confidence)
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

    # Dictionary-like access provided by DictCompatMixin


class ModelAuditResultModel(BaseModel, DictCompatMixin):
    """Pydantic model matching the exact current ModelAudit JSON output format"""

    model_config = ConfigDict(
        extra="allow",
        validate_assignment=False,  # Disable validation on assignment for performance
        frozen=False,  # Allow field mutations for efficient aggregation
    )

    # Core scan results
    bytes_scanned: int = Field(..., description="Total bytes scanned")
    issues: list["Issue"] = Field(default_factory=list, description="List of security issues found")
    checks: list["Check"] = Field(default_factory=list, description="List of all checks performed")
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

    def aggregate_scan_result(self, results: "Union[dict[str, Any], ModelAuditResultModel]") -> None:
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
        from ..scanners.base import Check, Issue, ScanResult

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
                Issue(
                    message=issue.message,
                    severity=issue.severity,
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
                Check(
                    name=check.name,
                    status=check.status.value,
                    message=check.message,
                    location=check.location,
                    details=check.details,
                    timestamp=check.timestamp,
                    severity=check.severity if check.severity else None,
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

    # Dictionary-like access provided by DictCompatMixin

    def _finalize_checks(self) -> None:
        """Calculate check statistics."""
        from .scanners.base import CheckStatus

        self.total_checks = len(self.checks)
        self.passed_checks = sum(1 for c in self.checks if c.status == CheckStatus.PASSED)
        self.failed_checks = sum(1 for c in self.checks if c.status == CheckStatus.FAILED)

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
    from .scanners.base import Check, Issue

    # Convert issues to Issue instances
    issues = []
    for issue in aggregated_results.get("issues", []):
        if isinstance(issue, dict):
            issues.append(Issue(**issue))
        elif hasattr(issue, "to_dict"):
            issues.append(Issue(**issue.to_dict()))

    # Convert checks to Check instances
    checks = []
    for check in aggregated_results.get("checks", []):
        if isinstance(check, dict):
            checks.append(Check(**check))
        elif hasattr(check, "to_dict"):
            checks.append(Check(**check.to_dict()))

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


def convert_issues_to_models(issues: list[Any]) -> list["Issue"]:
    """Convert list of issue dicts or objects to Issue instances."""
    import time

    from .scanners.base import Issue

    result = []
    for issue in issues:
        if isinstance(issue, dict):
            # Ensure required fields are present
            issue_dict = issue.copy()
            if "timestamp" not in issue_dict:
                issue_dict["timestamp"] = time.time()
            result.append(Issue(**issue_dict))
        elif hasattr(issue, "to_dict"):
            result.append(Issue(**issue.to_dict()))
        elif isinstance(issue, Issue):
            result.append(issue)
        else:
            # Skip unknown issue types
            continue
    return result


def convert_checks_to_models(checks: list[Any]) -> list["Check"]:
    """Convert list of check dicts or objects to Check instances."""
    import time

    from .scanners.base import Check

    result = []
    for check in checks:
        if isinstance(check, dict):
            # Ensure required fields are present
            check_dict = check.copy()
            if "timestamp" not in check_dict:
                check_dict["timestamp"] = time.time()
            result.append(Check(**check_dict))
        elif hasattr(check, "to_dict"):
            result.append(Check(**check.to_dict()))
        elif isinstance(check, Check):
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
    # Ensure models are properly rebuilt with scanner types
    rebuild_models()

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
        arbitrary_types_allowed=True,
    )

    # Core scanning parameters
    timeout: int = Field(default=3600, description="Timeout in seconds for scanning operations", gt=0)
    max_file_size: int = Field(default=0, description="Maximum file size to scan (0 = unlimited)", ge=0)
    max_total_size: int = Field(default=0, description="Maximum total size to scan (0 = unlimited)", ge=0)
    chunk_size: int = Field(default=8192, description="Chunk size for streaming operations", gt=0)

    # Advanced options
    blacklist_patterns: Optional[list[str]] = Field(default=None, description="Patterns to blacklist during scanning")
    enable_large_model_support: bool = Field(True, description="Enable optimizations for large models")
    include_license_scan: bool = Field(True, description="Include license scanning in results")
    enable_network_detection: bool = Field(True, description="Enable network communication detection")

    # Progress and output options
    enable_progress: bool = Field(True, description="Enable progress reporting")
    verbose: bool = Field(False, description="Enable verbose output")

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
        frozen=True,  # Make patterns immutable for performance
    )

    pattern: str = Field(..., description="The regex pattern or string to match")
    category: str = Field(..., description="Category of pattern (url, ip, domain, library, function)")
    severity: str = Field(default="warning", description="Severity level for matches")
    description: str = Field(..., description="Human-readable description of what this pattern detects")

    # Note: In a real implementation, these would be better as Enums, but keeping as strings for simplicity


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
            self.average_scan_time = decay_factor * self.average_scan_time + (1 - decay_factor) * scan_time


def rebuild_models() -> None:
    """Rebuild models with proper type references after all imports are available."""
    try:
        # Import the scanner models
        from .scanners.base import Check, Issue

        # Update the global namespace so forward references work
        globals()["Issue"] = Issue
        globals()["Check"] = Check

        # Rebuild models that use forward references
        ModelAuditResultModel.model_rebuild()

    except ImportError:
        # If scanner models aren't available, just use Any
        globals()["Issue"] = Any
        globals()["Check"] = Any
        ModelAuditResultModel.model_rebuild()
