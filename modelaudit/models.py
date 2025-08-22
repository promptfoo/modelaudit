"""Pydantic models that match the exact current JSON output format.

These models provide type safety and validation while producing the exact same
JSON structure that ModelAudit currently outputs for backward compatibility.
"""

import time
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class AssetModel(BaseModel):
    """Model for scanned assets"""

    path: str = Field(..., description="Path to the asset")
    type: str = Field(..., description="Type of asset (e.g., 'pickle')")
    size: Optional[int] = Field(None, description="Size of the asset in bytes")
    tensors: Optional[list[str]] = Field(None, description="List of tensor names (for safetensors)")
    keys: Optional[list[str]] = Field(None, description="List of keys (for JSON manifests)")
    contents: Optional[list[dict[str, Any]]] = Field(None, description="Contents list (for ZIP files)")


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


class IssueModel(BaseModel):
    """Model for security issues matching current format"""

    model_config = ConfigDict(use_enum_values=True)

    message: str = Field(..., description="Issue description")
    severity: str = Field(..., description="Issue severity level")
    location: Optional[str] = Field(None, description="File location or line number")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional issue details")
    timestamp: float = Field(..., description="Unix timestamp when issue was detected")
    why: Optional[str] = Field(None, description="Explanation of why this is a security concern")


class MLContextModel(BaseModel):
    """Model for ML context metadata"""

    frameworks: dict[str, Any] = Field(default_factory=dict, description="Detected ML frameworks")
    overall_confidence: float = Field(0.0, description="Overall confidence score")
    is_ml_content: bool = Field(False, description="Whether content is ML-related")
    detected_patterns: list[str] = Field(default_factory=list, description="Detected ML patterns")


class FileMetadataModel(BaseModel):
    """Model for individual file metadata"""

    file_size: Optional[int] = Field(None, description="File size in bytes")
    file_hashes: Optional[dict[str, str]] = Field(None, description="File hashes (md5, sha256, sha512)")
    max_stack_depth: Optional[int] = Field(None, description="Maximum stack depth for pickle files")
    ml_context: Optional[MLContextModel] = Field(None, description="ML context information")
    opcode_count: Optional[int] = Field(None, description="Number of opcodes for pickle files")
    suspicious_count: Optional[int] = Field(None, description="Count of suspicious patterns")
    license_info: list[Any] = Field(default_factory=list, description="License information")
    copyright_notices: list[Any] = Field(default_factory=list, description="Copyright notices")
    license_files_nearby: list[str] = Field(default_factory=list, description="License files found nearby")
    is_dataset: Optional[bool] = Field(None, description="Whether file appears to be a dataset")
    is_model: Optional[bool] = Field(None, description="Whether file appears to be a model")


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

    def aggregate_scan_result(self, results: dict[str, Any]) -> None:
        """Efficiently aggregate scan results into this model.

        This method updates the current model in-place for performance.
        """
        # Update scalar fields
        self.bytes_scanned += results.get("bytes_scanned", 0)
        self.files_scanned += results.get("files_scanned", 0)
        if results.get("has_errors", False):
            self.has_errors = True

        # Update success status - only set to False for operational errors, not security findings
        # Only set success to False if there are actual operational errors (has_errors=True)
        # Security findings should not affect the success status
        if results.get("success", True) is False and results.get("has_errors", False):
            self.success = False

        # Convert and extend issues
        new_issues = convert_issues_to_models(results.get("issues", []))
        self.issues.extend(new_issues)

        # Convert and extend checks
        new_checks = convert_checks_to_models(results.get("checks", []))
        self.checks.extend(new_checks)

        # Convert and extend assets
        new_assets = convert_assets_to_models(results.get("assets", []))
        self.assets.extend(new_assets)

        # Merge file metadata
        for path, metadata in results.get("file_metadata", {}).items():
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
        for scanner in results.get("scanners", []):
            if scanner and scanner not in self.scanner_names and scanner != "unknown":
                self.scanner_names.append(scanner)

    def finalize_statistics(self) -> None:
        """Calculate final statistics after all scan results are aggregated."""
        self.duration = time.time() - self.start_time
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
