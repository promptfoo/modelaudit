"""Pydantic models that match the exact current JSON output format.

These models provide type safety and validation while producing the exact same
JSON structure that ModelAudit currently outputs for backward compatibility.
"""

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class AssetModel(BaseModel):
    """Model for scanned assets"""

    path: str = Field(..., description="Path to the asset")
    type: str = Field(..., description="Type of asset (e.g., 'pickle')")
    size: Optional[int] = Field(None, description="Size of the asset in bytes")


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
    copyright_notices: list[str] = Field(default_factory=list, description="Copyright notices")
    license_files_nearby: list[str] = Field(default_factory=list, description="License files found nearby")
    is_dataset: Optional[bool] = Field(None, description="Whether file appears to be a dataset")
    is_model: Optional[bool] = Field(None, description="Whether file appears to be a model")


class ModelAuditResultModel(BaseModel):
    """Pydantic model matching the exact current ModelAudit JSON output format"""

    model_config = ConfigDict(use_enum_values=True, extra="allow")

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
