import hashlib
import os
from collections.abc import Iterable
from typing import Any, Optional, Union, cast

from cyclonedx.model import HashType, Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import LicenseExpression
from cyclonedx.output import OutputFormat, SchemaVersion, make_outputter

from .models import FileMetadataModel, ModelAuditResultModel
from .scanners.base import Issue, IssueSeverity


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _calculate_risk_score(path: str, issues: list["Issue"]) -> int:
    """Calculate risk score for a file based on associated issues."""
    score = 0
    for issue in issues:
        if issue.location == path:
            if issue.severity == IssueSeverity.CRITICAL:
                score += 5
            elif issue.severity == IssueSeverity.WARNING:
                score += 2
            elif issue.severity == IssueSeverity.INFO:
                score += 1
    return min(score, 10)  # Cap at 10


def _extract_license_expressions(metadata: FileMetadataModel) -> list[LicenseExpression]:
    """Extract license expressions from file metadata."""
    license_expressions: list[LicenseExpression] = []
    license_identifiers: list[str] = []

    # Check for legacy license field
    if metadata.license:
        license_identifiers.append(str(metadata.license))

    # Check for new license metadata
    if metadata.license_info:
        for lic in metadata.license_info:
            if lic.spdx_id:
                license_identifiers.append(str(lic.spdx_id))
            elif lic.name:
                license_identifiers.append(str(lic.name))

    # Remove duplicates while preserving order
    unique_licenses: list[str] = []
    seen = set()
    for lic_id in license_identifiers:
        if lic_id not in seen:
            unique_licenses.append(lic_id)
            seen.add(lic_id)

    # Create license expressions
    if len(unique_licenses) == 1:
        license_expressions.append(LicenseExpression(unique_licenses[0]))
    elif len(unique_licenses) > 1:
        compound_expression = " OR ".join(unique_licenses)
        license_expressions.append(LicenseExpression(compound_expression))

    return license_expressions


def _create_metadata_properties(metadata: FileMetadataModel) -> list[Property]:
    """Create CycloneDX properties from file metadata."""
    props: list[Property] = []

    # Add file type properties
    if metadata.is_dataset:
        props.append(Property(name="is_dataset", value="true"))
    if metadata.is_model:
        props.append(Property(name="is_model", value="true"))

    # Add copyright information
    if metadata.copyright_notices:
        copyright_holders = []
        for cr in metadata.copyright_notices:
            if cr.holder:
                copyright_holders.append(cr.holder)

        if copyright_holders:
            props.append(
                Property(
                    name="copyright_holders",
                    value=", ".join(copyright_holders),
                )
            )

    # Add license files information
    if metadata.license_files_nearby:
        props.append(Property(name="license_files_found", value=str(len(metadata.license_files_nearby))))

    return props


def _component_for_file_pydantic(
    path: str,
    metadata: Optional[FileMetadataModel],
    issues: list[Issue],
) -> Component:
    """Create a CycloneDX component from Pydantic models (type-safe version)."""
    size = os.path.getsize(path) if os.path.exists(path) else 0
    sha256 = _file_sha256(path) if os.path.exists(path) else ""

    # Start with basic properties
    props = [Property(name="size", value=str(size))]

    # Calculate and add risk score
    risk_score = _calculate_risk_score(path, issues)
    props.append(Property(name="risk_score", value=str(risk_score)))

    # Add metadata-based properties if available
    license_expressions: list[LicenseExpression] = []
    if metadata:
        license_expressions = _extract_license_expressions(metadata)
        props.extend(_create_metadata_properties(metadata))

    # Create the component
    component = Component(
        name=os.path.basename(path),
        bom_ref=path,
        type=ComponentType.FILE,
        hashes=[HashType.from_hashlib_alg("sha256", sha256)] if sha256 else [],
        properties=props,
    )

    # Add license expressions
    for license_expr in license_expressions:
        component.licenses.add(license_expr)

    return component


def _component_for_file(
    path: str,
    metadata: dict[str, Any],
    issues: Iterable[dict[str, Any]],
) -> Component:
    size = os.path.getsize(path)
    sha256 = _file_sha256(path)
    props = [Property(name="size", value=str(size))]

    # Compute risk score based on issues related to this file
    score = 0
    for issue in issues:
        if issue.get("location") == path:
            severity = issue.get("severity")
            if severity == "critical":
                score += 5
            elif severity == "warning":
                score += 2
            elif severity == "info":
                score += 1
    if score > 10:
        score = 10
    props.append(Property(name="risk_score", value=str(score)))

    # Enhanced license handling
    license_expressions = []
    if isinstance(metadata, dict):
        # Collect all license identifiers
        license_identifiers = []

        # Check for legacy license field
        legacy_license = metadata.get("license")
        if legacy_license:
            license_identifiers.append(str(legacy_license))

        # Check for new license metadata
        detected_licenses = metadata.get("license_info", [])
        for lic in detected_licenses:
            if isinstance(lic, dict) and lic.get("spdx_id"):
                license_identifiers.append(str(lic["spdx_id"]))
            elif isinstance(lic, dict) and lic.get("name"):
                license_identifiers.append(str(lic["name"]))

        # Create a single license expression to comply with CycloneDX
        if license_identifiers:
            # Remove duplicates while preserving order
            unique_licenses = []
            seen = set()
            for lic_id in license_identifiers:
                if lic_id not in seen:
                    unique_licenses.append(lic_id)
                    seen.add(lic_id)

            if len(unique_licenses) == 1:
                license_expressions.append(LicenseExpression(unique_licenses[0]))
            else:
                # Create compound license expression for multiple licenses
                compound_expression = " OR ".join(unique_licenses)
                license_expressions.append(LicenseExpression(compound_expression))

        # Add license-related properties
        if metadata.get("is_dataset"):
            props.append(Property(name="is_dataset", value="true"))
        if metadata.get("is_model"):
            props.append(Property(name="is_model", value="true"))

        # Add copyright information
        copyrights = metadata.get("copyright_notices", [])
        if copyrights:
            copyright_holders = [cr.get("holder", "") for cr in copyrights if isinstance(cr, dict)]
            if copyright_holders:
                props.append(
                    Property(
                        name="copyright_holders",
                        value=", ".join(copyright_holders),
                    ),
                )

        # Add license files information
        license_files = metadata.get("license_files_nearby", [])
        if license_files:
            props.append(
                Property(name="license_files_found", value=str(len(license_files))),
            )

    component = Component(
        name=os.path.basename(path),
        bom_ref=path,
        type=ComponentType.FILE,
        hashes=[HashType.from_hashlib_alg("sha256", sha256)],
        properties=props,
    )

    if license_expressions:
        for license_expr in license_expressions:
            component.licenses.add(license_expr)

    return component


def generate_sbom(paths: Iterable[str], results: Union[dict[str, Any], Any]) -> str:
    bom = Bom()
    issues = results.get("issues", [])
    # Convert issues to dicts if they are Pydantic models
    issues_dicts = []
    for issue in issues:
        if hasattr(issue, "model_dump"):
            issues_dicts.append(issue.model_dump())
        else:
            issues_dicts.append(issue)

    file_meta: dict[str, Any] = results.get("file_metadata", {})

    for input_path in paths:
        if os.path.isdir(input_path):
            for root, _, files in os.walk(input_path):
                for f in files:
                    fp = os.path.join(root, f)
                    meta_model = file_meta.get(fp)
                    # Convert Pydantic model to dict if needed
                    if meta_model is not None and hasattr(meta_model, "model_dump"):
                        meta = meta_model.model_dump()
                    else:
                        meta = meta_model or {}
                    component = _component_for_file(fp, meta, issues_dicts)
                    bom.components.add(component)
        else:
            meta_model = file_meta.get(input_path)
            # Convert Pydantic model to dict if needed
            if meta_model is not None and hasattr(meta_model, "model_dump"):
                meta = meta_model.model_dump()
            else:
                meta = meta_model or {}
            component = _component_for_file(input_path, meta, issues_dicts)
            bom.components.add(component)

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_5)
    return cast(  # type: ignore[redundant-cast]
        str,
        outputter.output_as_string(indent=2),
    )


def generate_sbom_pydantic(paths: Iterable[str], results: ModelAuditResultModel) -> str:
    """
    Generate SBOM directly from Pydantic models (type-safe version).

    This is the preferred method that works directly with Pydantic models
    without any dict conversions, providing full type safety.
    """
    bom = Bom()

    # Use Pydantic models directly
    issues: list[Issue] = results.issues or []
    file_metadata: dict[str, FileMetadataModel] = results.file_metadata or {}

    for input_path in paths:
        if os.path.isdir(input_path):
            for root, _, files in os.walk(input_path):
                for f in files:
                    fp = os.path.join(root, f)
                    metadata = file_metadata.get(fp)
                    component = _component_for_file_pydantic(fp, metadata, issues)
                    bom.components.add(component)
        else:
            metadata = file_metadata.get(input_path)
            component = _component_for_file_pydantic(input_path, metadata, issues)
            bom.components.add(component)

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_5)
    return outputter.output_as_string(indent=2)
