import hashlib
import os
from collections.abc import Iterable
from typing import Any, cast

from cyclonedx.model import HashType, Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import LicenseExpression
from cyclonedx.output import OutputFormat, SchemaVersion, make_outputter


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


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


def generate_sbom(paths: Iterable[str], results: dict[str, Any]) -> str:
    bom = Bom()
    issues = results.get("issues", [])
    file_meta: dict[str, Any] = results.get("file_metadata", {})

    for input_path in paths:
        if os.path.isdir(input_path):
            for root, _, files in os.walk(input_path):
                for f in files:
                    fp = os.path.join(root, f)
                    meta = file_meta.get(fp, {})
                    component = _component_for_file(fp, meta, issues)
                    bom.components.add(component)
        else:
            meta = file_meta.get(input_path, {})
            component = _component_for_file(input_path, meta, issues)
            bom.components.add(component)

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_5)
    return cast(  # type: ignore[redundant-cast]
        str,
        outputter.output_as_string(indent=2),
    )
