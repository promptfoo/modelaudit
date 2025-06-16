import hashlib
import os
from typing import Any, Iterable

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
    path: str, metadata: dict[str, Any], issues: Iterable[dict[str, Any]]
) -> Component:
    size = os.path.getsize(path)
    sha256 = _file_sha256(path)
    props = [Property(name="size", value=str(size))]

    # Compute risk score based on issues related to this file
    score = 0
    for issue in issues:
        if issue.get("location") == path:
            severity = issue.get("severity")
            if severity == "error":
                score += 5
            elif severity == "warning":
                score += 2
            elif severity == "info":
                score += 1
    if score > 10:
        score = 10
    props.append(Property(name="risk_score", value=str(score)))

    license_str = None
    if isinstance(metadata, dict):
        license_str = metadata.get("license")
    component = Component(
        name=os.path.basename(path),
        bom_ref=path,
        type=ComponentType.FILE,
        hashes=[HashType.from_hashlib_alg("sha256", sha256)],
        properties=props,
    )
    if license_str:
        component.licenses = [LicenseExpression(license_str)]
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
    return outputter.output_as_string(indent=2)
