"""Bounded snapshots and byte-addressed evidence; never rewrite a scanner report."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Literal

from .models import MAX_DOCUMENT_BYTES, MAX_EVIDENCE_BYTES, Artifact, Evidence, Finding


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, ensure_ascii=True, indent=2, allow_nan=False)
        stream.write("\n")


def is_document(path: str) -> bool:
    return bool(
        re.fullmatch(
            r"(?:(?:readme|model_card)(?:\.(?:md|markdown|rst|txt))?|modelcard\.(?:md|markdown|rst|txt))",
            Path(path).name,
            re.I,
        )
    )


def text_locations(report: dict[str, Any]) -> set[str]:
    """Require per-file scanner provenance, including supplemental format scans."""
    assets = report.get("assets", [])
    metadata = report.get("file_metadata", {})
    if not isinstance(assets, list) or not isinstance(metadata, dict):
        return set()
    types: dict[str, set[str]] = {}
    for asset in assets:
        if isinstance(asset, dict) and isinstance(asset.get("path"), str):
            types.setdefault(asset["path"], set()).add(str(asset.get("type")))
    return {
        path
        for path, formats in types.items()
        if formats == {"text"}
        and isinstance(metadata.get(path), dict)
        and metadata[path].get("scanner_dependency_ids") == ["text"]
    }


def snapshot(source: Path, destination: Path, *, max_bytes: int, max_files: int = 10000) -> list[Artifact]:
    """Copy regular files through anchored directory descriptors (POSIX prototype)."""
    if os.name != "posix":
        raise ValueError("The review prototype requires a POSIX host")
    # Normalize dot segments without following a mutable source or ancestor symlink.
    source = Path(os.path.abspath(source))
    destination.mkdir(mode=0o700)
    artifacts: list[Artifact] = []
    total = 0
    entries = 0

    def copy_entry(parent_fd: int, name: str, relative: Path) -> None:
        nonlocal total, entries
        entries += 1
        if entries > max_files:
            raise ValueError("Snapshot exceeds the configured entry limit")
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        target = destination / relative
        if stat.S_ISDIR(info.st_mode):
            target.mkdir(mode=0o700)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError("Snapshot source changed while opening")
                names: list[str] = []
                with os.scandir(child) as listing:
                    for entry in listing:
                        if len(names) >= max_files - entries:
                            raise ValueError("Snapshot exceeds the configured entry limit")
                        names.append(entry.name)
                for child_name in sorted(names):
                    copy_entry(child, child_name, relative / child_name)
            finally:
                os.close(child)
            return
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Snapshot contains a symlink or special file")
        if len(artifacts) >= max_files or info.st_size > max_bytes - total:
            raise ValueError("Snapshot exceeds the configured file or byte limit")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(fd, "rb") as incoming, target.open("xb") as outgoing:
            before = os.fstat(incoming.fileno())
            if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("Snapshot source changed while opening")
            hasher = hashlib.sha256()
            size = 0
            while chunk := incoming.read(1024 * 1024):
                total += len(chunk)
                size += len(chunk)
                if total > max_bytes:
                    raise ValueError("Snapshot exceeds the configured byte limit")
                hasher.update(chunk)
                outgoing.write(chunk)
            after = os.fstat(incoming.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or size != before.st_size:
                raise ValueError("Snapshot source changed while copying")
        target.chmod(0o444)
        path = relative.as_posix()
        artifacts.append(
            Artifact(
                path=path,
                sha256=hasher.hexdigest(),
                size=size,
                role="documentation" if is_document(path) else "artifact",
            )
        )

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(source.anchor, flags)
    try:
        for part in source.parts[1:-1]:
            child_fd = os.open(part, flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        copy_entry(parent_fd, source.name, Path(source.name))
    finally:
        os.close(parent_fd)
    return artifacts


def verify_artifact(root: Path, artifact: Artifact) -> bytes:
    path = root / artifact.path
    if path.is_symlink() or not path.is_file() or path.stat().st_size != artifact.size:
        raise ValueError("Snapshot artifact is missing or changed")
    with path.open("rb") as stream:
        data = stream.read(MAX_DOCUMENT_BYTES + 1)
    if artifact.size <= MAX_DOCUMENT_BYTES and digest(data) != artifact.sha256:
        raise ValueError("Snapshot artifact digest changed")
    return data


def index_findings(
    report: dict[str, Any], scan_sha256: str, root: Path, artifacts: list[Artifact]
) -> tuple[list[Finding], list[Evidence]]:
    by_location = {str(root / item.path): item for item in artifacts}
    confirmed_text = text_locations(report)
    evidence_by_path: dict[str, Evidence] = {}
    findings: list[Finding] = []
    evidence_bytes = 0
    for collection in ("issues", "checks"):
        records = report.get(collection, [])
        if not isinstance(records, list):
            raise ValueError("Scanner findings are not a list")
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise ValueError("Scanner finding is not an object")
            if collection == "checks" and record.get("status") != "failed":
                continue
            pointer = f"/{collection}/{index}"
            artifact = by_location.get(str(record.get("location", "")))
            details = record.get("details", {})
            # Restrict favorable advice to network/documentation context, not all README findings.
            network = record.get("name") == "Network Communication Detection" or (
                isinstance(details, dict)
                and details.get("type")
                in {
                    "url_detected",
                    "cloud_storage_url",
                    "domain",
                    "domain_name",
                    "ipv4_address",
                    "ipv6_address",
                    "network_function",
                    "network_library",
                    "network_command",
                    "cc_pattern",
                    "suspicious_port",
                    "explicit_network_pattern",
                    "blacklisted_domain",
                }
            )
            selected = bool(
                artifact
                and artifact.role == "documentation"
                and str(record.get("location", "")) in confirmed_text
                and network
                and record.get("severity") in {"warning", "critical"}
            )
            reason = "documentation network finding" if selected else "outside verified text-document network scope"
            ids: list[str] = []
            if selected and artifact:
                if artifact.path not in evidence_by_path:
                    data = verify_artifact(root, artifact)
                    available = max(0, min(MAX_DOCUMENT_BYTES, MAX_EVIDENCE_BYTES - evidence_bytes))
                    excerpt = data[:available]
                    evidence_bytes += len(excerpt)
                    encoding: Literal["utf-8", "unavailable"]
                    try:
                        content = excerpt.decode("utf-8")
                        encoding = "utf-8"
                    except UnicodeDecodeError:
                        content, encoding = "", "unavailable"
                    evidence_by_path[artifact.path] = Evidence(
                        evidence_id=f"e-{digest(artifact.path.encode())[:24]}",
                        artifact_path=artifact.path,
                        artifact_sha256=artifact.sha256,
                        sha256=digest(excerpt),
                        byte_start=0,
                        byte_end=len(excerpt),
                        line_start=1,
                        line_end=max(1, len(excerpt.splitlines())),
                        complete=len(excerpt) == artifact.size and encoding == "utf-8",
                        encoding=encoding,
                        text=content,
                    )
                ids.append(evidence_by_path[artifact.path].evidence_id)
            findings.append(
                Finding(
                    finding_id=f"f-{digest((scan_sha256 + pointer).encode())[:32]}",
                    pointer=pointer,
                    record=record,
                    artifact_path=artifact.path if artifact else None,
                    evidence_ids=ids,
                    selected=selected,
                    selection_reason=reason,
                )
            )
    return findings, list(evidence_by_path.values())
