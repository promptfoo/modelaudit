"""Match explicitly reviewed URL observations against the bytes inspected by TextScanner."""

import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from modelaudit.config.rule_config import CitationIndex
from modelaudit.detectors.network_comm import NetworkCommDetector
from modelaudit.utils._path_hardening import _file_stat_matches


def reviewed_readme_stat(path: str) -> os.stat_result | None:
    """Keep the ordinary scan when the logical README name or its path cannot be verified."""
    source = Path(path)
    if source.name != "README.md" or ".." in source.parts:
        return None
    try:
        source = source.absolute()
        for component in (*reversed(source.parents), source):
            entry = component.lstat()
            if (
                stat.S_ISLNK(entry.st_mode)
                or getattr(entry, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                return None
        return entry if stat.S_ISREG(entry.st_mode) and entry.st_ino else None
    except OSError:
        return None


def _fully_reported_hosts(findings: list[dict[str, Any]], payload: bytes) -> set[bytes]:
    """Find hosts for which every domain token is represented by its own reported URL."""
    positions: dict[bytes, set[int]] = {}
    for finding in findings:
        url, start = finding.get("url"), finding.get("position")
        if not isinstance(url, str) or not isinstance(start, int) or start < 0:
            continue
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not host or not host.isascii() or parsed.username is not None:
            continue
        prefix = (parsed.scheme + "://" + host).encode("ascii")
        if payload[start : start + len(prefix)].lower() == prefix:
            positions.setdefault(host.encode("ascii"), set()).add(start + len(parsed.scheme) + 3)
    complete = set(positions)
    for occurrence in NetworkCommDetector.DOMAIN_PATTERN.finditer(payload):
        token = occurrence.group().lower()
        if token in complete and occurrence.start() not in positions[token]:
            complete.remove(token)
            if not complete:
                break
    return complete


def _related_observations_match(
    related: list[dict[str, Any]],
    payload: bytes,
    host: str,
    host_position: int,
    expected_digest: str,
    fully_reported_hosts: set[bytes],
) -> bool:
    for observation in related:
        domain = observation.get("domain")
        if (
            observation.get("type") != "domain_name"
            or observation.get("severity") not in {"INFO", "LOW", "MEDIUM", "WARNING"}
            or observation.get("position") != host_position
            or not isinstance(domain, str)
            or domain.lower() != host
            or payload[host_position : host_position + len(domain)].lower() != host.encode("ascii")
        ):
            return False
    # A single domain observation can also represent a later, otherwise unreported host use.
    if related and host.encode("ascii") not in fully_reported_hosts:
        return False
    encoded = json.dumps(related, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest() == expected_digest


def match_reviewed_citations(
    path: str,
    payload: bytes,
    sha256: str,
    source_stat: os.stat_result,
    findings: list[dict[str, Any]],
    decisions: CitationIndex,
) -> dict[int, dict[str, Any]]:
    final_stat = reviewed_readme_stat(path)
    if final_stat is None or not _file_stat_matches(source_stat, final_stat, cross_view=True):
        return {}

    fully_reported_hosts: set[bytes] | None = None
    positions = Counter(item.get("position") for item in findings if item.get("type") == "url_detected")
    matched: dict[int, dict[str, Any]] = {}
    for index, finding in enumerate(findings):
        position = finding.get("position")
        fingerprint = finding.get("evidence_fingerprint")
        if (
            finding.get("type") != "url_detected"
            or finding.get("severity") not in {"WARNING", "MEDIUM"}
            or finding.get("evidence_source") != "documentation"
            or finding.get("context") != path
            or not isinstance(position, int)
            or not isinstance(fingerprint, str)
            or positions[position] != 1
            or finding.get("count", 1) != 1
        ):
            continue
        row = decisions.get((sha256, position, fingerprint))
        if row is None or row["url"] != finding.get("url"):
            continue
        span = finding.get("evidence_location", {})
        end = span.get("span_end")
        if (
            span.get("span_start") != position
            or not isinstance(end, int)
            or not 0 <= position < end <= len(payload)
            or payload[position:end] != row["raw_span"].encode("utf-8")
            or (end < len(payload) and payload[end] not in b" \t\r\n\x22'<>\x60")
        ):
            continue
        url = row["url"]
        # Span recovery can include closing Markdown delimiters. A query, fragment or
        # longer destination sharing the displayed URL's prefix is a different observation.
        raw_span = row["raw_span"]
        if raw_span[len(url) :].strip(").,;:]"):
            continue
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or not parsed.netloc.isascii()
            or parsed.username is not None
            or parsed.password is not None
            or "?" in url
            or "#" in url
            or re.search(r"%(?:0[0-9a-f]|1[0-9a-f]|25|7f)|[\x00-\x1f\x7f]", url, re.IGNORECASE)
        ):
            continue
        authority_end = len(parsed.scheme) + 3 + len(parsed.netloc)
        if (
            raw_span[:authority_end].lower() != url[:authority_end].lower()
            or raw_span[authority_end : len(url)] != url[authority_end:]
        ):
            continue
        host_position = position + len(parsed.scheme) + 3
        related = finding.get("deduplicated_related_findings", [])
        if related and fully_reported_hosts is None:
            fully_reported_hosts = _fully_reported_hosts(findings, payload)
        if _related_observations_match(
            related,
            payload,
            parsed.hostname,
            host_position,
            row["related_sha256"],
            fully_reported_hosts or set(),
        ):
            matched[index] = row
    return matched
