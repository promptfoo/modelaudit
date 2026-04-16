"""Scanner selection policy helpers.

Scanner selection is intentionally small: users may allowlist scanners with
``--scanners`` and subtract scanners with ``--exclude-scanner``. Keeping the
policy registry-metadata based lets CLI, core routing, nested archive dispatch,
and remote prefilters share the same semantics without loading scanner classes.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .scanner_registry_metadata import get_scanner_registry_metadata
from .scanner_results import IssueSeverity, ScanResult

SCANNER_SELECTION_CONFIG_KEY = "scanner_selection"
_GENERIC_CONTAINER_SCANNER_IDS = frozenset({"compressed", "rar", "sevenzip", "tar", "zip"})


def scanner_catalog() -> list[dict[str, Any]]:
    """Return scanner metadata suitable for CLI discovery output."""
    catalog: list[dict[str, Any]] = []
    for scanner_id, scanner_info in sorted(get_scanner_registry_metadata().items()):
        extensions = sorted(
            {
                str(extension)
                for key in ("extensions", "content_routed_extensions", "scanner_only_extensions")
                for extension in scanner_info.get(key, [])
                if str(extension)
            }
        )
        catalog.append(
            {
                "id": scanner_id,
                "class": scanner_info.get("class", ""),
                "description": scanner_info.get("description", ""),
                "extensions": extensions,
                "dependencies": sorted(str(dep) for dep in scanner_info.get("dependencies", [])),
            }
        )
    return catalog


def split_scanner_tokens(values: Iterable[str] | str | None) -> list[str]:
    """Normalize repeatable/comma-separated scanner option values."""
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]

    tokens: list[str] = []
    for value in values:
        for token in str(value).split(","):
            token = token.strip()
            if token:
                tokens.append(token)
    return tokens


def _alias_key(value: str) -> str:
    return value.strip().lower().replace("_", "").replace("-", "")


def _scanner_aliases(metadata: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
    aliases: dict[str, str] = {}

    def add(alias: str, scanner_id: str) -> None:
        key = _alias_key(alias)
        if key:
            aliases.setdefault(key, scanner_id)

    for scanner_id, scanner_info in metadata.items():
        add(scanner_id, scanner_id)
        add(scanner_id.replace("_", "-"), scanner_id)

        class_name = str(scanner_info.get("class", ""))
        add(class_name, scanner_id)
        if class_name.endswith("Scanner"):
            add(class_name[: -len("Scanner")], scanner_id)

    # Common user-facing aliases from docs and issue examples.
    aliases.setdefault(_alias_key("H5Scanner"), "keras_h5")
    aliases.setdefault(_alias_key("TensorflowSavedModelScanner"), "tf_savedmodel")
    aliases.setdefault(_alias_key("TensorFlowSavedModelScanner"), "tf_savedmodel")
    aliases.setdefault(_alias_key("TensorflowMetaGraphScanner"), "tf_metagraph")
    aliases.setdefault(_alias_key("TensorFlowMetaGraphScanner"), "tf_metagraph")
    return aliases


def resolve_scanner_ids(tokens: Iterable[str] | str | None) -> tuple[str, ...]:
    """Resolve scanner IDs, class names, and friendly aliases to canonical IDs."""
    metadata = get_scanner_registry_metadata()
    aliases = _scanner_aliases(metadata)
    resolved: list[str] = []
    unknown: list[str] = []

    for token in split_scanner_tokens(tokens):
        scanner_id = aliases.get(_alias_key(token))
        if scanner_id is None:
            unknown.append(token)
            continue
        if scanner_id not in resolved:
            resolved.append(scanner_id)

    if unknown:
        available = ", ".join(sorted(metadata.keys()))
        unknown_text = ", ".join(unknown)
        raise ValueError(f"Unknown scanner name(s): {unknown_text}. Available scanners: {available}")

    return tuple(resolved)


@dataclass(frozen=True)
class ScannerSelectionPolicy:
    """Resolved scanner selection policy."""

    enabled_scanner_ids: frozenset[str]
    all_scanner_ids: frozenset[str]
    exact_scanner_ids: frozenset[str] = frozenset()
    exclude_scanner_ids: frozenset[str] = frozenset()
    active: bool = False

    def allows(self, scanner_id: str | None) -> bool:
        """Return whether a canonical scanner ID may run."""
        if scanner_id is None:
            return False
        if not self.active:
            return True
        return scanner_id in self.enabled_scanner_ids

    def to_config(self) -> dict[str, Any]:
        """Return a stable, JSON-friendly config payload."""
        return {
            "active": self.active,
            "scanners": sorted(self.exact_scanner_ids) if self.exact_scanner_ids else None,
            "exclude_scanners": sorted(self.exclude_scanner_ids),
            "enabled_scanner_ids": sorted(self.enabled_scanner_ids),
        }

    def to_metadata(self) -> dict[str, Any]:
        """Return user-facing scan metadata."""
        return {
            "requested_scanner_ids": sorted(self.exact_scanner_ids) if self.exact_scanner_ids else None,
            "enabled_scanner_ids": sorted(self.enabled_scanner_ids),
            "excluded_scanner_ids": sorted(self.exclude_scanner_ids),
        }


def resolve_scanner_selection_policy(
    *,
    scanners: Iterable[str] | str | None = None,
    exclude_scanners: Iterable[str] | str | None = None,
) -> ScannerSelectionPolicy:
    """Resolve raw scanner selection inputs into a policy."""
    metadata = get_scanner_registry_metadata()
    all_scanner_ids = frozenset(metadata.keys())

    exact_ids = frozenset(resolve_scanner_ids(scanners))
    exclude_ids = frozenset(resolve_scanner_ids(exclude_scanners))
    base_ids = set(exact_ids or all_scanner_ids)
    enabled = frozenset(base_ids - set(exclude_ids))
    active = bool(exact_ids or exclude_ids)

    if active and not enabled:
        raise ValueError("Scanner selection does not enable any scanners")

    return ScannerSelectionPolicy(
        enabled_scanner_ids=enabled,
        all_scanner_ids=all_scanner_ids,
        exact_scanner_ids=exact_ids,
        exclude_scanner_ids=exclude_ids,
        active=active,
    )


def scanner_selection_config_from_inputs(
    *,
    scanners: Iterable[str] | str | None = None,
    exclude_scanners: Iterable[str] | str | None = None,
) -> dict[str, Any]:
    """Build a stable config dict for scanner selection inputs."""
    return resolve_scanner_selection_policy(
        scanners=scanners,
        exclude_scanners=exclude_scanners,
    ).to_config()


def policy_from_config(config: Mapping[str, Any] | None) -> ScannerSelectionPolicy:
    """Return the resolved selection policy from scanner config."""
    raw_config = config if isinstance(config, Mapping) else {}
    raw_selection = raw_config.get(SCANNER_SELECTION_CONFIG_KEY)

    if isinstance(raw_selection, Mapping):
        return resolve_scanner_selection_policy(
            scanners=raw_selection.get("scanners"),
            exclude_scanners=raw_selection.get("exclude_scanners"),
        )

    return resolve_scanner_selection_policy(
        scanners=raw_config.get("scanners"),
        exclude_scanners=raw_config.get("exclude_scanners"),
    )


def normalize_scanner_selection_config(config: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a mutable config with a normalized scanner selection payload."""
    normalized = dict(config or {})
    has_raw_selection = any(key in normalized for key in (SCANNER_SELECTION_CONFIG_KEY, "scanners", "exclude_scanners"))
    policy = policy_from_config(normalized)
    if policy.active or has_raw_selection:
        normalized[SCANNER_SELECTION_CONFIG_KEY] = policy.to_config()
    normalized.pop("scanners", None)
    normalized.pop("exclude_scanners", None)
    return normalized


def selected_scanner_extensions(
    policy: ScannerSelectionPolicy,
    *,
    conservative: bool = False,
) -> frozenset[str] | None:
    """Return suffixes owned by the policy's enabled scanners.

    When ``conservative`` is true, return ``None`` if suffix-only filtering
    would narrow away files that selected scanners can route by trusted
    headers. Remote sources only have filenames before download, so they need
    this fail-open behavior to avoid selection-created coverage gaps.
    """
    metadata = get_scanner_registry_metadata()
    extensions: set[str] = set()
    for scanner_id in policy.enabled_scanner_ids:
        scanner_info = metadata.get(scanner_id, {})
        if conservative and (scanner_id in _GENERIC_CONTAINER_SCANNER_IDS or scanner_info.get("header_formats")):
            return None
        for key in ("extensions", "content_routed_extensions", "scanner_only_extensions"):
            for extension in scanner_info.get(key, []):
                extension_text = str(extension).lower()
                extensions.add(extension_text)
    return frozenset(extensions)


def add_scanner_selection_skip_check(
    result: ScanResult,
    location: str,
    scanner_id: str | None,
    policy: ScannerSelectionPolicy,
    *,
    context: str | None = None,
) -> None:
    """Add an informational check for a scanner skipped by selection policy."""
    result.metadata.setdefault("scanner_selection", policy.to_metadata())
    skipped_scanner_ids = result.metadata.setdefault("skipped_scanner_ids", [])
    if isinstance(skipped_scanner_ids, list) and scanner_id and scanner_id not in skipped_scanner_ids:
        skipped_scanner_ids.append(scanner_id)

    scanner_label = scanner_id or "candidate scanner"
    message = f"Skipped {scanner_label} because it is not enabled by scanner selection policy"
    if context:
        message = f"{message} ({context})"

    result.add_check(
        name="Scanner Selection",
        passed=True,
        message=message,
        severity=IssueSeverity.INFO,
        location=location,
        details={
            "skipped_scanner_id": scanner_id,
            "enabled_scanner_ids": sorted(policy.enabled_scanner_ids),
            "context": context,
        },
    )


def make_scanner_selection_skip_result(
    path: str,
    scanner_id: str | None,
    policy: ScannerSelectionPolicy,
) -> ScanResult:
    """Build a successful result that makes intentional policy skips explicit."""
    result = ScanResult(scanner_name="scanner_selection")
    try:
        result.bytes_scanned = os.path.getsize(path)
    except OSError:
        result.bytes_scanned = 0

    result.metadata.update(
        {
            "scanner_selection": policy.to_metadata(),
            "skipped_scanner_id": scanner_id,
            "skip_reason": "scanner_not_enabled",
        }
    )
    if result.bytes_scanned:
        result.metadata["file_size"] = result.bytes_scanned

    add_scanner_selection_skip_check(result, path, scanner_id, policy)
    result.finish(success=True)
    return result
