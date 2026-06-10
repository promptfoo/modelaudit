"""Scanner selection policy helpers.

Scanner selection is intentionally small: users may allowlist scanners with
``--scanners`` and subtract scanners with ``--exclude-scanner``. Keeping the
policy registry-metadata based lets CLI, core routing, nested archive dispatch,
and remote prefilters share the same semantics without loading scanner classes.
"""

from __future__ import annotations

import difflib
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache, lru_cache
from typing import Any, Literal

from .scanner_registry_metadata import get_scanner_registry_metadata
from .scanner_results import IssueSeverity, ScanResult

ScannerSelectionSkipKind = Literal["preferred", "embedded"]

SCANNER_SELECTION_CONFIG_KEY = "scanner_selection"
_GENERIC_CONTAINER_SCANNER_IDS = frozenset({"compressed", "rar", "sevenzip", "tar", "zip"})
_PROTOBUF_MODEL_CANDIDATE_SCANNER_ID = "protobuf_model_candidate"
_PROTOBUF_MODEL_CANDIDATE_ANALYZER_IDS = frozenset({"onnx", "coreml"})
_ZIP_STRUCTURE_ROUTED_SCANNER_IDS = frozenset(
    {
        "executorch",
        "keras_zip",
        "numpy",
        "pytorch_zip",
        "skops",
        "torchserve_mar",
        "weight_distribution",
        "zip",
    }
)
_ZIP_CONTENT_ROUTED_SCANNER_IDS = frozenset(
    {
        "executorch",
        "keras_zip",
        "pytorch_zip",
        "skops",
        "torchserve_mar",
        "zip",
    }
)
_ZIP_EXTENSION_ROUTE_OVERRIDES = {
    "numpy": frozenset({".npz"}),
}


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


@lru_cache(maxsize=1)
def _scanner_metadata() -> dict[str, dict[str, Any]]:
    """Return the static registry metadata used by hot selection paths."""
    return get_scanner_registry_metadata()


@lru_cache(maxsize=1)
def _scanner_aliases() -> dict[str, str]:
    """Return canonical aliases derived from the static registry metadata."""
    aliases: dict[str, str] = {}

    def add(alias: str, scanner_id: str) -> None:
        key = _alias_key(alias)
        if key:
            aliases.setdefault(key, scanner_id)

    for scanner_id, scanner_info in _scanner_metadata().items():
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
    metadata = _scanner_metadata()
    aliases = _scanner_aliases()
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
        candidate_ids = sorted(set(metadata.keys()) | set(aliases.values()))
        suggestions: list[str] = []
        for bad in unknown:
            close = difflib.get_close_matches(bad.lower(), candidate_ids, n=2, cutoff=0.6)
            if close:
                suggestions.append(f"{bad} (did you mean: {', '.join(close)}?)")
            else:
                suggestions.append(bad)
        available = ", ".join(sorted(metadata.keys()))
        raise ValueError(f"Unknown scanner name(s): {'; '.join(suggestions)}. Available scanners: {available}")

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


def allows_protobuf_model_candidate_analysis(policy: ScannerSelectionPolicy) -> bool:
    """Return whether a bounded protobuf candidate may receive concrete analysis."""
    if _PROTOBUF_MODEL_CANDIDATE_SCANNER_ID in policy.exclude_scanner_ids:
        return False
    return policy.allows(_PROTOBUF_MODEL_CANDIDATE_SCANNER_ID) or any(
        policy.allows(scanner_id) for scanner_id in _PROTOBUF_MODEL_CANDIDATE_ANALYZER_IDS
    )


def allows_zip_structure_analysis(policy: ScannerSelectionPolicy, path: str | None = None) -> bool:
    """Return whether a selected route may analyze ZIP structure for this path."""
    if "zip" in policy.exclude_scanner_ids:
        return False
    selected_zip_scanner_ids = {
        scanner_id for scanner_id in _ZIP_STRUCTURE_ROUTED_SCANNER_IDS if policy.allows(scanner_id)
    }
    if not selected_zip_scanner_ids or path is None or not policy.active:
        return bool(selected_zip_scanner_ids)
    if selected_zip_scanner_ids & _ZIP_CONTENT_ROUTED_SCANNER_IDS:
        return True

    extension = os.path.splitext(path)[1].lower()
    metadata = _scanner_metadata()
    for scanner_id in selected_zip_scanner_ids:
        scanner_info = metadata.get(scanner_id, {})
        routed_extensions = {
            str(value).lower()
            for key in ("extensions", "content_routed_extensions", "scanner_only_extensions")
            for value in scanner_info.get(key, ())
        }
        routed_extensions.update(_ZIP_EXTENSION_ROUTE_OVERRIDES.get(scanner_id, ()))
        if extension in routed_extensions:
            return True
    return False


def allows_zip_content_analysis(policy: ScannerSelectionPolicy) -> bool:
    """Return whether selection permits content-routed ZIP container analysis."""
    if "zip" in policy.exclude_scanner_ids:
        return False
    return any(policy.allows(scanner_id) for scanner_id in _ZIP_CONTENT_ROUTED_SCANNER_IDS)


def allows_protobuf_model_candidate_analyzer(policy: ScannerSelectionPolicy, scanner_id: str) -> bool:
    """Keep internal candidate delegation within the user's scanner policy."""
    if scanner_id not in _PROTOBUF_MODEL_CANDIDATE_ANALYZER_IDS:
        return False
    if not allows_protobuf_model_candidate_analysis(policy) or scanner_id in policy.exclude_scanner_ids:
        return False
    return policy.allows(_PROTOBUF_MODEL_CANDIDATE_SCANNER_ID) or policy.allows(scanner_id)


def resolve_scanner_selection_policy(
    *,
    scanners: Iterable[str] | str | None = None,
    exclude_scanners: Iterable[str] | str | None = None,
) -> ScannerSelectionPolicy:
    """Resolve raw scanner selection inputs into a policy."""
    return _resolve_scanner_selection_policy_cached(
        tuple(split_scanner_tokens(scanners)),
        tuple(split_scanner_tokens(exclude_scanners)),
    )


@lru_cache(maxsize=256)
def _resolve_scanner_selection_policy_cached(
    scanners: tuple[str, ...],
    exclude_scanners: tuple[str, ...],
) -> ScannerSelectionPolicy:
    metadata = _scanner_metadata()
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
        normalized_policy = _policy_from_normalized_selection(raw_selection)
        if normalized_policy is not None:
            return normalized_policy
        return resolve_scanner_selection_policy(
            scanners=raw_selection.get("scanners"),
            exclude_scanners=raw_selection.get("exclude_scanners"),
        )

    return resolve_scanner_selection_policy(
        scanners=raw_config.get("scanners"),
        exclude_scanners=raw_config.get("exclude_scanners"),
    )


def _policy_from_normalized_selection(selection: Mapping[str, Any]) -> ScannerSelectionPolicy | None:
    """Rehydrate a policy from ``to_config()`` output without re-resolving aliases."""
    active = selection.get("active")
    enabled_values = selection.get("enabled_scanner_ids")
    if not isinstance(active, bool) or not isinstance(enabled_values, list):
        return None

    all_scanner_ids = frozenset(_scanner_metadata().keys())

    def parse_ids(value: Any, *, allow_none: bool = False) -> frozenset[str] | None:
        if value is None and allow_none:
            return frozenset()
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            return None
        ids = frozenset(value)
        return ids if ids <= all_scanner_ids else None

    enabled_ids = parse_ids(enabled_values)
    exact_ids = parse_ids(selection.get("scanners"), allow_none=True)
    exclude_ids = parse_ids(selection.get("exclude_scanners"))
    if enabled_ids is None or exact_ids is None or exclude_ids is None:
        return None

    expected_enabled = frozenset((exact_ids or all_scanner_ids) - exclude_ids)
    if enabled_ids != expected_enabled or active != bool(exact_ids or exclude_ids):
        return None
    if active and not enabled_ids:
        return None

    return ScannerSelectionPolicy(
        enabled_scanner_ids=enabled_ids,
        all_scanner_ids=all_scanner_ids,
        exact_scanner_ids=exact_ids,
        exclude_scanner_ids=exclude_ids,
        active=active,
    )


def normalize_scanner_selection_config(config: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a mutable config with a normalized scanner selection payload."""
    normalized = dict(config or {})
    raw_selection = normalized.get(SCANNER_SELECTION_CONFIG_KEY)
    if (
        "scanners" not in normalized
        and "exclude_scanners" not in normalized
        and isinstance(raw_selection, Mapping)
        and _policy_from_normalized_selection(raw_selection) is not None
    ):
        return normalized

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
    metadata = _scanner_metadata()
    extensions: set[str] = set()
    for scanner_id in policy.enabled_scanner_ids:
        scanner_info = metadata.get(scanner_id, {})
        if conservative and (scanner_id in _GENERIC_CONTAINER_SCANNER_IDS or scanner_info.get("header_formats")):
            return None
        remote_excluded_extensions = (
            {str(extension).lower() for extension in scanner_info.get("remote_excluded_extensions", [])}
            if conservative
            else set()
        )
        for key in ("extensions", "content_routed_extensions", "scanner_only_extensions"):
            for extension in scanner_info.get(key, []):
                extension_text = str(extension).lower()
                if extension_text not in remote_excluded_extensions:
                    extensions.add(extension_text)
    return frozenset(extensions)


def selected_scanner_filenames(
    policy: ScannerSelectionPolicy,
    *,
    conservative: bool = False,
) -> frozenset[str]:
    """Return exact basenames routed by the policy's enabled scanners."""
    metadata = _scanner_metadata()
    filenames: set[str] = set()
    for scanner_id in policy.enabled_scanner_ids:
        scanner_info = metadata.get(scanner_id, {})
        remote_excluded_extensions = (
            {str(extension).lower() for extension in scanner_info.get("remote_excluded_extensions", [])}
            if conservative
            else set()
        )
        for filename in scanner_info.get("content_routed_filenames", []):
            filename_text = str(filename).lower()
            if os.path.splitext(filename_text)[1] not in remote_excluded_extensions:
                filenames.add(filename_text)
    return frozenset(filenames)


@cache
def scanner_ids_for_extension(extension: str) -> frozenset[str]:
    """Return scanners that claim a normalized filename extension."""
    normalized_extension = extension.lower()
    scanner_ids: set[str] = set()
    for scanner_id, scanner_info in _scanner_metadata().items():
        for key in ("extensions", "content_routed_extensions"):
            if normalized_extension in {str(value).lower() for value in scanner_info.get(key, ())}:
                scanner_ids.add(scanner_id)
                break
    return frozenset(scanner_ids)


def scanner_ids_for_detected_format(detected_format: str) -> frozenset[str]:
    """Return scanners that can analyze a trusted content-routed format."""
    from modelaudit.utils.file.detection import (
        EXECUTABLE_ZIP_POLYGLOT_FORMAT,
        LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
        MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT,
        PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
        TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
        XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT,
        XML_MODEL_INCONCLUSIVE_FORMAT,
    )

    scanner_ids: set[str] = set()
    for scanner_id, scanner_info in _scanner_metadata().items():
        if detected_format == scanner_id or detected_format in scanner_info.get("header_formats", ()):
            scanner_ids.add(scanner_id)
    if detected_format in {"zip", EXECUTABLE_ZIP_POLYGLOT_FORMAT}:
        scanner_ids.update(_ZIP_STRUCTURE_ROUTED_SCANNER_IDS)
    if detected_format == EXECUTABLE_ZIP_POLYGLOT_FORMAT:
        scanner_ids.add("safetensors")
    if detected_format in {"tar", "gzip", "bzip2", "xz"}:
        scanner_ids.add("nemo")
    if detected_format in {"gzip", "bzip2", "xz"}:
        scanner_ids.add("tar")
    if detected_format == "safetensors":
        scanner_ids.update({"compressed", "keras_h5", "llamafile", "pickle", "torch7"})
        scanner_ids.update(_ZIP_STRUCTURE_ROUTED_SCANNER_IDS)
    if detected_format in {"llamafile", LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT}:
        scanner_ids.add("llamafile")
        scanner_ids.add("safetensors")
        scanner_ids.update(_ZIP_STRUCTURE_ROUTED_SCANNER_IDS)
    if detected_format == PROTOBUF_MODEL_CANDIDATE_FORMAT:
        scanner_ids.update({"coreml", "onnx", "tf_metagraph", "tf_savedmodel"})
    if detected_format == TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT:
        scanner_ids.update({"tf_metagraph", "tf_savedmodel"})
    if detected_format == MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT:
        scanner_ids.update({"jax_checkpoint", "mxnet"})
    if detected_format == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT:
        scanner_ids.add("xgboost")
    if detected_format == PICKLE_ROUTING_INCONCLUSIVE_FORMAT:
        scanner_ids.add("pickle")
    if detected_format == XML_MODEL_INCONCLUSIVE_FORMAT:
        scanner_ids.update({"openvino", "pmml"})
    return frozenset(scanner_ids)


SCANNER_SELECTION_CHECK_NAME = "Scanner Selection"
SCANNER_SELECTION_PREFERRED_KIND: ScannerSelectionSkipKind = "preferred"
SCANNER_SELECTION_EMBEDDED_KIND: ScannerSelectionSkipKind = "embedded"


def add_scanner_selection_skip_check(
    result: ScanResult,
    location: str,
    scanner_id: str | None,
    policy: ScannerSelectionPolicy,
    *,
    context: str | None = None,
    kind: ScannerSelectionSkipKind = SCANNER_SELECTION_EMBEDDED_KIND,
) -> None:
    """Add a check documenting a scanner that was skipped by selection policy.

    ``kind`` controls severity: ``"preferred"`` uses WARNING because the
    selection suppressed the scanner that routing would have picked for the
    file (a potential coverage gap); ``"embedded"`` uses INFO because the file
    is still being analyzed by its primary scanner and only an auxiliary
    embedded pass was skipped.
    """
    result.metadata.setdefault("scanner_selection", policy.to_metadata())
    skipped_scanner_ids = result.metadata.setdefault("skipped_scanner_ids", [])
    if isinstance(skipped_scanner_ids, list) and scanner_id and scanner_id not in skipped_scanner_ids:
        skipped_scanner_ids.append(scanner_id)

    scanner_label = scanner_id or "candidate scanner"
    message = f"Skipped {scanner_label} because it is not enabled by scanner selection policy"
    if context:
        message = f"{message} ({context})"

    severity = IssueSeverity.WARNING if kind == SCANNER_SELECTION_PREFERRED_KIND else IssueSeverity.INFO

    result.add_check(
        name=SCANNER_SELECTION_CHECK_NAME,
        passed=True,
        message=message,
        severity=severity,
        location=location,
        details={
            "skipped_scanner_id": scanner_id,
            "context": context,
            "kind": kind,
        },
    )


def make_scanner_selection_skip_result(
    path: str,
    scanner_id: str | None,
    policy: ScannerSelectionPolicy,
    *,
    kind: ScannerSelectionSkipKind = SCANNER_SELECTION_PREFERRED_KIND,
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

    add_scanner_selection_skip_check(result, path, scanner_id, policy, kind=kind)
    result.finish(success=True)
    return result


def embedded_pickle_scanner(
    config: Mapping[str, Any] | None,
    pickle_scanner_factory: Any,
) -> tuple[Any, ScannerSelectionPolicy]:
    """Instantiate an embedded pickle helper scanner only if selection allows it.

    Returns ``(scanner, policy)``. The scanner is ``None`` when pickle analysis
    is disabled by the active selection policy; callers should record a
    scanner-selection skip check for each embedded pickle they would have
    scanned and continue processing.
    """
    policy = policy_from_config(config)
    scanner = pickle_scanner_factory(config) if policy.allows("pickle") else None
    return scanner, policy


def collect_suppressed_preferred_scanners(checks: Iterable[Any]) -> list[dict[str, Any]]:
    """Return one entry per (scanner_id, location) flagged as preferred skip.

    Walks scan result checks and filters to preferred-kind Scanner Selection
    skips — the coverage-gap signal that CLI, SDK, and CI consumers need when
    a selection policy suppressed the scanner that routing would have picked.
    """
    aggregated: dict[tuple[str, str], dict[str, Any]] = {}
    for check in checks:
        if getattr(check, "name", None) != SCANNER_SELECTION_CHECK_NAME:
            continue
        details = getattr(check, "details", None)
        if not isinstance(details, Mapping) or details.get("kind") != SCANNER_SELECTION_PREFERRED_KIND:
            continue
        scanner_id = str(details.get("skipped_scanner_id") or "unknown")
        location = getattr(check, "location", None) or "<unknown>"
        aggregated.setdefault(
            (scanner_id, location),
            {"scanner_id": scanner_id, "location": location, "context": details.get("context")},
        )
    return sorted(aggregated.values(), key=lambda entry: (entry["scanner_id"], entry["location"]))
