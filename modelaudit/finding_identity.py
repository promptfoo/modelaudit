"""Retain producer-derived identity inputs separately from displayed evidence."""

from typing import Any

_FIELDS = frozenset({"message", "location", "type", "rule_code", "name"})
_DETAIL_FIELDS = frozenset({"evidence_fingerprint", "zip_entry_id", "zip_entry", "check_consolidation_key"})


def finding_identity(record: Any) -> Any:
    """Return an identity copy, accepting only producer-stamped record metadata."""
    metadata = record.get("finding_identity") if isinstance(record, dict) else getattr(record, "finding_identity", None)
    if not isinstance(metadata, dict):
        return record
    producer = metadata.get("producer")
    if not isinstance(producer, str) or producer not in {
        "mlflow_acquisition",
        "directory_owner",
        "stream",
        "huggingface_acquisition",
        "check_consolidation",
    }:
        return record
    fields = metadata.get("fields")
    if not isinstance(fields, dict):
        return record
    updates: dict[str, Any] = {
        name: value for name, value in fields.items() if name in _FIELDS and isinstance(value, str)
    }
    details = fields.get("details")
    if isinstance(details, dict):
        original = record.get("details", {}) if isinstance(record, dict) else record.details
        updates["details"] = {
            **(original if isinstance(original, dict) else {}),
            **{name: value for name, value in details.items() if name in _DETAIL_FIELDS and isinstance(value, str)},
        }
    return {**record, **updates} if isinstance(record, dict) else record.model_copy(update=updates)


def preserve_finding_identity(record: Any, producer: str, **fields: Any) -> None:
    """Store only identity inputs changed by raw evidence presentation."""
    get = record.get if isinstance(record, dict) else lambda name: getattr(record, name, None)
    changed = {name: value for name, value in fields.items() if name != "details" and value != get(name)}
    if isinstance(fields.get("details"), dict):
        details = {
            name: value for name, value in fields["details"].items() if value != (get("details") or {}).get(name)
        }
        if details:
            changed["details"] = details
    if changed:
        metadata = {"producer": producer, "fields": changed}
        if isinstance(record, dict):
            record["finding_identity"] = metadata
        else:
            record.finding_identity = metadata
