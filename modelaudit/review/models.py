"""Separate contracts for agent assertions and supervisor-owned provenance."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "modelaudit-review-v1"
POLICY_VERSION = "documentation-v1"
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_GROUP_FINDINGS = 8
ReviewStatus = Literal["complete", "partial", "failed", "not_needed", "not_requested"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Artifact(Contract):
    path: str
    sha256: str
    size: int
    role: Literal["documentation", "artifact"]


class Evidence(Contract):
    evidence_id: str
    artifact_path: str
    artifact_sha256: str
    sha256: str
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int
    complete: bool
    encoding: Literal["utf-8", "unavailable"]
    text: str


class Finding(Contract):
    finding_id: str
    pointer: str
    record: dict[str, Any]
    artifact_path: str | None
    evidence_ids: list[str]
    selected: bool
    selection_reason: str


class Assessment(Contract):
    finding_id: str
    assessment: Literal["benign_context", "false_positive", "actionable", "inconclusive"]
    context: Literal["documentation", "executable_artifact", "configuration", "unknown"]
    trigger: Literal["user_follows_documentation", "model_load", "none_established", "unknown"]
    explanation: str = Field(min_length=1, max_length=6000)
    evidence_ids: list[str] = Field(min_length=1, max_length=16)
    execution_implications: str = Field(min_length=1, max_length=3000)
    limitations: list[str] = Field(max_length=16)


class AgentResponse(Contract):
    assessments: list[Assessment] = Field(min_length=1, max_length=MAX_GROUP_FINDINGS)


class ReviewEntry(Contract):
    finding_id: str
    pointer: str
    status: Literal["reviewed", "not_reviewed", "failed"]
    display_action: Literal["retain", "de_emphasize"]
    assessment: Assessment | None
    reason: str


class ReviewReport(Contract):
    schema_version: str = SCHEMA_VERSION
    policy_version: str = POLICY_VERSION
    scan_sha256: str
    scan_exit_code: int
    scanner_issue_count: int | None = None
    scanner_failed_check_count: int | None = None
    review_status: ReviewStatus
    selected_count: int
    reviewed_count: int
    entries: list[ReviewEntry]
    errors: list[str]
