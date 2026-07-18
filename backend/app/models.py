from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MissionStage(str, Enum):
    QUEUED = "queued"
    CLONING = "cloning"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    PATCH_READY = "patch_ready"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class StartMissionRequest(BaseModel):
    repository_url: str = Field(min_length=1, max_length=2048)


class StartMissionResponse(BaseModel):
    mission_id: str


class TimelineEvent(BaseModel):
    label: str
    detail: str
    status: Literal["complete", "active", "pending"]
    occurred_at: datetime = Field(default_factory=utc_now)


class TraceEvent(BaseModel):
    id: str
    agent: str
    action: str
    status: Literal["running", "completed", "failed"]
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    detail: str
    attributes: dict[str, str | int | bool] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    fingerprint: str
    rule_id: str
    title: str
    severity: Severity
    scanner: str
    file_path: str
    line: int
    description: str
    status: Literal["open", "analyzed", "patch_ready", "verified"] = "open"


class TriageDecision(BaseModel):
    """A bounded priority decision made from scanner metadata, never source contents."""

    finding_id: str
    priority_rank: int = Field(ge=1)
    rationale: str
    next_step: str
    source: Literal["gemini", "openai", "deterministic"] = "deterministic"
    model: str | None = None


class PatchReview(BaseModel):
    """Independent safety review of a draft patch; it never applies the patch."""

    finding_id: str
    verdict: Literal["approved", "changes_requested", "manual_review"]
    summary: str
    concerns: list[str] = Field(default_factory=list)
    source: Literal["gemini", "openai", "fallback"] = "fallback"
    model: str | None = None
    reviewed_at: datetime = Field(default_factory=utc_now)


class ScannerStatus(BaseModel):
    scanner: str
    status: Literal["complete", "unavailable", "failed"]
    detail: str


class Mission(BaseModel):
    id: str
    repository_url: str
    repository_name: str
    stage: MissionStage
    progress: int = Field(ge=0, le=100)
    security_score: int = Field(ge=0, le=100)
    initial_security_score: int = Field(ge=0, le=100)
    workspace_path: str = Field(default="", exclude=True)
    scanners: list[ScannerStatus] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    trace: list[TraceEvent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    triage: list[TriageDecision] = Field(default_factory=list)
    error: str | None = None
    latest_verification: "VerificationResult | None" = None


class Explanation(BaseModel):
    finding_id: str
    root_cause: str
    impact: str
    recommendation: str
    confidence: int = Field(ge=0, le=100)
    patch_before: str
    patch_after: str
    patch_is_actionable: bool = True
    source: Literal["openai", "gemini", "fallback", "policy"] = "fallback"
    model: str | None = None
    notice: str | None = None


class PatchProposal(BaseModel):
    id: str
    finding_id: str
    file_path: str
    patch_before: str
    patch_after: str
    summary: str
    source_sha256: str = ""
    source_line: int = Field(default=1, ge=1)
    status: Literal["draft", "applied", "verified", "failed"] = "draft"
    created_at: datetime = Field(default_factory=utc_now)
    validation_note: str = "This patch has not been applied. Human approval is required."
    review: PatchReview | None = None


class VerificationResult(BaseModel):
    id: str
    mission_id: str
    patch_id: str
    finding_id: str
    status: Literal["verified", "failed"]
    detail: str
    scanner: str
    findings_before: int = Field(ge=0)
    findings_after: int = Field(ge=0)
    security_score_before: int = Field(ge=0, le=100)
    security_score_after: int = Field(ge=0, le=100)
    verified_at: datetime = Field(default_factory=utc_now)


class MissionReport(BaseModel):
    mission_id: str
    repository_name: str
    stage: MissionStage
    security_score_before: int = Field(ge=0, le=100)
    security_score_after: int = Field(ge=0, le=100)
    summary: str
    severity_counts: dict[str, int]
    findings: list[Finding]
    scanners: list[ScannerStatus]
    timeline: list[TimelineEvent]
    trace: list[TraceEvent]
    triage: list[TriageDecision]
    latest_verification: VerificationResult | None = None
    generated_at: datetime = Field(default_factory=utc_now)
