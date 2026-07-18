from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from time import perf_counter
from uuid import uuid4

from app.ai_service import AnalysisService
from app.models import (
    Explanation,
    Finding,
    Mission,
    MissionReport,
    MissionStage,
    PatchProposal,
    ScannerStatus,
    Severity,
    TimelineEvent,
    TraceEvent,
    VerificationResult,
    utc_now,
)
from app.patch_service import PatchError, PatchService
from app.report_service import ReportService
from app.repository_service import RepositoryError, RepositoryService
from app.scanner_service import ScannerService
from app.verification_service import VerificationService


class MissionNotFoundError(Exception):
    """The requested mission does not exist in the temporary mission store."""


class WorkflowError(Exception):
    """A mission action is not valid in its current workflow state."""


@dataclass
class _MissionRecord:
    mission: Mission
    analyses: dict[str, Explanation] = field(default_factory=dict)
    proposals: dict[str, PatchProposal] = field(default_factory=dict)
    lock: RLock = field(default_factory=RLock)


class MissionService:
    """Security mission orchestrator for scan, remediation, verification, and reporting."""

    _SEVERITY_ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }

    def __init__(self) -> None:
        self._records: dict[str, _MissionRecord] = {}
        self._records_lock = RLock()
        self._repository_service = RepositoryService()
        self._scanner_service = ScannerService()
        self._analysis_service = AnalysisService()
        self._patch_service = PatchService()
        self._verification_service = VerificationService(self._scanner_service, self._patch_service)
        self._report_service = ReportService()

    def create(self, repository_url: str) -> Mission:
        """Create an observable queued mission; `execute` performs the expensive work."""
        repository_name = self._repository_service.validate_url(repository_url)
        mission_id = str(uuid4())
        mission = Mission(
            id=mission_id,
            repository_url=repository_url,
            repository_name=repository_name,
            stage=MissionStage.QUEUED,
            progress=0,
            security_score=100,
            initial_security_score=100,
            timeline=[
                TimelineEvent(
                    label="Mission queued",
                    detail="Repository intake is waiting for the security worker.",
                    status="active",
                )
            ],
            trace=[
                TraceEvent(
                    id=str(uuid4()),
                    agent="Mission Coordinator",
                    action="Create mission",
                    status="completed",
                    completed_at=utc_now(),
                    duration_ms=0,
                    detail="Accepted a repository security mission.",
                    attributes={"repository_host": "github.com"},
                )
            ],
        )
        with self._records_lock:
            self._records[mission_id] = _MissionRecord(mission=mission)
        return mission.model_copy(deep=True)

    def start(self, repository_url: str) -> Mission:
        """Synchronous compatibility helper for scripts and local tests."""
        mission = self.create(repository_url)
        self.execute(mission.id)
        completed = self.get(mission.id)
        if completed is None:
            raise MissionNotFoundError("Mission disappeared before it could complete.")
        return completed

    def execute(self, mission_id: str) -> None:
        """Run clone, scan, and a bounded first-pass AI triage in a background task."""
        record = self._record(mission_id)
        try:
            with record.lock:
                self._advance(
                    record.mission,
                    stage=MissionStage.CLONING,
                    progress=10,
                    label="Repository intake",
                    detail="Cloning a shallow, public GitHub workspace.",
                )
                repository_url = record.mission.repository_url

            trace_id, started = self._trace_started(
                record.mission, "Repository Agent", "Clone repository", "Preparing an isolated shallow repository workspace."
            )
            try:
                repository_name, workspace_path = self._repository_service.clone(repository_url, mission_id)
            except Exception as error:
                self._trace_finished(record.mission, trace_id, started, "failed", "Repository clone failed.", {"error_type": type(error).__name__})
                raise
            self._trace_finished(record.mission, trace_id, started, "completed", "Repository workspace prepared.")
            with record.lock:
                record.mission.repository_name = repository_name
                record.mission.workspace_path = str(workspace_path)
                self._advance(
                    record.mission,
                    stage=MissionStage.SCANNING,
                    progress=25,
                    label="Repository cloned",
                    detail="Temporary workspace prepared for security analysis.",
                )

            trace_id, started = self._trace_started(
                record.mission, "Scanner Agent", "Run security scanners", "Running configured scanners against the isolated workspace."
            )
            try:
                findings, scanners = self._scanner_service.scan(workspace_path)
            except Exception as error:
                self._trace_finished(record.mission, trace_id, started, "failed", "Security scan failed.", {"error_type": type(error).__name__})
                raise
            self._trace_finished(
                record.mission, trace_id, started, "completed", "Security scanners completed.",
                {"finding_count": len(findings), "scanner_count": len(scanners)},
            )
            with record.lock:
                record.mission.findings = findings
                record.mission.scanners = scanners
                score = self._security_score(findings)
                record.mission.initial_security_score = score
                record.mission.security_score = score
                self._advance(
                    record.mission,
                    stage=MissionStage.ANALYZING,
                    progress=60,
                    label="Security scan complete",
                    detail=self._scanner_summary(scanners, findings),
                )
                findings_to_triage = sorted(
                    (finding.model_copy(deep=True) for finding in findings),
                    key=lambda finding: self._SEVERITY_ORDER[finding.severity],
                )[:3]
                workspace_for_analysis = Path(record.mission.workspace_path)

            if not findings_to_triage:
                with record.lock:
                    self._advance(
                        record.mission,
                        stage=MissionStage.VERIFIED,
                        progress=100,
                        label="No actionable findings",
                        detail="Completed scanners reported no findings. Review scanner availability in the mission report.",
                        terminal=True,
                    )
                return

            trace_id, started = self._trace_started(
                record.mission, "Remediation Agent", "Analyze prioritized findings", "Preparing bounded AI remediation from scanner evidence."
            )
            try:
                analyses: dict[str, Explanation] = {}
                for finding in findings_to_triage:
                    analyses[finding.id] = self._analysis_service.analyze(finding, workspace_for_analysis)
            except Exception as error:
                self._trace_finished(record.mission, trace_id, started, "failed", "AI remediation preparation failed.", {"error_type": type(error).__name__})
                raise
            self._trace_finished(
                record.mission, trace_id, started, "completed", "Remediation guidance prepared.",
                {"finding_count": len(analyses), "ai_response_count": sum(item.source in {"openai", "gemini"} for item in analyses.values())},
            )

            with record.lock:
                for finding_id, analysis in analyses.items():
                    record.analyses[finding_id] = analysis
                    finding = self._finding(record.mission, finding_id)
                    finding.status = "patch_ready" if analysis.patch_is_actionable else "analyzed"
                self._advance(
                    record.mission,
                    stage=MissionStage.PATCH_READY,
                    progress=80,
                    label="AI remediation prepared",
                    detail=f"Prepared evidence-backed guidance for {len(analyses)} highest-risk finding(s).",
                )
        except RepositoryError as error:
            with record.lock:
                self._fail(record.mission, str(error))
        except Exception:
            with record.lock:
                self._fail(record.mission, "The security mission could not complete. Check scanner status and try again.")

    def get(self, mission_id: str) -> Mission | None:
        try:
            record = self._record(mission_id)
        except MissionNotFoundError:
            return None
        with record.lock:
            return record.mission.model_copy(deep=True)

    def get_findings(self, mission_id: str) -> list[Finding]:
        record = self._record(mission_id)
        with record.lock:
            return [finding.model_copy(deep=True) for finding in record.mission.findings]

    def analyze(self, mission_id: str, finding_id: str) -> Explanation:
        record = self._record(mission_id)
        with record.lock:
            mission = record.mission
            self._assert_ready_for_remediation(mission)
            cached = record.analyses.get(finding_id)
            if cached is not None:
                return cached.model_copy(deep=True)
            finding = self._finding(mission, finding_id).model_copy(deep=True)
            workspace_path = Path(mission.workspace_path)
            self._advance(
                mission,
                stage=MissionStage.ANALYZING,
                progress=max(mission.progress, 70),
                label="AI analysis requested",
                detail=f"Preparing remediation evidence for {finding.title}.",
            )

        trace_id, started = self._trace_started(
            mission, "Remediation Agent", "Analyze finding", f"Preparing remediation for {finding.rule_id}."
        )
        try:
            analysis = self._analysis_service.analyze(finding, workspace_path)
        except Exception as error:
            self._trace_finished(mission, trace_id, started, "failed", "AI analysis failed.", {"error_type": type(error).__name__})
            raise
        self._trace_finished(
            mission, trace_id, started, "completed", "Remediation analysis prepared.",
            {"source": analysis.source, "actionable_patch": analysis.patch_is_actionable},
        )
        with record.lock:
            record.analyses[finding_id] = analysis
            target = self._finding(record.mission, finding_id)
            target.status = "patch_ready" if analysis.patch_is_actionable else "analyzed"
            self._advance(
                record.mission,
                stage=MissionStage.PATCH_READY,
                progress=max(record.mission.progress, 82),
                label="AI remediation prepared",
                detail=f"Remediation guidance is ready for {target.title}.",
            )
            return analysis.model_copy(deep=True)

    def propose_patch(self, mission_id: str, finding_id: str) -> PatchProposal:
        record = self._record(mission_id)
        with record.lock:
            existing = next((proposal for proposal in record.proposals.values() if proposal.finding_id == finding_id), None)
            if existing is not None:
                return existing.model_copy(deep=True)

        analysis = self.analyze(mission_id, finding_id)
        if not analysis.patch_is_actionable:
            raise WorkflowError("This finding requires human remediation and cannot receive an automatic source patch.")

        with record.lock:
            finding = self._finding(record.mission, finding_id)
            source_path = self._patch_service.source_path(Path(record.mission.workspace_path), finding.file_path)
            proposal = PatchProposal(
                id=str(uuid4()),
                finding_id=finding.id,
                file_path=finding.file_path,
                patch_before=analysis.patch_before,
                patch_after=analysis.patch_after,
                summary=analysis.recommendation,
                source_sha256=self._patch_service.source_sha256(source_path),
                source_line=finding.line,
            )
            record.proposals[proposal.id] = proposal
            return proposal.model_copy(deep=True)

    def verify_patch(self, mission_id: str, patch_id: str) -> VerificationResult:
        record = self._record(mission_id)
        with record.lock:
            mission = record.mission
            self._assert_ready_for_remediation(mission)
            proposal = record.proposals.get(patch_id)
            if proposal is None:
                raise WorkflowError("Patch proposal not found for this mission.")
            if proposal.status == "verified":
                raise WorkflowError("This patch has already been verified.")
            finding = self._finding(mission, proposal.finding_id)
            if finding.status == "verified":
                raise WorkflowError("This finding has already been verified.")
            workspace_path = Path(mission.workspace_path)
            score_before = mission.security_score
            self._advance(
                mission,
                stage=MissionStage.VERIFYING,
                progress=max(mission.progress, 88),
                label="Patch verification started",
                detail="Testing the approved patch in an isolated workspace before touching the mission source.",
            )

        trace_id, started = self._trace_started(
            mission, "Verification Agent", "Verify patch", "Applying the patch in a separate workspace and rescanning it."
        )
        try:
            result = self._verification_service.verify(
                mission_id=mission_id,
                workspace=workspace_path,
                finding=finding.model_copy(deep=True),
                proposal=proposal.model_copy(deep=True),
                security_score_before=score_before,
            )
        except Exception as error:
            self._trace_finished(mission, trace_id, started, "failed", "Patch verification failed to run.", {"error_type": type(error).__name__})
            raise
        self._trace_finished(
            mission, trace_id, started, "completed" if result.status == "verified" else "failed", result.detail,
            {"scanner": result.scanner, "findings_before": result.findings_before, "findings_after": result.findings_after},
        )

        with record.lock:
            mission = record.mission
            current_proposal = record.proposals[patch_id]
            target = self._finding(mission, current_proposal.finding_id)
            if result.status == "verified":
                try:
                    self._patch_service.apply(Path(mission.workspace_path), current_proposal)
                except PatchError as error:
                    result = result.model_copy(
                        update={
                            "status": "failed",
                            "detail": f"The isolated test passed, but Kavach could not apply the patch to the mission workspace: {error}",
                        }
                    )
                else:
                    target.status = "verified"
                    current_proposal.status = "applied"
                    score_after = self._security_score(mission.findings)
                    result = result.model_copy(update={"security_score_after": score_after})
                    current_proposal.status = "verified"
                    mission.security_score = score_after

            mission.latest_verification = result
            if result.status == "verified":
                remaining = [item for item in mission.findings if item.status != "verified"]
                if remaining:
                    self._advance(
                        mission,
                        stage=MissionStage.PATCH_READY,
                        progress=92,
                        label="Patch verified",
                        detail="The approved patch was applied after an isolated scanner verification. More findings remain.",
                    )
                else:
                    self._advance(
                        mission,
                        stage=MissionStage.VERIFIED,
                        progress=100,
                        label="Mission verified",
                        detail="No open findings remain in the mission record after scanner-backed verification.",
                        terminal=True,
                    )
            else:
                current_proposal.status = "failed"
                self._advance(
                    mission,
                    stage=MissionStage.PATCH_READY,
                    progress=88,
                    label="Patch verification failed",
                    detail=result.detail,
                )
            return result.model_copy(deep=True)

    def report(self, mission_id: str) -> MissionReport:
        record = self._record(mission_id)
        with record.lock:
            return self._report_service.build(record.mission.model_copy(deep=True))

    def html_report(self, mission_id: str) -> str:
        record = self._record(mission_id)
        with record.lock:
            return self._report_service.build_html(
                record.mission.model_copy(deep=True),
                {finding_id: analysis.model_copy(deep=True) for finding_id, analysis in record.analyses.items()},
                {patch_id: proposal.model_copy(deep=True) for patch_id, proposal in record.proposals.items()},
            )

    def cleanup(self, mission_id: str) -> None:
        with self._records_lock:
            record = self._records.pop(mission_id, None)
        if record is not None and record.mission.workspace_path:
            self._repository_service.cleanup(mission_id)

    def explain(self, finding_id: str) -> Explanation | None:
        """Legacy unscoped endpoint support. New clients must use mission-scoped analysis."""
        with self._records_lock:
            records = list(self._records.items())
        for mission_id, record in records:
            with record.lock:
                if any(finding.id == finding_id for finding in record.mission.findings):
                    break
        else:
            return None
        return self.analyze(mission_id, finding_id)

    def _record(self, mission_id: str) -> _MissionRecord:
        with self._records_lock:
            record = self._records.get(mission_id)
        if record is None:
            raise MissionNotFoundError("Mission not found.")
        return record

    @staticmethod
    def _finding(mission: Mission, finding_id: str) -> Finding:
        finding = next((item for item in mission.findings if item.id == finding_id), None)
        if finding is None:
            raise WorkflowError("Finding not found for this mission.")
        return finding

    @staticmethod
    def _scanner_summary(scanners: list[ScannerStatus], findings: list[Finding]) -> str:
        completed = sum(scanner.status == "complete" for scanner in scanners)
        return f"{completed} of {len(scanners)} scanners completed and found {len(findings)} normalized finding(s)."

    @staticmethod
    def _security_score(findings: list[Finding]) -> int:
        penalties = {Severity.CRITICAL: 30, Severity.HIGH: 18, Severity.MEDIUM: 8, Severity.LOW: 3}
        return max(0, 100 - sum(penalties[finding.severity] for finding in findings if finding.status != "verified"))

    @staticmethod
    def _assert_ready_for_remediation(mission: Mission) -> None:
        if mission.stage in {MissionStage.QUEUED, MissionStage.CLONING, MissionStage.SCANNING}:
            raise WorkflowError("Security scanning is still in progress. Wait for the mission to reach AI analysis.")
        if mission.stage == MissionStage.FAILED:
            raise WorkflowError(mission.error or "This mission failed before remediation could begin.")
        if not mission.workspace_path:
            raise WorkflowError("The mission workspace is not ready yet.")

    @staticmethod
    def _advance(
        mission: Mission,
        *,
        stage: MissionStage,
        progress: int,
        label: str,
        detail: str,
        terminal: bool = False,
    ) -> None:
        for event in mission.timeline:
            if event.status == "active":
                event.status = "complete"
        mission.stage = stage
        mission.progress = progress
        mission.timeline.append(TimelineEvent(label=label, detail=detail, status="complete" if terminal else "active"))

    def _fail(self, mission: Mission, detail: str) -> None:
        mission.error = detail
        self._advance(
            mission,
            stage=MissionStage.FAILED,
            progress=mission.progress,
            label="Mission failed",
            detail=detail,
            terminal=True,
        )

    @staticmethod
    def _trace_started(mission: Mission, agent: str, action: str, detail: str) -> tuple[str, float]:
        event = TraceEvent(id=str(uuid4()), agent=agent, action=action, status="running", detail=detail)
        mission.trace.append(event)
        return event.id, perf_counter()

    @staticmethod
    def _trace_finished(
        mission: Mission,
        event_id: str,
        started: float,
        status: str,
        detail: str,
        attributes: dict[str, str | int | bool] | None = None,
    ) -> None:
        event = next(item for item in mission.trace if item.id == event_id)
        event.status = status  # type: ignore[assignment]
        event.completed_at = utc_now()
        event.duration_ms = int((perf_counter() - started) * 1000)
        event.detail = detail
        if attributes:
            event.attributes = attributes


mission_service = MissionService()
