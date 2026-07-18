import shutil
import tempfile
from pathlib import Path
from uuid import uuid4

from app.models import Finding, PatchProposal, VerificationResult
from app.patch_service import PatchError, PatchService
from app.scanner_service import ScannerService


class VerificationService:
    """Validates a proposed patch in an isolated copy before modifying the mission workspace."""

    def __init__(self, scanner_service: ScannerService, patch_service: PatchService) -> None:
        self._scanner_service = scanner_service
        self._patch_service = patch_service

    def verify(
        self,
        *,
        mission_id: str,
        workspace: Path,
        finding: Finding,
        proposal: PatchProposal,
        security_score_before: int,
    ) -> VerificationResult:
        with tempfile.TemporaryDirectory(prefix="kavach-verify-") as temporary_directory:
            candidate_workspace = Path(temporary_directory) / "workspace"
            try:
                shutil.copytree(workspace, candidate_workspace, ignore=shutil.ignore_patterns(".git", "node_modules", ".venv", "venv"))
                self._patch_service.apply(candidate_workspace, proposal)
            except (OSError, PatchError) as error:
                return self._result(
                    mission_id=mission_id,
                    proposal=proposal,
                    finding=finding,
                    status="failed",
                    detail=f"Patch validation failed before verification: {error}",
                    findings_after=1,
                    security_score_before=security_score_before,
                    security_score_after=security_score_before,
                )

            rescanned_findings, scanner_status = self._scanner_service.scan_for(finding.scanner, candidate_workspace)
            if scanner_status.status != "complete":
                return self._result(
                    mission_id=mission_id,
                    proposal=proposal,
                    finding=finding,
                    status="failed",
                    detail=f"Verification scanner did not complete: {scanner_status.detail}",
                    findings_after=len(rescanned_findings),
                    security_score_before=security_score_before,
                    security_score_after=security_score_before,
                )

            still_present = any(self._matches_target(finding, result) for result in rescanned_findings)
            if still_present:
                return self._result(
                    mission_id=mission_id,
                    proposal=proposal,
                    finding=finding,
                    status="failed",
                    detail=(
                        f"{finding.scanner} still detected the same rule after the isolated patch test. "
                        "The original repository was not modified."
                    ),
                    findings_after=len(rescanned_findings),
                    security_score_before=security_score_before,
                    security_score_after=security_score_before,
                )

            return self._result(
                mission_id=mission_id,
                proposal=proposal,
                finding=finding,
                status="verified",
                detail=(
                    f"{finding.scanner} no longer detected the target rule in an isolated patched workspace. "
                    "Kavach can now apply the approved patch to the mission workspace."
                ),
                findings_after=len(rescanned_findings),
                security_score_before=security_score_before,
                security_score_after=security_score_before,
            )

    @staticmethod
    def _matches_target(original: Finding, rescanned: Finding) -> bool:
        return (
            original.scanner.lower() == rescanned.scanner.lower()
            and original.rule_id == rescanned.rule_id
            and original.file_path.replace("\\", "/") == rescanned.file_path.replace("\\", "/")
        )

    @staticmethod
    def _result(
        *,
        mission_id: str,
        proposal: PatchProposal,
        finding: Finding,
        status: str,
        detail: str,
        findings_after: int,
        security_score_before: int,
        security_score_after: int,
    ) -> VerificationResult:
        return VerificationResult(
            id=str(uuid4()),
            mission_id=mission_id,
            patch_id=proposal.id,
            finding_id=finding.id,
            status=status,  # type: ignore[arg-type]
            detail=detail,
            scanner=finding.scanner,
            findings_before=1,
            findings_after=findings_after,
            security_score_before=security_score_before,
            security_score_after=security_score_after,
        )
