import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.ai_service import AnalysisService
from app.models import Explanation, Finding, PatchProposal, ScannerStatus, Severity
from app.patch_service import PatchError, PatchService
from app.repository_service import RepositoryService
from app.services import MissionService
from app.scanner_service import ScannerService
from app.verification_service import VerificationService


def finding() -> Finding:
    return Finding(
        id="finding-1",
        fingerprint="fingerprint-1",
        rule_id="demo-unsafe-call",
        title="Unsafe call",
        severity=Severity.HIGH,
        scanner="Semgrep",
        file_path="src/example.py",
        line=1,
        description="Unsafe function call.",
    )


def proposal() -> PatchProposal:
    return PatchProposal(
        id="patch-1",
        finding_id="finding-1",
        file_path="src/example.py",
        patch_before="dangerous(user_input)",
        patch_after="safe(user_input)",
        summary="Use the safe function.",
    )


class FakeScanner:
    def scan_for(self, _: str, workspace: Path):
        source = (workspace / "src" / "example.py").read_text(encoding="utf-8")
        findings = [finding()] if "dangerous(user_input)" in source else []
        return findings, ScannerStatus(scanner="Semgrep", status="complete", detail="Fake scan complete")

    def scan(self, _: Path):
        return [finding()], [ScannerStatus(scanner="Semgrep", status="complete", detail="1 finding detected")]


class FakeRepository:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def validate_url(self, _: str) -> str:
        return "demo-repository"

    def clone(self, _: str, __: str):
        return "demo-repository", self.workspace

    def cleanup(self, _: str) -> None:
        return None


class FakeAnalysis:
    def analyze(self, security_finding: Finding, _: Path) -> Explanation:
        return Explanation(
            finding_id=security_finding.id,
            root_cause="Unsafe call receives untrusted data.",
            impact="An attacker could exploit unsafe behavior.",
            recommendation="Use the safe function.",
            confidence=95,
            patch_before="dangerous(user_input)",
            patch_after="safe(user_input)",
            patch_is_actionable=True,
            source="openai",
            model="test-model",
        )


class SecurityWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary_directory.name) / "workspace"
        (self.workspace / "src").mkdir(parents=True)
        (self.workspace / "src" / "example.py").write_text("dangerous(user_input)\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_patch_service_applies_an_exact_approved_replacement(self) -> None:
        PatchService().apply(self.workspace, proposal())
        self.assertEqual((self.workspace / "src" / "example.py").read_text(encoding="utf-8"), "safe(user_input)\n")

    def test_patch_service_refuses_a_path_outside_workspace(self) -> None:
        invalid = proposal().model_copy(update={"file_path": "../outside.py"})
        with self.assertRaises(PatchError):
            PatchService().apply(self.workspace, invalid)

    def test_verification_uses_an_isolated_copy_before_source_is_changed(self) -> None:
        service = VerificationService(FakeScanner(), PatchService())
        result = service.verify(
            mission_id="mission-1",
            workspace=self.workspace,
            finding=finding(),
            proposal=proposal(),
            security_score_before=70,
        )
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.findings_after, 0)
        self.assertEqual((self.workspace / "src" / "example.py").read_text(encoding="utf-8"), "dangerous(user_input)\n")

    def test_secret_findings_never_receive_an_automated_source_patch(self) -> None:
        secret_finding = finding().model_copy(update={"scanner": "Gitleaks", "rule_id": "generic-api-key"})
        explanation = AnalysisService().analyze(secret_finding, self.workspace)
        self.assertEqual(explanation.source, "policy")
        self.assertFalse(explanation.patch_is_actionable)
        self.assertIn("rotate", explanation.recommendation.lower())

    def test_live_remediation_returns_an_explanation_when_an_ai_client_is_available(self) -> None:
        service = AnalysisService()
        service._client = object()
        service._provider = "gemini"
        service._model = "test-model"
        service._request_remediation = lambda *_: SimpleNamespace(  # type: ignore[method-assign]
            root_cause="Unsafe call receives untrusted input.",
            impact="Unsafe behavior may be exploitable.",
            recommendation="Use the safe function.",
            confidence=91,
            patch_before="dangerous(user_input)",
            patch_after="safe(user_input)",
        )
        explanation = service.analyze(finding(), self.workspace)
        self.assertEqual(explanation.source, "gemini")
        self.assertTrue(explanation.patch_is_actionable)

    def test_scanner_ignores_nested_dependency_directories(self) -> None:
        nested_venv = self.workspace / "agent" / "venv"
        nested_venv.mkdir(parents=True)
        self.assertTrue(ScannerService()._is_ignored_path("agent/venv/Lib/site-packages/pip.py"))
        self.assertFalse(ScannerService()._is_ignored_path("agent/receivables.py"))
        ignored = ScannerService()._ignored_directories(self.workspace)
        self.assertIn(nested_venv, ignored)

    def test_semgrep_command_excludes_dependency_directories(self) -> None:
        command = ScannerService()._semgrep_command(self.workspace)
        self.assertIn("--exclude", command)
        self.assertIn("venv", command)
        self.assertIn("node_modules", command)

    def test_default_workspace_is_outside_the_project_directory(self) -> None:
        workspace_root = RepositoryService()._workspace_root
        self.assertEqual(workspace_root.name, "kavach-ai-workspaces")
        self.assertNotIn("Kavach Ai", str(workspace_root))

    def test_mission_orchestrator_completes_a_verified_remediation_loop(self) -> None:
        service = MissionService()
        scanner = FakeScanner()
        patch_service = PatchService()
        service._repository_service = FakeRepository(self.workspace)  # type: ignore[assignment]
        service._scanner_service = scanner  # type: ignore[assignment]
        service._analysis_service = FakeAnalysis()  # type: ignore[assignment]
        service._verification_service = VerificationService(scanner, patch_service)

        mission = service.create("https://github.com/demo/repository")
        service.execute(mission.id)
        prepared = service.get(mission.id)
        self.assertIsNotNone(prepared)
        if prepared is None:
            self.fail("Mission disappeared before remediation could be prepared.")
        self.assertEqual(prepared.stage.value, "patch_ready")

        patch = service.propose_patch(mission.id, prepared.findings[0].id)
        result = service.verify_patch(mission.id, patch.id)
        completed = service.get(mission.id)
        self.assertEqual(result.status, "verified")
        self.assertIsNotNone(completed)
        if completed is None:
            self.fail("Mission disappeared before verification could complete.")
        self.assertEqual(completed.stage.value, "verified")
        self.assertEqual(completed.security_score, 100)
        self.assertEqual(completed.findings[0].status, "verified")
        self.assertEqual(
            [(event.agent, event.status) for event in completed.trace],
            [
                ("Mission Coordinator", "completed"),
                ("Repository Agent", "completed"),
                ("Scanner Agent", "completed"),
                ("Triage Agent", "completed"),
                ("Remediation Agent", "completed"),
                ("Patch Review Agent", "completed"),
                ("Verification Agent", "completed"),
            ],
        )
        self.assertTrue(all(event.duration_ms is not None for event in completed.trace))
        self.assertEqual((self.workspace / "src" / "example.py").read_text(encoding="utf-8"), "safe(user_input)\n")

        html_report = service.html_report(mission.id)
        self.assertIn("Kavach AI Security Report", html_report)
        self.assertIn("Unsafe call", html_report)
        self.assertIn("OpenAI remediation", html_report)
        self.assertIn("Agent execution trace", html_report)
        self.assertIn("Triage decisions", html_report)


if __name__ == "__main__":
    unittest.main()
