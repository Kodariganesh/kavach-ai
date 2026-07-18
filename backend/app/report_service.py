from collections import Counter

from app.models import Finding, Mission, MissionReport, Severity


class ReportService:
    """Creates an evidence-oriented mission report from the in-memory audit record."""

    def build(self, mission: Mission) -> MissionReport:
        severity_counts = self._severity_counts(mission.findings)
        open_findings = [finding for finding in mission.findings if finding.status != "verified"]
        summary = self._summary(mission, open_findings)
        return MissionReport(
            mission_id=mission.id,
            repository_name=mission.repository_name,
            stage=mission.stage,
            security_score_before=mission.initial_security_score,
            security_score_after=mission.security_score,
            summary=summary,
            severity_counts=severity_counts,
            findings=mission.findings,
            scanners=mission.scanners,
            timeline=mission.timeline,
            trace=mission.trace,
            latest_verification=mission.latest_verification,
        )

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> dict[str, int]:
        counts = Counter(finding.severity.value for finding in findings if finding.status != "verified")
        return {severity.value: counts.get(severity.value, 0) for severity in Severity}

    @staticmethod
    def _summary(mission: Mission, open_findings: list[Finding]) -> str:
        if mission.error:
            return f"Mission stopped before completion: {mission.error}"
        if not open_findings:
            return "No open findings remain in the mission record. Any verified patch has scanner evidence in the audit timeline."
        highest = min(open_findings, key=lambda finding: list(Severity).index(finding.severity))
        return (
            f"{len(open_findings)} open finding(s) remain. The highest current risk is "
            f"{highest.severity.value.upper()} in {highest.file_path}:{highest.line}."
        )
