from collections import Counter
from html import escape

from app.models import Explanation, Finding, Mission, MissionReport, PatchProposal, Severity


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
            triage=mission.triage,
            latest_verification=mission.latest_verification,
        )

    def build_html(
        self,
        mission: Mission,
        analyses: dict[str, Explanation],
        proposals: dict[str, PatchProposal],
    ) -> str:
        """Create a self-contained, safe-to-share human report for a mission."""
        severity_counts = self._severity_counts(mission.findings)
        findings = "".join(self._finding_html(mission, finding, analyses.get(finding.id), proposals) for finding in mission.findings)
        scanner_rows = "".join(
            f"<tr><td>{escape(scanner.scanner)}</td><td class='{escape(scanner.status)}'>{escape(scanner.status)}</td><td>{escape(scanner.detail)}</td></tr>"
            for scanner in mission.scanners
        ) or "<tr><td colspan='3'>No scanner results were recorded.</td></tr>"
        trace_rows = "".join(
            f"<li><b>{escape(event.agent)}</b> — {escape(event.action)} <span>{escape(event.status)} · "
            f"{event.duration_ms if event.duration_ms is not None else 'running'} ms</span><small>{escape(event.detail)}</small></li>"
            for event in mission.trace
        ) or "<li>No agent trace events were recorded.</li>"
        triage_rows = "".join(
            f"<li><b>#{item.priority_rank} {escape(self._finding_title(mission.findings, item.finding_id))}</b> "
            f"<span>{escape(item.source)}</span><small>{escape(item.rationale)} Next: {escape(item.next_step)}</small></li>"
            for item in mission.triage
        ) or "<li>Findings were prioritized by deterministic severity order.</li>"
        verification = "No patch verification has been requested." if mission.latest_verification is None else escape(mission.latest_verification.detail)
        return f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Kavach AI Security Report — {escape(mission.repository_name)}</title>
<style>
body{{background:#08111b;color:#eaf5fc;font:15px/1.55 Arial,sans-serif;margin:0}}main{{max-width:1050px;margin:auto;padding:42px 28px 64px}}h1{{margin:0;font-size:32px}}h2{{font-size:19px;margin:30px 0 12px}}h3{{font-size:16px;margin:0 0 7px}}.eyebrow{{color:#35dfd1;letter-spacing:1.8px;font-size:11px;font-weight:bold}}.card{{background:#0d1926;border:1px solid #213547;border-radius:9px;padding:18px;margin:14px 0}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:20px}}.stat{{background:#102231;border-radius:8px;padding:13px}}.stat small,.muted,small{{color:#91a6b8;display:block}}.stat b{{display:block;font-size:25px}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #213547;padding:10px;text-align:left;vertical-align:top}}.complete{{color:#72dda2}}.failed{{color:#ff8790}}.unavailable{{color:#efc85e}}.finding{{border-left:4px solid #5dcce2}}.finding.high,.finding.critical{{border-left-color:#ff6570}}.finding.medium{{border-left-color:#f0c652}}.finding.low{{border-left-color:#65c7e8}}pre{{background:#071018;border-radius:6px;overflow:auto;padding:12px;white-space:pre-wrap}}.before{{border-left:3px solid #ff6570}}.after{{border-left:3px solid #66d99c}}ul{{padding-left:20px}}li{{margin:10px 0}}li span{{color:#86a6bb;font-size:12px}}.notice{{background:#172c3b;border-left:4px solid #35dfd1;padding:12px}}@media(max-width:700px){{.stats{{grid-template-columns:repeat(2,1fr)}}main{{padding:25px 16px}}}}
</style></head><body><main>
<p class='eyebrow'>KAVACH AI · SECURITY MISSION REPORT</p><h1>{escape(mission.repository_name)}</h1>
<p class='muted'>Mission {escape(mission.id)} · Status: {escape(mission.stage.value)} · Generated {escape(str(mission.timeline[-1].occurred_at if mission.timeline else 'now'))}</p>
<div class='notice'>Human approval is required before applying any patch. Secret values and raw AI reasoning are intentionally excluded from this report.</div>
<div class='stats'><div class='stat'><small>SECURITY SCORE</small><b>{mission.security_score}/100</b></div><div class='stat'><small>OPEN FINDINGS</small><b>{sum(severity_counts.values())}</b></div><div class='stat'><small>SCANNERS COMPLETE</small><b>{sum(item.status == 'complete' for item in mission.scanners)}/{len(mission.scanners)}</b></div><div class='stat'><small>AI REMEDIATIONS</small><b>{sum(item.source in {'openai', 'gemini'} for item in analyses.values())}</b></div></div>
<h2>Executive summary</h2><div class='card'>{escape(self._summary(mission, [item for item in mission.findings if item.status != 'verified']))}</div>
<h2>Scanner health</h2><div class='card'><table><thead><tr><th>Scanner</th><th>Status</th><th>Result</th></tr></thead><tbody>{scanner_rows}</tbody></table></div>
<h2>Triage decisions</h2><div class='card'><ul>{triage_rows}</ul></div>
<h2>Findings and remediation</h2>{findings or "<div class='card'>No findings were recorded.</div>"}
<h2>Verification evidence</h2><div class='card'>{verification}</div>
<h2>Agent execution trace</h2><div class='card'><ul>{trace_rows}</ul></div>
</main></body></html>"""

    def _finding_html(
        self,
        mission: Mission,
        finding: Finding,
        analysis: Explanation | None,
        proposals: dict[str, PatchProposal],
    ) -> str:
        patch = next((item for item in proposals.values() if item.finding_id == finding.id), None)
        remediation = self._manual_remediation(finding)
        analysis_html = f"<p><b>Recommended action:</b> {escape(remediation)}</p>"
        if analysis is not None:
            provider = "Gemini" if analysis.source == "gemini" else "OpenAI" if analysis.source == "openai" else "Kavach policy"
            analysis_html = f"<p><b>{provider} remediation:</b> {escape(analysis.recommendation)}</p><p><b>Root cause:</b> {escape(analysis.root_cause)}</p>"
            if analysis.patch_is_actionable:
                before = patch.patch_before if patch else analysis.patch_before
                after = patch.patch_after if patch else analysis.patch_after
                patch_status = patch.status if patch else "not proposed"
                analysis_html += f"<p><b>Patch status:</b> {escape(patch_status)}</p><pre class='before'>{escape(before)}</pre><pre class='after'>{escape(after)}</pre>"
                if patch and patch.review:
                    concerns = " ".join(patch.review.concerns)
                    analysis_html += f"<p><b>Independent patch review ({escape(patch.review.source)}):</b> {escape(patch.review.verdict)} â€” {escape(patch.review.summary)} {escape(concerns)}</p>"
            elif analysis.notice:
                analysis_html += f"<p><b>Manual remediation:</b> {escape(analysis.notice)}</p>"
        verified = mission.latest_verification if mission.latest_verification and mission.latest_verification.finding_id == finding.id else None
        verification_html = f"<p><b>Verification:</b> {escape(verified.detail) if verified else 'Not verified yet.'}</p>"
        return f"<article class='card finding {escape(finding.severity.value)}'><p class='eyebrow'>{escape(finding.severity.value.upper())} · {escape(finding.scanner)}</p><h3>{escape(finding.title)}</h3><p class='muted'>{escape(finding.file_path)}:{finding.line} · {escape(finding.rule_id)}</p><p>{escape(finding.description)}</p>{analysis_html}{verification_html}</article>"

    @staticmethod
    def _manual_remediation(finding: Finding) -> str:
        rule = finding.rule_id.lower()
        if finding.scanner.lower() == "gitleaks":
            return "Revoke or rotate the exposed credential, remove it from source control, and move it to a secret manager."
        if "timeout" in rule:
            return "Add a bounded network timeout and handle timeout failures explicitly."
        if "exec" in rule:
            return "Avoid executing dynamic code; replace it with an explicit, allowlisted implementation."
        if "bind" in rule or "host" in rule:
            return "Avoid binding development services to all interfaces; use a production server and restrict network exposure."
        return "Review the scanner evidence, use a safer API or validated input path, and add a regression test."

    @staticmethod
    def _finding_title(findings: list[Finding], finding_id: str) -> str:
        finding = next((item for item in findings if item.id == finding_id), None)
        return finding.title if finding else finding_id

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
