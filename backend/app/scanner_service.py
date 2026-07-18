import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from app.models import Finding, ScannerStatus, Severity


class ScannerService:
    """Runs supported scanners and normalizes their reports into stable findings."""

    def __init__(self, timeout_seconds: int | None = None) -> None:
        configured_timeout = os.getenv("KAVACH_SCANNER_TIMEOUT_SECONDS", "180")
        self._timeout_seconds = timeout_seconds or int(configured_timeout)

    def scan(self, workspace: Path) -> tuple[list[Finding], list[ScannerStatus]]:
        findings: list[Finding] = []
        statuses: list[ScannerStatus] = []
        for scanner in ("Semgrep", "Bandit", "Gitleaks"):
            scanner_findings, scanner_status = self.scan_for(scanner, workspace)
            findings.extend(scanner_findings)
            statuses.append(scanner_status)
        return findings, statuses

    def scan_for(self, scanner: str, workspace: Path) -> tuple[list[Finding], ScannerStatus]:
        """Run one scanner so verification can rescan only the relevant security rule."""
        runners = {
            "semgrep": self._run_semgrep,
            "bandit": self._run_bandit,
            "gitleaks": self._run_gitleaks,
        }
        runner = runners.get(scanner.lower())
        if runner is None:
            return [], ScannerStatus(scanner=scanner, status="failed", detail="Unsupported scanner requested.")
        return runner(workspace)

    def _run_semgrep(self, workspace: Path) -> tuple[list[Finding], ScannerStatus]:
        result = self._execute(
            "Semgrep",
            ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(workspace)],
        )
        if isinstance(result, ScannerStatus):
            return [], result
        try:
            report = json.loads(result.stdout)
            findings = [
                self._finding(
                    scanner="Semgrep",
                    rule_id=item["check_id"],
                    title=item["check_id"],
                    severity=self._severity(item.get("extra", {}).get("severity")),
                    file_path=self._relative_path(workspace, item["path"]),
                    line=item.get("start", {}).get("line", 1),
                    description=item.get("extra", {}).get("message", "Security issue detected by Semgrep."),
                )
                for item in report.get("results", [])
            ]
            return findings, ScannerStatus(scanner="Semgrep", status="complete", detail=f"{len(findings)} finding(s) detected")
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            return [], ScannerStatus(scanner="Semgrep", status="failed", detail=f"Could not parse scanner output: {error}")

    def _run_bandit(self, workspace: Path) -> tuple[list[Finding], ScannerStatus]:
        ignored_paths = ",".join(str(workspace / name) for name in (".git", "node_modules", ".venv", "venv"))
        result = self._execute(
            "Bandit",
            ["bandit", "-r", str(workspace), "-f", "json", "-q", "-x", ignored_paths],
        )
        if isinstance(result, ScannerStatus):
            return [], result
        try:
            report = json.loads(result.stdout)
            findings = [
                self._finding(
                    scanner="Bandit",
                    rule_id=item.get("test_id", item.get("test_name", "bandit-finding")),
                    title=item.get("test_name", item.get("test_id", "Bandit finding")),
                    severity=self._severity(item.get("issue_severity")),
                    file_path=self._relative_path(workspace, item["filename"]),
                    line=item.get("line_number", 1),
                    description=item.get("issue_text", "Security issue detected by Bandit."),
                )
                for item in report.get("results", [])
            ]
            return findings, ScannerStatus(scanner="Bandit", status="complete", detail=f"{len(findings)} finding(s) detected")
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            return [], ScannerStatus(scanner="Bandit", status="failed", detail=f"Could not parse scanner output: {error}")

    def _run_gitleaks(self, workspace: Path) -> tuple[list[Finding], ScannerStatus]:
        if shutil.which("gitleaks") is None:
            return [], ScannerStatus(scanner="Gitleaks", status="unavailable", detail="Install the Gitleaks CLI to enable secret scanning.")

        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "gitleaks-report.json"
            result = self._execute(
                "Gitleaks",
                [
                    "gitleaks",
                    "detect",
                    "--source",
                    str(workspace),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_path),
                    "--no-banner",
                ],
            )
            if isinstance(result, ScannerStatus):
                return [], result
            if not report_path.exists():
                return [], ScannerStatus(scanner="Gitleaks", status="failed", detail="Gitleaks did not produce a JSON report.")
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
                findings = [
                    self._finding(
                        scanner="Gitleaks",
                        rule_id=item.get("RuleID", "potential-secret"),
                        title=item.get("RuleID", "Potential secret"),
                        severity=Severity.HIGH,
                        file_path=self._relative_path(workspace, item.get("File", "unknown")),
                        line=item.get("StartLine", 1),
                        description=item.get("Description", "Potential secret detected by Gitleaks."),
                    )
                    for item in report
                ]
                return findings, ScannerStatus(scanner="Gitleaks", status="complete", detail=f"{len(findings)} finding(s) detected")
            except (json.JSONDecodeError, TypeError) as error:
                return [], ScannerStatus(scanner="Gitleaks", status="failed", detail=f"Could not parse scanner output: {error}")

    def _execute(self, scanner: str, command: list[str]) -> subprocess.CompletedProcess[str] | ScannerStatus:
        executable = shutil.which(command[0])
        venv_executable = Path(sys.executable).with_name(f"{command[0]}.exe")
        if executable is None and venv_executable.exists():
            command[0] = str(venv_executable)
        elif executable is None:
            return ScannerStatus(scanner=scanner, status="unavailable", detail=f"Install {scanner} to enable this scan.")
        try:
            return subprocess.run(command, capture_output=True, text=True, timeout=self._timeout_seconds, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            return ScannerStatus(scanner=scanner, status="failed", detail=f"Scanner could not run: {error}")

    @staticmethod
    def _finding(
        *,
        scanner: str,
        rule_id: str,
        title: str,
        severity: Severity,
        file_path: str,
        line: int,
        description: str,
    ) -> Finding:
        stable_key = f"{scanner.lower()}|{rule_id}|{file_path}|{line}"
        fingerprint = hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:20]
        return Finding(
            id=f"{scanner.lower()}-{fingerprint}",
            fingerprint=fingerprint,
            rule_id=rule_id,
            title=title,
            severity=severity,
            scanner=scanner,
            file_path=file_path,
            line=line,
            description=description,
        )

    @staticmethod
    def _relative_path(workspace: Path, file_path: str) -> str:
        try:
            return str(Path(file_path).resolve().relative_to(workspace.resolve()))
        except ValueError:
            return file_path

    @staticmethod
    def _severity(value: str | None) -> Severity:
        normalized = (value or "medium").lower()
        mapping = {
            "error": Severity.HIGH,
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "medium": Severity.MEDIUM,
            "info": Severity.LOW,
            "low": Severity.LOW,
        }
        return mapping.get(normalized, Severity.MEDIUM)
