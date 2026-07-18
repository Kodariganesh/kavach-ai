import hashlib
import json
import os
import shutil
# This module invokes only scanner commands built by Kavach's fixed adapters.
import subprocess  # nosec B404
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from app.models import Finding, ScannerStatus, Severity


@dataclass
class _CommandResult:
    stdout: str


class ScannerService:
    """Runs supported scanners concurrently and normalizes their reports."""

    _IGNORED_DIRECTORY_NAMES = frozenset({".git", ".venv", "venv", "env", "node_modules", "vendor", "dist", "build"})

    def __init__(self, timeout_seconds: int | None = None) -> None:
        self._timeout_seconds = timeout_seconds or int(os.getenv("KAVACH_SCANNER_TIMEOUT_SECONDS", "180"))
        self._max_output_bytes = int(os.getenv("KAVACH_SCANNER_MAX_OUTPUT_BYTES", str(10 * 1024 * 1024)))
        self._semgrep_config = os.getenv("KAVACH_SEMGREP_CONFIG", "p/default")

    def scan(self, workspace: Path) -> tuple[list[Finding], list[ScannerStatus]]:
        scanners = ("Semgrep", "Bandit", "Gitleaks")
        with ThreadPoolExecutor(max_workers=len(scanners), thread_name_prefix="kavach-scan") as executor:
            results = {scanner: executor.submit(self.scan_for, scanner, workspace) for scanner in scanners}
            completed = {scanner: future.result() for scanner, future in results.items()}
        findings: list[Finding] = []
        statuses: list[ScannerStatus] = []
        for scanner in scanners:
            scanner_findings, scanner_status = completed[scanner]
            findings.extend(scanner_findings)
            statuses.append(scanner_status)
        return findings, statuses

    def scan_for(self, scanner: str, workspace: Path) -> tuple[list[Finding], ScannerStatus]:
        runners = {"semgrep": self._run_semgrep, "bandit": self._run_bandit, "gitleaks": self._run_gitleaks}
        runner = runners.get(scanner.lower())
        if runner is None:
            return [], ScannerStatus(scanner=scanner, status="failed", detail="Unsupported scanner requested.")
        return runner(workspace)

    def _run_semgrep(self, workspace: Path) -> tuple[list[Finding], ScannerStatus]:
        result = self._execute("Semgrep", self._semgrep_command(workspace))
        if isinstance(result, ScannerStatus):
            return [], result
        try:
            report = json.loads(result.stdout)
            findings = [
                self._finding("Semgrep", item["check_id"], item["check_id"], self._severity(item.get("extra", {}).get("severity")),
                              self._relative_path(workspace, item["path"]), item.get("start", {}).get("line", 1),
                              item.get("extra", {}).get("message", "Security issue detected by Semgrep."))
                for item in report.get("results", [])
            ]
            return findings, ScannerStatus(scanner="Semgrep", status="complete", detail=f"{len(findings)} finding(s) detected")
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            return [], ScannerStatus(scanner="Semgrep", status="failed", detail=f"Could not parse scanner output: {error}")

    def _run_bandit(self, workspace: Path) -> tuple[list[Finding], ScannerStatus]:
        ignored_paths = ",".join(str(path) for path in self._ignored_directories(workspace))
        result = self._execute("Bandit", ["bandit", "-r", str(workspace), "-f", "json", "-q", "-x", ignored_paths])
        if isinstance(result, ScannerStatus):
            return [], result
        try:
            report = json.loads(result.stdout)
            findings = [
                self._finding("Bandit", item.get("test_id", item.get("test_name", "bandit-finding")),
                              item.get("test_name", item.get("test_id", "Bandit finding")), self._severity(item.get("issue_severity")),
                              self._relative_path(workspace, item["filename"]), item.get("line_number", 1),
                              item.get("issue_text", "Security issue detected by Bandit."))
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
            result = self._execute("Gitleaks", ["gitleaks", "detect", "--source", str(workspace), "--report-format", "json", "--report-path", str(report_path), "--no-banner"])
            if isinstance(result, ScannerStatus):
                return [], result
            if not report_path.exists() or report_path.stat().st_size > self._max_output_bytes:
                return [], ScannerStatus(scanner="Gitleaks", status="failed", detail="Gitleaks did not produce a bounded JSON report.")
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
                findings = [self._finding("Gitleaks", item.get("RuleID", "potential-secret"), item.get("RuleID", "Potential secret"), Severity.HIGH,
                                          self._relative_path(workspace, item.get("File", "unknown")), item.get("StartLine", 1),
                                          item.get("Description", "Potential secret detected by Gitleaks.")) for item in report]
                return findings, ScannerStatus(scanner="Gitleaks", status="complete", detail=f"{len(findings)} finding(s) detected")
            except (json.JSONDecodeError, TypeError) as error:
                return [], ScannerStatus(scanner="Gitleaks", status="failed", detail=f"Could not parse scanner output: {error}")

    def _execute(self, scanner: str, command: list[str]) -> _CommandResult | ScannerStatus:
        executable = shutil.which(command[0])
        venv_executable = Path(sys.executable).with_name(f"{command[0]}.exe")
        if executable is None and venv_executable.exists():
            command[0] = str(venv_executable)
        elif executable is None:
            return ScannerStatus(scanner=scanner, status="unavailable", detail=f"Install {scanner} to enable this scan.")
        try:
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                # `command` is built by Kavach's scanner adapters, never from repository contents or user shell input.
                subprocess.run(  # nosec B603
                    command,
                    stdout=output,
                    stderr=errors,
                    timeout=self._timeout_seconds,
                    check=False,
                    shell=False,
                )
                if output.tell() > self._max_output_bytes or errors.tell() > self._max_output_bytes:
                    return ScannerStatus(scanner=scanner, status="failed", detail="Scanner output exceeded Kavach's safety limit.")
                output.seek(0)
                return _CommandResult(output.read().decode("utf-8", errors="replace"))
        except (OSError, subprocess.TimeoutExpired) as error:
            return ScannerStatus(scanner=scanner, status="failed", detail=f"Scanner could not run: {error}")

    @staticmethod
    def _finding(scanner: str, rule_id: str, title: str, severity: Severity, file_path: str, line: int, description: str) -> Finding:
        stable_key = f"{scanner.lower()}|{rule_id}|{file_path}|{line}"
        fingerprint = hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:20]
        return Finding(id=f"{scanner.lower()}-{fingerprint}", fingerprint=fingerprint, rule_id=rule_id, title=title,
                       severity=severity, scanner=scanner, file_path=file_path, line=line, description=description)

    @staticmethod
    def _relative_path(workspace: Path, file_path: str) -> str:
        try:
            return str(Path(file_path).resolve().relative_to(workspace.resolve()))
        except ValueError:
            return file_path

    def _ignored_directories(self, workspace: Path) -> list[Path]:
        ignored: list[Path] = []
        for root, directories, _ in os.walk(workspace):
            excluded = [name for name in directories if name.lower() in self._IGNORED_DIRECTORY_NAMES]
            ignored.extend(Path(root) / name for name in excluded)
            directories[:] = [name for name in directories if name not in excluded]
        return ignored

    def _semgrep_command(self, workspace: Path) -> list[str]:
        command = ["semgrep", "scan", "--config", self._semgrep_config, "--json", "--quiet"]
        for directory_name in sorted(self._IGNORED_DIRECTORY_NAMES):
            command.extend(["--exclude", directory_name])
        command.append(str(workspace))
        return command

    def _is_ignored_path(self, file_path: str) -> bool:
        return any(part.lower() in self._IGNORED_DIRECTORY_NAMES for part in Path(file_path).parts)

    @staticmethod
    def _severity(value: str | None) -> Severity:
        mapping = {"error": Severity.HIGH, "critical": Severity.CRITICAL, "high": Severity.HIGH, "warning": Severity.MEDIUM,
                   "medium": Severity.MEDIUM, "info": Severity.LOW, "low": Severity.LOW}
        return mapping.get((value or "medium").lower(), Severity.MEDIUM)
