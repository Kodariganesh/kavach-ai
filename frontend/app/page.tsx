"use client";

import { FormEvent, useMemo, useState } from "react";

type Severity = "critical" | "high" | "medium" | "low";
type FindingStatus = "open" | "analyzed" | "patch_ready" | "verified";
type TimelineEvent = { label: string; detail: string; status: "complete" | "active" | "pending"; occurred_at?: string };
type TraceEvent = {
  id: string;
  agent: string;
  action: string;
  status: "running" | "completed" | "failed";
  duration_ms?: number | null;
  detail: string;
  attributes: Record<string, string | number | boolean>;
};
type ScannerStatus = { scanner: string; status: "complete" | "unavailable" | "failed"; detail: string };
type Finding = {
  id: string;
  fingerprint: string;
  rule_id: string;
  title: string;
  severity: Severity;
  scanner: string;
  file_path: string;
  line: number;
  description: string;
  status: FindingStatus;
};
type VerificationResult = {
  id: string;
  status: "verified" | "failed";
  detail: string;
  scanner: string;
  findings_before: number;
  findings_after: number;
  security_score_before: number;
  security_score_after: number;
};
type Mission = {
  id: string;
  repository_name: string;
  stage: string;
  progress: number;
  security_score: number;
  initial_security_score: number;
  error?: string | null;
  scanners: ScannerStatus[];
  findings: Finding[];
  timeline: TimelineEvent[];
  trace: TraceEvent[];
  latest_verification?: VerificationResult | null;
};
type Explanation = {
  root_cause: string;
  impact: string;
  recommendation: string;
  confidence: number;
  patch_before: string;
  patch_after: string;
  patch_is_actionable: boolean;
  source: "openai" | "fallback" | "policy";
  model?: string | null;
  notice?: string | null;
};
type PatchProposal = {
  id: string;
  finding_id: string;
  file_path: string;
  patch_before: string;
  patch_after: string;
  summary: string;
  status: "draft" | "applied" | "verified" | "failed";
  validation_note: string;
};

const demoMission: Mission = {
  id: "demo-mission",
  repository_name: "sample-api",
  stage: "patch_ready",
  progress: 80,
  security_score: 52,
  initial_security_score: 52,
  scanners: [
    { scanner: "Semgrep", status: "complete", detail: "1 finding detected" },
    { scanner: "Bandit", status: "complete", detail: "1 finding detected" },
    { scanner: "Gitleaks", status: "complete", detail: "1 finding detected" },
  ],
  timeline: [
    { label: "Mission queued", detail: "Repository intake accepted", status: "complete" },
    { label: "Repository cloned", detail: "Temporary workspace prepared", status: "complete" },
    { label: "Security scan complete", detail: "Three scanners completed", status: "complete" },
    { label: "AI remediation prepared", detail: "Human approval is required before applying a patch", status: "active" },
  ],
  trace: [
    { id: "demo-coordinator", agent: "Mission Coordinator", action: "Create mission", status: "completed", duration_ms: 0, detail: "Accepted the repository security mission.", attributes: { repository_host: "github.com" } },
    { id: "demo-scanner", agent: "Scanner Agent", action: "Run security scanners", status: "completed", duration_ms: 8400, detail: "Security scanners completed.", attributes: { finding_count: 3, scanner_count: 3 } },
    { id: "demo-remediation", agent: "Remediation Agent", action: "Analyze prioritized findings", status: "completed", duration_ms: 3600, detail: "Remediation guidance prepared.", attributes: { finding_count: 1, openai_response_count: 1 } },
  ],
  findings: [
    {
      id: "finding-sql-001",
      fingerprint: "demo-sql",
      rule_id: "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
      title: "SQL query built from untrusted input",
      severity: "critical",
      scanner: "Semgrep",
      file_path: "src/api/users.py",
      line: 42,
      description: "User-controlled input flows directly into a SQL query.",
      status: "patch_ready",
    },
    {
      id: "finding-secret-002",
      fingerprint: "demo-secret",
      rule_id: "generic-api-key",
      title: "Hard-coded API credential",
      severity: "high",
      scanner: "Gitleaks",
      file_path: "src/config.py",
      line: 8,
      description: "A credential is committed in source control.",
      status: "analyzed",
    },
    {
      id: "finding-subprocess-003",
      fingerprint: "demo-shell",
      rule_id: "B602",
      title: "Subprocess launched with shell=True",
      severity: "medium",
      scanner: "Bandit",
      file_path: "src/utils/export.py",
      line: 19,
      description: "Shell execution can permit command injection.",
      status: "open",
    },
  ],
};

const demoExplanation: Explanation = {
  root_cause: "The endpoint interpolates request data into SQL, so the database treats attacker-controlled text as executable query syntax.",
  impact: "An attacker could read, modify, or delete records outside their authorized scope.",
  recommendation: "Use parameterized queries so input is always passed as data, never as executable SQL.",
  confidence: 96,
  patch_before: "query = f\"SELECT * FROM users WHERE email = '{email}'\"\nuser = db.execute(query).fetchone()",
  patch_after: "query = \"SELECT * FROM users WHERE email = ?\"\nuser = db.execute(query, (email,)).fetchone()",
  patch_is_actionable: true,
  source: "openai",
  model: "demo",
};

const demoPatch: PatchProposal = {
  id: "demo-patch",
  finding_id: "finding-sql-001",
  file_path: "src/api/users.py",
  patch_before: demoExplanation.patch_before,
  patch_after: demoExplanation.patch_after,
  summary: demoExplanation.recommendation,
  status: "draft",
  validation_note: "Demo preview: a live mission validates this in an isolated workspace before applying it.",
};

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const pendingStages = new Set(["queued", "cloning", "scanning", "analyzing", "verifying"]);

export default function Home() {
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [mission, setMission] = useState<Mission | null>(demoMission);
  const [selected, setSelected] = useState<Finding | null>(demoMission.findings[0]);
  const [explanation, setExplanation] = useState<Explanation | null>(demoExplanation);
  const [patch, setPatch] = useState<PatchProposal | null>(demoPatch);
  const [isDemo, setIsDemo] = useState(true);
  const [loading, setLoading] = useState(false);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [message, setMessage] = useState<string | null>("Demo preview loaded. Start a live mission to generate scanner-backed evidence.");

  const counts = useMemo(() => {
    const findings = mission?.findings ?? [];
    return findings.reduce<Record<string, number>>((all, finding) => {
      if (finding.status !== "verified") all[finding.severity] = (all[finding.severity] ?? 0) + 1;
      return all;
    }, {});
  }, [mission]);

  const completedScanners = mission?.scanners.filter((scanner) => scanner.status === "complete").length ?? 0;
  const canVerify = Boolean(patch && patch.status === "draft" && selected && explanation?.patch_is_actionable && !verificationLoading);

  async function startMission(event: FormEvent) {
    event.preventDefault();
    if (!repositoryUrl.trim()) {
      setMessage("Enter a public GitHub HTTPS repository URL to launch a live mission.");
      return;
    }
    setLoading(true);
    setIsDemo(false);
    setMission(null);
    setSelected(null);
    setExplanation(null);
    setPatch(null);
    setMessage("Mission queued. Kavach is preparing an isolated repository workspace.");
    try {
      const response = await fetch(`${apiUrl}/api/v1/mission/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repository_url: repositoryUrl.trim() }),
      });
      if (!response.ok) throw new Error(await responseMessage(response));
      const { mission_id } = (await response.json()) as { mission_id: string };
      await pollMission(mission_id);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Kavach could not launch the live mission.");
    } finally {
      setLoading(false);
    }
  }

  async function pollMission(missionId: string) {
    let analysisLoaded = false;
    for (let attempt = 0; attempt < 150; attempt += 1) {
      const response = await fetch(`${apiUrl}/api/v1/mission/${missionId}`);
      if (!response.ok) throw new Error(await responseMessage(response));
      const nextMission = (await response.json()) as Mission;
      setMission(nextMission);

      if (nextMission.error) {
        setMessage(nextMission.error);
        return;
      }

      const priorityFinding = highestPriorityFinding(nextMission.findings);
      if (!analysisLoaded && priorityFinding && !pendingStages.has(nextMission.stage)) {
        analysisLoaded = true;
        await loadExplanation(priorityFinding, nextMission.id);
      }

      if (!pendingStages.has(nextMission.stage)) {
        if (!priorityFinding) setMessage("Mission complete: no open findings remain. Download the report for the audit trail.");
        return;
      }
      await delay(1200);
    }
    setMessage("The mission is still running. Refresh the dashboard shortly to view the latest status.");
  }

  async function loadExplanation(finding: Finding, missionId: string) {
    setSelected(finding);
    setPatch(null);
    if (missionId === demoMission.id) {
      setExplanation(finding.id === demoMission.findings[0].id ? demoExplanation : null);
      setPatch(finding.id === demoMission.findings[0].id ? demoPatch : null);
      setMessage(finding.id === demoMission.findings[0].id ? "Demo preview: this patch is illustrative." : "Demo preview: select the SQL injection finding to view the patch flow.");
      return;
    }

    setAnalysisLoading(true);
    try {
      const analysisResponse = await fetch(`${apiUrl}/api/v1/mission/${missionId}/findings/${finding.id}/analyze`, { method: "POST" });
      if (!analysisResponse.ok) throw new Error(await responseMessage(analysisResponse));
      const nextExplanation = (await analysisResponse.json()) as Explanation;
      setExplanation(nextExplanation);
      setMessage(nextExplanation.notice ?? "AI remediation is ready. Review the evidence before approving a patch.");

      if (nextExplanation.patch_is_actionable) {
        const patchResponse = await fetch(`${apiUrl}/api/v1/mission/${missionId}/findings/${finding.id}/patch`, { method: "POST" });
        if (!patchResponse.ok) throw new Error(await responseMessage(patchResponse));
        setPatch((await patchResponse.json()) as PatchProposal);
      }
    } catch (error) {
      setExplanation(null);
      setMessage(error instanceof Error ? error.message : "Kavach could not prepare AI remediation for this finding.");
    } finally {
      setAnalysisLoading(false);
    }
  }

  async function verifyPatch() {
    if (!mission || !patch || !selected) return;
    if (isDemo) {
      const verifiedMission: Mission = {
        ...demoMission,
        stage: "patch_ready",
        progress: 92,
        security_score: 82,
        findings: demoMission.findings.map((finding) => (finding.id === selected.id ? { ...finding, status: "verified" } : finding)),
        latest_verification: {
          id: "demo-verification",
          status: "verified",
          detail: "Demo preview: a live mission performs an isolated scanner rescan before source is modified.",
          scanner: selected.scanner,
          findings_before: 1,
          findings_after: 0,
          security_score_before: 52,
          security_score_after: 82,
        },
      };
      setMission(verifiedMission);
      setSelected({ ...selected, status: "verified" });
      setPatch({ ...patch, status: "verified" });
      setMessage(verifiedMission.latest_verification?.detail ?? null);
      return;
    }

    setVerificationLoading(true);
    setMessage("Verifying the approved patch in an isolated workspace and rerunning the relevant scanner.");
    try {
      const response = await fetch(`${apiUrl}/api/v1/mission/${mission.id}/patches/${patch.id}/verify`, { method: "POST" });
      if (!response.ok) throw new Error(await responseMessage(response));
      const result = (await response.json()) as VerificationResult;
      setMessage(result.detail);
      setPatch({ ...patch, status: result.status === "verified" ? "verified" : "failed" });
      const missionResponse = await fetch(`${apiUrl}/api/v1/mission/${mission.id}`);
      if (missionResponse.ok) {
        const nextMission = (await missionResponse.json()) as Mission;
        setMission(nextMission);
        const refreshedSelected = nextMission.findings.find((finding) => finding.id === selected.id) ?? null;
        setSelected(refreshedSelected);
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Kavach could not verify this patch.");
    } finally {
      setVerificationLoading(false);
    }
  }

  async function downloadReport() {
    if (!mission || isDemo) {
      setMessage("Launch a live mission to download its scanner-backed audit report.");
      return;
    }
    try {
      const response = await fetch(`${apiUrl}/api/v1/mission/${mission.id}/report`);
      if (!response.ok) throw new Error(await responseMessage(response));
      const report = await response.json();
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${mission.repository_name}-kavach-security-report.json`;
      link.click();
      URL.revokeObjectURL(url);
      setMessage("Security report downloaded with scanner status, findings, timeline, and verification evidence.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Kavach could not create the mission report.");
    }
  }

  function runDemo() {
    setIsDemo(true);
    setMission(demoMission);
    setSelected(demoMission.findings[0]);
    setExplanation(demoExplanation);
    setPatch(demoPatch);
    setMessage("Demo preview loaded. It is clearly separate from a live scanner-backed mission.");
  }

  return (
    <main>
      <nav>
        <div className="brand"><span className="shield">[]</span><span>KAVACH <b>AI</b></span></div>
        <span className={`online ${isDemo ? "demo" : ""}`}><i /> {isDemo ? "DEMO PREVIEW" : "MISSION CONTROL"}</span>
      </nav>

      <section className="hero">
        <p className="eyebrow">AI SECURITY MISSION CONTROL</p>
        <h1>From vulnerability<br /><em>to verified fix.</em></h1>
        <p className="sub">A human-approved security workflow: scanner evidence, AI remediation, isolated verification, and an exportable audit trail.</p>
        <form onSubmit={startMission}>
          <input
            aria-label="GitHub repository URL"
            placeholder="https://github.com/owner/repository"
            value={repositoryUrl}
            onChange={(event) => setRepositoryUrl(event.target.value)}
          />
          <button disabled={loading}>{loading ? "Launching mission..." : "Start live mission"}</button>
        </form>
        <button className="demo-button" type="button" onClick={runDemo}>View demo preview</button>
      </section>

      {message && <p className="mission-message" role="status">{message}</p>}

      {mission ? <>
        <section className="mission-header">
          <div>
            <p className="eyebrow">{isDemo ? "DEMO MISSION" : "ACTIVE MISSION"}</p>
            <h2>{mission.repository_name}</h2>
            <span className={`stage ${mission.stage === "failed" ? "failed" : ""}`}>{humanize(mission.stage)}</span>
          </div>
          <div className="score">
            <span>SECURITY SCORE</span>
            <strong>{mission.security_score}<small>/100</small></strong>
            <div className="meter"><i style={{ width: `${mission.security_score}%` }} /></div>
          </div>
        </section>

        <section className="stats">
          <Stat label="Critical" value={counts.critical ?? 0} color="red" />
          <Stat label="High" value={counts.high ?? 0} color="orange" />
          <Stat label="Medium" value={counts.medium ?? 0} color="yellow" />
          <Stat label="Scanners" value={`${completedScanners}/${mission.scanners.length || 3}`} color="blue" />
        </section>

        <section className="grid">
          <div className="panel findings">
            <div className="panel-title"><h3>Scanner findings</h3><span>{mission.findings.length} detected</span></div>
            {mission.findings.length === 0 ? <EmptyState title={pendingStages.has(mission.stage) ? "Scanning repository..." : "No findings detected"} text={pendingStages.has(mission.stage) ? "The scanner worker is still collecting evidence." : "Review scanner health below before treating this as a clean result."} /> :
              mission.findings.map((finding) => (
                <button
                  key={finding.id}
                  className={`finding ${selected?.id === finding.id ? "selected" : ""} ${finding.status === "verified" ? "resolved" : ""}`}
                  onClick={() => loadExplanation(finding, mission.id)}
                  disabled={pendingStages.has(mission.stage) && !isDemo}
                >
                  <span className={`dot ${finding.severity}`} />
                  <span><b>{finding.title}</b><small>{finding.scanner} / {finding.rule_id} / {finding.file_path}:{finding.line}</small></span>
                  <span className={`badge ${finding.status === "verified" ? "verified" : finding.severity}`}>{finding.status === "verified" ? "verified" : finding.severity}</span>
                </button>
              ))}
          </div>

          <div className="panel intelligence">
            <div className="panel-title"><h3>AI security analysis</h3><span className="confidence">{explanation ? `${explanation.confidence}% confidence` : "Awaiting selection"}</span></div>
            {analysisLoading ? <EmptyState title="Analyzing evidence..." text="Kavach is preparing a bounded remediation response from scanner evidence." /> : explanation && selected ? <>
              <p className="finding-label">{selected.title}</p>
              <Insight title="Root cause" text={explanation.root_cause} />
              <Insight title="Potential impact" text={explanation.impact} />
              <Insight title="Recommended fix" text={explanation.recommendation} />
              <p className={`analysis-source ${explanation.source}`}>{explanation.source === "openai" ? `OpenAI analysis${explanation.model ? ` / ${explanation.model}` : ""}` : explanation.source === "policy" ? "Secret-protection policy response" : "Deterministic fallback guidance"}</p>
            </> : <EmptyState title="Select a finding" text="Kavach will show evidence-backed remediation only after a finding is selected." />}
          </div>

          <div className="panel patch">
            <div className="panel-title"><h3>Human-approved patch</h3><span>{patch ? patch.status.toUpperCase() : "NO PATCH"}</span></div>
            {patch && explanation ? <>
              <Code title="- vulnerable" value={patch.patch_before} kind="before" />
              <Code title="+ recommended" value={patch.patch_after} kind="after" />
              <p className="patch-note">{patch.validation_note}</p>
              <button className="verify" disabled={!canVerify} onClick={verifyPatch}>
                {verificationLoading ? "Verifying in isolated workspace..." : patch.status === "verified" ? "Patch verified" : "Approve, apply & verify"}
              </button>
            </> : <EmptyState title={explanation?.patch_is_actionable === false ? "Manual remediation required" : "Patch unavailable"} text={explanation?.notice ?? "Select an actionable finding to prepare a patch proposal."} />}
          </div>
        </section>

        <section className="bottom-grid">
          <section className="panel timeline">
            <div className="panel-title"><h3>Mission audit trail</h3><span>{mission.progress}% complete</span></div>
            <div className="timeline-items">{mission.timeline.map((item, index) => <div key={`${item.label}-${index}`} className={item.status}><i>{item.status === "complete" ? "OK" : index + 1}</i><div><b>{item.label}</b><small>{item.detail}</small></div></div>)}</div>
            <div className="trace-header"><b>Agent execution trace</b><span>{mission.trace.length} events</span></div>
            <div className="trace-items">{mission.trace.map((event) => <div className={`trace-event ${event.status}`} key={event.id}><span className="trace-status" /><div><b>{event.agent}</b><small>{event.action} · {event.detail}</small></div><em>{event.duration_ms == null ? "running" : `${event.duration_ms} ms`}</em></div>)}</div>
          </section>
          <section className="panel scanner-health">
            <div className="panel-title"><h3>Scanner health</h3><button className="report-button" onClick={downloadReport}>Download report</button></div>
            {mission.scanners.length ? mission.scanners.map((scanner) => <div className="scanner-row" key={scanner.scanner}><span className={`scanner-state ${scanner.status}`} /><div><b>{scanner.scanner}</b><small>{scanner.detail}</small></div><em>{scanner.status}</em></div>) : <EmptyState title="Waiting for scanners" text="Scanner availability and result counts will appear here." />}
          </section>
        </section>
      </> : <section className="panel loading-mission"><EmptyState title="Mission is launching" text="Kavach will stream its scan-to-remediation status into this dashboard." /></section>}
    </main>
  );
}

function highestPriorityFinding(findings: Finding[]): Finding | null {
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...findings].filter((finding) => finding.status !== "verified").sort((left, right) => order[left.severity] - order[right.severity])[0] ?? null;
}

function humanize(value: string) {
  return value.replaceAll("_", " ").toUpperCase();
}

function delay(milliseconds: number) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function responseMessage(response: Response) {
  try {
    const body = (await response.json()) as { detail?: string };
    return body.detail ?? `Request failed (${response.status})`;
  } catch {
    return `Request failed (${response.status})`;
  }
}

function Stat({ label, value, color }: { label: string; value: string | number; color: string }) {
  return <div className="stat"><span className={color} /><small>{label.toUpperCase()}</small><strong>{value}</strong></div>;
}

function Insight({ title, text }: { title: string; text: string }) {
  return <article><h4>{title}</h4><p>{text}</p></article>;
}

function Code({ title, value, kind }: { title: string; value: string; kind: "before" | "after" }) {
  return <div className={`code ${kind}`}><small>{title}</small><pre>{value}</pre></div>;
}

function EmptyState({ title, text }: { title: string; text: string }) {
  return <div className="empty-state"><b>{title}</b><p>{text}</p></div>;
}
