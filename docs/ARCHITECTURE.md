# Hackathon Architecture

## Security-first mission flow

```text
Browser Mission Control
        |
        v
FastAPI API + Mission Orchestrator
        |
        +--> Background mission worker
        |      |
        |      +--> Repository Intake (public GitHub, shallow clone)
        |      +--> Scanner Adapters (Semgrep, Bandit, Gitleaks)
        |      +--> Finding Normalizer + Risk Score
        |      +--> OpenAI Remediation Analyst (structured output)
        |
        +--> Human-approved Patch Service
        |      |
        |      +--> Isolated verification workspace
        |             |
        |             +--> Rescan the relevant rule
        |
        +--> Report Service (audit trail + evidence)
```

## Design goal

Kavach AI is a Security-theme product, not a generic scanner dashboard. A mission turns a scanner result into a traceable remediation decision:

```text
Evidence -> AI explanation -> Human approval -> Isolated verification -> Applied patch -> Report
```

## Backend modules

| Module | Responsibility |
| --- | --- |
| `services.py` | Mission state machine and orchestration of every security step. |
| `repository_service.py` | Validate public GitHub HTTPS URLs, shallow-clone, and clean temporary workspaces. |
| `scanner_service.py` | Run scanner adapters and normalize outputs into stable finding IDs/fingerprints. |
| `ai_service.py` | Build bounded, redacted evidence context and request schema-constrained remediation from OpenAI. |
| `patch_service.py` | Apply only an exact, human-approved replacement within the mission workspace. |
| `verification_service.py` | Copy the workspace, test the patch there, and rescan the relevant scanner rule before touching source. |
| `report_service.py` | Produce an exportable mission report with score change, scanner health, findings, and timeline. |

## Mission state machine

```text
queued -> cloning -> scanning -> analyzing -> patch_ready -> verifying -> verified
                                      |                         |
                                      +-------------------------+
                                      |         more findings
                                      v
                                    failed
```

The API returns a mission ID immediately and performs cloning/scanning in a background task. The dashboard polls the mission, making progress and scanner health observable instead of hiding a long request behind a loading screen.

## Security boundaries

- Only public `https://github.com/owner/repository` URLs are accepted for the MVP.
- Workspaces are temporary and shallow-cloned.
- Scanner findings receive stable fingerprints; random IDs are not used for verification matching.
- Source paths are checked to remain inside the workspace before reading or patching.
- Source snippets are bounded and secret-looking values are redacted before model analysis.
- Gitleaks findings never send secret-bearing code to the AI service; they receive a human-led rotation workflow instead.
- Model output is structured with a Pydantic schema.
- A patch is first applied to an isolated copy and rescanned. The original workspace changes only after that verification succeeds.
- The MVP deliberately has no database or authentication. Mission state is in memory and is suitable only for a hackathon demo.

## Hackathon demo boundary

Kavach does not claim autonomous production deployment. It demonstrates a human-approved security workflow with real scanner evidence and a verified remediation loop. Future production architecture would add job isolation, persistent audit storage, authentication, repository size limits, CI integration, and pull request creation.
