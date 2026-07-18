# Kavach AI

**AI Security Mission Control - from vulnerability to verified fix.**

Kavach AI is a Security-theme hackathon project that turns scanner output into a human-approved, scanner-verified remediation workflow.

## Demo video

[Watch the Kavach AI demo on YouTube](https://youtu.be/GliteRW-RAI)

```text
Public GitHub repository
  -> scanner evidence
  -> AI triage and remediation
  -> independent AI patch review
  -> human-approved patch
  -> isolated rescan
  -> verified audit report
```

## What is real in this MVP

- Background security missions with observable states and scanner health
- Public GitHub shallow cloning
- Semgrep, Bandit, and Gitleaks scanning with normalized scanner evidence
- Stable normalized findings and an explainable security score
- Multi-agent workflow: Triage Agent, Remediation Agent, Patch Review Agent, and Verification Agent
- Structured Gemini or OpenAI remediation for the highest-priority findings
- Secret-safe behavior: potential secrets are not sent to the model and require human-led rotation
- Exact patch proposal, isolated workspace verification, relevant scanner rescan, then source application
- Downloadable HTML and JSON audit reports with timeline, agent trace, triage, and verification evidence

The UI has a clearly labelled demo preview, but live mission failures are shown as errors and are not silently replaced with demo data.

## Run locally

Start the API:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Add one AI provider key to .env.
uvicorn app.main:app --reload --port 8000
```

For Gemini (the current demo configuration), set:

```powershell
$env:AI_PROVIDER = "gemini"
$env:GEMINI_API_KEY = "your_api_key"
$env:GEMINI_MODEL = "gemini-3.5-flash"
```

OpenAI is also supported by setting `AI_PROVIDER=openai`, `OPENAI_API_KEY`, and `OPENAI_MODEL`.

Start the dashboard in a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`. Set `NEXT_PUBLIC_API_URL` if the API runs somewhere other than `http://localhost:8000`.

## Validation

```powershell
cd backend
.\.venv\Scripts\python -m unittest discover -s tests -v

cd ..\frontend
npx tsc --noEmit
```

## Important MVP boundary

This is a hackathon prototype. It keeps mission state in memory and processes scanner commands on the local API host. A production version would add worker/container isolation, persistent audit storage, authentication, repository size limits, CI/CD integration, and pull-request creation.
