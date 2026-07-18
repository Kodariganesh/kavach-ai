# Kavach AI

**AI Security Mission Control - from vulnerability to verified fix.**

Kavach AI is a Security-theme hackathon project that turns scanner output into a human-approved, scanner-verified remediation workflow.

```text
Public GitHub repository
  -> scanner evidence
  -> AI remediation analysis
  -> human-approved patch
  -> isolated rescan
  -> verified audit report
```

## What is real in this MVP

- Background security missions with observable states and scanner health
- Public GitHub shallow cloning
- Semgrep and Bandit scanning; optional Gitleaks secret scanning
- Stable normalized findings and an explainable security score
- OpenAI-backed structured remediation for selected/highest-risk findings
- Secret-safe behavior: potential secrets are not sent to the model and require human-led rotation
- Exact patch proposal, isolated workspace verification, relevant scanner rescan, then source application
- Downloadable JSON audit report with timeline and verification evidence

The UI has a clearly labelled demo preview, but live mission failures are shown as errors and are not silently replaced with demo data.

## Run locally

Start the API:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Add your OPENAI_API_KEY to .env, then load it into your terminal environment.
uvicorn app.main:app --reload --port 8000
```

Set the key in the PowerShell session before starting the API:

```powershell
$env:OPENAI_API_KEY = "your_api_key"
$env:OPENAI_MODEL = "gpt-5.4"
```

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
