# Hackathon Roadmap

## Completed MVP

- Repository intake and temporary workspaces
- Scanner adapters: Semgrep, Bandit, and Gitleaks
- Security Mission Control dashboard
- Background mission lifecycle and observable scanner health
- Gemini/OpenAI structured remediation analysis with caching and secret-safe handling
- Triage Agent and independent Patch Review Agent with observable execution trace
- Human-approved patch proposal
- Isolated patch verification and relevant-scanner rescan
- Exportable JSON and HTML mission audit reports

## Demo priorities

1. Use a small intentionally vulnerable public repository.
2. Show scanner evidence, the triage decision, and select one actionable finding.
3. Show AI root cause, impact, exact patch proposal, and Patch Review Agent verdict.
4. Explicitly approve the patch.
5. Show isolated verification, score change, and HTML/JSON audit-report download.

## After the hackathon

- Worker/container isolation and repository resource limits
- Persistent audit storage and user authentication
- Full test suite after patch application
- GitHub pull request creation instead of direct workspace mutation
- CI/CD and IDE integrations
