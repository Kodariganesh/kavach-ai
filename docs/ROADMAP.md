# Hackathon Roadmap

## Completed MVP

- Repository intake and temporary workspaces
- Scanner adapters: Semgrep, Bandit, optional Gitleaks
- Security Mission Control dashboard
- Background mission lifecycle and observable scanner health
- OpenAI structured remediation analysis with caching and secret-safe handling
- Human-approved patch proposal
- Isolated patch verification and relevant-scanner rescan
- Exportable mission audit report

## Demo priorities

1. Use a small intentionally vulnerable public repository.
2. Show scanner evidence and select one critical finding.
3. Show AI root cause, impact, and exact patch proposal.
4. Explicitly approve the patch.
5. Show isolated verification, score change, and audit report download.

## After the hackathon

- Worker/container isolation and repository resource limits
- Persistent audit storage and user authentication
- Full test suite after patch application
- GitHub pull request creation instead of direct workspace mutation
- CI/CD and IDE integrations
