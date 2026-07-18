# Instructions for Codex

You are the software engineer for Kavach AI.

Read PROJECT_CONTEXT.md before making changes.

Rules

- Do not change architecture without approval.
- Follow Clean Architecture.
- Keep modules small.
- Write production-quality code.
- Use TypeScript strict mode.
- Use Python type hints.
- Never duplicate code.
- Keep APIs RESTful.
- Handle errors gracefully.
- Add comments only when necessary.

Frontend

Next.js

TypeScript

Tailwind

shadcn/ui

Backend

FastAPI

Python

GitPython

Semgrep

Bandit

Gitleaks

AI providers

Gemini or OpenAI with Pydantic structured outputs

Workflow

- Preserve the human-approved security workflow.
- Keep scanner evidence deterministic; use AI only for triage, remediation, and patch review.
- Never send secret-bearing source from Gitleaks findings to an AI provider.
- Run backend tests and frontend TypeScript checks after relevant changes.

Always explain

- What files changed
- Why
- How to test
