# Kavach AI

## Project Name

Kavach AI - AI Security Mission Control

## Vision

Kavach AI is an AI Security Mission Control platform for the **Security** hackathon theme. It orchestrates security scanners and AI to transform findings into human-approved, scanner-verified remediation.

This is not another security scanner.

Existing scanners detect problems. Kavach AI explains, prioritizes, recommends a safe fix, verifies remediation, and produces developer-ready evidence.

## Problem Statement

Developers receive security findings but still need to understand the vulnerability, research the fix, implement it securely, and verify the remediation. Kavach AI reduces that manual security-engineering loop.

## Users

- Software Developers
- DevSecOps Engineers
- Security Engineers
- Students learning secure coding

## MVP Scope

```text
GitHub Repository
  -> Clone Repository
  -> Run Security Scanners
  -> Normalize Evidence and Prioritize Risk
  -> AI Security Analysis
  -> Human-approved Patch Proposal
  -> Isolated Verification Rescan
  -> Mission Report
```

## Technology

### Frontend

- Next.js 15
- React
- TypeScript
- Tailwind CSS

### Backend

- FastAPI
- Python 3.12

### Security

- Semgrep
- Bandit
- Gitleaks

### AI

- OpenAI Responses API
- Structured Outputs with Pydantic

### Git

- GitPython

## Architecture Philosophy

- Security-first, evidence-backed workflow
- Clean Architecture and small service modules
- Background mission orchestration with observable state
- Human approval before a source change
- Isolated patch verification before applying to the mission workspace
- No database or authentication for the MVP
- Temporary repository workspaces and in-memory mission state

## UI Theme

Dark cyber-security Mission Control dashboard. The live mission and demo preview must always be visibly distinct.

## Code Standards

- TypeScript strict mode
- Python type hints
- Small reusable functions
- Proper error handling
- Consistent folder structure

## Goal

Build a convincing, working Security-theme hackathon MVP in 24 hours. Prioritize verifiable evidence over unbounded autonomy.
