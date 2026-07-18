# Kavach AI

## Theme

**Security**

Kavach AI is an AI Security Mission Control platform: from vulnerability to verified fix.

## Elevator pitch

Security scanners find problems, but they do not close the security-engineering loop. Developers still have to interpret the finding, decide what is safe to change, implement it, and prove the fix worked.

Kavach AI turns scanner evidence into a human-approved remediation mission. It prioritizes risk, explains the finding, proposes the smallest safe patch, independently reviews the draft, validates it in an isolated workspace, reruns the relevant scanner, and exports the audit trail.

## What makes it different

```text
Traditional scanner: detection -> report

Kavach AI: detection -> evidence -> AI triage -> remediation -> patch review -> human approval -> verification -> audit report
```

Kavach does not claim autonomous code changes. The developer explicitly approves the patch, and the original workspace changes only after an isolated scanner rescan succeeds.

## Architecture story for judges

- Semgrep, Bandit, and Gitleaks produce real scanner evidence.
- Findings are normalized with stable scanner/rule/path fingerprints.
- Gemini or OpenAI returns structured triage, remediation, and patch-review output rather than unstructured chat text.
- Potential secrets are never sent to the model; Kavach directs the user to rotate them manually.
- Patch verification happens in a temporary copy of the repository.
- HTML and JSON mission reports capture score change, scanner health, findings, agent trace, and verification evidence.

## Demo

[Watch the Kavach AI demo on YouTube](https://youtu.be/GliteRW-RAI)

## Closing statement

Kavach AI does not replace security scanners. It makes their findings actionable, reviewable, and verifiable.
