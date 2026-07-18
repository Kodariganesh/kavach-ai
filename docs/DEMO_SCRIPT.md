# Demo Script

## Opening - 15 seconds

"Kavach AI is Security Mission Control. It takes a raw vulnerability finding all the way to a human-approved, scanner-verified fix."

## 1. Launch mission - 15 seconds

Paste a small intentionally vulnerable public GitHub repository and click **Start live mission**.

Point out that the dashboard immediately shows a queued mission rather than pretending the scan is instant.

## 2. Show evidence - 20 seconds

Show the mission audit trail advancing through repository intake, scan completion, and AI remediation. Show scanner health and a critical finding with scanner rule, file, and line.

Say: "These are real scanner adapters, not LLM-only findings."

## 3. Show AI remediation - 20 seconds

Select the critical SQL injection (or similar) finding. Explain the root cause, impact, confidence, and exact before/after patch.

Say: "Kavach uses the model for bounded remediation, but the developer remains in control."

## 4. Approve and verify - 25 seconds

Click **Approve, apply & verify**.

Explain that Kavach first copies the repository, applies the exact patch only in that isolated workspace, reruns the relevant scanner, and touches the mission source only if the finding disappears.

Show the resulting verification message and security score change.

## 5. Close - 10 seconds

Download the JSON report.

"Kavach turns detection into a transparent, verified security decision - not just another report."
