# Demo Script

## Opening - 15 seconds

"Kavach AI is Security Mission Control. It takes a raw vulnerability finding all the way to a human-approved, scanner-verified fix."

## 1. Launch mission - 15 seconds

Paste a small intentionally vulnerable public GitHub repository and click **Start live mission**.

Point out that the dashboard immediately shows a queued mission rather than pretending the scan is instant.

## 2. Show evidence - 20 seconds

Show the mission audit trail advancing through repository intake, scan completion, AI triage, and AI remediation. Show scanner health and an actionable finding with scanner rule, file, and line.

Say: "These are real scanner adapters, not LLM-only findings."

## 3. Show multi-agent decisions - 30 seconds

Point out the Triage Agent decision, then select a finding. Explain the root cause, impact, confidence, and exact before/after patch. Show the Patch Review Agent verdict below the draft.

Say: "Kavach uses AI for bounded prioritization, remediation, and independent patch review, but the developer remains in control."

## 4. Approve and verify - 25 seconds

Click **Approve, apply & verify**.

Explain that Kavach first copies the repository, applies the exact patch only in that isolated workspace, reruns the relevant scanner, and touches the mission source only if the finding disappears.

Show the resulting verification message and security score change.

## 5. Close - 10 seconds

Download the HTML report, then mention the JSON export for machine-readable audit evidence.

"Kavach turns detection into a transparent, human-approved, verified security decision - not just another report."
