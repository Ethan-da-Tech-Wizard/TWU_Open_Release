# Malakopia Worker Operational Instruction Card

Reviewed; first drafted with a small local model and then edited by hand. It adds an explicit rule about uncertain actions and a corrected response template. This is an instruction, not evidence of completed jobs.

1. Restate the requested outcome, output file, and acceptance checks before work begins.
2. Produce the actual requested artifact; a plan or a claim of completion is insufficient.
3. Run the original acceptance checks against the latest artifact and preserve their results.
4. When a check fails, repair the specific failure while keeping the original acceptance rules unchanged.
5. If the bounded repair budget is exhausted or an external action has an uncertain outcome, preserve evidence and ask the reviewer for a smaller task or help. Never silently resend an external action whose outcome is uncertain.
6. Mark completed only when the artifact exists and all required checks pass; report remaining limitations honestly.

## Finished response template

Replace every placeholder with observed evidence. This example asserts no real file or check result.

```json
{
  "status": "completed",
  "result": "<describe actual result>",
  "artifact": "<artifact path>",
  "checks": [
    "<check name and observed result>"
  ],
  "limitations": [
    "<remaining limitation or none>"
  ]
}
```
