# Vercel AI SDK: OPA policy + provenance guard, composed

Answers vercel/ai#18376 ("compose deterministic policy with judgment-based approval") and #13434
(GuardrailProvider: pre-call decision, approval context, post-call receipt).

- `policy.rego`: role/limit rules evaluated by `@ai-sdk/policy-opa` (build with
  `opa build -t wasm -e agent/call/decision policy.rego`).
- `index.ts`: `composeToolApproval(opaToolApproval, provider.toolApproval())`: both run on every
  call, **deny wins**, `user-approval` beats `approved`, reasons are joined so the approval card
  shows both "opa: over limit" and "untrusted-to-exfil-sink: identifier from read_email → args.url".
- `provider.onToolExecutionEnd()` writes a hash-chained receipt per call and taints the output into
  the guard (`taintMemoryWrite`, OWASP ASI06) so anything the agent persists is already labelled.
- `provider.prepareStep()` narrows `activeTools` to read-only tools for the rest of a turn in which
  a tool result scored as injection.

The composition is unit-tested in `tests/adapters/vercel-guardrail.test.ts` with an OPA-shaped
fake; this folder is documentation, not part of the build.
