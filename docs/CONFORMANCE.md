# Guard conformance

Numbered behaviours the agent guard (`prompt-protection/guard`) is tested against, one test per number
in `tests/guard/conformance.test.ts`. A number never changes meaning; new behaviours append. Numbers
marked *reserved* land in the minor named and are not yet asserted.

Reason codes referenced below are `DecisionReason` values (`src/guard/reasons.ts`), carried in
`GuardDecision.reasons`, highest severity first.

| # | Behaviour | Reason code | Since |
|---|---|---|---|
| 1 | A destination split across arguments (`{host, path}`, `{user, domain}`) still correlates with the tool result it came from and is blocked at an exfil sink. | `untrusted-to-exfil-sink` | 4.1 |
| 2 | A memory entry whose lineage reaches a `blocked` source, read back in a later session, blocks a flow into an exfil or exec sink even when the entry text itself scores clean. | `lineage-untrusted` | 4.1 |
| 3 | A lineage edge weaker than `STRONG_EDGE` (0.5) is recorded but does not propagate the parent's label. | — | 4.1 |
| 4 | `guard.handoff()` → `guard.absorb()` / `guard.fork()` carries source labels and trusted identifiers; the receiving guard's `depth` is `parent + 1` and appears in every decision. | — | 4.1 |
| 5 | A confirmed approval whose call arguments differ from the card (any value, after canonicalisation) blocks. | `approval-mismatch` | 4.1 |
| 6 | A confirmed approval replayed with canonically identical arguments clears a `confirm` to `allow`. It never clears a `block`. | `approved` | 4.1 |
| 7 | A confirmed approval past its TTL, or already spent, asks again. | `approval-expired` | 4.1 |
| 8 | Tool pinning: an unlisted or drifted tool definition under a lock. | `tool-unpinned`, `tool-drift` | 4.2 *reserved* |
| 9 | `readOnlyHint` and other annotations are honoured only under a lock. | — | 4.2 *reserved* |
| 10 | Loop and depth budgets. | `budget-exceeded` | 4.2 *reserved* |
| 11 | Observe mode records the would-be action without enforcing it. | — | 4.3 *reserved* |
| 12 | The `balanced` preset reproduces `DEFAULT_POLICIES` verdicts on the legacy dataset rows. | — | 4.3 *reserved* |
| 13 | `explain()` yields one step per reason code. | — | 4.3 *reserved* |
| 14 | `canonicalJson` follows RFC 8785 for JSON-representable values (sorted keys by UTF-16 code unit, `toJSON` honoured, `undefined` members omitted, `-0` → `0`) and throws `CanonicalJsonError` for `NaN`, `±Infinity`, `BigInt`, `Map`/`Set`, cycles and depth over 64. | — | 4.1 |
| 15 | Signed taint envelope: forged, replayed, expired or unknown-key envelopes are rejected. | `envelope-invalid` | 4.4 *reserved* |
| 16 | Under `failMode: 'closed'`, a throwing approval store, label resolver or policy yields a `block` with `internal-error`; malformed memory entries and handoffs throw rather than register. Under `'open'` the decision is `allow` with the same reason. | `internal-error` | 4.1 |

## Dataset rows

`datasets/agent-flows.jsonl` rows with a `steps` array exercise these behaviours end to end through
`datasets/steps.cjs`, the interpreter shared by `tests/guard/agent-flows.test.ts` and `bench/run.mjs`.
Scenarios `memory-persist`, `subagent-hop`, `split-identifier` and `approval-swap` each carry at least
three attack and two benign rows; their `expect_reason` is a `DecisionReason` the final decision must
contain. Bench gates: recall ≥ 90% on the first three, agreement = 100% on `approval-swap`.
