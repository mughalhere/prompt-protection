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
| 8 | Under a lock (`guard.pin` / `guard.lock`), a tool the lock does not list is refused, a pinned tool whose definition (name, description, schema, annotations; never `execute`) changed is refused or confirmed per `LockOptions.drift`, and `requireLock` refuses every call until a lock exists. | `tool-unpinned`, `tool-drift` | 4.2 |
| 9 | Annotations are honoured only under a lock: `readOnlyHint: true` resolves the sink to `none`; an unannotated tool the name heuristics call `none` resolves to `unknown` (exfil + exec) unless `annotationsDefault: 'heuristic'`. Explicit `sinks` always win. Unlocked guards resolve sinks exactly as 4.0. | — | 4.2 |
| 10 | Budgets (`GuardOptions.budgets`) count every attempt, blocked ones included; the fourth canonically identical call exceeds the default repeat budget; per-turn, per-tool, depth and cost limits yield `block` or `confirm` per `onExceed`. Budgets are off unless configured. | `budget-exceeded` | 4.2 |
| 11 | `mode: 'observe'` computes the verdict, returns `action: 'allow'` with `observedAction` / `observedRequiresConfirmation`, never throws from `wrapTools`, and logs the would-be action with `mode: 'observe'` so blocks still reach the log. | — | 4.3 |
| 12 | `preset: 'balanced'` (or no preset) reproduces `DEFAULT_POLICIES` verdicts on every legacy dataset row; `strict` and `permissive` only add or relax, and explicit options always beat the preset. | — | 4.3 |
| 13 | `explain(decision)` yields one step per reason code in decision order, with the flows on policy steps; unknown (future) codes get a generic line rather than an error. | — | 4.3 |
| 14 | `canonicalJson` follows RFC 8785 for JSON-representable values (sorted keys by UTF-16 code unit, `toJSON` honoured, `undefined` members omitted, `-0` → `0`) and throws `CanonicalJsonError` for `NaN`, `±Infinity`, `BigInt`, `Map`/`Set`, cycles and depth over 64. | — | 4.1 |
| 15 | Signed taint envelope (`prompt-protection/envelope`, preview): `open()` checks malformed → unknown key → signature → expiry / skew → nonce, in that order, so a forgery never reaches the nonce store. `guard.taintEnvelope` accepts a verified label as attested (injection-scored text stays `blocked`); a failed open registers a `blocked` source whose lineage starts at `envelope:<code>`, and any flow from it is refused. Sealed handoffs (`sealHandoff` / `absorbSealed`) and sealed memory entries (`sealMemoryEntry` / `memoryReadSealed`) follow the same rule (`handoff-untrusted`). Below the crypto floor everything fails closed with `crypto-unavailable`. | `envelope-invalid`, `handoff-untrusted` | 4.4 |
| 16 | Under `failMode: 'closed'`, a throwing approval store, label resolver or policy yields a `block` with `internal-error`; malformed memory entries and handoffs throw rather than register. Under `'open'` the decision is `allow` with the same reason. | `internal-error` | 4.1 |

## Dataset rows

`datasets/agent-flows.jsonl` rows with a `steps` array exercise these behaviours end to end through
`datasets/steps.cjs`, the interpreter shared by `tests/guard/agent-flows.test.ts` and `bench/run.mjs`.
Scenarios `memory-persist`, `subagent-hop`, `split-identifier` and `approval-swap` each carry at least
three attack and two benign rows; their `expect_reason` is a `DecisionReason` the final decision must
contain. Bench gates: recall ≥ 90% on the first three, agreement = 100% on `approval-swap`.
