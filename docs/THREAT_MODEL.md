# Threat model

What prompt-protection defends, against whom, and what it knowingly does not cover. Numbers cited
here come from `bench/results.json` and `training/REPORT.md`; identifiers refer to the OWASP Top 10
for LLM Applications (2025) and MITRE ATLAS. OWASP Agentic (ASI) identifiers are added once verified
against the published list.

## Assets

| Asset | Where it lives | Loss looks like |
|---|---|---|
| System prompt and operator instructions | model context | verbatim or paraphrased disclosure (LLM07:2025, AML.T0056) |
| Credentials reachable by tools | tool results, environment, files | exfiltration through an outbound tool call (LLM02:2025, AML.T0057) |
| User data inside tool results | email, calendar, documents, RAG chunks | forwarded to an attacker-chosen destination |
| Agent memory / long-term store | vector DB, notes, conversation summaries | poisoned with instructions that fire in later sessions |
| Side-effecting capabilities | network, email, messaging, file-write, exec, payment sinks | invoked with attacker-derived arguments |

## Trust boundaries

| Input | Trust | Why |
|---|---|---|
| Policy configuration, `sinks`, `plan()` | trusted | authored by the operator |
| User turn | semi-trusted | the user may be the attacker, but destinations the user names are theirs to name |
| Tool results (`guard.taint`) | **untrusted** | any tool result may carry attacker text (indirect injection, LLM01:2025) |
| Model output | untrusted | the model may have been steered by any of the above |
| Tool annotations (`readOnlyHint`, descriptions) | untrusted | supplied by the tool author; never used to relax a sink |

## Attacker capabilities assumed

- Controls the full content of any tool result (web page, email, file, RAG chunk, MCP tool description).
- Can paraphrase, encode (base64, percent, homoglyphs, zero-width), translate, or split instructions.
- Knows this library's rules and policies (they are public).
- **Cannot** alter guard state, policy configuration, or the harness code.

## Defences and what each covers

| Threat | Mechanism | Evidence |
|---|---|---|
| Untrusted data reaching an exfil/exec/payment sink | provenance guard: identifier, exact and shingle-containment flows → `untrusted-to-exfil-sink`, `untrusted-to-exec`, `untrusted-to-payment` | agent-flows agreement 100 % on 99 scored rows, benign FPR 4 % |
| Injection-bearing source followed by a sink call with no detectable flow | `injection-then-sink` (flag), `prepareStep` quarantine of sink tools for the rest of the turn | `af-036`; documented miss `af-037` when the rules score the source 0 |
| Tool set drift / unplanned actions | `plan()` allow-list → `plan-violation` | `af-0xx` plan rows |
| Memory poisoning | `taintMemoryWrite` refuses to store injection-scored results; spotlit text offered instead | unit tests; no external benchmark yet |
| Instruction/data confusion in the model | spotlighting (delimit / datamark / encode) | arXiv 2403.14720 reports ASR > 50 % → < 2 %; we ship the transform, not a re-measurement |
| System-prompt leakage in output | fuzzy canary variants + shingle similarity + output rules | output bench 10/10, 0 FP on 8 benign |
| Known-phrase injection and jailbreaks in text | 106 input rules, embedded classifier (off) | NotInject over-defence 97.1 %; **19.4 % FP** on hard benign; 14.6 % recall on evasive attacks |
| Library-internal failure | fail-closed (`failMode: 'closed'`) | `tests/fail-closed.test.ts` |
| Regex denial of service | every regex fuzzed with `recheck` in CI | 147 safe / 1 reviewed / 0 vulnerable of 148 |
| Supply chain | zero runtime dependencies; optional peers loaded dynamically; npm provenance; SBOM at release | `package.json`, `publish.yml` |

## Explicit non-goals

- **Isolation.** This is a policy layer inside your process. It cannot stop a tool that exfiltrates on its own side, a flow the model carries in hidden state, or a source you never registered.
- **Semantic paraphrase without shared identifiers.** Tainted prose rewritten so it shares no URL, email, path, token or 6-word shingle with its source is invisible to the guard.
- **Encodings the normaliser does not undo** (rot13, chunk reordering, translation) defeat containment.
- **Perfect recipient intent.** "Reply to them" leaves the recipient derived from the source, the same shape as attacker exfil; the default blocks and the harness should `trust()` the sender or install a confirm policy.
- **Attacks without a sink** — persuasion, misinformation, content policy — are out of scope.

## Failure semantics

Any internal throw yields `block` with a synthetic `internal-error` match, `result.error` set, and a logged event carrying the error. `failMode: 'open'` lets input through with the error still reported. A throwing logger never changes a verdict. Async LLM adapters propagate their failure (nothing passes) unless `failMode: 'open'`.

## Residual risks

- Rule over-defence on text *about* security (19.4 % FP on `datasets/benign-hard.jsonl`), gated at baseline and ratcheted down.
- The embedded classifier does not generalise across jailbreak genres (LODO F1 0.53); it stays off.
- Agent-flow evaluation is our own 100-row set, not an external benchmark; AgentDojo-format results are a follow-up.
- Identifier flow detection depends on the attacker's destination being expressible as a URL, host, email, path, IP or long token.
