# Changelog

## [4.0.0] - 2026-09-21

The surface cut. The guard is the product; text detection is a component; the root entry is the
stable tier and nothing else. No scoring, guard or rule behaviour changes; `RULES_VERSION` is
unchanged. Migration: `docs/migrations/v4.md`. Tiers and cadence: `docs/API_STABILITY.md`.

### Changed (breaking)
- Root entry exports only the stable tier: `analyzePrompt`, `verifyPrompt`, `stripPrompt`,
  `verifyPromptAsync`, `analyzeOutput`, `scanToolDefinition`, `createProtectionSession`,
  `createConsoleLogger`, `PromptInjectionError`, `ClaudeAdapter`, `OpenAIAdapter`, `RULES_VERSION`
  and the types. Engine plumbing (`normalize`, `resolveAction`, `precisionAllowsBlock`,
  `computeSeverity`, `analyzePromptWith`, `INTERNAL_ERROR_RULE`, message helpers, rule arrays) moves
  to `prompt-protection/internal`. The classifier moves to `/ml` only; spotlighting and canaries to
  `/spotlight` and `/canary` only. `/lite` drops the same re-exports.
- `ThreatCategory`, `ProtectionEvent['type']`, `ProtectionEvent['direction']`, guard `SinkKind` and
  `FlowKind` are open unions (`| (string & {})`). Exhaustive `switch` with a `never` default no
  longer compiles; unknown values should be handled as `flag`.

### Added
- `prompt-protection/internal` entry.
- `docs/API_STABILITY.md`: stable / preview / internal tiers, open-union rule, release cadence.
  `tests/api-surface.test.ts` enforces the root export list.
- `@beta` headers on every preview-tier entry file.
- Pre-release versions publish under the `next` dist-tag (`publish.yml`).

### Versioning
- 1.0, 2.0 and 3.0 were cut as majors for milestone reasons. From 4.0 a major is reserved for an
  incompatible change to the stable tier, at least six months apart, with a migration document.

## [3.1.1] - 2026-09-15

Registry metadata only. No code, rule or behaviour changes; `RULES_VERSION` is unchanged.

### Added
- `mcpName` in `package.json` and a root `server.json`, so the bundled MCP server can be listed in the
  [MCP registry](https://registry.modelcontextprotocol.io) as `io.github.mughalhere/prompt-protection`.
  `server.json` ships in the npm tarball, which is how the registry verifies ownership of the package.

### Fixed
- The README listed three MCP tools. The server has exposed seven since 3.0: `scan_prompt`,
  `scan_tool_definition`, `scan_output`, `register_source`, `check_tool_call`, `spotlight_text` and
  `detect_canary`.

## [3.1.0] - 2026-09-15

Production-grade release: nothing in the detection or guard semantics changes; what changes is
what the library can prove about itself and how it plugs into standards and frameworks.

### Added
- **Fail-closed semantics.** Any internal throw yields `block` with a synthetic `internal-error`
  match and `result.error`; `failMode: 'open'` opts into pass-through with the error still
  reported. Guard policies that throw block and name themselves; tool-call events carry
  `toolCallId`, `policy`, `reasons`, `sink` and value-free `flows`. `fallbackToSync` is a
  deprecated alias of `failMode: 'open'`.
- **ReDoS proof.** Every shipped regex (148) is fuzzed with `recheck` in CI (`npm run test:redos`);
  `vulnerable` fails, `unknown` passes only through a justified allowlist. The fuzzer found 29
  polynomial patterns in 3.0.0: all rewritten to linear forms with no bench regression; the allowlist is empty.
- **ATR interop** (`prompt-protection/atr`, `prompt-protection/atr/yaml`). `loadAtrRules` compiles
  `agent-threat-rules` YAML (regex / contains / exact / starts_with) into `customRules`, honouring
  `scan_target`, `agent_source` (spec §5.1), status and the enforce lane; AND / named / behavioural
  conditions are skipped with a reason, never approximated. `toAtrFindings` emits the spec §5.5
  ScanResult. `PatternRule` gains `mappings` (OWASP LLM 2025 + ATLAS ids for 62/106 input rules,
  CI-checked coverage floor) and `origin`. `yaml` is an optional peer.
- **Vercel reference composition** (`prompt-protection/adapters/vercel-guardrail`).
  `createGuardrailProvider` implements the pre-call decision / approval context / hash-chained
  receipt shape from vercel/ai#13434 on the provenance guard, with bridges for `toolApproval`,
  `onToolExecutionEnd` (taints outputs into memory) and `prepareStep` (plan lock + quarantine).
  `composeToolApproval` merges approval functions with deny > user-approval > approved, for use
  next to `@ai-sdk/policy-opa` (`examples/vercel-policy-opa/`). Guard gains `taintMemoryWrite`
  (OWASP ASI06) and `lastDecision`.
- **Observability.** `prompt-protection/audit`: tamper-evident JSONL audit log (SHA-256 hash chain,
  content stored as a digest by default, `replayAuditLog` re-verifies). `prompt-protection/otel`:
  span events / child spans and a `pp.decisions` counter with value-free `pp.*` attributes;
  `@opentelemetry/api` is an optional peer. `ProtectionLogger.logWithContent` hook.
- **Runtime compatibility proofs** in CI: Bun, Deno, and a no-Node-globals `vm` evaluation of the
  bundles (edge/browser proxy). README table; `npm run compat`.
- **Governance.** `docs/THREAT_MODEL.md`, `ADOPTERS.md`, SECURITY.md sections on failure semantics,
  regex safety, no telemetry and supported versions; CycloneDX SBOM attached to every GitHub
  release (`npm run sbom`); `RULES_VERSION` pinning with a digest test; `training/publish_hf.py`.
- **Bench**: agent-flows report "utility under attack" (benign pass-through) beside attack
  block-recall, per-scenario breakdown, `--json`; new gate benign utility ≥ 85 %.

### Rules
- `RULES_VERSION` 2026.09.15: 29 patterns rewritten for linear-time matching (see ReDoS proof);
  semantics preserved, benchmark unchanged.

### Deferred
- Mastra, OpenAI Agents JS, Genkit and LangChain.js adapters: designed (structural types, optional
  peers) but not shipped in 3.1.0, the hook shapes need verifying against installed packages first.

## [3.0.0] - 2026-09-14

Category change, not a rule change. 2.x was a regex scanner; 3.0 is an agent security
runtime whose primary mechanisms are not pattern matching. Every number below comes from
`bench/results.json` and `training/REPORT.md`, including the bad ones.

### Added
- **Tool-call guard** (`prompt-protection/guard`, `createGuard`). CaMeL-style provenance:
  tool results are labelled untrusted (`guard.taint`), user-named destinations are trusted
  (`guard.trust` / `analyzeUserTurn`), and every model-proposed call is checked
  (`guard.checkToolCall`) before execution. Flows are approximated across the model
  boundary by identifier tracking (URLs, hosts, emails, paths, tokens), exact substring and
  word/char shingle containment. Default policies block untrusted data reaching network /
  email / message / exec / file-write sinks, require confirmation for payment sinks, flag a
  sink call in the same turn as an injection-scored source, and enforce `guard.plan()`
  tool allow-lists. `guard.wrapTools()` enforces at execution; `guard.vercelToolApproval()`
  maps decisions onto the Vercel AI SDK `toolApproval` hook.
- **Spotlighting** (`prompt-protection/spotlight`): `spotlight` / `unspotlight` /
  `spotlightInstruction` in delimit, datamark and encode modes (arXiv 2403.14720). Composes
  with the guard: datamarked results are unmarked before flow detection.
- **Canaries** (`prompt-protection/canary`): `createCanary`, `injectCanary`, `detectCanary`
  with exact / normalized / spaced / base64 / hex / reversed / partial variants, plus
  `promptSimilarity` (shingle containment of the system prompt in the output).
  `analyzeOutput` accepts `canary` and `systemPrompt` and reports `result.canary`.
- **Embedded ML classifier** (`prompt-protection/ml`): hashed char 3–5-gram + word 1–2-gram
  logistic regression, 65,536 int8 buckets (33 KB gz), FNV-1a hashing reproduced bit-for-bit
  between Python training and JS inference (64 golden vectors under test). Exposed as
  `mlClassifier`, `predict`, and `analyzePrompt(text, { ml: 'escalate' | 'hybrid' })`.
  **Off by default**: see Known limitations.
- **`prompt-protection/lite`**: rules-only entry (20 KB gz) for size-sensitive browsers.
- **Datasets** (`datasets/`, CC-BY-4.0): 130 regex-evading attacks, 155 trigger-word benign
  prompts in NotInject's categories, 100 agent tool-call flows with expected decisions.
- **Benchmark**: regex / ml / hybrid side by side over local, published and external sets
  (NotInject, in-the-wild sample), agent-flow agreement, bundle-size gate. Runs in CI.
- **MCP server** tools `register_source`, `check_tool_call`, `spotlight_text`, `detect_canary`.
- **Output rule `out-markdown-image-beacon`** (weight 8, medium precision, blocks on its own): a
  markdown image whose URL carries a ≥16-char opaque query value, the zero-click exfil beacon the
  existing `out-markdown-exfil-link` rule only caught when the parameter was literally named
  `token`/`secret`. Found by the new output bench row `out-010`. Known trade-off: a signed CDN image
  URL echoed in model output will trip it; exclude with `allowlistRules: ['out-markdown-image-beacon']`.
- **Demo**: "Agent Guard" tab (user turn → tainted tool result → proposed call → decision) and the
  embedded model's probability shown next to the rules verdict.
- **Vercel middleware** `guard` and `onBlock` options: taints `tool-result` parts, checks
  `tool-call` parts in generate and stream (advisory, enforce with `wrapTools`).

### Changed (breaking)
- `ThreatCategory` gains `'data-flow'`; `ProtectionEvent.type` gains `tool-call.*` and
  `direction` gains `'tool-call'` (exhaustive switches need a case).
- `AnalysisResult.ml?`, `OutputAnalysisResult.canary?` added. `computeSeverity` moves to
  `src/core/analyze.ts` (still re-exported from the root).
- MCP server version 3.0.0. Package description/keywords no longer lead with a rule count.
- Sink inference: `http_*` tool names classify as `network` (previously `message` via `post`).

### Known limitations (measured)
- **Regex rules over-defend.** 19.4% false positives on `datasets/benign-hard.jsonl`
  (questions about prompt injection, fiction, "admin access" in benign use) and 14.6% recall
  on `datasets/attacks.jsonl`, which was written to evade proximity matching. NotInject
  over-defence accuracy is 97.1%. These are now CI-gated at baseline and ratcheted down.
- **The embedded model does not generalise yet.** 3-fold CV F1 0.98 in-distribution, but
  leave-one-dataset-out F1 0.53 and in-the-wild AUROC 0.67; recall 19% on our attacks set at
  24.5% in-the-wild FPR. Two training rounds: adding hackaprompt (7.8k attacks after dedupe)
  raised recall and false positives together and left cross-dataset F1 flat. Hashed n-grams
  do not transfer across jailbreak genres. Shipped for transparency and so the pipeline is
  reproducible; `ml` defaults to `'off'` until a model clears the external bench
  (in-the-wild recall ≥ 80% at an FPR clearly below the rules'). Enable with `{ ml: 'escalate' }`.
- **The guard is a policy layer, not an isolation boundary.** It cannot see flows through
  the model's hidden state, paraphrased content with no shared identifiers, or sources it
  was never told about. A recipient lifted from a tool result ("reply to them") is
  indistinguishable from an attacker address and blocks by default; call `guard.trust()`
  or swap in a confirm policy. One agent-flow row (`af-037`) is a documented miss.

## [2.0.1] - 2026-09-08

Benchmark-integrity release. No rule or API changes: the detection behaviour of
2.0.0 is untouched. What changes is how honestly the benchmark is reported and
whether anything mechanically keeps it true.

### Fixed
- **The published benchmark number was contaminated by the test fixtures.** 134 of
  the 169 input corpus items were byte-identical to `tests/__fixtures__/`, which
  `tests/api.test.ts` asserts on in CI: so they could not score wrong while the
  build was green. `bench/run.mjs` now partitions the corpus by set-membership
  against the fixtures at runtime and reports three rows: **tuning** (134 items,
  100%/100%/0%), **held-out** (35 items, **75.0% recall / 93.8% precision /
  6.7% FP**), and combined (unchanged at 94.8%/98.9%/1.4%). The split is computed,
  never maintained, so it cannot drift: a corpus line that is not also a fixture is
  automatically held out.
- **The benchmark now actually runs in CI.** README and the wiki claimed it ran as
  a CI gate; no workflow invoked it. `.github/workflows/ci.yml` gains a `bench` job,
  and `all-checks-passed` depends on it. The gate covers combined recall/FP,
  held-out recall/FP, and tool recall.
- **`bench/results.json` was written before the gate evaluated**, so a regressed run
  persisted its own numbers. The gate now runs first; a failing run exits non-zero
  and leaves the last-good file untouched.
- **Latency p99 was a cold-start artifact.** The benchmark had no warm-up, so with
  n=169 the p99 index landed on a JIT-compilation sample (10.16 ms). A warm-up pass
  brings it to steady state (~0.06 ms). The published p50 was always sound.
- `package.json` description advertised **117 rules**; actual is 126. npm renders
  this on the public package page.
- `demo/public/docs/owasp-llm01-prompt-injection.html` said "97 rules across seven
  categories"; actual is 106 across eight.
- `CONTRIBUTING.md` said `ThreatCategory` has 6 members; it has 8.

## [2.0.0] - 2026-09-03

The agentic-security major. Adds MCP tool-poisoning defence, an MCP server, a
Vercel AI SDK adapter, and a published, measured detection benchmark. The base
`npm install prompt-protection` stays **zero runtime dependencies**, the two new
SDK-backed surfaces are separate subpaths with *optional* peer dependencies.

### Added
- **Tool-poisoning detection.** New `tool-poisoning` threat category (9 rules) and
  `scanToolDefinition(tool)`: scans a tool/function definition (name, description,
  parameter schema; OpenAI `parameters` or MCP `inputSchema` shape) for hidden
  instructions, concealment directives ("do not tell the user"), exfiltration, and
  injection embedded in tool metadata. The rules also run on `tool`-role messages
  in normal transcripts.
- **MCP server** (`prompt-protection/mcp`, bin `prompt-protection-mcp`). Exposes
  `scan_prompt`, `scan_tool_definition`, and `scan_output` as MCP tools so an agent
  can vet its own inputs, tools, and outputs. Optional peer `@modelcontextprotocol/sdk`.
- **Vercel AI SDK adapter** (`prompt-protection/adapters/vercel`). `promptProtectionMiddleware()`
  for `wrapLanguageModel`; verifies user prompts before the call and optionally scans
  output. Optional peer `ai` (>=4).
- **Benchmark harness** (`npm run bench`) over a labeled corpus in `bench/corpus/`,
  reporting recall/precision/FP-rate/F1/latency to `bench/results.json`, and acting
  as a CI gate. Published numbers: input detection **94.8% recall / 98.9% precision /
  1.4% FP**, tool poisoning **100% / 100%**.
- **`llms.txt`** at the site root and repo, for AI coding assistants.
- `maxInputLength` option (default 100_000) on input and output analysis.
- Exports: `scanToolDefinition`, `TOOL_RULES`, `toolPoisoningRules`, `ToolDefinition`,
  `createProtectionMcpServer`, `promptProtectionMiddleware`.

### Changed
- Rule totals: **106 input across 8 categories + 20 output = 126** (was 97 + 20 = 117).
- **Performance:** rule regexes are now compiled once and cached (was recompiled per
  `score()` call); `buildIndexMap` no longer rescans the tail on decode-appended input
  (O(n²) → O(n) in the pathological case). These can shift `stripPrompt` span offsets
  or scores by a hair on unusual inputs, part of why this is a major bump.

### Migration
- Fully backward compatible for the documented API. `ThreatCategory` gained the
  `tool-poisoning` value: widen any exhaustive switch over it. Adaptive/pathological
  inputs may score marginally differently after the normalizer/scorer changes.

---

## [1.8.3] - 2026-08-20

### Fixed
- **`prompt-protection/adapters/openai` subpath was unresolvable.** `package.json`
  declared the export map entry, but `src/adapters/openai.ts` was missing from the
  `tsup` entry list, so `dist/adapters/openai.*` was never built. Importing
  `OpenAIAdapter` from the documented subpath failed at runtime; only the root
  barrel (`from 'prompt-protection'`) worked. Added the entry: the subpath now
  emits ESM, CJS, and both declaration formats.
- `README.md` "How Detection Works" said 94 input regexes; the correct count is 97.

### Changed
- npm `description` rewritten to lead with the terms the package is searched by,
  and `keywords` expanded 10 → 20 (`ai-security`, `llm-firewall`, `guardrails`,
  `owasp-llm`, `prompt-security`, `injection-detection`, `chatbot-security`,
  `llm-safety`, `ai-red-team`, `gpt`). Discoverability only: no runtime effect.
- `README.md`: monthly-downloads badge, reworked opening, new FAQ section, and
  links to the new guides on the documentation site.

### Added
- Documentation site under `demo/public/docs/`: six static, self-contained pages
  covering prompt injection in Node.js, jailbreak detection, OWASP LLM01, output
  scanning, an attack-pattern reference, and a comparison with adjacent tools.
- Crawlable metadata for the GitHub Pages site: Open Graph and Twitter card tags,
  canonical URLs, `SoftwareApplication` / `TechArticle` JSON-LD, `sitemap.xml`,
  `robots.txt`, a 1200×630 social preview image, and a static content section on
  the landing page that does not depend on JavaScript.

### Notes
- No detection rules were added, removed, or altered. Rule counts are unchanged at
  97 input + 20 output = 117. All 418 tests pass.

---

## [1.8.2] - 2026-08-10

Supply-chain and tooling maintenance only. **No runtime behaviour changes**: no
rules added or altered, no API changes, all 418 tests pass unchanged.

### Added
- `socket.yml`: Socket.dev configuration. Scopes analysis to the files that make
  up the published package and excludes the standalone `demo/` app, which carries
  its own dependency graph and ships nothing. Deliberately leaves the `usesEval`,
  `networkAccess`, `shellAccess`, and `gptSecurity` rules enabled rather than
  suppressing those alert classes.
- `SECURITY.md`: new "Supply chain" section documenting that the package ships
  zero runtime dependencies, with commands to verify it and a triage table for
  third-party scanner alerts that originate in optional peers or the dev graph.

### Changed
- Dev dependencies `@anthropic-ai/sdk` `^0.52.0` → `^0.116.0` and `openai`
  `^6.38.0` → `^7.4.0`, so the local lockfile matches the versions supply-chain
  scanners resolve from the open-ended peer ranges.
- Applied non-breaking `npm audit` fixes across the dev toolchain: 10 advisories
  (4 high, 3 moderate, 3 low) → 1 low. The remainder is an `esbuild` dev-server
  issue reachable only on Windows via `tsup --watch`; it does not affect builds
  or the published output.
- CI Node matrix `[18.x, 20.x, 22.x]` → `[20.x, 22.x, 24.x]`, matching the
  `engines.node` field (`>=20`). The 18.x job was testing a version the package
  declares unsupported.

### Notes
- `npm audit --omit=dev` remains **0 vulnerabilities**.
- No 1.8.1 was published; this release follows 1.8.0 directly.

---

## [1.8.0] - 2026-07-28

### Added
- **Deferred-reference injection rules**: catches follow-ups that re-invoke a prior turn without repeating the attack:
  - `injection-process-last-prompt`: "process/run/execute the last/previous prompt/message/request"
  - `injection-do-what-said-before`: "do what I said before" / "do what I asked in the previous message"
  - `injection-retry-previous-request`: "retry/re-do my previous request"
- **`createProtectionSession()`**: opt-in multi-turn correlation
  - Remembers recently blocked prompts (ring buffer, default 5)
  - Escalates deferred-ref follow-ups when prior blocked history exists (`session-correlate-blocked`)
  - `analyze` / `verify` / `strip` / `clear` / `getBlockedHistory`
- React hook: `enableSession` / `session` options for chat UIs
- Express + Next.js middleware: optional `session` or `getSession(req)` for per-conversation correlation
- Exports: `createProtectionSession`, `ProtectionSession`, `ProtectionSessionOptions`, `DEFERRED_REFERENCE_RULE_IDS`

### Changed
- Package version bump: `1.7.0` → `1.8.0`
- Total rules: 97 input + 20 output = **117** (was 94 + 20)

---

## [1.7.0] - 2026-07-28

### Added
- **Three-way actions**: `action: 'allow' | 'flag' | 'block'` on every analysis result
  - `isMalicious` remains true only when `action === 'block'` (backward compatible)
  - Optional `flagThreshold` for a review band that logs/flags without throwing
  - `verifyPrompt` / middleware throw only on `block`
- **Precision gating**: rules tagged `precision: 'high' | 'medium' | 'low'`
  - Lone `low`-precision matches (e.g. soft context-smuggling) can `flag` but cannot alone `block`
- **Pluggable logging**: `logger`, `logLevels`, `includeContent`, `onLoggerError`
  - Emits `ProtectionEvent` for input/output blocked/flagged (and optionally allow/clean)
  - `createConsoleLogger()` helper for local debugging
- **Allowlists**: `allowlistPatterns` / `allowlistRuleIds` exclude known-good spans from scoring
- **Normalizer hardening**: multi-pass URL/base64 decode, Unicode Tags strip, bidi controls, fullwidth fold
- **Accurate strip positions**: scorer uses `indexMap` from the normalizer
- **New detection rules**: ChatML/Llama special tokens, policy puppetry, fake tool calls, many-shot jailbreaks, translate-then-obey, output email/phone PII and markdown/HTML exfil
- Middleware `onFlag` callback (Express + Next.js); React hook exposes `action` on results
- Exports: `Action`, `RulePrecision`, `ProtectionEvent`, `ProtectionLogger`, `LoggingOptions`, `LogLevel`, `createConsoleLogger`, `resolveAction`, `precisionAllowsBlock`

### Changed
- Package version bump: `1.6.0` → `1.7.0`
- Total rules: 94 input + 20 output = **114** (was 82 + 15)
- `verifyPromptAsync`: sync `block` always wins; adapter may only escalate allow/flag → block
- Output analysis includes `action`; `isSuspicious` is true for `flag` or `block`
- Default output threshold JSDoc corrected to 40

---

## [1.6.0] - 2026-07-28

### Added
- **Chat message array input**: `analyzePrompt` / `verifyPrompt` / `stripPrompt` / `verifyPromptAsync` accept `PromptInput` (`string | ChatMessage[]`)
  - Default scans untrusted roles only (`user`, `tool`, `function`); override with `analyzeRoles: 'all' | string[]`
  - Express + Next.js middleware accept message arrays in the configured body field
  - React hook `verify` / `strip` / `analyze` accept message arrays
  - New exports: `ChatMessage`, `PromptInput`, `AnalyzeRoles`, `flattenChatMessages`, `isChatMessageArray`, `resolvePromptInput`
- **Short-form instruction overrides**: catches paraphrases that omit the instruction noun:
  - `injection-forget-above`: "Forget above.", "Forget everything.", "Forget all that"
  - `injection-ignore-above-short`: "Ignore above", "Disregard above"
  - `injection-discard-prior`: "Discard previous instructions/context"
- **Privileged password fishing**: interrogative credential asks that previously scored as safe:
  - `fishing-ask-password`: "What's the admin password?", "What is the password to root…"
  - `fishing-password-to-access`: "password to root access"
- **Root/admin access requests**: `jailbreak-request-root-access` ("Give me root access")

### Changed
- Package version bump: `1.5.1` → `1.6.0`
- Total input rules: 76 → 82

---

## [1.5.1] - 2026-07-27

### Changed
- npm publish CI now uses **Trusted Publisher** (OIDC) instead of a long-lived `NPM_TOKEN`
- Provenance attestations are generated automatically on publish from GitHub Actions

---

## [1.5.0] - 2026-05-21

### Added
- **Severity levels**: every `AnalysisResult` now includes `severity: 'critical' | 'high' | 'medium' | 'low' | 'safe'` derived from the 0–100 score, independent of threshold
- **Output scanning**: new `analyzeOutput(output, options?)` function scans LLM responses for compromise signals:
  - `system-prompt-leak`: model disclosing its system instructions
  - `credential-leak`: API keys (OpenAI, GitHub, generic), passwords, env secrets
  - `injection-relay`: output containing injection patterns targeting downstream systems
  - `pii-exposure`: SSN and credit card number formats
  - Returns `OutputAnalysisResult` with `score`, `severity`, `isSuspicious`, `threats`, `matches`
  - Default threshold 40 (higher than input's 35 to reduce false positives on legitimate responses)
  - Skips homoglyph digit→letter substitution so real credential patterns match correctly
- **OpenAI adapter**: `OpenAIAdapter` for AI-assisted verification via the OpenAI SDK
  - Defaults to `gpt-4o-mini`; model and maxTokens are configurable
  - Exported from main index and `prompt-protection/adapters/openai`
  - `openai` added as optional peer dependency
- **15 new output pattern rules** (`out-*` prefix) in `OUTPUT_RULES`
- `OUTPUT_RULES` and `outputRules` exported from main index
- `SeverityLevel`, `OutputAnalysisResult`, `OutputAnalysisOptions` types exported

### Changed
- Package version bump: `1.0.0` → `1.5.0`
- Total rule count: 76 input rules + 15 output rules = 91 rules
- `ThreatCategory` union extended with 4 output categories: `system-prompt-leak`, `credential-leak`, `injection-relay`, `pii-exposure`

---

## [1.0.0] - 2026-04-28

### Added
- Renamed package from internal name to `prompt-protection`
- `context-smuggling` threat category and 10 detection rules
- Stable public API

---

## [0.1.0] - 2026-04-22

### Added
- Initial release
- `verifyPrompt`: throws `PromptInjectionError` on malicious input
- `stripPrompt`: removes malicious spans, returns clean prompt
- `analyzePrompt`: returns full scored analysis without throwing
- `verifyPromptAsync` + `AIAdapter` interface for AI-assisted verification
- 66 detection rules across 6 threat categories (prompt-injection, jailbreak, data-exfiltration, security-bypass, social-engineering, data-fishing)
- Obfuscation-resistant normalizer (Unicode NFKC, homoglyphs, base64, URL encoding)
- Weighted exponential scoring engine
- Express middleware (`promptProtectionMiddleware`)
- Next.js App Router wrapper (`withPromptProtection`)
- React hook (`usePromptProtection`)
- Built-in Claude adapter (`ClaudeAdapter`) using Anthropic SDK
- Custom rules and per-category disable options
- Configurable threshold (default: 35: strict mode)
