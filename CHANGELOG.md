# Changelog

## [2.0.0] - 2026-09-03

The agentic-security major. Adds MCP tool-poisoning defence, an MCP server, a
Vercel AI SDK adapter, and a published, measured detection benchmark. The base
`npm install prompt-protection` stays **zero runtime dependencies** — the two new
SDK-backed surfaces are separate subpaths with *optional* peer dependencies.

### Added
- **Tool-poisoning detection.** New `tool-poisoning` threat category (9 rules) and
  `scanToolDefinition(tool)` — scans a tool/function definition (name, description,
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
  or scores by a hair on unusual inputs — part of why this is a major bump.

### Migration
- Fully backward compatible for the documented API. `ThreatCategory` gained the
  `tool-poisoning` value — widen any exhaustive switch over it. Adaptive/pathological
  inputs may score marginally differently after the normalizer/scorer changes.

---

## [1.8.3] - 2026-08-20

### Fixed
- **`prompt-protection/adapters/openai` subpath was unresolvable.** `package.json`
  declared the export map entry, but `src/adapters/openai.ts` was missing from the
  `tsup` entry list, so `dist/adapters/openai.*` was never built. Importing
  `OpenAIAdapter` from the documented subpath failed at runtime; only the root
  barrel (`from 'prompt-protection'`) worked. Added the entry — the subpath now
  emits ESM, CJS, and both declaration formats.
- `README.md` "How Detection Works" said 94 input regexes; the correct count is 97.

### Changed
- npm `description` rewritten to lead with the terms the package is searched by,
  and `keywords` expanded 10 → 20 (`ai-security`, `llm-firewall`, `guardrails`,
  `owasp-llm`, `prompt-security`, `injection-detection`, `chatbot-security`,
  `llm-safety`, `ai-red-team`, `gpt`). Discoverability only — no runtime effect.
- `README.md`: monthly-downloads badge, reworked opening, new FAQ section, and
  links to the new guides on the documentation site.

### Added
- Documentation site under `demo/public/docs/` — six static, self-contained pages
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

Supply-chain and tooling maintenance only. **No runtime behaviour changes** — no
rules added or altered, no API changes, all 418 tests pass unchanged.

### Added
- `socket.yml` — Socket.dev configuration. Scopes analysis to the files that make
  up the published package and excludes the standalone `demo/` app, which carries
  its own dependency graph and ships nothing. Deliberately leaves the `usesEval`,
  `networkAccess`, `shellAccess`, and `gptSecurity` rules enabled rather than
  suppressing those alert classes.
- `SECURITY.md` — new "Supply chain" section documenting that the package ships
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
- **Deferred-reference injection rules** — catches follow-ups that re-invoke a prior turn without repeating the attack:
  - `injection-process-last-prompt` — "process/run/execute the last/previous prompt/message/request"
  - `injection-do-what-said-before` — "do what I said before" / "do what I asked in the previous message"
  - `injection-retry-previous-request` — "retry/re-do my previous request"
- **`createProtectionSession()`** — opt-in multi-turn correlation
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
- **Three-way actions** — `action: 'allow' | 'flag' | 'block'` on every analysis result
  - `isMalicious` remains true only when `action === 'block'` (backward compatible)
  - Optional `flagThreshold` for a review band that logs/flags without throwing
  - `verifyPrompt` / middleware throw only on `block`
- **Precision gating** — rules tagged `precision: 'high' | 'medium' | 'low'`
  - Lone `low`-precision matches (e.g. soft context-smuggling) can `flag` but cannot alone `block`
- **Pluggable logging** — `logger`, `logLevels`, `includeContent`, `onLoggerError`
  - Emits `ProtectionEvent` for input/output blocked/flagged (and optionally allow/clean)
  - `createConsoleLogger()` helper for local debugging
- **Allowlists** — `allowlistPatterns` / `allowlistRuleIds` exclude known-good spans from scoring
- **Normalizer hardening** — multi-pass URL/base64 decode, Unicode Tags strip, bidi controls, fullwidth fold
- **Accurate strip positions** — scorer uses `indexMap` from the normalizer
- **New detection rules** — ChatML/Llama special tokens, policy puppetry, fake tool calls, many-shot jailbreaks, translate-then-obey, output email/phone PII and markdown/HTML exfil
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
- **Chat message array input** — `analyzePrompt` / `verifyPrompt` / `stripPrompt` / `verifyPromptAsync` accept `PromptInput` (`string | ChatMessage[]`)
  - Default scans untrusted roles only (`user`, `tool`, `function`); override with `analyzeRoles: 'all' | string[]`
  - Express + Next.js middleware accept message arrays in the configured body field
  - React hook `verify` / `strip` / `analyze` accept message arrays
  - New exports: `ChatMessage`, `PromptInput`, `AnalyzeRoles`, `flattenChatMessages`, `isChatMessageArray`, `resolvePromptInput`
- **Short-form instruction overrides** — catches paraphrases that omit the instruction noun:
  - `injection-forget-above` — "Forget above.", "Forget everything.", "Forget all that"
  - `injection-ignore-above-short` — "Ignore above", "Disregard above"
  - `injection-discard-prior` — "Discard previous instructions/context"
- **Privileged password fishing** — interrogative credential asks that previously scored as safe:
  - `fishing-ask-password` — "What's the admin password?", "What is the password to root…"
  - `fishing-password-to-access` — "password to root access"
- **Root/admin access requests** — `jailbreak-request-root-access` ("Give me root access")

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
- **Severity levels** — every `AnalysisResult` now includes `severity: 'critical' | 'high' | 'medium' | 'low' | 'safe'` derived from the 0–100 score, independent of threshold
- **Output scanning** — new `analyzeOutput(output, options?)` function scans LLM responses for compromise signals:
  - `system-prompt-leak` — model disclosing its system instructions
  - `credential-leak` — API keys (OpenAI, GitHub, generic), passwords, env secrets
  - `injection-relay` — output containing injection patterns targeting downstream systems
  - `pii-exposure` — SSN and credit card number formats
  - Returns `OutputAnalysisResult` with `score`, `severity`, `isSuspicious`, `threats`, `matches`
  - Default threshold 40 (higher than input's 35 to reduce false positives on legitimate responses)
  - Skips homoglyph digit→letter substitution so real credential patterns match correctly
- **OpenAI adapter** — `OpenAIAdapter` for AI-assisted verification via the OpenAI SDK
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
- `verifyPrompt` — throws `PromptInjectionError` on malicious input
- `stripPrompt` — removes malicious spans, returns clean prompt
- `analyzePrompt` — returns full scored analysis without throwing
- `verifyPromptAsync` + `AIAdapter` interface for AI-assisted verification
- 66 detection rules across 6 threat categories (prompt-injection, jailbreak, data-exfiltration, security-bypass, social-engineering, data-fishing)
- Obfuscation-resistant normalizer (Unicode NFKC, homoglyphs, base64, URL encoding)
- Weighted exponential scoring engine
- Express middleware (`promptProtectionMiddleware`)
- Next.js App Router wrapper (`withPromptProtection`)
- React hook (`usePromptProtection`)
- Built-in Claude adapter (`ClaudeAdapter`) using Anthropic SDK
- Custom rules and per-category disable options
- Configurable threshold (default: 35 — strict mode)
