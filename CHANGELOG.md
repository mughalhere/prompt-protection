# Changelog

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
