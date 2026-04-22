# Changelog

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
