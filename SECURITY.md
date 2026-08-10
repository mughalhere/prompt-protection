# Security Policy

## Scope

This package is a **detection layer** — it is not a guaranteed security boundary. It uses pattern matching and heuristics that can be bypassed by sufficiently novel attacks. Do not use it as your sole defence against adversarial inputs.

Version 1.7+ returns three-way actions (`allow` / `flag` / `block`) so medium-confidence hits can be reviewed without being treated as definitive blocks. Flagged traffic should still be monitored via the optional logger.

## Supply chain

`prompt-protection` ships **zero runtime dependencies**. Installing it pulls in no
transitive packages.

- `package.json` declares no `dependencies` and no `optionalDependencies`.
- The four peer dependencies (`@anthropic-ai/sdk`, `openai`, `express`, `react`)
  are all marked `optional: true` in `peerDependenciesMeta`, so npm does not
  install them on your behalf. They are only needed if you use the matching
  adapter, middleware, or React hook — each of which loads them via a lazy
  dynamic `import()` at call time.
- The published tarball contains `dist/`, `README.md`, `LICENSE`, and
  `CHANGELOG.md` only. It contains no `eval`, no `Function` constructor, no
  `fetch`/`XMLHttpRequest`, no `child_process`, and no filesystem access.

Verify any of this yourself:

```bash
npm audit --omit=dev                 # => found 0 vulnerabilities
npm pack --dry-run                   # => dist/ + docs only
grep -rE "eval\(|new Function\(|child_process|fetch\(" dist/   # => no matches
```

### Reading third-party scanner reports

Automated supply-chain scanners (Socket.dev, Snyk, and similar) analyse the
**full development graph**, and some of them resolve open-ended `peerDependencies`
ranges to the newest published version. Alerts raised that way are attributed to
this project's report page but originate in packages we do not ship. Known
examples, all verified non-exploitable through this package:

| Alert | Actually in | Why it is not reachable |
| --- | --- | --- |
| Shell access (`node:child_process`) | `@anthropic-ai/sdk` → `tools/agent-toolset/*` | An optional peer, and a documented SDK feature. `ClaudeAdapter` only calls `client.messages.create`; the agent toolset is never imported. |
| AI-detected potential security risk | `@anthropic-ai/sdk` → `src/tools/agent-toolset/node.ts` | Same file as above. |
| Network access (`globalThis.fetch`) | `@anthropic-ai/sdk` → `client.js` | An HTTP SDK performing HTTP. This package itself makes zero network calls. |
| Uses eval | `async-function` (dev graph) | A shim that calls `Function('return async function(){}')` to obtain the hidden `AsyncFunction` constructor. Dev-only, never bundled. |
| Optimized override available | `es-define-property` (via `express → qs → side-channel`) | Not a vulnerability; a registry-mirror suggestion. Dev-only. |

`socket.yml` in the repository root documents this and scopes analysis to the
files that make up the published package. We intentionally leave the
`usesEval` / `networkAccess` / `shellAccess` / `gptSecurity` rules **enabled**
rather than suppressing the alert classes outright, so that a genuinely
malicious future dependency still trips them.

If you find a scanner alert that points at code inside `dist/`, that is a real
finding — please report it using the process below.

## Reporting a Vulnerability

If you discover a bypass technique (a prompt that should be blocked but isn't) or a false-positive regression, please report it privately:

- Open a GitHub security advisory at https://github.com/mughalhere/prompt-protection/security/advisories/new

Please include:
- The exact prompt
- The `analyzePrompt()` output (score, action, categories, matches)
- The attack category you believe it represents

We will respond within 72 hours and aim to publish a fix within 7 days for critical bypasses.

## Supported Versions

Only the latest release receives security fixes.
