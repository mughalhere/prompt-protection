# Security Policy

## Scope

This package is a **policy layer** inside your process, a provenance-tracked tool-call guard plus detection heuristics. It is not an isolation boundary. The guard cannot see flows through the model's hidden state, paraphrased content that shares no identifiers with its source, or sources you never registered; the rules can be bypassed by novel phrasing. Do not use it as your sole defence. The full model is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

Actions are three-way (`allow` / `flag` / `block`; the guard adds `requiresConfirmation`) so medium-confidence hits can be reviewed without being treated as definitive blocks. Flagged traffic should still be monitored via the optional logger or the audit log.

## Failure semantics

The library **fails closed**. Any internal throw: a rule, a policy, a sink resolver, a classifier adapter, yields `block` with a synthetic `internal-error` match and `result.error` set, and the logged event carries the error. `failMode: 'open'` opts a call into pass-through with the error still reported. A throwing logger never changes a verdict. Details and a comparison table are in the README under "Failure semantics".

## Regular-expression safety

Every regex the library runs on untrusted text (148 at 3.1.0) is fuzzed with [`recheck`](https://makenowjust-labs.github.io/recheck/) in CI (`npm run test:redos`). A `vulnerable` verdict fails the build; an `unknown` verdict passes only through `tests/regex-safety/allowlist.json`, which requires a written justification per entry. 3.1.0 rewrote 29 patterns that the fuzzer found polynomial; the allowlist is empty.

## No telemetry

The library makes no network calls, reads no environment variables, and touches no filesystem. It runs unchanged in a `vm` context with no `process`, `Buffer`, `require` or `fetch` (`npm run compat`). Nothing about your prompts, tool results or decisions leaves your process unless you wire a logger to a sink of your own.

## Supply chain

`prompt-protection` ships **zero runtime dependencies**. Installing it pulls in no
transitive packages.

- `package.json` declares no `dependencies` and no `optionalDependencies`.
- Every peer dependency (`@anthropic-ai/sdk`, `openai`, `express`, `react`,
  `@modelcontextprotocol/sdk`, `ai`, `yaml`, `@opentelemetry/api`) is marked
  `optional: true` in `peerDependenciesMeta`, so npm does not install them on
  your behalf. Each is needed only by the matching adapter, middleware, hook,
  MCP server, ATR YAML loader or OpenTelemetry bridge, and each of those loads
  it via a lazy dynamic `import()` at call time.
- Every release publishes a CycloneDX SBOM (`sbom.cdx.json`) as a GitHub
  release asset alongside the npm provenance attestation.
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
finding: please report it using the process below.

## Reporting a Vulnerability

If you discover a bypass technique (a prompt that should be blocked but isn't) or a false-positive regression, please report it privately:

- Open a GitHub security advisory at https://github.com/mughalhere/prompt-protection/security/advisories/new

Please include:
- The exact prompt
- The `analyzePrompt()` output (score, action, categories, matches)
- The attack category you believe it represents

We will respond within 72 hours and aim to publish a fix within 7 days for critical bypasses.

## Supported Versions

| Version | Security fixes |
|---|---|
| 3.1.x | all |
| 3.0.x | critical guard bypasses for 90 days after 3.1.0 |
| ≤ 2.x | none, upgrade |

Rule-pack changes are pinned: `RULES_VERSION` (exported from the root) changes whenever any rule id, pattern, weight or precision changes, and `tests/patterns/rules-version.test.ts` fails if a rule changes without it.
