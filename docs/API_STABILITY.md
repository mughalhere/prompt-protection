# API stability

Three tiers. The tier decides what a version bump means for you.

| Tier | Contract | Where |
|---|---|---|
| **Stable** | Full semver. Removing or narrowing anything here is a major, announced one minor ahead with a deprecation note. | root entry, `/guard`, `/adapters/vercel`, `/mcp`, `/middleware/*`, `/react`, `/adapters/claude`, `/adapters/openai` |
| **Preview** | May change in a **minor**. Every change is listed under "Preview changes" in the CHANGELOG. Entry files carry a `@beta` header. | `/ml`, `/atr`, `/atr/yaml`, `/audit`, `/otel`, `/canary`, `/spotlight`, `/adapters/vercel-guardrail`, `/lite` |
| **Internal** | No contract. Any release may change or remove it. | `/internal` |

`tests/api-surface.test.ts` asserts the root runtime export list; a change there is a change here.

## Stable root exports

| Export | Kind |
|---|---|
| `analyzePrompt`, `verifyPrompt`, `stripPrompt`, `verifyPromptAsync` | input scoring |
| `analyzeOutput` | output scoring |
| `scanToolDefinition` | tool-definition scoring |
| `createProtectionSession` | multi-turn correlation |
| `createConsoleLogger` | logging |
| `PromptInjectionError` | thrown by `verify*` on `block` |
| `ClaudeAdapter`, `OpenAIAdapter` | optional second-opinion adapters (also on their subpaths) |
| `RULES_VERSION` | rule-pack pin |
| every `type` export | result, option and event shapes |

## Open unions

`ThreatCategory`, `ProtectionEvent['type']`, `ProtectionEvent['direction']`, guard `SinkKind` and
`FlowKind` are declared as `'known' | ... | (string & {})`. New members arrive in minors. Handle an
unknown value as `flag`; do not `switch` exhaustively over them. Closed unions (`Action`,
`SeverityLevel`, `RulePrecision`, `FailMode`, guard `PolicyAction`) stay closed and are stable.

## What versions independently of the package

- **Rules**: `RULES_VERSION`. Adding, removing or reweighting rules is at most a minor; the benchmark
  gates in `bench/run.mjs` are the compatibility contract for rules.
- **Classifier**: `ModelMeta.version` (`/ml`, preview). A retrain never bumps the package major.

## Cadence

- patch: fixes and rule updates, at most weekly
- minor: additive stable API, preview changes, monthly
- major: at least six months apart, only for an incompatible change to the stable tier, always with
  `docs/migrations/v<N>.md`

Pre-releases publish under the `next` dist-tag; `latest` never moves to one.
