# ATR interop: what maps, what is skipped, what differs

`prompt-protection/atr` makes the engine consume and emit [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) (ATR-SPEC v1). This page is the honest boundary of that claim.

## Loading

```ts
const { rules, report } = loadAtrRules(ruleObjects, {
  agentSource: 'llm_input',   // spec §5.1 event type → compatible rule source types
  scanTarget: 'mcp',          // keep rules with scan_target mcp or unset
  lane: 'enforce',            // stable maturity only; default 'hunt' keeps every non-draft rule
  fields: ['content', 'user_input'],
});
analyzePrompt(text, { customRules: rules });
```

Use `parseAtrYaml` from `prompt-protection/atr/yaml` (optional `yaml` peer) to turn a pack into objects. Core never parses YAML: a subset parser would silently corrupt regex sources (folded scalars, `\uXXXX` escapes, multi-document files).

## Operator mapping

| ATR operator | Compiled as |
|---|---|
| `regex` | JavaScript regex, flags `gi` (the scorer's contract). Leading inline `(?i)` / `(?is)` / `(?im)` are stripped; `s` rewrites `.` to `[\s\S]`. |
| `contains` | escaped literal |
| `exact` | `^literal$`, anchored to the **whole normalised input**, not a line |
| `starts_with` | `^literal` |

Rejected as `unsupported-syntax`: PCRE named groups `(?P<…>)`, `\h` `\R` `\K`, atomic groups, possessive quantifiers, `\p{…}` (needs the `u` flag), inline `x` mode. Rejected as `invalid-regex`: anything `new RegExp` refuses.

## Skipped, not approximated

| Reason | Meaning |
|---|---|
| `draft-or-deprecated` | spec: engines skip these (`includeDraft` overrides draft) |
| `lane-excluded` | `lane: 'enforce'` and maturity is not `stable` |
| `scan-target-mismatch` / `agent-source-mismatch` | spec §5.2 / §5.1 filters |
| `and-conditions-unsupported` | `condition: all` with more than one condition, a single `PatternRule` is one regex; we do not fake AND |
| `named-conditions-unsupported` | named / behavioural / sequence formats (`patterns`, `metric`, `steps`) |
| `field-not-applicable` | condition targets a field the call site does not carry (`tool_name` on a prompt scan) |

Every skip is in `report.skipped` with the rule id and detail. Nothing is silently dropped.

## Scoring

One `PatternRule` per compiled condition, all sharing `id: 'atr:<rule id>'`, so the scorer's diminishing-returns logic (`src/scorer.ts`) treats the ATR rule as one rule. Weight from severity (critical 10, high 8, medium 6, low 4, informational 2); precision from `tags.confidence`. `toAtrFindings` reports `confidence = matched conditions / total conditions`, sorted by severity then confidence (spec §3.5.3 step 7–8).

## Semantic differences from the reference engine

- **We scan normalised text.** `normalize()` strips zero-width and bidi characters, folds homoglyphs, decodes base64/percent and lowercases before rules run. ATR rules that target zero-width characters or rely on case cannot fire here, the obfuscation they detect has already been removed, and the same input is caught upstream by the normaliser's own rules. `bench/run.mjs --atr` replays each rule's embedded `test_cases` to quantify this.
- **`^` / `$` mean whole-input**, not line boundaries.
- **Conformance wording.** The ATR conformance corpus is proposed, not ratified. We verify the spec's mandatory engine behaviours with our own suite (`tests/atr/conformance.test.ts`); we do not claim "ATR-certified".

## Emitting

`toAtrFindings(result)` returns the spec §5.5 `ScanResult` (`rule_id`, `severity`, `confidence`, `matched_conditions`, `matched_patterns`, `references`, `engine.rules_version`). Native rules appear as `pp:<id>` with severity derived from weight and framework ids from `mappings`.
