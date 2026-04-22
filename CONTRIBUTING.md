# Contributing to prompt-protection

Thanks for helping make LLM applications safer. This document covers how to add detection rules, fix bugs, and submit pull requests.

## Setup

```bash
git clone https://github.com/mughalhere/prompt-protection.git
cd prompt-protection
npm install
npm test        # all tests should pass
npm run build   # verify dual ESM+CJS output
```

## Project Structure

```
src/
  api.ts                    # verifyPrompt / stripPrompt / analyzePrompt
  normalizer.ts             # obfuscation-resistant pre-processing
  scorer.ts                 # weighted exponential scoring
  patterns/
    injection.ts            # "ignore previous instructions" family
    jailbreak.ts            # DAN, dev mode, no-restrictions
    exfiltration.ts         # reveal system prompt, dump context
    bypass.ts               # disable safety filter, filter evasion
    social-engineering.ts   # persona hijack, fake authority
    data-fishing.ts         # passwords, DB dump, /etc/passwd
tests/
  patterns/                 # one test file per category
  __fixtures__/
    benign.txt              # prompts that must NEVER be blocked
    malicious.txt           # prompts that must ALWAYS be blocked
```

## Adding a Detection Rule

### 1. Write the rule

Open the appropriate file in `src/patterns/`. Add a new `PatternRule` object:

```typescript
{
  id: 'category-short-description',     // kebab-case, unique
  category: 'jailbreak',                // one of the 6 ThreatCategories
  pattern: /your regex here/,           // compiled with 'i' flag by the engine
  weight: 8,                            // 1–10; see weight guide below
  description: 'One-sentence description of what this detects',
},
```

**Weight guide:**

| Weight | Meaning |
|--------|---------|
| 9–10 | Unambiguous attack (DAN, `/etc/passwd`, `DROP TABLE`) |
| 7–8 | Strong signal, unlikely benign |
| 5–6 | Moderate signal, possible false positives |
| 1–4 | Weak signal, use with caution |

A single rule at weight ≥ 8 crosses the default threshold (35) and will block the prompt. At weight 6 a single rule scores ~33 — below the threshold. Two weight-6 rules score ~48 — above. Design weights accordingly.

### 2. Test the regex against the normalizer

The pattern engine runs against the **normalized** text, not the raw input. Verify your regex still matches after normalization:

```typescript
import { normalize } from './src/normalizer';
console.log(normalize('Your test input').normalized);
```

### 3. Write tests

Add your rule to the existing test file in `tests/patterns/`:

```typescript
describe('category-short-description', () => {
  // At least 3 inputs that should trigger
  it.each([
    'Exact attack phrasing',
    'Variant phrasing',
    'Another variant',
  ])('triggers on: %s', (prompt) => {
    expect(trigger(prompt)).toBe(true);
  });

  // At least 2 benign inputs that should NOT trigger
  it('does not trigger on benign input', () => {
    expect(trigger('Benign phrase containing similar words')).toBe(false);
  });
});
```

### 4. Update the fixtures

- Add attack variants to `tests/__fixtures__/malicious.txt` (one per line)
- If your rule might touch benign phrasing, verify nothing in `benign.txt` is newly blocked

### 5. Run the full suite

```bash
npm test
npm run typecheck
npm run lint
```

All 3 must pass before opening a PR.

## Writing Good Regexes

- Patterns are matched case-insensitively (the engine lowercases normalized text)
- Use `\s+` instead of ` ` to handle collapsed whitespace
- Use `\b` word boundaries to avoid partial matches
- Keep `.{0,N}` spans small (≤ 40 chars) to avoid catastrophic backtracking
- Avoid lookaheads/lookbehinds unless necessary — they are supported but add complexity
- Test your regex against both the attack and common benign phrases before submitting

## Reporting False Positives

If a legitimate prompt is being blocked, open a [pattern request issue](https://github.com/mughalhere/prompt-protection/issues/new?template=pattern_request.yml) with the full prompt and the output of `analyzePrompt()`.

## Pull Request Guidelines

1. One logical change per PR (new rule, bug fix, refactor — not mixed)
2. PR title: `feat(patterns): add rule for X`, `fix: handle Y edge case`, etc.
3. Include the `analyzePrompt()` output for any new or changed prompts in the PR description
4. Do not lower the coverage thresholds in `jest.config.cjs`

## Code Style

- TypeScript strict mode — no `any` without justification
- No comments explaining *what* the code does — only *why* when non-obvious
- Run `npm run lint:fix` before committing

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
