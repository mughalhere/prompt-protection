## Summary

<!-- What does this PR do? -->

## Type

- [ ] New detection rule(s)
- [ ] Bug fix (false positive or false negative)
- [ ] Refactor / performance
- [ ] Docs / tooling

## Testing

<!-- For new rules, paste the analyzePrompt() output for the target attack prompts and at least 2 benign prompts you verified still pass. -->

```
analyzePrompt('...') → { score: X, categories: [...], matches: [...] }
```

## Checklist

- [ ] `npm test` passes
- [ ] `npm run typecheck` passes
- [ ] `npm run lint` passes
- [ ] New patterns have ≥ 3 positive + ≥ 2 negative test cases
- [ ] Malicious fixtures updated if applicable
