import type { PatternRule, RuleMappings } from '../types.js';

// Ids only. OWASP LLM Top 10 (2025 edition) and MITRE ATLAS technique ids.
// OWASP Agentic Top 10 (ASI) ids are added once verified against the published list.
const INJECTION: RuleMappings = { owaspLlm: ['LLM01:2025'], atlas: ['AML.T0051', 'AML.T0051.000'] };
const INJECTION_INDIRECT: RuleMappings = { owaspLlm: ['LLM01:2025'], atlas: ['AML.T0051', 'AML.T0051.001'] };
const JAILBREAK: RuleMappings = { owaspLlm: ['LLM01:2025'], atlas: ['AML.T0054'] };
const PROMPT_LEAK: RuleMappings = { owaspLlm: ['LLM07:2025', 'LLM02:2025'], atlas: ['AML.T0056'] };
const DATA_LEAK: RuleMappings = { owaspLlm: ['LLM02:2025'], atlas: ['AML.T0057'] };
const TOOL_POISONING: RuleMappings = { owaspLlm: ['LLM01:2025', 'LLM03:2025'], atlas: ['AML.T0051.001'] };

const families: Array<[string[], RuleMappings]> = [
  [
    [
      'injection-ignore-previous', 'injection-disregard-above', 'injection-forget-context', 'injection-forget-above',
      'injection-ignore-above-short', 'injection-discard-prior', 'injection-new-instructions', 'injection-system-override',
      'injection-override-directive', 'injection-real-task', 'injection-context-switch', 'injection-human-turn',
      'injection-policy-puppetry', 'injection-translate-then-obey', 'injection-code-wrap', 'injection-process-last-prompt',
      'injection-do-what-said-before', 'injection-retry-previous-request',
    ],
    INJECTION,
  ],
  [
    [
      'injection-special-tokens', 'injection-xml-system', 'injection-end-prompt-marker', 'injection-chatml-im-tokens',
      'injection-llama-header', 'injection-gemini-role', 'injection-fake-tool-call',
    ],
    INJECTION_INDIRECT,
  ],
  [
    [
      'jailbreak-dan', 'jailbreak-developer-mode', 'jailbreak-no-restrictions', 'jailbreak-jailbreak', 'jailbreak-unfiltered',
      'jailbreak-opposite-mode', 'jailbreak-escape-training', 'jailbreak-evil-persona', 'jailbreak-sudo', 'jailbreak-admin-override',
      'jailbreak-request-root-access', 'jailbreak-free-mode', 'jailbreak-character-no-limits', 'jailbreak-token-limit',
      'jailbreak-fictional-instructions', 'jailbreak-many-shot', 'jailbreak-grandma-exploit', 'jailbreak-aim-pliny', 'jailbreak-unrestricted-agent',
    ],
    JAILBREAK,
  ],
  [
    ['exfil-reveal-system-prompt', 'exfil-summarize-instructions', 'exfil-what-told', 'exfil-base64-encode-prompt', 'exfil-print-full-context', 'exfil-dump-context-window'],
    PROMPT_LEAK,
  ],
  [['exfil-decrypt-return', 'exfil-send-config', 'exfil-api-key', 'exfil-training-data'], DATA_LEAK],
  [
    [
      'tool-hidden-instruction-tag', 'tool-before-using-directive', 'tool-conceal-from-user', 'tool-exfiltrate-result',
      'tool-override-other-tools', 'tool-read-secrets', 'tool-side-effect-injection', 'tool-role-injection', 'tool-ignore-previous',
    ],
    TOOL_POISONING,
  ],
];

export const RULE_MAPPINGS: Readonly<Record<string, RuleMappings>> = Object.freeze(
  Object.fromEntries(families.flatMap(([ids, m]) => ids.map((id) => [id, m]))),
);

/** Copies of `rules` with `mappings` attached where the table knows the id. */
export function withMappings<T extends PatternRule>(rules: readonly T[]): T[] {
  return rules.map((r) => (RULE_MAPPINGS[r.id] !== undefined && r.mappings === undefined ? { ...r, mappings: RULE_MAPPINGS[r.id] } : r));
}
