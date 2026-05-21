import type { PatternRule } from '../types.js';

export const outputRules: PatternRule[] = [
  // system-prompt-leak
  {
    id: 'out-system-prompt-explicit',
    category: 'system-prompt-leak',
    pattern: /(my system prompt (is|says|states|reads|tells me|contains|begins with)|here('s| is) my system prompt|the system prompt (is|says|reads|states))/,
    weight: 10,
    description: 'Model explicitly discloses system prompt',
  },
  {
    id: 'out-instructions-disclosure',
    category: 'system-prompt-leak',
    pattern: /(my (original |base |initial |hidden )?instructions? (say|tell me|state|require|forbid|allow|are)\b|according to my instructions|i was (told|instructed|programmed|configured) (by my (creator|developer|operator)))/,
    weight: 8,
    description: 'Model discloses its operating instructions',
  },
  {
    id: 'out-system-prompt-markup',
    category: 'system-prompt-leak',
    pattern: /(\[system\][\s\S]{0,400}\[\/system\]|<system>[\s\S]{0,400}<\/system>|```\s*system\s*\n)/,
    weight: 9,
    description: 'Output contains system prompt markup tags',
  },
  {
    id: 'out-you-are-preamble',
    category: 'system-prompt-leak',
    pattern: /^(you are (a |an )[\w\s]{3,60}(assistant|bot|ai|helper|agent)\b)/im,
    weight: 7,
    description: 'Output echoes system prompt role definition',
  },

  // credential-leak
  {
    id: 'out-openai-api-key',
    category: 'credential-leak',
    pattern: /\bsk-[A-Za-z0-9]{20,}/,
    weight: 10,
    description: 'OpenAI API key format in output',
  },
  {
    id: 'out-github-token',
    category: 'credential-leak',
    pattern: /\b(ghp_|gho_|ghu_|ghs_)[A-Za-z0-9]{36}/,
    weight: 10,
    description: 'GitHub token format in output',
  },
  {
    id: 'out-generic-token',
    category: 'credential-leak',
    pattern: /(api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_\-.]{16,}/i,
    weight: 9,
    description: 'Generic API key or token value in output',
  },
  {
    id: 'out-password-value',
    category: 'credential-leak',
    pattern: /\b(password|passwd|pwd)\s*(is\s*)?[:=]\s*['"]?\S{6,}/i,
    weight: 9,
    description: 'Password value exposed in output',
  },
  {
    id: 'out-env-secret',
    category: 'credential-leak',
    pattern: /\b[A-Z][A-Z0-9_]{3,}_(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\s*=\s*\S+/,
    weight: 8,
    description: 'Environment variable with sensitive value in output',
  },

  // injection-relay
  {
    id: 'out-relay-ignore-previous',
    category: 'injection-relay',
    pattern: /ignore (all )?(previous|prior) (instructions?|prompts?|context|messages?)/i,
    weight: 9,
    description: 'Output contains injection relay instruction',
  },
  {
    id: 'out-relay-new-instructions',
    category: 'injection-relay',
    pattern: /new (instructions?|directives?|system prompt|context|objective)\s*:/i,
    weight: 8,
    description: 'Output defines new downstream instructions',
  },
  {
    id: 'out-relay-override',
    category: 'injection-relay',
    pattern: /(override|replace|supersede|discard|forget) (the |your )?(previous |prior |current |all )?(instructions?|system prompt|context|guidelines)/i,
    weight: 8,
    description: 'Output instructs downstream system to override instructions',
  },
  {
    id: 'out-relay-act-as',
    category: 'injection-relay',
    pattern: /\b(act as|pretend (you are|to be)|you are now|from now on (you are|be))\b/i,
    weight: 7,
    description: 'Output contains role-override relay instruction',
  },

  // pii-exposure
  {
    id: 'out-ssn',
    category: 'pii-exposure',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/,
    weight: 8,
    description: 'SSN format number in output',
  },
  {
    id: 'out-credit-card',
    category: 'pii-exposure',
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/,
    weight: 9,
    description: 'Credit card number format in output',
  },
];
