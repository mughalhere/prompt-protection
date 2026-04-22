import type { PatternRule } from '../types.js';

export const bypassRules: PatternRule[] = [
  {
    id: 'bypass-disable-safety',
    category: 'security-bypass',
    pattern: /(disable|turn\s+off|remove|bypass|deactivate|circumvent)\s+(the\s+)?(safety|content|ethical?)\s+(filter|check|guard(rail)?|system|mode|policy|protocol)/,
    weight: 9,
    description: 'Disable safety/content filter',
  },
  {
    id: 'bypass-no-rules',
    category: 'security-bypass',
    pattern: /act\s+as\s+if\s+(there\s+are\s+)?(no\s+)?(rules?|policies?|guidelines?|restrictions?|ethics?|laws?)\s*(apply|exist)?/,
    weight: 9,
    description: 'Act as if no rules apply',
  },
  {
    id: 'bypass-ignore-guardrails',
    category: 'security-bypass',
    pattern: /ignore\s+(your\s+)?(guardrails?|safeguards?|alignment|ethical?\s+(guidelines?|constraints?|training)|safety\s+training)/,
    weight: 9,
    description: 'Ignore guardrails/safety training',
  },
  {
    id: 'bypass-pretend-allowed',
    category: 'security-bypass',
    pattern: /pretend\s+(that\s+)?(it\s+is\s+|it'?s\s+)?(allowed|permitted|legal|fine|okay|ok|acceptable)\s+(to|for)/,
    weight: 8,
    description: 'Pretend prohibited action is allowed',
  },
  {
    id: 'bypass-hypothetically',
    category: 'security-bypass',
    pattern: /hypothetically\s*(speaking\s*)?[,.]?\s*(how\s+(would|do|could|can|to)|what\s+(are\s+the\s+)?(steps?|ways?|methods?))\s*(to\s+|one\s+could\s+)?/,
    weight: 8,
    description: 'Hypothetical framing for harmful instructions',
  },
  {
    id: 'bypass-for-educational',
    category: 'security-bypass',
    pattern: /for\s+(educational|research|academic|scientific|informational)\s+purposes?\s*.{0,80}(how\s+to\s+(make|build|create|synthesize|hack|crack|exploit|attack))/,
    weight: 7,
    description: 'Educational framing for harmful instructions',
  },
  {
    id: 'bypass-as-fiction',
    category: 'security-bypass',
    pattern: /as\s+a?\s*(fictional|hypothetical|theoretical)\s+(character|ai|scenario|story|example)\s*.{0,50}(ignore|bypass|without\s+(restriction|filter|limit))/,
    weight: 7,
    description: 'Fictional framing to bypass safety',
  },
  {
    id: 'bypass-filter-evasion',
    category: 'security-bypass',
    pattern: /(evade|avoid|get\s+around|circumvent|trick)\s+(the\s+)?(filter|detection|moderation|guardrail|safety|content\s+policy)/,
    weight: 8,
    description: 'Explicit filter evasion',
  },
  {
    id: 'bypass-token-manipulation',
    category: 'security-bypass',
    pattern: /use\s+(unicode|zero.?width|homoglyphs?|special\s+characters?|invisible\s+characters?)\s+to\s+(bypass|evade|hide|obfuscate)/,
    weight: 9,
    description: 'Unicode/homoglyph evasion technique',
  },
  {
    id: 'bypass-prompt-injection-explicit',
    category: 'security-bypass',
    pattern: /prompt\s+injection/,
    weight: 7,
    description: 'Explicit prompt injection mention',
  },
];
