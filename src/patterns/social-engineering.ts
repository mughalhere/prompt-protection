import type { PatternRule } from '../types.js';

export const socialEngineeringRules: PatternRule[] = [
  {
    id: 'social-you-are-now',
    category: 'social-engineering',
    pattern: /you\s+are\s+now\s+(a\s+|an\s+|the\s+)?\w+(\s+\w+)?\s+(without|with\s+no|who\s+(ignores?|doesn'?t|has\s+no))/,
    weight: 8,
    description: 'You are now [persona without restrictions]',
  },
  {
    id: 'social-your-true-self',
    category: 'social-engineering',
    pattern: /your\s+(true|real|actual|hidden|inner|authentic)\s+(self|identity|purpose|goal|nature|personality|instructions?)/,
    weight: 7,
    description: 'Invoke true/real self',
  },
  {
    id: 'social-from-now-on',
    category: 'social-engineering',
    pattern: /(from\s+now\s+on|henceforth|going\s+forward)\s+(you\s+(are|will\s+be|must|shall|should)|always)/,
    weight: 8,
    description: 'Persistent persona/behavior change',
  },
  {
    id: 'social-your-creator',
    category: 'social-engineering',
    pattern: /(i\s+am\s+)?(your\s+)?(creator|developer|owner|maker|god|master|trainer|builder|designer)\b/,
    weight: 7,
    description: 'Claiming to be creator/owner',
  },
  {
    id: 'social-trust-me-authorized',
    category: 'social-engineering',
    pattern: /trust\s+me\s*[,.]?\s*(i\s+am|i'?m)\s+(an?\s+)?(developer|engineer|researcher|employee)\s*(of\s+|from\s+|at\s+)?(anthropic|openai|google|meta|microsoft)/,
    weight: 8,
    description: 'Trust me, I work at [AI company]',
  },
  {
    id: 'social-authorized-by',
    category: 'social-engineering',
    pattern: /i\s+(am|have\s+been)\s+(authorized|approved|allowed|cleared|certified)\s+(by\s+)?(anthropic|openai|google|the\s+(team|company|developers?))/,
    weight: 8,
    description: 'Claims of authorization from AI company',
  },
  {
    id: 'social-maintenance-mode',
    category: 'social-engineering',
    pattern: /(enter|enable|activate|switch\s+to)\s+maintenance\s+mode/,
    weight: 7,
    description: 'Maintenance mode activation',
  },
  {
    id: 'social-training-scenario',
    category: 'social-engineering',
    pattern: /(this\s+is\s+a\s+)?(training|test|simulation|evaluation|assessment)\s+(exercise|scenario|mode|run)\s*.{0,50}(respond\s+without|ignore|bypass)/,
    weight: 7,
    description: 'Fake training/test scenario',
  },
  {
    id: 'social-special-auth-token',
    category: 'social-engineering',
    pattern: /<\s*(magic|special|auth(orization)?|admin|master|override)\s*token\s*>|<<\s*auth\s*>>/,
    weight: 8,
    description: 'Fake authorization/magic token',
  },
  {
    id: 'social-you-must-always',
    category: 'social-engineering',
    pattern: /you\s+(must|have\s+to|are\s+required\s+to|need\s+to)\s+(always\s+)?(immediately\s+)?(comply|obey|follow|do|respond|agree)\s+(with\s+)?(any|all|every)/,
    weight: 8,
    description: 'Coercive compliance demand',
  },
];
