import type { PatternRule } from '../types.js';

export const exfiltrationRules: PatternRule[] = [
  {
    id: 'exfil-reveal-system-prompt',
    category: 'data-exfiltration',
    pattern: /(reveal|show|print|output|return|repeat|display|tell|give|share)\s+(me\s+)?(your\s+)?(system\s+prompt|initial\s+(instructions?|prompt)|base\s+prompt|original\s+(instructions?|prompt)|hidden\s+(instructions?|prompt))/,
    weight: 9,
    description: 'Reveal system prompt',
  },
  {
    id: 'exfil-decrypt-return',
    category: 'data-exfiltration',
    pattern: /decrypt\s+.{0,50}(and\s+)?(return|send|output|show|reveal|give)/,
    weight: 8,
    description: 'Decrypt and return data',
  },
  {
    id: 'exfil-send-config',
    category: 'data-exfiltration',
    pattern: /(send|return|output|show|give|reveal)\s+(me\s+)?(the\s+)?(config(uration)?|settings?|env(ironment)?\s*variables?|credentials?|secrets?\.json|\.env)/,
    weight: 8,
    description: 'Exfiltrate config/credentials',
  },
  {
    id: 'exfil-print-full-context',
    category: 'data-exfiltration',
    pattern: /(print|output|show|dump|reveal|return)\s+(the\s+)?(full\s+)?(context|conversation|chat\s+history|message\s+history|previous\s+messages)/,
    weight: 7,
    description: 'Print full context/conversation',
  },
  {
    id: 'exfil-summarize-instructions',
    category: 'data-exfiltration',
    pattern: /(summarize|repeat|paraphrase|recite|list|enumerate)\s+(your|the)\s+(instructions?|guidelines?|rules?|directives?|system\s+prompt)/,
    weight: 7,
    description: 'Summarize/repeat instructions',
  },
  {
    id: 'exfil-what-told',
    category: 'data-exfiltration',
    pattern: /what\s+(were|are)\s+you\s+(told|instructed|programmed|trained|asked)\s+(to\s+do|not\s+to|to\s+say|to\s+avoid)/,
    weight: 8,
    description: 'What were you told/instructed',
  },
  {
    id: 'exfil-base64-encode-prompt',
    category: 'data-exfiltration',
    pattern: /(encode|base64|hex(-encode)?)\s+.{0,30}(your\s+)?(prompt|instructions?|system\s+message)/,
    weight: 8,
    description: 'Encode your prompt/instructions',
  },
  {
    id: 'exfil-api-key',
    category: 'data-exfiltration',
    pattern: /(output|reveal|show|give|return|send)\s+(me\s+)?(the\s+)?(api\s+key|secret\s+key|access\s+token|auth\s+token|bearer\s+token|private\s+key)/,
    weight: 9,
    description: 'Exfiltrate API/secret keys',
  },
  {
    id: 'exfil-dump-context-window',
    category: 'data-exfiltration',
    pattern: /dump\s+(your\s+)?(full\s+)?(context(\s+window)?|memory|conversation|training)/,
    weight: 8,
    description: 'Dump context window/memory',
  },
  {
    id: 'exfil-training-data',
    category: 'data-exfiltration',
    pattern: /(show|give|return|output|reproduce)\s+(me\s+)?examples?\s+(from\s+)?(your\s+)?(training\s+data|dataset|pre-?training)/,
    weight: 6,
    description: 'Reproduce training data',
  },
];
