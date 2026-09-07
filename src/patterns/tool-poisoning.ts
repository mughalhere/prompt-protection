import type { PatternRule } from '../types.js';

/**
 * Tool-poisoning rules target malicious instructions hidden inside a **tool or
 * function definition** (its description or parameter docs) — the MCP / agent
 * attack where the agent reads the poisoned metadata but the user never sees it.
 * These are written to run against the flattened text of a tool definition (see
 * `scanToolDefinition`), where imperative "instructions to the model" are almost
 * never legitimate — hence mostly high precision.
 */
export const toolPoisoningRules: PatternRule[] = [
  {
    id: 'tool-hidden-instruction-tag',
    category: 'tool-poisoning',
    // <important>, <system>, <instructions>, <secret> blocks embedded in metadata
    pattern: /<\s*(important|system|instructions?|secret|hidden|ai_instructions?)\s*>/,
    weight: 9,
    precision: 'high',
    description: 'Hidden instruction/system block embedded in a tool definition',
  },
  {
    id: 'tool-before-using-directive',
    category: 'tool-poisoning',
    // "before using this tool, (you must) ..." / "before calling this function, first ..."
    pattern:
      /before\s+(using|calling|invoking|running)\s+(this|the)\s+(tool|function|command)\b.{0,60}?\b(you\s+must|first|always|make\s+sure|ensure|read|fetch|send|call)/,
    weight: 8,
    precision: 'high',
    description: 'Imperative "before using this tool, do X" directive in tool metadata',
  },
  {
    id: 'tool-conceal-from-user',
    category: 'tool-poisoning',
    // "do not tell/mention/inform the user", "without informing the user", "keep this hidden from the user"
    pattern:
      /\b(do\s*n[o']?t|never|without)\s+(tell|telling|mention(ing)?|inform(ing)?|reveal(ing)?|show(ing)?|notify(ing)?)\s+(this\s+)?(to\s+)?the\s+user\b|\b(hide|conceal|keep\s+(this|it)\s+(hidden|secret))\s+from\s+the\s+user\b/,
    weight: 9,
    precision: 'high',
    description: 'Directive to conceal tool behaviour from the user',
  },
  {
    id: 'tool-exfiltrate-result',
    category: 'tool-poisoning',
    // "send/forward/post/upload the result/output/data/response to <destination>".
    // Note: input normalization folds "@" -> "a", so email addresses cannot be
    // matched by "@"; match the verb+object+destination shape instead.
    pattern:
      /\b(send|forward|post|upload|exfiltrate|transmit|leak)\s+(the\s+)?(results?|output|data|response|content|files?|contents?|conversation|context)\s+(to|at)\s+(https?:\/\/\S+|the\s+following|[\w.+-]{2,})/,
    weight: 9,
    precision: 'high',
    description: 'Directive in tool metadata to exfiltrate results to an external destination',
  },
  {
    id: 'tool-override-other-tools',
    category: 'tool-poisoning',
    // "ignore/disregard (all) other tools", "do not use any other tool", "always use this tool instead"
    pattern:
      /\b(ignore|disregard|do\s*n[o']?t\s+use|never\s+use|avoid)\s+(all\s+)?(the\s+)?other\s+(tools?|functions?|commands?)\b|\balways\s+use\s+(this|the)\s+(tool|function)\s+(instead|for\s+(all|every))/,
    weight: 8,
    precision: 'high',
    description: 'Directive steering the agent away from other tools toward this one',
  },
  {
    id: 'tool-read-secrets',
    category: 'tool-poisoning',
    // instruction to read credentials/secret files as part of the tool.
    // No leading \b on the alternation — targets like ".env" and "/etc/passwd"
    // start with a non-word char, so a boundary there never matches.
    pattern:
      /\b(read|cat|open|load|include|attach|fetch)\b.{0,40}?(\.env|\.ssh|\/etc\/passwd|~\/\.aws|id_rsa|\bprivate\s+key\b|\bcredentials?\b|\bsecrets?\b|\bapi[_\s-]?keys?\b)/,
    weight: 8,
    precision: 'high',
    description: 'Tool metadata instructing retrieval of credentials or secret files',
  },
  {
    id: 'tool-side-effect-injection',
    category: 'tool-poisoning',
    // "when/whenever this tool is called/used, (also) ..."
    pattern:
      /\b(when(ever)?|each\s+time|every\s+time)\s+(this|the)\s+(tool|function|command)\s+is\s+(called|used|invoked|run)\b.{0,50}?\b(also|additionally|first|then|silently|secretly)\b/,
    weight: 8,
    precision: 'high',
    description: 'Hidden side-effect attached to tool invocation in its definition',
  },
  {
    id: 'tool-role-injection',
    category: 'tool-poisoning',
    // role/turn markers or "you are now" repositioning inside a tool description
    pattern:
      /(<\|(im_start|system|assistant)\|>|\[system\]|\bassistant\s*:|\byou\s+are\s+now\s+(a|an|the)\b)/,
    weight: 7,
    precision: 'medium',
    description: 'Role/turn injection markers inside a tool definition',
  },
  {
    id: 'tool-ignore-previous',
    category: 'tool-poisoning',
    // classic override phrasing appearing in tool metadata
    pattern:
      /\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|the\s+system)\s+(instructions?|rules?|prompt|context)/,
    weight: 8,
    precision: 'high',
    description: 'Instruction-override phrasing embedded in a tool definition',
  },
];
