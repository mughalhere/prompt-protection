import type { PatternRule } from '../types.js';

export const contextSmugglingRules: PatternRule[] = [
  {
    id: 'smuggling-but-before-pivot',
    category: 'context-smuggling',
    // "but before I can [eat/do X], I need / can you / help me"
    // .{0,60}? allows for words between "I can" and the request verb
    pattern:
      /\b(but|except)\s+before\s+(i\s+can|i\s+am\s+able\s+to|we\s+can|that\s+happens?)\b.{0,60}?\b(i\s+need|i\s+want|can\s+you|could\s+you|help\s+me|tell\s+me|explain|show\s+me)/i,
    weight: 4,
    description: 'Pivot phrase "but before I can X, I need Y" used to smuggle a request after a benign preamble',
  },
  {
    id: 'smuggling-also-by-the-way',
    category: 'context-smuggling',
    // "by the way / btw / anyway, [can you / tell me ...] how ..."
    // Requires "how" in the request to avoid false positives like "by the way, can you recommend a book"
    pattern:
      /\b(by\s+the\s+way|btw|anyway|while\s+(i\s+have\s+you|i'?ve\s+got\s+you|we'?re?\s+at\s+it|you'?re?\s+here))\s*[,.]?\s*(how\s+(do|would|can|could)\s+(i|you|one)|(can\s+you|could\s+you|would\s+you|help\s+me|tell\s+me|explain).{0,30}?\bhow\b)/i,
    weight: 2,
    description: 'Side-request injection via "by the way / btw / while you\'re at it" with how-to framing',
  },
  {
    id: 'smuggling-setting-aside',
    category: 'context-smuggling',
    // "setting that aside / putting that aside ... how do / can you"
    pattern:
      /\b(setting\s+(that\s+)?aside|putting\s+that\s+aside|leaving\s+that\s+(for\s+later|aside)|forget\s+about\s+that\s+for\s+now|ignoring\s+that\s+(for\s+a\s+moment|temporarily))\s*[,.]?\s*(how\s+(do|can|would|could)|can\s+you|could\s+you|tell\s+me|help\s+me)/i,
    weight: 4,
    description: 'Topic dismissal pivot followed by a new request',
  },
  {
    id: 'smuggling-unrelated-question',
    category: 'context-smuggling',
    // "unrelated question: / off-topic: / changing gears: ... how/can"
    pattern:
      /\b(unrelated(\s+question)?|separate\s+question|off[\s-]topic(\s+question)?|changing\s+(gears?|the\s+subject|topics?)|on\s+a\s+(completely\s+)?different\s+(note|topic|subject))\s*[,.:]\s*(how\s+(do|can|would|could)|can\s+you|could\s+you|tell\s+me|help\s+me|what\s+(is|are))/i,
    weight: 5,
    description: 'Explicit topic-boundary declaration followed by a new request',
  },
  {
    id: 'smuggling-while-doing-dual-task',
    category: 'context-smuggling',
    // "while you're at it, can you also tell me"
    pattern:
      /\bwhile\s+(you'?re?\s+(at\s+it|helping|here)|i\s+have\s+you|we'?re?\s+(talking|at\s+it|on\s+the\s+topic))\s*[,.]?\s*(can\s+you\s+also|could\s+you\s+also|also\s+(tell|help|explain|show)|tell\s+me\s+how)/i,
    weight: 2,
    description: 'Dual-task injection via "while you\'re at it, can you also"',
  },
  {
    id: 'smuggling-first-but-then',
    category: 'context-smuggling',
    // "first / before we start, help me figure out how to"
    pattern:
      /\b(first|before\s+(that|anything|we\s+start|i\s+forget))\s*[,.]?\s*(i\s+need\s+(you\s+to\s+|to\s+)?(tell|explain|show|help|give|describe)|can\s+you\s+(tell|explain|show|help|give)|help\s+me\s+(understand|figure\s+out|with))\s+how\s+to\b/i,
    weight: 4,
    description: 'Prerequisite-request framing: inject a request before the stated main task',
  },
  {
    id: 'smuggling-benign-but-harmful',
    category: 'context-smuggling',
    // "[benign thing] but first/also/then tell me how to"
    pattern:
      /\b(but\s+(first|also|after(wards?)?|then|before\s+that))\s+(tell\s+me|help\s+me|explain|show\s+me|i\s+need\s+to\s+know)\s+(how\s+to|about|the\s+way\s+to)\b/i,
    weight: 5,
    description: 'Canonical context-smuggling form: benign preamble + "but first/also/then tell me how to"',
  },
  {
    id: 'smuggling-real-question',
    category: 'context-smuggling',
    // "my real / actual question is" — meta-admission of smuggling
    pattern:
      /\b(my\s+(real|actual|main|true)\s+(question|request|problem|issue)\s+is|what\s+i\s+(really|actually)\s+(need|want)\s+is|the\s+(real|actual|main)\s+reason\s+i('?m|\s+am)\s+(asking|here)\s+is)/i,
    weight: 4,
    description: 'Explicit framing that the preceding content was a decoy',
  },
  {
    id: 'smuggling-pivot-before-helping',
    category: 'context-smuggling',
    // "before you help [me] / before you answer, I need you to"
    // (\s+\w+)? allows for direct objects like "me" after the verb
    pattern:
      /\b(before\s+you\s+(help|answer|respond|continue)(\s+\w+)?|prior\s+to\s+(helping|answering|that))\s*[,.]?\s*(i\s+need\s+you\s+to|can\s+you|could\s+you|please)/i,
    weight: 2,
    description: 'Prerequisite injection before answering the stated request',
  },
  {
    id: 'smuggling-irrelevant-preamble',
    category: 'context-smuggling',
    // "random question: / weird question:" self-labeling of unrelatedness
    pattern:
      /\b(i\s+know\s+this\s+(is\s+)?(unrelated|off[\s-]topic|weird)|this\s+(might|may)\s+seem\s+(unrelated|random|weird|off[\s-]topic)|random(\s+question)?\s*[,:]\s*|weird\s+question\s*[,:]\s*)/i,
    weight: 2,
    description: 'Self-labeling of topic randomness/unrelatedness as a soft smuggling signal',
  },
];
