import { ALL_RULES, OUTPUT_RULES, TOOL_RULES } from '../../src/patterns/index';
import { DEFAULT_SINK_PATTERNS } from '../../src/guard/sinks';
import { IDENTIFIER_REGEXES } from '../../src/utils/identifiers';
import { PROVENANCE_REGEXES } from '../../src/guard/provenance';
import { ENCODING_REGEXES } from '../../src/utils/encoding';
import { UNICODE_REGEXES } from '../../src/utils/unicode';

export interface RegexUnderTest {
  owner: string;
  id: string;
  source: string;
  /** Flags the regex actually runs with (rules are compiled `gi` by the scorer). */
  flags: string;
}

function fromBag(owner: string, bag: Record<string, RegExp>): RegexUnderTest[] {
  return Object.entries(bag).map(([id, re]) => ({ owner, id, source: re.source, flags: re.flags }));
}

/** Every regex the library runs on untrusted text, deduplicated by source + flags. */
export function collectRegexes(): RegexUnderTest[] {
  const out: RegexUnderTest[] = [];
  const seen = new Set<string>();
  const push = (r: RegexUnderTest) => {
    const key = `${r.flags}/${r.source}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(r);
  };

  for (const [owner, rules] of [
    ['input-rules', ALL_RULES],
    ['output-rules', OUTPUT_RULES],
    ['tool-rules', TOOL_RULES],
  ] as const) {
    for (const rule of rules) push({ owner, id: rule.id, source: rule.pattern.source, flags: 'gi' });
  }
  for (const entry of DEFAULT_SINK_PATTERNS) push({ owner: 'guard-sinks', id: entry.sink, source: entry.pattern.source, flags: entry.pattern.flags });
  for (const r of fromBag('identifiers', IDENTIFIER_REGEXES)) push(r);
  for (const r of fromBag('provenance', PROVENANCE_REGEXES)) push(r);
  for (const r of fromBag('encoding', ENCODING_REGEXES)) push(r);
  for (const r of fromBag('unicode', UNICODE_REGEXES)) push(r);
  return out;
}
