import type { AtrOperator, AtrSkipReason } from './types.js';

export type CompileOutcome = { ok: true; pattern: RegExp } | { ok: false; reason: AtrSkipReason; detail: string };

const OPERATORS = new Set<string>(['regex', 'contains', 'exact', 'starts_with']);
// PCRE constructs JavaScript cannot express; a silent approximation would change what the rule means.
const PCRE_ONLY = /\(\?P</;
const PCRE_TOKENS = /\\[hHRK]|\(\?>|[*+?}]\+/;
const INLINE_FLAGS = /^\(\?([a-zA-Z]+)\)/;

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function isSupportedOperator(op: string | undefined): op is AtrOperator {
  return op !== undefined && OPERATORS.has(op);
}

/** Turns one ATR condition into a JavaScript regex source the scorer compiles with `gi`. */
export function compileCondition(operator: AtrOperator, value: string): CompileOutcome {
  switch (operator) {
    case 'contains':
      return safeRegExp(escapeRegExp(value));
    case 'exact':
      return safeRegExp(`^${escapeRegExp(value)}$`);
    case 'starts_with':
      return safeRegExp(`^${escapeRegExp(value)}`);
    case 'regex':
      return compileRegex(value);
  }
}

function compileRegex(source: string): CompileOutcome {
  let src = source;
  const flags = INLINE_FLAGS.exec(src);
  if (flags) {
    const letters = flags[1] ?? '';
    if (/[^ismx]/.test(letters)) return { ok: false, reason: 'unsupported-syntax', detail: `inline flag (?${letters})` };
    src = src.slice(flags[0].length);
    if (letters.includes('s')) src = src.replace(/(?<!\\)\.(?![^[]*\])/g, '[\\s\\S]');
    if (letters.includes('x')) return { ok: false, reason: 'unsupported-syntax', detail: 'extended (x) mode' };
  }
  if (PCRE_ONLY.test(src)) return { ok: false, reason: 'unsupported-syntax', detail: 'named group (?P<…>)' };
  if (PCRE_TOKENS.test(src)) return { ok: false, reason: 'unsupported-syntax', detail: 'PCRE-only token (\\h \\R \\K, atomic or possessive)' };
  if (/\\p\{/.test(src)) return { ok: false, reason: 'unsupported-syntax', detail: 'unicode property escape needs the u flag' };
  return safeRegExp(src);
}

function safeRegExp(src: string): CompileOutcome {
  try {
    return { ok: true, pattern: new RegExp(src, 'gi') };
  } catch (err) {
    return { ok: false, reason: 'invalid-regex', detail: err instanceof Error ? err.message : String(err) };
  }
}
