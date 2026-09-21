import { REDACT_RULES } from './patterns/redact.js';
import type { RedactRule, RedactTier } from './patterns/redact.js';

export type { RedactRule, RedactTier } from './patterns/redact.js';

export interface RedactOptions {
  /** Which recognisers run. Default both. */
  tiers?: RedactTier[];
  /** Replacement text, or a function of the rule id and the matched value. Default `[REDACTED:<id>]`. */
  replacement?: string | ((id: string, value: string) => string);
  /** Rule ids to skip. */
  disabledRuleIds?: string[];
  /** Extra recognisers, run after the built-in ones. */
  customRules?: RedactRule[];
}

export interface Redaction {
  id: string;
  tier: RedactTier;
  start: number;
  end: number;
}

export interface RedactResult {
  text: string;
  redactions: Redaction[];
}

function luhn(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function ibanMod97(value: string): boolean {
  const compact = value.replace(/\s+/g, '').toUpperCase();
  if (compact.length < 15 || compact.length > 34) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const piece = ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of piece) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

/** SSA rules: no 000/666/9xx area, no 00 group, no 0000 serial. */
function ssn(value: string): boolean {
  const [area, group, serial] = value.split('-');
  if (area === undefined || group === undefined || serial === undefined) return false;
  if (area === '000' || area === '666' || area.startsWith('9')) return false;
  return group !== '00' && serial !== '0000';
}

function ipv4(value: string): boolean {
  return value.split('.').every((o) => Number(o) <= 255);
}

const VALIDATORS: Record<NonNullable<RedactRule['validate']>, (v: string) => boolean> = { luhn, iban: ibanMod97, ssn, ipv4 };

function spanOf(rule: RedactRule, m: RegExpExecArray): { start: number; end: number; value: string } | null {
  if (rule.group === undefined) return { start: m.index, end: m.index + m[0].length, value: m[0] };
  const value = m[rule.group];
  if (value === undefined) return null;
  const offset = m[0].indexOf(value);
  if (offset === -1) return null;
  return { start: m.index + offset, end: m.index + offset + value.length, value };
}

/**
 * Replaces secrets and PII in `text`. Spans are found on the raw text (no normalisation, so digit
 * patterns survive), validated in code where a checksum exists, then replaced right-to-left so
 * offsets in `redactions` refer to the original text. Never applied to guard arguments automatically.
 */
export function redact(text: string, options: RedactOptions = {}): RedactResult {
  const tiers = new Set<RedactTier>(options.tiers ?? ['secrets', 'pii']);
  const disabled = new Set(options.disabledRuleIds ?? []);
  const rules = [...REDACT_RULES, ...(options.customRules ?? [])].filter((r) => tiers.has(r.tier) && !disabled.has(r.id));
  const spans: Redaction[] = [];
  const taken: Array<[number, number]> = [];
  const overlaps = (s: number, e: number) => taken.some(([ts, te]) => s < te && e > ts);

  for (const rule of rules) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const span = spanOf(rule, m);
      if (span === null || overlaps(span.start, span.end)) continue;
      if (rule.validate !== undefined && !VALIDATORS[rule.validate](span.value)) continue;
      taken.push([span.start, span.end]);
      spans.push({ id: rule.id, tier: rule.tier, start: span.start, end: span.end });
    }
  }

  spans.sort((a, b) => a.start - b.start);
  let out = text;
  for (let i = spans.length - 1; i >= 0; i--) {
    const s = spans[i] as Redaction;
    const value = text.slice(s.start, s.end);
    const replacement =
      typeof options.replacement === 'function' ? options.replacement(s.id, value) : (options.replacement ?? `[REDACTED:${s.id}]`);
    out = out.slice(0, s.start) + replacement + out.slice(s.end);
  }
  return { text: out, redactions: spans };
}
