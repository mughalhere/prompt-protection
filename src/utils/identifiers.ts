export type IdentifierKind = 'url' | 'host' | 'email' | 'path' | 'ipv4' | 'token' | 'phone';

export interface Identifier {
  kind: IdentifierKind;
  /** Canonical form: lowercase host/email/url-host, trailing punctuation stripped. */
  value: string;
  /** Text exactly as it appeared. */
  raw: string;
  /** Offset of `raw` in the input. */
  index: number;
}

interface Span {
  start: number;
  end: number;
}

const URL_RE = /\bhttps?:\/\/[^\s<>"'`()[\]{}]+/gi;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g;
const IPV4_RE = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g;
const HOST_RE = /(?<![A-Za-z0-9.@/-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![A-Za-z0-9-])/g;
const PATH_RE =
  /(?<![A-Za-z0-9._~-])(?:~\/[^\s"'<>`]+|\.{1,2}\/[^\s"'<>`]+|\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+|[A-Za-z]:\\[^\s"'<>`]+)/g;
const TOKEN_RE = /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g;
const PHONE_RE = /(?<![\d+])\+?\d[\d\s().-]{7,18}\d(?!\d)/g;

const TRAILING_PUNCT_RE = /[.,;:!?'"`)\]}>]+$/;
const FILE_EXT_TLDS = new Set([
  'js', 'ts', 'tsx', 'jsx', 'mjs', 'cjs', 'py', 'md', 'txt', 'json', 'yml', 'yaml', 'html',
  'css', 'csv', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'pdf', 'exe', 'sh', 'env', 'lock', 'toml',
  'xml', 'zip', 'tar', 'gz', 'log', 'test', 'spec', 'config', 'min', 'map', 'rs', 'go', 'java',
]);

function stripTrailing(raw: string): string {
  return raw.replace(TRAILING_PUNCT_RE, '');
}

function overlaps(taken: Span[], start: number, end: number): boolean {
  for (const s of taken) if (start < s.end && end > s.start) return true;
  return false;
}

function hostOfUrl(url: string): string | null {
  const afterScheme = url.slice(url.indexOf('//') + 2);
  const authority = afterScheme.split(/[/?#]/, 1)[0] ?? '';
  const host = authority.slice(authority.lastIndexOf('@') + 1).replace(/:\d+$/, '');
  return host.length > 0 ? host.toLowerCase() : null;
}

function validIpv4(raw: string): boolean {
  return raw.split('.').every((o) => Number(o) <= 255);
}

function phoneDigits(raw: string): string | null {
  const digits = raw.replace(/\D/g, '');
  if (digits.length < 10 || digits.length > 15) return null;
  return raw.startsWith('+') ? `+${digits}` : digits;
}

function hasLetterAndDigit(s: string): boolean {
  return /[A-Za-z]/.test(s) && /\d/.test(s);
}

/**
 * Extracts URLs, hosts, emails, filesystem paths, IPv4s, opaque tokens and phone
 * numbers. Kinds are matched in priority order and never overlap, except that a
 * URL also emits its host so that host-only mentions elsewhere correlate with it.
 */
export function extractIdentifiers(text: string): Identifier[] {
  const out: Identifier[] = [];
  const taken: Span[] = [];

  const claim = (kind: IdentifierKind, raw: string, index: number, value: string): void => {
    taken.push({ start: index, end: index + raw.length });
    out.push({ kind, value, raw, index });
  };

  for (const m of text.matchAll(URL_RE)) {
    const raw = stripTrailing(m[0]);
    const host = hostOfUrl(raw);
    if (host === null) continue;
    const schemeEnd = raw.indexOf('//') + 2;
    const authorityEnd = schemeEnd + (raw.slice(schemeEnd).split(/[/?#]/, 1)[0] ?? '').length;
    const value = raw.slice(0, authorityEnd).toLowerCase() + raw.slice(authorityEnd);
    claim('url', raw, m.index, value);
    out.push({ kind: 'host', value: host, raw: host, index: m.index + schemeEnd });
  }

  for (const m of text.matchAll(EMAIL_RE)) {
    const raw = stripTrailing(m[0]);
    if (overlaps(taken, m.index, m.index + raw.length)) continue;
    claim('email', raw, m.index, raw.toLowerCase());
  }

  for (const m of text.matchAll(PATH_RE)) {
    const raw = stripTrailing(m[0]);
    if (raw.length < 2 || overlaps(taken, m.index, m.index + raw.length)) continue;
    claim('path', raw, m.index, raw);
  }

  for (const m of text.matchAll(IPV4_RE)) {
    const raw = m[0];
    if (!validIpv4(raw) || overlaps(taken, m.index, m.index + raw.length)) continue;
    claim('ipv4', raw, m.index, raw);
  }

  for (const m of text.matchAll(PHONE_RE)) {
    const raw = m[0].trim();
    const value = phoneDigits(raw);
    if (value === null || overlaps(taken, m.index, m.index + raw.length)) continue;
    claim('phone', raw, m.index, value);
  }

  for (const m of text.matchAll(HOST_RE)) {
    const raw = m[0];
    const tld = raw.slice(raw.lastIndexOf('.') + 1).toLowerCase();
    if (FILE_EXT_TLDS.has(tld) || overlaps(taken, m.index, m.index + raw.length)) continue;
    claim('host', raw, m.index, raw.toLowerCase());
  }

  for (const m of text.matchAll(TOKEN_RE)) {
    const raw = m[0];
    if (!hasLetterAndDigit(raw) || overlaps(taken, m.index, m.index + raw.length)) continue;
    claim('token', raw, m.index, raw);
  }

  return out.sort((a, b) => a.index - b.index || a.kind.localeCompare(b.kind));
}
