'use strict';
// Translates JS regex sources to Python-ready sources for python/.../_data/rules.json.
// Plan design item 2 and owner decision 1 (py-port-4-5); errors per e-54dd32.

const WS = '\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff';
const DOT = '[^\\n\\r\\u2028\\u2029]';

const range = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => from + i);

// D15: the 25 JS \s members, then NEL, U+001C and ZWSP, which \s does not match.
const SEPARATORS = Object.freeze([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, ...range(0x2000, 0x200a),
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff,
  0x85, 0x1c, 0x200b,
]);

function fail(source, reason) {
  return new Error(`cannot translate regex source "${source}": ${reason}`);
}

// `start` indexes the '[' that opens the class. Returns the translated class and the index after its ']'.
function translateClass(source, start) {
  let i = start + 1;
  const negated = source[i] === '^';
  if (negated) i++;
  let rest = '';
  let hasNonSpace = false;
  for (; i < source.length; i++) {
    const c = source[i];
    if (c === ']') {
      return { text: finishClass(source, negated, rest, hasNonSpace), next: i + 1 };
    }
    if (c !== '\\') {
      rest += c;
      continue;
    }
    const e = source[i + 1];
    if (e === undefined) break;
    i++;
    if (e === 's') rest += WS;
    else if (e === 'S') hasNonSpace = true;
    else rest += `\\${e}`;
  }
  throw fail(source, 'unterminated character class');
}

function finishClass(source, negated, rest, hasNonSpace) {
  if (!hasNonSpace) return `[${negated ? '^' : ''}${rest}]`;
  if (negated) throw fail(source, '\\S inside a negated character class');
  return rest === '' ? `[^${WS}]` : `(?:[${rest}]|[^${WS}])`;
}

function translateSource(source) {
  let out = '';
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === '\\') {
      const e = source[i + 1];
      if (e === undefined) throw fail(source, 'dangling backslash');
      i++;
      if (e === 's') out += `[${WS}]`;
      else if (e === 'S') out += `[^${WS}]`;
      else out += `\\${e}`;
    } else if (c === '[') {
      const cls = translateClass(source, i);
      out += cls.text;
      i = cls.next - 1;
    } else {
      out += c === '.' ? DOT : c;
    }
  }
  return out;
}

function buildRulesJson(rules, rulesVersion, deferred) {
  return {
    rulesVersion,
    deferredReferenceRuleIds: [...deferred],
    rules: rules.map((rule) => ({
      id: rule.id,
      source: translateSource(rule.pattern.source),
      weight: rule.weight,
      category: rule.category,
      ...(rule.mappings === undefined ? {} : { mappings: rule.mappings }),
      precision: rule.precision ?? 'medium',
    })),
  };
}

module.exports = { translateSource, buildRulesJson, SEPARATORS };
