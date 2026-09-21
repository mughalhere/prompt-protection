import { normalizeUnicode } from './utils/unicode.js';
import { decodeObfuscation } from './utils/encoding.js';
import { score } from './scorer.js';
import { OUTPUT_RULES } from './patterns/index.js';
import { computeSeverity, failedAnalysis } from './core/analyze.js';
import { resolveAction } from './verdict.js';
import { emitOutputLog } from './logging.js';
import {
  detectCanary,
  promptSimilarity,
  SIMILARITY_CONTAINMENT_THRESHOLD,
  SIMILARITY_RUN_THRESHOLD,
} from './canary/index.js';
import { normalize } from './normalizer.js';
import { redact } from './redact.js';
import type {
  CanaryDetection,
  OutputAnalysisOptions,
  OutputAnalysisResult,
  PatternMatch,
  PatternRule,
  RenderFinding,
  ThreatCategory,
} from './types.js';

// Higher than input default (35) to reduce false positives, but low enough
// that a single high-confidence match (weight 10 → score ~49) still triggers.
const DEFAULT_OUTPUT_THRESHOLD = 40;
const DEFAULT_MAX_INPUT_LENGTH = 100_000;

// Synthetic rules (never match text; see session.ts CORRELATION_RULE precedent).
const CANARY_LEAK_RULE: PatternRule = {
  id: 'out-canary-leak',
  category: 'system-prompt-leak',
  pattern: /(?!)/,
  weight: 10,
  precision: 'high',
  description: 'Canary token injected into the system prompt appears in the output',
};

const PROMPT_SIMILARITY_RULE: PatternRule = {
  id: 'out-system-prompt-similarity',
  category: 'system-prompt-leak',
  pattern: /(?!)/,
  weight: 8,
  precision: 'medium',
  description: 'Output reproduces a substantial verbatim portion of the system prompt',
};

function syntheticMatch(rule: PatternRule, matchedText: string): PatternMatch {
  return { rule, matchedText, startIndex: 0, endIndex: 0 };
}

// --- Render-exfil (4.3): only when `renderAllowlist` is set, so existing users see no change. ---

const RENDER_UNLISTED_HOST_RULE: PatternRule = {
  id: 'out-render-unlisted-host',
  category: 'data-exfiltration',
  pattern: /(?!)/,
  weight: 9,
  precision: 'high',
  description: 'Output renders or links a URL on a host outside the render allowlist',
};
const DATA_URI_RULE: PatternRule = {
  id: 'out-data-uri-exfil',
  category: 'data-exfiltration',
  pattern: /(?!)/,
  weight: 8,
  precision: 'high',
  description: 'Output renders a data: URI (client-side payload carrier)',
};
const QUERY_ENTROPY_RULE: PatternRule = {
  id: 'out-query-param-high-entropy',
  category: 'data-exfiltration',
  pattern: /(?!)/,
  weight: 8,
  precision: 'medium',
  description: 'A rendered URL carries a long high-entropy query value',
};
const QUERY_CONVERSATION_RULE: PatternRule = {
  id: 'out-query-param-conversation',
  category: 'data-exfiltration',
  pattern: /(?!)/,
  weight: 9,
  precision: 'high',
  description: 'A rendered URL carries conversation text in a query value',
};

const MD_IMAGE_RE = /!\[[^\][\n]{0,200}\]\(\s*([^\s)]+)/g;
const MD_LINK_RE = /(?<!!)\[[^\][\n]{0,200}\]\(\s*([^\s)]+)/g;
const HTML_SRC_RE = /(?<![\w-])src\s*=\s*["']?([^"'\s>]+)/gi;
const HTML_HREF_RE = /(?<![\w-])href\s*=\s*["']?([^"'\s>]+)/gi;
export const RENDER_REGEXES = { MD_IMAGE_RE, MD_LINK_RE, HTML_SRC_RE, HTML_HREF_RE } as const;

const ENTROPY_MIN_CHARS = 20;
const ENTROPY_MIN_BITS = 3.5;

function shannonBitsPerChar(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

function hostAllowed(host: string, allow: readonly string[]): boolean {
  const h = host.toLowerCase();
  return allow.some((entry) => {
    const e = entry.toLowerCase();
    if (e.startsWith('*.')) return h === e.slice(2) || h.endsWith(e.slice(1));
    return h === e;
  });
}

function detectRender(
  output: string,
  options: OutputAnalysisOptions,
): { render: RenderFinding[]; synthetic: PatternMatch[] } | null {
  const allow = options.renderAllowlist;
  if (allow === undefined) return null;
  const render: RenderFinding[] = [];
  const synthetic: PatternMatch[] = [];
  const conversation = options.conversation !== undefined ? normalize(options.conversation).normalized : null;
  const seen = new Set<string>();
  const sources: Array<[RegExp, RenderFinding['via']]> = [
    [MD_IMAGE_RE, 'markdown-image'],
    [MD_LINK_RE, 'markdown-link'],
    [HTML_SRC_RE, 'html-src'],
    [HTML_HREF_RE, 'html-href'],
  ];
  for (const [re, via] of sources) {
    for (const m of output.matchAll(re)) {
      const raw = m[1];
      if (raw === undefined || seen.has(`${via}:${raw}`)) continue;
      seen.add(`${via}:${raw}`);
      if (/^data:/i.test(raw)) {
        render.push({ url: raw.slice(0, 120), host: '', via: 'data-uri', allowed: false });
        synthetic.push(syntheticMatch(DATA_URI_RULE, raw.slice(0, 64)));
        continue;
      }
      let url: URL;
      try {
        url = new URL(raw);
      } catch {
        continue; // relative or malformed: nothing to exfiltrate to
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
      const allowed = hostAllowed(url.hostname, allow);
      const finding: RenderFinding = { url: raw, host: url.hostname, via, allowed };
      const suspicious: NonNullable<RenderFinding['suspiciousParams']> = [];
      for (const [name, value] of url.searchParams) {
        if (value.length >= ENTROPY_MIN_CHARS && shannonBitsPerChar(value) >= ENTROPY_MIN_BITS) suspicious.push({ name, reason: 'high-entropy' });
        else if (conversation !== null && value.length >= 12 && conversation.includes(normalize(value).normalized)) suspicious.push({ name, reason: 'conversation' });
      }
      if (suspicious.length > 0) finding.suspiciousParams = suspicious;
      render.push(finding);
      if (!allowed) synthetic.push(syntheticMatch(RENDER_UNLISTED_HOST_RULE, `${via} ${url.hostname}`));
      for (const p of suspicious) {
        synthetic.push(syntheticMatch(p.reason === 'high-entropy' ? QUERY_ENTROPY_RULE : QUERY_CONVERSATION_RULE, `${url.hostname}?${p.name}`));
      }
    }
  }
  return { render, synthetic };
}

/**
 * Runs canary + system-prompt similarity when configured. Returns the
 * detection plus the synthetic matches it justifies (appended to `matches`
 * before verdict resolution so `action` and `isSuspicious` stay consistent).
 */
function detectLeaks(
  output: string,
  options: OutputAnalysisOptions,
): { canary: CanaryDetection; synthetic: PatternMatch[] } | null {
  if (options.canary === undefined && options.systemPrompt === undefined) return null;

  const canary: CanaryDetection =
    options.canary !== undefined
      ? detectCanary(output, options.canary)
      : { leaked: false, confidence: 0, variants: [] };
  if (options.systemPrompt !== undefined) {
    canary.promptSimilarity = promptSimilarity(output, options.systemPrompt);
  }

  const synthetic: PatternMatch[] = [];
  if (canary.leaked) {
    synthetic.push(syntheticMatch(CANARY_LEAK_RULE, canary.variants.join(',')));
  }
  const sim = canary.promptSimilarity;
  if (
    sim &&
    (sim.containment >= SIMILARITY_CONTAINMENT_THRESHOLD || sim.longestRun >= SIMILARITY_RUN_THRESHOLD)
  ) {
    synthetic.push(
      syntheticMatch(
        PROMPT_SIMILARITY_RULE,
        `containment=${sim.containment.toFixed(2)} run=${sim.longestRun}`,
      ),
    );
  }
  return { canary, synthetic };
}

function rescore(rawScore: number, synthetic: PatternMatch[]): number {
  const raw = synthetic.reduce((acc, m) => acc + m.rule.weight, rawScore);
  return Math.round(100 * (1 - Math.exp(-raw / 15)));
}

/**
 * Normalizes output text for scanning without applying the homoglyph digit→letter
 * substitution used for input analysis. Output scanning needs real digits intact
 * so that patterns for API keys, SSNs, and credit card numbers can match.
 */
function normalizeOutput(text: string): string {
  const afterUnicode = normalizeUnicode(text);
  const afterDecoding = decodeObfuscation(afterUnicode);
  return afterDecoding.toLowerCase();
}

function buildOutputRuleSet(options: OutputAnalysisOptions): PatternRule[] {
  let rules = [...OUTPUT_RULES];

  if (options.disabledCategories && options.disabledCategories.length > 0) {
    const disabled = new Set(options.disabledCategories);
    rules = rules.filter((r) => !disabled.has(r.category));
  }

  if (options.disabledRuleIds && options.disabledRuleIds.length > 0) {
    const disabled = new Set(options.disabledRuleIds);
    rules = rules.filter((r) => !disabled.has(r.id));
  }

  if (options.customRules && options.customRules.length > 0) {
    rules = [...rules, ...options.customRules];
  }

  return rules;
}

/**
 * Scans LLM output for signs of compromise: system prompt leakage,
 * credential exposure, injection relay, and PII exposure.
 */
export function analyzeOutput(
  output: string,
  options: OutputAnalysisOptions = {},
): OutputAnalysisResult {
  const threshold = options.threshold ?? DEFAULT_OUTPUT_THRESHOLD;
  try {
  const rules = buildOutputRuleSet(options);

  const cap = options.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
  const capped = output.length > cap ? output.slice(0, cap) : output;
  const normalized = normalizeOutput(capped);
  const scored = score(rules, normalized, capped, {
    ...(options.allowlistPatterns ? { allowlistPatterns: options.allowlistPatterns } : {}),
    ...(options.allowlistRuleIds ? { allowlistRuleIds: options.allowlistRuleIds } : {}),
  });

  const leaks = detectLeaks(capped, options);
  const render = detectRender(capped, options);
  const synthetic = [...(leaks?.synthetic ?? []), ...(render?.synthetic ?? [])];
  const matches = synthetic.length > 0 ? [...scored.matches, ...synthetic] : scored.matches;
  const normalizedScore = synthetic.length > 0 ? rescore(scored.rawScore, synthetic) : scored.normalizedScore;

  const threats = [...new Set(matches.map((m) => m.rule.category))] as ThreatCategory[];
  const action = resolveAction(normalizedScore, matches, threshold, options.flagThreshold);

  const result: OutputAnalysisResult = {
    score: normalizedScore,
    severity: computeSeverity(normalizedScore),
    isSuspicious: action === 'flag' || action === 'block',
    action,
    matches,
    threats,
  };
  if (leaks) result.canary = leaks.canary;
  if (render) result.render = render.render;
  if (options.redact !== undefined && options.redact !== false) {
    const tiers = options.redact === 'all' ? undefined : [options.redact];
    const r = redact(output, tiers !== undefined ? { tiers } : {});
    result.redacted = r.text;
    result.redactions = r.redactions;
  }

  emitOutputLog(result, output, options);

  return result;
  } catch (err) {
    const failed = failedAnalysis(err, options.failMode ?? 'closed', threshold);
    const result: OutputAnalysisResult = {
      score: failed.score,
      severity: failed.severity,
      isSuspicious: failed.action !== 'allow',
      action: failed.action,
      matches: failed.matches,
      threats: [],
      ...(failed.error ? { error: failed.error } : {}),
    };
    emitOutputLog(result, output, options);
    return result;
  }
}
