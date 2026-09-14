import type { AnalysisResult, OutputAnalysisResult, PatternMatch, PatternRule, RuleMappings } from '../types.js';
import { RULES_VERSION } from '../patterns/version.js';
import { ATR_ID_PREFIX } from './load.js';
import type { AtrFinding, AtrScanResult, AtrScanTarget, AtrSeverity } from './types.js';

const SEVERITY_RANK: Record<AtrSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };

export interface ToAtrFindingsOptions {
  scanType?: AtrScanTarget;
  rulesLoaded?: number;
  /** Rules to report as `matched: false` (coverage reports). */
  includeNonMatching?: readonly PatternRule[];
  contentHash?: string;
  engineVersion?: string;
  /** Extra framework ids for native rules, keyed by rule id. */
  mappings?: Readonly<Record<string, RuleMappings>>;
  now?: () => Date;
}

interface ResultLike {
  matches: PatternMatch[];
}

function severityFromWeight(weight: number): AtrSeverity {
  if (weight >= 9) return 'critical';
  if (weight >= 7) return 'high';
  if (weight >= 5) return 'medium';
  return 'low';
}

function toReferences(m: RuleMappings | undefined): AtrFinding['references'] | undefined {
  if (!m) return undefined;
  const refs: NonNullable<AtrFinding['references']> = {};
  if (m.owaspLlm) refs.owasp_llm = m.owaspLlm;
  if (m.owaspAsi) refs.owasp_agentic = m.owaspAsi;
  if (m.owaspAst) refs.owasp_ast = m.owaspAst;
  if (m.atlas) refs.mitre_atlas = m.atlas;
  if (m.attack) refs.mitre_attack = m.attack;
  if (m.cve) refs.cve = m.cve;
  return Object.keys(refs).length > 0 ? refs : undefined;
}

/** Groups matches into spec §5.5 findings: one per ATR rule, one per native rule. */
export function toAtrFindings(
  result: AnalysisResult | OutputAnalysisResult | ResultLike,
  options: ToAtrFindingsOptions = {},
): AtrScanResult {
  const byRule = new Map<string, AtrFinding & { seen: Set<number> }>();

  for (const match of result.matches) {
    const rule = match.rule;
    const origin = rule.origin;
    if (origin?.format === 'atr') {
      const key = origin.ruleId;
      let f = byRule.get(key);
      if (f === undefined) {
        f = {
          rule_id: origin.ruleId,
          severity: origin.severity,
          confidence: 0,
          matched: true,
          matched_conditions: [],
          matched_patterns: [],
          tags: origin.tags,
          seen: new Set<number>(),
        };
        if (origin.tags.scan_target !== undefined) f.scan_target = origin.tags.scan_target;
        const refs = toReferences(rule.mappings);
        if (refs !== undefined) f.references = refs;
        byRule.set(key, f);
      }
      if (!f.seen.has(origin.conditionIndex)) {
        f.seen.add(origin.conditionIndex);
        f.matched_conditions.push(origin.conditionIndex);
        f.matched_patterns.push(rule.pattern.source);
        f.confidence = f.seen.size / Math.max(1, origin.conditionCount);
      }
      continue;
    }
    const key = `pp:${rule.id}`;
    if (byRule.has(key)) continue;
    const mappings = rule.mappings ?? options.mappings?.[rule.id];
    const native: AtrFinding & { seen: Set<number> } = {
      rule_id: key,
      severity: severityFromWeight(rule.weight),
      confidence: 1,
      matched: true,
      matched_conditions: [0],
      matched_patterns: [rule.pattern.source],
      title: rule.description,
      seen: new Set([0]),
    };
    const refs = toReferences(mappings);
    if (refs !== undefined) native.references = refs;
    byRule.set(key, native);
  }

  const matches: AtrFinding[] = [...byRule.values()].map(({ seen: _seen, ...f }) => f);
  for (const rule of options.includeNonMatching ?? []) {
    const id = rule.origin?.format === 'atr' ? rule.origin.ruleId : `pp:${rule.id}`;
    if (byRule.has(id)) continue;
    const miss: AtrFinding = {
      rule_id: id,
      severity: rule.origin?.severity ?? severityFromWeight(rule.weight),
      confidence: 0,
      matched: false,
      matched_conditions: [],
      matched_patterns: [],
    };
    matches.push(miss);
    byRule.set(id, { ...miss, seen: new Set() });
  }
  matches.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.confidence - a.confidence || a.rule_id.localeCompare(b.rule_id));

  return {
    scan_type: options.scanType ?? 'runtime',
    ...(options.contentHash !== undefined ? { content_hash: options.contentHash } : {}),
    timestamp: (options.now ?? (() => new Date()))().toISOString(),
    rules_loaded: options.rulesLoaded ?? matches.length,
    matches,
    threat_count: matches.filter((m) => m.matched).length,
    engine: { name: 'prompt-protection', version: options.engineVersion ?? ENGINE_VERSION, rules_version: RULES_VERSION },
  };
}

/** Kept in sync with package.json by the release checklist. */
export const ENGINE_VERSION = '3.1.0';

export { ATR_ID_PREFIX };
