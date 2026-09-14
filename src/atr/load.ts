import type { PatternRule, RuleMappings, RulePrecision, ThreatCategory } from '../types.js';
import { sourceCompatible } from './compat.js';
import { compileCondition, isSupportedOperator } from './compile.js';
import type { AtrCondition, AtrLoadOptions, AtrLoadResult, AtrRule, AtrSeverity, AtrSkip } from './types.js';

export const ATR_ID_PREFIX = 'atr:';

const SEVERITY_WEIGHT: Record<AtrSeverity, number> = { critical: 10, high: 8, medium: 6, low: 4, informational: 2 };

export const DEFAULT_CATEGORY_MAP: Record<string, ThreatCategory> = {
  'prompt-injection': 'prompt-injection',
  'tool-poisoning': 'tool-poisoning',
  'skill-compromise': 'tool-poisoning',
  'context-exfiltration': 'data-exfiltration',
  'agent-manipulation': 'social-engineering',
  'privilege-escalation': 'security-bypass',
  'excessive-autonomy': 'security-bypass',
  'data-poisoning': 'context-smuggling',
  'model-abuse': 'jailbreak',
  'model-security': 'jailbreak',
};

const DEFAULT_FIELDS: readonly string[] = ['content', 'user_input'];

function isRule(value: unknown): value is AtrRule {
  if (typeof value !== 'object' || value === null) return false;
  const r = value as Partial<AtrRule>;
  return typeof r.id === 'string' && typeof r.severity === 'string' && typeof r.detection === 'object' && r.detection !== null;
}

export function referencesToMappings(refs: AtrRule['references'], ruleId: string): RuleMappings {
  const out: RuleMappings = { atr: [ruleId] };
  if (refs?.owasp_llm?.length) out.owaspLlm = [...refs.owasp_llm];
  if (refs?.owasp_agentic?.length) out.owaspAsi = [...refs.owasp_agentic];
  if (refs?.owasp_ast?.length) out.owaspAst = [...refs.owasp_ast];
  if (refs?.mitre_atlas?.length) out.atlas = [...refs.mitre_atlas];
  if (refs?.mitre_attack?.length) out.attack = [...refs.mitre_attack];
  if (refs?.cve?.length) out.cve = [...refs.cve];
  return out;
}

/**
 * Compiles ATR rules into `PatternRule`s for `customRules`. Every condition of
 * an `any` rule becomes one PatternRule sharing `atr:<id>`, so the scorer's
 * diminishing-returns logic treats the ATR rule as a single rule.
 */
export function loadAtrRules(input: readonly unknown[], options: AtrLoadOptions = {}): AtrLoadResult {
  const skipped: AtrSkip[] = [];
  const rules: PatternRule[] = [];
  const fields = new Set(options.fields ?? DEFAULT_FIELDS);
  const categoryMap = { ...DEFAULT_CATEGORY_MAP, ...(options.categoryMap ?? {}) };
  let compiledRules = 0;
  let compiledConditions = 0;
  let droppedConditions = 0;

  for (const raw of input) {
    if (!isRule(raw)) {
      skipped.push({ rule_id: String((raw as { id?: unknown } | null)?.id ?? '?'), reason: 'invalid-rule' });
      continue;
    }
    const rule = raw;
    const skip = (reason: AtrSkip['reason'], detail?: string) =>
      skipped.push({ rule_id: rule.id, reason, ...(detail !== undefined ? { detail } : {}) });

    const retired = rule.status === 'deprecated' || rule.maturity === 'deprecated' || (rule.status === 'draft' && !options.includeDraft);
    if (retired) { skip('draft-or-deprecated'); continue; }
    if (options.lane === 'enforce' && rule.maturity !== 'stable') { skip('lane-excluded', `maturity ${rule.maturity ?? 'unset'}`); continue; }
    const target = rule.tags?.scan_target;
    if (options.scanTarget !== undefined && target !== undefined && target !== options.scanTarget) { skip('scan-target-mismatch', target); continue; }
    if (options.agentSource !== undefined && !sourceCompatible(options.agentSource, rule.agent_source?.type)) {
      skip('agent-source-mismatch', rule.agent_source?.type ?? 'unset');
      continue;
    }

    const conditions = rule.detection.conditions;
    if (!Array.isArray(conditions)) { skip('named-conditions-unsupported'); continue; }
    const logic = (rule.detection.condition ?? 'any').toLowerCase();
    if ((logic === 'all' || logic === 'and') && conditions.length > 1) { skip('and-conditions-unsupported', `${conditions.length} conditions`); continue; }
    if (logic !== 'any' && logic !== 'or' && logic !== 'all' && logic !== 'and') { skip('named-conditions-unsupported', `condition "${rule.detection.condition}"`); continue; }

    const weight = options.weightFor?.(rule) ?? SEVERITY_WEIGHT[rule.severity] ?? 6;
    const precision: RulePrecision = options.precisionFor?.(rule) ?? rule.tags?.confidence ?? 'medium';
    const category = categoryMap[rule.tags?.category ?? ''] ?? 'prompt-injection';
    const mappings = referencesToMappings(rule.references, rule.id);
    let produced = 0;

    conditions.forEach((cond: AtrCondition, index) => {
      const field = cond.field ?? 'content';
      if (!fields.has(field)) { droppedConditions++; skip('field-not-applicable', `${index}:${field}`); return; }
      if (cond.patterns !== undefined || cond.metric !== undefined || cond.steps !== undefined) { droppedConditions++; skip('named-conditions-unsupported', `${index}`); return; }
      if (!isSupportedOperator(cond.operator)) { droppedConditions++; skip('unsupported-operator', `${index}:${cond.operator ?? 'unset'}`); return; }
      if (typeof cond.value !== 'string' || cond.value.length === 0) { droppedConditions++; skip('invalid-rule', `${index}: empty value`); return; }
      const compiled = compileCondition(cond.operator, cond.value);
      if (!compiled.ok) { droppedConditions++; skip(compiled.reason, `${index}: ${compiled.detail}`); return; }
      produced++;
      compiledConditions++;
      rules.push({
        id: `${ATR_ID_PREFIX}${rule.id}`,
        category,
        pattern: compiled.pattern,
        weight,
        precision,
        description: cond.description ?? rule.title,
        mappings,
        origin: {
          format: 'atr',
          ruleId: rule.id,
          ...(rule.rule_version !== undefined ? { ruleVersion: rule.rule_version } : {}),
          severity: rule.severity,
          tags: rule.tags,
          conditionIndex: index,
          conditionCount: conditions.length,
          field,
          operator: cond.operator,
        },
      });
    });
    if (produced > 0) compiledRules++;
  }

  return {
    rules,
    report: { loaded: input.length, compiled: compiledRules, skipped, conditions: { compiled: compiledConditions, dropped: droppedConditions } },
  };
}
