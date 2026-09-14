import { normalize } from './normalizer.js';
import { score } from './scorer.js';
import { TOOL_RULES } from './patterns/index.js';
import { resolveAction } from './verdict.js';
import { emitInputLog } from './logging.js';
import { mlClassifier } from './ml/index.js';
import {
  DEFAULT_THRESHOLD,
  analyzePromptWith,
  buildRuleSet,
  capLength,
  computeSeverity,
  stripPromptWith,
  verifyPromptWith,
} from './core/analyze.js';
import type { AnalysisResult, AnalyzeOptions, ThreatCategory, ToolDefinition } from './types.js';

export { computeSeverity };

export const analyzePrompt = analyzePromptWith(mlClassifier);
export const verifyPrompt = verifyPromptWith(analyzePrompt);
export const stripPrompt = stripPromptWith(analyzePrompt);

/** Flattens the human-readable fields of a tool definition into one scannable string. */
function flattenToolDefinition(tool: ToolDefinition): string {
  const parts: string[] = [];
  if (tool.name) parts.push(tool.name);
  if (tool.description) parts.push(tool.description);
  const schema = tool.parameters ?? tool.inputSchema;
  if (schema !== undefined) {
    try {
      parts.push(JSON.stringify(schema));
    } catch {
      /* circular or non-serialisable schema — skip it */
    }
  }
  return parts.join('\n');
}

/**
 * Scans a tool / function **definition** (name, description, parameter schema)
 * for poisoning — hidden instructions, concealment directives, exfiltration, and
 * injection embedded in tool metadata that an agent reads but the user never
 * sees. Uses the tool-poisoning rule set plus injection/exfiltration rules.
 *
 * Custom rules and allowlists from `options` still apply; the default rule set is
 * `TOOL_RULES` rather than the full input set.
 */
export function scanToolDefinition(
  tool: ToolDefinition,
  options: AnalyzeOptions = {},
): AnalysisResult {
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const rules = buildRuleSet(options, TOOL_RULES);

  const text = capLength(flattenToolDefinition(tool), options.maxInputLength);
  const { normalized, indexMap } = normalize(text);
  const { normalizedScore, matches } = score(rules, normalized, text, {
    indexMap,
    ...(options.allowlistPatterns ? { allowlistPatterns: options.allowlistPatterns } : {}),
    ...(options.allowlistRuleIds ? { allowlistRuleIds: options.allowlistRuleIds } : {}),
  });

  const categories = [...new Set(matches.map((m) => m.rule.category))] as ThreatCategory[];
  const action = resolveAction(normalizedScore, matches, threshold, options.flagThreshold);

  const result: AnalysisResult = {
    score: normalizedScore,
    severity: computeSeverity(normalizedScore),
    isMalicious: action === 'block',
    action,
    matches,
    categories,
    normalizedPrompt: normalized,
  };

  emitInputLog(result, text, options);

  return result;
}
