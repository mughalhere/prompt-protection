import type { PatternRule, RulePrecision, ThreatCategory } from '../types.js';

export type AtrSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type AtrScanTarget = 'mcp' | 'skill' | 'runtime';
export type AtrStatus = 'draft' | 'experimental' | 'stable' | 'deprecated';
export type AtrMaturity = 'experimental' | 'test' | 'stable' | 'deprecated';
export type AtrOperator = 'regex' | 'contains' | 'exact' | 'starts_with';
export type AtrField = 'content' | 'tool_name' | 'tool_args' | 'tool_response' | 'user_input' | 'agent_output';

export type AtrSourceType =
  | 'llm_io'
  | 'tool_call'
  | 'tool_response'
  | 'mcp_exchange'
  | 'agent_behavior'
  | 'multi_agent_comm'
  | 'context_window'
  | 'memory_access'
  | 'skill_lifecycle'
  | 'skill_permission'
  | 'skill_chain';

/** Input event types an engine evaluates (spec §5.1). */
export type AtrEventType =
  | 'llm_input'
  | 'llm_output'
  | 'tool_call'
  | 'tool_response'
  | 'mcp_exchange'
  | 'agent_behavior'
  | 'multi_agent_message'
  | 'skill_file';

/** `enforce` = stable maturity only; `hunt` = everything non-draft (spec lanes). */
export type AtrLane = 'enforce' | 'alert' | 'hunt';

export interface AtrCondition {
  field?: string;
  operator?: string;
  value?: string;
  description?: string;
  // Named-format members; their presence marks a condition we cannot compile.
  patterns?: string[];
  match_type?: string;
  metric?: string;
  threshold?: number;
  steps?: unknown[];
}

export interface AtrReferences {
  owasp_llm?: string[];
  owasp_agentic?: string[];
  owasp_ast?: string[];
  mitre_atlas?: string[];
  mitre_attack?: string[];
  cve?: string[];
}

export interface AtrTestCases {
  true_positives?: Array<{ input: string; description?: string }>;
  true_negatives?: Array<{ input: string; description?: string }>;
}

export interface AtrRule {
  id: string;
  title: string;
  status: AtrStatus;
  severity: AtrSeverity;
  description?: string;
  maturity?: AtrMaturity;
  rule_version?: number;
  schema_version?: string;
  tags: { category: string; subcategory?: string; confidence?: RulePrecision; scan_target?: AtrScanTarget };
  agent_source?: { type: AtrSourceType; framework?: string[]; provider?: string[] };
  detection: { condition?: string; conditions: AtrCondition[] | Record<string, AtrCondition> };
  references?: AtrReferences;
  test_cases?: AtrTestCases;
}

export type AtrSkipReason =
  | 'invalid-rule'
  | 'draft-or-deprecated'
  | 'scan-target-mismatch'
  | 'agent-source-mismatch'
  | 'lane-excluded'
  | 'named-conditions-unsupported'
  | 'and-conditions-unsupported'
  | 'field-not-applicable'
  | 'unsupported-operator'
  | 'unsupported-syntax'
  | 'invalid-regex';

export interface AtrLoadOptions {
  /** Keep rules whose `tags.scan_target` is absent or equal to this. */
  scanTarget?: AtrScanTarget;
  /** Keep rules whose `agent_source.type` is compatible with this event type (spec §5.1). */
  agentSource?: AtrEventType;
  /** Condition fields to compile; others are dropped with `field-not-applicable`. Default content + user_input. */
  fields?: readonly string[];
  /** `enforce` keeps stable-maturity rules only. Default `hunt`. */
  lane?: AtrLane;
  /** Compile `draft` rules too (spec says skip). Default false. */
  includeDraft?: boolean;
  categoryMap?: Partial<Record<string, ThreatCategory>>;
  weightFor?: (rule: AtrRule) => number;
  precisionFor?: (rule: AtrRule) => RulePrecision;
}

export interface AtrSkip {
  rule_id: string;
  reason: AtrSkipReason;
  detail?: string;
}

export interface AtrLoadReport {
  /** Rules seen in the input. */
  loaded: number;
  /** Rules that produced at least one compiled condition. */
  compiled: number;
  skipped: AtrSkip[];
  conditions: { compiled: number; dropped: number };
}

export interface AtrLoadResult {
  rules: PatternRule[];
  report: AtrLoadReport;
}

export interface AtrFinding {
  rule_id: string;
  severity: AtrSeverity;
  confidence: number;
  matched: boolean;
  matched_conditions: number[];
  matched_patterns: string[];
  title?: string;
  tags?: AtrRule['tags'];
  scan_target?: AtrScanTarget;
  references?: AtrReferences;
}

export interface AtrScanResult {
  scan_type: AtrScanTarget;
  content_hash?: string;
  timestamp: string;
  rules_loaded: number;
  matches: AtrFinding[];
  threat_count: number;
  engine: { name: 'prompt-protection'; version: string; rules_version: string };
}
