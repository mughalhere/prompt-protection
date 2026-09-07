export type ThreatCategory =
  | 'prompt-injection'
  | 'jailbreak'
  | 'data-exfiltration'
  | 'security-bypass'
  | 'social-engineering'
  | 'data-fishing'
  | 'context-smuggling'
  | 'tool-poisoning'
  | 'system-prompt-leak'
  | 'credential-leak'
  | 'injection-relay'
  | 'pii-exposure';

/** Coarse severity band derived from the 0–100 score, independent of threshold. */
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe';

/**
 * Three-way verdict for FP control.
 * - `allow` — below thresholds
 * - `flag` — reviewable / loggable, does not throw
 * - `block` — treated as malicious (`isMalicious === true`); verify throws
 */
export type Action = 'allow' | 'flag' | 'block';

/**
 * How diagnostic a rule is. Lone `low` matches can flag but cannot alone produce `block`.
 * Default when omitted: `medium`.
 */
export type RulePrecision = 'high' | 'medium' | 'low';

export interface PatternRule {
  id: string;
  category: ThreatCategory;
  /** Always compiled with the `i` flag */
  pattern: RegExp;
  /** 1–10; higher = more diagnostic of an attack */
  weight: number;
  description: string;
  /** Default `medium`. Lone `low` rules cannot alone produce `block`. */
  precision?: RulePrecision;
}

export interface PatternMatch {
  rule: PatternRule;
  matchedText: string;
  /** Position in the original (pre-normalisation) string */
  startIndex: number;
  endIndex: number;
}

export interface AnalysisResult {
  /** 0–100 normalised confidence that the prompt is malicious */
  score: number;
  severity: SeverityLevel;
  /** True only when `action === 'block'` (backward compatible) */
  isMalicious: boolean;
  /** Three-way verdict: allow / flag / block */
  action: Action;
  matches: PatternMatch[];
  /** Deduplicated list of triggered threat categories */
  categories: ThreatCategory[];
  normalizedPrompt: string;
  /** Per-sentence scores, only present when options.sentenceAnalysis is true */
  sentenceScores?: Array<{ sentence: string; score: number }>;
}

/** OpenAI / Anthropic-style chat turn. Only `role` + `content` are required. */
export interface ChatMessage {
  role: string;
  content: string;
}

/**
 * A tool / function definition, as passed to an LLM. Accepts both the OpenAI
 * shape (`parameters`) and the MCP / Anthropic shape (`inputSchema`). All fields
 * are optional so partial definitions can still be scanned.
 */
export interface ToolDefinition {
  name?: string;
  description?: string;
  /** OpenAI-style JSON schema for arguments. */
  parameters?: unknown;
  /** MCP / Anthropic-style JSON schema for arguments. */
  inputSchema?: unknown;
}

/** Plain prompt string or a chat transcript (roles are used for smarter scanning). */
export type PromptInput = string | ChatMessage[];

/**
 * Which chat roles to scan when `PromptInput` is a message array.
 * Default: `user`, `tool`, and `function` (system/assistant are skipped).
 * Pass `'all'` to score every turn.
 */
export type AnalyzeRoles = 'all' | string[];

/** Log levels that can be emitted by the protection logger. */
export type LogLevel = 'blocked' | 'flagged' | 'allowed' | 'clean';

export interface ProtectionEvent {
  type:
    | 'input.blocked'
    | 'input.flagged'
    | 'input.allowed'
    | 'output.blocked'
    | 'output.flagged'
    | 'output.clean';
  timestamp: string;
  score: number;
  action: Action;
  severity: SeverityLevel;
  categories: ThreatCategory[];
  ruleIds: string[];
  direction: 'input' | 'output';
  /** Present only when `includeContent` is true */
  promptPreview?: string;
  contentPreview?: string;
}

export interface ProtectionLogger {
  log(event: ProtectionEvent): void | Promise<void>;
}

export interface LoggingOptions {
  logger?: ProtectionLogger;
  /**
   * Which outcomes to log. Default: `['blocked', 'flagged']`
   * (does not log every allow/clean).
   */
  logLevels?: LogLevel[];
  /** When true, include a truncated content preview. Default: false */
  includeContent?: boolean;
  /** Max preview length when `includeContent` is true. Default: 200 */
  maxContentLength?: number;
  /** Called if the logger throws; never rethrown into analyze/verify */
  onLoggerError?: (err: unknown) => void;
}

export interface AnalyzeOptions extends LoggingOptions {
  /** 0–100 block cutoff, default 35 (strict) */
  threshold?: number;
  /**
   * Optional flag band: when set and `flagThreshold <= score < threshold`,
   * `action` is `'flag'` (does not throw). Omit for allow/block only (1.6 behaviour).
   */
  flagThreshold?: number;
  customRules?: PatternRule[];
  disabledCategories?: ThreatCategory[];
  disabledRuleIds?: string[];
  /**
   * Spans matching these patterns are excluded from scoring (FP control for DX jargon).
   */
  allowlistPatterns?: RegExp[];
  /**
   * Rule IDs whose matches are excluded from scoring.
   */
  allowlistRuleIds?: string[];
  /** When true, each sentence is scored independently and reported in sentenceScores */
  sentenceAnalysis?: boolean;
  /**
   * When input is a chat message array, which roles to include in scoring.
   * Default: user / tool / function.
   */
  analyzeRoles?: AnalyzeRoles;
  /**
   * Hard cap on input length (characters) scored. Longer input is truncated
   * before normalization/scoring, bounding regex work on adversarial input.
   * Default: 100_000.
   */
  maxInputLength?: number;
}

export type VerifyOptions = AnalyzeOptions;

export interface StripOptions extends AnalyzeOptions {
  /** Text to insert where malicious spans are removed. Default: "" */
  replacement?: string;
  /** If true, expands matched span to the surrounding sentence boundary. Default: false */
  stripWholeSegment?: boolean;
}

export interface AIAdapter {
  analyze(prompt: string): Promise<{ isMalicious: boolean; reason?: string }>;
}

export interface AsyncVerifyOptions extends VerifyOptions {
  adapter: AIAdapter;
  /** If adapter throws, fall back to the sync result. Default: false */
  fallbackToSync?: boolean;
}

export interface PromptInjectionErrorDetails {
  score: number;
  matches: PatternMatch[];
  categories: ThreatCategory[];
}

export interface OutputAnalysisResult {
  /** 0–100 confidence that the LLM output is compromised/suspicious */
  score: number;
  severity: SeverityLevel;
  /** True when action is `flag` or `block` */
  isSuspicious: boolean;
  /** Three-way verdict: allow / flag / block */
  action: Action;
  matches: PatternMatch[];
  /** Deduplicated list of triggered output threat categories */
  threats: ThreatCategory[];
}

export interface OutputAnalysisOptions extends LoggingOptions {
  /** 0–100 block cutoff, default 40 (higher than input to reduce false positives) */
  threshold?: number;
  /**
   * Optional flag band for output. When omitted, only allow/block (same as input 1.6 style).
   */
  flagThreshold?: number;
  customRules?: PatternRule[];
  disabledCategories?: ThreatCategory[];
  disabledRuleIds?: string[];
  allowlistPatterns?: RegExp[];
  allowlistRuleIds?: string[];
  /**
   * Hard cap on output length (characters) scored. Longer output is truncated
   * before normalization/scoring. Default: 100_000.
   */
  maxInputLength?: number;
}
