/** Widens a literal union to any string while keeping literal autocomplete (TypeScript #29729). */
export type AnyString = string & Record<never, never>;

/**
 * Known threat categories. Open union: a minor release may add values, so treat an
 * unknown category as `flag` and do not switch exhaustively. See docs/API_STABILITY.md.
 */
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
  | 'pii-exposure'
  | 'data-flow'
  | AnyString;

/** Coarse severity band derived from the 0–100 score, independent of threshold. */
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe';

/**
 * Three-way verdict for FP control.
 * - `allow`: below thresholds
 * - `flag`: reviewable / loggable, does not throw
 * - `block`: treated as malicious (`isMalicious === true`); verify throws
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
  /** Framework identifiers this rule maps to (ATR / OWASP / ATLAS). Ids only, never prose. */
  mappings?: RuleMappings;
  /** Present when the rule was compiled from an external rule format. */
  origin?: RuleOrigin;
}

export interface RuleMappings {
  atr?: string[];
  owaspLlm?: string[];
  owaspAsi?: string[];
  owaspAst?: string[];
  atlas?: string[];
  attack?: string[];
  cve?: string[];
}

export interface RuleOrigin {
  format: 'atr';
  ruleId: string;
  ruleVersion?: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  tags: { category: string; subcategory?: string; confidence?: RulePrecision; scan_target?: 'mcp' | 'skill' | 'runtime' };
  conditionIndex: number;
  conditionCount: number;
  field: string;
  operator: string;
}

export interface PatternMatch {
  rule: PatternRule;
  matchedText: string;
  /** Position in the original (pre-normalisation) string */
  startIndex: number;
  endIndex: number;
}

/** What to do when the library itself throws: block (default) or let the input through. */
export type FailMode = 'closed' | 'open';

export interface AnalysisError {
  code: 'internal-error';
  message: string;
}

/** Compact description of one provenance flow, safe for logs (no argument values). */
export interface FlowSummary {
  kind: 'exact' | 'identifier' | 'content' | AnyString; // mirrors guard FlowKind (open)
  sourceId: string;
  sourceTool: string;
  path: string;
  strength: number;
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
  /** Set when analysis itself failed and the verdict came from `failMode`. */
  error?: AnalysisError;
  /** Embedded-classifier verdict; absent when no model is wired or `ml: 'off'`. */
  ml?: MlContribution;
}

/** How the embedded classifier affected the final action. */
export interface MlContribution {
  /** Model probability that the input is an injection, 0–1. */
  probability: number;
  contributed: 'none' | 'escalated' | 'flagged' | 'downgraded';
}

/**
 * Embedded-classifier fusion mode. `escalate` (default) may only raise the
 * action; `hybrid` may also downgrade weak rules-only blocks; `off` skips the
 * model entirely (rules-only, same as the `lite` entry).
 */
export type MlMode = 'off' | 'escalate' | 'hybrid';

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
    | 'output.clean'
    | 'tool-call.blocked'
    | 'tool-call.flagged'
    | 'tool-call.allowed'
    | AnyString; // open union, see ThreatCategory
  timestamp: string;
  score: number;
  action: Action;
  severity: SeverityLevel;
  categories: ThreatCategory[];
  ruleIds: string[];
  direction: 'input' | 'output' | 'tool-call' | AnyString;
  /** Tool name for `tool-call.*` events. */
  toolName?: string;
  toolCallId?: string;
  /** Guard policy that decided a `tool-call.*` event, and every policy that fired. */
  policy?: string;
  reasons?: string[];
  sink?: string;
  flows?: FlowSummary[];
  /** Present when the verdict came from `failMode` after an internal error. */
  error?: string;
  /** `observe` when the guard recorded the verdict without enforcing it; `action` is then `allow`. */
  mode?: 'enforce' | 'observe' | AnyString;
  /** The enforced verdict a `tool-call.*` event would have had in observe mode. */
  observedAction?: Action;
  /** Present only when `includeContent` is true */
  promptPreview?: string;
  contentPreview?: string;
}

export interface ProtectionLogger {
  log(event: ProtectionEvent): void | Promise<void>;
  /**
   * Optional: receives the raw scanned content alongside the event so a sink can
   * hash it itself. Called instead of `log` when present. Raw text never reaches `log`.
   */
  logWithContent?(event: ProtectionEvent, content: string): void | Promise<void>;
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
  /** Embedded-classifier fusion mode. Default `'escalate'`; ignored by the `lite` entry. */
  ml?: MlMode;
  /** Verdict when analysis throws internally. Default `'closed'` → block. */
  failMode?: FailMode;
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
  /** @deprecated Use `failMode: 'open'`. Kept as an alias. */
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
  /** Present only when `canary` or `systemPrompt` was passed. */
  canary?: CanaryDetection;
  /** Present when `renderAllowlist` was passed: URLs the output would render or link, with their verdicts. */
  render?: RenderFinding[];
  /** Output with secrets / PII replaced; present only when `redact` was set. */
  redacted?: string;
  redactions?: Array<{ id: string; tier: 'secrets' | 'pii'; start: number; end: number }>;
  /** Set when the scan itself failed and the verdict came from `failMode`. */
  error?: AnalysisError;
}

export interface RenderFinding {
  url: string;
  host: string;
  /** Where the URL appeared. */
  via: 'markdown-image' | 'markdown-link' | 'html-src' | 'html-href' | 'data-uri';
  allowed: boolean;
  /** Query parameters that looked like carried data. */
  suspiciousParams?: Array<{ name: string; reason: 'high-entropy' | 'conversation' }>;
}

export interface OutputAnalysisOptions extends LoggingOptions {
  /** 0–100 block cutoff, default 40 (higher than input to reduce false positives) */
  threshold?: number;
  /** Verdict when the scan throws internally. Default `'closed'` → block. */
  failMode?: FailMode;
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
  /** Canary token(s) injected into the system prompt; a leak adds `out-canary-leak`. */
  canary?: Canary | Canary[];
  /** System prompt to compare against; verbatim overlap adds `out-system-prompt-similarity`. */
  systemPrompt?: string;
  /**
   * Hosts the client may render or link to (`example.com`, `*.example.com`). When set, markdown
   * images/links and HTML `src`/`href` to any other host add `out-render-unlisted-host`, `data:` URLs
   * add `out-data-uri-exfil`, and query parameters carrying high-entropy or conversation-derived
   * values add `out-query-param-high-entropy` / `out-query-param-conversation`. Off when absent.
   */
  renderAllowlist?: string[];
  /** Conversation text (user turns, tool results) that a URL query parameter must not carry. */
  conversation?: string;
  /** Redact secrets / PII in the returned `redacted` text. Default off. */
  redact?: false | 'secrets' | 'pii' | 'all';
}

export interface Canary {
  /** Full token as injected, e.g. `pp-3f9a…`. */
  token: string;
  /** Random part of the token (used for partial matching). */
  secret: string;
  prefix: string;
}

export type CanaryVariant =
  | 'exact'
  | 'normalized'
  | 'spaced'
  | 'base64'
  | 'hex'
  | 'reversed'
  | 'partial';

export interface PromptSimilarity {
  /** Fraction of system-prompt word shingles found in the output (0–1). */
  containment: number;
  /** Longest run of consecutive system-prompt shingles present in the output. */
  longestRun: number;
}

export interface CanaryDetection {
  leaked: boolean;
  /** 0–1; max over detected variants, 0 when nothing leaked. */
  confidence: number;
  variants: CanaryVariant[];
  /** Set when `systemPrompt` was supplied. */
  promptSimilarity?: PromptSimilarity;
}
