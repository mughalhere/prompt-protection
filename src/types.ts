export type ThreatCategory =
  | 'prompt-injection'
  | 'jailbreak'
  | 'data-exfiltration'
  | 'security-bypass'
  | 'social-engineering'
  | 'data-fishing';

export interface PatternRule {
  id: string;
  category: ThreatCategory;
  /** Always compiled with the `i` flag */
  pattern: RegExp;
  /** 1–10; higher = more diagnostic of an attack */
  weight: number;
  description: string;
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
  isMalicious: boolean;
  matches: PatternMatch[];
  /** Deduplicated list of triggered threat categories */
  categories: ThreatCategory[];
  normalizedPrompt: string;
}

export interface AnalyzeOptions {
  /** 0–100, default 35 (strict) */
  threshold?: number;
  customRules?: PatternRule[];
  disabledCategories?: ThreatCategory[];
  disabledRuleIds?: string[];
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
