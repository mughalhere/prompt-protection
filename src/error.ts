import type { PatternMatch, PromptInjectionErrorDetails, ThreatCategory } from './types.js';

export class PromptInjectionError extends Error {
  override readonly name = 'PromptInjectionError';
  readonly score: number;
  readonly matches: PatternMatch[];
  readonly categories: ThreatCategory[];

  constructor(details: PromptInjectionErrorDetails) {
    const categoryList = details.categories.join(', ');
    super(
      `Potentially malicious prompt detected (score: ${details.score}, categories: ${categoryList})`,
    );
    this.score = details.score;
    this.matches = details.matches;
    this.categories = details.categories;
    Object.setPrototypeOf(this, PromptInjectionError.prototype);
  }
}
