import { injectionRules } from './injection.js';
import { jailbreakRules } from './jailbreak.js';
import { exfiltrationRules } from './exfiltration.js';
import { bypassRules } from './bypass.js';
import { socialEngineeringRules } from './social-engineering.js';
import { dataFishingRules } from './data-fishing.js';
import { contextSmugglingRules } from './context-smuggling.js';
import { toolPoisoningRules } from './tool-poisoning.js';
import { outputRules } from './output.js';
import type { PatternRule } from '../types.js';

export const ALL_RULES: PatternRule[] = [
  ...injectionRules,
  ...jailbreakRules,
  ...exfiltrationRules,
  ...bypassRules,
  ...socialEngineeringRules,
  ...dataFishingRules,
  ...contextSmugglingRules,
  ...toolPoisoningRules,
];

export const OUTPUT_RULES: PatternRule[] = [...outputRules];

/**
 * Rules used when scanning a tool/function *definition* (`scanToolDefinition`):
 * the tool-poisoning set plus the injection and exfiltration rules, which also
 * fire on hostile tool metadata.
 */
export const TOOL_RULES: PatternRule[] = [
  ...toolPoisoningRules,
  ...injectionRules,
  ...exfiltrationRules,
];

export {
  injectionRules,
  jailbreakRules,
  exfiltrationRules,
  bypassRules,
  socialEngineeringRules,
  dataFishingRules,
  contextSmugglingRules,
  toolPoisoningRules,
  outputRules,
};

export { DEFERRED_REFERENCE_RULE_IDS } from './injection.js';
