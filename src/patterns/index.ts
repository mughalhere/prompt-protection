import { injectionRules } from './injection.js';
import { jailbreakRules } from './jailbreak.js';
import { exfiltrationRules } from './exfiltration.js';
import { bypassRules } from './bypass.js';
import { socialEngineeringRules } from './social-engineering.js';
import { dataFishingRules } from './data-fishing.js';
import { contextSmugglingRules } from './context-smuggling.js';
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
];

export const OUTPUT_RULES: PatternRule[] = [...outputRules];

export {
  injectionRules,
  jailbreakRules,
  exfiltrationRules,
  bypassRules,
  socialEngineeringRules,
  dataFishingRules,
  contextSmugglingRules,
  outputRules,
};
