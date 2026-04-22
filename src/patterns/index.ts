import { injectionRules } from './injection.js';
import { jailbreakRules } from './jailbreak.js';
import { exfiltrationRules } from './exfiltration.js';
import { bypassRules } from './bypass.js';
import { socialEngineeringRules } from './social-engineering.js';
import { dataFishingRules } from './data-fishing.js';
import type { PatternRule } from '../types.js';

export const ALL_RULES: PatternRule[] = [
  ...injectionRules,
  ...jailbreakRules,
  ...exfiltrationRules,
  ...bypassRules,
  ...socialEngineeringRules,
  ...dataFishingRules,
];

export {
  injectionRules,
  jailbreakRules,
  exfiltrationRules,
  bypassRules,
  socialEngineeringRules,
  dataFishingRules,
};
