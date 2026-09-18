/**
 * @packageDocumentation
 * @beta Preview tier: may change in a minor release. See docs/API_STABILITY.md.
 */
export { loadAtrRules, referencesToMappings, DEFAULT_CATEGORY_MAP, ATR_ID_PREFIX } from './load.js';
export { toAtrFindings, ENGINE_VERSION } from './findings.js';
export type { ToAtrFindingsOptions } from './findings.js';
export { compileCondition, escapeRegExp, isSupportedOperator } from './compile.js';
export type { CompileOutcome } from './compile.js';
export { AGENT_SOURCE_COMPAT, sourceCompatible } from './compat.js';
export { RULES_VERSION } from '../patterns/version.js';
export { RULE_MAPPINGS, withMappings } from '../patterns/mappings.js';
export type * from './types.js';
