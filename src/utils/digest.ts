// Kept as a path so audit.ts and the adapters are untouched; the implementation lives in canonical.ts.
export { canonicalJson, digest, fnv1a64Hex, digestSyncWeak, CanonicalJsonError } from './canonical.js';
export type { CanonicalJsonErrorCode } from './canonical.js';
