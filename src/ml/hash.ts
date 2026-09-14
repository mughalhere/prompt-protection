import { fnv1a32 } from '../utils/hash.js';
import type { GramFamily } from './types.js';

/** U+0001 separates the family salt from the gram so "c3"+"abc" != "c"+"3abc". */
const FAMILY_SEP = String.fromCharCode(1);

/** Family-salted hashing trick: bucket index plus alternate sign from bit 16. */
export function bucketOf(
  family: GramFamily,
  gram: string,
  buckets: number,
): { bucket: number; sign: 1 | -1 } {
  const h = fnv1a32(family + FAMILY_SEP + gram);
  return { bucket: h % buckets, sign: (h >>> 16) & 1 ? -1 : 1 };
}
