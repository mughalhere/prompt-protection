const HEX = '0123456789abcdef';

/** `length` random lowercase hex chars from the platform CSPRNG (Node ≥20 and browsers). */
export function randomHex(length: number): string {
  const bytes = new Uint8Array(Math.ceil(length / 2));
  globalThis.crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] as number;
    out += HEX.charAt(b >> 4) + HEX.charAt(b & 15);
  }
  return out.slice(0, length);
}
