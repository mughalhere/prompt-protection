const BASE64_RE = /[A-Za-z0-9+/]{20,}={0,2}/g;
const PERCENT_RE = /%[0-9A-Fa-f]{2}/g;

const MAX_DECODE_PASSES = 3;
const MAX_DECODED_LENGTH = 50_000;

function tryBase64Decode(segment: string): string | null {
  try {
    const decoded = atob(segment);
    if (/^[\x20-\x7E]+$/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

function tryPercentDecode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

function decodeOnce(text: string): { text: string; changed: boolean } {
  let changed = false;

  let result = text.replace(PERCENT_RE, (match) => {
    const decoded = tryPercentDecode(match);
    if (decoded !== match) changed = true;
    return decoded;
  });

  const extraDecoded: string[] = [];
  result.replace(BASE64_RE, (match) => {
    const decoded = tryBase64Decode(match);
    if (decoded !== null) {
      extraDecoded.push(decoded);
      changed = true;
    }
    return match;
  });

  if (extraDecoded.length > 0) {
    result = result + ' ' + extraDecoded.join(' ');
  }

  if (result.length > MAX_DECODED_LENGTH) {
    result = result.slice(0, MAX_DECODED_LENGTH);
  }

  return { text: result, changed };
}

/**
 * Decodes URL percent-encoding and appends decoded base64 segments.
 * Runs up to {@link MAX_DECODE_PASSES} passes to catch nested encodings.
 * Returns the expanded text for scoring (not for display).
 */
export function decodeObfuscation(text: string): string {
  let result = text;

  for (let pass = 0; pass < MAX_DECODE_PASSES; pass++) {
    const { text: next, changed } = decodeOnce(result);
    result = next;
    if (!changed) break;
  }

  return result;
}
