const BASE64_RE = /[A-Za-z0-9+/]{20,}={0,2}/g;
const PERCENT_RE = /%[0-9A-Fa-f]{2}/g;

function tryBase64Decode(segment: string): string | null {
  try {
    // atob is available in both browsers and Node 16+
    const decoded = atob(segment);
    // Only keep it if it decodes to printable ASCII
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

/**
 * Decodes URL percent-encoding and appends decoded base64 segments.
 * Returns the expanded text for scoring (not for display).
 */
export function decodeObfuscation(text: string): string {
  // 1. URL percent-decode
  let result = text.replace(PERCENT_RE, (match) => tryPercentDecode(match));

  // 2. Base64: find candidate segments and append decoded text
  const extraDecoded: string[] = [];
  result.replace(BASE64_RE, (match) => {
    const decoded = tryBase64Decode(match);
    if (decoded !== null) {
      extraDecoded.push(decoded);
    }
    return match;
  });

  if (extraDecoded.length > 0) {
    result = result + ' ' + extraDecoded.join(' ');
  }

  return result;
}
