const enc = new TextEncoder();

export function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export const randomToken = (bytes = 32): string => b64url(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));

/** SHA-256 as base64url. Codes and cookie tokens are stored only as this hash. */
export async function sha256(s: string): Promise<string> {
  return b64url(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', enc.encode(s))));
}

export function readCookie(header: string | null | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
