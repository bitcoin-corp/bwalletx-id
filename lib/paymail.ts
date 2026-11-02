import { PAYMAIL_LOOKUP_URL } from './config';

export interface Names {
  paymail: string | null;
  handle: string | null;
}

/** Best effort: the bWalletX paymail and $handle for an identity key. Never blocks sign-in for more than 1.5 s. */
export async function lookupNames(identityKey: string, f: typeof fetch = fetch): Promise<Names> {
  try {
    const r = await f(`${PAYMAIL_LOOKUP_URL}?key=${encodeURIComponent(identityKey)}`, { signal: AbortSignal.timeout(1500) });
    if (!r.ok) return { paymail: null, handle: null };
    const j = (await r.json()) as { paymail?: unknown };
    if (typeof j.paymail === 'string' && /^[a-z0-9._-]{1,64}@[a-z0-9.-]{1,190}$/i.test(j.paymail)) {
      const paymail = j.paymail.toLowerCase();
      return { paymail, handle: '$' + paymail.split('@')[0] };
    }
  } catch {
    /* best effort */
  }
  return { paymail: null, handle: null };
}
