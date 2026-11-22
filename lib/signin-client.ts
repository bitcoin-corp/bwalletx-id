/**
 * Browser-side sign-in helpers shared by /signin and the root page (where bWalletX returns a phone, @bwalletx/connect
 * 0.9.0+). No secrets here: the hub re-checks everything it is sent.
 */
import type { Challenge, SignInResult, SignInStatus } from '@bwalletx/connect';
import { HUB_SIGNIN_PROTOCOL } from '@bwalletx/connect/sso';

export const LABEL: Record<SignInStatus, string> = {
  finding: 'Opening your wallet…',
  opening: 'Approve in bWalletX…',
  signing: 'Approve in bWalletX…',
  pairing: 'Scan the QR with bWalletX…',
};

export async function post<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
  const j = (await r.json().catch(() => ({}))) as T & { error?: string };
  if (!r.ok) throw Object.assign(new Error(j.error ?? `Request failed (${r.status})`), { stage: 'verify' });
  return j;
}

export function plain(e: unknown): string {
  const err = e as { message?: string; stage?: string; code?: string };
  const m = err?.message ?? '';
  if (err?.code === 'RETURNED_IN_ANOTHER_TAB') return 'You finished signing in in another tab.';
  if (/denied|reject|cancel|declin/i.test(m)) return 'Cancelled in bWalletX.';
  if (err?.code === 'NOT_FOUND') return 'No wallet found. Open this page in bWalletX or install the extension.';
  if (err?.stage === 'challenge') return 'Could not start the sign-in. Try again.';
  if (err?.stage === 'identity' || err?.stage === 'signature') return 'bWalletX did not finish the approval. Try again.';
  if (err?.stage === 'verify') return m || 'That signature was not accepted. Try again.';
  return 'Something went wrong. Try again.';
}

/** The hub's challenge, always under the hub's own protocol (bWalletX only accepts it from id.bwalletx.com). */
export async function hubChallenge(): Promise<Challenge> {
  return { ...(await post<{ nonce: string; message: string; keyID: string }>('/api/challenge', {})), protocolID: HUB_SIGNIN_PROTOCOL };
}

export type Verified = { next: string; paymail: string | null };

export function verifySignIn(r: Pick<SignInResult, 'identityKey' | 'nonce' | 'signature'>, authorize: Record<string, string> | null): Promise<Verified> {
  return post<Verified>('/api/verify', { identityKey: r.identityKey, nonce: r.nonce, signature: r.signature, authorize });
}

/**
 * The site's /authorize request, kept in this browser while the user is in bWalletX. On a phone bWalletX sends the
 * user back to the hub's ROOT (often in a new tab), which has lost /signin's query; the root page takes it from here.
 * Not secret (it was in the address bar) and re-checked by /api/verify. One at a time, 10 minutes, taken once.
 */
const PENDING_KEY = 'bwx_hub_signin';
const PENDING_TTL_MS = 10 * 60 * 1000;

export function savePendingSignIn(authorize: Record<string, string> | null): void {
  try {
    localStorage.setItem(PENDING_KEY, JSON.stringify({ a: authorize, at: Date.now() }));
  } catch {
    /* private mode: the return lands on the hub home instead of the site */
  }
}

export function clearPendingSignIn(): void {
  try {
    localStorage.removeItem(PENDING_KEY);
  } catch {
    /* nothing kept */
  }
}

export function takePendingSignIn(): Record<string, string> | null {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(PENDING_KEY);
    localStorage.removeItem(PENDING_KEY);
  } catch {
    return null;
  }
  try {
    const p = JSON.parse(raw ?? 'null') as { a?: unknown; at?: unknown } | null;
    if (!p || typeof p.at !== 'number' || Date.now() - p.at > PENDING_TTL_MS || !p.a || typeof p.a !== 'object') return null;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(p.a as Record<string, unknown>)) if (typeof v === 'string') out[k] = v;
    return out;
  } catch {
    return null;
  }
}
