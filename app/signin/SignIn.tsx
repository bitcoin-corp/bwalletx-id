'use client';

import { bindPrewarm, pairingModal, signInWithBwalletX, type SignInStatus } from '@bwalletx/connect';
import { useEffect, useRef, useState } from 'react';

const LABEL: Record<SignInStatus, string> = {
  finding: 'Opening your wallet…',
  opening: 'Approve in bWalletX…',
  signing: 'Approve in bWalletX…',
  pairing: 'Scan the QR with bWalletX…',
};

async function post<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
  const j = (await r.json().catch(() => ({}))) as T & { error?: string };
  if (!r.ok) throw Object.assign(new Error(j.error ?? `Request failed (${r.status})`), { stage: 'verify' });
  return j;
}

function plain(e: unknown): string {
  const err = e as { message?: string; stage?: string; code?: string };
  const m = err?.message ?? '';
  if (/denied|reject|cancel|declin/i.test(m)) return 'Cancelled in bWalletX.';
  if (err?.code === 'NOT_FOUND') return 'No wallet found. Open this page in bWalletX or install the extension.';
  if (err?.stage === 'challenge') return 'Could not start the sign-in. Try again.';
  if (err?.stage === 'identity' || err?.stage === 'signature') return 'bWalletX did not finish the approval. Try again.';
  if (err?.stage === 'verify') return m || 'That signature was not accepted. Try again.';
  return 'Something went wrong. Try again.';
}

export default function SignIn({ site, authorize }: { site: string | null; authorize: Record<string, string> | null }) {
  const btn = useRef<HTMLButtonElement>(null);
  const [label, setLabel] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => (btn.current ? bindPrewarm(btn.current) : undefined), []);

  async function go() {
    setError(null);
    setLabel('Opening your wallet…'); // feedback before any await
    try {
      // ONE sheet: the challenge first (no key needed), then the identity key and the signature together.
      const r = await signInWithBwalletX({
        challenge: () => post('/api/challenge', {}),
        pairing: pairingModal({ title: 'Sign in with bWalletX' }),
        onStatus: (s) => setLabel(LABEL[s]),
      });
      setLabel('Checking…');
      const v = await post<{ next: string; paymail: string | null }>('/api/verify', {
        identityKey: r.identityKey,
        nonce: r.nonce,
        signature: r.signature,
        authorize,
      });
      setLabel(`Signed in as ${v.paymail ?? `${r.identityKey.slice(0, 8)}…`}`);
      // Same-origin path from the hub (validated there); the hub then redirects to the registered site address.
      window.location.assign(v.next.startsWith('/') && !v.next.startsWith('//') ? v.next : '/');
    } catch (e) {
      setLabel(null);
      setError(plain(e));
    }
  }

  return (
    <div className="card" data-signin>
      <h1>{site ? `Sign in to ${site}` : 'Sign in with bWalletX'}</h1>
      <p className="lead">One sign-in for every b*X site.</p>
      <p className="explain" data-explain>
        <span>
          <b>Sign in:</b> shares only your public identity key, moves no money
        </span>
      </p>
      <button ref={btn} className="btn" type="button" onClick={go} disabled={label !== null} data-signin-button>
        <span className="mark">b</span>
        {label ?? 'Sign in with bWalletX'}
      </button>
      {error && (
        <p className="err" role="alert">
          {error}
        </p>
      )}
      <p className="small">
        No wallet yet? <a href="https://bwalletx.com/get">Get bWalletX</a>
      </p>
    </div>
  );
}
