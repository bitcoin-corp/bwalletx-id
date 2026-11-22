'use client';

import { bindPrewarm, pairingModal, signInWithBwalletX } from '@bwalletx/connect';
import { safeReturnTo } from '@bwalletx/connect/sso';
import { useEffect, useRef, useState } from 'react';
import { LABEL, clearPendingSignIn, hubChallenge, plain, savePendingSignIn, verifySignIn } from '@/lib/signin-client';

export default function SignIn({ site, authorize }: { site: string | null; authorize: Record<string, string> | null }) {
  const btn = useRef<HTMLButtonElement>(null);
  const [label, setLabel] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => (btn.current ? bindPrewarm(btn.current) : undefined), []);

  async function go() {
    setError(null);
    setLabel('Opening your wallet…'); // feedback before any await
    // On a phone bWalletX returns to the hub's root page (often a new tab), which finishes from here (app/Returned.tsx).
    savePendingSignIn(authorize);
    try {
      // ONE sheet: the challenge first (no key needed), then the identity key and the signature together.
      const r = await signInWithBwalletX({
        challenge: hubChallenge,
        pairing: pairingModal({ title: 'Sign in with bWalletX' }),
        onStatus: (s) => setLabel(LABEL[s]),
      });
      setLabel('Checking…');
      const v = await verifySignIn(r, authorize);
      clearPendingSignIn();
      setLabel(`Signed in as ${v.paymail ?? `${r.identityKey.slice(0, 8)}…`}`);
      // Same-origin path from the hub (validated there); the hub then redirects to the registered site address.
      window.location.assign(safeReturnTo(v.next, '/'));
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
