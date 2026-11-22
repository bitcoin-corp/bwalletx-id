'use client';

/**
 * Same-phone sign-in (@bwalletx/connect 0.9.0+). bWalletX on a phone sends the user back to the ROOT of the origin the
 * relay saw (`/#bwx=ok&rid=…`), usually in a new tab, not to /signin. This finishes the pairing here, then asks the
 * wallet for the hub sign-in over that pairing and continues the site's /authorize request.
 *
 * The hub's challenge is under its own protocol (HUB_SIGNIN_PROTOCOL), which bWalletX does not fold into Connect, so
 * the sign-in approval is a second request after pairing ("Approve in bWalletX"), never a signature from the fragment.
 */
import { resumeReturnedPairing, signInWithBwalletX } from '@bwalletx/connect';
import { safeReturnTo } from '@bwalletx/connect/sso';
import { useEffect, useState } from 'react';
import { LABEL, hubChallenge, plain, takePendingSignIn, verifySignIn } from '@/lib/signin-client';

declare global {
  interface Window {
    /** The wallet's return fragment, taken off the address bar by RETURN_STRIP_SCRIPT before anything else ran. */
    __bwxReturn?: string;
  }
}

let started = false; // once per page load (React dev runs effects twice)

export default function Returned() {
  const [label, setLabel] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState('/signin');

  useEffect(() => {
    if (started) return;
    started = true;
    const hash = window.__bwxReturn;
    delete window.__bwxReturn;
    void (async () => {
      let authorize: Record<string, string> | null = null;
      try {
        // With no stashed fragment, connect falls back to the one it stripped at its own module load (if any).
        const r = await resumeReturnedPairing(hash ? { hash, href: location.href } : {});
        if (!r) return;
        authorize = takePendingSignIn();
        if (authorize) setRetry(`/signin?${new URLSearchParams(authorize)}`);
        document.querySelector<HTMLElement>('[data-home]')?.setAttribute('hidden', '');
        setLabel('Approve the sign-in in bWalletX…');
        // r.login is a folded sign-in under the shared site protocol; the hub never accepts that, so it is not used.
        const s = await signInWithBwalletX({ wallet: r.wallet, challenge: hubChallenge, onStatus: (st) => setLabel(LABEL[st]) });
        setLabel('Checking…');
        const v = await verifySignIn(s, authorize);
        setLabel(`Signed in as ${v.paymail ?? `${s.identityKey.slice(0, 8)}…`}`);
        window.location.assign(safeReturnTo(v.next, '/'));
      } catch (e) {
        document.querySelector<HTMLElement>('[data-home]')?.setAttribute('hidden', '');
        setLabel(null);
        setError(plain(e));
      }
    })();
  }, []);

  if (!label && !error) return null;
  return (
    <div className="card" data-returned>
      <h1>Finishing your sign-in</h1>
      {label && (
        <>
          <p className="lead">{label}</p>
          <p className="small">
            Not seeing it? <a href="bwalletx://open">Open bWalletX</a>
          </p>
        </>
      )}
      {error && (
        <>
          <p className="err" role="alert">
            {error}
          </p>
          <p className="small">
            <a href={retry}>Start again</a>
          </p>
        </>
      )}
    </div>
  );
}
