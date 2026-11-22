'use client';

/**
 * Hub sign-in v2 (docs/HUB-SIGNIN-V2.md). This page never talks to the wallet: it starts a pending sign-in (the hub
 * sets an HttpOnly cookie), shows the code, and polls. bWalletX shows the same code, and on approval signs and POSTs
 * straight to the hub. Once the hub has it, the next poll sets the hub session and the page goes on to the site.
 */
import { safeReturnTo } from '@bwalletx/connect/sso';
import { useCallback, useEffect, useRef, useState } from 'react';

type Started = { requestId: string; userCode: string; walletLink: string; interval: number; expiresAt: number };
type Polled = { status: 'pending' | 'approved' | 'expired' | 'failed'; next?: string; paymail?: string | null; identityKey?: string; userCode?: string };

async function post<T>(url: string, body: unknown): Promise<{ ok: boolean; status: number; body: T & { error?: string } }> {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
  return { ok: r.ok, status: r.status, body: (await r.json().catch(() => ({}))) as T & { error?: string } };
}

export default function SignIn({ site, authorize, resume = false }: { site: string | null; authorize: Record<string, string> | null; resume?: boolean }) {
  const [started, setStarted] = useState<Started | null>(null);
  const [code, setCode] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const active = useRef(resume);

  const check = useCallback(async () => {
    if (timer.current) clearTimeout(timer.current);
    if (!active.current) return;
    let r: Awaited<ReturnType<typeof post<Polled>>>;
    try {
      r = await post<Polled>('/api/signin/poll', {});
    } catch {
      timer.current = setTimeout(() => void check(), 4000); // offline for a moment: keep trying
      return;
    }
    if (r.status === 429) {
      timer.current = setTimeout(() => void check(), 10_000);
      return;
    }
    const p = r.body;
    if (p.status === 'approved') {
      active.current = false;
      setDone(`Signed in as ${p.paymail ?? `${(p.identityKey ?? '').slice(0, 8)}…`}`);
      window.location.assign(safeReturnTo(p.next, '/'));
      return;
    }
    if (p.status === 'pending') {
      if (p.userCode) setCode(p.userCode);
      timer.current = setTimeout(() => void check(), 2000);
      return;
    }
    active.current = false;
    setStarted(null);
    setCode(null);
    setError(
      p.status === 'failed'
        ? 'That approval was refused too many times. Start again.'
        : resume
          ? 'Nothing is waiting in this browser. Go back to the tab where you started, or start again here.'
          : 'That code has expired. Start again.',
    );
  }, [resume]);

  useEffect(() => {
    if (resume) void check();
    // Back from bWalletX: check at once instead of waiting for the next tick.
    const wake = () => document.visibilityState === 'visible' && active.current && void check();
    document.addEventListener('visibilitychange', wake);
    window.addEventListener('pageshow', wake);
    return () => {
      document.removeEventListener('visibilitychange', wake);
      window.removeEventListener('pageshow', wake);
      if (timer.current) clearTimeout(timer.current);
    };
  }, [check, resume]);

  async function start() {
    setError(null);
    setBusy(true);
    try {
      const r = await post<Started>('/api/signin/start', { authorize });
      if (!r.ok) {
        setError(r.status === 429 ? 'Too many tries. Wait a minute and start again.' : (r.body.error ?? 'Could not start the sign-in. Try again.'));
        return;
      }
      setStarted(r.body);
      setCode(r.body.userCode);
      active.current = true;
      timer.current = setTimeout(() => void check(), r.body.interval * 1000);
    } catch {
      setError('Could not reach the sign-in service. Try again.');
    } finally {
      setBusy(false);
    }
  }

  const showing = code ?? started?.userCode ?? null;
  return (
    <div className="card" data-signin>
      <h1>{site ? `Sign in to ${site}` : 'Sign in with bWalletX'}</h1>
      <p className="lead">One sign-in for every b*X site.</p>
      <p className="explain" data-explain>
        <span>
          <b>Sign in:</b> shares only your public identity key, moves no money
        </span>
      </p>
      {done ? (
        <p className="lead" role="status">{done}</p>
      ) : showing ? (
        <div data-code-panel>
          <p className="small">Approve in bWalletX when it shows this code:</p>
          <p className="code" data-user-code aria-label={`Code ${showing.split('').join(' ')}`}>
            {showing}
          </p>
          {started && (
            <a className="btn" href={started.walletLink} data-open-wallet>
              <span className="mark">b</span>Open bWalletX
            </a>
          )}
          <p className="small">
            On another device: in bWalletX, choose <b>Sign in to a b*X site</b> and enter the code. Only approve a code that this page is
            showing you now. Never approve a code someone sent you.
          </p>
          <p className="small" role="status">Waiting for bWalletX…</p>
        </div>
      ) : (
        <button className="btn" type="button" onClick={start} disabled={busy} data-signin-button>
          <span className="mark">b</span>
          {busy ? 'Starting…' : 'Sign in with bWalletX'}
        </button>
      )}
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
