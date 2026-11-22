import { cookies } from 'next/headers';
import { getHub } from '@/lib/instance';
import Returned from './Returned';

export const dynamic = 'force-dynamic';

export default async function Home() {
  return (
    <>
      {/* bWalletX returns a phone here; the layout's head script has already taken #bwx=ok&… off the address bar. */}
      <Returned />
      <div data-home style={{ display: 'contents' }}>
        <HomeCard />
      </div>
    </>
  );
}

async function HomeCard() {
  const hub = await getHub();
  const jar = await cookies();
  const header = jar.getAll().map((c) => `${c.name}=${c.value}`).join('; ');
  const s = await hub.currentSession(new Request('http://hub/', { headers: { cookie: header } }));
  if (!s) {
    return (
      <div className="card">
        <h1>One sign-in for every b*X site</h1>
        <p className="lead">Sign in once with bWalletX and every b*X site knows it is you. Signing in shares only your public identity key and moves no money.</p>
        <a className="btn" href="/signin">
          <span className="mark">b</span>Sign in with bWalletX
        </a>
        <p className="small">
          No wallet yet? <a href="https://bwalletx.com/get">Get bWalletX</a>
        </p>
      </div>
    );
  }
  const name = s.paymail ?? `${s.identityKey.slice(0, 8)}…${s.identityKey.slice(-6)}`;
  return (
    <div className="card">
      <h1>Signed in as {name}</h1>
      <p className="lead">Every b*X site you open will know it is you. Signing out here signs you out of all of them.</p>
      <p className="key">{s.identityKey}</p>
      <div className="row">
        <a className="btn ghost" href="/account/api-keys">API keys</a>
        <a className="btn" href="/logout">Sign out of all b*X sites</a>
      </div>
    </div>
  );
}
