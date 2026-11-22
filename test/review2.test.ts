/**
 * Security review round 2 (22 Nov 2026), hub side. Written before the fixes.
 *   HIGH-1  sign-in v2: the wallet POSTs straight to the hub, bound to a pending sign-in the browser holds as a
 *           __Host- HttpOnly cookie and a user code shown on both screens; the page polls. No page-delivered signature.
 *   MED-1   client auth on /token and /session/epoch; per-client limits; the IP bucket counts failures only
 *   MED-2   authenticated, batched epoch calls; the per-key limit only for unauthenticated callers
 *   LOWs    logout hint = HMAC per client; Sec-Fetch-Site on the hub's logout POST
 */
import { PrivateKey } from '@bsv/sdk';
import { HUB_SIGNIN_PROTOCOL, clientBasicAuth, hubSignInMessage, isHubUserCode, logoutHint } from '@bwalletx/connect/sso';
import { describe, expect, it } from 'vitest';
import { clientSecret } from '@/lib/clients';
import {
  CALLBACK,
  CLIENT_KEY,
  ISSUER,
  SHARED_LOGIN,
  codeFor,
  pkce,
  poll,
  rig,
  secretFor,
  signIn,
  signature,
  startSignIn,
  tokenReq,
  walletApprove,
  walletInfo,
  type StoreKind,
} from './helpers';
import { randomToken } from '@bwalletx/connect/sso';

describe.each<StoreKind>(['memory', 'postgres'])('review 2 (%s store)', (kind) => {
  describe('HIGH-1: sign-in v2', () => {
    it('start: same-origin only; a __Host- HttpOnly cookie holds the pending sign-in; the page gets the code and a wallet link', async () => {
      const { hub } = await rig(kind);
      const s = await startSignIn(hub);
      expect(s.res.status).toBe(200);
      const set = s.res.headers.get('set-cookie')!;
      expect(set).toMatch(/^__Host-bwx_signin=[A-Za-z0-9_-]{43};/);
      for (const a of [/HttpOnly/, /Secure/, /SameSite=Lax/, /Path=\//, /Max-Age=300/]) expect(set).toMatch(a);
      expect(set).not.toMatch(/Domain=/i);
      expect(isHubUserCode(s.body.userCode)).toBe(true);
      expect(s.body.walletLink).toBe(`bwalletx://hub-signin?r=${s.body.requestId}`);
      expect(s.body.interval).toBeGreaterThanOrEqual(2);
      // the browser secret is never in the body
      expect(JSON.stringify(s.body)).not.toContain(s.cookie.split('=')[1]);
      expect((await startSignIn(hub, undefined, { origin: 'https://evil.example' })).res.status).toBe(403);
      expect((await startSignIn(hub, undefined, { 'sec-fetch-site': 'same-site' })).res.status).toBe(403);
    });

    it('start refuses an /authorize request that is not registered', async () => {
      const { hub } = await rig(kind);
      const p = await pkce();
      const bad = { client_id: 'site', redirect_uri: 'https://evil.example/cb', state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256' };
      expect((await startSignIn(hub, bad)).res.status).toBe(400);
    });

    it('the wallet looks the request up by id or by code: hub, site, code and the exact message to sign', async () => {
      const { hub } = await rig(kind);
      const p = await pkce();
      const authorize = { client_id: 'site', redirect_uri: CALLBACK, state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256', response_type: 'code' };
      const s = await startSignIn(hub, authorize);
      for (const q of [`r=${s.body.requestId}`, `code=${s.body.userCode}`]) {
        const info = await walletInfo(hub, q);
        expect(info.status).toBe(200);
        const j = info.body!;
        expect(j).toMatchObject({ requestId: s.body.requestId, userCode: s.body.userCode, hub: ISSUER, site: { clientId: 'site', name: 'Site' }, keyID: s.body.requestId });
        expect(j.protocolID).toEqual(HUB_SIGNIN_PROTOCOL);
        expect(j.message).toBe(hubSignInMessage({ hub: ISSUER, requestId: s.body.requestId, userCode: s.body.userCode, clientId: 'site', issuedAt: j.issuedAt }));
      }
      expect((await walletInfo(hub, 'r=' + 'x'.repeat(22))).status).toBe(404);
      expect((await walletInfo(hub, 'code=BCDF-GHJK')).status).toBe(404);
    });

    it('approve → poll: only the browser that started it gets the hub session; it works once', async () => {
      const { hub } = await rig(kind);
      const root = PrivateKey.fromRandom();
      const s = await startSignIn(hub);
      expect((await poll(hub, s.cookie)).body.status).toBe('pending');
      const ok = await walletApprove(hub, s.body.requestId, root);
      expect(ok.status).toBe(200);
      // another browser (no cookie, or its own pending sign-in) gets nothing
      expect((await poll(hub, '')).body.status).toBe('expired');
      const other = await startSignIn(hub);
      expect((await poll(hub, other.cookie)).body.status).toBe('pending');
      const done = await poll(hub, s.cookie);
      expect(done.body).toMatchObject({ status: 'approved', next: '/', identityKey: root.toPublicKey().toString() });
      const cookies = done.res.headers.getSetCookie();
      expect(cookies.some((c) => /^__Host-bwx_hub=[A-Za-z0-9_-]{43};/.test(c) && /HttpOnly/.test(c))).toBe(true);
      expect(cookies.some((c) => /^__Host-bwx_signin=;/.test(c) && /Max-Age=0/.test(c))).toBe(true);
      expect((await poll(hub, s.cookie)).body.status).toBe('expired'); // used
    });

    it('poll is same-origin only', async () => {
      const { hub } = await rig(kind);
      const s = await startSignIn(hub);
      expect((await poll(hub, s.cookie, { origin: 'https://evil.example' })).res.status).toBe(403);
    });

    it('a signature the hub never asked the wallet for is refused: wrong protocol (shared site or the old v1 name), wrong key, wrong message', async () => {
      const { hub } = await rig(kind);
      const root = PrivateKey.fromRandom();
      const s = await startSignIn(hub);
      const info = (await walletInfo(hub, `r=${s.body.requestId}`)).body!;
      const id = root.toPublicKey().toString();
      const tries = [
        { identityKey: id, signature: await signature(root, info.message, info.keyID, SHARED_LOGIN) },
        { identityKey: id, signature: await signature(root, info.message, info.keyID, [2, 'bwalletx id sign in']) },
        { identityKey: id, signature: await signature(PrivateKey.fromRandom(), info.message, info.keyID) },
        { identityKey: id, signature: await signature(root, info.message + 'x', info.keyID) },
        { identityKey: id, signature: await signature(root, info.message, 'another-key-id-000000') },
      ];
      for (const t of tries) expect((await walletApprove(hub, s.body.requestId, root, t)).status).toBe(401);
      expect((await poll(hub, s.cookie)).body.status).toBe('failed'); // 5 bad attempts: dead
      expect((await walletApprove(hub, s.body.requestId, root)).status).toBe(409);
    });

    it('the user code must match (constant-time compare)', async () => {
      const { hub } = await rig(kind);
      const s = await startSignIn(hub);
      const root = PrivateKey.fromRandom();
      expect((await walletApprove(hub, s.body.requestId, root, { userCode: s.body.userCode === 'BCDF-GHJK' ? 'BCDF-GHJL' : 'BCDF-GHJK' })).status).toBe(401);
      expect((await walletApprove(hub, s.body.requestId, root)).status).toBe(200);
    });

    it('a request expires after 5 minutes; a second approval is refused', async () => {
      const { hub, clock } = await rig(kind);
      const s = await startSignIn(hub);
      const root = PrivateKey.fromRandom();
      const s2 = await startSignIn(hub);
      expect((await walletApprove(hub, s2.body.requestId, root)).status).toBe(200);
      expect((await walletApprove(hub, s2.body.requestId, root)).status).toBe(409);
      clock.t += 301_000;
      expect((await walletApprove(hub, s.body.requestId, root)).status).toBe(410);
      expect((await poll(hub, s.cookie)).body.status).toBe('expired');
      expect((await poll(hub, s2.cookie)).body.status).toBe('expired'); // approved but never collected in time
    });

    it('the wallet endpoint refuses web pages (an http(s) Origin) unless that origin is an allowed wallet origin', async () => {
      const { hub } = await rig(kind, undefined, undefined, { walletOrigins: ['https://web.bwalletx.com'] });
      const root = PrivateKey.fromRandom();
      const a = await startSignIn(hub);
      expect((await walletApprove(hub, a.body.requestId, root, {}, { origin: 'https://evil.example' })).status).toBe(403);
      expect((await walletApprove(hub, a.body.requestId, root, {}, { origin: 'null' })).status).toBe(403);
      expect((await walletApprove(hub, a.body.requestId, root, {}, { origin: 'chrome-extension://abcdefghijklmnop' })).status).toBe(200);
      const b = await startSignIn(hub);
      expect((await walletApprove(hub, b.body.requestId, root, {}, { origin: 'https://web.bwalletx.com' })).status).toBe(200);
      const c = await startSignIn(hub);
      expect((await walletApprove(hub, c.body.requestId, root)).status).toBe(200); // native app: no Origin
    });

    it('the page-delivered sign-in (v1 /api/challenge + /api/verify) is gone', async () => {
      const { hub } = await rig(kind);
      expect('verify' in hub).toBe(false);
      expect('challenge' in hub).toBe(false);
    });

    it('a sign-in for a site continues to /authorize (prompt dropped); the message names the site', async () => {
      const { hub } = await rig(kind);
      const p = await pkce();
      const authorize = { client_id: 'site', redirect_uri: CALLBACK, state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256', prompt: 'login' };
      const { body } = await signIn(hub, PrivateKey.fromRandom(), authorize);
      const next = new URL(body.next, ISSUER);
      expect(next.pathname).toBe('/authorize');
      expect(next.searchParams.get('client_id')).toBe('site');
      expect(next.searchParams.get('prompt')).toBeNull();
    });
  });

  describe('MED-1: client auth and limits', () => {
    it('/token needs the client secret (Basic or client_secret_post); a wrong or another client’s secret is refused', async () => {
      const { hub } = await rig(kind);
      const body = async () => {
        const { code, verifier } = await codeFor(hub);
        return { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK };
      };
      expect((await hub.token(tokenReq(await body(), { auth: 'none' }))).status).toBe(401);
      expect((await hub.token(tokenReq(await body(), { auth: 'basic' }))).status).toBe(200);
      expect((await hub.token(tokenReq(await body(), { auth: 'post' }))).status).toBe(200);
      const wrong = await hub.token(tokenReq(await body(), { authHeader: clientBasicAuth('site', 'w'.repeat(43)) }));
      expect(wrong.status).toBe(401);
      expect(((await wrong.json()) as { error: string }).error).toBe('invalid_client');
      expect((await hub.token(tokenReq(await body(), { authHeader: clientBasicAuth('vault', await secretFor('vault')) }))).status).toBe(401);
    });

    it('client secrets are derived per client and version from the hub key (no secret in git)', async () => {
      const a = await clientSecret(CLIENT_KEY, { client_id: 'site' });
      expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(await clientSecret(CLIENT_KEY, { client_id: 'site' })).toBe(a);
      expect(await clientSecret(CLIENT_KEY, { client_id: 'vault' })).not.toBe(a);
      expect(await clientSecret(CLIENT_KEY, { client_id: 'site', secret_version: 2 })).not.toBe(a);
      expect(await clientSecret('z'.repeat(40), { client_id: 'site' })).not.toBe(a);
      await expect(clientSecret('short', { client_id: 'site' })).rejects.toThrow();
    });

    it('the per-IP bucket on /token counts failed attempts only; good exchanges from a busy shared IP all pass', async () => {
      const { hub } = await rig(kind, undefined, { token: 3 });
      for (let i = 0; i < 6; i++) {
        const { code, verifier } = await codeFor(hub);
        expect((await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }))).status).toBe(200);
      }
      for (let i = 0; i < 3; i++) expect((await hub.token(tokenReq({ grant_type: 'authorization_code', code: 'nope', code_verifier: 'v'.repeat(43), client_id: 'site', redirect_uri: CALLBACK }))).status).toBe(400);
      const { code, verifier } = await codeFor(hub);
      const r = await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }));
      expect(r.status).toBe(429);
      expect(r.headers.get('retry-after')).toBeTruthy();
      // another IP is fine
      const c2 = await codeFor(hub);
      expect((await hub.token(tokenReq({ grant_type: 'authorization_code', code: c2.code, code_verifier: c2.verifier, client_id: 'site', redirect_uri: CALLBACK }, { ip: '203.0.113.9' }))).status).toBe(200);
    });

    it('per-client limits on /token and /session/epoch (across IPs)', async () => {
      const { hub } = await rig(kind, undefined, { clientToken: 2, clientEpoch: 2 });
      const ex = async (ip: string) => {
        const { code, verifier } = await codeFor(hub);
        return (await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }, { ip }))).status;
      };
      expect(await ex('198.51.100.1')).toBe(200);
      expect(await ex('198.51.100.2')).toBe(200);
      expect(await ex('198.51.100.3')).toBe(429);
      const ep = (ip: string) => hub.epoch(epochReq({ sids: ['x'.repeat(24)] }, { ip }));
      expect((await ep('198.51.100.1')).status).toBe(200);
      expect((await ep('198.51.100.2')).status).toBe(200);
      expect((await ep('198.51.100.3')).status).toBe(429);
    });
  });

  describe('MED-2: epoch', () => {
    it('authenticated batch: POST { sids } → one answer per sid; unauthenticated is refused when the hub has a client key', async () => {
      const { hub } = await rig(kind);
      const a = await signIn(hub);
      const sidA = (await hub.currentSession(new Request(ISSUER, { headers: { cookie: a.cookie } })))!.sid;
      const r = await hub.epoch(epochReq({ sids: [sidA, 'u'.repeat(24)] }));
      expect(r.status).toBe(200);
      expect(await r.json()).toEqual({ sessions: [{ sid: sidA, active: true, epoch: 0 }, { sid: 'u'.repeat(24), active: false, epoch: null }] });
      expect((await hub.epoch(epochReq({ sids: [sidA] }, { auth: 'none' }))).status).toBe(401);
      expect((await hub.epoch(epochReq({ sids: Array.from({ length: 101 }, (_, i) => `sid${String(i).padStart(8, '0')}`) }))).status).toBe(400);
      expect((await hub.epoch(epochReq({ sids: ['bad sid!'] }))).status).toBe(400);
    });

    it('the per-identity-key limit does not apply to an authenticated site (no one can starve a victim’s checks)', async () => {
      const { hub } = await rig(kind, undefined, { epoch: 2, clientEpoch: 1000 });
      const a = await signIn(hub);
      const sid = (await hub.currentSession(new Request(ISSUER, { headers: { cookie: a.cookie } })))!.sid;
      for (let i = 0; i < 6; i++) expect((await hub.epoch(epochReq({ sids: [sid] }, { ip: `198.51.100.${i + 10}` }))).status).toBe(200);
    });

    it('without a client key (development) epoch calls are unauthenticated, and then the IP and per-key limits apply', async () => {
      const { hub } = await rig(kind, undefined, { epoch: 2 }, { clientKey: null });
      const a = await signIn(hub);
      const sid = (await hub.currentSession(new Request(ISSUER, { headers: { cookie: a.cookie } })))!.sid;
      const st: number[] = [];
      for (let i = 0; i < 3; i++) st.push((await hub.epoch(epochReq({ sids: [sid] }, { auth: 'none', ip: `198.51.100.${i + 20}` }))).status);
      expect(st).toEqual([200, 200, 429]);
    });
  });

  describe('LOWs', () => {
    it('logout hint: the HMAC with the named client’s secret signs out at once; the old unkeyed form, another client’s, or none gets the confirm page', async () => {
      const { hub, clock } = await rig(kind);
      const t = Math.floor(clock.t / 1000);
      const go = async (hint: string, clientId = 'site') => {
        const { cookie } = await signIn(hub);
        const sid = (await hub.currentSession(new Request(ISSUER, { headers: { cookie } })))!.sid;
        const h = hint.replace('SID', sid);
        const r = await hub.logout(new Request(`${ISSUER}/logout?client_id=${clientId}&redirect_uri=${encodeURIComponent('https://site.example/')}&logout_hint=${encodeURIComponent(await mk(h, sid))}`, { headers: { cookie } }));
        return r.status === 303 ? 'signed-out' : (await r.text()).includes('Sign out of all b*X sites?') ? 'confirm' : String(r.status);
      };
      const mk = async (kind2: string, sid: string) => {
        if (kind2 === 'good') return logoutHint(sid, { clientId: 'site', clientSecret: await secretFor('site') }, t);
        if (kind2 === 'vault') return logoutHint(sid, { clientId: 'vault', clientSecret: await secretFor('vault') }, t);
        if (kind2 === 'old') {
          const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`bwx-logout:${sid}:${t}`)));
          return `${t}.${Buffer.from(d).toString('base64url')}`;
        }
        return '';
      };
      expect(await go('good')).toBe('signed-out');
      expect(await go('old')).toBe('confirm');
      expect(await go('vault')).toBe('confirm'); // vault's hint, presented as site's
      expect(await go('none')).toBe('confirm');
    });

    it('the confirm POST also needs Sec-Fetch-Site: same-origin when the browser sends it', async () => {
      const { hub } = await rig(kind);
      const { cookie } = await signIn(hub);
      const post = (h: Record<string, string>) => hub.logout(new Request(`${ISSUER}/logout`, { method: 'POST', headers: { cookie, origin: ISSUER, 'content-type': 'application/x-www-form-urlencoded', ...h }, body: '' }));
      expect((await post({ 'sec-fetch-site': 'same-site' })).status).toBe(403);
      expect(await hub.currentSession(new Request(ISSUER, { headers: { cookie } }))).not.toBeNull();
      expect((await post({ 'sec-fetch-site': 'same-origin' })).status).toBe(200);
      expect(await hub.currentSession(new Request(ISSUER, { headers: { cookie } }))).toBeNull();
    });
  });
});

function epochReq(body: unknown, o: { auth?: 'basic' | 'none'; ip?: string } = {}): Request {
  return new Request(`${ISSUER}/session/epoch`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-real-ip': o.ip ?? '203.0.113.1',
      ...(o.auth === 'none' ? {} : { authorization: SITE_BASIC }),
    },
    body: JSON.stringify(body),
  });
}
const SITE_BASIC = clientBasicAuth('site', await secretFor('site'));
