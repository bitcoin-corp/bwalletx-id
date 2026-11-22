import { PrivateKey } from '@bsv/sdk';
import { clearEpochCache, clearJwksCache, handleSsoCallback, verifyHubToken, verifySiteSession, type SsoOptions } from '@bwalletx/connect/sso/server';
import { encodeTx, randomToken, txCookieName } from '@bwalletx/connect/sso';
import { afterEach, describe, expect, it } from 'vitest';
import { logoutHint } from '@bwalletx/connect/sso';
import { newPrivateJwk, signerFromJwk } from '@/lib/keys';
import { DEFAULT_RATE_LIMITS, MAX_SESSIONS_PER_IDENTITY, rateLimitsFromEnv } from '@/lib/config';
import { pgHubStore, pgRoleCheck } from '@/lib/store/postgres';
import {
  CALLBACK,
  ISSUER,
  MIGRATION,
  MIGRATION_2,
  SITE,
  authorizeReq,
  codeFor,
  epochGet,
  hubFetch,
  logoutFromSite,
  migratedDb,
  pkce,
  poll,
  rig,
  secretForSync,
  sidOf,
  signIn,
  startSignIn,
  tokenReq,
  walletApprove,
  type StoreKind,
} from './helpers';

afterEach(() => {
  clearJwksCache();
  clearEpochCache();
});

const isErrorPage = async (r: Response) => {
  expect(r.status).toBe(400);
  expect(r.headers.get('location')).toBeNull();
  expect(r.headers.get('content-type')).toMatch(/text\/html/);
  expect(await r.text()).toContain('This sign-in link isn&#39;t valid');
};

describe.each<StoreKind>(['memory', 'postgres'])('hub (%s store)', (kind) => {
  it('happy path: authorize → code → token → ID token that the add-on verifies', async () => {
    const { hub } = await rig(kind);
    const { code, state, loc, verifier, root } = await codeFor(hub);
    expect(loc.origin + loc.pathname).toBe(CALLBACK);
    expect(loc.searchParams.get('state')).toBe(state);
    expect(loc.searchParams.get('iss')).toBe(ISSUER);
    const r = await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }));
    expect(r.status).toBe(200);
    const b = (await r.json()) as { id_token: string };
    const claims = await verifyHubToken(b.id_token, { hub: ISSUER, clientId: 'site', fetch: hubFetch(hub) });
    expect(claims.identityKey).toBe(root.toPublicKey().toString());
    expect(claims).toMatchObject({ aud: 'site', paymail: 'alice@bwalletx.com', handle: '$alice', tier: 'standard', epoch: 0 });
  });

  it('PKCE mismatch is refused', async () => {
    const { hub } = await rig(kind);
    const { code } = await codeFor(hub);
    const wrong = (await pkce()).verifier;
    const r = await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: wrong, client_id: 'site', redirect_uri: CALLBACK }));
    expect(r.status).toBe(400);
    expect(await r.json()).toMatchObject({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
  });

  it('a reused code is refused', async () => {
    const { hub } = await rig(kind);
    const { code, verifier } = await codeFor(hub);
    const body = { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK };
    expect((await hub.token(tokenReq(body))).status).toBe(200);
    const again = await hub.token(tokenReq(body));
    expect(again.status).toBe(400);
    expect(await again.json()).toMatchObject({ error: 'invalid_grant' });
  });

  it('a failed attempt still uses up the code (no second try with the right verifier)', async () => {
    const { hub } = await rig(kind);
    const { code, verifier } = await codeFor(hub);
    await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: (await pkce()).verifier, client_id: 'site', redirect_uri: CALLBACK }));
    const r = await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }));
    expect(r.status).toBe(400);
  });

  it('an expired code is refused (60 s)', async () => {
    const { hub, clock } = await rig(kind);
    const { code, verifier } = await codeFor(hub);
    clock.t += 61_000;
    const r = await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }));
    expect(r.status).toBe(400);
    expect(await r.json()).toMatchObject({ error: 'invalid_grant', error_description: 'Code expired' });
  });

  it('a code is bound to its client_id and redirect_uri', async () => {
    const { hub } = await rig(kind);
    const a = await codeFor(hub);
    const r1 = await hub.token(tokenReq({ grant_type: 'authorization_code', code: a.code, code_verifier: a.verifier, client_id: 'vault', redirect_uri: 'https://vault.example/sso/callback' }));
    expect(await r1.json()).toMatchObject({ error: 'invalid_grant' });
    const b = await codeFor(hub);
    const r2 = await hub.token(tokenReq({ grant_type: 'authorization_code', code: b.code, code_verifier: b.verifier, client_id: 'site', redirect_uri: CALLBACK + '/' }));
    expect(await r2.json()).toMatchObject({ error: 'invalid_grant', error_description: 'redirect_uri does not match' });
  });

  it('a redirect_uri not exactly in the registry shows the error page and does not redirect', async () => {
    const { hub } = await rig(kind);
    const { cookie } = await signIn(hub);
    const p = await pkce();
    for (const bad of [
      CALLBACK + '/',
      CALLBACK + '?x=1',
      'http://site.example/sso/callback',
      'https://SITE.example/sso/callback',
      'https://site.example.evil.com/sso/callback',
      'https://evil.example/sso/callback',
      'https://site.example/sso/callback#frag',
      'https://site.example/sso/other',
      '',
    ]) {
      const r = await hub.authorize(authorizeReq({ client_id: 'site', redirect_uri: bad, state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256' }, cookie));
      await isErrorPage(r);
    }
    // a repeated redirect_uri (parameter pollution) is also an error page
    const q = new URLSearchParams({ client_id: 'site', redirect_uri: CALLBACK, state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256' });
    q.append('redirect_uri', 'https://evil.example/');
    await isErrorPage(await hub.authorize(new Request(`${ISSUER}/authorize?${q}`, { headers: { cookie } })));
  });

  it('an unknown client is refused (error page at /authorize, invalid_client at /token)', async () => {
    const { hub } = await rig(kind);
    const p = await pkce();
    await isErrorPage(await hub.authorize(authorizeReq({ client_id: 'nobody', redirect_uri: CALLBACK, state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256' })));
    const r = await hub.token(tokenReq({ grant_type: 'authorization_code', code: 'x', code_verifier: p.verifier, client_id: 'nobody', redirect_uri: CALLBACK }));
    expect(r.status).toBe(401);
    expect(await r.json()).toMatchObject({ error: 'invalid_client' });
  });

  it('a token with the wrong aud is refused by the add-on verifier', async () => {
    const { hub } = await rig(kind);
    const { code, verifier } = await codeFor(hub);
    const b = (await (await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }))).json()) as { id_token: string };
    await expect(verifyHubToken(b.id_token, { hub: ISSUER, clientId: 'vault', fetch: hubFetch(hub) })).rejects.toMatchObject({ code: 'bad_aud' });
  });

  it('a bumped epoch logs out: hub logout ends every site session', async () => {
    const { hub, clock } = await rig(kind);
    const { code, state, verifier, cookie } = await codeFor(hub);
    const site: SsoOptions = { clientId: 'site', secret: 's'.repeat(40), clientSecret: secretForSync('site'), hub: ISSUER, fetch: hubFetch(hub), now: () => clock.t };
    const cb = await handleSsoCallback(
      new Request(`${CALLBACK}?code=${code}&state=${state}&iss=${encodeURIComponent(ISSUER)}`, { headers: { cookie: `${txCookieName(state)}=${encodeTx({ state, verifier, returnTo: '/home' })}` } }),
      site,
    );
    expect(cb.headers.get('location')).toBe('/home');
    const siteCookie = cb.headers.getSetCookie().find((c) => c.startsWith('__Host-bwx_site='))!.split(';')[0];
    const req = () => new Request(SITE, { headers: { cookie: siteCookie } });
    expect((await verifySiteSession(req(), site)).session?.sid).toBeTruthy();

    // "Sign out of all b*X sites" at the hub, coming back to the site's home page.
    const out = await logoutFromSite(hub, cookie, clock, `client_id=site&redirect_uri=${encodeURIComponent(SITE + '/')}`);
    expect(out.status).toBe(303);
    expect(out.headers.get('location')).toBe(SITE + '/');
    expect(out.headers.get('set-cookie')).toMatch(/Max-Age=0/);

    clock.t += 301_000; // past the site's 5-minute epoch cache
    const after = await verifySiteSession(req(), site);
    expect(after.session).toBeNull();
    expect(after.setCookie[0]).toMatch(/^__Host-bwx_site=;/);
    // and the hub session is gone: a quiet check comes back login_required
    const p = await pkce();
    const r = await hub.authorize(authorizeReq({ client_id: 'site', redirect_uri: CALLBACK, state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256', prompt: 'none' }, cookie));
    expect(new URL(r.headers.get('location')!).searchParams.get('error')).toBe('login_required');
  });

  it('logout everywhere also ends the same identity’s hub session in another browser', async () => {
    const { hub, clock } = await rig(kind);
    const root = PrivateKey.fromRandom();
    const a = await signIn(hub, root);
    const b = await signIn(hub, root);
    await logoutFromSite(hub, a.cookie, clock);
    expect(await hub.currentSession(new Request(ISSUER, { headers: { cookie: b.cookie } }))).toBeNull();
  });

  it('logout never redirects to an unregistered address', async () => {
    const { hub, clock } = await rig(kind);
    const { cookie } = await signIn(hub);
    const r = await logoutFromSite(hub, cookie, clock, `client_id=site&redirect_uri=${encodeURIComponent('https://evil.example/')}`);
    expect(r.status).toBe(200);
    expect(r.headers.get('location')).toBeNull();
    expect(await r.text()).toContain('Signed out of all b*X sites');
  });

  it('prompt=none with no session returns error=login_required to the registered redirect only', async () => {
    const { hub } = await rig(kind);
    const p = await pkce();
    const state = randomToken(24);
    const r = await hub.authorize(authorizeReq({ client_id: 'site', redirect_uri: CALLBACK, state, code_challenge: p.challenge, code_challenge_method: 'S256', prompt: 'none' }));
    expect(r.status).toBe(303);
    const loc = new URL(r.headers.get('location')!);
    expect(loc.origin + loc.pathname).toBe(CALLBACK);
    expect(loc.searchParams.get('error')).toBe('login_required');
    expect(loc.searchParams.get('state')).toBe(state);
    expect(loc.searchParams.get('code')).toBeNull();
    // an unregistered redirect with prompt=none: error page, no redirect
    await isErrorPage(await hub.authorize(authorizeReq({ client_id: 'site', redirect_uri: 'https://evil.example/cb', state, code_challenge: p.challenge, code_challenge_method: 'S256', prompt: 'none' })));
  });

  it('no session: /authorize sends the visitor to the hub sign-in page; verify continues the same authorize request', async () => {
    const { hub } = await rig(kind);
    const p = await pkce();
    const params = { client_id: 'site', redirect_uri: CALLBACK, state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256' };
    const r = await hub.authorize(authorizeReq(params));
    const loc = new URL(r.headers.get('location')!);
    expect(loc.origin + loc.pathname).toBe(`${ISSUER}/signin`);
    const { body, cookie } = await signIn(hub, undefined, { ...params, prompt: 'login' });
    expect(body.next.startsWith('/authorize?')).toBe(true);
    expect(new URLSearchParams(body.next.split('?')[1]).get('prompt')).toBeNull();
    const r2 = await hub.authorize(new Request(ISSUER + body.next, { headers: { cookie } }));
    expect(new URL(r2.headers.get('location')!).searchParams.get('code')).toBeTruthy();
  });

  it('prompt=login ignores an existing session and asks for a fresh wallet sign-in', async () => {
    const { hub } = await rig(kind);
    const { cookie } = await signIn(hub);
    const p = await pkce();
    const r = await hub.authorize(authorizeReq({ client_id: 'site', redirect_uri: CALLBACK, state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256', prompt: 'login' }, cookie));
    expect(new URL(r.headers.get('location')!).pathname).toBe('/signin');
  });

  it('missing PKCE or a plain method goes back to the site as invalid_request', async () => {
    const { hub } = await rig(kind);
    const p = await pkce();
    for (const extra of [{ code_challenge_method: 'plain', code_challenge: p.challenge }, { code_challenge_method: 'S256', code_challenge: 'short' }, { code_challenge_method: 'S256', code_challenge: p.challenge, state: 'x' }]) {
      const r = await hub.authorize(authorizeReq({ client_id: 'site', redirect_uri: CALLBACK, state: randomToken(24), ...extra }));
      expect(new URL(r.headers.get('location')!).searchParams.get('error')).toBe('invalid_request');
    }
  });

  it('hub cookie: __Host-, httpOnly, Secure, SameSite=Lax, 30 days; high-tier clients get tier=high in the token', async () => {
    const { hub } = await rig(kind);
    const s = await startSignIn(hub);
    await walletApprove(hub, s.body.requestId, PrivateKey.fromRandom());
    const set = (await poll(hub, s.cookie)).res.headers.getSetCookie().find((c) => c.startsWith('__Host-bwx_hub='))!;
    expect(set).toMatch(/^__Host-bwx_hub=/);
    for (const part of ['HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/', `Max-Age=${30 * 24 * 3600}`]) expect(set).toContain(part);
    expect(set).not.toMatch(/Domain=/i);
    const v = await codeFor(hub, 'vault', 'https://vault.example/sso/callback');
    const t = (await (await hub.token(tokenReq({ grant_type: 'authorization_code', code: v.code, code_verifier: v.verifier, client_id: 'vault', redirect_uri: 'https://vault.example/sso/callback' }))).json()) as { tier: string };
    expect(t.tier).toBe('high');
  });

  it('session epoch endpoint: active, then inactive after logout', async () => {
    const { hub, clock } = await rig(kind);
    const { code, verifier, cookie } = await codeFor(hub);
    const t = (await (await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }))).json()) as { sid: string };
    const ep = async () => (await epochGet(hub, t.sid)).json();
    expect(await ep()).toEqual({ sid: t.sid, active: true, epoch: 0 });
    await logoutFromSite(hub, cookie, clock);
    expect(await ep()).toMatchObject({ active: false });
  });
});

describe.each<StoreKind>(['memory', 'postgres'])('security review fixes (%s store)', (kind) => {
  // Finding 3a: rate limits.
  it('rate limits: sign-in start 10/min per IP, then 429 + Retry-After; another IP and the next minute are fine', async () => {
    const { hub, clock } = await rig(kind, undefined, DEFAULT_RATE_LIMITS);
    clock.t = Math.floor(clock.t / 60_000) * 60_000 + 15_000; // 15 s into a window
    for (let i = 0; i < 10; i++) expect((await startSignIn(hub)).res.status).toBe(200);
    const r = (await startSignIn(hub)).res;
    expect(r.status).toBe(429);
    expect(r.headers.get('retry-after')).toBe('45');
    expect(await r.json()).toMatchObject({ error: 'rate_limited' });
    expect((await startSignIn(hub, undefined, { 'x-real-ip': '198.51.100.7' })).res.status).toBe(200);
    clock.t += 46_000;
    expect((await startSignIn(hub)).res.status).toBe(200);
  });

  it('rate limits: the wallet endpoint 30/min per IP (failed attempts count); poll 120/min per IP', async () => {
    const { hub } = await rig(kind, undefined, DEFAULT_RATE_LIMITS);
    const root = PrivateKey.fromRandom();
    const junk = () => walletApprove(hub, 'j'.repeat(22), root);
    let last = 0;
    for (let i = 0; i < 15; i++) last = (await junk()).status; // each junk try = a GET for info + a POST
    expect(last).toBe(404);
    expect((await junk()).status).toBe(429);
    const s = await startSignIn(hub, undefined, { 'x-real-ip': '198.51.100.50' });
    for (let i = 0; i < 120; i++) expect((await poll(hub, s.cookie, { 'x-real-ip': '198.51.100.50' })).res.status).toBe(200);
    expect((await poll(hub, s.cookie, { 'x-real-ip': '198.51.100.50' })).res.status).toBe(429);
  });

  it('rate limits: /token 20 failed attempts/min per IP; unauthenticated /session/epoch 120/min per IP (development)', async () => {
    const { hub } = await rig(kind, undefined, DEFAULT_RATE_LIMITS);
    const tok = () => hub.token(tokenReq({ grant_type: 'authorization_code', client_id: 'site', code: 'x', code_verifier: 'v'.repeat(43), redirect_uri: CALLBACK }, { ip: '203.0.113.9' }));
    for (let i = 0; i < 20; i++) expect((await tok()).status).toBe(400);
    const r = await tok();
    expect(r.status).toBe(429);
    expect(Number(r.headers.get('retry-after'))).toBeGreaterThan(0);
    const dev = await rig(kind, undefined, DEFAULT_RATE_LIMITS, { clientKey: null });
    const ep = () => dev.hub.epoch(new Request(`${ISSUER}/session/epoch?sid=${'s'.repeat(24)}`, { headers: { 'x-real-ip': '203.0.113.9' } }));
    for (let i = 0; i < 120; i++) expect((await ep()).status).toBe(200);
    expect((await ep()).status).toBe(429);
  });

  it('rate limits can be raised from env (SSO_RATE_LIMITS), bad values ignored', () => {
    expect(rateLimitsFromEnv({ SSO_RATE_LIMITS: '{"epoch":600,"token":-1,"verify":"x"}' } as unknown as NodeJS.ProcessEnv)).toEqual({ epoch: 600 });
    expect(rateLimitsFromEnv({ SSO_RATE_LIMITS: 'nope' } as unknown as NodeJS.ProcessEnv)).toEqual({});
    expect(rateLimitsFromEnv({} as unknown as NodeJS.ProcessEnv)).toEqual({});
  });

  // Finding 3d: session cap.
  it(`at most ${MAX_SESSIONS_PER_IDENTITY} hub sessions per identity key: the oldest is evicted`, async () => {
    const { hub, clock } = await rig(kind);
    const root = PrivateKey.fromRandom();
    const cookies: string[] = [];
    for (let i = 0; i < MAX_SESSIONS_PER_IDENTITY + 1; i++) {
      clock.t += 1000;
      cookies.push((await signIn(hub, root)).cookie); // a new browser each time (no cookie sent)
    }
    expect(await sidOf(hub, cookies[0])).toBeNull();
    for (const c of cookies.slice(1)) expect(await sidOf(hub, c)).not.toBeNull();
  });

  // Finding 3c: cleanup.
  it('cleanup removes expired pending sign-ins, codes, sessions and rate-limit windows', async () => {
    const { hub, store, clock } = await rig(kind);
    const real = Date.now();
    clock.t = real;
    await store.putPendingSignIn({ requestId: 'old'.padEnd(22, 'o'), browserHash: 'bh-old', userCode: 'BCDF-GHJK', clientId: null, authorize: null, message: 'm', status: 'pending', identityKey: null, attempts: 0, createdAt: real - 400_000, expiresAt: real - 1000 });
    await store.putCode('codehash', { clientId: 'site', redirectUri: CALLBACK, codeChallenge: 'c', sid: 's', identityKey: 'k', expiresAt: real - 1000 });
    await store.hit('x:ip:y', 1000, real - 10_000);
    await store.createSession({ sid: 'expired-sid-1', tokenHash: 'th1', identityKey: '02'.padEnd(66, 'a'), paymail: null, handle: null, epoch: 0, authTime: real, createdAt: real, rotatedAt: real, expiresAt: real - 2 * 86400_000 });
    await store.cleanup();
    expect(await store.getPendingSignIn('old'.padEnd(22, 'o'))).toBeNull();
    expect(await store.takeCode('codehash')).toBeNull();
    expect(await store.getSession('expired-sid-1')).toBeNull();
    expect((await store.hit('x:ip:y', 1000, real - 10_000)).hits).toBe(1); // the old window was deleted, so it starts again
    void hub;
  });

  // Finding 7: /logout.
  it('GET /logout without a site hint shows a confirm page and signs nobody out', async () => {
    const { hub } = await rig(kind);
    const { cookie } = await signIn(hub);
    const r = await hub.logout(new Request(`${ISSUER}/logout?client_id=site&redirect_uri=${encodeURIComponent(SITE + '/')}`, { headers: { cookie } }));
    expect(r.status).toBe(200);
    expect(r.headers.get('set-cookie')).toBeNull();
    expect(r.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    const html = await r.text();
    expect(html).toContain('Sign out of all b*X sites?');
    expect(html).toContain('<form method="post" action="/logout">');
    expect(html).toContain('name="redirect_uri" value="https://site.example/"');
    expect(html).toContain('<meta name="referrer" content="same-origin">');
    expect(await sidOf(hub, cookie)).not.toBeNull();
    // a hint for another session is no better than none
    const wrong = await logoutHint('not-this-session', { clientId: 'site', clientSecret: secretForSync('site') }, Math.floor(Date.now() / 1000));
    const r2 = await hub.logout(new Request(`${ISSUER}/logout?client_id=site&logout_hint=${wrong}`, { headers: { cookie } }));
    expect(await r2.text()).toContain('Sign out of all b*X sites?');
    expect(await sidOf(hub, cookie)).not.toBeNull();
    // an unregistered redirect_uri is dropped from the form
    const r3 = await hub.logout(new Request(`${ISSUER}/logout?client_id=site&redirect_uri=${encodeURIComponent('https://evil.example/')}`, { headers: { cookie } }));
    expect(await r3.text()).not.toContain('evil.example');
  });

  it('POST /logout: same-origin signs out everywhere; a cross-site or Origin-less POST is refused', async () => {
    const { hub } = await rig(kind);
    const { cookie } = await signIn(hub);
    const form = (origin?: string) =>
      new Request(`${ISSUER}/logout`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie, ...(origin ? { origin } : {}) },
        body: new URLSearchParams({ client_id: 'site', redirect_uri: SITE + '/' }).toString(),
      });
    expect((await hub.logout(form('https://evil.example'))).status).toBe(403);
    expect((await hub.logout(form('null'))).status).toBe(403);
    expect((await hub.logout(form())).status).toBe(403);
    expect(await sidOf(hub, cookie)).not.toBeNull();
    const ok = await hub.logout(form(ISSUER));
    expect(ok.status).toBe(303);
    expect(ok.headers.get('location')).toBe(SITE + '/');
    expect(ok.headers.get('set-cookie')).toMatch(/Max-Age=0/);
    expect(await sidOf(hub, cookie)).toBeNull();
  });

  it('GET /logout with a valid site hint signs out at once (the add-on’s one-click "Sign out of all")', async () => {
    const { hub, clock } = await rig(kind);
    const { cookie } = await signIn(hub);
    const r = await logoutFromSite(hub, cookie, clock, `client_id=site&redirect_uri=${encodeURIComponent(SITE + '/')}`);
    expect(r.status).toBe(303);
    expect(r.headers.get('location')).toBe(SITE + '/');
    expect(await sidOf(hub, cookie)).toBeNull();
  });

  // Finding 8: a fresh sign-in keeps the sid.
  it('a fresh wallet sign-in in the same browser keeps the sid (other sites stay signed in) and refreshes auth_time', async () => {
    const { hub, clock } = await rig(kind);
    const root = PrivateKey.fromRandom();
    const first = await signIn(hub, root);
    const sid = await sidOf(hub, first.cookie);
    const before = (await hub.currentSession(new Request(ISSUER, { headers: { cookie: first.cookie } })))!;
    clock.t += 3600_000;
    const again = await signIn(hub, root, undefined, { cookie: first.cookie });
    expect(again.cookie).not.toBe(first.cookie); // the cookie token rotates
    const after = (await hub.currentSession(new Request(ISSUER, { headers: { cookie: again.cookie } })))!;
    expect(after.sid).toBe(sid);
    expect(after.authTime).toBe(clock.t);
    expect(after.authTime).toBeGreaterThan(before.authTime);
    expect(await (await epochGet(hub, sid!)).json()).toMatchObject({ active: true });
    // the new auth_time reaches the next ID token
    const p = await pkce();
    const state = randomToken(24);
    const a = await hub.authorize(authorizeReq({ client_id: 'site', redirect_uri: CALLBACK, state, code_challenge: p.challenge, code_challenge_method: 'S256' }, again.cookie));
    const code = new URL(a.headers.get('location')!).searchParams.get('code')!;
    const t = (await (await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: p.verifier, client_id: 'site', redirect_uri: CALLBACK }))).json()) as { auth_time: number; sid: string };
    expect(t.sid).toBe(sid);
    expect(t.auth_time).toBe(Math.floor(clock.t / 1000));
  });

  it('a different wallet signing in on the same browser replaces the previous hub session', async () => {
    const { hub } = await rig(kind);
    const a = await signIn(hub);
    const sidA = await sidOf(hub, a.cookie);
    const b = await signIn(hub, PrivateKey.fromRandom(), undefined, { cookie: a.cookie });
    expect(await sidOf(hub, b.cookie)).not.toBe(sidA);
    expect(await (await epochGet(hub, sidA!)).json()).toMatchObject({ active: false });
  });
});

describe('database: least-privilege role, own schema, RLS', () => {
  it('creates sso_hub NOLOGIN, tables in schema sso with RLS on, nothing for anon/authenticated', async () => {
    const db = await migratedDb();
    const role = (await db.query<{ rolcanlogin: boolean; rolsuper: boolean; rolbypassrls: boolean }>(`select rolcanlogin, rolsuper, rolbypassrls from pg_roles where rolname = 'sso_hub'`)).rows[0];
    expect(role).toEqual({ rolcanlogin: false, rolsuper: false, rolbypassrls: false });
    const tables = (await db.query<{ relname: string; relrowsecurity: boolean }>(
      `select c.relname, c.relrowsecurity from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'sso' and c.relkind = 'r' order by 1`,
    )).rows;
    expect(tables).toEqual(['challenges', 'codes', 'epochs', 'pending_signins', 'rate_limits', 'sessions'].map((relname) => ({ relname, relrowsecurity: true })));
    expect((await db.query(`select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname like 'sso_%'`)).rows).toEqual([]);
    for (const r of ['anon', 'authenticated']) {
      const has = (await db.query<{ u: boolean; s: boolean }>(`select has_schema_privilege('${r}', 'sso', 'usage') as u, has_table_privilege('${r}', 'sso.sessions', 'select') as s`)).rows[0];
      expect(has).toEqual({ u: false, s: false });
    }
    await db.exec(`set role anon`);
    await expect(db.query(`select * from sso.sessions`)).rejects.toThrow(/permission denied/);
  });

  it('sso_hub can use its own tables and nothing else; the role check sees it', async () => {
    const db = await migratedDb();
    await db.exec(`create table public.other_secrets (x text); insert into public.other_secrets values ('nope');`);
    await db.exec(`set role sso_hub`);
    const q = (sql: string, params: unknown[]) => db.query(sql, params);
    expect(await pgRoleCheck(q)).toEqual({ user: 'sso_hub', superuser: false, bypassrls: false });
    await expect(db.query(`select * from public.other_secrets`)).rejects.toThrow(/permission denied/);
    const store = pgHubStore(q);
    await store.bumpEpoch('02'.padEnd(66, 'b'));
    expect(await store.getEpoch('02'.padEnd(66, 'b'))).toBe(1);
    await store.cleanup();
    await db.exec(`reset role`);
    expect(await pgRoleCheck(q)).toMatchObject({ superuser: true });
  });

  it('the migration can be run twice (pg_cron block skipped where pg_cron is not installed)', async () => {
    const db = await migratedDb();
    await db.exec(MIGRATION);
    await db.exec(MIGRATION_2);
    expect((await db.query(`select count(*)::int as n from pg_policies where schemaname = 'sso' and policyname = 'sso_hub_all'`)).rows[0]).toEqual({ n: 6 });
  });
});

describe('keys', () => {
  it('rotation: the JWKS lists the current and previous key; tokens from either verify', async () => {
    const oldJwk = await newPrivateJwk();
    const newJwk = await newPrivateJwk();
    const before = await rig('memory', await signerFromJwk(oldJwk));
    const { code, verifier } = await codeFor(before.hub);
    const oldToken = ((await (await before.hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }))).json()) as { id_token: string }).id_token;

    const { d: _d, ...oldPublic } = oldJwk;
    void _d;
    const rotated = await rig('memory', await signerFromJwk(newJwk, [oldPublic]));
    const jwks = (await rotated.hub.jwks().json()) as { keys: { kid: string; d?: string }[] };
    expect(jwks.keys.map((k) => k.kid)).toEqual([newJwk.kid, oldJwk.kid]);
    expect(jwks.keys.every((k) => k.d === undefined)).toBe(true);
    // a site that fetched the rotated JWKS still accepts a token signed with the previous key
    await expect(verifyHubToken(oldToken, { hub: ISSUER, clientId: 'site', fetch: hubFetch(rotated.hub) })).resolves.toMatchObject({ aud: 'site' });
  });

  it('refuses a non-ES256 or public-only signing key', async () => {
    const j = await newPrivateJwk();
    const { d: _d, ...pub } = j;
    void _d;
    await expect(signerFromJwk(pub)).rejects.toThrow(/private part/);
    await expect(signerFromJwk({ ...j, crv: 'P-384' })).rejects.toThrow(/P-256/);
  });
});
