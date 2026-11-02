import { PrivateKey } from '@bsv/sdk';
import { clearEpochCache, clearJwksCache, handleSsoCallback, verifyHubToken, verifySiteSession, type SsoOptions } from '@bwalletx/connect/sso/server';
import { encodeTx, randomToken, txCookieName } from '@bwalletx/connect/sso';
import { afterEach, describe, expect, it } from 'vitest';
import { newPrivateJwk, signerFromJwk } from '@/lib/keys';
import { CALLBACK, ISSUER, SITE, authorizeReq, challenge, codeFor, hubFetch, pkce, post, rig, signIn, signature, tokenReq, type StoreKind } from './helpers';

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
    const site: SsoOptions = { clientId: 'site', secret: 's'.repeat(40), hub: ISSUER, fetch: hubFetch(hub), now: () => clock.t };
    const cb = await handleSsoCallback(
      new Request(`${CALLBACK}?code=${code}&state=${state}&iss=${encodeURIComponent(ISSUER)}`, { headers: { cookie: `${txCookieName(state)}=${encodeTx({ state, verifier, returnTo: '/home' })}` } }),
      site,
    );
    expect(cb.headers.get('location')).toBe('/home');
    const siteCookie = cb.headers.getSetCookie().find((c) => c.startsWith('bwx_site='))!.split(';')[0];
    const req = () => new Request(SITE, { headers: { cookie: siteCookie } });
    expect((await verifySiteSession(req(), site)).session?.sid).toBeTruthy();

    // "Sign out of all b*X sites" at the hub, coming back to the site's home page.
    const out = await hub.logout(new Request(`${ISSUER}/logout?client_id=site&redirect_uri=${encodeURIComponent(SITE + '/')}`, { headers: { cookie } }));
    expect(out.status).toBe(303);
    expect(out.headers.get('location')).toBe(SITE + '/');
    expect(out.headers.get('set-cookie')).toMatch(/Max-Age=0/);

    clock.t += 301_000; // past the site's 5-minute epoch cache
    const after = await verifySiteSession(req(), site);
    expect(after.session).toBeNull();
    expect(after.setCookie[0]).toMatch(/^bwx_site=;/);
    // and the hub session is gone: a quiet check comes back login_required
    const p = await pkce();
    const r = await hub.authorize(authorizeReq({ client_id: 'site', redirect_uri: CALLBACK, state: randomToken(24), code_challenge: p.challenge, code_challenge_method: 'S256', prompt: 'none' }, cookie));
    expect(new URL(r.headers.get('location')!).searchParams.get('error')).toBe('login_required');
  });

  it('logout everywhere also ends the same identity’s hub session in another browser', async () => {
    const { hub } = await rig(kind);
    const root = PrivateKey.fromRandom();
    const a = await signIn(hub, root);
    const b = await signIn(hub, root);
    await hub.logout(new Request(`${ISSUER}/logout`, { headers: { cookie: a.cookie } }));
    expect(await hub.currentSession(new Request(ISSUER, { headers: { cookie: b.cookie } }))).toBeNull();
  });

  it('logout never redirects to an unregistered address', async () => {
    const { hub } = await rig(kind);
    const { cookie } = await signIn(hub);
    const r = await hub.logout(new Request(`${ISSUER}/logout?client_id=site&redirect_uri=${encodeURIComponent('https://evil.example/')}`, { headers: { cookie } }));
    expect(r.status).toBe(200);
    expect(r.headers.get('location')).toBeNull();
    expect(await r.text()).toContain('Signed out of all b*X sites');
  });

  it('a bad signature at sign-in is refused', async () => {
    const { hub } = await rig(kind);
    const root = PrivateKey.fromRandom();
    const other = PrivateKey.fromRandom();
    const c = await challenge(hub);
    // signed by another key, but claiming root's key
    const r = await hub.verify(post('/api/verify', { identityKey: root.toPublicKey().toString(), nonce: c.nonce, signature: await signature(other, c.message, c.keyID) }));
    expect(r.status).toBe(401);
    expect(r.headers.get('set-cookie')).toBeNull();
    // a signature over a different message
    const c2 = await challenge(hub);
    const r2 = await hub.verify(post('/api/verify', { identityKey: root.toPublicKey().toString(), nonce: c2.nonce, signature: await signature(root, c2.message + 'x', c2.keyID) }));
    expect(r2.status).toBe(401);
  });

  it('a replayed challenge is refused', async () => {
    const { hub } = await rig(kind);
    const root = PrivateKey.fromRandom();
    const c = await challenge(hub);
    const body = { identityKey: root.toPublicKey().toString(), nonce: c.nonce, signature: await signature(root, c.message, c.keyID) };
    expect((await hub.verify(post('/api/verify', body))).status).toBe(200);
    expect((await hub.verify(post('/api/verify', body))).status).toBe(401);
  });

  it('an expired challenge is refused (2 minutes)', async () => {
    const { hub } = await rig(kind);
    const root = PrivateKey.fromRandom();
    const c = await challenge(hub);
    const sig = await signature(root, c.message, c.keyID);
    const realNow = Date.now;
    Date.now = () => realNow() + 121_000; // the challenge lifetime is checked by @bwalletx/connect with Date.now
    try {
      expect((await hub.verify(post('/api/verify', { identityKey: root.toPublicKey().toString(), nonce: c.nonce, signature: sig }))).status).toBe(401);
    } finally {
      Date.now = realNow;
    }
  });

  it('challenge and verify only answer the hub’s own origin', async () => {
    const { hub } = await rig(kind);
    expect((await hub.challenge(post('/api/challenge', {}, { origin: 'https://evil.example' }))).status).toBe(403);
    expect((await hub.verify(post('/api/verify', {}, { origin: 'https://evil.example' }))).status).toBe(403);
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
    const root = PrivateKey.fromRandom();
    const c = await challenge(hub);
    const r = await hub.verify(post('/api/verify', { identityKey: root.toPublicKey().toString(), nonce: c.nonce, signature: await signature(root, c.message, c.keyID) }));
    const set = r.headers.get('set-cookie')!;
    expect(set).toMatch(/^__Host-bwx_hub=/);
    for (const part of ['HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/', `Max-Age=${30 * 24 * 3600}`]) expect(set).toContain(part);
    expect(set).not.toMatch(/Domain=/i);
    const v = await codeFor(hub, 'vault', 'https://vault.example/sso/callback');
    const t = (await (await hub.token(tokenReq({ grant_type: 'authorization_code', code: v.code, code_verifier: v.verifier, client_id: 'vault', redirect_uri: 'https://vault.example/sso/callback' }))).json()) as { tier: string };
    expect(t.tier).toBe('high');
  });

  it('session epoch endpoint: active, then inactive after logout', async () => {
    const { hub } = await rig(kind);
    const { code, verifier, cookie } = await codeFor(hub);
    const t = (await (await hub.token(tokenReq({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'site', redirect_uri: CALLBACK }))).json()) as { sid: string };
    const ep = async () => (await hub.epoch(new Request(`${ISSUER}/session/epoch?sid=${t.sid}`))).json();
    expect(await ep()).toEqual({ sid: t.sid, active: true, epoch: 0 });
    await hub.logout(new Request(`${ISSUER}/logout`, { headers: { cookie } }));
    expect(await ep()).toMatchObject({ active: false });
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
