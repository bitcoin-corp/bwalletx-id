/**
 * The b*X single sign-on hub: authorization code + PKCE (S256) for first-party b*X sites.
 *
 * Rule zero: a hub session proves WHO you are. It never authorises spending; every payment, signature or transfer
 * still goes through a bWalletX approval sheet.
 *
 * Every handler takes a Web Request and returns a Response, so tests drive them directly.
 */
import { createChallenge, verifySignIn, type NonceStore } from '@bwalletx/connect/server';
import { isPkceChallenge, isPkceVerifier, pkceChallenge } from '@bwalletx/connect/sso';
import { CODE_TTL_MS, HUB_SESSION_MS, ID_TOKEN_SECONDS, ROTATE_AFTER_MS } from './config';
import { randomToken, readCookie, sha256 } from './crypto';
import { errorPage, page } from './html';
import type { Names } from './paymail';
import type { Client, Registry } from './registry';
import type { Signer } from './keys';
import type { HubSession, HubStore } from './store/types';

export interface HubDeps {
  issuer: string;
  registry: Registry;
  store: HubStore;
  signer: Signer;
  /** paymail + $handle for a key (best effort). */
  lookup?: (identityKey: string) => Promise<Names>;
  now?: () => number;
}

export interface AuthorizeParams {
  client_id: string;
  redirect_uri: string;
  state: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  prompt?: 'none' | 'login';
}

type Checked = { ok: true; client: Client; p: AuthorizeParams } | { ok: false; res: Response };

const PARAMS = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'prompt', 'response_type'] as const;

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', pragma: 'no-cache', ...headers } });

const oauthError = (error: string, description: string, status = 400) => json({ error, error_description: description }, status);

export class Hub {
  constructor(private d: HubDeps) {}

  private now(): number {
    return this.d.now?.() ?? Date.now();
  }
  get secure(): boolean {
    return this.d.issuer.startsWith('https://');
  }
  /** __Host- on https: Secure, Path=/, no Domain, so no subdomain can set or read it. */
  get cookieName(): string {
    return this.secure ? '__Host-bwx_hub' : 'bwx_hub';
  }
  private cookie(token: string, maxAgeS: number): string {
    return [`${this.cookieName}=${token}`, 'Path=/', `Max-Age=${maxAgeS}`, 'HttpOnly', 'SameSite=Lax', ...(this.secure ? ['Secure'] : [])].join('; ');
  }
  private nonceStore(): NonceStore {
    return { put: (n, c) => this.d.store.putChallenge(n, c), take: (n) => this.d.store.takeChallenge(n) };
  }

  /** The hub session for this request, if it exists, is unexpired and was not signed out everywhere. */
  async currentSession(req: Request): Promise<HubSession | null> {
    const tok = readCookie(req.headers.get('cookie'), this.cookieName);
    if (!tok || tok.length > 128) return null;
    const s = await this.d.store.getSessionByToken(await sha256(tok));
    return s && (await this.live(s)) ? s : null;
  }

  private async live(s: HubSession): Promise<boolean> {
    return s.expiresAt > this.now() && s.epoch === (await this.d.store.getEpoch(s.identityKey));
  }

  /** Check /authorize parameters. Client and redirect URI problems are an error page; the rest go back to the site. */
  checkAuthorize(q: URLSearchParams): Checked {
    for (const k of PARAMS) if (q.getAll(k).length > 1) return { ok: false, res: errorPage(`The link repeats "${k}".`) };
    const client = this.d.registry.get(q.get('client_id'));
    if (!client) return { ok: false, res: errorPage('It names a site that is not registered with bWalletX.') };
    const redirect_uri = q.get('redirect_uri') ?? '';
    if (!this.d.registry.redirectAllowed(client, redirect_uri)) {
      return { ok: false, res: errorPage(`It would send you to an address that is not registered for ${client.name}.`) };
    }
    const state = q.get('state') ?? '';
    const back = (error: string) => ({ ok: false as const, res: this.redirectBack(redirect_uri, { error, state }) });
    if (!/^[\x21-\x7e]{16,512}$/.test(state)) return back('invalid_request');
    const rt = q.get('response_type');
    if (rt !== null && rt !== 'code') return back('unsupported_response_type');
    if (q.get('code_challenge_method') !== 'S256') return back('invalid_request');
    const code_challenge = q.get('code_challenge');
    if (!isPkceChallenge(code_challenge)) return back('invalid_request');
    const prompt = q.get('prompt') ?? '';
    if (prompt !== '' && prompt !== 'none' && prompt !== 'login') return back('invalid_request');
    return {
      ok: true,
      client,
      p: { client_id: client.client_id, redirect_uri, state, code_challenge, code_challenge_method: 'S256', ...(prompt ? { prompt } : {}) } as AuthorizeParams,
    };
  }

  /** Redirect to a redirect URI that is already known to be registered for the client. */
  private redirectBack(redirectUri: string, params: Record<string, string>, cookies: string[] = []): Response {
    const u = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v) u.searchParams.set(k, v);
    u.searchParams.set('iss', this.d.issuer); // RFC 9207: tells the site which hub answered
    const h = new Headers({ location: u.toString(), 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
    for (const c of cookies) if (c) h.append("set-cookie", c);
    return new Response(null, { status: 303, headers: h });
  }

  /** GET /authorize */
  async authorize(req: Request): Promise<Response> {
    const c = this.checkAuthorize(new URL(req.url).searchParams);
    if (!c.ok) return c.res;
    const { p } = c;
    const s = p.prompt === 'login' ? null : await this.currentSession(req);
    if (!s) {
      if (p.prompt === 'none') return this.redirectBack(p.redirect_uri, { error: 'login_required', state: p.state });
      const q = new URLSearchParams(p as unknown as Record<string, string>);
      return new Response(null, { status: 303, headers: { location: `${this.d.issuer}/signin?${q}`, 'cache-control': 'no-store' } });
    }
    // Signed in at the hub: a single-use code, 60 s, bound to this client, redirect URI and PKCE challenge.
    const code = randomToken(32);
    const now = this.now();
    await this.d.store.putCode(await sha256(code), {
      clientId: p.client_id,
      redirectUri: p.redirect_uri,
      codeChallenge: p.code_challenge,
      sid: s.sid,
      identityKey: s.identityKey,
      expiresAt: now + CODE_TTL_MS,
    });
    return this.redirectBack(p.redirect_uri, { code, state: p.state }, [await this.slide(s)]);
  }

  /** 30 days sliding; the cookie token rotates once a day (the sid sites hold stays the same). */
  private async slide(s: HubSession): Promise<string> {
    const now = this.now();
    const expiresAt = now + HUB_SESSION_MS;
    const token = randomToken(32);
    if (now - s.rotatedAt >= ROTATE_AFTER_MS) {
      await this.d.store.updateSession(s.sid, { expiresAt, tokenHash: await sha256(token), rotatedAt: now });
      return this.cookie(token, HUB_SESSION_MS / 1000);
    }
    await this.d.store.updateSession(s.sid, { expiresAt });
    return ''; // cookie unchanged until rotation; its Max-Age is refreshed then
  }

  /** POST /token (site server → hub): code + code_verifier + client_id + redirect_uri → signed ID token. */
  async token(req: Request): Promise<Response> {
    if (req.method !== 'POST') return oauthError('invalid_request', 'POST only', 405);
    let b: Record<string, string> = {};
    try {
      const ct = req.headers.get('content-type') ?? '';
      if (ct.includes('application/json')) b = (await req.json()) as Record<string, string>;
      else b = Object.fromEntries(new URLSearchParams(await req.text()));
    } catch {
      return oauthError('invalid_request', 'Unreadable body');
    }
    if (b.grant_type !== 'authorization_code') return oauthError('unsupported_grant_type', 'Only authorization_code');
    const client = this.d.registry.get(typeof b.client_id === 'string' ? b.client_id : null);
    if (!client) return oauthError('invalid_client', 'Unknown client', 401);
    if (typeof b.code !== 'string' || b.code.length > 256) return oauthError('invalid_grant', 'No code');
    // Taken (deleted) before any other check: a code works once, even if this attempt fails.
    const rec = await this.d.store.takeCode(await sha256(b.code));
    if (!rec) return oauthError('invalid_grant', 'Unknown or already used code');
    if (rec.expiresAt <= this.now()) return oauthError('invalid_grant', 'Code expired');
    if (rec.clientId !== client.client_id) return oauthError('invalid_grant', 'Code was issued to another client');
    if (rec.redirectUri !== b.redirect_uri) return oauthError('invalid_grant', 'redirect_uri does not match');
    if (!isPkceVerifier(b.code_verifier) || (await pkceChallenge(b.code_verifier)) !== rec.codeChallenge) {
      return oauthError('invalid_grant', 'PKCE verification failed');
    }
    const s = await this.d.store.getSession(rec.sid);
    if (!s || !(await this.live(s))) return oauthError('invalid_grant', 'The hub session has ended');
    const iat = Math.floor(this.now() / 1000);
    const claims = {
      iss: this.d.issuer,
      sub: s.identityKey,
      aud: client.client_id,
      iat,
      exp: iat + ID_TOKEN_SECONDS,
      sid: s.sid,
      epoch: s.epoch,
      identityKey: s.identityKey,
      paymail: s.paymail,
      handle: s.handle,
      tier: client.tier,
      auth_time: Math.floor(s.authTime / 1000),
      jti: randomToken(12),
    };
    const id_token = await this.d.signer.sign(claims);
    return json({ id_token, token_type: 'id_token', expires_in: ID_TOKEN_SECONDS, ...claims });
  }

  /** GET /session/epoch?sid= → { sid, active, epoch }. Sites cache it for at most 5 minutes. */
  async epoch(req: Request): Promise<Response> {
    const sid = new URL(req.url).searchParams.get('sid') ?? '';
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(sid)) return json({ error: 'bad sid' }, 400);
    const s = await this.d.store.getSession(sid);
    if (!s) return json({ sid, active: false, epoch: null });
    const current = await this.d.store.getEpoch(s.identityKey);
    return json({ sid, active: s.expiresAt > this.now() && s.epoch === current, epoch: current });
  }

  /** GET /logout?client_id=&redirect_uri= : end the hub session and bump the epoch, signing out every b*X site. */
  async logout(req: Request): Promise<Response> {
    const q = new URL(req.url).searchParams;
    const tok = readCookie(req.headers.get('cookie'), this.cookieName);
    const s = tok && tok.length <= 128 ? await this.d.store.getSessionByToken(await sha256(tok)) : null;
    if (s) {
      await this.d.store.deleteSession(s.sid);
      await this.d.store.bumpEpoch(s.identityKey);
    }
    const clear = this.cookie('', 0);
    const client = this.d.registry.get(q.get('client_id'));
    const to = q.get('redirect_uri');
    if (client && this.d.registry.postLogoutAllowed(client, to)) {
      return new Response(null, { status: 303, headers: { location: to!, 'set-cookie': clear, 'cache-control': 'no-store' } });
    }
    const res = page({ title: 'Signed out of all b*X sites', body: 'You are signed out here and on every b*X site. Sites notice within five minutes.', links: [{ href: '/', label: 'Done' }] });
    res.headers.append('set-cookie', clear);
    return res;
  }

  jwks(): Response {
    return new Response(JSON.stringify(this.d.signer.jwks()), {
      headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=300', 'access-control-allow-origin': '*' },
    });
  }

  private originOk(req: Request): boolean {
    return req.headers.get('origin') === this.d.issuer;
  }

  /** POST /api/challenge (the hub's own sign-in page only). No identity key needed: one wallet sheet. */
  async challenge(req: Request): Promise<Response> {
    if (req.method !== 'POST') return json({ error: 'POST only' }, 405);
    if (!this.originOk(req)) return json({ error: 'Wrong origin' }, 403);
    let b: { identityKey?: unknown } = {};
    try {
      b = ((await req.json()) ?? {}) as { identityKey?: unknown };
    } catch {
      /* empty body is fine */
    }
    try {
      return json(await createChallenge({ origin: this.d.issuer, identityKey: b.identityKey, store: this.nonceStore() }));
    } catch {
      return json({ error: 'Bad identity key' }, 400);
    }
  }

  /**
   * POST /api/verify { identityKey, nonce, signature, authorize? } → hub session cookie + { next }.
   * The signature must be for a fresh challenge (single use, 2 minutes) made for this hub's origin, by the claimed key.
   */
  async verify(req: Request): Promise<Response> {
    if (req.method !== 'POST') return json({ error: 'POST only' }, 405);
    if (!this.originOk(req)) return json({ error: 'Wrong origin' }, 403);
    let b: { identityKey?: unknown; nonce?: unknown; signature?: unknown; authorize?: unknown };
    try {
      b = (await req.json()) as typeof b;
    } catch {
      return json({ error: 'Unreadable body' }, 400);
    }
    const identityKey = await verifySignIn({ origin: this.d.issuer, identityKey: b.identityKey, nonce: b.nonce, signature: b.signature, store: this.nonceStore() });
    if (!identityKey) return json({ error: 'That signature was not accepted. Start again.' }, 401);

    const old = await this.currentSession(req);
    if (old) await this.d.store.deleteSession(old.sid);
    const names = (await this.d.lookup?.(identityKey)) ?? { paymail: null, handle: null };
    const now = this.now();
    const token = randomToken(32);
    const s: HubSession = {
      sid: randomToken(18),
      tokenHash: await sha256(token),
      identityKey,
      paymail: names.paymail,
      handle: names.handle,
      epoch: await this.d.store.getEpoch(identityKey),
      authTime: now,
      createdAt: now,
      rotatedAt: now,
      expiresAt: now + HUB_SESSION_MS,
    };
    await this.d.store.createSession(s);

    // Continue the sign-in the site started. prompt is dropped: the wallet sign-in just happened.
    let next = '/';
    if (b.authorize && typeof b.authorize === 'object') {
      const q = new URLSearchParams();
      for (const k of PARAMS) {
        const v = (b.authorize as Record<string, unknown>)[k];
        if (typeof v === 'string' && k !== 'prompt') q.set(k, v);
      }
      if (this.checkAuthorize(q).ok) next = `/authorize?${q}`;
    }
    return json({ ok: true, identityKey, paymail: names.paymail, handle: names.handle, next }, 200, { 'set-cookie': this.cookie(token, HUB_SESSION_MS / 1000) });
  }

  /** For the hub's own pages. */
  clientName(clientId: string | null | undefined): string | null {
    return this.d.registry.get(clientId)?.name ?? null;
  }
  get registry(): Registry {
    return this.d.registry;
  }
}
