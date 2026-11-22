/**
 * The b*X single sign-on hub: authorization code + PKCE (S256) for first-party b*X sites.
 *
 * Rule zero: a hub session proves WHO you are. It never authorises spending; every payment, signature or transfer
 * still goes through a bWalletX approval sheet.
 *
 * Sign-in is v2 (docs/HUB-SIGNIN-V2.md): the hub page shows a short code; the wallet, which has the hub's address
 * built in, signs and POSTs straight to /api/wallet-signin. The hub never accepts a wallet signature that a web page
 * or a relay hands it.
 *
 * Every handler takes a Web Request and returns a Response, so tests drive them directly.
 */
import { ProtoWallet } from '@bsv/sdk';
import { isIdentityKey } from '@bwalletx/connect/server';
import {
  HUB_SIGNIN_PROTOCOL,
  USER_CODE_ALPHABET,
  checkLogoutHint,
  hubSignInMessage,
  isHubRequestId,
  isHubUserCode,
  isPkceChallenge,
  isPkceVerifier,
  parseHubSignInMessage,
  pkceChallenge,
  safeReturnTo,
  sameString,
} from '@bwalletx/connect/sso';
import { authenticateClient, clientSecret, type ClientAuth } from './clients';
import {
  CODE_TTL_MS,
  DEFAULT_RATE_LIMITS,
  HUB_SESSION_MS,
  ID_TOKEN_SECONDS,
  MAX_SESSIONS_PER_IDENTITY,
  RATE_WINDOW_MS,
  ROTATE_AFTER_MS,
  SIGNIN_MAX_ATTEMPTS,
  SIGNIN_POLL_SECONDS,
  SIGNIN_TTL_MS,
  type RateLimits,
} from './config';
import { randomToken, readCookie, sha256 } from './crypto';
import { confirmLogoutPage, errorPage, page } from './html';
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
  /** Requests per minute (see RateLimits). Defaults: DEFAULT_RATE_LIMITS. */
  limits?: Partial<RateLimits>;
  now?: () => number;
  /**
   * SSO_CLIENT_KEY: site secrets are derived from it (lib/clients.ts). With it, /token and /session/epoch need client
   * auth. Without it (development only; production refuses to start) they accept unauthenticated calls.
   */
  clientKey?: string;
  /** http(s) origins allowed to POST to /api/wallet-signin (a web wallet). Native apps and extensions send none / non-web. */
  walletOrigins?: string[];
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
  /** The browser's pending sign-in cookie (v2). __Host- on https. */
  get signinCookieName(): string {
    return this.secure ? '__Host-bwx_signin' : 'bwx_signin';
  }
  private signinCookie(secret: string, maxAgeS: number): string {
    return [`${this.signinCookieName}=${secret}`, 'Path=/', `Max-Age=${maxAgeS}`, 'HttpOnly', 'SameSite=Lax', ...(this.secure ? ['Secure'] : [])].join('; ');
  }
  /** The session the hub cookie points at (live or not). */
  private async cookieSession(req: Request): Promise<HubSession | null> {
    const tok = readCookie(req.headers.get('cookie'), this.cookieName);
    if (!tok || tok.length > 128) return null;
    return this.d.store.getSessionByToken(await sha256(tok));
  }

  /** The hub session for this request, if it exists, is unexpired and was not signed out everywhere. */
  async currentSession(req: Request): Promise<HubSession | null> {
    const s = await this.cookieSession(req);
    return s && (await this.live(s)) ? s : null;
  }

  /**
   * The client's IP. On Vercel, x-vercel-forwarded-for / x-real-ip are set by the platform (a client can't forge
   * them); x-forwarded-for is the fallback for other hosts behind a proxy that overwrites it.
   */
  private clientIp(req: Request): string {
    const h = req.headers;
    const v = h.get('x-vercel-forwarded-for') ?? h.get('x-real-ip') ?? h.get('x-forwarded-for')?.split(',')[0];
    return (v ?? '').trim().slice(0, 64) || 'unknown';
  }

  /**
   * Fixed-window limits (1 minute) in the store, so they hold across instances. One bucket per IP (hashed: no raw IPs
   * stored) and, where the request names one, per identity key. 429 + Retry-After when a bucket is over.
   */
  private async limited(route: keyof RateLimits, who: { req?: Request; identityKey?: string; clientId?: string }): Promise<Response | null> {
    const max = this.d.limits?.[route] ?? DEFAULT_RATE_LIMITS[route];
    const now = this.now();
    for (const b of await this.buckets(route, who)) {
      const { hits, resetAt } = await this.d.store.hit(b, RATE_WINDOW_MS, now);
      if (hits > max) return this.tooMany(resetAt, now);
    }
    return null;
  }
  /** Over the limit already? (Counts nothing: for buckets that only count failures.) */
  private async over(route: keyof RateLimits, who: { req?: Request }): Promise<Response | null> {
    const max = this.d.limits?.[route] ?? DEFAULT_RATE_LIMITS[route];
    const now = this.now();
    for (const b of await this.buckets(route, who)) {
      const { hits, resetAt } = await this.d.store.peek(b, RATE_WINDOW_MS, now);
      if (hits >= max) return this.tooMany(resetAt, now);
    }
    return null;
  }
  /** Count a failure in a failures-only bucket. */
  private async failed(route: keyof RateLimits, who: { req?: Request }): Promise<void> {
    for (const b of await this.buckets(route, who)) await this.d.store.hit(b, RATE_WINDOW_MS, this.now());
  }
  private async buckets(route: string, who: { req?: Request; identityKey?: string; clientId?: string }): Promise<string[]> {
    const out: string[] = [];
    if (who.req) out.push(`${route}:ip:${(await sha256(this.clientIp(who.req))).slice(0, 22)}`);
    if (who.identityKey) out.push(`${route}:key:${who.identityKey}`);
    if (who.clientId) out.push(`${route}:client:${who.clientId}`);
    return out;
  }
  private tooMany(resetAt: number, now: number): Response {
    const retry = String(Math.max(1, Math.ceil((resetAt - now) / 1000)));
    return json({ error: 'rate_limited', error_description: 'Too many requests. Try again in a minute.' }, 429, { 'retry-after': retry });
  }

  private clientAuth(req: Request, form?: Record<string, string>): Promise<ClientAuth> {
    return authenticateClient(req, this.d.registry, this.d.clientKey, form);
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

  /**
   * POST /token (site server → hub): code + code_verifier + client_id + redirect_uri → signed ID token.
   * Client auth (Basic or client_secret_post) is required when the hub has a client key. Limits: failed attempts per IP
   * (good exchanges from a site's shared egress IP never count), all exchanges per client; per identity key only for
   * unauthenticated callers (development).
   */
  async token(req: Request): Promise<Response> {
    if (req.method !== 'POST') return oauthError('invalid_request', 'POST only', 405);
    const slow = await this.over('token', { req });
    if (slow) return slow;
    const fail = async (r: Response) => {
      await this.failed('token', { req });
      return r;
    };
    let b: Record<string, string> = {};
    try {
      const ct = req.headers.get('content-type') ?? '';
      if (ct.includes('application/json')) b = (await req.json()) as Record<string, string>;
      else b = Object.fromEntries(new URLSearchParams(await req.text()));
    } catch {
      return fail(oauthError('invalid_request', 'Unreadable body'));
    }
    const auth = await this.clientAuth(req, b);
    if (!auth.ok) return fail(oauthError('invalid_client', 'Client authentication failed', 401));
    if (b.grant_type !== 'authorization_code') return fail(oauthError('unsupported_grant_type', 'Only authorization_code'));
    const client = auth.authenticated ? auth.client : this.d.registry.get(typeof b.client_id === 'string' ? b.client_id : null);
    if (!client) return fail(oauthError('invalid_client', 'Unknown client', 401));
    if (auth.authenticated && b.client_id !== undefined && b.client_id !== client.client_id) return fail(oauthError('invalid_client', 'client_id does not match the credentials', 401));
    if (auth.authenticated) {
      const busy = await this.limited('clientToken', { clientId: client.client_id });
      if (busy) return busy;
    }
    if (typeof b.code !== 'string' || b.code.length > 256) return fail(oauthError('invalid_grant', 'No code'));
    // Taken (deleted) before any other check: a code works once, even if this attempt fails.
    const rec = await this.d.store.takeCode(await sha256(b.code));
    if (!rec) return fail(oauthError('invalid_grant', 'Unknown or already used code'));
    if (rec.expiresAt <= this.now()) return fail(oauthError('invalid_grant', 'Code expired'));
    if (rec.clientId !== client.client_id) return fail(oauthError('invalid_grant', 'Code was issued to another client'));
    if (rec.redirectUri !== b.redirect_uri) return fail(oauthError('invalid_grant', 'redirect_uri does not match'));
    if (!isPkceVerifier(b.code_verifier) || (await pkceChallenge(b.code_verifier)) !== rec.codeChallenge) {
      return fail(oauthError('invalid_grant', 'PKCE verification failed'));
    }
    if (!auth.authenticated) {
      const perKey = await this.limited('token', { identityKey: rec.identityKey });
      if (perKey) return perKey;
    }
    const s = await this.d.store.getSession(rec.sid);
    if (!s || !(await this.live(s))) return fail(oauthError('invalid_grant', 'The hub session has ended'));
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

  /**
   * Session epochs for sites: GET ?sid= → { sid, active, epoch }, or POST { sids: [...] } (1–100) → { sessions: [...] }.
   * Authenticated (Basic) when the hub has a client key, limited per client. Unauthenticated calls (development only)
   * are limited per IP and per identity key; the per-key limit never applies to an authenticated site, so nobody can
   * starve the checks for someone else's sessions.
   */
  async epoch(req: Request): Promise<Response> {
    const auth = await this.clientAuth(req);
    if (!auth.ok) {
      const slow = await this.over('epoch', { req });
      if (slow) return slow;
      await this.failed('epoch', { req });
      return oauthError('invalid_client', 'Client authentication failed', 401);
    }
    const slow = auth.authenticated ? await this.limited('clientEpoch', { clientId: auth.client.client_id }) : await this.limited('epoch', { req });
    if (slow) return slow;
    let sids: string[];
    let batch = false;
    if (req.method === 'POST') {
      batch = true;
      let b: { sids?: unknown };
      try {
        b = (await req.json()) as typeof b;
      } catch {
        return json({ error: 'Unreadable body' }, 400);
      }
      if (!Array.isArray(b?.sids) || b.sids.length < 1 || b.sids.length > 100) return json({ error: 'sids: 1 to 100 session ids' }, 400);
      sids = b.sids as string[];
    } else {
      sids = [new URL(req.url).searchParams.get('sid') ?? ''];
    }
    if (!sids.every((x) => typeof x === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(x))) return json({ error: 'bad sid' }, 400);
    const out: { sid: string; active: boolean; epoch: number | null }[] = [];
    for (const sid of [...new Set(sids)]) {
      const s = await this.d.store.getSession(sid);
      if (!s) {
        out.push({ sid, active: false, epoch: null });
        continue;
      }
      if (!auth.authenticated) {
        const perKey = await this.limited('epoch', { identityKey: s.identityKey });
        if (perKey) return perKey;
      }
      const current = await this.d.store.getEpoch(s.identityKey);
      out.push({ sid, active: s.expiresAt > this.now() && s.epoch === current, epoch: current });
    }
    return batch ? json({ sessions: out }) : json(out[0]);
  }

  /**
   * /logout?client_id=&redirect_uri=[&logout_hint=] : "Sign out of all b*X sites". Ends the hub session and bumps the
   * identity's epoch, so every site's session ends within 5 minutes.
   *
   * A foreign page must not be able to sign people out of everything with a link or an auto-submitting form, so:
   *   GET  with a logout_hint from a b*X site's server (an HMAC with that site's client secret over the sid, for the
   *        client_id in the link) signs out at once; any other GET shows a confirm page with a POST button.
   *   POST (the confirm button) needs Origin: <the hub>, and Sec-Fetch-Site: same-origin when the browser sends it.
   */
  async logout(req: Request): Promise<Response> {
    if (req.method === 'POST') {
      if (!this.sameOriginPost(req)) return page({ title: 'Not signed out', body: 'That sign-out request did not come from bWalletX. Nothing was changed.', status: 403 });
      let f: URLSearchParams;
      try {
        f = new URLSearchParams(await req.text());
      } catch {
        f = new URLSearchParams();
      }
      return this.signOutEverywhere(req, f.get('client_id'), f.get('redirect_uri'));
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return json({ error: 'GET or POST only' }, 405);
    const q = new URL(req.url).searchParams;
    const s = await this.cookieSession(req);
    if (!s) return this.signOutEverywhere(req, q.get('client_id'), q.get('redirect_uri')); // nothing to end here
    const client = this.d.registry.get(q.get('client_id'));
    if (client && this.d.clientKey) {
      const c = { clientId: client.client_id, clientSecret: await clientSecret(this.d.clientKey, client) };
      if (await checkLogoutHint(q.get('logout_hint'), s.sid, c, Math.floor(this.now() / 1000))) {
        return this.signOutEverywhere(req, q.get('client_id'), q.get('redirect_uri'));
      }
    }
    const to = q.get('redirect_uri');
    return confirmLogoutPage({
      who: s.paymail ?? s.handle ?? `${s.identityKey.slice(0, 8)}…`,
      clientId: client && this.d.registry.postLogoutAllowed(client, to) ? client.client_id : null,
      redirectUri: client && this.d.registry.postLogoutAllowed(client, to) ? to : null,
    });
  }

  private async signOutEverywhere(req: Request, clientId: string | null, to: string | null): Promise<Response> {
    const s = await this.cookieSession(req);
    if (s) {
      await this.d.store.deleteSession(s.sid);
      await this.d.store.bumpEpoch(s.identityKey);
    }
    const clear = this.cookie('', 0);
    const client = this.d.registry.get(clientId);
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
  /** A POST from the hub's own pages: Origin is the hub, and Sec-Fetch-Site (when sent) is same-origin. */
  private sameOriginPost(req: Request): boolean {
    const sfs = req.headers.get('sec-fetch-site');
    return this.originOk(req) && (sfs === null || sfs === 'same-origin');
  }

  /** A user code from the RFC 8628 alphabet (no vowels), 8 letters, without modulo bias. */
  private userCode(): string {
    const out: string[] = [];
    while (out.length < 8) {
      for (const b of globalThis.crypto.getRandomValues(new Uint8Array(16))) {
        if (b < 240 && out.length < 8) out.push(USER_CODE_ALPHABET[b % 20]);
      }
    }
    return `${out.slice(0, 4).join('')}-${out.slice(4).join('')}`;
  }

  /**
   * POST /api/signin/start (the hub's own sign-in page) { authorize? } → { requestId, userCode, walletLink, interval,
   * expiresAt, site } and the browser's pending sign-in cookie (__Host-bwx_signin, HttpOnly, 5 minutes). One pending
   * sign-in per browser: starting again replaces it.
   */
  async signInStart(req: Request): Promise<Response> {
    if (req.method !== 'POST') return json({ error: 'POST only' }, 405);
    if (!this.sameOriginPost(req)) return json({ error: 'Wrong origin' }, 403);
    const slow = await this.limited('start', { req });
    if (slow) return slow;
    let b: { authorize?: unknown };
    try {
      b = (await req.json()) as typeof b;
    } catch {
      return json({ error: 'Unreadable body' }, 400);
    }
    let authorize: Record<string, string> | null = null;
    let clientId: string | null = null;
    if (b?.authorize && typeof b.authorize === 'object') {
      const q = new URLSearchParams();
      for (const k of PARAMS) {
        const v = (b.authorize as Record<string, unknown>)[k];
        if (typeof v === 'string' && k !== 'prompt') q.set(k, v); // prompt is spent: the wallet sign-in is happening now
      }
      const c = this.checkAuthorize(q);
      if (!c.ok) return json({ error: 'That sign-in link is not valid. Go back to the site and try again.' }, 400);
      authorize = Object.fromEntries(q);
      clientId = c.client.client_id;
    }
    const now = this.now();
    for (let i = 0; i < 4; i++) {
      const requestId = randomToken(16);
      const secret = randomToken(32);
      const userCode = this.userCode();
      const message = hubSignInMessage({ hub: this.d.issuer, requestId, userCode, clientId, issuedAt: now });
      const ok = await this.d.store.putPendingSignIn({
        requestId,
        browserHash: await sha256(secret),
        userCode,
        clientId,
        authorize,
        message,
        status: 'pending',
        identityKey: null,
        attempts: 0,
        createdAt: now,
        expiresAt: now + SIGNIN_TTL_MS,
      });
      if (!ok) continue; // a clash on the id or code: try new ones
      return json(
        {
          requestId,
          userCode,
          walletLink: `bwalletx://hub-signin?r=${requestId}`,
          interval: SIGNIN_POLL_SECONDS,
          expiresAt: now + SIGNIN_TTL_MS,
          site: clientId ? this.d.registry.get(clientId)?.name ?? null : null,
        },
        200,
        { 'set-cookie': this.signinCookie(secret, SIGNIN_TTL_MS / 1000) },
      );
    }
    return json({ error: 'Could not start a sign-in. Try again.' }, 503);
  }

  /**
   * The wallet endpoint (docs/HUB-SIGNIN-V2.md). Wallets call it directly over TLS; web pages may not (an http(s)
   * Origin is refused unless it is a configured web wallet). Rate limited per IP, every call.
   *   GET  ?r=<request id> or ?code=<user code> → what to show and the exact message to sign
   *   POST { requestId, userCode, identityKey, signature } → approves the pending sign-in
   */
  async walletSignIn(req: Request): Promise<Response> {
    const origin = req.headers.get('origin');
    if (origin !== null && (origin === 'null' || /^https?:/i.test(origin)) && !(this.d.walletOrigins ?? []).includes(origin)) {
      return json({ error: 'Web pages cannot approve hub sign-ins. Approve it in bWalletX.' }, 403);
    }
    const slow = await this.limited('wallet', { req });
    if (slow) return slow;
    const now = this.now();
    if (req.method === 'GET') {
      const q = new URL(req.url).searchParams;
      const r = q.get('r');
      const code = q.get('code');
      const p = isHubRequestId(r) ? await this.d.store.getPendingSignIn(r) : isHubUserCode(code) ? await this.d.store.getPendingSignInByCode(code) : null;
      if (!p || p.status !== 'pending' || p.expiresAt <= now) return json({ error: 'not_found', error_description: 'No sign-in is waiting for that code.' }, 404);
      const m = parseHubSignInMessage(p.message);
      return json({
        requestId: p.requestId,
        userCode: p.userCode,
        hub: this.d.issuer,
        site: p.clientId ? { clientId: p.clientId, name: this.d.registry.get(p.clientId)?.name ?? p.clientId } : null,
        message: p.message,
        protocolID: HUB_SIGNIN_PROTOCOL,
        keyID: p.requestId,
        issuedAt: m?.issuedAt ?? p.createdAt,
        expiresAt: p.expiresAt,
      });
    }
    if (req.method !== 'POST') return json({ error: 'GET or POST only' }, 405);
    let b: { requestId?: unknown; userCode?: unknown; identityKey?: unknown; signature?: unknown };
    try {
      b = (await req.json()) as typeof b;
    } catch {
      return json({ error: 'Unreadable body' }, 400);
    }
    if (!isHubRequestId(b?.requestId)) return json({ error: 'not_found' }, 404);
    const p = await this.d.store.getPendingSignIn(b.requestId);
    if (!p) return json({ error: 'not_found' }, 404);
    if (p.expiresAt <= now) return json({ error: 'expired', error_description: 'That code has expired. Start again on the page.' }, 410);
    if (p.status !== 'pending') return json({ error: 'not_pending', error_description: 'That sign-in is already finished.' }, 409);
    const bad = async () => {
      await this.d.store.failPendingSignIn(p.requestId, SIGNIN_MAX_ATTEMPTS);
      return json({ error: 'not_accepted', error_description: 'That approval was not accepted.' }, 401);
    };
    if (!isHubUserCode(b.userCode) || !sameString(b.userCode, p.userCode)) return bad();
    // The stored text must be exactly the v2 message for this hub, request, code and site (defence in depth).
    const m = parseHubSignInMessage(p.message);
    if (
      !m ||
      m.host !== new URL(this.d.issuer).host ||
      m.requestId !== p.requestId ||
      m.userCode !== p.userCode ||
      m.clientId !== p.clientId ||
      p.message !== hubSignInMessage({ hub: this.d.issuer, requestId: p.requestId, userCode: p.userCode, clientId: p.clientId, issuedAt: m.issuedAt })
    ) {
      return bad();
    }
    if (!isIdentityKey(b.identityKey)) return bad();
    const identityKey = b.identityKey.toLowerCase();
    const sig = b.signature;
    if (!Array.isArray(sig) || sig.length < 8 || sig.length > 80 || !sig.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) return bad();
    let valid = false;
    try {
      ({ valid } = await new ProtoWallet('anyone').verifySignature({
        protocolID: HUB_SIGNIN_PROTOCOL,
        keyID: p.requestId,
        counterparty: identityKey,
        data: Array.from(new TextEncoder().encode(p.message)),
        signature: sig as number[],
      }));
    } catch {
      valid = false; // @bsv/sdk throws on a bad signature instead of returning valid: false
    }
    if (!valid) return bad();
    if (!(await this.d.store.approvePendingSignIn(p.requestId, identityKey, now))) return json({ error: 'not_pending' }, 409);
    return json({ ok: true, site: p.clientId ? this.d.registry.get(p.clientId)?.name ?? null : null });
  }

  /**
   * POST /api/signin/poll (the hub page, with its pending sign-in cookie) → { status: 'pending' | 'approved' |
   * 'expired' | 'failed' }. On 'approved' (once): the hub session cookie, the pending cookie cleared, and `next`.
   */
  async signInPoll(req: Request): Promise<Response> {
    if (req.method !== 'POST') return json({ error: 'POST only' }, 405);
    if (!this.sameOriginPost(req)) return json({ error: 'Wrong origin' }, 403);
    const slow = await this.limited('poll', { req });
    if (slow) return slow;
    const clear = this.signinCookie('', 0);
    const secret = readCookie(req.headers.get('cookie'), this.signinCookieName);
    if (!secret || secret.length > 128) return json({ status: 'expired' }, 200, { 'set-cookie': clear });
    const h = await sha256(secret);
    const now = this.now();
    const taken = await this.d.store.takeApprovedSignIn(h, now);
    if (taken && taken.identityKey) {
      const { token, names } = await this.establishSession(req, taken.identityKey);
      const next = taken.authorize && this.checkAuthorize(new URLSearchParams(taken.authorize)).ok ? safeReturnTo(`/authorize?${new URLSearchParams(taken.authorize)}`, '/') : '/';
      const res = json({ status: 'approved', identityKey: taken.identityKey, paymail: names.paymail, handle: names.handle, next });
      res.headers.append('set-cookie', this.cookie(token, HUB_SESSION_MS / 1000));
      res.headers.append('set-cookie', clear);
      return res;
    }
    const p = await this.d.store.getPendingSignInByBrowser(h);
    if (!p || p.status === 'used' || p.expiresAt <= now) return json({ status: 'expired' }, 200, { 'set-cookie': clear });
    if (p.status === 'failed') return json({ status: 'failed' }, 200, { 'set-cookie': clear });
    return json({ status: 'pending', interval: SIGNIN_POLL_SECONDS, expiresAt: p.expiresAt, userCode: p.userCode });
  }

  /**
   * The hub session for a proven identity in this browser. A fresh wallet sign-in in a browser that already has a
   * session for the same identity keeps that session (and its sid, so the other b*X sites stay signed in) and
   * refreshes auth_time; a different identity replaces it. Only "Sign out of all" ends sessions elsewhere.
   */
  private async establishSession(req: Request, identityKey: string): Promise<{ token: string; names: Names }> {
    const names = (await this.d.lookup?.(identityKey)) ?? { paymail: null, handle: null };
    const now = this.now();
    const token = randomToken(32);
    const old = await this.currentSession(req);
    if (old && old.identityKey === identityKey) {
      await this.d.store.updateSession(old.sid, {
        tokenHash: await sha256(token),
        rotatedAt: now,
        expiresAt: now + HUB_SESSION_MS,
        authTime: now,
        paymail: names.paymail,
        handle: names.handle,
      });
    } else {
      if (old) await this.d.store.deleteSession(old.sid);
      await this.d.store.createSession({
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
      });
      // At most MAX_SESSIONS_PER_IDENTITY hub sessions per identity; the oldest go first.
      await this.d.store.evictSessions(identityKey, MAX_SESSIONS_PER_IDENTITY);
    }
    return { token, names };
  }

  /** For the hub's own pages. */
  clientName(clientId: string | null | undefined): string | null {
    return this.d.registry.get(clientId)?.name ?? null;
  }
  get registry(): Registry {
    return this.d.registry;
  }
}
