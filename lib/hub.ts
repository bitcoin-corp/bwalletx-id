/**
 * The b*X single sign-on hub: authorization code + PKCE (S256) for first-party b*X sites.
 *
 * Rule zero: a hub session proves WHO you are. It never authorises spending; every payment, signature or transfer
 * still goes through a bWalletX approval sheet.
 *
 * Every handler takes a Web Request and returns a Response, so tests drive them directly.
 */
import { ProtoWallet } from '@bsv/sdk';
import { isIdentityKey } from '@bwalletx/connect/server';
import {
  HUB_SIGNIN_PROTOCOL,
  checkLogoutHint,
  hubSignInMessage,
  isPkceChallenge,
  isPkceVerifier,
  parseHubSignInMessage,
  pkceChallenge,
  safeReturnTo,
} from '@bwalletx/connect/sso';
import { CHALLENGE_TTL_MS, CODE_TTL_MS, DEFAULT_RATE_LIMITS, HUB_SESSION_MS, ID_TOKEN_SECONDS, MAX_SESSIONS_PER_IDENTITY, RATE_WINDOW_MS, ROTATE_AFTER_MS, type RateLimits } from './config';
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
  /** Requests per minute per IP and per identity key. Defaults: DEFAULT_RATE_LIMITS. */
  limits?: Partial<RateLimits>;
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
  private async limited(route: keyof RateLimits, who: { req?: Request; identityKey?: string }): Promise<Response | null> {
    const max = this.d.limits?.[route] ?? DEFAULT_RATE_LIMITS[route];
    const now = this.now();
    const buckets: string[] = [];
    if (who.req) buckets.push(`${route}:ip:${(await sha256(this.clientIp(who.req))).slice(0, 22)}`);
    if (who.identityKey) buckets.push(`${route}:key:${who.identityKey}`);
    for (const b of buckets) {
      const { hits, resetAt } = await this.d.store.hit(b, RATE_WINDOW_MS, now);
      if (hits > max) {
        const retry = String(Math.max(1, Math.ceil((resetAt - now) / 1000)));
        return json({ error: 'rate_limited', error_description: 'Too many requests. Try again in a minute.' }, 429, { 'retry-after': retry });
      }
    }
    return null;
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
    const slow = await this.limited('token', { req });
    if (slow) return slow;
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
    const perKey = await this.limited('token', { identityKey: rec.identityKey });
    if (perKey) return perKey;
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
    const slow = await this.limited('epoch', { req });
    if (slow) return slow;
    const sid = new URL(req.url).searchParams.get('sid') ?? '';
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(sid)) return json({ error: 'bad sid' }, 400);
    const s = await this.d.store.getSession(sid);
    if (!s) return json({ sid, active: false, epoch: null });
    const perKey = await this.limited('epoch', { identityKey: s.identityKey });
    if (perKey) return perKey;
    const current = await this.d.store.getEpoch(s.identityKey);
    return json({ sid, active: s.expiresAt > this.now() && s.epoch === current, epoch: current });
  }

  /**
   * /logout?client_id=&redirect_uri=[&logout_hint=] : "Sign out of all b*X sites". Ends the hub session and bumps the
   * identity's epoch, so every site's session ends within 5 minutes.
   *
   * A foreign page must not be able to sign people out of everything with a link or an auto-submitting form, so:
   *   GET  with a logout_hint from a b*X site's server (logoutHint(sid): only the hub and that site know the sid)
   *        signs out at once; any other GET shows a confirm page with a POST button.
   *   POST (the confirm button) needs Origin: <the hub>. Cross-site POSTs are refused.
   */
  async logout(req: Request): Promise<Response> {
    if (req.method === 'POST') {
      if (!this.originOk(req)) return page({ title: 'Not signed out', body: 'That sign-out request did not come from bWalletX. Nothing was changed.', status: 403 });
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
    if (await checkLogoutHint(q.get('logout_hint'), s.sid, Math.floor(this.now() / 1000))) {
      return this.signOutEverywhere(req, q.get('client_id'), q.get('redirect_uri'));
    }
    const client = this.d.registry.get(q.get('client_id'));
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

  /**
   * POST /api/challenge (the hub's own sign-in page only). No identity key needed: one wallet sheet.
   * The wallet signs under the hub's own protocol, HUB_SIGNIN_PROTOCOL [2, 'bwalletx id sign in'], which bWalletX only
   * accepts from id.bwalletx.com, and the message names the hub and the challenge.
   */
  async challenge(req: Request): Promise<Response> {
    if (req.method !== 'POST') return json({ error: 'POST only' }, 405);
    if (!this.originOk(req)) return json({ error: 'Wrong origin' }, 403);
    const slow = await this.limited('challenge', { req });
    if (slow) return slow;
    const nonce = randomToken(16);
    const now = this.now();
    const expiresAt = now + CHALLENGE_TTL_MS;
    const message = hubSignInMessage(this.d.issuer, nonce, now);
    await this.d.store.putChallenge(nonce, { identityKey: '', origin: this.d.issuer, message, expiresAt });
    return json({ nonce, message, protocolID: HUB_SIGNIN_PROTOCOL, keyID: nonce, expiresAt });
  }

  /**
   * The proven identity key, or null. The challenge is taken (deleted) first, so it works once. It must be this hub's,
   * unexpired, its message exactly "Sign in to <hub host> · challenge <nonce> · <time>", and the signature must verify
   * under HUB_SIGNIN_PROTOCOL with keyID = nonce for the claimed key.
   */
  private async checkSignIn(b: { identityKey?: unknown; nonce?: unknown; signature?: unknown }): Promise<string | null> {
    if (typeof b.nonce !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(b.nonce)) return null;
    const nonce = b.nonce;
    const c = await this.d.store.takeChallenge(nonce);
    if (!c || this.now() > c.expiresAt || c.origin !== this.d.issuer) return null;
    const m = parseHubSignInMessage(c.message);
    if (!m || m.host !== new URL(this.d.issuer).host || m.nonce !== nonce || c.message !== hubSignInMessage(this.d.issuer, nonce, m.issuedAt)) return null;
    if (!isIdentityKey(b.identityKey)) return null;
    const identityKey = b.identityKey.toLowerCase();
    if (c.identityKey && c.identityKey !== identityKey) return null;
    const sig = b.signature;
    if (!Array.isArray(sig) || sig.length < 8 || sig.length > 80 || !sig.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) return null;
    try {
      const { valid } = await new ProtoWallet('anyone').verifySignature({
        protocolID: HUB_SIGNIN_PROTOCOL,
        keyID: nonce,
        counterparty: identityKey,
        data: Array.from(new TextEncoder().encode(c.message)),
        signature: sig as number[],
      });
      return valid ? identityKey : null;
    } catch {
      return null; // @bsv/sdk throws on a bad signature instead of returning valid: false
    }
  }

  /**
   * POST /api/verify { identityKey, nonce, signature, authorize? } → hub session cookie + { next }.
   * A fresh wallet sign-in in a browser that already has a session for the same identity keeps that session (and its
   * sid, so the other b*X sites stay signed in) and refreshes auth_time. Only "Sign out of all" ends sessions.
   */
  async verify(req: Request): Promise<Response> {
    if (req.method !== 'POST') return json({ error: 'POST only' }, 405);
    if (!this.originOk(req)) return json({ error: 'Wrong origin' }, 403);
    const slow = await this.limited('verify', { req });
    if (slow) return slow;
    let b: { identityKey?: unknown; nonce?: unknown; signature?: unknown; authorize?: unknown };
    try {
      b = (await req.json()) as typeof b;
    } catch {
      return json({ error: 'Unreadable body' }, 400);
    }
    const identityKey = await this.checkSignIn(b ?? {});
    if (!identityKey) return json({ error: 'That signature was not accepted. Start again.' }, 401);
    // Counted per key only once the signature is good, so nobody can lock a stranger out by naming their key.
    const perKey = await this.limited('verify', { identityKey });
    if (perKey) return perKey;

    const names = (await this.d.lookup?.(identityKey)) ?? { paymail: null, handle: null };
    const now = this.now();
    const token = randomToken(32);
    const old = await this.currentSession(req);
    if (old && old.identityKey === identityKey) {
      // Same wallet, same browser: keep the sid, new cookie token, fresh auth_time.
      await this.d.store.updateSession(old.sid, {
        tokenHash: await sha256(token),
        rotatedAt: now,
        expiresAt: now + HUB_SESSION_MS,
        authTime: now,
        paymail: names.paymail,
        handle: names.handle,
      });
    } else {
      // A different wallet in this browser: the previous one is signed out of the hub here (its own sites follow).
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

    // Continue the sign-in the site started. prompt is dropped: the wallet sign-in just happened.
    let next = '/';
    if (b.authorize && typeof b.authorize === 'object') {
      const q = new URLSearchParams();
      for (const k of PARAMS) {
        const v = (b.authorize as Record<string, unknown>)[k];
        if (typeof v === 'string' && k !== 'prompt') q.set(k, v);
      }
      if (this.checkAuthorize(q).ok) next = safeReturnTo(`/authorize?${q}`, '/');
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
