import { PGlite } from '@electric-sql/pglite';
import { PrivateKey, ProtoWallet } from '@bsv/sdk';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Hub } from '@/lib/hub';
import { newPrivateJwk, signerFromJwk, type Signer } from '@/lib/keys';
import { Registry, type Client } from '@/lib/registry';
import { memoryHubStore } from '@/lib/store/memory';
import { pgHubStore } from '@/lib/store/postgres';
import type { HubStore } from '@/lib/store/types';
import type { RateLimits } from '@/lib/config';
import { HUB_SIGNIN_PROTOCOL, clientBasicAuth, logoutHint, pkceChallenge, randomToken } from '@bwalletx/connect/sso';
import { clientSecret } from '@/lib/clients';

export const ISSUER = 'https://id.example';
export const SITE = 'https://site.example';
export const CALLBACK = `${SITE}/sso/callback`;

export const CLIENTS: Client[] = [
  { client_id: 'site', name: 'Site', tier: 'standard', redirect_uris: [CALLBACK] },
  { client_id: 'vault', name: 'Vault', tier: 'high', redirect_uris: ['https://vault.example/sso/callback'] },
];

export type StoreKind = 'memory' | 'postgres';

export const MIGRATION = readFileSync(new URL('../supabase/migrations/0001_sso.sql', import.meta.url), 'utf8');
export const MIGRATION_2 = readFileSync(new URL('../supabase/migrations/0002_signin_v2.sql', import.meta.url), 'utf8');

/** The hub's client key in tests (real ones come from env). Site secrets are derived from it. */
export const CLIENT_KEY = 'test-client-key-'.padEnd(48, 'k');
export const secretFor = (clientId: string) => clientSecret(CLIENT_KEY, { client_id: clientId });
/** The same derivation as lib/clients.ts, synchronously (node:crypto), for building requests inline. */
export const secretForSync = (clientId: string, version = 1) =>
  createHmac('sha256', CLIENT_KEY).update(`bwx-client-secret:v${version}:${clientId}`).digest('base64url');

/** A fresh PGlite with Supabase's API roles and the hub migration applied (as the superuser). */
export async function migratedDb(): Promise<PGlite> {
  const db = new PGlite();
  // Supabase's API roles, so the migration's revoke block runs exactly as on the server.
  await db.exec(`create role anon; create role authenticated;`);
  await db.exec(MIGRATION);
  await db.exec(MIGRATION_2);
  return db;
}

export async function makeStore(kind: StoreKind): Promise<HubStore> {
  if (kind === 'memory') return memoryHubStore();
  const db = await migratedDb();
  // Every store query runs as the hub's least-privilege role, exactly as in production.
  await db.exec(`set role sso_hub`);
  return pgHubStore((sql, params) => db.query(sql, params));
}

export interface Rig {
  hub: Hub;
  store: HubStore;
  signer: Signer;
  clock: { t: number };
}

/** Limits high enough that ordinary tests never meet them; the rate-limit tests pass the real defaults. */
export const RELAXED: RateLimits = { start: 1000, poll: 1000, wallet: 1000, token: 1000, epoch: 1000, clientToken: 1000, clientEpoch: 1000 };

export interface RigOptions {
  /** The hub's client key; null = development mode with no client auth. Default CLIENT_KEY. */
  clientKey?: string | null;
  walletOrigins?: string[];
}

export async function rig(kind: StoreKind, signer?: Signer, limits: Partial<RateLimits> = RELAXED, o: RigOptions = {}): Promise<Rig> {
  const clock = { t: Date.now() };
  const store = await makeStore(kind);
  const s = signer ?? (await signerFromJwk(await newPrivateJwk()));
  const hub = new Hub({
    issuer: ISSUER,
    registry: new Registry(CLIENTS, { dev: false }),
    store,
    signer: s,
    lookup: async () => ({ paymail: 'alice@bwalletx.com', handle: '$alice' }),
    limits: { ...RELAXED, ...limits },
    now: () => clock.t,
    clientKey: o.clientKey === undefined ? CLIENT_KEY : (o.clientKey ?? undefined),
    walletOrigins: o.walletOrigins,
  });
  return { hub, store, signer: s, clock };
}

/** The shared sign-in protocol every site uses. The hub must NOT accept signatures made under it. */
export const SHARED_LOGIN: [2, string] = [2, 'bwallet sign in'];

export async function signature(root: PrivateKey, message: string, keyID: string, protocolID: [2, string] = HUB_SIGNIN_PROTOCOL): Promise<number[]> {
  const { signature } = await new ProtoWallet(root).createSignature({ protocolID, keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(message)) });
  return Array.from(signature);
}

export function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(ISSUER + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: ISSUER, 'x-real-ip': '203.0.113.1', ...headers }, body: JSON.stringify(body) });
}

type StartBody = { requestId: string; userCode: string; walletLink: string; interval: number; expiresAt: number };

/** The hub page starting a sign-in (POST /api/signin/start). Returns the browser's pending sign-in cookie. */
export async function startSignIn(hub: Hub, authorize?: Record<string, string>, headers: Record<string, string> = {}) {
  const res = await hub.signInStart(post('/api/signin/start', { authorize }, headers));
  const body = (res.status === 200 ? await res.clone().json() : {}) as StartBody;
  const cookie = (res.headers.get('set-cookie') ?? '').split(';')[0];
  return { res, body, cookie };
}

type WalletInfo = { requestId: string; userCode: string; hub: string; site: { clientId: string; name: string } | null; message: string; protocolID: [number, string]; keyID: string; issuedAt: number; expiresAt: number };

/** The wallet's GET /api/wallet-signin?r=… or ?code=… (no Origin: a native app). */
export async function walletInfo(hub: Hub, query: string) {
  const res = await hub.walletSignIn(new Request(`${ISSUER}/api/wallet-signin?${query}`, { headers: { 'x-real-ip': '198.51.100.200' } }));
  return { status: res.status, body: res.status === 200 ? ((await res.json()) as WalletInfo) : null };
}

/** The wallet signing the request and POSTing it to the hub (overrides replace body fields). */
export async function walletApprove(hub: Hub, requestId: string, root: PrivateKey, over: Record<string, unknown> = {}, headers: Record<string, string> = {}): Promise<Response> {
  const info = (await walletInfo(hub, `r=${requestId}`)).body;
  const body = info
    ? { requestId, userCode: info.userCode, identityKey: root.toPublicKey().toString(), signature: await signature(root, info.message, info.keyID), ...over }
    : { requestId, userCode: 'BCDF-GHJK', identityKey: root.toPublicKey().toString(), signature: [1, 2, 3, 4, 5, 6, 7, 8], ...over };
  return hub.walletSignIn(
    new Request(`${ISSUER}/api/wallet-signin`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.200', ...headers }, body: JSON.stringify(body) }),
  );
}

/** The hub page polling (POST /api/signin/poll) with the browser's cookies. */
export async function poll(hub: Hub, cookie: string, headers: Record<string, string> = {}) {
  const res = await hub.signInPoll(post('/api/signin/poll', {}, { ...(cookie ? { cookie } : {}), ...headers }));
  const body = (await res.clone().json().catch(() => ({}))) as { status: string; next?: string; identityKey?: string; paymail?: string | null };
  return { res, body };
}

/** Wallet sign-in at the hub (v2) with a throwaway key; returns the hub cookie header. Pass `cookie` to sign in again in the same browser. */
export async function signIn(hub: Hub, root = PrivateKey.fromRandom(), authorize?: Record<string, string>, o: { cookie?: string; ip?: string } = {}) {
  const ip: Record<string, string> = o.ip ? { 'x-real-ip': o.ip } : {};
  const s = await startSignIn(hub, authorize, ip);
  if (s.res.status !== 200) throw new Error(`start ${s.res.status}`);
  const a = await walletApprove(hub, s.body.requestId, root);
  if (a.status !== 200) throw new Error(`approve ${a.status}`);
  const p = await poll(hub, [s.cookie, o.cookie].filter(Boolean).join('; '), ip);
  if (p.body.status !== 'approved') throw new Error(`poll ${p.body.status}`);
  const set = p.res.headers.getSetCookie().find((c) => /bwx_hub=/.test(c))!;
  return { cookie: set.split(';')[0], body: p.body as { next: string; identityKey: string }, root };
}

/** The hub's session id behind a hub cookie. */
export async function sidOf(hub: Hub, cookie: string): Promise<string | null> {
  return (await hub.currentSession(new Request(ISSUER, { headers: { cookie } })))?.sid ?? null;
}

/** "Sign out of all" the way a b*X site sends it: GET /logout with the site's logout_hint (HMAC, client "site"). */
export async function logoutFromSite(hub: Hub, cookie: string, clock: { t: number }, query = ''): Promise<Response> {
  const sid = (await hub.currentSession(new Request(ISSUER, { headers: { cookie } })))?.sid ?? 'none';
  const hint = await logoutHint(sid, { clientId: 'site', clientSecret: await secretFor('site') }, Math.floor(clock.t / 1000));
  const q = new URLSearchParams(query);
  if (!q.has('client_id')) q.set('client_id', 'site');
  q.set('logout_hint', hint);
  return hub.logout(new Request(`${ISSUER}/logout?${q}`, { headers: { cookie } }));
}

export async function pkce() {
  const verifier = randomToken(48);
  return { verifier, challenge: await pkceChallenge(verifier) };
}

export function authorizeReq(params: Record<string, string>, cookie?: string): Request {
  return new Request(`${ISSUER}/authorize?${new URLSearchParams(params)}`, { headers: cookie ? { cookie } : {} });
}

/** POST /token as a site server: Basic client auth for body.client_id by default ('post' = client_secret in the body). */
export function tokenReq(body: Record<string, string>, o: { auth?: 'basic' | 'post' | 'none'; authHeader?: string; ip?: string } = {}): Request {
  const auth = o.authHeader ?? (o.auth === undefined || o.auth === 'basic' ? clientBasicAuth(body.client_id, secretForSync(body.client_id)) : undefined);
  const b = o.auth === 'post' ? { ...body, client_secret: secretForSync(body.client_id) } : body;
  return new Request(`${ISSUER}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-real-ip': o.ip ?? '203.0.113.1', ...(auth ? { authorization: auth } : {}) },
    body: new URLSearchParams(b).toString(),
  });
}

/** A fetch that routes hub URLs to the Hub instance (what a site's server would reach over the network). */
export function hubFetch(hub: Hub) {
  return async (url: string, init?: RequestInit): Promise<Response> => {
    const u = new URL(url);
    const req = new Request(url, init);
    if (u.pathname === '/token') return hub.token(req);
    if (u.pathname === '/.well-known/jwks.json') return hub.jwks();
    if (u.pathname === '/session/epoch') return hub.epoch(req);
    if (u.pathname === '/logout') return hub.logout(req);
    return new Response('not found', { status: 404 });
  };
}

/** GET /session/epoch?sid= as the "site" client (authenticated). */
export function epochGet(hub: Hub, sid: string, ip = '203.0.113.1'): Promise<Response> {
  return hub.epoch(new Request(`${ISSUER}/session/epoch?sid=${sid}`, { headers: { authorization: clientBasicAuth('site', secretForSync('site')), 'x-real-ip': ip } }));
}

/** Sign in and get a code for `site`. */
export async function codeFor(hub: Hub, clientId = 'site', redirect = CALLBACK) {
  const { cookie, root } = await signIn(hub);
  const p = await pkce();
  const state = randomToken(24);
  const r = await hub.authorize(authorizeReq({ response_type: 'code', client_id: clientId, redirect_uri: redirect, state, code_challenge: p.challenge, code_challenge_method: 'S256' }, cookie));
  const loc = new URL(r.headers.get('location')!);
  return { code: loc.searchParams.get('code')!, state, loc, verifier: p.verifier, cookie, root };
}
