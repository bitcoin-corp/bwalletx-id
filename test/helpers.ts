import { PGlite } from '@electric-sql/pglite';
import { PrivateKey, ProtoWallet } from '@bsv/sdk';
import { readFileSync } from 'node:fs';
import { Hub } from '@/lib/hub';
import { newPrivateJwk, signerFromJwk, type Signer } from '@/lib/keys';
import { Registry, type Client } from '@/lib/registry';
import { memoryHubStore } from '@/lib/store/memory';
import { pgHubStore } from '@/lib/store/postgres';
import type { HubStore } from '@/lib/store/types';
import type { RateLimits } from '@/lib/config';
import { HUB_SIGNIN_PROTOCOL, logoutHint, pkceChallenge, randomToken } from '@bwalletx/connect/sso';

export const ISSUER = 'https://id.example';
export const SITE = 'https://site.example';
export const CALLBACK = `${SITE}/sso/callback`;

export const CLIENTS: Client[] = [
  { client_id: 'site', name: 'Site', tier: 'standard', redirect_uris: [CALLBACK] },
  { client_id: 'vault', name: 'Vault', tier: 'high', redirect_uris: ['https://vault.example/sso/callback'] },
];

export type StoreKind = 'memory' | 'postgres';

export const MIGRATION = readFileSync(new URL('../supabase/migrations/0001_sso.sql', import.meta.url), 'utf8');

/** A fresh PGlite with Supabase's API roles and the hub migration applied (as the superuser). */
export async function migratedDb(): Promise<PGlite> {
  const db = new PGlite();
  // Supabase's API roles, so the migration's revoke block runs exactly as on the server.
  await db.exec(`create role anon; create role authenticated;`);
  await db.exec(MIGRATION);
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
export const RELAXED: RateLimits = { challenge: 1000, verify: 1000, token: 1000, epoch: 1000 };

export async function rig(kind: StoreKind, signer?: Signer, limits: Partial<RateLimits> = RELAXED): Promise<Rig> {
  const clock = { t: Date.now() };
  const store = await makeStore(kind);
  const s = signer ?? (await signerFromJwk(await newPrivateJwk()));
  const hub = new Hub({
    issuer: ISSUER,
    registry: new Registry(CLIENTS, { dev: false }),
    store,
    signer: s,
    lookup: async () => ({ paymail: 'alice@bwalletx.com', handle: '$alice' }),
    limits,
    now: () => clock.t,
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

export async function challenge(hub: Hub, headers: Record<string, string> = {}) {
  const r = await hub.challenge(post('/api/challenge', {}, headers));
  if (r.status !== 200) throw new Error(`challenge ${r.status}`);
  return (await r.json()) as { nonce: string; message: string; keyID: string; protocolID: [number, string] };
}

/** Wallet sign-in at the hub with a throwaway key; returns the hub cookie header. Pass `cookie` to sign in again in the same browser. */
export async function signIn(hub: Hub, root = PrivateKey.fromRandom(), authorize?: Record<string, string>, o: { cookie?: string; ip?: string } = {}) {
  const ip: Record<string, string> = o.ip ? { 'x-real-ip': o.ip } : {};
  const c = await challenge(hub, ip);
  const r = await hub.verify(
    post('/api/verify', { identityKey: root.toPublicKey().toString(), nonce: c.nonce, signature: await signature(root, c.message, c.keyID), authorize }, { ...ip, ...(o.cookie ? { cookie: o.cookie } : {}) }),
  );
  if (r.status !== 200) throw new Error(`verify ${r.status}`);
  const set = r.headers.get('set-cookie')!;
  return { cookie: set.split(';')[0], body: (await r.json()) as { next: string; identityKey: string }, root };
}

/** The hub's session id behind a hub cookie. */
export async function sidOf(hub: Hub, cookie: string): Promise<string | null> {
  return (await hub.currentSession(new Request(ISSUER, { headers: { cookie } })))?.sid ?? null;
}

/** "Sign out of all" the way a b*X site sends it: GET /logout with the site's logout_hint for this session. */
export async function logoutFromSite(hub: Hub, cookie: string, clock: { t: number }, query = ''): Promise<Response> {
  const sid = (await hub.currentSession(new Request(ISSUER, { headers: { cookie } })))?.sid ?? 'none';
  const hint = await logoutHint(sid, Math.floor(clock.t / 1000));
  return hub.logout(new Request(`${ISSUER}/logout?logout_hint=${encodeURIComponent(hint)}${query ? '&' + query : ''}`, { headers: { cookie } }));
}

export async function pkce() {
  const verifier = randomToken(48);
  return { verifier, challenge: await pkceChallenge(verifier) };
}

export function authorizeReq(params: Record<string, string>, cookie?: string): Request {
  return new Request(`${ISSUER}/authorize?${new URLSearchParams(params)}`, { headers: cookie ? { cookie } : {} });
}

export function tokenReq(body: Record<string, string>): Request {
  return new Request(`${ISSUER}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body).toString() });
}

/** A fetch that routes hub URLs to the Hub instance (what a site's server would reach over the network). */
export function hubFetch(hub: Hub) {
  return async (url: string, init?: RequestInit): Promise<Response> => {
    const u = new URL(url);
    const req = new Request(url, init);
    if (u.pathname === '/token') return hub.token(req);
    if (u.pathname === '/.well-known/jwks.json') return hub.jwks();
    if (u.pathname === '/session/epoch') return hub.epoch(req);
    return new Response('not found', { status: 404 });
  };
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
