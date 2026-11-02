import { PGlite } from '@electric-sql/pglite';
import { PrivateKey, ProtoWallet } from '@bsv/sdk';
import { readFileSync } from 'node:fs';
import { Hub } from '@/lib/hub';
import { newPrivateJwk, signerFromJwk, type Signer } from '@/lib/keys';
import { Registry, type Client } from '@/lib/registry';
import { memoryHubStore } from '@/lib/store/memory';
import { pgHubStore } from '@/lib/store/postgres';
import type { HubStore } from '@/lib/store/types';
import { pkceChallenge, randomToken } from '@bwalletx/connect/sso';

export const ISSUER = 'https://id.example';
export const SITE = 'https://site.example';
export const CALLBACK = `${SITE}/sso/callback`;

export const CLIENTS: Client[] = [
  { client_id: 'site', name: 'Site', tier: 'standard', redirect_uris: [CALLBACK] },
  { client_id: 'vault', name: 'Vault', tier: 'high', redirect_uris: ['https://vault.example/sso/callback'] },
];

export type StoreKind = 'memory' | 'postgres';

export async function makeStore(kind: StoreKind): Promise<HubStore> {
  if (kind === 'memory') return memoryHubStore();
  const db = new PGlite();
  // Supabase's API roles, so the migration's revoke block runs exactly as on the server.
  await db.exec(`create role anon; create role authenticated;`);
  await db.exec(readFileSync(new URL('../supabase/migrations/0001_sso.sql', import.meta.url), 'utf8'));
  return pgHubStore((sql, params) => db.query(sql, params));
}

export interface Rig {
  hub: Hub;
  store: HubStore;
  signer: Signer;
  clock: { t: number };
}

export async function rig(kind: StoreKind, signer?: Signer): Promise<Rig> {
  const clock = { t: Date.now() };
  const store = await makeStore(kind);
  const s = signer ?? (await signerFromJwk(await newPrivateJwk()));
  const hub = new Hub({
    issuer: ISSUER,
    registry: new Registry(CLIENTS, { dev: false }),
    store,
    signer: s,
    lookup: async () => ({ paymail: 'alice@bwalletx.com', handle: '$alice' }),
    now: () => clock.t,
  });
  return { hub, store, signer: s, clock };
}

const LOGIN: [2, string] = [2, 'bwallet sign in'];

export async function signature(root: PrivateKey, message: string, keyID: string): Promise<number[]> {
  const { signature } = await new ProtoWallet(root).createSignature({ protocolID: LOGIN, keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(message)) });
  return Array.from(signature);
}

export function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(ISSUER + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: ISSUER, ...headers }, body: JSON.stringify(body) });
}

export async function challenge(hub: Hub) {
  const r = await hub.challenge(post('/api/challenge', {}));
  return (await r.json()) as { nonce: string; message: string; keyID: string };
}

/** Wallet sign-in at the hub with a throwaway key; returns the hub cookie header. */
export async function signIn(hub: Hub, root = PrivateKey.fromRandom(), authorize?: Record<string, string>) {
  const c = await challenge(hub);
  const r = await hub.verify(post('/api/verify', { identityKey: root.toPublicKey().toString(), nonce: c.nonce, signature: await signature(root, c.message, c.keyID), authorize }));
  if (r.status !== 200) throw new Error(`verify ${r.status}`);
  const set = r.headers.get('set-cookie')!;
  return { cookie: set.split(';')[0], body: (await r.json()) as { next: string; identityKey: string }, root };
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
