/**
 * Client secrets for b*X sites (MED-1, review 22 Nov 2026). Nothing secret is stored or committed: each site's secret
 * is derived from the hub's client key (SSO_CLIENT_KEY, env only) and the site's client_id and secret_version:
 *
 *   client_secret = base64url(HMAC-SHA256(SSO_CLIENT_KEY, "bwx-client-secret:v<secret_version>:<client_id>"))
 *
 * The owner gives a site its secret with `pnpm client-secret <client_id>` (prints it once; it goes in that site's env as
 * BWX_CLIENT_SECRET). Bump a client's secret_version in clients.json to rotate just that site.
 */
import { parseClientBasicAuth, sameString } from '@bwalletx/connect/sso';
import type { Client, Registry } from './registry';

const enc = new TextEncoder();
export const MIN_CLIENT_KEY_LENGTH = 32;

export async function clientSecret(clientKey: string, client: Pick<Client, 'client_id' | 'secret_version'>): Promise<string> {
  if (typeof clientKey !== 'string' || clientKey.length < MIN_CLIENT_KEY_LENGTH) throw new Error(`The hub client key must be at least ${MIN_CLIENT_KEY_LENGTH} characters.`);
  const key = await globalThis.crypto.subtle.importKey('raw', enc.encode(clientKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, enc.encode(`bwx-client-secret:v${client.secret_version ?? 1}:${client.client_id}`)));
  return Buffer.from(mac).toString('base64url');
}

export type ClientAuth =
  /** Credentials were sent and are right. */
  | { ok: true; client: Client; authenticated: true }
  /** No credentials, and the hub has no client key (development only). */
  | { ok: true; client: null; authenticated: false }
  /** Credentials missing (the hub requires them) or wrong. */
  | { ok: false };

/**
 * Who is calling a server-to-server endpoint. Credentials: Authorization: Basic (client_secret_basic), or client_id +
 * client_secret in a form body (client_secret_post, /token only). With a client key the hub requires them; without one
 * (development) a call without credentials is allowed as unauthenticated.
 */
export async function authenticateClient(req: Request, registry: Registry, clientKey: string | undefined, form?: Record<string, string>): Promise<ClientAuth> {
  const h = req.headers.get('authorization');
  let creds: { clientId: string; clientSecret: string } | null = null;
  if (h) {
    creds = parseClientBasicAuth(h);
    if (!creds) return { ok: false };
  } else if (form && typeof form.client_secret === 'string' && typeof form.client_id === 'string') {
    creds = { clientId: form.client_id, clientSecret: form.client_secret };
  }
  if (!creds) return clientKey ? { ok: false } : { ok: true, client: null, authenticated: false };
  if (!clientKey) return { ok: false }; // credentials the hub can't check: refuse rather than ignore them
  const client = registry.get(creds.clientId);
  if (!client) return { ok: false };
  const want = await clientSecret(clientKey, client);
  return sameString(creds.clientSecret, want) ? { ok: true, client, authenticated: true } : { ok: false };
}
