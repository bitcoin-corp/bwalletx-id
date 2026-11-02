/**
 * The client registry (clients.json): client_id → exact redirect URIs + risk tier + name.
 * Exact string match only: no wildcards, no prefix matching, https only (http://localhost only in dev).
 */
import raw from '../clients.json';
import { isProd } from './config';

export type RiskTier = 'standard' | 'high';

export interface Client {
  client_id: string;
  name: string;
  tier: RiskTier;
  redirect_uris: string[];
  /** Honoured only when NODE_ENV !== 'production'. */
  dev_redirect_uris?: string[];
}

const ID = /^[a-z0-9][a-z0-9-]{0,62}$/;

function checkUri(u: string, dev: boolean): void {
  if (u.includes('*')) throw new Error(`redirect URI may not contain a wildcard: ${u}`);
  const url = new URL(u);
  if (url.href !== u) throw new Error(`redirect URI must be written in canonical form: ${u} (canonical: ${url.href})`);
  if (url.hash || url.username || url.password) throw new Error(`redirect URI may not have a fragment or credentials: ${u}`);
  if (dev) {
    if (url.protocol !== 'http:' || url.hostname !== 'localhost') throw new Error(`dev redirect URI must be http://localhost:<port>/…: ${u}`);
  } else if (url.protocol !== 'https:') {
    throw new Error(`redirect URI must be https: ${u}`);
  }
}

export class Registry {
  private byId = new Map<string, { client: Client; allowed: Set<string>; postLogout: Set<string> }>();

  constructor(clients: Client[], opts: { dev: boolean }) {
    for (const c of clients) {
      if (!ID.test(c.client_id)) throw new Error(`bad client_id: ${c.client_id}`);
      if (this.byId.has(c.client_id)) throw new Error(`duplicate client_id: ${c.client_id}`);
      if (c.tier !== 'standard' && c.tier !== 'high') throw new Error(`bad tier for ${c.client_id}`);
      if (!c.name) throw new Error(`client ${c.client_id} needs a name`);
      c.redirect_uris.forEach((u) => checkUri(u, false));
      (c.dev_redirect_uris ?? []).forEach((u) => checkUri(u, true));
      const allowed = new Set([...c.redirect_uris, ...(opts.dev ? (c.dev_redirect_uris ?? []) : [])]);
      // After "Sign out of all", the hub may send the visitor back to the home page of a registered origin only.
      const postLogout = new Set([...allowed].map((u) => new URL(u).origin + '/'));
      this.byId.set(c.client_id, { client: c, allowed, postLogout });
    }
  }

  get(clientId: string | null | undefined): Client | null {
    return (clientId && this.byId.get(clientId)?.client) || null;
  }

  /** Exactly one of this client's registered redirect URIs, byte for byte. */
  redirectAllowed(client: Client, uri: string | null | undefined): boolean {
    return !!uri && !!this.byId.get(client.client_id)?.allowed.has(uri);
  }

  postLogoutAllowed(client: Client, uri: string | null | undefined): boolean {
    return !!uri && !!this.byId.get(client.client_id)?.postLogout.has(uri);
  }

  all(): Client[] {
    return [...this.byId.values()].map((v) => v.client);
  }
}

export function loadRegistry(dev = !isProd()): Registry {
  return new Registry((raw as { clients: Client[] }).clients, { dev });
}
