import { isProd } from '../config';
import { memoryHubStore } from './memory';
import { pgHubStore, pgQueryFromUrl, pgRoleCheck } from './postgres';
import type { HubStore } from './types';

export type { HubStore, HubSession, CodeRecord, PendingSignIn, SessionPatch } from './types';
export { memoryHubStore } from './memory';
export { pgHubStore, pgRoleCheck } from './postgres';

/** The only role the hub may connect as (supabase/migrations/0001_sso.sql creates it). */
export const HUB_DB_ROLE = 'sso_hub';

/** Postgres when SSO_DATABASE_URL is set; in-memory in dev; production refuses to run without a database. */
export async function storeFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<HubStore> {
  if (env.SSO_DATABASE_URL) {
    const query = await pgQueryFromUrl(env.SSO_DATABASE_URL);
    // SSO_DATABASE_URL must use sso_hub, never postgres: refuse to run as anything else in production.
    const role = await pgRoleCheck(query);
    if (role.user !== HUB_DB_ROLE || role.superuser || role.bypassrls) {
      const msg = `SSO_DATABASE_URL connects as "${role.user}"${role.superuser ? ' (superuser)' : ''}${role.bypassrls ? ' (bypasses RLS)' : ''}. It must use the ${HUB_DB_ROLE} role.`;
      if (isProd()) throw new Error(msg);
      console.warn(`[bwalletx-id] ${msg} (allowed in development only)`);
    }
    return pgHubStore(query);
  }
  if (isProd()) throw new Error('SSO_DATABASE_URL is not set. The in-memory store is for development only.');
  console.warn('[bwalletx-id] Using the in-memory store (development only).');
  return memoryHubStore();
}
