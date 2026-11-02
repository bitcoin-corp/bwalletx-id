import { isProd } from '../config';
import { memoryHubStore } from './memory';
import { pgHubStore, pgQueryFromUrl } from './postgres';
import type { HubStore } from './types';

export type { HubStore, HubSession, CodeRecord, PendingChallenge } from './types';
export { memoryHubStore } from './memory';
export { pgHubStore } from './postgres';

/** Postgres when SSO_DATABASE_URL is set; in-memory in dev; production refuses to run without a database. */
export async function storeFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<HubStore> {
  if (env.SSO_DATABASE_URL) return pgHubStore(await pgQueryFromUrl(env.SSO_DATABASE_URL));
  if (isProd()) throw new Error('SSO_DATABASE_URL is not set. The in-memory store is for development only.');
  console.warn('[bwalletx-id] Using the in-memory store (development only).');
  return memoryHubStore();
}
