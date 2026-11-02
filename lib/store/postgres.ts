/**
 * Postgres store (self-hosted Supabase on Hetzner). Tables in schema `sso` from supabase/migrations/0001_sso.sql.
 * Connect as the `sso_hub` role, never postgres (see storeFromEnv).
 * No driver is imported here: pass `query(sql, params)` resolving to `{ rows }` (node-postgres, PGlite) or an array
 * (postgres.js `sql.unsafe`). `fromUrl` below builds one with postgres.js from a server-only URL.
 */
import type { CodeRecord, HubSession, HubStore, PendingChallenge, SessionPatch } from './types';

export type PgQuery = (sql: string, params: unknown[]) => Promise<{ rows: unknown[] } | unknown[]>;
type Row = Record<string, unknown>;

const rows = (r: { rows: unknown[] } | unknown[]): Row[] => (Array.isArray(r) ? r : r.rows) as Row[];
const ms = (v: unknown): number => Number(v);
const ts = (n: number) => n / 1000; // → to_timestamp($n)
const T = (col: string) => `floor(extract(epoch from ${col}) * 1000)::float8`;

const SESSION_COLS = `sid, token_hash, identity_key, paymail, handle, epoch, ${T('auth_time')} as auth_ms, ${T('created_at')} as created_ms,
  ${T('rotated_at')} as rotated_ms, ${T('expires_at')} as expires_ms`;

function toSession(r: Row): HubSession {
  return {
    sid: String(r.sid),
    tokenHash: String(r.token_hash),
    identityKey: String(r.identity_key),
    paymail: (r.paymail as string | null) ?? null,
    handle: (r.handle as string | null) ?? null,
    epoch: Number(r.epoch),
    authTime: ms(r.auth_ms),
    createdAt: ms(r.created_ms),
    rotatedAt: ms(r.rotated_ms),
    expiresAt: ms(r.expires_ms),
  };
}

export function pgHubStore(query: PgQuery): HubStore {
  return {
    async putChallenge(nonce, c: PendingChallenge) {
      await query(`delete from sso.challenges where expires_at < now()`, []);
      await query(`insert into sso.challenges (nonce, identity_key, origin, message, expires_at) values ($1, $2, $3, $4, to_timestamp($5))`, [
        nonce,
        c.identityKey,
        c.origin,
        c.message,
        ts(c.expiresAt),
      ]);
    },
    async takeChallenge(nonce) {
      const r = rows(await query(`delete from sso.challenges where nonce = $1 returning identity_key, origin, message, ${T('expires_at')} as expires_ms`, [nonce]))[0];
      return r ? { identityKey: String(r.identity_key), origin: String(r.origin), message: String(r.message), expiresAt: ms(r.expires_ms) } : null;
    },
    async putCode(h, c: CodeRecord) {
      await query(`delete from sso.codes where expires_at < now()`, []);
      await query(
        `insert into sso.codes (code_hash, client_id, redirect_uri, code_challenge, sid, identity_key, expires_at) values ($1, $2, $3, $4, $5, $6, to_timestamp($7))`,
        [h, c.clientId, c.redirectUri, c.codeChallenge, c.sid, c.identityKey, ts(c.expiresAt)],
      );
    },
    async takeCode(h) {
      const r = rows(
        await query(`delete from sso.codes where code_hash = $1 returning client_id, redirect_uri, code_challenge, sid, identity_key, ${T('expires_at')} as expires_ms`, [h]),
      )[0];
      return r
        ? {
            clientId: String(r.client_id),
            redirectUri: String(r.redirect_uri),
            codeChallenge: String(r.code_challenge),
            sid: String(r.sid),
            identityKey: String(r.identity_key),
            expiresAt: ms(r.expires_ms),
          }
        : null;
    },
    async createSession(s: HubSession) {
      // Sign-ins are rare enough to prune here too, in case pg_cron isn't installed.
      await query(`delete from sso.sessions where expires_at < now() - interval '1 day'`, []);
      await query(`delete from sso.rate_limits where expires_at < now()`, []);
      await query(
        `insert into sso.sessions (sid, token_hash, identity_key, paymail, handle, epoch, auth_time, created_at, rotated_at, expires_at)
         values ($1, $2, $3, $4, $5, $6, to_timestamp($7), to_timestamp($8), to_timestamp($9), to_timestamp($10))`,
        [s.sid, s.tokenHash, s.identityKey, s.paymail, s.handle, s.epoch, ts(s.authTime), ts(s.createdAt), ts(s.rotatedAt), ts(s.expiresAt)],
      );
    },
    async getSession(sid) {
      const r = rows(await query(`select ${SESSION_COLS} from sso.sessions where sid = $1`, [sid]))[0];
      return r ? toSession(r) : null;
    },
    async getSessionByToken(h) {
      const r = rows(await query(`select ${SESSION_COLS} from sso.sessions where token_hash = $1`, [h]))[0];
      return r ? toSession(r) : null;
    },
    async updateSession(sid, p: SessionPatch) {
      const opt = (n: number | undefined) => (n === undefined ? null : ts(n));
      await query(
        `update sso.sessions set token_hash = coalesce($2, token_hash), rotated_at = coalesce(to_timestamp($3), rotated_at),
           expires_at = coalesce(to_timestamp($4), expires_at), auth_time = coalesce(to_timestamp($5), auth_time),
           paymail = case when $6::boolean then $7 else paymail end, handle = case when $8::boolean then $9 else handle end
         where sid = $1`,
        [
          sid,
          p.tokenHash ?? null,
          opt(p.rotatedAt),
          opt(p.expiresAt),
          opt(p.authTime),
          'paymail' in p,
          p.paymail ?? null,
          'handle' in p,
          p.handle ?? null,
        ],
      );
    },
    async deleteSession(sid) {
      await query(`delete from sso.sessions where sid = $1`, [sid]);
    },
    async evictSessions(k, keep) {
      const r = rows(
        await query(
          `delete from sso.sessions where identity_key = $1 and sid not in
             (select sid from sso.sessions where identity_key = $1 order by created_at desc, sid limit $2) returning sid`,
          [k, keep],
        ),
      );
      return r.length;
    },
    async getEpoch(k) {
      const r = rows(await query(`select epoch from sso.epochs where identity_key = $1`, [k]))[0];
      return r ? Number(r.epoch) : 0;
    },
    async bumpEpoch(k) {
      const r = rows(
        await query(
          `insert into sso.epochs (identity_key, epoch) values ($1, 1)
           on conflict (identity_key) do update set epoch = sso.epochs.epoch + 1, updated_at = now() returning epoch`,
          [k],
        ),
      )[0];
      return Number(r.epoch);
    },
    async hit(bucket, windowMs, t) {
      const start = Math.floor(t / windowMs) * windowMs;
      const resetAt = start + windowMs;
      const r = rows(
        await query(
          `insert into sso.rate_limits (bucket, window_start, hits, expires_at) values ($1, to_timestamp($2), 1, to_timestamp($3))
           on conflict (bucket, window_start) do update set hits = sso.rate_limits.hits + 1 returning hits`,
          [bucket, ts(start), ts(resetAt)],
        ),
      )[0];
      return { hits: Number(r.hits), resetAt };
    },
    async cleanup() {
      await query(`select sso.cleanup()`, []);
    },
  };
}

/**
 * The role this connection runs as. The hub must connect as sso_hub: least privilege, RLS applies. A superuser or
 * a BYPASSRLS role (postgres, service_role) could read every table on the server if the hub were ever compromised.
 */
export async function pgRoleCheck(query: PgQuery): Promise<{ user: string; superuser: boolean; bypassrls: boolean }> {
  const r = rows(await query(`select current_user::text as u, rolsuper, rolbypassrls from pg_roles where rolname = current_user`, []))[0];
  return { user: String(r?.u ?? ''), superuser: r?.rolsuper === true, bypassrls: r?.rolbypassrls === true };
}

/** postgres.js client from a server-only URL. prepare:false works through Supabase's transaction pooler too. */
export async function pgQueryFromUrl(url: string): Promise<PgQuery> {
  const { default: postgres } = await import('postgres');
  const sql = postgres(url, { prepare: false, max: 3, idle_timeout: 20, connect_timeout: 10 });
  return (text, params) => sql.unsafe(text, params as never[]) as unknown as Promise<unknown[]>;
}
