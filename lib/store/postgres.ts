/**
 * Postgres store (self-hosted Supabase on Hetzner). Tables from supabase/migrations/0001_sso.sql.
 * No driver is imported here: pass `query(sql, params)` resolving to `{ rows }` (node-postgres, PGlite) or an array
 * (postgres.js `sql.unsafe`). `fromUrl` below builds one with postgres.js from a server-only URL.
 */
import type { CodeRecord, HubSession, HubStore, PendingChallenge } from './types';

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
      await query(`delete from sso_challenges where expires_at < now()`, []);
      await query(`insert into sso_challenges (nonce, identity_key, origin, message, expires_at) values ($1, $2, $3, $4, to_timestamp($5))`, [
        nonce,
        c.identityKey,
        c.origin,
        c.message,
        ts(c.expiresAt),
      ]);
    },
    async takeChallenge(nonce) {
      const r = rows(await query(`delete from sso_challenges where nonce = $1 returning identity_key, origin, message, ${T('expires_at')} as expires_ms`, [nonce]))[0];
      return r ? { identityKey: String(r.identity_key), origin: String(r.origin), message: String(r.message), expiresAt: ms(r.expires_ms) } : null;
    },
    async putCode(h, c: CodeRecord) {
      await query(`delete from sso_codes where expires_at < now()`, []);
      await query(
        `insert into sso_codes (code_hash, client_id, redirect_uri, code_challenge, sid, identity_key, expires_at) values ($1, $2, $3, $4, $5, $6, to_timestamp($7))`,
        [h, c.clientId, c.redirectUri, c.codeChallenge, c.sid, c.identityKey, ts(c.expiresAt)],
      );
    },
    async takeCode(h) {
      const r = rows(
        await query(`delete from sso_codes where code_hash = $1 returning client_id, redirect_uri, code_challenge, sid, identity_key, ${T('expires_at')} as expires_ms`, [h]),
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
      await query(`delete from sso_sessions where expires_at < now() - interval '1 day'`, []);
      await query(
        `insert into sso_sessions (sid, token_hash, identity_key, paymail, handle, epoch, auth_time, created_at, rotated_at, expires_at)
         values ($1, $2, $3, $4, $5, $6, to_timestamp($7), to_timestamp($8), to_timestamp($9), to_timestamp($10))`,
        [s.sid, s.tokenHash, s.identityKey, s.paymail, s.handle, s.epoch, ts(s.authTime), ts(s.createdAt), ts(s.rotatedAt), ts(s.expiresAt)],
      );
    },
    async getSession(sid) {
      const r = rows(await query(`select ${SESSION_COLS} from sso_sessions where sid = $1`, [sid]))[0];
      return r ? toSession(r) : null;
    },
    async getSessionByToken(h) {
      const r = rows(await query(`select ${SESSION_COLS} from sso_sessions where token_hash = $1`, [h]))[0];
      return r ? toSession(r) : null;
    },
    async updateSession(sid, p) {
      await query(
        `update sso_sessions set token_hash = coalesce($2, token_hash), rotated_at = coalesce(to_timestamp($3), rotated_at),
           expires_at = coalesce(to_timestamp($4), expires_at) where sid = $1`,
        [sid, p.tokenHash ?? null, p.rotatedAt === undefined ? null : ts(p.rotatedAt), p.expiresAt === undefined ? null : ts(p.expiresAt)],
      );
    },
    async deleteSession(sid) {
      await query(`delete from sso_sessions where sid = $1`, [sid]);
    },
    async getEpoch(k) {
      const r = rows(await query(`select epoch from sso_epochs where identity_key = $1`, [k]))[0];
      return r ? Number(r.epoch) : 0;
    },
    async bumpEpoch(k) {
      const r = rows(
        await query(
          `insert into sso_epochs (identity_key, epoch) values ($1, 1)
           on conflict (identity_key) do update set epoch = sso_epochs.epoch + 1, updated_at = now() returning epoch`,
          [k],
        ),
      )[0];
      return Number(r.epoch);
    },
  };
}

/** postgres.js client from a server-only URL. prepare:false works through Supabase's transaction pooler too. */
export async function pgQueryFromUrl(url: string): Promise<PgQuery> {
  const { default: postgres } = await import('postgres');
  const sql = postgres(url, { prepare: false, max: 3, idle_timeout: 20, connect_timeout: 10 });
  return (text, params) => sql.unsafe(text, params as never[]) as unknown as Promise<unknown[]>;
}
