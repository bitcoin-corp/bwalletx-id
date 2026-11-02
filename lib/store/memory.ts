import type { CodeRecord, HubSession, HubStore, PendingChallenge } from './types';

/** In-memory store for dev and tests. Lost on restart and not shared between instances: never use in production. */
export function memoryHubStore(now: () => number = Date.now): HubStore {
  const challenges = new Map<string, PendingChallenge>();
  const codes = new Map<string, CodeRecord>();
  const sessions = new Map<string, HubSession>();
  const byToken = new Map<string, string>();
  const epochs = new Map<string, number>();
  const limits = new Map<string, { hits: number; expiresAt: number }>();
  const prune = <T extends { expiresAt: number }>(m: Map<string, T>) => {
    const t = now();
    for (const [k, v] of m) if (v.expiresAt < t) m.delete(k);
  };
  return {
    async putChallenge(nonce, c) {
      prune(challenges);
      challenges.set(nonce, { ...c });
    },
    async takeChallenge(nonce) {
      const c = challenges.get(nonce) ?? null;
      challenges.delete(nonce);
      return c;
    },
    async putCode(h, c) {
      prune(codes);
      codes.set(h, { ...c });
    },
    async takeCode(h) {
      const c = codes.get(h) ?? null;
      codes.delete(h);
      return c;
    },
    async createSession(s) {
      sessions.set(s.sid, { ...s });
      byToken.set(s.tokenHash, s.sid);
    },
    async getSession(sid) {
      const s = sessions.get(sid);
      return s ? { ...s } : null;
    },
    async getSessionByToken(h) {
      const sid = byToken.get(h);
      const s = sid ? sessions.get(sid) : undefined;
      return s && s.tokenHash === h ? { ...s } : null;
    },
    async updateSession(sid, patch) {
      const s = sessions.get(sid);
      if (!s) return;
      if (patch.tokenHash && patch.tokenHash !== s.tokenHash) {
        byToken.delete(s.tokenHash);
        byToken.set(patch.tokenHash, sid);
      }
      Object.assign(s, patch);
    },
    async deleteSession(sid) {
      const s = sessions.get(sid);
      if (s) byToken.delete(s.tokenHash);
      sessions.delete(sid);
    },
    async evictSessions(k, keep) {
      const mine = [...sessions.values()].filter((s) => s.identityKey === k).sort((a, b) => b.createdAt - a.createdAt);
      for (const s of mine.slice(keep)) {
        byToken.delete(s.tokenHash);
        sessions.delete(s.sid);
      }
      return Math.max(0, mine.length - keep);
    },
    async getEpoch(k) {
      return epochs.get(k) ?? 0;
    },
    async bumpEpoch(k) {
      const e = (epochs.get(k) ?? 0) + 1;
      epochs.set(k, e);
      return e;
    },
    async hit(bucket, windowMs, t) {
      const start = Math.floor(t / windowMs) * windowMs;
      const resetAt = start + windowMs;
      if (limits.size > 50_000) prune(limits);
      const key = `${bucket} ${start}`;
      const cur = limits.get(key) ?? { hits: 0, expiresAt: resetAt };
      cur.hits += 1;
      limits.set(key, cur);
      return { hits: cur.hits, resetAt };
    },
    async cleanup() {
      prune(challenges);
      prune(codes);
      prune(limits);
      const day = now() - 24 * 3600 * 1000;
      for (const [sid, s] of sessions) {
        if (s.expiresAt < day) {
          byToken.delete(s.tokenHash);
          sessions.delete(sid);
        }
      }
    },
  };
}
