import type { CodeRecord, HubSession, HubStore, PendingSignIn } from './types';

/** In-memory store for dev and tests. Lost on restart and not shared between instances: never use in production. */
export function memoryHubStore(now: () => number = Date.now): HubStore {
  const signins = new Map<string, PendingSignIn>();
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
    async putPendingSignIn(p) {
      prune(signins);
      for (const x of signins.values()) if (x.requestId === p.requestId || x.userCode === p.userCode || x.browserHash === p.browserHash) return false;
      signins.set(p.requestId, { ...p, authorize: p.authorize ? { ...p.authorize } : null });
      return true;
    },
    async getPendingSignIn(id) {
      const p = signins.get(id);
      return p ? { ...p } : null;
    },
    async getPendingSignInByCode(code) {
      for (const p of signins.values()) if (p.userCode === code) return { ...p };
      return null;
    },
    async getPendingSignInByBrowser(h) {
      for (const p of signins.values()) if (p.browserHash === h) return { ...p };
      return null;
    },
    async approvePendingSignIn(id, identityKey, t) {
      const p = signins.get(id);
      if (!p || p.status !== 'pending' || p.expiresAt <= t) return false;
      p.status = 'approved';
      p.identityKey = identityKey;
      return true;
    },
    async failPendingSignIn(id, max) {
      const p = signins.get(id);
      if (!p || p.status !== 'pending') return;
      p.attempts += 1;
      if (p.attempts >= max) p.status = 'failed';
    },
    async takeApprovedSignIn(h, t) {
      for (const p of signins.values()) {
        if (p.browserHash !== h) continue;
        if (p.status !== 'approved' || p.expiresAt <= t) return null;
        p.status = 'used';
        return { ...p };
      }
      return null;
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
    async peek(bucket, windowMs, t) {
      const start = Math.floor(t / windowMs) * windowMs;
      return { hits: limits.get(`${bucket} ${start}`)?.hits ?? 0, resetAt: start + windowMs };
    },
    async cleanup() {
      prune(signins);
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
