/**
 * Hub storage. Two adapters: memory (dev + tests) and Postgres (production: self-hosted Supabase on Hetzner).
 * All times are ms since the epoch. Codes and cookie tokens are stored as SHA-256 hashes, never in the clear.
 * `take*` must read and delete in one step, so a challenge or code can be used once.
 */

/**
 * A hub sign-in in progress (v2). The browser that started it holds a random secret in an HttpOnly cookie (only its
 * SHA-256 is stored); the wallet approves it by request id + user code, POSTing its signature straight to the hub.
 */
export interface PendingSignIn {
  /** Public: goes in the wallet link. */
  requestId: string;
  /** SHA-256 of the browser's cookie secret. */
  browserHash: string;
  /** BCDF-GHJK, shown on the page and in the wallet. */
  userCode: string;
  clientId: string | null;
  /** The site's /authorize request (without prompt), re-checked when used. */
  authorize: Record<string, string> | null;
  /** The exact text the wallet signs. */
  message: string;
  status: 'pending' | 'approved' | 'used' | 'failed';
  identityKey: string | null;
  attempts: number;
  createdAt: number;
  expiresAt: number;
}

export interface CodeRecord {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  sid: string;
  identityKey: string;
  expiresAt: number;
}

export interface HubSession {
  /** Stable session id, shared with sites (in the ID token) for the epoch check. */
  sid: string;
  /** SHA-256 of the current cookie token (rotates). */
  tokenHash: string;
  identityKey: string;
  paymail: string | null;
  handle: string | null;
  /** The identity's epoch when this session started; a bigger epoch means it was signed out everywhere. */
  epoch: number;
  authTime: number;
  createdAt: number;
  rotatedAt: number;
  expiresAt: number;
}

export interface HubStore {
  /** False if the request id, user code or browser hash is already taken (the caller retries with new values). */
  putPendingSignIn(p: PendingSignIn): Promise<boolean>;
  getPendingSignIn(requestId: string): Promise<PendingSignIn | null>;
  getPendingSignInByCode(userCode: string): Promise<PendingSignIn | null>;
  getPendingSignInByBrowser(browserHash: string): Promise<PendingSignIn | null>;
  /** pending → approved with this key, only if still pending and unexpired at `now`. True if it changed. */
  approvePendingSignIn(requestId: string, identityKey: string, now: number): Promise<boolean>;
  /** One more bad attempt; at maxAttempts a pending sign-in becomes failed. */
  failPendingSignIn(requestId: string, maxAttempts: number): Promise<void>;
  /** approved → used for this browser, only if unexpired at `now`; returns it, or null. Read and change in one step. */
  takeApprovedSignIn(browserHash: string, now: number): Promise<PendingSignIn | null>;
  putCode(codeHash: string, c: CodeRecord): Promise<void>;
  takeCode(codeHash: string): Promise<CodeRecord | null>;
  createSession(s: HubSession): Promise<void>;
  getSession(sid: string): Promise<HubSession | null>;
  getSessionByToken(tokenHash: string): Promise<HubSession | null>;
  updateSession(sid: string, patch: SessionPatch): Promise<void>;
  deleteSession(sid: string): Promise<void>;
  /** Keep this identity's `keep` newest hub sessions (by createdAt) and delete the rest. Returns how many were deleted. */
  evictSessions(identityKey: string, keep: number): Promise<number>;
  /** 0 for an identity that was never signed out everywhere. */
  getEpoch(identityKey: string): Promise<number>;
  /** Sign this identity out everywhere: returns the new epoch. */
  bumpEpoch(identityKey: string): Promise<number>;
  /**
   * Fixed-window rate limit: count one hit on `bucket` in the window containing `now` (windows are `windowMs` long,
   * aligned to the epoch). Returns the hits so far in this window, including this one, and when the window ends.
   */
  hit(bucket: string, windowMs: number, now: number): Promise<{ hits: number; resetAt: number }>;
  /** The hits so far in the window containing `now`, without counting one. */
  peek(bucket: string, windowMs: number, now: number): Promise<{ hits: number; resetAt: number }>;
  /** Delete expired pending sign-ins, codes, sessions (a day after expiry) and rate-limit windows. */
  cleanup(): Promise<void>;
}

export type SessionPatch = Partial<Pick<HubSession, 'tokenHash' | 'rotatedAt' | 'expiresAt' | 'authTime' | 'paymail' | 'handle'>>;
