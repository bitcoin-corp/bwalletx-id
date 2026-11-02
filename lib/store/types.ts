/**
 * Hub storage. Two adapters: memory (dev + tests) and Postgres (production: self-hosted Supabase on Hetzner).
 * All times are ms since the epoch. Codes and cookie tokens are stored as SHA-256 hashes, never in the clear.
 * `take*` must read and delete in one step, so a challenge or code can be used once.
 */

export interface PendingChallenge {
  identityKey: string;
  origin: string;
  message: string;
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
  putChallenge(nonce: string, c: PendingChallenge): Promise<void>;
  takeChallenge(nonce: string): Promise<PendingChallenge | null>;
  putCode(codeHash: string, c: CodeRecord): Promise<void>;
  takeCode(codeHash: string): Promise<CodeRecord | null>;
  createSession(s: HubSession): Promise<void>;
  getSession(sid: string): Promise<HubSession | null>;
  getSessionByToken(tokenHash: string): Promise<HubSession | null>;
  updateSession(sid: string, patch: Partial<Pick<HubSession, 'tokenHash' | 'rotatedAt' | 'expiresAt'>>): Promise<void>;
  deleteSession(sid: string): Promise<void>;
  /** 0 for an identity that was never signed out everywhere. */
  getEpoch(identityKey: string): Promise<number>;
  /** Sign this identity out everywhere: returns the new epoch. */
  bumpEpoch(identityKey: string): Promise<number>;
}
