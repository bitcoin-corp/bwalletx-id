/** Hub settings. Everything that can differ between dev and production lives here. */

export const isProd = (): boolean => process.env.NODE_ENV === 'production';

/** The hub's public origin: the ID token issuer and the origin the wallet signs in to. From config, never the request. */
export function issuer(): string {
  const v = process.env.SSO_ISSUER;
  if (v) return new URL(v).origin;
  return isProd() ? 'https://id.bwalletx.com' : 'http://localhost:3400';
}

/** Hub session: 30 days, sliding; its cookie token rotates once a day. */
export const HUB_SESSION_MS = 30 * 24 * 3600 * 1000;
export const ROTATE_AFTER_MS = 24 * 3600 * 1000;
/** Authorization codes: single use, 60 seconds. */
export const CODE_TTL_MS = 60 * 1000;
/** ID tokens are only for the code exchange; the site then sets its own session. */
export const ID_TOKEN_SECONDS = 300;
/** Wallet sign-in challenges: single use, 2 minutes. */
export const CHALLENGE_TTL_MS = 2 * 60 * 1000;
/** Hub sessions per identity key; a new sign-in beyond this evicts the oldest. */
export const MAX_SESSIONS_PER_IDENTITY = 20;

/** Requests per minute, per IP and (where known) per identity key. Fixed 1-minute windows, kept in the store. */
export interface RateLimits {
  challenge: number;
  verify: number;
  token: number;
  epoch: number;
}
export const RATE_WINDOW_MS = 60 * 1000;
export const DEFAULT_RATE_LIMITS: RateLimits = { challenge: 10, verify: 10, token: 60, epoch: 120 };

/**
 * Optional overrides from env, e.g. SSO_RATE_LIMITS='{"epoch":600}'. /token and /session/epoch are called by site
 * SERVERS, whose egress IPs (Vercel) are shared, so a busy site may need a higher per-IP limit there.
 */
export function rateLimitsFromEnv(env: NodeJS.ProcessEnv = process.env): Partial<RateLimits> {
  if (!env.SSO_RATE_LIMITS) return {};
  try {
    const v = JSON.parse(env.SSO_RATE_LIMITS) as Record<string, unknown>;
    const out: Partial<RateLimits> = {};
    for (const k of Object.keys(DEFAULT_RATE_LIMITS) as (keyof RateLimits)[]) {
      const n = v[k];
      if (typeof n === 'number' && Number.isInteger(n) && n > 0) out[k] = n;
    }
    return out;
  } catch {
    console.warn('[bwalletx-id] SSO_RATE_LIMITS is not valid JSON; using the defaults.');
    return {};
  }
}

export const GET_BWALLETX_URL = 'https://bwalletx.com/get';
export const PAYMAIL_LOOKUP_URL = 'https://pay.bwallet.space/api/paymail/lookup';
