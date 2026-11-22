/** Hub settings. Everything that can differ between dev and production lives here. */

export const isProd = (): boolean => process.env.NODE_ENV === 'production';

/** The hub's public origin: the ID token issuer and the origin the wallet signs in to. From config, never the request. */
export function issuer(): string {
  const v = process.env.SSO_ISSUER;
  if (v) return new URL(v).origin;
  return isProd() ? 'https://id.bwalletx.com' : 'http://localhost:3400';
}

/**
 * SSO_CLIENT_KEY (32+ chars, env only): b*X site secrets are derived from it (lib/clients.ts). Required in production;
 * without it (development) /token and /session/epoch take unauthenticated calls.
 */
export function clientKey(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const v = env.SSO_CLIENT_KEY;
  if (v && v.length >= 32) return v;
  if (isProd()) throw new Error('SSO_CLIENT_KEY is not set (32+ characters). Sites authenticate to /token and /session/epoch with secrets derived from it.');
  if (v) console.warn('[bwalletx-id] SSO_CLIENT_KEY is shorter than 32 characters; ignoring it (development).');
  return undefined;
}

/** SSO_WALLET_ORIGINS: comma-separated https origins of web wallets allowed to POST /api/wallet-signin. Default none. */
export function walletOrigins(env: NodeJS.ProcessEnv = process.env): string[] {
  return (env.SSO_WALLET_ORIGINS ?? '')
    .split(',')
    .map((x) => x.trim())
    .filter((x) => /^https:\/\/[a-z0-9.-]+(:\d+)?$/.test(x));
}

/** Hub session: 30 days, sliding; its cookie token rotates once a day. */
export const HUB_SESSION_MS = 30 * 24 * 3600 * 1000;
export const ROTATE_AFTER_MS = 24 * 3600 * 1000;
/** Authorization codes: single use, 60 seconds. */
export const CODE_TTL_MS = 60 * 1000;
/** ID tokens are only for the code exchange; the site then sets its own session. */
export const ID_TOKEN_SECONDS = 300;
/** Pending sign-ins (v2): the code on the page and in the wallet lasts 5 minutes. */
export const SIGNIN_TTL_MS = 5 * 60 * 1000;
/** How often the page polls, seconds. */
export const SIGNIN_POLL_SECONDS = 2;
/** Bad wallet attempts on one pending sign-in before it is dead. */
export const SIGNIN_MAX_ATTEMPTS = 5;
/** Hub sessions per identity key; a new sign-in beyond this evicts the oldest. */
export const MAX_SESSIONS_PER_IDENTITY = 20;

/**
 * Requests per minute. Fixed 1-minute windows, kept in the store.
 *   start, poll, wallet: per IP (the sign-in page and the wallet).
 *   token: FAILED code exchanges per IP (good ones from a busy site's shared egress IP never count).
 *   epoch: unauthenticated epoch calls (development only), per IP and per identity key.
 *   clientToken, clientEpoch: per authenticated client (site), across all its IPs.
 */
export interface RateLimits {
  start: number;
  poll: number;
  wallet: number;
  token: number;
  epoch: number;
  clientToken: number;
  clientEpoch: number;
}
export const RATE_WINDOW_MS = 60 * 1000;
export const DEFAULT_RATE_LIMITS: RateLimits = { start: 10, poll: 120, wallet: 30, token: 20, epoch: 120, clientToken: 600, clientEpoch: 600 };

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
