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

export const GET_BWALLETX_URL = 'https://bwalletx.com/get';
export const PAYMAIL_LOOKUP_URL = 'https://pay.bwallet.space/api/paymail/lookup';
