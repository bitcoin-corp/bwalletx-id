/**
 * Print a NEW ES256 private JWK (one line of JSON) for SSO_SIGNING_JWK.
 *
 *   pnpm gen-key            # copy the line straight into the hosting env (Vercel → Settings → Environment Variables)
 *
 * It is printed to stdout only and never written to disk. Never commit it, paste it in chat, or put it in a file in git.
 * Rotation: move the current value to SSO_SIGNING_JWK_PREVIOUS, set the new one as SSO_SIGNING_JWK, deploy, and remove
 * SSO_SIGNING_JWK_PREVIOUS after a day (sites cache the JWKS for 5 minutes).
 * (Self-contained so Node can run it directly; lib/keys.ts newPrivateJwk() makes the same shape.)
 */
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';

const { privateKey } = await generateKeyPair('ES256', { extractable: true });
const jwk = await exportJWK(privateKey);
const kid = `bwx-${new Date().toISOString().slice(0, 10)}-${(await calculateJwkThumbprint(jwk)).slice(0, 8)}`;
process.stdout.write(JSON.stringify({ ...jwk, kid, alg: 'ES256', use: 'sig' }) + '\n');
process.stderr.write(`kid: ${kid} (ES256). Put the line above in SSO_SIGNING_JWK. Do not save it to a file in git.\n`);
