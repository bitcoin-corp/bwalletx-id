/**
 * ID-token signing keys. ES256 (P-256). The private key comes from env only (SSO_SIGNING_JWK); in dev an ephemeral
 * key is made in memory. Rotation: put the new key in SSO_SIGNING_JWK and the old one in SSO_SIGNING_JWK_PREVIOUS;
 * the JWKS lists both (public parts only) until sites have refreshed (5 min cache), then drop the previous one.
 */
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { isProd } from './config';

export interface Signer {
  kid: string;
  sign(claims: Record<string, unknown>): Promise<string>;
  jwks(): { keys: JWK[] };
}

const publicPart = (j: JWK, kid: string): JWK => ({ kty: 'EC', crv: 'P-256', x: j.x, y: j.y, kid, alg: 'ES256', use: 'sig' });

function checkEc(j: JWK, needPrivate: boolean, name: string): void {
  if (j.kty !== 'EC' || j.crv !== 'P-256' || !j.x || !j.y) throw new Error(`${name} must be an EC P-256 JWK (ES256)`);
  if (needPrivate && !j.d) throw new Error(`${name} must include the private part ("d")`);
}

export async function signerFromJwk(priv: JWK, previous: JWK[] = []): Promise<Signer> {
  checkEc(priv, true, 'SSO_SIGNING_JWK');
  const kid = priv.kid || (await calculateJwkThumbprint(priv));
  const key = await importJWK({ ...priv, alg: 'ES256' }, 'ES256');
  const keys = [publicPart(priv, kid)];
  for (const p of previous) {
    checkEc(p, false, 'SSO_SIGNING_JWK_PREVIOUS');
    const pk = p.kid || (await calculateJwkThumbprint(p));
    if (pk === kid) throw new Error('SSO_SIGNING_JWK_PREVIOUS must have a different kid from SSO_SIGNING_JWK');
    keys.push(publicPart(p, pk));
  }
  return {
    kid,
    sign: (claims) => new SignJWT(claims).setProtectedHeader({ alg: 'ES256', kid, typ: 'JWT' }).sign(key),
    jwks: () => ({ keys }),
  };
}

/** A fresh private JWK (for scripts/gen-signing-key.ts and dev). */
export async function newPrivateJwk(): Promise<JWK> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(privateKey);
  const date = new Date().toISOString().slice(0, 10);
  const thumb = (await calculateJwkThumbprint(jwk)).slice(0, 8);
  return { ...jwk, kid: `bwx-${date}-${thumb}`, alg: 'ES256', use: 'sig' };
}

function parseJwk(v: string, name: string): JWK {
  try {
    return JSON.parse(v) as JWK;
  } catch {
    throw new Error(`${name} is not valid JSON`); // never echo the value
  }
}

const g = globalThis as { __bwxDevSigner?: Promise<Signer> };

export async function loadSigner(env: NodeJS.ProcessEnv = process.env): Promise<Signer> {
  const cur = env.SSO_SIGNING_JWK;
  if (cur) {
    const prev = env.SSO_SIGNING_JWK_PREVIOUS ? [parseJwk(env.SSO_SIGNING_JWK_PREVIOUS, 'SSO_SIGNING_JWK_PREVIOUS')] : [];
    return signerFromJwk(parseJwk(cur, 'SSO_SIGNING_JWK'), prev);
  }
  if (isProd()) throw new Error('SSO_SIGNING_JWK is not set. Make one with `pnpm gen-key` and put it in the hosting env.');
  // Dev: one ephemeral key per process, shared by every route bundle.
  return (g.__bwxDevSigner ??= newPrivateJwk().then((j) => signerFromJwk({ ...j, kid: `dev-${j.kid}` })));
}
