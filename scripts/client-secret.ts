/**
 * Print a b*X site's client secret (for that site's env as BWX_CLIENT_SECRET).
 *
 *   SSO_CLIENT_KEY=… pnpm client-secret bsvapi
 *
 * The secret is derived from the hub's SSO_CLIENT_KEY, the client_id and its secret_version in clients.json
 * (lib/clients.ts): base64url(HMAC-SHA256(SSO_CLIENT_KEY, "bwx-client-secret:v<version>:<client_id>")). Printed to
 * stdout only, never written to disk. Never commit it or paste it in chat. Rotate one site: bump its secret_version.
 * (Self-contained so Node can run it directly.)
 */
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

const id = process.argv[2];
const key = process.env.SSO_CLIENT_KEY ?? '';
if (!id) {
  process.stderr.write('usage: SSO_CLIENT_KEY=… pnpm client-secret <client_id>\n');
  process.exit(2);
}
if (key.length < 32) {
  process.stderr.write('SSO_CLIENT_KEY must be set (32+ characters), the same value as in the hub env.\n');
  process.exit(2);
}
const reg = JSON.parse(readFileSync(new URL('../clients.json', import.meta.url), 'utf8')) as { clients: { client_id: string; secret_version?: number }[] };
const c = reg.clients.find((x) => x.client_id === id);
if (!c) {
  process.stderr.write(`no client "${id}" in clients.json\n`);
  process.exit(2);
}
const v = c.secret_version ?? 1;
process.stdout.write(createHmac('sha256', key).update(`bwx-client-secret:v${v}:${id}`).digest('base64url') + '\n');
process.stderr.write(`client secret for ${id} (version ${v}). Put it in that site's env as BWX_CLIENT_SECRET.\n`);
