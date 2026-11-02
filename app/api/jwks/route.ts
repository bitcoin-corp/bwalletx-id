import { getHub } from '@/lib/instance';

/** Served at /.well-known/jwks.json (rewrite in next.config.ts). */
export const dynamic = 'force-dynamic';

export async function GET(): Promise<Response> {
  return (await getHub()).jwks();
}
