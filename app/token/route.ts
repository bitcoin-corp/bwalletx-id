import { getHub } from '@/lib/instance';

export const dynamic = 'force-dynamic';

/** Server to server only: no CORS headers, so no browser page can call it cross-origin. */
export async function POST(req: Request): Promise<Response> {
  return (await getHub()).token(req);
}
