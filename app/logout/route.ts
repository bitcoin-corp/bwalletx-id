import { getHub } from '@/lib/instance';

export const dynamic = 'force-dynamic';

/** GET: signs out at once with a b*X site's logout_hint, otherwise shows a confirm page. */
export async function GET(req: Request): Promise<Response> {
  return (await getHub()).logout(req);
}

/** POST: the confirm page's button. Same-origin only (Origin must be the hub). */
export async function POST(req: Request): Promise<Response> {
  return (await getHub()).logout(req);
}
