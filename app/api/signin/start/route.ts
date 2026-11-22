import { getHub } from '@/lib/instance';

export const dynamic = 'force-dynamic';

/** The hub page starts a sign-in: a code for the page and the wallet, and the browser's pending sign-in cookie. */
export async function POST(req: Request): Promise<Response> {
  return (await getHub()).signInStart(req);
}
