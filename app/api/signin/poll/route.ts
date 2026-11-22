import { getHub } from '@/lib/instance';

export const dynamic = 'force-dynamic';

/** The hub page asks whether the wallet has approved; once it has, this sets the hub session. */
export async function POST(req: Request): Promise<Response> {
  return (await getHub()).signInPoll(req);
}
