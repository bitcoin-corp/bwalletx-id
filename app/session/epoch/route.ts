import { getHub } from '@/lib/instance';

export const dynamic = 'force-dynamic';

/** Sites only (client auth): GET ?sid= for one session, POST { sids } for up to 100. */
export async function GET(req: Request): Promise<Response> {
  return (await getHub()).epoch(req);
}

export async function POST(req: Request): Promise<Response> {
  return (await getHub()).epoch(req);
}
