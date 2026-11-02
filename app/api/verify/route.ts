import { getHub } from '@/lib/instance';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return (await getHub()).verify(req);
}
