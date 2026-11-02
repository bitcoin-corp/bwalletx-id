import { getHub } from '@/lib/instance';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  return (await getHub()).logout(req);
}
