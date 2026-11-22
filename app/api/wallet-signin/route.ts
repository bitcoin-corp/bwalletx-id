import { getHub } from '@/lib/instance';

export const dynamic = 'force-dynamic';

/** Wallets only (docs/HUB-SIGNIN-V2.md): what to show for a code, and the approval itself. */
export async function GET(req: Request): Promise<Response> {
  return (await getHub()).walletSignIn(req);
}

export async function POST(req: Request): Promise<Response> {
  return (await getHub()).walletSignIn(req);
}
