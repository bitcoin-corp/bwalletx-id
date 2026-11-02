import { getHub } from '@/lib/instance';
import SignIn from './SignIn';

export const dynamic = 'force-dynamic';

const KEYS = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'response_type', 'prompt'] as const;

export default async function SignInPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const hub = await getHub();
  const q = new URLSearchParams();
  for (const k of KEYS) {
    const v = sp[k];
    if (typeof v === 'string') q.set(k, v);
  }
  let site: string | null = null;
  let authorize: Record<string, string> | null = null;
  if (q.get('client_id')) {
    const c = hub.checkAuthorize(q);
    if (!c.ok) {
      return (
        <div className="card">
          <h1>This sign-in link isn&apos;t valid</h1>
          <p className="lead">It names a site or an address that is not registered with bWalletX. For your safety we won&apos;t send you on. Go back to the site and try again.</p>
        </div>
      );
    }
    site = c.client.name;
    authorize = Object.fromEntries(q);
  }
  return <SignIn site={site} authorize={authorize} />;
}
