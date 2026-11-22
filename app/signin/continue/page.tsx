import SignIn from '../SignIn';

export const dynamic = 'force-dynamic';

/**
 * Where bWalletX may send the user after approving (https://id.bwalletx.com/signin/continue). In the browser that
 * started the sign-in (its pending sign-in cookie), this finishes it and goes on to the site.
 */
export default function Continue() {
  return <SignIn site={null} authorize={null} resume />;
}
