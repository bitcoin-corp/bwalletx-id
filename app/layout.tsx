import type { Metadata, Viewport } from 'next';
import { headers } from 'next/headers';
import type { ReactNode } from 'react';
import './globals.css';
import { RETURN_STRIP_SCRIPT } from '@/lib/return-strip';

export const metadata: Metadata = {
  title: 'Sign in · bWalletX',
  description: 'One sign-in for every b*X site. Shares only your public identity key and moves no money.',
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { width: 'device-width', initialScale: 1, themeColor: '#000000' };

export default async function RootLayout({ children }: { children: ReactNode }) {
  // The per-request CSP nonce from proxy.ts (also makes every page dynamic, so Next puts the nonce on its scripts).
  const nonce = (await headers()).get('x-nonce') ?? undefined;
  return (
    <html lang="en">
      <head>
        {/* Before any other script, on every path: a stray bWalletX return fragment (#bwx=ok&…) comes off the address bar. */}
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: RETURN_STRIP_SCRIPT }} />
      </head>
      <body>
        <div className="shell">
          <header className="top">
            <a className="brand" href="/">
              <span className="mark">b</span>
              <span>bWalletX sign-in</span>
            </a>
          </header>
          <main className="main">{children}</main>
          <footer className="foot">A sign-in proves who you are. It never moves money: every payment still asks you in bWalletX.</footer>
        </div>
      </body>
    </html>
  );
}
