import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { RETURN_STRIP_SCRIPT } from '@/lib/return-strip';

export const metadata: Metadata = {
  title: 'Sign in · bWalletX',
  description: 'One sign-in for every b*X site. Shares only your public identity key and moves no money.',
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { width: 'device-width', initialScale: 1, themeColor: '#000000' };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <head>
        {/* Before any other script: bWalletX's return fragment (#bwx=ok&…) comes off the address bar (app/Returned.tsx). */}
        <script dangerouslySetInnerHTML={{ __html: RETURN_STRIP_SCRIPT }} />
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
