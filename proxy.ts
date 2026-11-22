/**
 * A nonce-based Content-Security-Policy for the hub's pages (security review 22 Nov 2026, LOW). Each request gets a
 * fresh nonce; Next.js reads it from the request's CSP header and puts it on its own scripts, and the layout puts it
 * on its one inline script. Anything else (an injected <script>, an inline handler) does not run.
 *
 * Route handlers (/api, /token, /session, /authorize, /logout, JWKS) are not matched: they return JSON, redirects or
 * the small server pages in lib/html.ts, which carry their own strict CSP.
 */
import { NextResponse, type NextRequest } from 'next/server';

export function contentSecurityPolicy(nonce: string, dev: boolean): string {
  return [
    "default-src 'self'",
    // 'strict-dynamic': scripts the nonce'd ones load are allowed; host lists and 'unsafe-inline' are ignored.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ''}`,
    `style-src 'self'${dev ? " 'unsafe-inline'" : ` 'nonce-${nonce}'`}`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(dev ? [] : ['upgrade-insecure-requests']),
  ].join('; ');
}

export function proxy(request: NextRequest): NextResponse {
  const nonce = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(16))).toString('base64');
  const csp = contentSecurityPolicy(nonce, process.env.NODE_ENV !== 'production');
  const headers = new Headers(request.headers);
  headers.set('x-nonce', nonce);
  headers.set('content-security-policy', csp);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set('content-security-policy', csp);
  return res;
}

export const config = {
  matcher: [
    {
      source: '/((?!api/|_next/static|_next/image|favicon\\.ico|token|session/|authorize|logout|\\.well-known/).*)',
      // prefetches don't render a page with scripts
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
