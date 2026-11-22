/** Review 22 Nov 2026 LOWs: nonce-based CSP on the hub's pages; the head strip script runs on every path. */
import { NextRequest } from 'next/server';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { RETURN_STRIP_SCRIPT } from '@/lib/return-strip';
import { errorPage } from '@/lib/html';
import { config, contentSecurityPolicy, proxy } from '@/proxy';

const scriptSrc = (csp: string) => csp.split('; ').find((d) => d.startsWith('script-src '))!;

describe('CSP', () => {
  it('a fresh nonce per request, on the response and forwarded to Next (x-nonce + the CSP request header)', () => {
    const a = proxy(new NextRequest('https://id.example/signin'));
    const b = proxy(new NextRequest('https://id.example/signin'));
    const ca = a.headers.get('content-security-policy')!;
    const na = /'nonce-([A-Za-z0-9+/=]{24})'/.exec(ca)![1];
    expect(na).not.toBe(/'nonce-([A-Za-z0-9+/=]{24})'/.exec(b.headers.get('content-security-policy')!)![1]);
    // NextResponse.next({ request: { headers } }) passes request headers on as x-middleware-request-*
    expect(a.headers.get('x-middleware-request-x-nonce')).toBe(na);
    expect(a.headers.get('x-middleware-request-content-security-policy')).toBe(ca);
  });

  it('production policy: nonce + strict-dynamic, no unsafe-inline/eval for scripts, no framing, no plugins, no base', () => {
    const csp = contentSecurityPolicy('n0nce', false);
    expect(scriptSrc(csp)).toBe("script-src 'self' 'nonce-n0nce' 'strict-dynamic'");
    for (const d of ["object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'", "connect-src 'self'"]) expect(csp).toContain(d);
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
    expect(scriptSrc(contentSecurityPolicy('n', true))).toContain("'unsafe-eval'"); // dev (React refresh) only
  });

  it('pages are matched; route handlers are not (they set their own headers)', () => {
    const re = new RegExp(`^${config.matcher[0].source}$`);
    for (const p of ['/', '/signin', '/signin/continue', '/account/api-keys']) expect(re.test(p), p).toBe(true);
    for (const p of ['/api/signin/start', '/api/wallet-signin', '/token', '/session/epoch', '/authorize', '/logout', '/.well-known/jwks.json', '/_next/static/x.js']) {
      expect(re.test(p), p).toBe(false);
    }
  });

  it('the small server pages (errors, sign-out) allow no script at all', () => {
    expect(errorPage('x').headers.get('content-security-policy')).toBe("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  });
});

describe('head strip script', () => {
  const run = (path: string, hash: string) => {
    const calls: string[] = [];
    const location = { pathname: path, search: '?a=1', hash };
    runInNewContext(RETURN_STRIP_SCRIPT, { location, history: { state: null, replaceState: (_s: unknown, _t: string, u: string) => calls.push(u) } });
    return calls;
  };
  it('drops #bwx=ok&… on every path, keeps path and query, never stashes it', () => {
    for (const p of ['/', '/signin', '/signin/continue', '/account/api-keys']) expect(run(p, '#bwx=ok&rid=x&wk=y&f=z'), p).toEqual([`${p}?a=1`]);
    expect(run('/x', '#top')).toEqual([]);
    expect(run('/x', '#bwx=okay')).toEqual([]);
    expect(RETURN_STRIP_SCRIPT).not.toContain('__bwxReturn');
  });
});
