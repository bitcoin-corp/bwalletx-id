import type { NextConfig } from 'next';

const security = [
  // Never framed: sign-in is top-level only (clickjacking, and Safari blocks third-party cookies anyway).
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Content-Security-Policy', value: "frame-ancestors 'none'" },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: security }];
  },
  async rewrites() {
    return [{ source: '/.well-known/jwks.json', destination: '/api/jwks' }];
  },
};

export default nextConfig;
