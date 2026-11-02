import { describe, expect, it } from 'vitest';
import { Registry, loadRegistry } from '@/lib/registry';

describe('registry', () => {
  it('seed: b0-x and bsvapi with exact https callbacks; localhost only in dev', () => {
    const prod = loadRegistry(false);
    const b0x = prod.get('b0-x')!;
    expect(prod.redirectAllowed(b0x, 'https://b0-x.com/sso/callback')).toBe(true);
    expect(prod.redirectAllowed(b0x, 'http://localhost:3402/sso/callback')).toBe(false);
    const bsvapi = prod.get('bsvapi')!;
    expect(bsvapi.tier).toBe('standard');
    expect(prod.redirectAllowed(bsvapi, 'https://www.bsvapi.com/sso/callback')).toBe(true);
    expect(prod.redirectAllowed(bsvapi, 'https://bsvapi.com/sso/callback')).toBe(true);
    expect(prod.redirectAllowed(bsvapi, 'http://localhost:3401/sso/callback')).toBe(false);
    const dev = loadRegistry(true);
    expect(dev.redirectAllowed(dev.get('bsvapi')!, 'http://localhost:3401/sso/callback')).toBe(true);
  });

  it('rejects wildcards, http, fragments and non-localhost dev URIs at load', () => {
    const base = { client_id: 'x', name: 'X', tier: 'standard' as const };
    expect(() => new Registry([{ ...base, redirect_uris: ['https://*.example.com/cb'] }], { dev: false })).toThrow(/wildcard/);
    expect(() => new Registry([{ ...base, redirect_uris: ['http://example.com/cb'] }], { dev: false })).toThrow(/https/);
    expect(() => new Registry([{ ...base, redirect_uris: ['https://example.com/cb#x'] }], { dev: false })).toThrow(/fragment/);
    expect(() => new Registry([{ ...base, redirect_uris: [], dev_redirect_uris: ['http://127.0.0.1:3000/cb'] }], { dev: true })).toThrow(/localhost/);
  });
});
