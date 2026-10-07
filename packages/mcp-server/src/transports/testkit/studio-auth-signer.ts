/**
 * Test-only: mint studio-auth assertions with THROWAWAY ES256 keys and serve their JWKS. Nothing here is a
 * secret: every key is generated in memory by the spec that uses it and dies with the process.
 */
import { webcrypto } from 'node:crypto';

export const TEST_ISSUER = 'https://auth.test.invalid';
export const TEST_JWKS_URL = 'https://auth.test.invalid/.well-known/jwks.json';
export const TEST_AUDIENCE = 'discord-mcp';

const subtle = webcrypto.subtle;

export interface AssertionClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  login: string;
  tier: string;
  iat: number;
  exp: number;
  jti: string;
  [key: string]: unknown;
}

export function b64url(input: string | Uint8Array): string {
  return Buffer.from(input).toString('base64url');
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Claims for a healthy `studio` user assertion for `sub`; override any field. */
export function claimsFor(sub: string, overrides: Partial<AssertionClaims> = {}): AssertionClaims {
  const now = nowSeconds();
  return {
    iss: TEST_ISSUER,
    aud: TEST_AUDIENCE,
    sub,
    login: `login-${sub}`,
    tier: 'studio',
    iat: now - 10,
    exp: now + 3600,
    jti: `jti-${sub}-${now}`,
    ...overrides,
  };
}

export interface Signer {
  readonly kid: string;
  jwks(): { keys: Array<Record<string, unknown>> };
  /** Sign arbitrary header and claims objects exactly as given (the caller owns validity). */
  signRaw(header: Record<string, unknown>, claims: Record<string, unknown>): Promise<string>;
  /** A normal assertion for `sub`, with claim and header overrides. */
  mint(
    sub: string,
    claimOverrides?: Partial<AssertionClaims>,
    headerOverrides?: Record<string, unknown>,
  ): Promise<string>;
}

export async function createSigner(kid = 'test-kid-1'): Promise<Signer> {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const publicJwk = await subtle.exportKey('jwk', pair.publicKey);
  const signRaw = async (
    header: Record<string, unknown>,
    claims: Record<string, unknown>,
  ): Promise<string> => {
    const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
    const signature = await subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      pair.privateKey,
      new TextEncoder().encode(signingInput),
    );
    return `${signingInput}.${b64url(new Uint8Array(signature))}`;
  };
  return {
    kid,
    jwks: () => ({
      keys: [
        { kty: 'EC', crv: 'P-256', x: publicJwk.x, y: publicJwk.y, kid, use: 'sig', alg: 'ES256' },
      ],
    }),
    signRaw,
    mint: (sub, claimOverrides = {}, headerOverrides = {}) =>
      signRaw(
        { alg: 'ES256', kid, typ: 'JWT', ...headerOverrides },
        claimsFor(sub, claimOverrides),
      ),
  };
}

export interface JwksFetchStub {
  /** How many times the JWKS URL was fetched. */
  readonly jwksFetches: () => number;
  restore(): void;
}

/**
 * Replace `globalThis.fetch` so the JWKS URL answers with `signer`'s keys and everything else (the spec's own
 * client calls to a loopback server) passes through. The vendored verifier reads `globalThis.fetch` lazily on
 * every fetch, which is the seam: no production code takes a fetch parameter.
 */
export function stubJwksFetch(
  jwksUrl: string,
  body: () => { status: number; json?: unknown },
): JwksFetchStub {
  const original = globalThis.fetch;
  let count = 0;
  globalThis.fetch = (async (input: unknown, init?: unknown) => {
    const url =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.href
          : (input as Request).url;
    if (url === jwksUrl) {
      count += 1;
      const answer = body();
      return new Response(JSON.stringify(answer.json ?? {}), {
        status: answer.status,
        headers: { 'content-type': 'application/json' },
      });
    }
    return original(input as never, init as never);
  }) as typeof fetch;
  return {
    jwksFetches: () => count,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}
