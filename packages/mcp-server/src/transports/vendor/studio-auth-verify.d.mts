/**
 * Types for the vendored `studio-auth-verify.mjs`. OURS, not vendored: it sits outside the sha256 pin.
 * Covers only what this repo calls; the vendored file's JSDoc is the full contract.
 */
export interface VerifierConfig {
  issuer: string;
  jwksUrl: string;
  audience: string | string[];
  tiers?: Array<'studio' | 'owners'>;
  kinds?: Array<'user' | 'machine'>;
  allowSubs?: string[];
  allowLogins?: string[];
  kidTiers?: Record<string, 'studio' | 'owners'>;
  allowInsecureLocalhost?: boolean;
  clock?: () => number;
  fetch?: typeof fetch;
}

export type VerifyResult =
  | {
      ok: true;
      claims: { sub: string; login: string; tier: string; exp: number; jti: string; kind: string };
    }
  | { ok: false; code: string };

export interface Verifier {
  verify(token: string): Promise<VerifyResult>;
}

export function createVerifier(cfg: VerifierConfig): Verifier;
export function bearerFromRequest(headers: unknown): string | null;
