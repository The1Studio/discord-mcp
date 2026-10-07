/**
 * The vendored studio-auth verifier is a SECURITY BOUNDARY copied by hand from `The1Studio/theonekit-model-router`
 * at a pinned commit. Nobody re-reviews it here, so its integrity IS the review: this test recomputes the sha256
 * of the vendored bytes (everything below the BEGIN VENDORED SOURCE marker) and fails when they differ from the
 * hash recorded in the header, so a local edit, accidental or malicious, cannot ship unnoticed.
 *
 * Upgrading is a deliberate act: re-pin the SHA, re-copy the file and update the hash comment together, in one
 * reviewed change.
 *
 * What this cannot catch, stated rather than implied: rewriting the file AND its header hash in one commit is
 * invisible to any test over two local values. The pull request whose subject is "re-vendor at SHA X" witnesses that.
 * The EXPECTED_* constants below are a second local copy, so that edit has to touch three places in one diff.
 *
 * `vendor/studio-auth-verify.d.mts` beside it is OURS (a type declaration for tsc, not vendored) and is
 * deliberately outside the hash.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const VENDORED = new URL('./vendor/studio-auth-verify.mjs', import.meta.url);
const MARKER = '// BEGIN VENDORED SOURCE';

/** The SHA this change vendored. Changing it is the deliberate re-pin. */
const EXPECTED_PINNED_SHA = 'dd10188a44e8bee3f6c8c33ce3f6d425b375f4e9';
/** The sha256 of the upstream file at that SHA (independently recomputed from the GitHub contents API). */
const EXPECTED_SHA256 = 'b45ff7cd4ad9f57f0d343d43483524371d934859b7cd14386f20a48a952ba820';

/** Parse a vendored text into its recorded facts and the recomputed hash. Pure over a string so a spec can feed it a tampered copy. */
function vendoredFacts(text: string) {
  const markerIdx = text.indexOf(MARKER);
  const markerCount = text.split(MARKER).length - 1;
  const recorded = /^\/\/\s*sha256\s*:\s*([0-9a-f]{64})\s*$/m.exec(text)?.[1];
  const pinned = /^\/\/\s*Pinned sha\s*:\s*([0-9a-f]{40})\s*$/m.exec(text)?.[1];
  const body = markerIdx < 0 ? '' : text.slice(markerIdx + MARKER.length).replace(/^[\r\n]+/, '');
  const actual = createHash('sha256').update(body, 'utf8').digest('hex');
  return { markerIdx, markerCount, recorded, pinned, actual };
}

const text = readFileSync(VENDORED, 'utf8');

describe('vendored studio-auth verifier pin', () => {
  it('carries the provenance header: exactly one marker, a 40-hex pinned sha, a 64-hex sha256', () => {
    const facts = vendoredFacts(text);
    expect(facts.markerIdx).toBeGreaterThanOrEqual(0);
    expect(facts.markerCount, 'exactly one marker, or "everything below it" is ambiguous').toBe(1);
    expect(facts.pinned ?? '').toMatch(/^[0-9a-f]{40}$/);
    expect(facts.recorded ?? '').toMatch(/^[0-9a-f]{64}$/);
  });

  it('the vendored bytes hash to exactly the sha256 recorded in the header', () => {
    const facts = vendoredFacts(text);
    expect(
      facts.actual,
      'the vendored bytes changed since they were pinned: re-vendor, never hand-edit',
    ).toBe(facts.recorded);
  });

  it('the recorded facts are the ones this change vendored (a re-pin must edit this test too)', () => {
    const facts = vendoredFacts(text);
    expect(facts.pinned).toBe(EXPECTED_PINNED_SHA);
    expect(facts.recorded).toBe(EXPECTED_SHA256);
    expect(facts.actual).toBe(EXPECTED_SHA256);
  });

  it('a ONE-BYTE change to the body is detected (the guard can fail)', () => {
    const tampered = text.replace('const SKEW_SECONDS = 30;', 'const SKEW_SECONDS = 31;');
    expect(tampered).not.toBe(text);
    const facts = vendoredFacts(tampered);
    expect(facts.actual).not.toBe(facts.recorded);
  });

  it('a changed RECORDED hash is detected (editing only the header does not satisfy the guard)', () => {
    const flipped = text.replace(
      /^(\/\/\s*sha256\s*:\s*)([0-9a-f])/m,
      (_match, prefix: string, first: string) => `${prefix}${first === 'f' ? '0' : 'f'}`,
    );
    expect(flipped).not.toBe(text);
    const facts = vendoredFacts(flipped);
    expect(facts.actual).not.toBe(facts.recorded);
  });

  it('a second marker is detected (a hidden payload above a decoy marker cannot hide)', () => {
    expect(vendoredFacts(`${MARKER}\n${text}`).markerCount).toBe(2);
  });

  it('the vendored module still exposes the API the glue calls, and evaluating it does nothing observable', async () => {
    const before = globalThis.fetch;
    const mod = await import('./vendor/studio-auth-verify.mjs');
    expect(typeof mod.createVerifier).toBe('function');
    expect(typeof mod.bearerFromRequest).toBe('function');
    expect(globalThis.fetch, 'evaluating the verifier must not touch globals').toBe(before);
  });
});
