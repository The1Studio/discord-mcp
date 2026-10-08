import { describe, expect, it } from 'vitest';
import { runWithPrincipal, tryGetPrincipal } from './principal.js';

describe('request principal store', () => {
  it('is undefined when no transport established one', () => {
    expect(tryGetPrincipal()).toBeUndefined();
  });

  it('is visible to everything the run awaits, and gone afterwards', async () => {
    const seen = await runWithPrincipal('github:1001', async () => {
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      return tryGetPrincipal();
    });
    expect(seen).toBe('github:1001');
    expect(tryGetPrincipal()).toBeUndefined();
  });

  it('keeps concurrent requests apart (each sees its own principal)', async () => {
    const pause = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
    const [a, b, none] = await Promise.all([
      runWithPrincipal('github:1', async () => {
        await pause(15);
        return tryGetPrincipal();
      }),
      runWithPrincipal('github:2', async () => {
        await pause(1);
        return tryGetPrincipal();
      }),
      (async () => {
        await pause(5);
        return tryGetPrincipal();
      })(),
    ]);
    expect([a, b, none]).toEqual(['github:1', 'github:2', undefined]);
  });

  it.each(['', '   '])('refuses a blank principal (%j) instead of recording nothing', (blank) => {
    expect(() => runWithPrincipal(blank, () => 1)).toThrow(TypeError);
  });

  it('refuses a non-string principal', () => {
    expect(() => runWithPrincipal(1001 as never, () => 1)).toThrow(TypeError);
  });
});
