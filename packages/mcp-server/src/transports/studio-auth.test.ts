import { readFileSync } from 'node:fs';
import type { IncomingHttpHeaders } from 'node:http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createModuleLoader,
  createStudioGuard,
  isStudioJws,
  parseAllowSubs,
  pickStudioAuthEnv,
  readStudioAuthConfig,
  resetStudioAuthState,
  STUDIO_AUDIENCE,
  STUDIO_AUTH_ENV_KEYS,
  STUDIO_MAX_TOKEN_CHARS,
  STUDIO_REALM,
  STUDIO_REFUSAL_CODES,
  STUDIO_VERIFIER_CACHE_MAX,
  StudioAuthConfigError,
  type StudioAuthEnv,
  type StudioDecision,
  type StudioGateDeps,
  type StudioLogSink,
  type StudioRefusal,
  studioAuthEnabled,
  studioAuthRequired,
  studioBadRequestResponse,
  studioGate,
  studioRefusalResponse,
  studioVerifierCacheSize,
} from './studio-auth.js';
import {
  b64url,
  claimsFor,
  createSigner,
  type JwksFetchStub,
  type Signer,
  stubJwksFetch,
  TEST_AUDIENCE,
  TEST_ISSUER,
  TEST_JWKS_URL,
} from './testkit/studio-auth-signer.js';

const VENDORED_URL = new URL('./vendor/studio-auth-verify.mjs', import.meta.url);

const ENABLED_ENV: StudioAuthEnv = {
  STUDIO_AUTH_ENABLED: 'true',
  STUDIO_AUTH_ISSUER: TEST_ISSUER,
  STUDIO_AUTH_JWKS_URL: TEST_JWKS_URL,
  STUDIO_AUTH_ALLOW_SUBS: '1001,1002',
};
const REQUIRED_ENV: StudioAuthEnv = { ...ENABLED_ENV, STUDIO_AUTH_REQUIRED: 'true' };

const bearer = (token: string): IncomingHttpHeaders => ({ authorization: `Bearer ${token}` });

/** A throwaway fresh kid per test: the verifier cache is keyed by config, never by kid, so isolation is explicit. */
let signer: Signer;
let jwks: JwksFetchStub;
let kidCounter = 0;
const logs: Array<{ level: string; message: string; fields: unknown }> = [];
const sink: StudioLogSink = (level, message, fields) => logs.push({ level, message, fields });
const deps = (extra: StudioGateDeps = {}): StudioGateDeps => ({ log: sink, ...extra });

beforeEach(async () => {
  resetStudioAuthState();
  logs.length = 0;
  kidCounter += 1;
  signer = await createSigner(`kid-${kidCounter}`);
  jwks = stubJwksFetch(TEST_JWKS_URL, () => ({ status: 200, json: signer.jwks() }));
});

afterEach(() => {
  jwks.restore();
  vi.restoreAllMocks();
});

function expectRefusal(decision: StudioDecision, status: number, code: string): StudioRefusal {
  expect(decision.decision).toBe('refuse');
  const refusal = decision as StudioRefusal;
  expect({ status: refusal.status, code: refusal.code }).toEqual({ status, code });
  return refusal;
}

describe('flags are the exact string "true"', () => {
  it.each([
    [' true'],
    ['true '],
    ['True'],
    ['TRUE'],
    ['1'],
    ['yes'],
    ['on'],
    [''],
    ['false'],
    [undefined],
    [null],
    [true],
    [1],
  ])('ENABLED=%j and REQUIRED=%j are off', (raw) => {
    expect(studioAuthEnabled(raw)).toBe(false);
    expect(studioAuthRequired(raw)).toBe(false);
  });

  it('only "true" turns either on', () => {
    expect(studioAuthEnabled('true')).toBe(true);
    expect(studioAuthRequired('true')).toBe(true);
  });

  it('a gate with a lookalike flag value is inactive and never consults the verifier module', async () => {
    const loadModule = vi.fn();
    for (const raw of [' true', 'True', '1', 'yes', 'false', '']) {
      const decision = await studioGate(
        bearer('a.b.c'),
        { ...REQUIRED_ENV, STUDIO_AUTH_ENABLED: raw },
        deps({ loadModule }),
      );
      expect(decision).toEqual({ decision: 'inactive' });
    }
    expect(loadModule).not.toHaveBeenCalled();
  });

  it('flag-off never loads the vendored module (a fresh module instance counts zero loads)', async () => {
    vi.resetModules();
    const fresh = await import('./studio-auth.js');
    expect(fresh.createStudioGuard({ STUDIO_AUTH_ENABLED: 'True' })).toBeNull();
    expect(await fresh.studioGate(bearer('a.b.c'), {})).toEqual({ decision: 'inactive' });
    expect(fresh.studioModuleLoadCount()).toBe(0);
    // positive control: a flag-on gate DOES load it, so the zero above is not vacuous.
    await fresh.studioGate({}, ENABLED_ENV);
    expect(fresh.studioModuleLoadCount()).toBe(1);
  });
});

describe('createStudioGuard', () => {
  it('is null when off and constructs nothing', () => {
    expect(createStudioGuard(undefined)).toBeNull();
    expect(createStudioGuard({})).toBeNull();
    expect(createStudioGuard({ STUDIO_AUTH_ENABLED: 'false' })).toBeNull();
  });

  it('refuses REQUIRED=true without ENABLED=true (it would look protected and be open)', () => {
    expect(() => createStudioGuard({ STUDIO_AUTH_REQUIRED: 'true' })).toThrow(
      StudioAuthConfigError,
    );
    expect(() =>
      createStudioGuard({ STUDIO_AUTH_ENABLED: 'True', STUDIO_AUTH_REQUIRED: 'true' }),
    ).toThrow(/needs STUDIO_AUTH_ENABLED=true/);
  });

  it.each([
    ['TRUE'],
    ['1'],
    ['yes'],
    [' true'],
  ])('refuses an ambiguous REQUIRED=%j while enabled (the one flag whose failure is "less secure")', (raw) => {
    expect(() => createStudioGuard({ ...ENABLED_ENV, STUDIO_AUTH_REQUIRED: raw })).toThrow(
      /must be exactly "true" or "false"/,
    );
  });

  it.each([[undefined], [''], ['false'], ['true']])('accepts REQUIRED=%j while enabled', (raw) => {
    const env: StudioAuthEnv = { ...ENABLED_ENV };
    if (raw !== undefined) env.STUDIO_AUTH_REQUIRED = raw;
    expect(createStudioGuard(env)).not.toBeNull();
  });
});

describe('allowlist parsing: numeric ids only, empty means nobody, malformed fails closed', () => {
  it('empty, absent and whitespace-only are the empty list', () => {
    expect(parseAllowSubs(undefined)).toEqual([]);
    expect(parseAllowSubs(null)).toEqual([]);
    expect(parseAllowSubs('')).toEqual([]);
    expect(parseAllowSubs(' , ,')).toEqual([]);
  });

  it('keeps ids as strings, trimmed, in order', () => {
    expect(parseAllowSubs(' 1001 , 1002 ')).toEqual(['1001', '1002']);
    expect(parseAllowSubs('9007199254740993')).toEqual(['9007199254740993']);
  });

  it.each([
    ['octocat'],
    ['a@b.example'],
    ['github:1001'],
    ['01'],
    ['0'],
    ['-1'],
    ['+1'],
    ['1.5'],
    ['1e3'],
    ['0x10'],
    ['1001,octocat'],
    ['1001;1002'],
  ])('rejects %j instead of dropping it', (raw) => {
    expect(() => parseAllowSubs(raw)).toThrow(StudioAuthConfigError);
  });

  it('rejects a non-string value', () => {
    expect(() => parseAllowSubs(1001)).toThrow(/comma-separated string/);
    expect(() => parseAllowSubs(['1001'])).toThrow(/comma-separated string/);
  });

  it('the error never echoes the offending value', () => {
    try {
      parseAllowSubs('super-secret-login');
      expect.unreachable();
    } catch (err) {
      expect(String((err as Error).message)).not.toContain('super-secret-login');
    }
  });
});

describe('readStudioAuthConfig', () => {
  it('is null (admits nobody) when the issuer or the JWKS URL is missing or blank', () => {
    expect(readStudioAuthConfig(undefined)).toBeNull();
    expect(readStudioAuthConfig({ STUDIO_AUTH_ISSUER: TEST_ISSUER })).toBeNull();
    expect(readStudioAuthConfig({ STUDIO_AUTH_JWKS_URL: TEST_JWKS_URL })).toBeNull();
    expect(
      readStudioAuthConfig({ STUDIO_AUTH_ISSUER: '  ', STUDIO_AUTH_JWKS_URL: TEST_JWKS_URL }),
    ).toBeNull();
  });

  it('pins the audience in code: another value throws, the pinned one and unset are fine', () => {
    expect(() =>
      readStudioAuthConfig({ ...ENABLED_ENV, STUDIO_AUTH_AUDIENCE: 'knowledge-retrieval' }),
    ).toThrow(/pinned to "discord-mcp"/);
    expect(
      readStudioAuthConfig({ ...ENABLED_ENV, STUDIO_AUTH_AUDIENCE: STUDIO_AUDIENCE })?.audience,
    ).toBe('discord-mcp');
    expect(readStudioAuthConfig({ ...ENABLED_ENV, STUDIO_AUTH_AUDIENCE: '' })?.audience).toBe(
      'discord-mcp',
    );
  });

  it('sorts and de-duplicates the lists so the verifier key is stable', () => {
    const config = readStudioAuthConfig({
      ...ENABLED_ENV,
      STUDIO_AUTH_ALLOW_SUBS: '1002, 1001,1001',
      STUDIO_AUTH_STUDIO_KIDS: 'b,a,a',
    });
    expect(config?.allowSubs).toEqual(['1001', '1002']);
    expect(config?.studioKids).toEqual(['a', 'b']);
  });

  it('pickStudioAuthEnv snapshots exactly the studio keys', () => {
    const picked = pickStudioAuthEnv({ ...ENABLED_ENV, DISCORD_TOKEN: 'x', PATH: '/bin' });
    expect(Object.keys(picked).sort()).toEqual(
      [
        'STUDIO_AUTH_ALLOW_SUBS',
        'STUDIO_AUTH_ENABLED',
        'STUDIO_AUTH_ISSUER',
        'STUDIO_AUTH_JWKS_URL',
      ].sort(),
    );
    for (const key of Object.keys(picked)) expect(STUDIO_AUTH_ENV_KEYS).toContain(key);
  });
});

// ---------------------------------------------------------------- the claim rule

const jws = (header: unknown, payload = 'e30', signature = 'AAAA'): string =>
  `${b64url(JSON.stringify(header))}.${payload}.${signature}`;

describe('isStudioJws: the claim rule', () => {
  it('claims a three-segment JWS whose protected header has alg ES256', () => {
    expect(isStudioJws(jws({ alg: 'ES256', kid: 'k' }))).toBe(true);
    expect(isStudioJws(jws({ alg: 'ES256' }))).toBe(true);
  });

  it.each([
    ['RS256', { alg: 'RS256' }],
    ['HS256', { alg: 'HS256' }],
    ['none', { alg: 'none' }],
    ['lower-case es256', { alg: 'es256' }],
    ['ES256 with a trailing space', { alg: 'ES256 ' }],
    ['alg is an array', { alg: ['ES256'] }],
    ['alg missing', { kid: 'k' }],
    ['alg null', { alg: null }],
    ['header is an array', ['ES256']],
    ['header is a string', 'ES256'],
    ['header is null', null],
    ['header is a number', 7],
  ])('does not claim %s', (_name, header) => {
    expect(isStudioJws(jws(header))).toBe(false);
  });

  it('does not claim an inherited alg (only an own property counts)', () => {
    const inherited = `${b64url('{"__proto__":{"alg":"ES256"}}')}.e30.AAAA`;
    expect(isStudioJws(inherited)).toBe(false);
  });

  it.each([
    ['an opaque API key', 'tok_abcdef0123456789abcdef0123456789'],
    ['a two-segment token', `${b64url('{"alg":"ES256"}')}.e30`],
    ['a four-segment token', `${b64url('{"alg":"ES256"}')}.e30.AAAA.AAAA`],
    ['an empty string', ''],
    ['dots only', '..'],
    ['an empty header segment', '.e30.AAAA'],
    ['a dotted CI key', 'abc.def.ghi'],
    ['a header that is not base64url', '@@@@.e30.AAAA'],
    [
      'a header with standard-base64 characters',
      `${Buffer.from('{"alg":"ES256"}').toString('base64')}+/.e30.AAAA`,
    ],
    ['a header that is base64url of non-JSON', `${b64url('not json')}.e30.AAAA`],
    [
      'a header that is not valid UTF-8',
      `${Buffer.from([0xff, 0xfe, 0xfd]).toString('base64url')}.e30.AAAA`,
    ],
  ])('does not claim %s and does not throw', (_name, token) => {
    expect(() => isStudioJws(token)).not.toThrow();
    expect(isStudioJws(token)).toBe(false);
  });

  it.each([
    [undefined],
    [null],
    [0],
    [{}],
    [[]],
    [Symbol.iterator],
  ])('never throws on a non-string (%s)', (value) => {
    expect(isStudioJws(value)).toBe(false);
  });

  it('does not claim an otherwise-ES256 header that is not valid UTF-8 (the decode is fatal)', () => {
    const bytes = Buffer.concat([
      Buffer.from('{"alg":"ES256","p":"'),
      Buffer.from([0xff]),
      Buffer.from('"}'),
    ]);
    expect(isStudioJws(`${bytes.toString('base64url')}.e30.AAAA`)).toBe(false);
  });

  it('does not claim a header written in standard base64 (+ and / are not base64url)', () => {
    const std = Buffer.from('{"alg":"ES256","x":"???>>>>>"}').toString('base64');
    expect(std).toMatch(/[+/]/);
    expect(std.endsWith('=')).toBe(false);
    expect(isStudioJws(`${std}.e30.AAAA`)).toBe(false);
    // control: the same bytes as base64url ARE claimed, so the refusal above is about the alphabet alone.
    expect(
      isStudioJws(`${Buffer.from('{"alg":"ES256","x":"???>>>>>"}').toString('base64url')}.e30.AAAA`),
    ).toBe(true);
  });

  it('ignores the payload and signature segments (the verifier owns them)', () => {
    expect(isStudioJws(jws({ alg: 'ES256' }, '!!!!', '????'))).toBe(true);
  });
});

/** A valid, decodable ES256 header whose base64url form is exactly `chars` characters (chars % 4 === 0). */
function headerOfExactLength(chars: number): string {
  const bytes = (chars / 4) * 3;
  const prefix = '{"alg":"ES256","p":"';
  const suffix = '"}';
  const json = prefix + 'x'.repeat(bytes - prefix.length - suffix.length) + suffix;
  const head = Buffer.from(json).toString('base64url');
  expect(head.length).toBe(chars);
  return head;
}

describe('isStudioJws: the token cap is checked before any decode', () => {
  it('mirrors the vendored verifier MAX_TOKEN_CHARS', () => {
    expect(resolveMaxTokenChars(readFileSync(VENDORED_URL, 'utf8'))).toBe(STUDIO_MAX_TOKEN_CHARS);
  });

  it('claims at the cap and 4 under it; refuses 4 and 100 over it (valid, decodable headers)', () => {
    const cap = STUDIO_MAX_TOKEN_CHARS;
    expect(isStudioJws(`${headerOfExactLength(cap - 4)}.e30.AAAA`)).toBe(true);
    expect(isStudioJws(`${headerOfExactLength(cap)}.e30.AAAA`)).toBe(true);
    expect(isStudioJws(`${headerOfExactLength(cap + 4)}.e30.AAAA`)).toBe(false);
    expect(isStudioJws(`${headerOfExactLength(cap + 100)}.e30.AAAA`)).toBe(false);
  });

  it('cap+1 is pinned by an atob call-count spy (a lone trailing base64 char fails decoding anyway)', () => {
    const cap = STUDIO_MAX_TOKEN_CHARS;
    const spy = vi.spyOn(globalThis, 'atob');

    // positive control: a small valid header registers a call, so "zero calls" below is not vacuous.
    isStudioJws(jws({ alg: 'ES256' }));
    expect(spy).toHaveBeenCalledTimes(1);

    spy.mockClear();
    // at the cap the header IS decoded ...
    isStudioJws(`${headerOfExactLength(cap)}.e30.AAAA`);
    expect(spy).toHaveBeenCalledTimes(1);

    // ... one character over it is not looked at, and neither are far larger ones.
    spy.mockClear();
    expect(isStudioJws(`${'A'.repeat(cap + 1)}.e30.AAAA`)).toBe(false);
    expect(isStudioJws(`${headerOfExactLength(cap + 4)}.e30.AAAA`)).toBe(false);
    expect(isStudioJws(`${'A'.repeat(1_000_000)}.e30.AAAA`)).toBe(false);
    expect(spy).not.toHaveBeenCalled();
  });

  it('an over-long PAYLOAD or SIGNATURE with a normal header is still claimed (the verifier refuses it)', async () => {
    const big = 'A'.repeat(STUDIO_MAX_TOKEN_CHARS + 50);
    expect(isStudioJws(jws({ alg: 'ES256' }, big))).toBe(true);
    expect(isStudioJws(jws({ alg: 'ES256' }, 'e30', big))).toBe(true);
    // and the gate turns that into bad_format without ever fetching a JWKS
    const decision = await studioGate(
      bearer(jws({ alg: 'ES256', kid: 'k' }, big)),
      ENABLED_ENV,
      deps(),
    );
    expectRefusal(decision, 401, 'bad_format');
    expect(jwks.jwksFetches()).toBe(0);
  });
});

/**
 * Resolve the vendored verifier's MAX_TOKEN_CHARS from its source. Anchored on the DECLARATION: comments are
 * stripped first, then exactly one `const MAX_TOKEN_CHARS = <int>;` line must remain. A decoy (another name, a
 * commented-out declaration, a renamed const) must not satisfy it and two declarations are ambiguous.
 */
function resolveMaxTokenChars(source: string): number {
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  const matches = [
    ...code.matchAll(/^[ \t]*const[ \t]+MAX_TOKEN_CHARS[ \t]*=[ \t]*(\d+)[ \t]*;[ \t]*$/gm),
  ];
  if (matches.length !== 1) {
    throw new Error(`expected exactly one MAX_TOKEN_CHARS declaration, found ${matches.length}`);
  }
  return Number(matches[0]?.[1]);
}

describe('the MAX_TOKEN_CHARS resolver can fail', () => {
  const real = 'const MAX_TOKEN_CHARS = 8192;';
  it('reads the real declaration', () => {
    expect(resolveMaxTokenChars(`${real}\n`)).toBe(8192);
  });
  it('ignores a decoy declaration above (a different name)', () => {
    expect(
      resolveMaxTokenChars(
        `const OLD_MAX_TOKEN_CHARS = 1;\nconst MAX_TOKEN_CHARS_X = 2;\n${real}\n`,
      ),
    ).toBe(8192);
  });
  it('ignores a decoy in a line comment and in a block comment', () => {
    expect(
      resolveMaxTokenChars(
        `// const MAX_TOKEN_CHARS = 1;\n/* const MAX_TOKEN_CHARS = 2; */\n${real}\n`,
      ),
    ).toBe(8192);
  });
  it('throws when the const was renamed', () => {
    expect(() => resolveMaxTokenChars('const MAX_TOKEN_LEN = 8192;\n')).toThrow(/found 0/);
  });
  it('throws on two declarations', () => {
    expect(() => resolveMaxTokenChars(`${real}\nconst MAX_TOKEN_CHARS = 9;\n`)).toThrow(/found 2/);
  });
});

// ---------------------------------------------------------------- the gate

describe('studioGate: not a studio credential', () => {
  it.each([
    ['no Authorization header', {}],
    ['an opaque key', bearer('opaque-key-0123456789abcdef0123456789')],
    ['a dotted CI key', bearer('abc.def.ghi')],
    ['an RS256 JWT', bearer(jws({ alg: 'RS256' }))],
    ['a Basic header', { authorization: 'Basic dXNlcjpwYXNz' }],
    ['an empty bearer', { authorization: 'Bearer ' }],
  ])('REQUIRED off: %s is unclaimed and the existing path runs unchanged', async (_name, headers) => {
    expect(await studioGate(headers, ENABLED_ENV, deps())).toEqual({ decision: 'unclaimed' });
  });

  it('REQUIRED off never consults the legacy-credential hook', async () => {
    const legacyCredentialOk = vi.fn(() => true);
    await studioGate(bearer('opaque'), ENABLED_ENV, deps({ legacyCredentialOk }));
    expect(legacyCredentialOk).not.toHaveBeenCalled();
  });

  it('REQUIRED on: no credential is 401 studio_credential_required (challenge without invalid_token)', async () => {
    const refusal = expectRefusal(
      await studioGate({}, REQUIRED_ENV, deps()),
      401,
      'studio_credential_required',
    );
    expect(refusal.presented).toBe(false);
  });

  it('REQUIRED on: an unaccepted credential is 401 studio_credential_not_accepted', async () => {
    const hook = vi.fn(() => false);
    expectRefusal(
      await studioGate(bearer('opaque-key'), REQUIRED_ENV, deps({ legacyCredentialOk: hook })),
      401,
      'studio_credential_not_accepted',
    );
    expect(hook).toHaveBeenCalledTimes(1);
  });

  it('REQUIRED on: a whitespace-only Authorization header counts as absent', async () => {
    expectRefusal(
      await studioGate({ authorization: '   ' }, REQUIRED_ENV, deps()),
      401,
      'studio_credential_required',
    );
  });

  it('REQUIRED on: the correct legacy credential is admitted as `legacy`, a wrong one is not', async () => {
    const legacyCredentialOk = (authorization: string | undefined) =>
      authorization === 'Bearer the-shared-secret';
    expect(
      await studioGate(
        { authorization: 'Bearer the-shared-secret' },
        REQUIRED_ENV,
        deps({ legacyCredentialOk }),
      ),
    ).toEqual({ decision: 'legacy' });
    expectRefusal(
      await studioGate(
        { authorization: 'Bearer nope' },
        REQUIRED_ENV,
        deps({ legacyCredentialOk }),
      ),
      401,
      'studio_credential_not_accepted',
    );
  });
});

describe('studioGate: a claimed studio credential', () => {
  it('allows a valid assertion for an allow-listed numeric id, principal github:<id>', async () => {
    const token = await signer.mint('1001');
    expect(await studioGate(bearer(token), ENABLED_ENV, deps())).toEqual({
      decision: 'allow',
      principal: 'github:1001',
    });
  });

  it('allows it in REQUIRED mode too', async () => {
    const token = await signer.mint('1002');
    expect(await studioGate(bearer(token), REQUIRED_ENV, deps())).toEqual({
      decision: 'allow',
      principal: 'github:1002',
    });
  });

  it('finds the Authorization header whatever its case', async () => {
    const token = await signer.mint('1001');
    expect(
      (await studioGate({ Authorization: `bearer ${token}` }, ENABLED_ENV, deps())).decision,
    ).toBe('allow');
  });

  const claimedRefusals: Array<[string, () => Promise<string>, number, string]> = [
    [
      'an expired assertion',
      () => signer.mint('1001', { exp: Math.floor(Date.now() / 1000) - 3600 }),
      401,
      'expired',
    ],
    [
      'an assertion issued in the future',
      () =>
        signer.mint('1001', {
          iat: Math.floor(Date.now() / 1000) + 3600,
          exp: Math.floor(Date.now() / 1000) + 7200,
        }),
      401,
      'not_yet_valid',
    ],
    [
      'another audience',
      () => signer.mint('1001', { aud: 'knowledge-retrieval' }),
      401,
      'wrong_aud',
    ],
    [
      'an audience list without ours',
      () => signer.mint('1001', { aud: ['knowledge-retrieval', 'ual'] }),
      401,
      'wrong_aud',
    ],
    [
      'another issuer',
      () => signer.mint('1001', { iss: 'https://evil.example' }),
      401,
      'wrong_iss',
    ],
    ['an owners-tier assertion', () => signer.mint('1001', { tier: 'owners' }), 403, 'wrong_tier'],
    [
      'a machine assertion',
      () =>
        signer.mint('1001', {
          kind: 'machine',
          sub: 'oidc:repo:The1Studio/x:ref:refs/heads/main',
          login: 'oidc',
        }),
      403,
      'wrong_kind',
    ],
    ['a valid id that is not on the allowlist', () => signer.mint('2002'), 403, 'not_allowed'],
    ['a non-numeric sub', () => signer.mint('github:1001'), 401, 'bad_format'],
    ['an unknown kid', () => signer.mint('1001', {}, { kid: 'someone-elses-key' }), 401, 'bad_sig'],
  ];

  it.each(
    claimedRefusals,
  )('refuses %s with the right status and a stable code', async (_name, mint, status, code) => {
    expectRefusal(await studioGate(bearer(await mint()), ENABLED_ENV, deps()), status, code);
  });

  it('refuses a tampered signature (bad_sig) and a tampered payload', async () => {
    const token = await signer.mint('1001');
    const [h, p, s] = token.split('.');
    const flipped = `${s?.slice(0, -2)}${s?.endsWith('AA') ? 'BB' : 'AA'}`;
    expectRefusal(
      await studioGate(bearer(`${h}.${p}.${flipped}`), ENABLED_ENV, deps()),
      401,
      'bad_sig',
    );
    const swapped = b64url(JSON.stringify(claimsFor('2002')));
    expectRefusal(
      await studioGate(bearer(`${h}.${swapped}.${s}`), ENABLED_ENV, deps()),
      401,
      'bad_sig',
    );
  });

  it('an empty allowlist admits NOBODY, even with an otherwise perfect assertion', async () => {
    const token = await signer.mint('1001');
    for (const raw of [undefined, '', ' , ']) {
      resetStudioAuthState();
      const env: StudioAuthEnv = { ...ENABLED_ENV };
      if (raw === undefined) delete env.STUDIO_AUTH_ALLOW_SUBS;
      else env.STUDIO_AUTH_ALLOW_SUBS = raw;
      expectRefusal(await studioGate(bearer(token), env, deps()), 403, 'not_allowed');
    }
  });

  it('JWKS down and never fetched fails closed with 503 jwks_unavailable', async () => {
    jwks.restore();
    jwks = stubJwksFetch(TEST_JWKS_URL, () => ({ status: 500 }));
    const token = await signer.mint('1001');
    expectRefusal(await studioGate(bearer(token), ENABLED_ENV, deps()), 503, 'jwks_unavailable');
  });

  it('the numeric sub is compared as a STRING: ids above 2^53 do not collapse onto their neighbours', async () => {
    const env: StudioAuthEnv = { ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: '9007199254740993' };
    expect(
      (await studioGate(bearer(await signer.mint('9007199254740993')), env, deps())).decision,
    ).toBe('allow');
    expectRefusal(
      await studioGate(bearer(await signer.mint('9007199254740992')), env, deps()),
      403,
      'not_allowed',
    );
    expectRefusal(
      await studioGate(bearer(await signer.mint('9007199254740994')), env, deps()),
      403,
      'not_allowed',
    );
  });

  it('identity is the numeric sub, never the login: a login equal to an allowed id gets nothing', async () => {
    expectRefusal(
      await studioGate(bearer(await signer.mint('999', { login: '1001' })), ENABLED_ENV, deps()),
      403,
      'not_allowed',
    );
    const decision = await studioGate(
      bearer(await signer.mint('1001', { login: 'attacker' })),
      ENABLED_ENV,
      deps(),
    );
    expect(decision).toEqual({ decision: 'allow', principal: 'github:1001' });
  });

  it('pinned signing kids: a kid outside STUDIO_AUTH_STUDIO_KIDS is refused wrong_tier', async () => {
    const token = await signer.mint('1001');
    expectRefusal(
      await studioGate(
        bearer(token),
        { ...ENABLED_ENV, STUDIO_AUTH_STUDIO_KIDS: 'some-other-kid' },
        deps(),
      ),
      403,
      'wrong_tier',
    );
    resetStudioAuthState();
    expect(
      (
        await studioGate(
          bearer(token),
          { ...ENABLED_ENV, STUDIO_AUTH_STUDIO_KIDS: signer.kid },
          deps(),
        )
      ).decision,
    ).toBe('allow');
  });

  it('an unknown verifier code (a future verifier) fails closed as 401 invalid_credential', async () => {
    const loadModule = async () => ({
      bearerFromRequest: (await import('./vendor/studio-auth-verify.mjs')).bearerFromRequest,
      createVerifier: () => ({
        verify: async () => ({ ok: false as const, code: 'brand_new_code' }),
      }),
    });
    expectRefusal(
      await studioGate(bearer(await signer.mint('1001')), ENABLED_ENV, deps({ loadModule })),
      401,
      'invalid_credential',
    );
  });
});

describe('studioGate: a claimed verdict is final and never rescued', () => {
  it('an invalid studio bearer is refused even when the legacy hook, an Access header and a cookie would all say yes', async () => {
    const legacyCredentialOk = vi.fn(() => true);
    const headers: IncomingHttpHeaders = {
      authorization: `Bearer ${await signer.mint('2002')}`,
      'cf-access-jwt-assertion': 'eyJhbGciOiJSUzI1NiJ9.e30.AAAA',
      'cf-access-authenticated-user-email': 'admin@the1studio.org',
      cookie: 'CF_Authorization=abc',
    };
    for (const env of [ENABLED_ENV, REQUIRED_ENV]) {
      resetStudioAuthState();
      expectRefusal(
        await studioGate(headers, env, deps({ legacyCredentialOk })),
        403,
        'not_allowed',
      );
    }
    expect(legacyCredentialOk).not.toHaveBeenCalled();
  });

  it('a verifier throw is a 500 with no identity, never a fall back', async () => {
    const bearerFromRequest = (await import('./vendor/studio-auth-verify.mjs')).bearerFromRequest;
    const loadModule = async () => ({
      bearerFromRequest,
      createVerifier: () => ({
        verify: async (): Promise<never> => {
          throw new Error('boom: eyJsecret.token.value');
        },
      }),
    });
    const refusal = expectRefusal(
      await studioGate(bearer(await signer.mint('1001')), ENABLED_ENV, deps({ loadModule })),
      500,
      'studio_auth_error',
    );
    expect(refusal.presented).toBe(false);
    expect(JSON.stringify(logs)).not.toContain('eyJsecret');
    expect(JSON.stringify(logs)).not.toContain('boom');
  });

  it('a createVerifier throw and a failed module load are 500, and the load is retried', async () => {
    const real = await import('./vendor/studio-auth-verify.mjs');
    expectRefusal(
      await studioGate(
        bearer(await signer.mint('1001')),
        ENABLED_ENV,
        deps({
          loadModule: async () => ({
            bearerFromRequest: real.bearerFromRequest,
            createVerifier: () => {
              throw new Error('bad config');
            },
          }),
        }),
      ),
      500,
      'studio_auth_error',
    );

    let attempts = 0;
    const loader = createModuleLoader(async () => {
      attempts += 1;
      if (attempts === 1) throw new Error('disk hiccup');
      return real;
    });
    resetStudioAuthState();
    const token = await signer.mint('1001');
    expectRefusal(
      await studioGate(bearer(token), ENABLED_ENV, deps({ loadModule: loader.load })),
      500,
      'studio_auth_error',
    );
    expect(
      (await studioGate(bearer(token), ENABLED_ENV, deps({ loadModule: loader.load }))).decision,
    ).toBe('allow');
    expect(loader.count()).toBe(2);
  });

  it('config errors on a claimed bearer are 500, not a pass: bad allowlist, bad audience, no issuer', async () => {
    const token = await signer.mint('1001');
    expectRefusal(
      await studioGate(
        bearer(token),
        { ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: 'octocat' },
        deps(),
      ),
      500,
      'studio_auth_config_invalid',
    );
    expectRefusal(
      await studioGate(bearer(token), { ...ENABLED_ENV, STUDIO_AUTH_AUDIENCE: 'ual' }, deps()),
      500,
      'studio_auth_config_invalid',
    );
    const { STUDIO_AUTH_ISSUER: _issuer, ...noIssuer } = ENABLED_ENV;
    expectRefusal(
      await studioGate(bearer(token), noIssuer, deps()),
      500,
      'studio_auth_not_configured',
    );
  });

  it('a repeated config-class failure logs once, with a fixed message', async () => {
    const token = await signer.mint('1001');
    for (let i = 0; i < 5; i += 1) {
      await studioGate(
        bearer(token),
        { ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: 'octocat' },
        deps(),
      );
    }
    expect(logs.filter((l) => l.level === 'warn')).toHaveLength(1);
  });
});

describe('verifier cache: a stable string key, bounded, JWKS fetched once per config', () => {
  async function countingModule() {
    const real = await import('./vendor/studio-auth-verify.mjs');
    const created: unknown[] = [];
    return {
      created,
      loadModule: async () => ({
        bearerFromRequest: real.bearerFromRequest,
        createVerifier: (cfg: Parameters<typeof real.createVerifier>[0]) => {
          created.push(cfg);
          return real.createVerifier(cfg);
        },
      }),
    };
  }

  it('a config literal rebuilt per request still hits: one verifier, one JWKS fetch for 25 requests', async () => {
    const { created, loadModule } = await countingModule();
    const token = await signer.mint('1001');
    for (let i = 0; i < 25; i += 1) {
      const rebuilt = { ...ENABLED_ENV }; // a fresh object every time, like the per-request env read
      expect((await studioGate(bearer(token), rebuilt, deps({ loadModule }))).decision).toBe(
        'allow',
      );
    }
    expect(created).toHaveLength(1);
    expect(jwks.jwksFetches()).toBe(1);
    expect(studioVerifierCacheSize()).toBe(1);
  });

  it('list order and duplicates do not split the key; a real change does', async () => {
    const { created, loadModule } = await countingModule();
    const token = await signer.mint('1001');
    await studioGate(
      bearer(token),
      { ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: '1001,1002' },
      deps({ loadModule }),
    );
    await studioGate(
      bearer(token),
      { ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: '1002, 1001,1001' },
      deps({ loadModule }),
    );
    expect(created).toHaveLength(1);
    await studioGate(
      bearer(token),
      { ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: '1001' },
      deps({ loadModule }),
    );
    expect(created).toHaveLength(2);
  });

  it('concurrent first requests share one verifier and one JWKS fetch (single flight)', async () => {
    const token = await signer.mint('1001');
    const results = await Promise.all(
      Array.from({ length: 20 }, () => studioGate(bearer(token), { ...ENABLED_ENV }, deps())),
    );
    expect(results.every((r) => r.decision === 'allow')).toBe(true);
    expect(jwks.jwksFetches()).toBe(1);
  });

  it('is bounded: more distinct configs than the cap never grow it past the cap', async () => {
    const token = await signer.mint('1001');
    for (let i = 0; i < STUDIO_VERIFIER_CACHE_MAX + 5; i += 1) {
      await studioGate(
        bearer(token),
        { ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: `1001,${5000 + i}` },
        deps(),
      );
      expect(studioVerifierCacheSize()).toBeLessThanOrEqual(STUDIO_VERIFIER_CACHE_MAX);
    }
    expect(studioVerifierCacheSize()).toBe(STUDIO_VERIFIER_CACHE_MAX);
  });

  it('a cache reset isolates specs: the same kid under a new key is refused until the cache is dropped', async () => {
    const sameKidA = await createSigner('shared-kid');
    jwks.restore();
    jwks = stubJwksFetch(TEST_JWKS_URL, () => ({ status: 200, json: sameKidA.jwks() }));
    expect(
      (await studioGate(bearer(await sameKidA.mint('1001')), ENABLED_ENV, deps())).decision,
    ).toBe('allow');

    const sameKidB = await createSigner('shared-kid');
    jwks.restore();
    jwks = stubJwksFetch(TEST_JWKS_URL, () => ({ status: 200, json: sameKidB.jwks() }));
    // the cached verifier still holds A's key: B's token is bad_sig. This is the leak the reset prevents.
    expectRefusal(
      await studioGate(bearer(await sameKidB.mint('1001')), ENABLED_ENV, deps()),
      401,
      'bad_sig',
    );
    resetStudioAuthState();
    expect(
      (await studioGate(bearer(await sameKidB.mint('1001')), ENABLED_ENV, deps())).decision,
    ).toBe('allow');
  });
});

describe('no token, assertion or claim material in logs or bodies', () => {
  it('across every outcome the logs and refusal bodies carry none of it', async () => {
    const secrets: string[] = [];
    const tokens: string[] = [
      await signer.mint('1001', { login: 'ultra-secret-login' }),
      await signer.mint('2002', { login: 'ultra-secret-login-2' }),
      await signer.mint('1001', { tier: 'owners', login: 'ultra-secret-login-3' }),
      await signer.mint('1001', { exp: 1, iat: 0, login: 'ultra-secret-login-4' }),
    ];
    for (const t of tokens) secrets.push(t, ...t.split('.'));
    secrets.push('ultra-secret-login', 'jti-1001', 'jti-2002');
    const refusalBodies: string[] = [];
    const run = async (env: StudioAuthEnv, headers: IncomingHttpHeaders) => {
      const decision = await studioGate(headers, env, deps());
      if (decision.decision === 'refuse') {
        refusalBodies.push(
          studioRefusalResponse(decision, true).body,
          studioRefusalResponse(decision, false).body,
        );
      }
    };
    for (const t of tokens) await run(ENABLED_ENV, bearer(t));
    await run({ ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: 'octocat' }, bearer(tokens[0] ?? ''));
    await run(REQUIRED_ENV, bearer('opaque-secret-key-value-123'));
    secrets.push('opaque-secret-key-value-123');
    const everything = JSON.stringify(logs) + refusalBodies.join('\n');
    for (const secret of secrets)
      expect(everything, `leaked ${secret.slice(0, 12)}...`).not.toContain(secret);
    expect(refusalBodies.length).toBeGreaterThan(0); // positive control: the loop did produce bodies
  });
});

describe('refusal responses', () => {
  const r = (status: StudioRefusal['status'], code: string, presented: boolean): StudioRefusal => ({
    decision: 'refuse',
    status,
    code,
    presented,
  });

  it('/mcp gets a JSON-RPC error envelope with id null; other routes a small REST body; length is exact', () => {
    const mcp = studioRefusalResponse(r(401, 'expired', true), true);
    expect(JSON.parse(mcp.body)).toEqual({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32001, message: 'unauthorized: expired', data: { code: 'expired' } },
    });
    expect(mcp.headers['content-length']).toBe(String(Buffer.byteLength(mcp.body)));
    expect(mcp.headers['content-type']).toBe('application/json');
    expect(mcp.headers['cache-control']).toBe('no-store');
    expect(JSON.parse(studioRefusalResponse(r(401, 'expired', true), false).body)).toEqual({
      error: 'unauthorized',
      code: 'expired',
    });
  });

  it('401 carries the realm, plus invalid_token only when a studio credential was presented', () => {
    expect(
      studioRefusalResponse(r(401, 'studio_credential_required', false), true).headers[
        'www-authenticate'
      ],
    ).toBe(`Bearer realm="${STUDIO_REALM}"`);
    expect(studioRefusalResponse(r(401, 'bad_sig', true), true).headers['www-authenticate']).toBe(
      `Bearer realm="${STUDIO_REALM}", error="invalid_token"`,
    );
  });

  it('403 has no challenge, 503 has Retry-After, 500 is a server-side JSON-RPC error', () => {
    const forbidden = studioRefusalResponse(r(403, 'not_allowed', true), true);
    expect(forbidden.headers['www-authenticate']).toBeUndefined();
    expect(JSON.parse(forbidden.body).error.code).toBe(-32001);
    const unavailable = studioRefusalResponse(r(503, 'jwks_unavailable', true), true);
    expect(unavailable.headers['retry-after']).toBe('30');
    expect(JSON.parse(unavailable.body).error.code).toBe(-32603);
    const broken = studioRefusalResponse(r(500, 'studio_auth_error', false), false);
    expect(JSON.parse(broken.body)).toEqual({ error: 'misconfigured', code: 'studio_auth_error' });
  });

  it('the 400 for a bad request target is stable and echoes nothing from the request', () => {
    const bad = studioBadRequestResponse();
    expect(bad.status).toBe(400);
    expect(JSON.parse(bad.body)).toEqual({ error: 'bad_request', code: 'invalid_request_target' });
    expect(bad.headers['content-length']).toBe(String(Buffer.byteLength(bad.body)));
  });

  it('every code the gate can emit is in STUDIO_REFUSAL_CODES', () => {
    expect(new Set(STUDIO_REFUSAL_CODES)).toEqual(
      new Set([
        'bad_format',
        'bad_alg',
        'bad_sig',
        'wrong_iss',
        'wrong_aud',
        'expired',
        'not_yet_valid',
        'wrong_tier',
        'wrong_kind',
        'not_allowed',
        'jwks_unavailable',
        'invalid_credential',
        'studio_credential_required',
        'studio_credential_not_accepted',
        'studio_auth_config_invalid',
        'studio_auth_not_configured',
        'studio_auth_error',
      ]),
    );
  });
});

describe('StudioGuard.prepare: fail fast at startup, no network', () => {
  const guard = (env: StudioAuthEnv) => {
    const g = createStudioGuard(env, deps());
    if (g === null) throw new Error('guard unexpectedly null');
    return g;
  };

  it('succeeds on a good config, reports a summary, and makes no network call', async () => {
    await guard(ENABLED_ENV).prepare();
    expect(jwks.jwksFetches()).toBe(0);
    expect(logs[0]).toMatchObject({
      level: 'info',
      message: 'studio auth enabled',
      fields: { issuer: TEST_ISSUER, audience: TEST_AUDIENCE, allowed: 2, required: false },
    });
  });

  it('warns loudly when the allowlist is empty (nobody can use the studio path)', async () => {
    await guard({ ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: '' }).prepare();
    expect(logs.some((l) => l.level === 'warn' && /nobody/.test(l.message))).toBe(true);
  });

  it.each([
    [
      'a missing issuer',
      { STUDIO_AUTH_ENABLED: 'true', STUDIO_AUTH_JWKS_URL: TEST_JWKS_URL },
      /needs STUDIO_AUTH_ISSUER/,
    ],
    [
      'a missing JWKS URL',
      { STUDIO_AUTH_ENABLED: 'true', STUDIO_AUTH_ISSUER: TEST_ISSUER },
      /needs STUDIO_AUTH_ISSUER/,
    ],
    [
      'a malformed allowlist',
      { ...ENABLED_ENV, STUDIO_AUTH_ALLOW_SUBS: 'octocat' },
      /numeric GitHub ids/,
    ],
    ['a different audience', { ...ENABLED_ENV, STUDIO_AUTH_AUDIENCE: 'ual' }, /pinned to/],
    [
      'a non-https JWKS URL',
      { ...ENABLED_ENV, STUDIO_AUTH_JWKS_URL: 'http://auth.test.invalid/jwks' },
      /must be https/,
    ],
    [
      'an unparseable JWKS URL',
      { ...ENABLED_ENV, STUDIO_AUTH_JWKS_URL: 'not a url' },
      /not a valid URL/,
    ],
  ])('rejects %s', async (_name, env, message) => {
    await expect(guard(env as StudioAuthEnv).prepare()).rejects.toThrow(message);
  });
});

describe('the audience is not the one any sibling service pins', () => {
  it('is discord-mcp', () => {
    expect(STUDIO_AUDIENCE).toBe('discord-mcp');
    expect(STUDIO_REALM).toBe('discord-mcp');
  });
});
