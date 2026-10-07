/**
 * FLAG-OFF BYTE IDENTITY. With the studio gate off, `http.ts` must answer exactly what it answered before the
 * gate existed. The oracle is the pre-change handler, frozen in `legacy/http.legacy.ts`; this spec runs the same
 * request matrix against both and compares status, headers (minus `date`) and a hash of the body.
 *
 * The oracle is only worth anything if it IS the pre-change handler, so two pins make that checkable:
 *   BASE_ORIGINAL_SHA256  the sha256 of `git show bf1bb51:packages/mcp-server/src/transports/http.ts`
 *   LEGACY_FILE_SHA256    the sha256 of the frozen copy as committed
 * and the original is reconstructed from the copy by reversing exactly the declared import rewrites.
 *
 * Not claimed: this proves the two handlers agree on the matrix below, not on every possible request.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type { Server } from 'node:http';
import { request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { startHttp as startCurrent } from './http.js';
import { startHttp as startLegacy } from './legacy/http.legacy.js';
import { b64url } from './testkit/studio-auth-signer.js';

const BASE_ORIGINAL_SHA256 = '4d963b158c8ad96e53e34f50e77c6a43687bb765107b5ef6be9fc5e06cc696e8';
const LEGACY_FILE_SHA256 = 'cbc8fce883933df543ca7a96fe18dafd91d0eae329abbab42181133cc0c3be2f';

const LEGACY_FILE = new URL('./legacy/http.legacy.ts', import.meta.url);
const CURRENT_FILE = new URL('./http.ts', import.meta.url);
const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

/** The declared rewrites between the original and the oracle (it sits one directory deeper). */
const REWRITES: Array<[original: string, oracle: string]> = [
  ["from '../lib/activity.js'", "from '../../lib/activity.js'"],
  ["from '../otel.js'", "from '../../otel.js'"],
  ["import('../otel.js')", "import('../../otel.js')"],
];

function reconstructOriginal(oracleText: string): string {
  let text = oracleText;
  for (const [original, oracle] of REWRITES) text = text.split(oracle).join(original);
  return text;
}

const VALID_TOKEN = `Bot ${'a'.repeat(60)}`;
const ACCESS_TOKEN = 'test-access-token-with-at-least-32-characters';
const LIST_TOOLS = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
const savedEnv = { ...process.env };

describe('the oracle is the pre-change handler', () => {
  const oracleText = readFileSync(LEGACY_FILE, 'utf8');

  it('the frozen copy is byte-for-byte what was committed (an edit fails here)', () => {
    expect(sha256(oracleText)).toBe(LEGACY_FILE_SHA256);
  });

  it('reversing the declared import rewrites reproduces the original blob exactly', () => {
    expect(sha256(reconstructOriginal(oracleText))).toBe(BASE_ORIGINAL_SHA256);
  });

  it('the rewrites are exactly the declared ones (an undeclared change would break the reconstruction)', () => {
    const changed = reconstructOriginal(oracleText) !== oracleText;
    expect(changed).toBe(true);
    expect(reconstructOriginal(oracleText)).not.toContain('../../');
  });

  it('the oracle contains no studio code, and the real handler does (so they cannot be the same file)', () => {
    expect(/studio/i.test(oracleText)).toBe(false);
    expect(/studio/i.test(readFileSync(CURRENT_FILE, 'utf8'))).toBe(true);
  });

  it('a one-character edit to the oracle is detected by the hash pin', () => {
    expect(sha256(oracleText.replace("'/healthz'", "'/healthy'"))).not.toBe(LEGACY_FILE_SHA256);
  });
});

interface Normalized {
  status: number;
  headers: Array<[string, string]>;
  bodySha: string;
  bodyLength: number;
}

function exchange(
  port: number,
  method: string,
  path: string,
  headers: Record<string, string>,
  body: string | undefined,
): Promise<Normalized> {
  return new Promise((resolve) => {
    const req = request(
      { host: '127.0.0.1', port, method, path, headers, agent: false },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        const finish = () => {
          const bodyBuffer = Buffer.concat(chunks);
          resolve({
            status: response.statusCode ?? 0,
            headers: Object.entries(response.headers)
              .filter(([name]) => name !== 'date')
              .map(([name, value]): [string, string] => [name, String(value)])
              .sort(([a], [b]) => a.localeCompare(b)),
            bodySha: createHash('sha256').update(bodyBuffer).digest('hex'),
            bodyLength: bodyBuffer.length,
          });
        };
        response.once('end', finish);
        response.once('error', finish);
      },
    );
    req.once('error', () =>
      resolve({ status: -1, headers: [['error', 'request failed']], bodySha: '', bodyLength: 0 }),
    );
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const fakeStudioJws = `${b64url('{"alg":"ES256","kid":"k"}')}.${b64url('{"sub":"1001"}')}.${'A'.repeat(86)}`;
const CREDENTIALS: Array<[string, Record<string, string>]> = [
  ['none', {}],
  ['legacy secret', { authorization: `Bearer ${ACCESS_TOKEN}` }],
  ['legacy secret, lower-case scheme', { authorization: `bearer ${ACCESS_TOKEN}` }],
  ['wrong opaque token', { authorization: 'Bearer wrong-opaque-token-0000000000000000' }],
  ['studio-shaped ES256 JWS', { authorization: `Bearer ${fakeStudioJws}` }],
  ['huge whitespace bearer', { authorization: `Bearer ${' '.repeat(50_000)}` }],
  ['bare Bearer', { authorization: 'Bearer' }],
  ['Basic', { authorization: 'Basic dXNlcjpwYXNz' }],
  [
    'Access-style headers only',
    { 'cf-access-jwt-assertion': 'eyJhbGciOiJSUzI1NiJ9.e30.AAAA', cookie: 'CF_Authorization=x' },
  ],
];
const METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS'];
const PATHS = [
  '/mcp',
  '/healthz',
  '/MCP',
  '/HEALTHZ',
  '/mcp/',
  '/healthz/',
  '/x',
  '//evil/mcp',
  '/%6dcp',
  '/mcp?x=1',
  '/healthz?x=1',
];

async function runMatrix(port: number): Promise<Record<string, Normalized>> {
  const out: Record<string, Normalized> = {};
  for (const method of METHODS) {
    for (const path of PATHS) {
      for (const [name, credential] of CREDENTIALS) {
        const hasBody = method === 'POST';
        const headers: Record<string, string> = {
          ...credential,
          ...(hasBody
            ? { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }
            : {}),
        };
        out[`${method} ${path} [${name}]`] = await exchange(
          port,
          method,
          path,
          headers,
          hasBody ? LIST_TOOLS : undefined,
        );
      }
    }
  }
  return out;
}

let server: Server | undefined;
let activityRoot: string;
const rejections: string[] = [];
const onRejection = (reason: unknown) =>
  rejections.push(String((reason as Error)?.message ?? reason));

async function closeServer(): Promise<void> {
  if (server === undefined) return;
  await new Promise<void>((resolve, reject) =>
    server?.close((error) => (error ? reject(error) : resolve())),
  );
  server = undefined;
}

function setEnv(env: Record<string, string | undefined>): void {
  process.env = { ...savedEnv };
  process.env.APPDATA = activityRoot;
  process.env.XDG_CONFIG_HOME = activityRoot;
  process.env.DISCORD_TOKEN = VALID_TOKEN;
  process.env.LOG_LEVEL = 'fatal';
  process.env.MCP_AUDIT_ENABLED = 'false';
  delete process.env.DISCORD_MCP_ACCESS_TOKEN;
  delete process.env.DISCORD_EXPECTED_BOT_ID;
  for (const key of Object.keys(process.env))
    if (key.startsWith('STUDIO_AUTH_')) delete process.env[key];
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

async function withServer<T>(
  start: typeof startCurrent,
  env: Record<string, string | undefined>,
  use: (port: number) => Promise<T>,
): Promise<T> {
  setEnv(env);
  server = await start({ port: 0, registerSignalHandlers: false });
  try {
    return await use((server.address() as AddressInfo).port);
  } finally {
    await closeServer();
  }
}

beforeEach(() => {
  activityRoot = mkdtempSync(join(tmpdir(), 'discord-mcp-differential-'));
  rejections.length = 0;
  process.on('unhandledRejection', onRejection);
});

afterEach(async () => {
  process.off('unhandledRejection', onRejection);
  await closeServer();
  rmSync(activityRoot, { recursive: true, force: true });
  process.env = { ...savedEnv };
});

const STUDIO_VARS = {
  STUDIO_AUTH_ISSUER: 'https://auth.test.invalid',
  STUDIO_AUTH_JWKS_URL: 'https://auth.test.invalid/.well-known/jwks.json',
  STUDIO_AUTH_ALLOW_SUBS: '1001,1002',
};

const SCENARIOS: Array<[string, Record<string, string | undefined>]> = [
  ['no studio variables, no shared secret', {}],
  ['no studio variables, shared secret set', { DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN }],
  [
    'studio variables present but ENABLED unset, shared secret set',
    { ...STUDIO_VARS, DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN },
  ],
  [
    'ENABLED=false with REQUIRED=false, shared secret set',
    {
      ...STUDIO_VARS,
      STUDIO_AUTH_ENABLED: 'false',
      STUDIO_AUTH_REQUIRED: 'false',
      DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN,
    },
  ],
  ...[' true', 'True', '1', 'yes', 'TRUE', 'true '].map(
    (lookalike): [string, Record<string, string | undefined>] => [
      `ENABLED=${JSON.stringify(lookalike)} (a lookalike is OFF), shared secret set`,
      { ...STUDIO_VARS, STUDIO_AUTH_ENABLED: lookalike, DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN },
    ],
  ),
  ['ENABLED="True", no shared secret', { ...STUDIO_VARS, STUDIO_AUTH_ENABLED: 'True' }],
];

describe('flag off: the real handler is byte-identical to the frozen pre-change handler', () => {
  it.each(SCENARIOS)('%s', async (_name, env) => {
    const legacy = await withServer(startLegacy, env, runMatrix);
    const current = await withServer(startCurrent, env, runMatrix);
    const keys = Object.keys(legacy);
    expect(keys.length).toBe(METHODS.length * PATHS.length * CREDENTIALS.length);
    expect(Object.keys(current)).toEqual(keys);
    for (const key of keys) expect(current[key], key).toEqual(legacy[key]);
  });

  it('the matrix is not vacuous: it contains 200s, 401s and 404s from the legacy handler', async () => {
    const legacy = await withServer(
      startLegacy,
      { DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN },
      runMatrix,
    );
    const statuses = new Set(Object.values(legacy).map((r) => r.status));
    for (const expected of [200, 401, 404])
      expect(statuses.has(expected), `status ${expected}`).toBe(true);
  });
});

/** Raw request: returns the first response line, or '' when the connection closed without answering. */
function raw(port: number, text: string): Promise<string> {
  return new Promise((resolve) => {
    const socket = createConnection(port, '127.0.0.1');
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
    });
    socket.on('close', () => resolve(buffer.split('\r\n')[0] ?? ''));
    socket.on('error', () => resolve(''));
    socket.write(text);
    setTimeout(() => socket.destroy(), 600);
  });
}

describe('flag off keeps the legacy malformed-request-target crash on purpose', () => {
  const targets = [
    'GET // HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n',
    'GET http://[bad/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n',
  ];

  it('both handlers drop the connection and raise one unhandled rejection per request (flag off)', async () => {
    const observed: Record<string, { lines: string[]; rejections: number }> = {};
    for (const [name, start] of [
      ['legacy', startLegacy],
      ['current', startCurrent],
    ] as const) {
      rejections.length = 0;
      const lines = await withServer(start, {}, async (port) => {
        const out: string[] = [];
        for (const text of targets) out.push(await raw(port, text));
        return out;
      });
      observed[name] = { lines, rejections: rejections.length };
    }
    expect(observed.current).toEqual(observed.legacy);
    expect(observed.legacy?.lines).toEqual(['', '']);
    expect(observed.legacy?.rejections).toBe(2);
  });

  it('with the flag ON the same request is a 400 and no rejection (the guard is flag-on only)', async () => {
    rejections.length = 0;
    const lines = await withServer(
      startCurrent,
      { ...STUDIO_VARS, STUDIO_AUTH_ENABLED: 'true' },
      async (port) => Promise.all(targets.map((text) => raw(port, text))),
    );
    expect(lines).toEqual(['HTTP/1.1 400 Bad Request', 'HTTP/1.1 400 Bad Request']);
    expect(rejections).toEqual([]);
  });
});
