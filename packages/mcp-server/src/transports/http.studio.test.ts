/**
 * The studio gate WIRED into the real HTTP transport, over real loopback sockets. The unit specs
 * (studio-auth.test.ts) pin the decision; these pin that http.ts acts on it: where the gate sits in the request
 * path, that a refusal is written before any MCP handling exists, and that the legacy path is unchanged for
 * everything the gate does not claim.
 *
 * Dispatch is counted at the SDK boundary (`toNodeHandler`): a refused request must leave the counter at zero,
 * and the allowed controls in the same file prove the counter does move.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import type { Server } from 'node:http';
import { Agent, request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { startHttp } from './http.js';
import { resetStudioAuthState, STUDIO_MAX_TOKEN_CHARS } from './studio-auth.js';
import {
  createSigner,
  type JwksFetchStub,
  type Signer,
  stubJwksFetch,
  TEST_ISSUER,
  TEST_JWKS_URL,
} from './testkit/studio-auth-signer.js';

const dispatch = vi.hoisted(() => ({ count: 0 }));

vi.mock('@modelcontextprotocol/node', async (importOriginal) => {
  const original = await importOriginal<typeof import('@modelcontextprotocol/node')>();
  return {
    ...original,
    toNodeHandler: (...args: Parameters<typeof original.toNodeHandler>) => {
      const handler = original.toNodeHandler(...args);
      return (...handlerArgs: Parameters<typeof handler>) => {
        dispatch.count += 1;
        return handler(...handlerArgs);
      };
    },
  };
});

const VALID_TOKEN = `Bot ${'a'.repeat(60)}`;
const ACCESS_TOKEN = 'test-access-token-with-at-least-32-characters';
const LIST_TOOLS = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
const savedEnv = { ...process.env };

let server: Server | undefined;
let activityRoot: string;
let signer: Signer;
let jwks: JwksFetchStub;
let kidCounter = 0;
const rejections: unknown[] = [];
const onRejection = (reason: unknown) => rejections.push(reason);

interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function port(): number {
  const address = server?.address() as AddressInfo | null;
  if (address === null || address === undefined) throw new Error('HTTP server is not listening');
  return address.port;
}

function send(
  options: {
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    body?: string;
    /** Offer keep-alive, so a `Connection: close` in the reply is the SERVER's choice, not an echo of ours. */
    keepAlive?: boolean;
  } = {},
): Promise<Reply> {
  const agent = options.keepAlive ? new Agent({ keepAlive: true }) : false;
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port: port(),
        method: options.method ?? 'POST',
        path: options.path ?? '/mcp',
        agent,
        headers: {
          ...(options.method === 'GET' || options.method === 'HEAD'
            ? {}
            : {
                'content-type': 'application/json',
                accept: 'application/json, text/event-stream',
              }),
          ...options.headers,
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.once('end', () => {
          if (agent) agent.destroy();
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.once('error', reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

/** POST tools/list with an Authorization header (or none). */
const list = (authorization?: string, extra: Record<string, string> = {}) =>
  send({
    body: LIST_TOOLS,
    headers: { ...(authorization === undefined ? {} : { authorization }), ...extra },
  });

/** Write raw bytes and return the first response line, or '' when the server closed without answering. */
function raw(text: string): Promise<string> {
  return new Promise((resolve) => {
    const socket = createConnection(port(), '127.0.0.1');
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

async function boot(env: Record<string, string | undefined>): Promise<void> {
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  server = await startHttp({ port: 0, registerSignalHandlers: false });
}

const STUDIO = {
  STUDIO_AUTH_ENABLED: 'true',
  STUDIO_AUTH_ISSUER: TEST_ISSUER,
  STUDIO_AUTH_JWKS_URL: TEST_JWKS_URL,
  STUDIO_AUTH_ALLOW_SUBS: '1001,1002',
};
const REQUIRED = { ...STUDIO, STUDIO_AUTH_REQUIRED: 'true' };

async function closeServer(): Promise<void> {
  if (server === undefined) return;
  await new Promise<void>((resolve, reject) =>
    server?.close((error) => (error ? reject(error) : resolve())),
  );
  server = undefined;
}

beforeEach(async () => {
  resetStudioAuthState();
  dispatch.count = 0;
  rejections.length = 0;
  process.on('unhandledRejection', onRejection);
  activityRoot = mkdtempSync(join(tmpdir(), 'discord-mcp-studio-http-'));
  process.env = { ...savedEnv };
  process.env.APPDATA = activityRoot;
  process.env.XDG_CONFIG_HOME = activityRoot;
  process.env.DISCORD_TOKEN = VALID_TOKEN;
  process.env.LOG_LEVEL = 'fatal';
  process.env.MCP_AUDIT_ENABLED = 'false';
  delete process.env.DISCORD_MCP_ACCESS_TOKEN;
  delete process.env.DISCORD_EXPECTED_BOT_ID;
  delete process.env.MCP_HTTP_MAX_BODY_BYTES;
  delete process.env.MCP_HTTP_MAX_IN_FLIGHT;
  for (const key of Object.keys(process.env))
    if (key.startsWith('STUDIO_AUTH_')) delete process.env[key];
  kidCounter += 1;
  signer = await createSigner(`wired-kid-${kidCounter}`);
  jwks = stubJwksFetch(TEST_JWKS_URL, () => ({ status: 200, json: signer.jwks() }));
});

afterEach(async () => {
  process.off('unhandledRejection', onRejection);
  await closeServer();
  jwks.restore();
  vi.restoreAllMocks();
  rmSync(activityRoot, { recursive: true, force: true });
  process.env = { ...savedEnv };
});

const bearer = (token: string) => `Bearer ${token}`;
/** The Streamable HTTP reply is an SSE frame (`event: message` / `data: {...}`) or plain JSON. */
function toolCount(reply: Reply): number {
  const data = /^data: (.*)$/m.exec(reply.body)?.[1] ?? reply.body;
  return JSON.parse(data).result.tools.length;
}

describe('dual mode (ENABLED, REQUIRED off): the studio bearer is an ADDITIONAL credential', () => {
  it('serves a verified studio bearer even when DISCORD_MCP_ACCESS_TOKEN is set (it replaces the shared secret)', async () => {
    await boot({ ...STUDIO, DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN });
    const reply = await list(bearer(await signer.mint('1001')));
    expect(reply.status).toBe(200);
    expect(toolCount(reply)).toBe(209);
    expect(dispatch.count).toBe(1); // positive control for every zero below
  });

  it('a real SDK client with the studio bearer lists the tools', async () => {
    await boot(STUDIO);
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port()}/mcp`), {
      requestInit: { headers: { Authorization: bearer(await signer.mint('1002')) } },
    });
    const client = new Client({ name: 'studio-wired', version: '0.0.0' });
    await client.connect(transport as never);
    try {
      expect((await client.listTools()).tools).toHaveLength(209);
    } finally {
      await client.close();
    }
  });

  it('no credential and a shared secret set: the legacy 401 is byte-for-byte what it was', async () => {
    await boot({ ...STUDIO, DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN });
    const reply = await list();
    expect(reply.status).toBe(401);
    expect(reply.headers['www-authenticate']).toBe('Bearer');
    expect(reply.body).toBe('');
    expect(dispatch.count).toBe(0);
  });

  it('the correct shared secret still works; a wrong opaque token gets the legacy 401', async () => {
    await boot({ ...STUDIO, DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN });
    expect((await list(bearer(ACCESS_TOKEN))).status).toBe(200);
    const wrong = await list(bearer('wrong-opaque-token-000000000000000000'));
    expect(wrong.status).toBe(401);
    expect(wrong.headers['www-authenticate']).toBe('Bearer');
  });

  it('no credential and no shared secret: the existing open behaviour (Access is the gate)', async () => {
    await boot(STUDIO);
    expect((await list()).status).toBe(200);
  });

  it('a CLAIMED invalid bearer is refused even though the legacy path is open and Access-style headers are present', async () => {
    await boot(STUDIO);
    const expired = await signer.mint('1001', { exp: Math.floor(Date.now() / 1000) - 3600 });
    const reply = await list(bearer(expired), {
      'cf-access-jwt-assertion': 'eyJhbGciOiJSUzI1NiJ9.e30.AAAA',
      'cf-access-authenticated-user-email': 'admin@the1studio.org',
      cookie: 'CF_Authorization=abc',
    });
    expect(reply.status).toBe(401);
    expect(JSON.parse(reply.body).error.data.code).toBe('expired');
    expect(dispatch.count).toBe(0);
  });

  const refusals: Array<[string, () => Promise<string>, number, string]> = [
    ['an id not on the allowlist', () => signer.mint('2002'), 403, 'not_allowed'],
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
    [
      'another audience',
      () => signer.mint('1001', { aud: 'knowledge-retrieval' }),
      401,
      'wrong_aud',
    ],
    [
      'another issuer',
      () => signer.mint('1001', { iss: 'https://evil.example' }),
      401,
      'wrong_iss',
    ],
    [
      'an unknown signing key',
      () => signer.mint('1001', {}, { kid: 'nobody-signed-this' }),
      401,
      'bad_sig',
    ],
  ];
  it.each(
    refusals,
  )('refuses %s with the exact status and code, before any dispatch', async (_name, mint, status, code) => {
    await boot(STUDIO);
    const reply = await list(bearer(await mint()));
    expect(reply.status).toBe(status);
    expect(JSON.parse(reply.body).error.data.code).toBe(code);
    expect(dispatch.count).toBe(0);
  });

  it('JWKS unreachable is a 503 with Retry-After, never a pass', async () => {
    jwks.restore();
    jwks = stubJwksFetch(TEST_JWKS_URL, () => ({ status: 500 }));
    await boot(STUDIO);
    const reply = await list(bearer(await signer.mint('1001')));
    expect(reply.status).toBe(503);
    expect(reply.headers['retry-after']).toBe('30');
    expect(dispatch.count).toBe(0);
  });

  it('the JWKS is fetched once for many requests, including concurrent ones', async () => {
    await boot(STUDIO);
    const token = await signer.mint('1001');
    const replies = await Promise.all(Array.from({ length: 12 }, () => list(bearer(token))));
    expect(replies.every((r) => r.status === 200)).toBe(true);
    await list(bearer(token));
    expect(jwks.jwksFetches()).toBe(1);
  });

  it('after the gate allows, the rest of the pipeline is unchanged: an oversized body is still 413', async () => {
    await boot({ ...STUDIO, MCP_HTTP_MAX_BODY_BYTES: '1024' });
    const reply = await send({
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: {},
        pad: 'x'.repeat(4096),
      }),
      headers: { authorization: bearer(await signer.mint('1001')) },
    });
    expect(reply.status).toBe(413);
  });
});

describe('REQUIRED: the open fall-through is closed', () => {
  it('no credential is 401 studio_credential_required, a complete JSON response, before any dispatch', async () => {
    await boot(REQUIRED);
    const reply = await send({ body: LIST_TOOLS, keepAlive: true });
    expect(reply.status).toBe(401);
    expect(reply.headers['content-type']).toBe('application/json');
    expect(reply.headers['content-length']).toBe(String(Buffer.byteLength(reply.body)));
    expect(reply.headers.connection).toBe('close');
    expect(reply.headers['mcp-session-id']).toBeUndefined();
    expect(reply.headers['www-authenticate']).toBe('Bearer realm="discord-mcp"');
    expect(JSON.parse(reply.body)).toEqual({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32001,
        message: 'unauthorized: studio_credential_required',
        data: { code: 'studio_credential_required' },
      },
    });
    expect(dispatch.count).toBe(0);
  });

  it('an opaque credential is 401 studio_credential_not_accepted (legacy secret unset)', async () => {
    await boot(REQUIRED);
    const reply = await list(bearer('opaque-key-0123456789abcdef0123456789'));
    expect(reply.status).toBe(401);
    expect(JSON.parse(reply.body).error.data.code).toBe('studio_credential_not_accepted');
  });

  it('the CORRECT shared secret is admitted (an existing, really-checked credential); a wrong one is not', async () => {
    await boot({ ...REQUIRED, DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN });
    expect((await list(bearer(ACCESS_TOKEN))).status).toBe(200);
    const wrong = await list(bearer('wrong-opaque-token-000000000000000000'));
    expect(wrong.status).toBe(401);
    expect(JSON.parse(wrong.body).error.data.code).toBe('studio_credential_not_accepted');
  });

  it('a verified studio bearer is served', async () => {
    await boot(REQUIRED);
    expect((await list(bearer(await signer.mint('1002')))).status).toBe(200);
  });

  it('a refusal to a POST that declared a body still answers, then closes the connection', async () => {
    await boot(REQUIRED);
    const reply = await send({
      body: 'x'.repeat(4096),
      headers: { 'transfer-encoding': 'chunked' },
      keepAlive: true,
    });
    expect(reply.status).toBe(401);
    expect(reply.headers.connection).toBe('close');
  });

  it('a refusal comes before the body is read: an oversized declared body is 401, not 413', async () => {
    await boot({ ...REQUIRED, MCP_HTTP_MAX_BODY_BYTES: '1024' });
    const reply = await send({ body: JSON.stringify({ pad: 'x'.repeat(4096) }) });
    expect(reply.status).toBe(401);
  });

  it('an unknown path is still the legacy 404 (the router answers before the gate, nothing is routed)', async () => {
    await boot(REQUIRED);
    for (const path of ['/unknown', '/MCP', '/mcp/', '/mcp/x', '/%6dcp', '/admin']) {
      expect((await send({ method: 'GET', path })).status, path).toBe(404);
    }
    expect(dispatch.count).toBe(0);
  });
});

describe('GET /healthz is the only exemption, and it is exactly that', () => {
  it('is open under REQUIRED with no credential (the deploy smoke test and the container probe)', async () => {
    await boot(REQUIRED);
    const reply = await send({ method: 'GET', path: '/healthz' });
    expect(reply.status).toBe(200);
    expect(JSON.parse(reply.body)).toEqual({ status: 'ok' });
  });

  it.each([
    ['HEAD'],
    ['POST'],
    ['PUT'],
    ['DELETE'],
  ])('%s /healthz is NOT exempt (401 under REQUIRED)', async (method) => {
    await boot(REQUIRED);
    const reply = await send({ method, path: '/healthz' });
    expect(reply.status).toBe(401);
  });

  it.each([
    ['/HEALTHZ'],
    ['/Healthz'],
    ['/healthz/'],
    ['/evil/healthz'],
    ['//evil/healthz/x'],
    ['/%68ealthz'],
    ['/healthz%2f'],
    ['/healthz;x'],
  ])('GET %s is never a 200 under REQUIRED (it is not the route)', async (path) => {
    await boot(REQUIRED);
    const reply = await send({ method: 'GET', path });
    expect(reply.status, path).toBe(404);
  });

  it('the exemption skips only the studio gate: with a shared secret set, /healthz still demands it', async () => {
    await boot({ ...REQUIRED, DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN });
    const bare = await send({ method: 'GET', path: '/healthz' });
    expect(bare.status).toBe(401);
    expect(bare.headers['www-authenticate']).toBe('Bearer');
    expect(
      (
        await send({
          method: 'GET',
          path: '/healthz',
          headers: { authorization: bearer(ACCESS_TOKEN) },
        })
      ).status,
    ).toBe(200);
  });

  it('a junk or invalid studio bearer on /healthz is not evaluated (the route carries nothing to protect)', async () => {
    await boot(REQUIRED);
    const expired = await signer.mint('1001', { exp: 1, iat: 0 });
    expect(
      (await send({ method: 'GET', path: '/healthz', headers: { authorization: bearer(expired) } }))
        .status,
    ).toBe(200);
  });
});

describe('the over-long bearer is not decoded and not claimed', () => {
  it('REQUIRED off: a header segment over the cap is not claimed, so the existing path serves it; atob is never called', async () => {
    await boot(STUDIO);
    const spy = vi.spyOn(globalThis, 'atob');
    const huge = `${'A'.repeat(STUDIO_MAX_TOKEN_CHARS + 1)}.e30.AAAA`;
    const reply = await list(bearer(huge));
    expect(reply.status).toBe(200);
    expect(spy).not.toHaveBeenCalled();
    // positive control: a normal claimed bearer does decode through the same path.
    await list(bearer(await signer.mint('1001')));
    expect(spy).toHaveBeenCalled();
  });

  it('REQUIRED on: the same token is 401 studio_credential_not_accepted', async () => {
    await boot(REQUIRED);
    const reply = await list(bearer(`${'A'.repeat(STUDIO_MAX_TOKEN_CHARS + 100)}.e30.AAAA`));
    expect(reply.status).toBe(401);
    expect(JSON.parse(reply.body).error.data.code).toBe('studio_credential_not_accepted');
  });
});

describe('a request target the URL parser rejects (flag on)', () => {
  const targets = [
    ['GET //', 'GET // HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'],
    ['GET http://[bad/', 'GET http://[bad/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'],
  ] as const;

  it.each(
    targets,
  )('%s is a 400, the process keeps serving, no unhandled rejection (REQUIRED off and on)', async (_name, text) => {
    for (const env of [STUDIO, REQUIRED]) {
      await closeServer();
      resetStudioAuthState();
      await boot(env);
      expect(await raw(text)).toBe('HTTP/1.1 400 Bad Request');
      expect((await send({ method: 'GET', path: '/healthz' })).status).toBe(200);
    }
    expect(rejections).toEqual([]);
  });

  it('the 400 body is stable and echoes nothing from the request', async () => {
    await boot(REQUIRED);
    const reply = await send({
      method: 'GET',
      path: '//',
      headers: { 'x-secret-probe': 'zzz-probe' },
    });
    expect(reply.status).toBe(400);
    expect(JSON.parse(reply.body)).toEqual({
      error: 'bad_request',
      code: 'invalid_request_target',
    });
    expect(reply.body).not.toContain('zzz-probe');
    expect(reply.body).not.toContain('127.0.0.1');
  });

  it.each([
    ['[bad'],
    ['a b'],
    [''],
  ])('a malformed Host %j never crashes the gate path', async (host) => {
    await boot(REQUIRED);
    const line = await raw(`GET /mcp HTTP/1.1\r\nHost: ${host}\r\n\r\n`);
    expect(line).toBe('HTTP/1.1 401 Unauthorized');
    expect((await send({ method: 'GET', path: '/healthz' })).status).toBe(200);
    expect(rejections).toEqual([]);
  });
});

describe('startup is fail-fast: a broken gate never serves', () => {
  it.each([
    ['no issuer', { ...STUDIO, STUDIO_AUTH_ISSUER: undefined }, /needs STUDIO_AUTH_ISSUER/],
    ['no JWKS URL', { ...STUDIO, STUDIO_AUTH_JWKS_URL: undefined }, /needs STUDIO_AUTH_ISSUER/],
    [
      'a login in the allowlist',
      { ...STUDIO, STUDIO_AUTH_ALLOW_SUBS: 'octocat' },
      /numeric GitHub ids/,
    ],
    [
      'another audience',
      { ...STUDIO, STUDIO_AUTH_AUDIENCE: 'knowledge-retrieval' },
      /pinned to "discord-mcp"/,
    ],
    [
      'an http JWKS URL',
      { ...STUDIO, STUDIO_AUTH_JWKS_URL: 'http://auth.test.invalid/jwks' },
      /must be https/,
    ],
    [
      'REQUIRED without ENABLED',
      { STUDIO_AUTH_REQUIRED: 'true' },
      /needs STUDIO_AUTH_ENABLED=true/,
    ],
    [
      'an ambiguous REQUIRED',
      { ...STUDIO, STUDIO_AUTH_REQUIRED: 'yes' },
      /exactly "true" or "false"/,
    ],
  ])('startHttp rejects on %s', async (_name, env, message) => {
    for (const [key, value] of Object.entries(env)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await expect(startHttp({ port: 0, registerSignalHandlers: false })).rejects.toThrow(message);
  });

  it('lookalike flag values leave the gate OFF: nothing is required, nothing is verified', async () => {
    for (const lookalike of [' true', 'True', '1', 'yes']) {
      await closeServer();
      await boot({
        STUDIO_AUTH_ENABLED: lookalike,
        STUDIO_AUTH_REQUIRED: undefined,
        STUDIO_AUTH_ISSUER: undefined,
        STUDIO_AUTH_JWKS_URL: undefined,
      });
      const reply = await list();
      expect(reply.status, lookalike).toBe(200);
    }
    expect(jwks.jwksFetches()).toBe(0);
  });
});

describe('the channel is the Authorization header only', () => {
  it('a studio assertion in the query string or a cookie is not a credential', async () => {
    await boot(REQUIRED);
    const token = await signer.mint('1001');
    const viaQuery = await send({
      body: LIST_TOOLS,
      path: `/mcp?access_token=${token}&token=${token}`,
    });
    expect(viaQuery.status).toBe(401);
    const viaCookie = await send({
      body: LIST_TOOLS,
      headers: { cookie: `token=${token}; CF_Authorization=${token}` },
    });
    expect(viaCookie.status).toBe(401);
    const viaHeader = await send({
      body: LIST_TOOLS,
      headers: { 'x-api-key': token, 'cf-access-jwt-assertion': token },
    });
    expect(viaHeader.status).toBe(401);
    expect(dispatch.count).toBe(0);
  });

  it('a `Bearer` scheme in another case and extra spaces still reach the verifier', async () => {
    await boot(REQUIRED);
    const token = await signer.mint('1001');
    expect((await list(`bearer   ${token}`)).status).toBe(200);
  });

  it('a malformed Authorization value is not a pass', async () => {
    await boot(REQUIRED);
    const token = await signer.mint('1001');
    for (const value of [token, `Token ${token}`, `Bearer ${token} extra`, `Bearer\t`, 'Bearer']) {
      expect((await list(value)).status, value).toBe(401);
    }
  });
});
