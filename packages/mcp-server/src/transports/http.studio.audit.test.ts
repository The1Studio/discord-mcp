/**
 * The audit record names the studio principal, and only when the studio gate admitted the request.
 *
 * `MCP_DRY_RUN=false` runs in production, so a destructive call that carries `__confirm:true` really executes and
 * is audited. This spec drives exactly that over the real HTTP transport, with Discord replaced by an in-process
 * fake REST (nothing leaves the machine), and reads the file audit sink. The audit record is where "who did this"
 * lives; a request admitted by the studio gate must name `github:<numeric id>` there, and every other request
 * (flag off, shared secret, Access-fronted, unauthenticated) must produce the record it produced before the field
 * existed, byte for byte.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type { Server } from 'node:http';
import { request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { startHttp } from './http.js';
import { resetStudioAuthState } from './studio-auth.js';
import {
  createSigner,
  type JwksFetchStub,
  type Signer,
  stubJwksFetch,
  TEST_ISSUER,
  TEST_JWKS_URL,
} from './testkit/studio-auth-signer.js';

const discord = vi.hoisted(() => ({ calls: [] as string[] }));

vi.mock('@discordjs/rest', () => {
  class FakeREST {
    setToken(): this {
      return this;
    }
    on(): this {
      return this;
    }
    async get(route: string) {
      discord.calls.push(`GET ${route}`);
      return { id: '112233445566778899', type: 0, guild_id: '998877665544332211', name: 'fake' };
    }
    async delete(route: string) {
      discord.calls.push(`DELETE ${route}`);
      return undefined;
    }
    async post(route: string) {
      discord.calls.push(`POST ${route}`);
      return {};
    }
    async patch(route: string) {
      discord.calls.push(`PATCH ${route}`);
      return {};
    }
    async put(route: string) {
      discord.calls.push(`PUT ${route}`);
      return {};
    }
  }
  return { REST: FakeREST, DiscordAPIError: class DiscordAPIError extends Error {} };
});

const VALID_TOKEN = `Bot ${'a'.repeat(60)}`;
const ACCESS_TOKEN = 'test-access-token-with-at-least-32-characters';
const CHANNEL = '112233445566778899';
const savedEnv = { ...process.env };
const STUDIO = {
  STUDIO_AUTH_ENABLED: 'true',
  STUDIO_AUTH_ISSUER: TEST_ISSUER,
  STUDIO_AUTH_JWKS_URL: TEST_JWKS_URL,
  STUDIO_AUTH_ALLOW_SUBS: '1001,1002',
};
// The legacy key set of an audit line from a mutating tool call (no active OTel span, so no trace ids).
const LEGACY_AUDIT_KEYS = [
  'args_redacted',
  'category',
  'duration_ms',
  'idempotent',
  'request_id',
  'status',
  'timestamp',
  'tool',
  'transport',
];

let server: Server | undefined;
let root: string;
let signer: Signer;
let jwks: JwksFetchStub;
let kidCounter = 0;

function post(body: unknown, authorization?: string): Promise<{ status: number; body: string }> {
  const address = server?.address() as AddressInfo | null;
  if (address === null || address === undefined) throw new Error('HTTP server is not listening');
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port: address.port,
        method: 'POST',
        path: '/mcp',
        agent: false,
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          ...(authorization === undefined ? {} : { authorization }),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.once('end', () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.once('error', reject);
    req.end(JSON.stringify(body));
  });
}

async function boot(env: Record<string, string>): Promise<void> {
  Object.assign(process.env, {
    MCP_DRY_RUN: 'false',
    MCP_AUDIT_ENABLED: 'true',
    MCP_AUDIT_SINK: 'file',
    MCP_AUDIT_FILE: join(root, 'audit.jsonl'),
    ...env,
  });
  server = await startHttp({ port: 0, registerSignalHandlers: false });
}

const destructive = (id: number) => ({
  jsonrpc: '2.0',
  id,
  method: 'tools/call',
  params: { name: 'channels_delete', arguments: { channel_id: CHANNEL, __confirm: true } },
});
const bearer = (token: string) => `Bearer ${token}`;

/** Audit lines, waiting for the file sink's async stream to have written `expected` of them. */
async function auditLines(expected: number): Promise<Array<Record<string, unknown>>> {
  const file = join(root, 'audit.jsonl');
  const deadline = Date.now() + 5000;
  for (;;) {
    const lines = existsSync(file)
      ? readFileSync(file, 'utf8')
          .split('\n')
          .filter((line) => line !== '')
      : [];
    if (lines.length >= expected || Date.now() > deadline) {
      return lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
const rawAudit = () => readFileSync(join(root, 'audit.jsonl'), 'utf8');

beforeEach(async () => {
  resetStudioAuthState();
  discord.calls.length = 0;
  root = mkdtempSync(join(tmpdir(), 'discord-mcp-studio-audit-'));
  process.env = { ...savedEnv };
  process.env.APPDATA = root;
  process.env.XDG_CONFIG_HOME = root;
  process.env.DISCORD_TOKEN = VALID_TOKEN;
  process.env.LOG_LEVEL = 'fatal';
  for (const key of Object.keys(process.env))
    if (key.startsWith('STUDIO_AUTH_')) delete process.env[key];
  delete process.env.DISCORD_MCP_ACCESS_TOKEN;
  delete process.env.DISCORD_EXPECTED_BOT_ID;
  kidCounter += 1;
  signer = await createSigner(`audit-kid-${kidCounter}`);
  jwks = stubJwksFetch(TEST_JWKS_URL, () => ({ status: 200, json: signer.jwks() }));
});

afterEach(async () => {
  if (server !== undefined) {
    await new Promise<void>((resolve, reject) =>
      server?.close((error) => (error ? reject(error) : resolve())),
    );
    server = undefined;
  }
  jwks.restore();
  vi.restoreAllMocks();
  rmSync(root, { recursive: true, force: true });
  process.env = { ...savedEnv };
});

describe('a destructive call is attributed to the studio principal that made it', () => {
  it('records github:<numeric id> on a studio-admitted, confirmed destructive call, and nothing else new', async () => {
    await boot(STUDIO);
    const reply = await post(destructive(1), bearer(await signer.mint('1002')));
    expect(reply.status).toBe(200);
    // Positive control: the call really executed against (fake) Discord, it was not a dry-run preview.
    expect(discord.calls.some((c) => c.startsWith('DELETE '))).toBe(true);
    const events = await auditLines(1);
    expect(events).toHaveLength(1);
    const [event] = events;
    expect(event?.principal).toBe('github:1002');
    expect(event?.tool).toBe('channels_delete');
    expect(event?.status).toBe('success');
    expect(event?.transport).toBe('http');
    expect(Object.keys(event ?? {}).sort()).toEqual([...LEGACY_AUDIT_KEYS, 'principal'].sort());
  });

  it('every inner call of an mcp_pipeline request is recorded with the principal', async () => {
    await boot(STUDIO);
    const pipeline = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'mcp_pipeline',
        arguments: {
          steps: [
            { id: 'a', tool: 'channels_delete', args: { channel_id: CHANNEL, __confirm: true } },
            { id: 'b', tool: 'channels_delete', args: { channel_id: CHANNEL, __confirm: true } },
          ],
        },
      },
    };
    const reply = await post(pipeline, bearer(await signer.mint('1001')));
    expect(reply.status).toBe(200);
    expect(discord.calls.filter((c) => c.startsWith('DELETE ')).length).toBe(2);
    const events = await auditLines(2);
    expect(events.filter((e) => e.tool === 'channels_delete')).toHaveLength(2);
    // Whatever else the audit middleware records for this request (the wrapper itself), none lacks the principal.
    expect(events.map((e) => e.principal)).toEqual(events.map(() => 'github:1001'));
  });

  it('principals do not leak across requests: each is recorded as itself, an unauthenticated one as nobody', async () => {
    await boot(STUDIO);
    await post(destructive(1), bearer(await signer.mint('1001')));
    await post(destructive(2), bearer(await signer.mint('1002')));
    await post(destructive(3)); // dual mode, no credential: the existing (open) path
    const events = await auditLines(3);
    expect(events.map((e) => e.principal)).toEqual(['github:1001', 'github:1002', undefined]);
    expect(Object.hasOwn(events[2] ?? {}, 'principal')).toBe(false);
  });
});

describe('every other path records exactly what it recorded before the field existed', () => {
  it.each([
    ['the gate is OFF (no studio variable set)', {}],
    ['the gate is ON and the request used the shared secret', STUDIO],
  ])('%s', async (_name, studioEnv) => {
    await boot({ ...studioEnv, DISCORD_MCP_ACCESS_TOKEN: ACCESS_TOKEN });
    const reply = await post(destructive(1), bearer(ACCESS_TOKEN));
    expect(reply.status).toBe(200);
    expect(discord.calls.some((c) => c.startsWith('DELETE '))).toBe(true);
    const [event] = await auditLines(1);
    expect(Object.keys(event ?? {}).sort()).toEqual(LEGACY_AUDIT_KEYS);
    expect(rawAudit()).not.toContain('principal');
    expect(rawAudit()).not.toContain('github:');
  });

  it('a refused studio request is not executed, not audited, and names no principal', async () => {
    await boot({ ...STUDIO, STUDIO_AUTH_REQUIRED: 'true' });
    const expired = await signer.mint('1001', { exp: Math.floor(Date.now() / 1000) - 3600 });
    expect((await post(destructive(1), bearer(expired))).status).toBe(401);
    expect((await post(destructive(2), bearer(await signer.mint('9999')))).status).toBe(403);
    expect(discord.calls).toEqual([]);
    // Control: an admitted request proves the file sink works in this run, so the zero above is not vacuous.
    expect((await post(destructive(3), bearer(await signer.mint('1001')))).status).toBe(200);
    const events = await auditLines(1);
    expect(events).toHaveLength(1);
    expect(events[0]?.principal).toBe('github:1001');
  });
});

describe('the record holds an identifier, never credential material', () => {
  it('no token, assertion segment, issuer, JWKS URL or claim reaches the audit file (the scan has a positive control)', async () => {
    await boot(STUDIO);
    const token = await signer.mint('1001');
    await post(destructive(1), bearer(token));
    await auditLines(1);
    const text = rawAudit();
    const material = (haystack: string) =>
      [
        token,
        ...token.split('.'),
        TEST_ISSUER,
        TEST_JWKS_URL,
        'login-1001',
        '"sub"',
        '"aud"',
        '"iss"',
        '"kid"',
        '"jti"',
      ].filter((needle) => haystack.includes(needle));
    expect(material(text)).toEqual([]);
    // Positive control: the same scan finds a token when one is planted, and the record does hold the id.
    expect(material(`${text}${token}`)).toContain(token);
    expect(text).toContain('"principal":"github:1001"');
  });
});
