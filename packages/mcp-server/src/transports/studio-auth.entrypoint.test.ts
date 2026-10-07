/**
 * The REAL entrypoint: the built `dist/cli.js serve --http` process, with the gate on, against a local https
 * JWKS server using a throwaway self-signed certificate and throwaway ES256 keys. Nothing live is contacted and
 * nothing here is a secret: the key material is generated per run in a temp directory and deleted afterwards.
 *
 * What this proves that the in-process specs cannot: the lazily imported vendored verifier really is in the
 * build output (a missing chunk would be a 500 only the packaged binary shows), the env flags are read from a
 * real process environment, `serve` fails fast with a non-zero exit on a broken gate, the log lines carry no
 * token material, and a trusted-CA https JWKS fetch works end to end.
 *
 * Runs on the Linux/macOS legs only: the throwaway certificate is made with the `openssl` binary.
 */
import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { createConnection, createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createSigner, nowSeconds, type Signer } from './testkit/studio-auth-signer.js';

const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const DIST = join(PACKAGE_ROOT, 'dist');
const CLI = join(DIST, 'cli.js');
const describeReal = process.platform === 'win32' ? describe.skip : describe;

const LIST_TOOLS = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });

let scratch: string;
let signer: Signer;
let jwksServer: HttpsServer;
let jwksHits = 0;
let jwksPort = 0;
let caFile = '';

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createNetServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address() as AddressInfo;
      probe.close(() => resolve(port));
    });
  });
}

interface Running {
  child: ChildProcess;
  port: number;
  output: () => string;
  stop: () => Promise<void>;
}

function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? '',
    HOME: scratch,
    APPDATA: scratch,
    XDG_CONFIG_HOME: scratch,
    DISCORD_TOKEN: `Bot ${'d'.repeat(60)}`,
    LOG_LEVEL: 'info',
    MCP_AUDIT_ENABLED: 'false',
    NODE_EXTRA_CA_CERTS: caFile,
    ...extra,
  };
  return env;
}

async function start(extra: Record<string, string>): Promise<Running> {
  const port = await freePort();
  const child = spawn(
    process.execPath,
    [CLI, 'serve', '--http', '--host', '127.0.0.1', '--port', String(port)],
    {
      env: childEnv(extra),
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let captured = '';
  child.stdout?.on('data', (chunk) => {
    captured += chunk.toString();
  });
  child.stderr?.on('data', (chunk) => {
    captured += chunk.toString();
  });
  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()));
    child.kill('SIGTERM');
    await Promise.race([exited, new Promise<void>((resolve) => setTimeout(resolve, 3000))]);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  };
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null)
      throw new Error(`serve exited early (${child.exitCode}): ${captured.slice(0, 400)}`);
    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (res.status === 200) return { child, port, output: () => captured, stop };
    } catch {
      // not listening yet
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  await stop();
  throw new Error(`serve did not become ready: ${captured.slice(0, 400)}`);
}

async function post(
  port: number,
  authorization?: string,
): Promise<{ status: number; body: string }> {
  const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...(authorization === undefined ? {} : { authorization }),
    },
    body: LIST_TOOLS,
  });
  return { status: res.status, body: await res.text() };
}

const toolCount = (body: string): number =>
  JSON.parse(/^data: (.*)$/m.exec(body)?.[1] ?? body).result.tools.length;

const studioEnv = () => ({
  STUDIO_AUTH_ENABLED: 'true',
  STUDIO_AUTH_ISSUER: 'https://auth.test.invalid',
  STUDIO_AUTH_JWKS_URL: `https://127.0.0.1:${jwksPort}/.well-known/jwks.json`,
  STUDIO_AUTH_ALLOW_SUBS: '1001,1002',
});

beforeAll(async () => {
  if (process.platform === 'win32') return;
  scratch = mkdtempSync(join(tmpdir(), 'discord-mcp-entrypoint-'));
  const keyFile = join(scratch, 'jwks-host.key');
  caFile = join(scratch, 'jwks-host.crt');
  const made = spawnSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:prime256v1',
      '-nodes',
      '-keyout',
      keyFile,
      '-out',
      caFile,
      '-days',
      '1',
      '-subj',
      '/CN=localhost',
      '-addext',
      'subjectAltName=IP:127.0.0.1,DNS:localhost',
    ],
    { encoding: 'utf8' },
  );
  if (made.status !== 0)
    throw new Error(`openssl could not make the throwaway certificate: ${made.stderr}`);
  signer = await createSigner('entrypoint-kid');
  jwksServer = createHttpsServer(
    { key: readFileSync(keyFile), cert: readFileSync(caFile) },
    (req, res) => {
      if (req.url === '/.well-known/jwks.json') {
        jwksHits += 1;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(signer.jwks()));
        return;
      }
      res.writeHead(404).end();
    },
  );
  await new Promise<void>((resolve) => jwksServer.listen(0, '127.0.0.1', resolve));
  jwksPort = (jwksServer.address() as AddressInfo).port;
});

afterAll(async () => {
  if (process.platform === 'win32') return;
  await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
  rmSync(scratch, { recursive: true, force: true });
});

describeReal('the built dist/cli.js, gate on, against a local https JWKS', () => {
  it('the build is current: it contains the gate and ships the lazily imported verifier chunk', () => {
    const files = readdirSync(DIST).filter((f) => f.endsWith('.js'));
    const withGate = files.filter((f) =>
      readFileSync(join(DIST, f), 'utf8').includes('studio auth enabled'),
    );
    expect(withGate, 'dist is stale: run `pnpm --filter @discord-mcp/cli build`').toHaveLength(1);
    expect(files.some((f) => f.startsWith('studio-auth-verify-'))).toBe(true);
    expect(files.some((f) => /legacy/i.test(f))).toBe(false);
    expect(
      files.some((f) => readFileSync(join(DIST, f), 'utf8').includes('frozen pre-change')),
    ).toBe(false);
  });

  it('dual mode: a studio bearer is served, no credential is served, a claimed bad one is refused; the JWKS is fetched once', async () => {
    jwksHits = 0;
    const run = await start(studioEnv());
    try {
      const good = await post(
        run.port,
        `Bearer ${await signer.mint('1001', { login: 'entrypoint-secret-login' })}`,
      );
      expect(good.status).toBe(200);
      expect(toolCount(good.body)).toBe(209);

      expect((await post(run.port)).status).toBe(200); // Access would still be the gate at the edge

      const stranger = await post(run.port, `Bearer ${await signer.mint('2002')}`);
      expect(stranger.status).toBe(403);
      expect(JSON.parse(stranger.body).error.data.code).toBe('not_allowed');

      const expired = await post(
        run.port,
        `Bearer ${await signer.mint('1001', { exp: nowSeconds() - 3600 })}`,
      );
      expect(expired.status).toBe(401);
      expect(JSON.parse(expired.body).error.data.code).toBe('expired');

      expect(jwksHits).toBe(1);
    } finally {
      await run.stop();
    }
  });

  it('REQUIRED: no credential is 401, a studio bearer passes, /healthz stays open, a bad request target is a 400 and the process survives', async () => {
    const secretLogin = 'entrypoint-secret-login';
    const run = await start({ ...studioEnv(), STUDIO_AUTH_REQUIRED: 'true' });
    try {
      const token = await signer.mint('1002', { login: secretLogin });
      const refused = await post(run.port);
      expect(refused.status).toBe(401);
      expect(JSON.parse(refused.body).error.data.code).toBe('studio_credential_required');

      expect((await post(run.port, `Bearer ${token}`)).status).toBe(200);
      expect((await fetch(`http://127.0.0.1:${run.port}/healthz`)).status).toBe(200);

      const bad = await new Promise<string>((resolve) => {
        const socket = createConnection(run.port, '127.0.0.1');
        let buffer = '';
        socket.on('data', (chunk) => {
          buffer += chunk.toString();
        });
        socket.on('close', () => resolve(buffer.split('\r\n')[0] ?? ''));
        socket.on('error', () => resolve(''));
        socket.write('GET // HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
        setTimeout(() => socket.destroy(), 600);
      });
      expect(bad).toBe('HTTP/1.1 400 Bad Request');
      expect(run.child.exitCode).toBeNull();
      expect((await post(run.port, `Bearer ${token}`)).status).toBe(200);

      // the real process log: the principal is there, no token material is
      const log = run.output();
      expect(log).toContain('studio auth enabled');
      expect(log).toContain('github:1002');
      for (const secret of [token, ...token.split('.'), secretLogin]) {
        expect(log, 'token material in the process log').not.toContain(secret);
      }
    } finally {
      await run.stop();
    }
  });

  it('fails fast and exits non-zero on a broken gate (no issuer), never serving', async () => {
    const { STUDIO_AUTH_ISSUER: _issuer, ...noIssuer } = studioEnv();
    const port = await freePort();
    const result = spawnSync(
      process.execPath,
      [CLI, 'serve', '--http', '--host', '127.0.0.1', '--port', String(port)],
      {
        env: childEnv(noIssuer),
        encoding: 'utf8',
        timeout: 20_000,
      },
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('discord-mcp failed to start');
    expect(result.stderr).toContain('STUDIO_AUTH_ISSUER');
    await expect(fetch(`http://127.0.0.1:${port}/healthz`)).rejects.toThrow();
  });

  it('a lookalike flag value leaves the real process ungated and never touches the JWKS server', async () => {
    jwksHits = 0;
    const run = await start({ ...studioEnv(), STUDIO_AUTH_ENABLED: 'True' });
    try {
      expect((await post(run.port)).status).toBe(200);
      expect((await post(run.port, `Bearer ${await signer.mint('2002')}`)).status).toBe(200);
      expect(jwksHits).toBe(0);
      expect(run.output()).not.toContain('studio auth');
    } finally {
      await run.stop();
    }
  });
});
