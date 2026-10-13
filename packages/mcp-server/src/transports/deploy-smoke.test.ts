/**
 * The deploy's post-restart smoke step, run for real against fake servers, in both gate modes.
 *
 * Why it exists: with STUDIO_AUTH_REQUIRED=true the container refuses every request that carries no credential,
 * and the old step sent exactly that (an anonymous `POST /mcp`, `curl -f`), so the first deploy after the flip went
 * red even though the service was healthy and the gate was doing its job. In that mode the step now (1) asserts the
 * app itself refuses an anonymous caller with `401 studio_credential_required`, which is the proof that Cloudflare
 * Access can be narrowed, and (2) checks the bot token directly against Discord, because the HTTP route it used
 * for that is now (correctly) closed to a credential-less runner.
 *
 * These specs run the REAL step text from deploy.yml; a change to the workflow changes what they see. The fake MCP
 * server answers with the REAL refusal builder (`studioRefusalResponse`), not a hand-typed body.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { studioRefusalResponse } from './studio-auth.js';
import { runSmokeStep, smokeIdentityStep } from './testkit/compose-render.js';

const IS_WINDOWS = process.platform === 'win32';
const TOKEN = 'T'.repeat(60);

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((done) => s.close(done))));
});

async function listen(handler: Parameters<typeof createServer>[1]): Promise<number> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((ready) => server.listen(0, '127.0.0.1', ready));
  return (server.address() as AddressInfo).port;
}

interface Seen {
  mcpAuthorization: (string | undefined)[];
  discordAuthorization: (string | undefined)[];
}

/** The MCP origin. `refuse` answers an anonymous POST /mcp the way the REQUIRED gate does. */
async function mcpServer(
  mode: 'refuse' | 'open' | 'bare-401' | 'identity-error',
  seen: Seen,
): Promise<number> {
  return listen((req, res) => {
    req.resume();
    seen.mcpAuthorization.push(req.headers.authorization);
    if (mode === 'refuse') {
      const r = studioRefusalResponse(
        { decision: 'refuse', status: 401, code: 'studio_credential_required', presented: false },
        true,
      );
      res.writeHead(r.status, r.headers).end(r.body);
    } else if (mode === 'bare-401') {
      res.writeHead(401).end();
    } else if (mode === 'identity-error') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          result: { isError: true, content: [{ type: 'text', text: 'bad token' }] },
        }),
      );
    } else {
      res.writeHead(200, { 'content-type': 'application/json' });
      // The real tool result carries the user object both as text and as structuredContent.
      const user = { id: '1', bot: true };
      res.end(
        JSON.stringify({
          result: {
            content: [{ type: 'text', text: JSON.stringify(user) }],
            structuredContent: user,
          },
        }),
      );
    }
  });
}

/** Stands in for https://discord.com/api/v10. */
async function discordServer(ok: boolean, seen: Seen): Promise<string> {
  const port = await listen((req, res) => {
    seen.discordAuthorization.push(req.headers.authorization);
    if (ok && req.url === '/users/@me') {
      res.writeHead(200, { 'content-type': 'application/json' }).end('{"id":"1","bot":true}');
    } else {
      res
        .writeHead(401, { 'content-type': 'application/json' })
        .end('{"message":"401: Unauthorized"}');
    }
  });
  return `http://127.0.0.1:${port}`;
}

const seenNone = (): Seen => ({ mcpAuthorization: [], discordAuthorization: [] });

describe.skipIf(IS_WINDOWS)('deploy smoke step, STUDIO_AUTH_REQUIRED=true', () => {
  it('passes when the app refuses an anonymous caller and the bot token is good, and sends the token to Discord once, as a Bot credential', async () => {
    const seen = seenNone();
    const port = await mcpServer('refuse', seen);
    const discord = await discordServer(true, seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: `Bot ${TOKEN}`,
      DISCORD_API_BASE: discord,
    });
    expect(r.stderr).toBe('');
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('anonymous POST /mcp refused');
    expect(seen.mcpAuthorization).toEqual([undefined]);
    expect(seen.discordAuthorization).toEqual([`Bot ${TOKEN}`]);
  });

  it('accepts a bare token (no "Bot " prefix) and still sends exactly one Bot credential', async () => {
    const seen = seenNone();
    const port = await mcpServer('refuse', seen);
    const discord = await discordServer(true, seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      DISCORD_API_BASE: discord,
    });
    expect(r.status).toBe(0);
    expect(seen.discordAuthorization).toEqual([`Bot ${TOKEN}`]);
  });

  it('FAILS when an anonymous caller is NOT refused: the flag is set but the gate is not live', async () => {
    const seen = seenNone();
    const port = await mcpServer('open', seen);
    const discord = await discordServer(true, seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      DISCORD_API_BASE: discord,
    });
    expect(r.status).not.toBe(0);
    expect(r.stdout + r.stderr).toContain('the gate is not refusing anonymous callers');
    expect(seen.discordAuthorization).toEqual([]);
  });

  it('FAILS on a bare 401 that is not the app gate (no studio_credential_required code)', async () => {
    const seen = seenNone();
    const port = await mcpServer('bare-401', seen);
    const discord = await discordServer(true, seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      DISCORD_API_BASE: discord,
    });
    expect(r.status).not.toBe(0);
    expect(r.stdout + r.stderr).toContain('the gate is not refusing anonymous callers');
  });

  it('FAILS when Discord rejects the token, even though the gate refuses anonymous callers', async () => {
    const seen = seenNone();
    const port = await mcpServer('refuse', seen);
    const discord = await discordServer(false, seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      DISCORD_API_BASE: discord,
    });
    expect(r.status).not.toBe(0);
  });

  it('never prints the token', async () => {
    const seen = seenNone();
    const port = await mcpServer('refuse', seen);
    const discord = await discordServer(false, seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      DISCORD_API_BASE: discord,
    });
    expect(r.stdout + r.stderr).not.toContain(TOKEN);
  });
});

describe.skipIf(IS_WINDOWS)(
  'deploy smoke step, dual mode (STUDIO_AUTH_REQUIRED unset or false): unchanged',
  () => {
    for (const required of ['', 'false']) {
      it(`REQUIRED=${JSON.stringify(required)}: checks the bot identity through POST /mcp and never calls Discord directly`, async () => {
        const seen = seenNone();
        const port = await mcpServer('open', seen);
        const discord = await discordServer(true, seen);
        const r = await runSmokeStep({
          HOST_PORT: String(port),
          STUDIO_AUTH_REQUIRED: required,
          DISCORD_TOKEN: TOKEN,
          DISCORD_API_BASE: discord,
        });
        expect(r.status).toBe(0);
        expect(r.stdout).toContain('bot identity confirmed');
        expect(seen.mcpAuthorization).toEqual([undefined]);
        expect(seen.discordAuthorization).toEqual([]);
      });

      it(`REQUIRED=${JSON.stringify(required)}: FAILS when users_get_current reports an error`, async () => {
        const seen = seenNone();
        const port = await mcpServer('identity-error', seen);
        const r = await runSmokeStep({
          HOST_PORT: String(port),
          STUDIO_AUTH_REQUIRED: required,
          DISCORD_TOKEN: TOKEN,
        });
        expect(r.status).not.toBe(0);
      });

      it(`REQUIRED=${JSON.stringify(required)}: FAILS on a 401 (a refused anonymous call is only expected under REQUIRED)`, async () => {
        const seen = seenNone();
        const port = await mcpServer('refuse', seen);
        const r = await runSmokeStep({
          HOST_PORT: String(port),
          STUDIO_AUTH_REQUIRED: required,
          DISCORD_TOKEN: TOKEN,
        });
        expect(r.status).not.toBe(0);
      });
    }
  },
);

describe('deploy smoke step wiring', () => {
  it('exists and receives the two inputs it branches on from the same sources as the override-render step', () => {
    const step = smokeIdentityStep();
    expect(step).toBeDefined();
    // biome-ignore lint/suspicious/noTemplateCurlyInString: GitHub Actions expressions, not JS templates
    expect(step?.env?.STUDIO_AUTH_REQUIRED).toBe('${{ vars.STUDIO_AUTH_REQUIRED }}');
    // biome-ignore lint/suspicious/noTemplateCurlyInString: GitHub Actions expression, not a JS template
    expect(step?.env?.DISCORD_TOKEN).toBe('${{ secrets.DISCORD_TOKEN }}');
  });
});
