/**
 * The deploy's post-restart smoke step: the REAL step text from deploy.yml, run against fake servers that
 * emulate each gate mode. The real gate over loopback sockets is covered by http.studio.test.ts; this file pins
 * the step's own logic (what it accepts, what it fails on, and the message it fails with).
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

type DiscordMode =
  | 'ok'
  | 'reject'
  | 'not-a-bot'
  | 'bot-without-id'
  | 'bot-empty-id'
  | 'bot-numeric-id'
  | 'bot-as-string'
  | 'not-json';

const DISCORD_BODIES: Record<Exclude<DiscordMode, 'reject'>, string> = {
  ok: '{"id":"1","bot":true}',
  'not-a-bot': '{"id":"1","bot":false}',
  'bot-without-id': '{"bot":true}',
  'bot-empty-id': '{"id":"","bot":true}',
  'bot-numeric-id': '{"id":1,"bot":true}',
  'bot-as-string': '{"id":"1","bot":"true"}',
  'not-json': 'ok "bot": true',
};

/** Stands in for https://discord.com/api/v10. `reject` is a real 401; every other mode answers 200 with a body. */
async function discordServer(mode: DiscordMode, seen: Seen): Promise<string> {
  const port = await listen((req, res) => {
    seen.discordAuthorization.push(req.headers.authorization);
    if (mode !== 'reject' && req.url === '/users/@me') {
      res.writeHead(200, { 'content-type': 'application/json' }).end(DISCORD_BODIES[mode]);
    } else {
      res
        .writeHead(401, { 'content-type': 'application/json' })
        .end('{"message":"401: Unauthorized"}');
    }
  });
  return `http://127.0.0.1:${port}`;
}

/** The step as it was before this change (010b926), verbatim apart from the scratch path. Positive control only. */
const PRE_CHANGE_STEP = `set -euo pipefail
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
curl -fsS -X POST "http://127.0.0.1:\${HOST_PORT}/mcp" \\
  -H 'content-type: application/json' \\
  -H 'accept: application/json, text/event-stream' \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"users_get_current","arguments":{}}}' \\
  -o "$out"
grep -q '"bot":true' "$out"
if grep -q '"isError":true' "$out"; then
  echo "::error::users_get_current failed against Discord"
  cat "$out"
  exit 1
fi
echo " ✓ bot identity confirmed"
`;

const seenNone = (): Seen => ({ mcpAuthorization: [], discordAuthorization: [] });

describe.skipIf(IS_WINDOWS)('deploy smoke step, STUDIO_AUTH_REQUIRED=true', () => {
  it('passes when the app refuses an anonymous caller and the bot token is good, and sends the token to Discord once, as a Bot credential', async () => {
    const seen = seenNone();
    const port = await mcpServer('refuse', seen);
    const discord = await discordServer('ok', seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: `Bot ${TOKEN}`,
      TEST_DISCORD_BASE: discord,
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
    const discord = await discordServer('ok', seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      TEST_DISCORD_BASE: discord,
    });
    expect(r.status).toBe(0);
    expect(seen.discordAuthorization).toEqual([`Bot ${TOKEN}`]);
  });

  it('FAILS when an anonymous caller is NOT refused: the flag is set but the gate is not live', async () => {
    const seen = seenNone();
    const port = await mcpServer('open', seen);
    const discord = await discordServer('ok', seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      TEST_DISCORD_BASE: discord,
    });
    expect(r.status).not.toBe(0);
    expect(r.stdout + r.stderr).toContain('the gate is not refusing anonymous callers');
    expect(seen.discordAuthorization).toEqual([]);
  });

  it('FAILS on a bare 401 that is not the app gate (no studio_credential_required code)', async () => {
    const seen = seenNone();
    const port = await mcpServer('bare-401', seen);
    const discord = await discordServer('ok', seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      TEST_DISCORD_BASE: discord,
    });
    expect(r.status).not.toBe(0);
    expect(r.stdout + r.stderr).toContain('the gate is not refusing anonymous callers');
  });

  it('FAILS when Discord rejects the token (a 401 dies inside curl, before the identity guard)', async () => {
    const seen = seenNone();
    const port = await mcpServer('refuse', seen);
    const discord = await discordServer('reject', seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      TEST_DISCORD_BASE: discord,
    });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('401');
    expect(r.stdout).not.toContain('bot identity confirmed');
  });

  // These answer 200, so curl succeeds and the failure can only come from the identity guard itself. Each asserts on
  // the guard's own message: a mutation of the guard to `true` leaves the step green, which these cases catch.
  const IDENTITY_FAILURES: [DiscordMode, string][] = [
    ['not-a-bot', 'bot:false'],
    ['bot-without-id', 'bot:true but no id'],
    ['bot-empty-id', 'bot:true but an empty id'],
    ['bot-numeric-id', 'bot:true but a non-string id'],
    ['bot-as-string', 'bot as the string "true"'],
    ['not-json', 'a body that is not JSON but contains the old grep marker'],
  ];
  for (const [mode, what] of IDENTITY_FAILURES) {
    it(`FAILS at the identity guard when Discord answers 200 with ${what}`, async () => {
      const seen = seenNone();
      const port = await mcpServer('refuse', seen);
      const discord = await discordServer(mode, seen);
      const r = await runSmokeStep({
        HOST_PORT: String(port),
        STUDIO_AUTH_REQUIRED: 'true',
        DISCORD_TOKEN: TOKEN,
        TEST_DISCORD_BASE: discord,
      });
      expect(r.status).not.toBe(0);
      expect(r.stdout + r.stderr).toContain('Discord did not identify the token as a bot user');
      expect(r.stdout).not.toContain('bot identity confirmed');
      expect(r.stderr).not.toContain('curl:');
      expect(seen.discordAuthorization).toEqual([`Bot ${TOKEN}`]);
    });
  }

  it('positive control: the pre-change step (anonymous POST, curl -f) fails under REQUIRED, which is what this change fixes', async () => {
    const seen = seenNone();
    const port = await mcpServer('refuse', seen);
    const r = await runSmokeStep(
      { HOST_PORT: String(port), STUDIO_AUTH_REQUIRED: 'true', DISCORD_TOKEN: TOKEN },
      { run: PRE_CHANGE_STEP },
    );
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('401');
    // ...while the shipped step passes the very same server.
    const discord = await discordServer('ok', seen);
    const fixed = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      TEST_DISCORD_BASE: discord,
    });
    expect(fixed.status).toBe(0);
  });

  it('never prints the token', async () => {
    const seen = seenNone();
    const port = await mcpServer('refuse', seen);
    const discord = await discordServer('reject', seen);
    const r = await runSmokeStep({
      HOST_PORT: String(port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      TEST_DISCORD_BASE: discord,
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
        const discord = await discordServer('ok', seen);
        const r = await runSmokeStep({
          HOST_PORT: String(port),
          STUDIO_AUTH_REQUIRED: required,
          DISCORD_TOKEN: TOKEN,
          TEST_DISCORD_BASE: discord,
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
