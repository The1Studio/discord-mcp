/**
 * The deploy step that writes docker-compose.override.yml, run for real with hostile repository-variable values.
 *
 * Why it exists: the six STUDIO_AUTH_* values are operator-editable repository variables and the file they land in
 * is YAML that `docker compose up` consumes as root. Expanding a raw `${VAR}` into a quoted scalar let a value with
 * a double quote and a newline close the scalar and add a SERVICE-level key (`privileged: true` parses as true).
 * `.github/scripts/render-compose-override.sh` now checks every value against the charset the gate documents and
 * refuses the deploy otherwise. These specs run the REAL workflow step and the REAL script (testkit/compose-render)
 * and assert on the parsed result, so the question they answer is "can a variable change the key set of the file
 * root will run", not "does the script contain a regex".
 *
 * Platform: the renderer is bash and the deploy runs on a Linux runner, so the behavioural lane skips on win32 (the
 * ci.yml matrix has a windows-latest leg). What still runs on Windows is the platform-independent lane at the
 * bottom: the script exists, is wired into the step, is executable-by-bash text with LF endings, and the golden is
 * well-formed YAML. The behaviour itself is guarded by the ubuntu legs only; that is stated in the PR, not hidden.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { STUDIO_AUTH_ENV_KEYS } from './studio-auth.js';
import {
  DISCORD_TOKEN_FIXTURE,
  overrideWriteStep,
  parseOverride,
  RENDER_SCRIPT,
  REPO_ROOT,
  renderOverride,
} from './testkit/compose-render.js';

const SETTABLE = STUDIO_AUTH_ENV_KEYS.filter((k) => k !== 'STUDIO_AUTH_AUDIENCE');
const EXPECTED_ENV_KEYS = ['DISCORD_TOKEN', 'MCP_DRY_RUN', ...SETTABLE].sort();

/** What the pre-change inline heredoc rendered with every studio variable unset (captured from the old step). */
const GOLDEN_UNSET = `services:
  discord-mcp:
    environment:
      DISCORD_TOKEN: "${DISCORD_TOKEN_FIXTURE}"
      # Destructive tools and Components V2 sends execute only when a call ALSO
      # passes __confirm:true (V2: plus the one-time payload hash + approval id).
      # With the default (true) every such call returns DRY_RUN_PREVIEW, so V2
      # cards could never be sent from this deployment.
      MCP_DRY_RUN: "false"
      STUDIO_AUTH_ENABLED: ""
      STUDIO_AUTH_REQUIRED: ""
      STUDIO_AUTH_ISSUER: ""
      STUDIO_AUTH_JWKS_URL: ""
      STUDIO_AUTH_ALLOW_SUBS: ""
      STUDIO_AUTH_STUDIO_KIDS: ""
    ports:
      - "3001:3000"
`;

/** The shape of a render that is allowed to succeed: exactly the keys the file always had, nothing smuggled. */
function expectUntouchedShape(override: string): void {
  const parsed = parseOverride(override);
  expect(parsed.topLevelKeys).toEqual(['services']);
  expect(parsed.serviceNames).toEqual(['discord-mcp']);
  expect(parsed.serviceKeys).toEqual(['environment', 'ports']);
  expect(Object.keys(parsed.environment).sort()).toEqual(EXPECTED_ENV_KEYS);
  expect(parsed.ports).toEqual(['3001:3000']);
}

/** The pre-change step body, kept ONLY as a positive control: it is how the injection was reproduced. */
const NAIVE_STEP = `set -euo pipefail
umask 077
sudo tee "$DEPLOY_ROOT/docker-compose.override.yml" > /dev/null <<EOF
services:
  discord-mcp:
    environment:
      DISCORD_TOKEN: "$DISCORD_TOKEN"
      MCP_DRY_RUN: "false"
      STUDIO_AUTH_STUDIO_KIDS: "\${STUDIO_AUTH_STUDIO_KIDS:-}"
    ports:
      - "\${HOST_PORT}:3000"
EOF
`;

const INJECTION = '"\n    privileged: true #';

// Every payload that has been (or could be) used against a double-quoted YAML scalar written through a shell
// heredoc. Each is fed to EVERY settable variable below.
const HOSTILE: Array<[label: string, value: string, mustRefuse: boolean]> = [
  ['the reproduced injection (quote + newline + service key)', INJECTION, true],
  ['a bare double quote', '"', true],
  ['a quote then a sibling key on the same line', 'x", privileged: true, y: "', true],
  ['a newline', 'a\nb', true],
  ['a trailing newline', 'true\n', true],
  ['a carriage return', 'a\rb', true],
  ['command substitution', '$(touch /var/tmp/should-not-exist)', true],
  ['a backtick substitution', '`id`', true],
  // biome-ignore lint/suspicious/noTemplateCurlyInString: a literal shell parameter-expansion payload, not a JS template
  ['a parameter expansion', '${HOME}', true],
  ['a bare variable reference', '$HOME', true],
  ['a variable reference inside text', 'a$b', true],
  ['a comment marker', 'a #b', true],
  ['a lone backslash', 'a\\b', true],
  ['a backslash escape', 'a\\"b\\n', true],
  ['a flow mapping', '{privileged: true}', true],
  ['a tab', 'a\tb', true],
  ['non-ASCII letters', 'khóa', true],
  ['a full-width double quote', '＂', true],
  ['a right-to-left override', 'a\u202eb', true],
  ['a very long value', 'a'.repeat(10_000), true],
  // Inside the documented charset of SOME variables and inert in a double-quoted scalar, so the contract here is
  // "refused, or rendered with the key set unchanged and the value intact", never "always refused".
  ['a mapping indicator', 'k: v', false],
  ['a YAML document marker', '---', false],
];

const bash = process.platform === 'win32' ? describe.skip : describe;

bash('the real deploy step, with the six repository variables hostile', () => {
  it('the harness is real: the OLD inline heredoc really does let a value add a service-level key (positive control)', () => {
    const naive = renderOverride({ STUDIO_AUTH_STUDIO_KIDS: INJECTION }, { run: NAIVE_STEP });
    expect(naive.status).toBe(0);
    const parsed = parseOverride(naive.override) as unknown as { serviceKeys: string[] };
    expect(parsed.serviceKeys).toContain('privileged');
    const service = (
      parse(naive.override) as { services: { 'discord-mcp': { privileged?: unknown } } }
    ).services['discord-mcp'];
    expect(service.privileged).toBe(true);
  });

  it('with every variable unset the override is byte-identical to what the pre-change step wrote (golden)', () => {
    const result = renderOverride();
    expect({ status: result.status, stderr: result.stderr }).toEqual({ status: 0, stderr: '' });
    expect(result.override).toBe(GOLDEN_UNSET);
  });

  it('empty strings render identically to unset (what an unset repository variable expands to in Actions)', () => {
    const empty = Object.fromEntries(SETTABLE.map((k) => [k, '']));
    const result = renderOverride(empty);
    expect(result.status).toBe(0);
    expect(result.override).toBe(GOLDEN_UNSET);
  });

  describe.each(SETTABLE)('%s', (name) => {
    it.each(
      HOSTILE,
    )('%s: refused, or rendered with the key set unchanged (never echoed, never a smuggled key)', (_label, value, mustRefuse) => {
      const result = renderOverride({ [name]: value });
      if (result.status === 0) {
        expect(mustRefuse, `${name} accepted ${JSON.stringify(value).slice(0, 60)}`).toBe(false);
        expectUntouchedShape(result.override);
        expect(parseOverride(result.override).environment[name]).toBe(value);
        return;
      }
      expect(result.wroteOverride).toBe(false);
      expect(result.stdout).toContain(`::error::${name}`);
      // The value can itself be a workflow command (`::set-output ...`); the message names the variable only.
      const text = `${result.stdout}${result.stderr}`;
      expect(text).not.toContain('privileged');
      expect(text).not.toContain('should-not-exist');
      expect(text).not.toContain('khóa');
    });
  });

  it('exactly the documented-charset payloads render, by identity (a widened charset that admits another fails here)', () => {
    const rendered: string[] = [];
    for (const name of SETTABLE) {
      for (const [, value] of HOSTILE) {
        const result = renderOverride({ [name]: value });
        if (result.status === 0) {
          rendered.push(`${name}=${value}`);
          expectUntouchedShape(result.override);
        }
      }
    }
    // KIDS allow ":" and " " and "-"; the two URL variables allow "-"; the flags and the allowlist allow none of them.
    expect(rendered.sort()).toEqual(
      [
        'STUDIO_AUTH_ISSUER=---',
        'STUDIO_AUTH_JWKS_URL=---',
        'STUDIO_AUTH_STUDIO_KIDS=---',
        'STUDIO_AUTH_STUDIO_KIDS=k: v',
      ].sort(),
    );
  });

  it('the documented values for each variable render, unchanged, and keep the key set', () => {
    const values: Record<string, string> = {
      STUDIO_AUTH_ENABLED: 'true',
      STUDIO_AUTH_REQUIRED: 'false',
      STUDIO_AUTH_ISSUER: 'https://auth.example.org',
      STUDIO_AUTH_JWKS_URL: 'https://auth.example.org/.well-known/jwks.json?x=1&y=a%20b',
      STUDIO_AUTH_ALLOW_SUBS: '1001, 1002,3003',
      STUDIO_AUTH_STUDIO_KIDS: 'studio-2026.10:a_b, kid-2',
    };
    const result = renderOverride(values);
    expect({ status: result.status, stdout: result.stdout }).toEqual({ status: 0, stdout: '' });
    expectUntouchedShape(result.override);
    const env = parseOverride(result.override).environment;
    for (const [key, value] of Object.entries(values)) expect(env[key], key).toBe(value);
  });

  it('the flag variables accept only true/false: a lookalike is a loud deploy failure, not a silent OFF', () => {
    for (const lookalike of ['True', 'TRUE', '1', 'yes', ' true', 'true ', 'on']) {
      for (const name of ['STUDIO_AUTH_ENABLED', 'STUDIO_AUTH_REQUIRED']) {
        const result = renderOverride({ [name]: lookalike });
        expect(result.status, `${name}=${JSON.stringify(lookalike)}`).not.toBe(0);
        expect(result.stdout).toContain(`::error::${name} must be exactly "true" or "false"`);
      }
    }
  });

  it('the allowlist takes digits, commas and spaces only: a login or an email is refused at deploy', () => {
    for (const bad of ['octocat', '1001,octocat', 'a@b.c', '1001;1002', '-1', '1e3']) {
      const result = renderOverride({ STUDIO_AUTH_ALLOW_SUBS: bad });
      expect(result.status, bad).not.toBe(0);
      expect(result.stdout).toContain('::error::STUDIO_AUTH_ALLOW_SUBS');
    }
  });

  it('length caps are enforced at the boundary (512 renders, 513 is refused)', () => {
    const at = renderOverride({ STUDIO_AUTH_ISSUER: `https://${'a'.repeat(504)}` });
    expect(at.status).toBe(0);
    const over = renderOverride({ STUDIO_AUTH_ISSUER: `https://${'a'.repeat(505)}` });
    expect(over.status).not.toBe(0);
    expect(over.stdout).toContain('::error::STUDIO_AUTH_ISSUER is longer than 512 characters');
  });

  it('a refused render leaves the previous good override untouched and no scratch file behind', () => {
    const previous = 'services:\n  discord-mcp:\n    environment:\n      PREVIOUS: "good"\n';
    const refused = renderOverride(
      { STUDIO_AUTH_STUDIO_KIDS: INJECTION },
      { existingOverride: previous },
    );
    expect(refused.status).not.toBe(0);
    expect(refused.override).toBe(previous);
    expect(refused.leftovers).toEqual([]);
    const ok = renderOverride({}, { existingOverride: previous });
    expect(ok.status).toBe(0);
    expect(ok.override).toBe(GOLDEN_UNSET);
    expect(ok.leftovers).toEqual([]);
  });

  it('the written override is mode 600 even over an older world-readable file (tee keeps an existing mode)', () => {
    const result = renderOverride({}, { existingOverride: 'old\n', existingMode: 0o644 });
    expect(result.status).toBe(0);
    expect(result.mode).toBe('600');
  });

  it('a missing renderer fails the step (the step cannot silently fall back to writing an unchecked file)', () => {
    const result = renderOverride({}, { withoutScript: true });
    expect(result.status).not.toBe(0);
    expect(result.wroteOverride).toBe(false);
  });

  it('a failure of the renderer fails the step even though a later command would succeed (pipefail)', () => {
    const result = renderOverride({ STUDIO_AUTH_ENABLED: 'True' });
    expect(result.status).toBe(1);
    expect(result.wroteOverride).toBe(false);
  });

  it('a missing DISCORD_TOKEN still fails the step before any rendering, as before', () => {
    const result = renderOverride({ DISCORD_TOKEN: '' });
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('::error::org secret DISCORD_TOKEN is unset');
    expect(result.wroteOverride).toBe(false);
  });
});

describe('the renderer is wired into the deploy step (platform-independent)', () => {
  const script = readFileSync(join(REPO_ROOT, RENDER_SCRIPT), 'utf8');
  const run = overrideWriteStep()?.run ?? '';

  it('the step runs the script from the deploy checkout and no longer expands a studio variable itself', () => {
    expect(run).toContain('.github/scripts/render-compose-override.sh');
    expect(run).not.toMatch(/STUDIO_AUTH_\w+:-/);
    expect(run).not.toContain('<<EOF');
  });

  it('the script is bash text with LF endings that validates before it writes', () => {
    expect(script.startsWith('#!/usr/bin/env bash\n')).toBe(true);
    expect(script).not.toContain('\r');
    expect(script).toContain('set -euo pipefail');
    expect(script.indexOf('check STUDIO_AUTH_ENABLED')).toBeGreaterThan(-1);
    expect(script.indexOf('cat > "$out"')).toBeGreaterThan(
      script.indexOf('check STUDIO_AUTH_STUDIO_KIDS'),
    );
  });

  it('every settable variable has a check in the script and a line in the template', () => {
    for (const name of SETTABLE) {
      expect(script, name).toContain(`check ${name} "$${name}"`);
      expect(script, name).toContain(`${name}: "$${name}"`);
    }
  });

  it('the golden is well-formed YAML with the expected key set', () => {
    expectUntouchedShape(GOLDEN_UNSET);
  });
});
