/**
 * Config and wiring guards for the studio gate: that the ONLY committed place that turns it on is the deploy
 * workflow's defaults (REQUIRED is never committed on), that the deploy override renders those defaults as an
 * ENABLED gate with the studio-auth issuer (and passes repository variables through when set),
 * that the docs name every variable and every refusal code, that this suite is actually run by CI, and that
 * the frozen oracle cannot reach production.
 *
 * A guard that never fails guards nothing: each check below is mutated in studio-auth.mutation notes (PR body).
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import {
  createStudioGuard,
  pickStudioAuthEnv,
  readStudioAuthConfig,
  STUDIO_AUTH_ENV_KEYS,
  STUDIO_REFUSAL_CODES,
} from './studio-auth.js';
import { parseOverride, renderOverride } from './testkit/compose-render.js';

const REPO = fileURLToPath(new URL('../../../../', import.meta.url));
const read = (relativePath: string) => readFileSync(join(REPO, relativePath), 'utf8');
const exists = (relativePath: string) => {
  try {
    readFileSync(join(REPO, relativePath));
    return true;
  } catch {
    return false;
  }
};

const DOC = read('docs/studio-auth.md');
const DEPLOY = read('.github/workflows/deploy.yml');

/** Non-comment lines of a text file (a `# STUDIO_AUTH_ENABLED: "true"` hint in a comment is not configuration). */
const codeLines = (text: string) => text.split('\n').filter((line) => !/^\s*#/.test(line));

/** The studio-auth issuer origin and JWKS the committed deploy defaults must name (SSOT: studio-auth apps/api/deployments.json). */
const ISSUER_DEFAULT = 'https://auth-api.the1studio.org';
const JWKS_DEFAULT = 'https://auth-api.the1studio.org/.well-known/jwks.json';

const enabledTrueLines = (text: string) =>
  codeLines(text).filter((line) => /STUDIO_AUTH_ENABLED\b[^\n]*\btrue\b/.test(line));
const requiredTrueLines = (text: string) =>
  codeLines(text).filter((line) => /STUDIO_AUTH_REQUIRED\b[^\n]*\btrue\b/.test(line));

describe('committed config: the deploy workflow default is the ONE place the gate is ON; REQUIRED is never on', () => {
  const committed = [
    'docker-compose.yml',
    'docker-compose.override.example.yml',
    'Dockerfile',
    'server.json',
    'package.json',
    'packages/mcp-server/package.json',
    ...readdirSync(join(REPO, '.github/workflows')).map((f) => `.github/workflows/${f}`),
  ];
  const DEPLOY_FILE = '.github/workflows/deploy.yml';

  it.each(
    committed.filter((f) => f !== DEPLOY_FILE),
  )('%s does not set STUDIO_AUTH_ENABLED to true (only the deploy workflow default does)', (file) => {
    expect(enabledTrueLines(read(file))).toEqual([]);
  });

  it.each(
    committed,
  )('%s does not set STUDIO_AUTH_REQUIRED to true (legacy path stays ON: phase M is not here)', (file) => {
    expect(requiredTrueLines(read(file))).toEqual([]);
  });

  it('the deploy workflow commits exactly ONE ENABLED default, and it is true', () => {
    // Both directions: a second line, or the default silently flipping back to dark, turns this red.
    expect(enabledTrueLines(DEPLOY)).toEqual([
      // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, not a JS template
      "          STUDIO_AUTH_ENABLED: ${{ vars.STUDIO_AUTH_ENABLED || 'true' }}",
    ]);
  });

  it('the opt-in default is pinned by exact value: ONE line in deploy.yml, true, and in no other committed file', () => {
    const optIn = (text: string) =>
      codeLines(text).filter((line) =>
        /STUDIO_AUTH_ALLOW_ALL_AUDIENCE_MEMBERS\b[^\n]*\btrue\b/.test(line),
      );
    expect(optIn(DEPLOY)).toEqual([
      // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, not a JS template
      "          STUDIO_AUTH_ALLOW_ALL_AUDIENCE_MEMBERS: ${{ vars.STUDIO_AUTH_ALLOW_ALL_AUDIENCE_MEMBERS || 'true' }}",
    ]);
    for (const file of committed.filter((f) => f !== DEPLOY_FILE)) {
      expect(optIn(read(file)), file).toEqual([]);
    }
  });

  it('the scan can fail: a committed `STUDIO_AUTH_ENABLED: "true"` is caught, a commented hint is not', () => {
    expect(enabledTrueLines('      STUDIO_AUTH_ENABLED: "true"\n')).toHaveLength(1);
    expect(requiredTrueLines('ENV STUDIO_AUTH_REQUIRED=true\n')).toHaveLength(1);
    expect(enabledTrueLines('      # STUDIO_AUTH_ENABLED: "true"\n')).toHaveLength(0);
  });

  it('the example file names every variable (commented) and sets none', () => {
    const example = read('docker-compose.override.example.yml');
    for (const key of STUDIO_AUTH_ENV_KEYS) expect(example, key).toContain(key);
    expect(codeLines(example).filter((line) => line.includes('STUDIO_AUTH_'))).toEqual([]);
  });
});

describe('the deploy override', () => {
  const workflow = parse(DEPLOY) as {
    jobs: {
      deploy: {
        env: Record<string, string>;
        steps: Array<{ name?: string; run?: string; env?: Record<string, string> }>;
      };
    };
  };
  const steps = workflow.jobs.deploy.steps;
  const writeStep = steps.find((s) => s.name?.startsWith('Write docker-compose.override.yml'));
  const SETTABLE = STUDIO_AUTH_ENV_KEYS.filter((k) => k !== 'STUDIO_AUTH_AUDIENCE');

  // Committed defaults by IDENTITY: a variable of the same name overrides each one; everything else passes through bare.
  const DEFAULTS: Record<string, string | undefined> = {
    STUDIO_AUTH_ENABLED: 'true',
    STUDIO_AUTH_ALLOW_ALL_AUDIENCE_MEMBERS: 'true',
    STUDIO_AUTH_ISSUER: ISSUER_DEFAULT,
    STUDIO_AUTH_JWKS_URL: JWKS_DEFAULT,
  };
  const expression = (key: string) =>
    DEFAULTS[key] === undefined
      ? `\${{ vars.${key} }}`
      : `\${{ vars.${key} || '${DEFAULTS[key]}' }}`;

  it('passes each settable variable from a repository VARIABLE (never a secret), with exactly the committed defaults', () => {
    expect(writeStep?.env).toBeDefined();
    for (const key of SETTABLE) {
      expect(writeStep?.env?.[key], key).toBe(expression(key));
    }
    expect(Object.values(writeStep?.env ?? {}).filter((v) => /secrets\./.test(v))).toEqual([
      // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, not a JS template
      '${{ secrets.DISCORD_TOKEN }}',
    ]);
  });

  it('REQUIRED, ALLOW_SUBS and STUDIO_KIDS carry NO committed default (dual mode, no committed narrowing)', () => {
    for (const key of [
      'STUDIO_AUTH_REQUIRED',
      'STUDIO_AUTH_ALLOW_SUBS',
      'STUDIO_AUTH_STUDIO_KIDS',
    ]) {
      expect(writeStep?.env?.[key], key).not.toContain('||');
    }
  });

  it('never passes the audience (it is pinned in code)', () => {
    expect(writeStep?.env).not.toHaveProperty('STUDIO_AUTH_AUDIENCE');
    expect(writeStep?.run).not.toContain('STUDIO_AUTH_AUDIENCE');
  });

  const render = (env: Record<string, string>) => {
    const result = renderOverride(env);
    return {
      status: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
      override: result.override,
    };
  };
  const environmentOf = (override: string): Record<string, string> =>
    parseOverride(override).environment;

  // The runner is Linux; the render needs bash, so this lane does not run on the Windows matrix leg.
  const bash = process.platform === 'win32' ? it.skip : it;

  bash(
    'the renderer alone, with no input at all, still renders and leaves the gate OFF (the defaults live in the workflow)',
    () => {
      const { status, stderr, override } = render({});
      expect({ status, stderr }).toEqual({ status: 0, stderr: '' });
      const environment = environmentOf(override);
      expect(environment.MCP_DRY_RUN).toBe('false');
      expect(environment.DISCORD_TOKEN).toBe(`Bot ${'t'.repeat(60)}`);
      for (const key of SETTABLE) expect(environment[key], key).toBe('');
      expect(parse(override).services['discord-mcp'].ports).toEqual(['3001:3000']);
      expect(createStudioGuard(pickStudioAuthEnv(environment))).toBeNull();
    },
  );

  bash(
    'the committed defaults (what an unset repository variable expands to) render an ENABLED, not-required gate for the studio-auth issuer',
    () => {
      const values = Object.fromEntries(
        Object.entries(DEFAULTS).filter(([, v]) => v !== undefined),
      ) as Record<string, string>;
      const { status, stderr, override } = render(values);
      expect({ status, stderr }).toEqual({ status: 0, stderr: '' });
      const environment = environmentOf(override);
      expect(environment.STUDIO_AUTH_ENABLED).toBe('true');
      expect(environment.STUDIO_AUTH_REQUIRED).toBe('');
      expect(environment.STUDIO_AUTH_ALLOW_SUBS).toBe('');
      expect(environment.STUDIO_AUTH_ALLOW_ALL_AUDIENCE_MEMBERS).toBe('true');
      const guard = createStudioGuard(pickStudioAuthEnv(environment));
      expect(guard).not.toBeNull();
      expect(readStudioAuthConfig(pickStudioAuthEnv(environment))).toMatchObject({
        issuer: ISSUER_DEFAULT,
        jwksUrl: JWKS_DEFAULT,
        audience: 'discord-mcp',
        allowSubs: [],
        audienceOnly: true,
      });
    },
  );

  bash('set variables pass through exactly, and turn the gate on', () => {
    const values = {
      STUDIO_AUTH_ENABLED: 'true',
      STUDIO_AUTH_REQUIRED: 'false',
      STUDIO_AUTH_ISSUER: 'https://auth.example',
      STUDIO_AUTH_JWKS_URL: 'https://auth.example/.well-known/jwks.json',
      STUDIO_AUTH_ALLOW_SUBS: '1001, 1002',
      STUDIO_AUTH_STUDIO_KIDS: 'kid-a',
    };
    const { status, override } = render(values);
    expect(status).toBe(0);
    const environment = environmentOf(override);
    for (const [key, value] of Object.entries(values)) expect(environment[key], key).toBe(value);
    expect(createStudioGuard(pickStudioAuthEnv(environment))).not.toBeNull();
  });

  bash('a lookalike flag value is refused at deploy (loud), never rendered as a silent OFF', () => {
    const { status, stdout, override } = render({ STUDIO_AUTH_ENABLED: 'True' });
    expect(status).not.toBe(0);
    expect(stdout).toContain('::error::STUDIO_AUTH_ENABLED must be exactly "true" or "false"');
    expect(override).toBe('');
    // The server itself would still treat the lookalike as OFF (the contract in studio-auth.ts); the deploy
    // refuses it earlier so an operator who meant ON finds out at deploy time, not at the first 200.
    expect(createStudioGuard(pickStudioAuthEnv({ STUDIO_AUTH_ENABLED: 'True' }))).toBeNull();
  });

  it('the render harness is real: a broken run script fails it', () => {
    if (process.platform === 'win32') return;
    const dir = mkdtempSync(join(tmpdir(), 'discord-mcp-deploy-render-'));
    try {
      const result = spawnSync('bash', ['-c', 'set -e; exit 7'], { encoding: 'utf8' });
      expect(result.status).toBe(7);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('BLOCKER 1 is closed: the identity smoke is REQUIRED-aware and the docs no longer list it as open', () => {
    const smoke = steps.find((s) => s.name?.startsWith('Smoke test - the secret authenticates'));
    expect(smoke?.run, 'the identity smoke step was renamed or removed').toBeDefined();
    // Behaviour is proven in deploy-smoke.test.ts; this only keeps the docs and the step in step.
    expect(smoke?.run).toContain('STUDIO_AUTH_REQUIRED');
    expect(smoke?.run).toContain('studio_credential_required');
    expect(DOC, 'blocker 1 is closed: do not list the smoke as open again').not.toContain(
      'The deploy smoke test sends no credential',
    );
  });

  it('the readiness smoke only calls GET /healthz, the one exempt route', () => {
    const readiness = steps.find((s) => s.name?.startsWith('Smoke test - readiness'));
    expect(readiness?.run).toContain('/healthz');
    expect(readiness?.run).not.toContain('/mcp');
  });
});

describe('docs', () => {
  it('name every variable the gate reads', () => {
    for (const key of STUDIO_AUTH_ENV_KEYS) expect(DOC, key).toContain(key);
  });

  it('name every refusal code the gate can emit', () => {
    for (const code of STUDIO_REFUSAL_CODES) expect(DOC, code).toContain(`\`${code}\``);
  });

  it('give the cutover order: ENABLED, loopback proof, headersHelper, REQUIRED, Access removed LAST', () => {
    const positions = [
      DOC.indexOf('**ENABLED, dual mode'),
      DOC.indexOf('**Loopback proof'),
      DOC.indexOf('**`headersHelper` registration**'),
      DOC.indexOf('**REQUIRED.**'),
      DOC.indexOf('**Remove the Access app LAST.**'),
    ];
    expect(
      positions.every((p) => p >= 0),
      JSON.stringify(positions),
    ).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it('state the audience and that the exemption is the literal GET /healthz', () => {
    expect(DOC).toContain('`discord-mcp`');
    expect(DOC).toContain('GET /healthz');
  });
});

describe('wiring: a test nothing runs guards nothing', () => {
  const NEW_SPECS = [
    'studio-auth.test.ts',
    'studio-auth-vendor.test.ts',
    'http.studio.test.ts',
    'http.differential.test.ts',
    'studio-auth-config.test.ts',
    'studio-auth.entrypoint.test.ts',
    'compose-override-render.test.ts',
  ];
  const vitestConfig = read('packages/mcp-server/vitest.config.ts');

  it('the vitest include pattern covers every new spec and the specs exist', () => {
    expect(vitestConfig).toContain("include: ['src/**/*.test.ts'");
    for (const spec of NEW_SPECS) {
      expect(exists(`packages/mcp-server/src/transports/${spec}`), spec).toBe(true);
      expect(spec.endsWith('.test.ts')).toBe(true);
    }
  });

  it('CI runs the package suite and the typecheck on every pull request, with no path filter', () => {
    const ci = parse(read('.github/workflows/ci.yml')) as {
      on: { pull_request: Record<string, unknown> | null };
      jobs: { test: { steps: Array<{ run?: string }> } };
    };
    const runs = ci.jobs.test.steps.map((s) => s.run).filter(Boolean);
    expect(runs).toContain('pnpm test');
    expect(runs).toContain('pnpm typecheck');
    expect(runs).toContain('pnpm lint');
    expect(ci.on.pull_request ?? {}).not.toHaveProperty('paths');
    expect(ci.on.pull_request ?? {}).not.toHaveProperty('paths-ignore');
  });

  it('the root test script reaches this package through turbo', () => {
    expect(JSON.parse(read('package.json')).scripts.test).toBe('turbo run test');
    expect(JSON.parse(read('packages/mcp-server/package.json')).scripts.test).toBe('vitest run');
  });

  it('biome ignores the vendored byte copy and nothing else new', () => {
    const biome = JSON.parse(read('biome.json')) as { files: { includes: string[] } };
    expect(biome.files.includes).toContain(
      '!packages/mcp-server/src/transports/vendor/studio-auth-verify.mjs',
    );
  });
});

describe('the frozen oracle cannot reach production', () => {
  const SRC = join(REPO, 'packages/mcp-server/src');
  const walk = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
      entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)],
    );

  it('no production source imports legacy/ or the testkit', () => {
    const production = walk(SRC).filter(
      (f) => f.endsWith('.ts') && !f.endsWith('.test.ts') && !/[\\/](legacy|testkit)[\\/]/.test(f),
    );
    expect(production.length).toBeGreaterThan(10);
    const importers = production.filter((f) =>
      /from ['"][^'"]*\b(legacy|testkit)\//.test(readFileSync(f, 'utf8')),
    );
    expect(importers.map((f) => relative(REPO, f))).toEqual([]);
  });

  it('the build entry is src/cli.ts only, so a file outside its import graph is not bundled', () => {
    expect(read('packages/mcp-server/tsdown.config.ts')).toContain("entry: ['src/cli.ts']");
  });
});
