/**
 * Runs the REAL deploy step that writes docker-compose.override.yml, the way the sv-2 runner does, so a spec
 * asserts on what a deploy would actually write: the step's `run:` text is taken from deploy.yml, `sudo` is a
 * pass-through shim, and the deploy checkout is a temp directory holding a copy of the real renderer script.
 * Nothing here re-implements the step; a change to the workflow or the script changes what the specs see.
 */
import { spawn, spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

export const REPO_ROOT = fileURLToPath(new URL('../../../../../', import.meta.url));
export const RENDER_SCRIPT = '.github/scripts/render-compose-override.sh';
export const DISCORD_TOKEN_FIXTURE = `Bot ${'t'.repeat(60)}`;

interface WorkflowStep {
  name?: string;
  run?: string;
  env?: Record<string, string>;
}

export function deployWorkflowSteps(): WorkflowStep[] {
  const workflow = parse(readFileSync(join(REPO_ROOT, '.github/workflows/deploy.yml'), 'utf8')) as {
    jobs: { deploy: { steps: WorkflowStep[] } };
  };
  return workflow.jobs.deploy.steps;
}

export function overrideWriteStep(): WorkflowStep | undefined {
  return deployWorkflowSteps().find((s) => s.name?.startsWith('Write docker-compose.override.yml'));
}

export interface RenderResult {
  status: number | null;
  stdout: string;
  stderr: string;
  /** The file the deploy would hand to `docker compose`, or '' when the step failed before writing it. */
  override: string;
  /** Whether `docker-compose.override.yml` exists in the (temp) deploy checkout after the run. */
  wroteOverride: boolean;
  /** Files the step left behind in its temp directory (the rendered scratch file must not outlive the step). */
  leftovers: string[];
  /** Permission bits of the written override ('' when none was written), e.g. '600'. */
  mode: string;
}

export interface RenderOptions {
  /** Shell text run INSTEAD of the workflow step (used by positive controls). Default: the real step. */
  run?: string;
  /** Skip copying the real renderer into the temp checkout (used to prove the step needs it). */
  withoutScript?: boolean;
  /** Content of an override already on the box from the previous deploy (a refusal must leave it untouched). */
  existingOverride?: string;
  /** Mode of that pre-existing file (an override left world-readable by an older hand-written version). */
  existingMode?: number;
}

/** Render with the given environment (the six studio variables and/or overrides of DISCORD_TOKEN). */
export function renderOverride(
  env: Record<string, string> = {},
  options: RenderOptions = {},
): RenderResult {
  const dir = mkdtempSync(join(tmpdir(), 'discord-mcp-deploy-render-'));
  try {
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    writeFileSync(join(bin, 'sudo'), '#!/bin/sh\nexec "$@"\n');
    chmodSync(join(bin, 'sudo'), 0o755);
    const root = join(dir, 'checkout');
    mkdirSync(join(root, '.github/scripts'), { recursive: true });
    if (options.withoutScript !== true) {
      copyFileSync(join(REPO_ROOT, RENDER_SCRIPT), join(root, RENDER_SCRIPT));
    }
    if (options.existingOverride !== undefined) {
      writeFileSync(join(root, 'docker-compose.override.yml'), options.existingOverride);
      chmodSync(join(root, 'docker-compose.override.yml'), options.existingMode ?? 0o600);
    }
    const result = spawnSync('bash', ['-c', options.run ?? overrideWriteStep()?.run ?? 'exit 99'], {
      env: {
        PATH: `${bin}${delimiter}${process.env.PATH ?? ''}`,
        DEPLOY_ROOT: root,
        HOST_PORT: '3001',
        DISCORD_TOKEN: DISCORD_TOKEN_FIXTURE,
        TMPDIR: dir,
        ...env,
      },
      encoding: 'utf8',
    });
    const file = join(root, 'docker-compose.override.yml');
    const wroteOverride = existsSync(file);
    const leftovers = readdirSync(dir).filter((entry) => entry !== 'bin' && entry !== 'checkout');
    return {
      status: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
      override: wroteOverride ? readFileSync(file, 'utf8') : '',
      wroteOverride,
      leftovers,
      mode: wroteOverride ? (statSync(file).mode & 0o777).toString(8) : '',
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export interface ParsedOverride {
  serviceKeys: string[];
  environment: Record<string, string>;
  ports: string[];
  /** Every top-level key of the whole document (a smuggled sibling service or `x-` key shows up here). */
  topLevelKeys: string[];
  serviceNames: string[];
}

export function parseOverride(override: string): ParsedOverride {
  const doc = parse(override) as {
    services: Record<string, { environment: Record<string, string>; ports: string[] }>;
  } & Record<string, unknown>;
  const service = doc.services['discord-mcp'] as Record<string, unknown>;
  return {
    serviceKeys: Object.keys(service),
    environment: service.environment as Record<string, string>,
    ports: service.ports as string[],
    topLevelKeys: Object.keys(doc),
    serviceNames: Object.keys(doc.services),
  };
}

export function smokeIdentityStep(): WorkflowStep | undefined {
  return deployWorkflowSteps().find((s) =>
    s.name?.startsWith('Smoke test - the secret authenticates'),
  );
}

export interface SmokeResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** The one host the smoke step may send the bot token to. The workflow passes it as a literal argument. */
export const DISCORD_API_BASE_LITERAL = 'https://discord.com/api/v10';
export const BOT_IDENTITY_SCRIPT = '.github/scripts/verify-discord-bot-identity.sh';

/** Runs `bash -c <text>` with a pass-through `sudo` and a temp deploy checkout holding the real scripts. */
function spawnInCheckout(
  text: string,
  env: Record<string, string>,
  args: string[] = [],
  scriptText?: string,
): Promise<SmokeResult> {
  const dir = mkdtempSync(join(tmpdir(), 'discord-mcp-deploy-smoke-'));
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  writeFileSync(join(bin, 'sudo'), '#!/bin/sh\nexec "$@"\n');
  chmodSync(join(bin, 'sudo'), 0o755);
  const root = join(dir, 'checkout');
  mkdirSync(join(root, '.github/scripts'), { recursive: true });
  if (scriptText === undefined) {
    copyFileSync(join(REPO_ROOT, BOT_IDENTITY_SCRIPT), join(root, BOT_IDENTITY_SCRIPT));
  } else {
    writeFileSync(join(root, BOT_IDENTITY_SCRIPT), scriptText);
  }
  return new Promise<SmokeResult>((resolve, reject) => {
    const child = spawn('bash', ['-c', text, 'bash', ...args], {
      env: {
        PATH: `${bin}${delimiter}${process.env.PATH ?? ''}`,
        TMPDIR: dir,
        DEPLOY_ROOT: root,
        ...env,
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
    child.once('error', reject);
    child.once('close', (status) => resolve({ status, stdout, stderr }));
  }).finally(() => rmSync(dir, { recursive: true, force: true }));
}

/**
 * Runs the REAL "Smoke test - the secret authenticates against Discord" step (its `run:` text from deploy.yml)
 * against a local server, the way the runner does (loopback, HOST_PORT). `spawn`, not `spawnSync`: the fake
 * servers live in this process and must keep answering while the step runs. `run` replaces the step text
 * (used to replay the pre-change step as a positive control).
 *
 * The step hardcodes the Discord host, so a fake Discord needs a seam: `TEST_DISCORD_BASE` (consumed here, never
 * passed to the step) replaces that literal in the step text. The literal must be present exactly once, or the
 * run throws: a step that no longer names the host cannot be redirected, and a spec must notice that. Every other
 * variable reaches the step untouched, so a stray `DISCORD_API_BASE` in the runner environment is testable.
 */
export function runSmokeStep(
  env: Record<string, string>,
  options: { run?: string } = {},
): Promise<SmokeResult> {
  const { TEST_DISCORD_BASE: fakeDiscord, ...stepEnv } = env;
  let text = options.run ?? smokeIdentityStep()?.run ?? 'exit 99';
  if (fakeDiscord !== undefined) {
    const occurrences = text.split(DISCORD_API_BASE_LITERAL).length - 1;
    if (occurrences !== 1) {
      throw new Error(
        `expected the step to name ${DISCORD_API_BASE_LITERAL} exactly once, found ${occurrences}`,
      );
    }
    text = text.replace(DISCORD_API_BASE_LITERAL, fakeDiscord);
  }
  return spawnInCheckout(text, stepEnv);
}

/**
 * Runs the real identity script directly: `base` is its positional argument, `env` its environment.
 * `scriptText` runs a modified copy instead (a mutation, used to prove a spec can fail).
 */
export function runBotIdentityScript(
  env: Record<string, string>,
  base: string,
  scriptText?: string,
): Promise<SmokeResult> {
  return spawnInCheckout(
    'exec bash "$DEPLOY_ROOT/$1" "$2"',
    env,
    [BOT_IDENTITY_SCRIPT, base],
    scriptText,
  );
}
