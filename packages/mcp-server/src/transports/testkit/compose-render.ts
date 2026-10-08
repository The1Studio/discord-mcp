/**
 * Runs the REAL deploy step that writes docker-compose.override.yml, the way the sv-2 runner does, so a spec
 * asserts on what a deploy would actually write: the step's `run:` text is taken from deploy.yml, `sudo` is a
 * pass-through shim, and the deploy checkout is a temp directory holding a copy of the real renderer script.
 * Nothing here re-implements the step; a change to the workflow or the script changes what the specs see.
 */
import { spawnSync } from 'node:child_process';
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
