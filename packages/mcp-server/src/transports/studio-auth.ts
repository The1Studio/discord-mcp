/**
 * Studio bearer verification IN FRONT of the HTTP MCP transport (a transport concern: it lives in
 * `transports/`, never in `@discord-mcp/core`). DORMANT: nothing here runs unless STUDIO_AUTH_ENABLED is
 * exactly "true". See ../../../../docs/studio-auth.md for the operator view and the cutover blockers.
 *
 * Why it exists. The only credential this transport checks itself is the optional shared
 * DISCORD_MCP_ACCESS_TOKEN; production does not set it and relies on the Cloudflare Access edge. Removing that
 * Access app would leave a 209-tool Discord bot (bans, channel deletes) readable by anyone who can reach the
 * tunnel. This module is the replacement gate.
 *
 * ## The decision, per protected request
 *
 *   flag off (anything but the exact string "true") ... `inactive`: this module is not even constructed.
 *   a CLAIMED bearer (three segments, ES256 header) ... the studio verdict is FINAL: `allow` or `refuse`. An
 *                                                      invalid bearer is never rescued by any other credential,
 *                                                      and a verifier failure never falls back to "let it through".
 *   no studio credential, STUDIO_AUTH_REQUIRED off ... `unclaimed`: the existing path runs UNCHANGED (this is the
 *                                                      dual-mode window while Access is still in front).
 *   no studio credential, STUDIO_AUTH_REQUIRED on  ... refused, EXCEPT a request that presents the legacy
 *                                                      DISCORD_MCP_ACCESS_TOKEN correctly (`legacy`): that is an
 *                                                      existing credential that is really checked, so it widens nothing.
 *
 * REQUIRED is what makes removing Access safe: with it off, a request with no credential still falls through
 * to the existing path, which is open when DISCORD_MCP_ACCESS_TOKEN is unset.
 *
 * ## Claim rule
 *
 * An `Authorization: Bearer` is a studio credential ONLY if it is a three-segment JWS whose protected header
 * decodes to a JSON object with `alg === "ES256"`. Anything else (an opaque key, a non-ES256 JWT, a header that
 * does not decode) is NOT claimed. The check runs before the verifier's own length cap, so it never decodes an
 * attacker-sized segment (`isStudioJws`).
 *
 * ## Identity
 *
 * The identity is the numeric GitHub id (`sub`), kept as a string. `login` is display-only and is never read
 * here. The principal is reported as `github:<id>` for the log and is NEVER authorized on as a string: the
 * allowlist is checked by the verifier against the numeric id. Human surface only: tiers ["studio"], kinds
 * ["user"] (an owners assertion is `wrong_tier`, a machine `oidc:` assertion is `wrong_kind`).
 *
 * The verifier is the vendored `vendor/studio-auth-verify.mjs` (pinned, hash-checked), loaded LAZILY through a
 * cached dynamic import on the first request that needs it. With the flag off it is never loaded.
 */
import type { IncomingHttpHeaders } from 'node:http';
import type { Verifier } from './vendor/studio-auth-verify.mjs';

type VerifierModule = typeof import('./vendor/studio-auth-verify.mjs');

/** The audience this service accepts. Pinned in code on purpose: an env var could point it at another service's audience. */
export const STUDIO_AUDIENCE = 'discord-mcp';

/**
 * The longest token, in characters, the vendored verifier will look at: its `MAX_TOKEN_CHARS`, which the
 * vendored file does not export and which is hash-pinned, so it can be neither imported nor edited here.
 * Mirrored ONCE here; `studio-auth.test.ts` reads the vendored source and fails if the two ever differ.
 */
export const STUDIO_MAX_TOKEN_CHARS = 8192;

/** Most verifiers kept alive. A real deployment has ONE config (the env is a startup snapshot); the bound is a backstop. */
export const STUDIO_VERIFIER_CACHE_MAX = 8;

/** Realm on every 401. */
export const STUDIO_REALM = 'discord-mcp';

/** The vars the studio path reads. All optional strings: committed config ships none of them set. */
export interface StudioAuthEnv {
  STUDIO_AUTH_ENABLED?: string;
  STUDIO_AUTH_REQUIRED?: string;
  STUDIO_AUTH_ISSUER?: string;
  STUDIO_AUTH_JWKS_URL?: string;
  STUDIO_AUTH_AUDIENCE?: string;
  STUDIO_AUTH_ALLOW_SUBS?: string;
  STUDIO_AUTH_STUDIO_KIDS?: string;
}

/** Every variable the studio path reads; the docs and the compose example must name each one (studio-auth-config.test.ts). */
export const STUDIO_AUTH_ENV_KEYS = [
  'STUDIO_AUTH_ENABLED',
  'STUDIO_AUTH_REQUIRED',
  'STUDIO_AUTH_ISSUER',
  'STUDIO_AUTH_JWKS_URL',
  'STUDIO_AUTH_AUDIENCE',
  'STUDIO_AUTH_ALLOW_SUBS',
  'STUDIO_AUTH_STUDIO_KIDS',
] as const;

/** Snapshot exactly the studio vars out of a process env (so a later mutation of `process.env` changes nothing). */
export function pickStudioAuthEnv(env: Record<string, string | undefined>): StudioAuthEnv {
  const out: Record<string, string> = {};
  for (const key of STUDIO_AUTH_ENV_KEYS) {
    const value = env[key];
    if (value !== undefined) out[key] = value;
  }
  return out as StudioAuthEnv;
}

/** The error a malformed studio-auth variable raises. Fail closed: it is never swallowed into "allow". */
export class StudioAuthConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StudioAuthConfigError';
  }
}

/** Whether the studio path is on. Strictly the exact string "true": " true", "True", "1", "yes" leave it OFF. */
export function studioAuthEnabled(raw: unknown): boolean {
  return raw === 'true';
}

/** Whether a request with no studio credential is refused. Strictly the exact string "true". */
export function studioAuthRequired(raw: unknown): boolean {
  return raw === 'true';
}

/** A GitHub numeric id: positive, no sign, no leading zero. */
const NUMERIC_ID = /^[1-9]\d*$/;

function splitList(raw: unknown, name: string): string[] {
  if (raw === undefined || raw === null) return [];
  if (typeof raw !== 'string') {
    throw new StudioAuthConfigError(`${name} must be a comma-separated string`);
  }
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '');
}

/**
 * Parse `STUDIO_AUTH_ALLOW_SUBS`: comma-separated NUMERIC GitHub ids, kept as strings (never through Number).
 *
 * Empty or absent is `[]`, which allows NOBODY. A malformed entry (a login, an email, a typo) THROWS: dropping
 * it would quietly turn a typo into a smaller list that still looks configured.
 */
export function parseAllowSubs(raw: unknown): string[] {
  const ids = splitList(raw, 'STUDIO_AUTH_ALLOW_SUBS');
  for (const id of ids) {
    if (!NUMERIC_ID.test(id)) {
      throw new StudioAuthConfigError(
        'STUDIO_AUTH_ALLOW_SUBS must be comma-separated numeric GitHub ids (a login or email is not an identity)',
      );
    }
  }
  return ids;
}

export interface StudioAuthConfig {
  issuer: string;
  jwksUrl: string;
  audience: typeof STUDIO_AUDIENCE;
  allowSubs: string[];
  studioKids: string[];
}

const trimmedString = (value: unknown): string | null =>
  typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
const uniqueSorted = (values: string[]): string[] => [...new Set(values)].sort();

/**
 * Resolve the studio-auth configuration from the env.
 *
 * @returns `null` when the issuer or JWKS URL is missing (an unconfigured deploy admits nobody).
 * @throws {StudioAuthConfigError} when the allowlist or kid list is malformed, or STUDIO_AUTH_AUDIENCE names a
 *   different audience than the one pinned in code.
 */
export function readStudioAuthConfig(
  env: StudioAuthEnv | Record<string, unknown> | undefined,
): StudioAuthConfig | null {
  const e = (env ?? {}) as Record<string, unknown>;
  const audience = e.STUDIO_AUTH_AUDIENCE;
  if (
    audience !== undefined &&
    audience !== null &&
    audience !== '' &&
    trimmedString(audience) !== STUDIO_AUDIENCE
  ) {
    throw new StudioAuthConfigError(
      `STUDIO_AUTH_AUDIENCE is pinned to "${STUDIO_AUDIENCE}" in code: remove the variable or set exactly that`,
    );
  }
  const issuer = trimmedString(e.STUDIO_AUTH_ISSUER);
  const jwksUrl = trimmedString(e.STUDIO_AUTH_JWKS_URL);
  if (issuer === null || jwksUrl === null) return null;
  return {
    issuer,
    jwksUrl,
    audience: STUDIO_AUDIENCE,
    allowSubs: uniqueSorted(parseAllowSubs(e.STUDIO_AUTH_ALLOW_SUBS)),
    studioKids: uniqueSorted(splitList(e.STUDIO_AUTH_STUDIO_KIDS, 'STUDIO_AUTH_STUDIO_KIDS')),
  };
}

// ---------------------------------------------------------------- logging (never a token, assertion or claim)

/**
 * Where the gate reports. A fixed message plus a few scalar fields; never a token, an assertion or a claim.
 * http.ts adapts this to its pino logger; a spec records the calls.
 */
export type StudioLogSink = (
  level: 'info' | 'warn',
  message: string,
  fields?: Readonly<Record<string, string | number | boolean>>,
) => void;

const logged = new Set<string>();
const LOGGED_MAX = 32;

/** Log a fixed warning once per process (bounded), so a hostile caller cannot flood the journal. */
function warnOnce(sink: StudioLogSink | undefined, message: string): void {
  if (sink === undefined || logged.has(message) || logged.size >= LOGGED_MAX) return;
  logged.add(message);
  sink('warn', message);
}

// ---------------------------------------------------------------- lazy module + verifier cache

export interface ModuleLoader<T> {
  /** Load once and cache the promise. A failed load is NOT cached, so a later request retries. */
  load(): Promise<T>;
  /** How many loads were started. */
  count(): number;
}

/** A cached lazy loader around `importer`. Exported so a spec can drive the failure path with a fake importer. */
export function createModuleLoader<T>(importer: () => Promise<T>): ModuleLoader<T> {
  let promise: Promise<T> | null = null;
  let loads = 0;
  return {
    load() {
      if (promise === null) {
        loads += 1;
        promise = importer().catch((err: unknown) => {
          promise = null;
          throw err;
        });
      }
      return promise;
    },
    count: () => loads,
  };
}

const verifierModule = createModuleLoader<VerifierModule>(
  () => import('./vendor/studio-auth-verify.mjs'),
);

/** The vendored verifier, loaded once on first use. Never called while the flag is off. */
export const loadVerifierModule = (): Promise<VerifierModule> => verifierModule.load();

/** How many times the vendored module was loaded. A test seam: flag-off must leave it at 0. */
export const studioModuleLoadCount = (): number => verifierModule.count();

const verifiers = new Map<string, Verifier>();

/**
 * The cache key is a STABLE STRING over every input that defines the verifier. Never the config object:
 * `readStudioAuthConfig` returns a fresh literal per request, so an identity key would never hit and every
 * request would rebuild the verifier and refetch the JWKS. The lists are already sorted and de-duplicated.
 */
const verifierKey = (config: StudioAuthConfig): string =>
  JSON.stringify([
    config.issuer,
    config.jwksUrl,
    config.audience,
    config.allowSubs,
    config.studioKids,
  ]);

function verifierFor(mod: VerifierModule, config: StudioAuthConfig): Verifier {
  const key = verifierKey(config);
  const hit = verifiers.get(key);
  if (hit) return hit;
  const built = mod.createVerifier({
    issuer: config.issuer,
    jwksUrl: config.jwksUrl,
    audience: config.audience,
    tiers: ['studio'],
    kinds: ['user'],
    allowSubs: config.allowSubs,
    ...(config.studioKids.length > 0
      ? {
          kidTiers: Object.fromEntries(config.studioKids.map((kid) => [kid, 'studio' as const])),
        }
      : {}),
  });
  if (verifiers.size >= STUDIO_VERIFIER_CACHE_MAX) {
    const oldest = verifiers.keys().next().value;
    if (oldest !== undefined) verifiers.delete(oldest);
  }
  verifiers.set(key, built);
  return built;
}

/** Drop every cached verifier and forget logged messages. A test seam: production never calls it. */
export function resetStudioAuthState(): void {
  verifiers.clear();
  logged.clear();
}

/** How many verifiers are cached. A test seam. */
export function studioVerifierCacheSize(): number {
  return verifiers.size;
}

// ---------------------------------------------------------------- the claim rule

const B64URL = /^[A-Za-z0-9_-]+$/;

/**
 * Whether a bearer token is a studio credential: three dot-separated segments and a protected header that
 * base64url-decodes to a JSON object with `alg === "ES256"`. Never throws: any decode failure is "no".
 *
 * Cheap on purpose: this runs BEFORE the verifier's own `MAX_TOKEN_CHARS` check, so it must never decode an
 * attacker-sized segment. A non-string, or a first (header) segment longer than `STUDIO_MAX_TOKEN_CHARS`, is
 * simply not claimed, found by `indexOf` scans with no `split`, no `atob` and no allocation. A protected
 * header longer than the whole token the verifier would accept can never belong to a verifiable studio
 * credential. A token with a normal header but an over-long payload or signature is still CLAIMED here and
 * the verifier refuses it `bad_format` before any JWKS fetch.
 */
export function isStudioJws(token: unknown): boolean {
  if (typeof token !== 'string') return false;
  const first = token.indexOf('.');
  if (first < 1 || first > STUDIO_MAX_TOKEN_CHARS) return false;
  const second = token.indexOf('.', first + 1);
  if (second === -1 || token.indexOf('.', second + 1) !== -1) return false;
  try {
    const head = token.slice(0, first);
    if (!B64URL.test(head)) return false;
    const b64 = head.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const header: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    // `Object.hasOwn` is false for an array or a string and throws on null (caught below): none is claimed.
    return Object.hasOwn(header as object, 'alg') && (header as { alg: unknown }).alg === 'ES256';
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- the one credential-free route

/**
 * Whether a request skips the studio gate: exactly `GET /healthz`, nothing else. The comparison is on the
 * parsed pathname and the raw method, both exact: no case folding, no prefix or suffix, no trailing slash,
 * no other method. Kept as one named predicate (not an inline expression) because http.ts routes every
 * other path to a 404 BEFORE the gate, so a widened comparison here is invisible to a request-level test;
 * the unit spec pins each widening axis on this function instead (http.studio.test.ts).
 */
export function isStudioExemptRoute(
  method: string | undefined,
  pathname: string | undefined,
): boolean {
  return method === 'GET' && pathname === '/healthz';
}

// ---------------------------------------------------------------- the decision

export interface StudioRefusal {
  decision: 'refuse';
  /** 401 bad/absent credential, 403 authenticated but not permitted here, 500 our misconfiguration, 503 JWKS outage. */
  status: 401 | 403 | 500 | 503;
  code: string;
  /** Whether a claimed studio credential was presented (decides `error="invalid_token"` on the 401). */
  presented: boolean;
}

export type StudioDecision =
  | { decision: 'inactive' }
  | { decision: 'unclaimed' }
  | { decision: 'legacy' }
  | { decision: 'allow'; principal: string }
  | StudioRefusal;

export interface StudioGateDeps {
  /** Test seam: where the vendored verifier module comes from. */
  loadModule?: () => Promise<VerifierModule>;
  /** Whether the raw Authorization header carries the correct legacy DISCORD_MCP_ACCESS_TOKEN. Only consulted in REQUIRED mode. */
  legacyCredentialOk?: (authorization: string | undefined) => boolean;
  /** Where the gate reports (fixed messages only). */
  log?: StudioLogSink;
}

const refuse = (
  status: StudioRefusal['status'],
  code: string,
  presented: boolean,
): StudioRefusal => ({ decision: 'refuse', status, code, presented });

/** Verifier codes that mean "the credential is authentic but not for this surface": 403, not 401. */
const FORBIDDEN_CODES = new Set(['wrong_tier', 'wrong_kind', 'not_allowed']);
const UNAUTHORIZED_CODES = new Set([
  'bad_format',
  'bad_alg',
  'bad_sig',
  'wrong_iss',
  'wrong_aud',
  'expired',
  'not_yet_valid',
]);

/** Every refusal code this module can emit. The docs table must name each one (studio-auth-config.test.ts). */
export const STUDIO_REFUSAL_CODES: readonly string[] = [
  ...UNAUTHORIZED_CODES,
  ...FORBIDDEN_CODES,
  'jwks_unavailable',
  'invalid_credential',
  'studio_credential_required',
  'studio_credential_not_accepted',
  'studio_auth_config_invalid',
  'studio_auth_not_configured',
  'studio_auth_error',
];

/** Map a verifier code to a status and a code safe to echo. An unknown code (a future verifier) fails closed as a 401. */
function refusalForVerifierCode(code: string): StudioRefusal {
  if (code === 'jwks_unavailable') return refuse(503, code, true);
  if (FORBIDDEN_CODES.has(code)) return refuse(403, code, true);
  if (UNAUTHORIZED_CODES.has(code)) return refuse(401, code, true);
  return refuse(401, 'invalid_credential', true);
}

/** The raw Authorization header, found case-insensitively like the vendored `bearerFromRequest`. */
function rawAuthorization(headers: IncomingHttpHeaders): string | undefined {
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === 'authorization') {
      const value = headers[key];
      return typeof value === 'string' ? value : undefined;
    }
  }
  return undefined;
}

/**
 * Decide a request on the studio path. Never throws, never logs a token or any claim, and never returns more
 * than the principal on success. `env` is the studio-vars snapshot.
 */
export async function studioGate(
  headers: IncomingHttpHeaders,
  env: StudioAuthEnv | Record<string, unknown> | undefined,
  deps: StudioGateDeps = {},
): Promise<StudioDecision> {
  const e = (env ?? {}) as Record<string, unknown>;
  if (!studioAuthEnabled(e.STUDIO_AUTH_ENABLED)) return { decision: 'inactive' };
  try {
    const mod = await (deps.loadModule ?? loadVerifierModule)();
    const token = mod.bearerFromRequest(headers);

    if (token === null || !isStudioJws(token)) {
      // Not a studio credential: the existing path decides, unless REQUIRED closes the open fall-through.
      if (!studioAuthRequired(e.STUDIO_AUTH_REQUIRED)) return { decision: 'unclaimed' };
      const authorization = rawAuthorization(headers);
      if (authorization !== undefined && deps.legacyCredentialOk?.(authorization) === true) {
        return { decision: 'legacy' };
      }
      const absent = authorization === undefined || authorization.trim() === '';
      return refuse(
        401,
        absent ? 'studio_credential_required' : 'studio_credential_not_accepted',
        false,
      );
    }

    // A studio credential was presented. From here the studio verdict is final.
    let config: StudioAuthConfig | null;
    try {
      config = readStudioAuthConfig(e);
    } catch (err) {
      warnOnce(
        deps.log,
        err instanceof StudioAuthConfigError ? err.message : 'invalid configuration',
      );
      return refuse(500, 'studio_auth_config_invalid', true);
    }
    if (config === null) {
      warnOnce(
        deps.log,
        'STUDIO_AUTH_ISSUER / STUDIO_AUTH_JWKS_URL is not configured; refusing the studio bearer',
      );
      return refuse(500, 'studio_auth_not_configured', true);
    }

    const result = await verifierFor(mod, config).verify(token);
    if (!result.ok) return refusalForVerifierCode(result.code);
    return { decision: 'allow', principal: `github:${result.claims.sub}` };
  } catch (err) {
    // The verifier (or the module load) threw: no identity, and never a fall back to anything spoofable.
    warnOnce(deps.log, `verifier failed: ${err instanceof Error ? err.name : 'unknown'}`);
    return refuse(500, 'studio_auth_error', false);
  }
}

// ---------------------------------------------------------------- the refusal response

export interface StudioRefusalResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * Build the HTTP response for a refusal. It is a plain, complete JSON response (explicit content-length) so a
 * client never sees an SSE stream or a half-written MCP session: the caller writes it BEFORE any MCP handling.
 * `/mcp` gets a JSON-RPC error envelope (`id: null`, no request was parsed); every other route a small REST body.
 */
export function studioRefusalResponse(
  refusal: StudioRefusal,
  isMcpRoute: boolean,
): StudioRefusalResponse {
  const { status, code } = refusal;
  const clientFault = status === 401 || status === 403;
  const body = isMcpRoute
    ? {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: clientFault ? -32001 : -32603,
          message: `${clientFault ? 'unauthorized' : 'unavailable'}: ${code}`,
          data: { code },
        },
      }
    : {
        error: clientFault ? 'unauthorized' : status === 503 ? 'unavailable' : 'misconfigured',
        code,
      };
  const text = JSON.stringify(body);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(text)),
    'cache-control': 'no-store',
  };
  if (status === 401) {
    headers['www-authenticate'] =
      `Bearer realm="${STUDIO_REALM}"${refusal.presented ? ', error="invalid_token"' : ''}`;
  }
  if (status === 503) headers['retry-after'] = '30';
  return { status, headers, body: text };
}

/** Stable code for a request target the URL parser rejects (`GET //`, an unterminated IPv6 literal). */
export const STUDIO_BAD_REQUEST_CODE = 'invalid_request_target';

/**
 * The 400 answered (flag on only) when `new URL(...)` rejects the request target. A complete JSON response with a
 * stable code; it echoes nothing from the request (not the Host, not the target) and is written before routing.
 */
export function studioBadRequestResponse(): StudioRefusalResponse {
  const text = JSON.stringify({ error: 'bad_request', code: STUDIO_BAD_REQUEST_CODE });
  return {
    status: 400,
    headers: {
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(text)),
      'cache-control': 'no-store',
    },
    body: text,
  };
}

// ---------------------------------------------------------------- the guard the HTTP transport owns

/** What the transport holds when the flag is on. `null` (never constructed) when it is off. */
export class StudioGuard {
  constructor(
    private readonly env: StudioAuthEnv,
    private readonly deps: StudioGateDeps,
  ) {}

  /**
   * Fail fast at startup: a flag-on process with a broken gate must not start and serve. Throws on a missing
   * issuer/JWKS URL, a malformed allowlist, a wrong pinned audience, or a non-https JWKS URL. Builds the
   * verifier (no network) so the first request reuses it.
   */
  async prepare(): Promise<void> {
    const mod = await (this.deps.loadModule ?? loadVerifierModule)();
    const config = readStudioAuthConfig(this.env);
    if (config === null) {
      throw new StudioAuthConfigError(
        'STUDIO_AUTH_ENABLED=true needs STUDIO_AUTH_ISSUER and STUDIO_AUTH_JWKS_URL',
      );
    }
    verifierFor(mod, config);
    const required = studioAuthRequired(this.env.STUDIO_AUTH_REQUIRED);
    this.deps.log?.('info', 'studio auth enabled', {
      issuer: config.issuer,
      audience: config.audience,
      allowed: config.allowSubs.length,
      required,
    });
    if (config.allowSubs.length === 0) {
      this.deps.log?.('warn', 'STUDIO_AUTH_ALLOW_SUBS is empty: nobody can use the studio path');
    }
  }

  decide(headers: IncomingHttpHeaders): Promise<StudioDecision> {
    return studioGate(headers, this.env, this.deps);
  }

  /** Report an allowed request: the principal and the route class, nothing else. */
  logAllow(principal: string, route: 'mcp' | 'healthz'): void {
    this.deps.log?.('info', 'studio auth allow', { principal, route });
  }
}

/**
 * Build the guard for the transport, or `null` when the flag is not exactly "true" (flag-off: no object, no
 * overhead, nothing loaded). Throws on a REQUIRED value that cannot mean what the operator intended:
 * REQUIRED=true without ENABLED=true would look protected and be open, and any REQUIRED value other than
 * empty / "true" / "false" is ambiguous on the one flag whose failure mode is "less secure".
 */
export function createStudioGuard(
  env: StudioAuthEnv | undefined,
  deps: StudioGateDeps = {},
): StudioGuard | null {
  const e = env ?? {};
  if (!studioAuthEnabled(e.STUDIO_AUTH_ENABLED)) {
    if (studioAuthRequired(e.STUDIO_AUTH_REQUIRED)) {
      throw new StudioAuthConfigError(
        'STUDIO_AUTH_REQUIRED=true needs STUDIO_AUTH_ENABLED=true (the gate is off, so nothing would be required)',
      );
    }
    return null;
  }
  const required = e.STUDIO_AUTH_REQUIRED;
  if (required !== undefined && required !== '' && required !== 'true' && required !== 'false') {
    throw new StudioAuthConfigError(
      'STUDIO_AUTH_REQUIRED must be exactly "true" or "false" (or unset)',
    );
  }
  return new StudioGuard(e, deps);
}
