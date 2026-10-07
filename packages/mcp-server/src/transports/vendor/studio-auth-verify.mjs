// VENDORED - do not edit by hand.
//
// Source repo : https://github.com/The1Studio/theonekit-model-router
// Source path : studio-auth/verify/studio-auth-verify.mjs
// Pinned sha  : dd10188a44e8bee3f6c8c33ce3f6d425b375f4e9
// sha256      : b45ff7cd4ad9f57f0d343d43483524371d934859b7cd14386f20a48a952ba820
//
// Everything below the BEGIN VENDORED SOURCE marker is a byte-for-byte copy of the file at the
// pinned commit (git blob 6d6908496d8b8c7d8f3f259bd2e350c29df86781). The bytes were fetched from
// `main` (HEAD d7d350c1ff99e9f1542c8ba895ad23e627127b0f) and re-fetched at the pinned SHA: identical
// (dd10188a is the last commit that touched the file). It is vendored, not installed, so a later
// upstream change never reaches this repo unreviewed.
// studio-auth-vendor.test.ts recomputes the sha256 of the bytes below the marker and fails when they
// differ from the hash above. To upgrade: re-pin the SHA, re-copy the file and update the hash
// together, in one reviewed PR.
//
// Used by ../studio-auth.ts, which http.ts calls for the dormant studio-auth bearer path. Loaded
// lazily (dynamic import) and only when STUDIO_AUTH_ENABLED is exactly "true".
//
// BEGIN VENDORED SOURCE
// studio-auth-verify.mjs — verify a studio-auth assertion locally.
//
// Zero dependencies (WebCrypto + fetch only). Runs in Cloudflare Workers and
// Node >= 20. Never calls GitHub, never logs a token. Vendor this one file by
// pinned SHA (see README.md).
//
// Assertion contract (shared with the studio-auth Worker, do not change):
//   header  : alg = ES256, kid
//   claims  : iss, aud (string | array), sub (numeric GitHub id, as string),
//             login, tier ("studio" | "owners"), iat, exp, jti,
//             kind ("user" when absent | "machine")
//   machine : kind "machine", sub "oidc:<GitHub Actions OIDC sub>", login "oidc". Refused unless the
//             service opts in with kinds: ['machine'] (see createVerifier).

const SKEW_SECONDS = 30; // max clock skew, either direction
const JWKS_FRESH_MS = 5 * 60_000; // serve from cache without refetch
const JWKS_STALE_MAX_MS = 60 * 60_000; // serve stale if the fetch fails
const UNKNOWN_KID_REFRESH_MS = 30_000; // at most one kid-miss refresh per window
const FAILED_FETCH_RETRY_MS = 5_000; // do not hammer a down JWKS endpoint
const FETCH_TIMEOUT_MS = 5_000;
const MAX_TOKEN_CHARS = 8192;
const TIERS = ['studio', 'owners'];
const KINDS = ['user', 'machine'];

const B64URL = /^[A-Za-z0-9_-]+$/;

function b64urlBytes(s) {
  if (!B64URL.test(s)) throw new Error('b64');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlJson(s) {
  const v = JSON.parse(new TextDecoder().decode(b64urlBytes(s)));
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('json');
  return v;
}

/** Extract the bearer token from a Headers instance, a plain object, or a Request. Returns null when absent. */
export function bearerFromRequest(headers) {
  const h = headers && typeof headers.headers === 'object' && headers.headers !== null ? headers.headers : headers;
  let raw = null;
  if (h && typeof h.get === 'function') raw = h.get('authorization');
  else if (h && typeof h === 'object') {
    for (const k of Object.keys(h)) if (k.toLowerCase() === 'authorization') raw = h[k];
  }
  if (typeof raw !== 'string') return null;
  const m = /^Bearer[ \t]+(\S+)[ \t]*$/i.exec(raw);
  return m ? m[1] : null;
}

async function importJwks(body) {
  if (!body || !Array.isArray(body.keys)) throw new Error('jwks shape');
  const keys = new Map();
  for (const jwk of body.keys) {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.kid !== 'string') continue;
    if (jwk.use !== undefined && jwk.use !== 'sig') continue;
    if (jwk.alg !== undefined && jwk.alg !== 'ES256') continue;
    try {
      const pub = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true };
      keys.set(jwk.kid, await crypto.subtle.importKey('jwk', pub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']));
    } catch {
      // skip an unusable key; the others stay valid
    }
  }
  if (keys.size === 0) throw new Error('jwks has no usable ES256 key');
  return keys;
}

/**
 * @param {object} cfg
 * @param {string} cfg.issuer      exact `iss` expected
 * @param {string} cfg.jwksUrl     where the Worker publishes its JWKS
 * @param {string|string[]} cfg.audience  this service's audience
 * @param {string[]} [cfg.tiers]   accepted tiers (default both)
 * @param {string[]} [cfg.kinds]   accepted assertion kinds (default ['user']): a service that never opted in
 *                                      to machine callers keeps rejecting machine assertions (`wrong_kind`)
 * @param {string[]} [cfg.allowSubs]    user kind: numeric GitHub ids (the identity to use); machine kind: the
 *                                      FULL `oidc:<sub>` strings (exact match, no wildcard); [] allows nobody.
 *                                      REQUIRED when kinds includes 'machine' (never "any machine")
 * @param {string[]} [cfg.allowLogins]  extra narrowing by login (case-insensitive); a login can be renamed and
 *                                      reclaimed by someone else, so never use it alone; [] allows nobody
 * @param {Record<string,'studio'|'owners'>} [cfg.kidTiers]  pin each signing kid to the one tier it may mint;
 *                                      a kid not listed is rejected. An owners service MUST be given the owners
 *                                      JWKS URL and tiers ['owners']
 * @param {boolean} [cfg.allowInsecureLocalhost]  permit an http jwksUrl on localhost / 127.0.0.1 (dev only)
 * @param {() => number} [cfg.clock]    ms since epoch, test seam
 * @param {typeof fetch} [cfg.fetch]    fetch implementation, test seam
 */
export function createVerifier(cfg) {
  if (!cfg || typeof cfg.issuer !== 'string' || !cfg.issuer) throw new Error('studio-auth-verify: issuer is required');
  if (typeof cfg.jwksUrl !== 'string' || !cfg.jwksUrl) throw new Error('studio-auth-verify: jwksUrl is required');
  let jwks;
  try {
    jwks = new URL(cfg.jwksUrl);
  } catch {
    throw new Error('studio-auth-verify: jwksUrl is not a valid URL');
  }
  const localDev = cfg.allowInsecureLocalhost === true && jwks.protocol === 'http:' && (jwks.hostname === 'localhost' || jwks.hostname === '127.0.0.1');
  if (jwks.protocol !== 'https:' && !localDev) throw new Error('studio-auth-verify: jwksUrl must be https (http only for localhost with allowInsecureLocalhost: true)');
  const normIss = (v) => (typeof v === 'string' ? v.replace(/\/$/, '') : v);
  const issuer = normIss(cfg.issuer);
  const audiences = (Array.isArray(cfg.audience) ? cfg.audience : [cfg.audience]).filter((a) => typeof a === 'string' && a);
  if (audiences.length === 0) throw new Error('studio-auth-verify: audience is required');
  const tiers = cfg.tiers ?? TIERS;
  if (!Array.isArray(tiers) || tiers.some((t) => !TIERS.includes(t))) throw new Error('studio-auth-verify: tiers must be studio and/or owners');
  const kinds = cfg.kinds ?? ['user'];
  if (!Array.isArray(kinds) || kinds.length === 0 || kinds.some((k) => !KINDS.includes(k))) throw new Error('studio-auth-verify: kinds must be user and/or machine');
  const acceptsMachine = kinds.includes('machine');
  const allow = cfg.allowLogins === undefined ? null : new Set(cfg.allowLogins.map((l) => String(l).toLowerCase()));
  const subOk = (x) => typeof x === 'string' && (/^\d+$/.test(x) || (acceptsMachine && /^oidc:\S+$/.test(x)));
  if (cfg.allowSubs !== undefined && (!Array.isArray(cfg.allowSubs) || cfg.allowSubs.some((x) => !subOk(x)))) {
    throw new Error(`studio-auth-verify: allowSubs must be an array of numeric GitHub id strings${acceptsMachine ? ' or full oidc:<sub> strings' : ''}`);
  }
  if (acceptsMachine && cfg.allowSubs === undefined) throw new Error('studio-auth-verify: kinds including machine requires allowSubs (the exact oidc:<sub> callers)');
  const allowSubs = cfg.allowSubs === undefined ? null : new Set(cfg.allowSubs);
  if (cfg.kidTiers !== undefined) {
    const kt = cfg.kidTiers;
    if (kt === null || typeof kt !== 'object' || Array.isArray(kt) || Object.values(kt).some((t) => !TIERS.includes(t))) {
      throw new Error('studio-auth-verify: kidTiers must map kid -> studio|owners');
    }
  }
  const kidTiers = cfg.kidTiers ?? null;
  const clock = cfg.clock ?? Date.now;
  const doFetch = cfg.fetch ?? ((...a) => globalThis.fetch(...a));

  let keys = null; // Map kid -> CryptoKey, null until the first successful fetch
  let fetchedAt = 0;
  let lastAttempt = -Infinity;
  let lastAttemptFailed = false;
  let lastKidMissRefresh = -Infinity;
  let inflight = null;

  function refresh(now) {
    if (inflight) return inflight; // single-flight
    lastAttempt = now;
    inflight = (async () => {
      try {
        const res = await doFetch(cfg.jwksUrl, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
        if (!res.ok) throw new Error('jwks status');
        keys = await importJwks(await res.json());
        fetchedAt = clock();
        lastAttemptFailed = false;
        return true;
      } catch {
        lastAttemptFailed = true;
        return false;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  // Returns { key } | { code } for the kid in the token header.
  async function keyFor(kid) {
    const now = clock();
    if (keys === null) {
      if (!inflight && lastAttemptFailed && now - lastAttempt < FAILED_FETCH_RETRY_MS) return { code: 'jwks_unavailable' };
      if (!(await refresh(now)) || keys === null) return { code: 'jwks_unavailable' };
      const k = keys.get(kid);
      return k ? { key: k } : { code: 'bad_sig' };
    }
    const age = now - fetchedAt;
    if (age >= JWKS_FRESH_MS) {
      const canRetry = !(lastAttemptFailed && now - lastAttempt < FAILED_FETCH_RETRY_MS);
      const ok = inflight ? await inflight : canRetry ? await refresh(now) : false;
      if (!ok && age > JWKS_STALE_MAX_MS) return { code: 'jwks_unavailable' };
    } else if (!keys.has(kid) && now - lastKidMissRefresh >= UNKNOWN_KID_REFRESH_MS) {
      lastKidMissRefresh = now;
      await refresh(now);
    }
    const k = keys.get(kid);
    return k ? { key: k } : { code: 'bad_sig' };
  }

  return {
    async verify(token) {
      const fail = (code) => ({ ok: false, code });
      if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_CHARS) return fail('bad_format');
      const parts = token.split('.');
      if (parts.length !== 3) return fail('bad_format');
      let header, claims;
      try {
        header = b64urlJson(parts[0]);
        claims = b64urlJson(parts[1]);
      } catch {
        return fail('bad_format');
      }
      if (Object.hasOwn(header, 'crit')) return fail('bad_format');
      // Checked before the signature is even parsed: alg none carries an empty one.
      if (!Object.hasOwn(header, 'alg') || header.alg !== 'ES256') return fail('bad_alg');
      if (!Object.hasOwn(header, 'kid') || typeof header.kid !== 'string' || !header.kid) return fail('bad_format');
      let sig;
      try {
        sig = b64urlBytes(parts[2]);
      } catch {
        return fail('bad_format');
      }
      if (sig.length !== 64) return fail('bad_sig');

      const found = await keyFor(header.kid);
      if (!found.key) return fail(found.code);
      let valid = false;
      try {
        valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, found.key, sig, new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
      } catch {
        valid = false;
      }
      if (!valid) return fail('bad_sig');

      // Signature is good: from here the claims are the Worker's, but still validated.
      const { iss, aud, sub, login, tier, iat, exp, jti, nbf } = claims;
      // `kind` is a signed claim: absent means a user assertion (contract before machines existed).
      const kind = Object.hasOwn(claims, 'kind') ? claims.kind : 'user';
      if (typeof kind !== 'string' || !KINDS.includes(kind)) return fail('bad_format');
      if (!kinds.includes(kind)) return fail('wrong_kind');
      if (typeof exp !== 'number' || !Number.isFinite(exp) || typeof iat !== 'number' || !Number.isFinite(iat)) return fail('bad_format');
      if (typeof sub !== 'string' || typeof login !== 'string' || !login || typeof jti !== 'string' || !jti) return fail('bad_format');
      // The numeric-id check is for users only; a machine sub is the namespaced OIDC sub.
      if (kind === 'user' ? !/^\d+$/.test(sub) : !/^oidc:\S+$/.test(sub) || login !== 'oidc') return fail('bad_format');
      if (normIss(iss) !== issuer) return fail('wrong_iss');
      const auds = Array.isArray(aud) ? aud : [aud];
      if (!auds.some((a) => typeof a === 'string' && audiences.includes(a))) return fail('wrong_aud');
      const nowSec = clock() / 1000;
      if (nbf !== undefined && (typeof nbf !== 'number' || !Number.isFinite(nbf))) return fail('bad_format');
      if (exp <= nowSec - SKEW_SECONDS) return fail('expired');
      if (iat > nowSec + SKEW_SECONDS || (nbf !== undefined && nbf > nowSec + SKEW_SECONDS)) return fail('not_yet_valid');
      if (typeof tier !== 'string' || !tiers.includes(tier)) return fail('wrong_tier');
      if (kidTiers !== null && (!Object.hasOwn(kidTiers, header.kid) || kidTiers[header.kid] !== tier)) return fail('wrong_tier');
      if (allowSubs !== null && !allowSubs.has(sub)) return fail('not_allowed');
      if (allow !== null && !allow.has(login.toLowerCase())) return fail('not_allowed');
      return { ok: true, claims: { sub, login, tier, exp, jti, kind } };
    },
  };
}
