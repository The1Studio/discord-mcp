# Studio auth for the discord-mcp HTTP transport (dormant)

A GitHub-token ("studio auth") login in front of the Streamable HTTP endpoint, **off by default and byte-identical to the
previous behaviour while off**. Code: `packages/mcp-server/src/transports/studio-auth.ts`, wired in
`packages/mcp-server/src/transports/http.ts`. The verifier is the vendored
`packages/mcp-server/src/transports/vendor/studio-auth-verify.mjs` (pinned, hash-checked). Design:
`plans/261005-zt-github-auth/central-auth-design.md` in `The1Studio/theonekit-core`.

This server is the origin behind `discord-mcp.the1studio.org` (tunnel to `localhost:3001`, container port 3000). The
sibling `mcp.the1studio.org` (knowledge-retrieval) shares the Cloudflare Access app `Mcp` with it and has its own gate
in `The1Studio/AIPoweredGameDevelopmentSystem` (PR #137). The two audiences are different on purpose.

## Why this exists

The only credential this transport checks itself is the optional shared `DISCORD_MCP_ACCESS_TOKEN`, and the production
deploy does not set it: the Cloudflare Access edge is the whole gate. The server exposes 209 Discord tools (bans, channel
and role deletes, message sends) and the production deploy runs with `MCP_DRY_RUN=false`, so a confirmed destructive call
executes. Removing the Access app without a replacement would leave that reachable by anyone who can reach the tunnel.
This gate is the replacement, and the cutover blocker it closes.

## What it is

Two flags, both **exactly the string `true`** (` true`, `True`, `1`, `yes` are off). Committed config sets neither.

| Flag | Meaning |
|---|---|
| `STUDIO_AUTH_ENABLED=true` | Studio gate on. A *claimed* bearer (below) is verified and its verdict is final. A request with no studio credential still falls through to the existing behaviour (Access remains the gate). This is the dual-mode window. |
| `STUDIO_AUTH_REQUIRED=true` | Only meaningful with ENABLED. A request with no studio credential is **refused**, except one that presents the correct `DISCORD_MCP_ACCESS_TOKEN` (an existing credential that is really checked). This is what makes removing Access safe. |

Other variables (read once at startup):

| Variable | Rule |
|---|---|
| `STUDIO_AUTH_ISSUER` | Required when enabled: the studio-auth Worker's `iss`. |
| `STUDIO_AUTH_JWKS_URL` | Required when enabled, **https only** (the verifier refuses http). |
| `STUDIO_AUTH_ALLOW_SUBS` | Comma-separated **numeric GitHub ids**. Empty or unset = **nobody**. Any malformed entry (a login, an email, `github:123`) makes startup fail. |
| `STUDIO_AUTH_STUDIO_KIDS` | Optional: pin signing key ids to the `studio` tier. |
| `STUDIO_AUTH_AUDIENCE` | Do not set. The audience is **pinned in code** to `discord-mcp` (`STUDIO_AUDIENCE`); setting any other value fails startup. |

A broken gate never serves: with the flag on, `startHttp` rejects (the process exits, the container restarts, the deploy's
readiness smoke goes red) on a missing issuer/JWKS URL, a malformed allowlist, a wrong audience or a non-https JWKS URL.
`STUDIO_AUTH_REQUIRED=true` without `STUDIO_AUTH_ENABLED=true`, or a REQUIRED value other than empty/`true`/`false` while
enabled, also fails at construction (a REQUIRED typo must never silently leave the surface open). No network call is made
at startup.

## What it covers

The router answers first: only `/mcp` and `/healthz` exist, everything else is the legacy `404` before any credential is
looked at (so a future route is added to that allowlist, and lands behind the gate automatically). Behind the router the
gate covers everything except one thing:

- `GET /healthz`, **kept open on purpose** in every mode. The deploy workflow's readiness smoke test and the container
  probe call it with no credential; it answers `{"status":"ok"}` and can call no tool. The exemption is the literal
  `GET /healthz`: `HEAD`/`POST`/`PUT`/`DELETE /healthz` are NOT exempt (`401 studio_credential_required` under REQUIRED), and
  `/HEALTHZ`, `/Healthz`, `/healthz/`, `/healthzx`, `/evil/healthz`, `/x/healthz`, `/%68ealthz`, `/healthz%2f` and `/healthz;x`
  are not that route at all (the router answers an empty `404` before any credential is read). Pinned by test, per widening
  axis, on the predicate `isStudioExemptRoute` (a request-level test cannot see a widened comparison, because the router
  404s those paths first).

  The credential-free surface is **exactly** the following, and nothing else. Two extra request targets reach it through URL
  normalisation, and both answer the same constant `200 {"status":"ok"}` with no credential:

  | Request target | Why it is `/healthz` |
  |---|---|
  | `GET /healthz` | the literal route |
  | `GET //evil/healthz` | a leading `//` makes `evil` the URL host; the parsed pathname is `/healthz` |
  | `GET /healthz?x=1` | the query string is not part of the pathname |

  The same two targets with any other method are refused `401`. The exemption skips only this gate: with
  `DISCORD_MCP_ACCESS_TOKEN` set, `/healthz` still demands it, as before.

A request whose target the URL parser rejects (`GET //`, `GET http://[bad/`) gets `400 {"error":"bad_request","code":"invalid_request_target"}`
with the gate on (see blocker 5).

## Identity and claim rule

- Identity is the **numeric GitHub `sub`**, kept as a string (never through `Number`). `login` is never read. Human surface
  only: tier `studio`, kind `user`. An `owners` assertion is `wrong_tier`, a machine (`oidc:`) assertion `wrong_kind`.
- The log line is `studio auth allow` with `principal=github:<id>` and the route class. The string is for the log only:
  authorization is the allowlist check on the numeric id inside the verifier, and a login or `sub` spelled `github:<id>`
  gets nothing (tested).
- `Authorization: Bearer` is the only channel (no query string, no cookie, no `X-API-Key`).
- **Claim rule:** a bearer is a studio credential only if it is a three-segment JWS whose decoded header has
  `alg === "ES256"`. Anything else (an opaque key, a non-ES256 JWT, a header that does not decode) is not claimed and, with
  REQUIRED off, the existing path runs unchanged. The check runs before the verifier's own length cap and never decodes an
  attacker-sized segment (cap 8192, mirrored from the vendored verifier and test-pinned on both sides). A claimed token's
  verdict is final: never rescued by an Access header, a cookie or the shared secret; a verifier failure never falls back
  to "let it through". Consequence: `DISCORD_MCP_ACCESS_TOKEN` must not itself be a three-segment ES256 JWS (a random
  string of 32+ characters is not).
- A verified studio bearer **replaces** the `DISCORD_MCP_ACCESS_TOKEN` check for that request; it is not required in
  addition to it.

## Refusals

A refusal is a complete JSON response written **before any MCP handling exists** (explicit `content-length`, never a
stream, `Connection: close`, request body never read). `/mcp` gets a JSON-RPC error envelope with `id: null`; other routes
get `{"error": "...", "code": "..."}`.

| Status | Codes | Notes |
|---|---|---|
| 401 | `bad_format` `bad_alg` `bad_sig` `wrong_iss` `wrong_aud` `expired` `not_yet_valid` `invalid_credential` `studio_credential_required` `studio_credential_not_accepted` | `WWW-Authenticate: Bearer realm="discord-mcp"`, plus `error="invalid_token"` when a studio credential was presented |
| 403 | `wrong_tier` `wrong_kind` `not_allowed` | authentic credential, not permitted here; no challenge |
| 503 | `jwks_unavailable` | `Retry-After: 30`; our outage, never a pass |
| 500 | `studio_auth_config_invalid` `studio_auth_not_configured` `studio_auth_error` | our misconfiguration or a verifier fault; fail closed |

Logs go through the server's pino logger: fixed messages, the issuer, the audience, a count, and the `github:<id>` of an
allowed request. Never a token, an assertion or a claim. A repeated config-class failure logs once.

## How a Claude Code session presents the credential

Core's `studio-auth-headers.cjs` is registered as the MCP `headersHelper` and prints
`{"Authorization":"Bearer <assertion>"}`, where the assertion comes from `POST /v1/exchange` on the studio-auth Worker.
The exchange takes no audience: the assertion carries the deployment's whole `AUDIENCE` list. This gate accepts exactly
that (`Authorization: Bearer` with an ES256 JWS whose `aud` contains `discord-mcp`). **The Worker's `AUDIENCE` setting must
therefore include `discord-mcp`** (and `knowledge-retrieval` for the sibling); an assertion without it is `wrong_aud`.
Registration is `claude mcp add-json -s user`, never local scope (a local-scope helper does not run until the workspace
trust dialog is accepted).

## What a merge deploys

`.github/workflows/deploy.yml` triggers on every push to `main`: it resets the deploy checkout on the sv-2 runner,
regenerates the gitignored `docker-compose.override.yml` from the org secret, runs `docker compose up -d --build` (the
repository `Dockerfile`, which copies all of `packages/mcp-server`, so the vendored file is built into `dist/`) and smoke
tests `GET /healthz` and one `POST /mcp` call.

The override is **regenerated on every deploy**, so a value edited on the box would be lost. The studio variables are
therefore passed through from non-secret repository **variables** (`vars.STUDIO_AUTH_*`) into that override. Unset
variables render as empty strings, which every flag treats as off, so **a merge changes no behaviour** (differential-proven,
and the rendered override is asserted in `studio-auth-config.test.ts`). Enabling is setting repository variables and
re-running the deploy, never a code change.

The override is written by `.github/scripts/render-compose-override.sh`, not by an inline heredoc, and **every studio value is
checked against its documented charset before anything is written**. A value outside it fails the deploy step with an
`::error::` that names the variable (never its value) and leaves the previous override untouched; empty or unset means
off. This is a security control: the file is YAML that `docker compose up` consumes as root, and a raw `${VAR}` inside a
quoted scalar let a value containing `"` and a newline add a service-level key such as `privileged: true`. Accepted
characters (ASCII only):

| Variable | Accepted |
|---|---|
| `STUDIO_AUTH_ENABLED`, `STUDIO_AUTH_REQUIRED` | exactly `true` or `false` (so `True`, `1`, `yes` fail the deploy loudly rather than silently meaning off) |
| `STUDIO_AUTH_ISSUER`, `STUDIO_AUTH_JWKS_URL` | letters, digits and `. _ ~ : / @ % + = & ? -`, at most 512 characters |
| `STUDIO_AUTH_ALLOW_SUBS` | digits, commas and spaces, at most 2048 characters |
| `STUDIO_AUTH_STUDIO_KIDS` | letters, digits and `. _ : - ,` and space, at most 512 characters |

A key id outside that set needs the script's pattern extended together with its test
(`compose-override-render.test.ts`). `DISCORD_TOKEN` (an org secret) and `HOST_PORT` (a literal in the workflow) are
interpolated as before: neither is an operator-editable variable.

## Tool surface: what is reachable, and who may reach it

Every one of the 209 tools sits behind the same gate and the same tier: `studio` users on the numeric-id allowlist.
That is the same blast radius Access gives today (any org member) **narrowed** to an explicit list, with empty meaning
nobody. Decision for this change:

- **No tool is held to a stricter tier here.** Mutating tools (message send/delete, channel and role changes, bans) are
  reachable by every allowlisted id. The server's own confirm flow is unchanged and is still the second control: a
  destructive call needs `__confirm: true` (Components V2 sends additionally need the one-time payload hash and approval
  id) because `MCP_DRY_RUN` guards them. **Production runs `MCP_DRY_RUN=false`** (deploy PR #1), so a confirmed call
  executes. Keep the allowlist to people trusted to operate the bot.
- **A per-tool tier cannot be enforced at this transport.** `mcp_pipeline` runs other tools by name from inside the
  request body, so an edge policy keyed on `tools/call` `params.name` is bypassable by wrapping the call in a pipeline
  (and `discord_intent_plan` plans calls the same way). A stricter tier (the `owners` assertion tier, or a second
  allowlist for destructive tools) has to be enforced in the tool middleware chain, with the principal threaded through
  to it. That is a follow-up, not part of this change; see blocker 7.
- `MCP_WRITE_MODE=preview` makes every mutating call a preview for the whole process. It is a server-wide switch, not a
  per-principal one, but it is the quickest way to run a read-only studio-auth canary.

## Cutover (operator checklist; do not start before the blockers below are closed)

1. **Agree the audience.** It is `discord-mcp`, fixed in code. Tell the studio-auth owner so the Worker's `AUDIENCE`
   includes it. Collect the numeric GitHub ids that may operate the bot (`gh api users/<login> --jq .id`). That list is the
   human decision (who may operate a Discord bot that can ban members); nothing in this repo makes it.
2. **ENABLED, dual mode, no outage.** Set repository variables `STUDIO_AUTH_ENABLED=true`, `STUDIO_AUTH_ISSUER`,
   `STUDIO_AUTH_JWKS_URL` and `STUDIO_AUTH_ALLOW_SUBS`; leave `STUDIO_AUTH_REQUIRED` unset. Re-run the `deploy` workflow.
   The container log must show `studio auth enabled` with `allowed=N required=false`.
3. **Loopback proof, on the box** (`http://127.0.0.1:3001`, a studio assertion minted by the Worker for you): a valid one
   is 200 on `/mcp`, one for another audience is 401 `wrong_aud`, a non-member is 403 `not_allowed`, an expired one 401
   `expired`, no credential is still 200 (Access remains the gate).
4. **`headersHelper` registration** on every client, user scope only: `claude mcp add-json -s user discord-mcp ...` with the
   helper from core. Core owns this (`install-discord-mcp.sh` and the **two** `discord-mcp` entries in `t1k-config-core.json`
   must flip together). Through the public hostname this can only be proven after step 6, because the Access app rejects a
   non-Access bearer at the edge (not verified by this change).
5. **REQUIRED.** Set `STUDIO_AUTH_REQUIRED=true`, re-run the deploy, and confirm no credential now answers 401
   `studio_credential_required` over loopback. Do this only after blockers 1 to 3 are closed, and only once step 4 is
   complete: clients still on Access OAuth are refused from this moment.
6. **Remove the Access app LAST.** The app `Mcp` also fronts `mcp.the1studio.org`; remove or bypass it only when both
   origins are on REQUIRED (this one and PR #137 for knowledge-retrieval), in one announced change window.
7. **Verify** a logged-in member passes, a non-member (403), a 2FA-off member (no assertion is minted) and an expired
   assertion (401) are refused, and the log shows `studio auth allow` lines.

**Rollback:** unset `STUDIO_AUTH_REQUIRED` and `STUDIO_AUTH_ENABLED` (repository variables), re-run the deploy, and
restore the Access app policy. No code change.

## Cutover blockers (found by this change, none closed by it)

1. **The deploy smoke test sends no credential.** The `Smoke test - the secret authenticates against Discord` step POSTs
   `tools/call users_get_current` to `/mcp` with no `Authorization`. With `STUDIO_AUTH_REQUIRED=true` every deploy's
   smoke step goes red after the restart (the readiness step on `GET /healthz` is unaffected). The only credential
   REQUIRED admits besides a studio assertion is the correct `DISCORD_MCP_ACCESS_TOKEN`, which needs a new repository
   secret, a line in the generated override and an `Authorization` header on that `curl`. A new secret is a human step, so it is
   not done here. `studio-auth-config.test.ts` pins this blocker both ways: if the smoke ever sends a credential, the test
   fails until this item is removed.
2. **The override is regenerated per deploy**, so the flags only reach the container through `deploy.yml`. This change
   adds the pass-through of `vars.STUDIO_AUTH_*` (default empty = off). Setting a repository variable is the live switch.
3. **Access rejects the assertion at the edge.** While the `Mcp` app fronts the hostname, a request carrying only a studio
   bearer never reaches this origin. End-to-end proof through `discord-mcp.the1studio.org` needs the app removed or set to
   bypass for this host, which is the last step. Until then the proof is loopback only (step 3).
4. **`Mcp` is shared with knowledge-retrieval.** Removing it needs both origins gated (PR #137 is open, dormant) and
   distinct audiences (`discord-mcp`, `knowledge-retrieval`), both in the Worker's `AUDIENCE`.
5. **Malformed request-target crash: closed with the gate on, deliberately left with it off.** `new URL(req.url, ...)`
   throws on `GET //` or `GET http://[bad/` inside the async handler, which has no catch; Node exits on the unhandled
   rejection. This predates the change (proved against the frozen pre-change handler: connection dropped, one unhandled
   rejection per request) and Cloudflare normally rejects such a request at the edge. With Access removed and the tunnel
   origin reachable it would be a one-request denial of service that precedes any credential check. With the gate **on**
   the parse is guarded (400, no echo, process keeps serving); with it **off** the legacy statement is kept exactly, and
   `http.differential.test.ts` asserts the legacy crash is still there so a guard leaking into the flag-off path turns it red.
   Since REQUIRED needs ENABLED, any process that has Access removed also has the guard.
6. **Who may operate the bot is undecided** (cutover step 1): `STUDIO_AUTH_ALLOW_SUBS` is a human decision, and
   `MCP_DRY_RUN=false` in production means the allowlist is the only thing between an id and an executed destructive call.
7. **No per-tool tier.** The audit record now names the principal (below), but nothing enforces a stricter tier yet. A
   destructive-tools allowlist or the `owners` tier has to sit in the tool middleware chain (the only place that sees
   `mcp_pipeline`'s inner calls), reading the same principal the audit middleware reads. That is a follow-up.

   **Audit attribution (closed here).** When the studio gate admits a request, `startHttp` runs the MCP handling inside
   `runWithPrincipal("github:<numeric id>")` (`@discord-mcp/core`, `als/principal.ts`), and the audit middleware copies
   that string into the `AuditEvent` as the optional `principal` field. It is present **only** for a studio-admitted
   request: stdio, the gate off, the shared secret and Access-fronted requests produce the record they always did, byte
   for byte (no `principal` key at all, pinned by test), and a refused request is never executed or audited. Inner calls of
   an `mcp_pipeline` request are audited by the same middleware and carry it too. The field is the numeric id only; no
   token, assertion or claim is stored (spy-tested with a positive control). The OTLP sink carries it in the log body (the
   full event); it is not added as a bounded attribute.

## Vendored verifier

`packages/mcp-server/src/transports/vendor/studio-auth-verify.mjs` is a byte copy of
`studio-auth/verify/studio-auth-verify.mjs` from `The1Studio/theonekit-model-router` at commit
`dd10188a44e8bee3f6c8c33ce3f6d425b375f4e9` (sha256 `b45ff7cd4ad9f57f0d343d43483524371d934859b7cd14386f20a48a952ba820`).
`studio-auth-vendor.test.ts` fails on a one-byte edit. To upgrade: re-pin, re-copy and update the recorded hash and the
test's expected values in one reviewed PR. `vendor/studio-auth-verify.d.mts` is ours (types) and outside the hash; biome
ignores the vendored file. The module is loaded lazily on the first request that needs it; with the flag off it is never
loaded.

## Tests

`pnpm test` picks up every `src/**/*.test.ts` of `@discord-mcp/cli` (CI runs it on every pull request; there is no path
filter): `studio-auth.test.ts` (glue and claim rule), `studio-auth-vendor.test.ts` (hash pin), `http.studio.test.ts` (the
gate wired into the real transport over loopback sockets), `http.differential.test.ts` (flag-off byte identity against the
frozen handler in `src/transports/legacy/`, shipped as test code only and never imported by production),
`studio-auth-config.test.ts` (committed config stays off, the deploy override render, these docs),
`compose-override-render.test.ts` (the real deploy step with hostile variable values), `http.studio.audit.test.ts` (the audit
record names the principal; Discord is an in-process fake) and
`studio-auth.entrypoint.test.ts` (the built `dist/cli.js serve --http` against a local https JWKS with throwaway keys).
