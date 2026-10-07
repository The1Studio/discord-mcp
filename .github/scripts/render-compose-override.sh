#!/usr/bin/env bash
# Render the gitignored docker-compose.override.yml that the deploy workflow hands to `docker compose up`
# (run as root on the deploy host). Usage: render-compose-override.sh <output-file>
#
# Inputs (environment): DISCORD_TOKEN (required), HOST_PORT (required), and the six NON-secret repository
# variables STUDIO_AUTH_{ENABLED,REQUIRED,ISSUER,JWKS_URL,ALLOW_SUBS,STUDIO_KIDS} (unset or empty = the
# gate is off, and the file renders exactly as it did before they existed).
#
# Why this is a script and not an inline heredoc: the studio values are operator-editable repository variables,
# and the file is YAML consumed as root. Expanding a raw `${VAR}` into a quoted scalar let a value containing
# `"` plus a newline close the scalar and add a SERVICE-level key (`privileged: true` parses as true).
# So every studio value is checked against the charset the gate itself documents BEFORE anything is written:
# a value outside it fails the deploy with a clear `::error::` and writes nothing. Charsets exclude `"`, `\`,
# `$`, backtick, `#`, newline and every non-ASCII byte, so a validated value is inert inside a double-quoted
# YAML scalar and inside this heredoc. The error text names the variable, never its value (a value can itself
# be a workflow command).
#
# DISCORD_TOKEN and HOST_PORT are interpolated as they always were: the first is an org secret and the second a
# literal set by the workflow, neither is an operator-editable variable.
set -euo pipefail
# Byte semantics for the regex classes and the length checks, whatever locale the runner has.
export LC_ALL=C

out="${1:?usage: render-compose-override.sh <output-file>}"

fail() {
  echo "::error::$1"
  exit 1
}

# check <NAME> <value> <ERE> <max-length> <what the value must be>; empty is always accepted (= off).
check() {
  local name="$1" value="$2" pattern="$3" max="$4" what="$5"
  [ -z "$value" ] && return 0
  [ "${#value}" -le "$max" ] || fail "$name is longer than $max characters"
  case "$value" in
    *$'\n'* | *$'\r'*) fail "$name must be $what (it contains a line break)" ;;
  esac
  [[ $value =~ $pattern ]] || fail "$name must be $what"
}

STUDIO_AUTH_ENABLED="${STUDIO_AUTH_ENABLED:-}"
STUDIO_AUTH_REQUIRED="${STUDIO_AUTH_REQUIRED:-}"
STUDIO_AUTH_ISSUER="${STUDIO_AUTH_ISSUER:-}"
STUDIO_AUTH_JWKS_URL="${STUDIO_AUTH_JWKS_URL:-}"
STUDIO_AUTH_ALLOW_SUBS="${STUDIO_AUTH_ALLOW_SUBS:-}"
STUDIO_AUTH_STUDIO_KIDS="${STUDIO_AUTH_STUDIO_KIDS:-}"

url_chars='^[A-Za-z0-9._~:/@%+=&?-]+$'
check STUDIO_AUTH_ENABLED "$STUDIO_AUTH_ENABLED" '^(true|false)$' 5 'exactly "true" or "false" (or unset)'
check STUDIO_AUTH_REQUIRED "$STUDIO_AUTH_REQUIRED" '^(true|false)$' 5 'exactly "true" or "false" (or unset)'
check STUDIO_AUTH_ISSUER "$STUDIO_AUTH_ISSUER" "$url_chars" 512 'a URL of letters, digits and . _ ~ : / @ % + = & ? -'
check STUDIO_AUTH_JWKS_URL "$STUDIO_AUTH_JWKS_URL" "$url_chars" 512 'a URL of letters, digits and . _ ~ : / @ % + = & ? -'
check STUDIO_AUTH_ALLOW_SUBS "$STUDIO_AUTH_ALLOW_SUBS" '^[0-9, ]+$' 2048 'comma-separated numeric GitHub ids (digits, commas and spaces only)'
check STUDIO_AUTH_STUDIO_KIDS "$STUDIO_AUTH_STUDIO_KIDS" '^[A-Za-z0-9._:, -]+$' 512 'comma-separated key ids (letters, digits and . _ : - , space only)'

cat > "$out" <<EOF
services:
  discord-mcp:
    environment:
      DISCORD_TOKEN: "$DISCORD_TOKEN"
      # Destructive tools and Components V2 sends execute only when a call ALSO
      # passes __confirm:true (V2: plus the one-time payload hash + approval id).
      # With the default (true) every such call returns DRY_RUN_PREVIEW, so V2
      # cards could never be sent from this deployment.
      MCP_DRY_RUN: "false"
      STUDIO_AUTH_ENABLED: "$STUDIO_AUTH_ENABLED"
      STUDIO_AUTH_REQUIRED: "$STUDIO_AUTH_REQUIRED"
      STUDIO_AUTH_ISSUER: "$STUDIO_AUTH_ISSUER"
      STUDIO_AUTH_JWKS_URL: "$STUDIO_AUTH_JWKS_URL"
      STUDIO_AUTH_ALLOW_SUBS: "$STUDIO_AUTH_ALLOW_SUBS"
      STUDIO_AUTH_STUDIO_KIDS: "$STUDIO_AUTH_STUDIO_KIDS"
    ports:
      - "${HOST_PORT}:3000"
EOF
