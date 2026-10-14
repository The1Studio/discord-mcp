#!/usr/bin/env bash
# Prove DISCORD_TOKEN authenticates as a bot user directly against Discord (run by the deploy smoke step when
# STUDIO_AUTH_REQUIRED=true, where the loopback /mcp route is closed to a credential-less runner).
# Usage: verify-discord-bot-identity.sh <discord-api-base>
#
# Input (environment): DISCORD_TOKEN (with or without a leading "Bot ").
#
# The API base is a POSITIONAL argument, never an environment variable: the workflow passes the literal
# https://discord.com/api/v10, so nothing set in the runner's environment can redirect the bot token to another
# host. The token goes to curl on stdin as a `-K -` config file, never on a command line, so it is validated
# against the characters that could break out of the quoted config value BEFORE the config is built: a token
# holding a double quote plus a newline would otherwise add arbitrary curl config lines (another `url`, a
# `output` path, `header` lines). The error names the rule, never the token.
set -euo pipefail
# Byte semantics for the control-character class, whatever locale the runner has.
export LC_ALL=C

base="${1:?usage: verify-discord-bot-identity.sh <discord-api-base>}"

fail() {
  echo "::error::$1"
  exit 1
}

token="${DISCORD_TOKEN:-}"
token="${token#Bot }"
[ -n "$token" ] || fail "DISCORD_TOKEN is empty"
# Not-allowed set: " and \ (they end or escape the quoted curl config value), CR/LF and every other control char.
if [[ $token == *'"'* || $token == *\\* || $token =~ [[:cntrl:]] ]]; then
  fail "DISCORD_TOKEN contains a double quote, backslash or control character, which a bot token never holds; refusing to build the curl config"
fi
if ! command -v node >/dev/null 2>&1; then
  fail "node is required on the runner to verify the bot identity under STUDIO_AUTH_REQUIRED"
fi

out="$(mktemp)"
trap 'rm -f "$out"' EXIT
printf 'header = "Authorization: Bot %s"\n' "$token" \
  | curl -fsS -K - "${base}/users/@me" -o "$out"
# Parse the response: a substring match would accept any body that merely mentions the marker.
# No expected bot id is configured, so the check is "a bot user with a non-empty string id".
node -e '
  const fail = (why) => {
    console.error("::error::Discord did not identify the token as a bot user: " + why);
    process.exit(1);
  };
  let u;
  try {
    u = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
  } catch {
    fail("the /users/@me response is not JSON");
  }
  if (u === null || typeof u !== "object") fail("the /users/@me response is not an object");
  if (u.bot !== true) fail("bot is not true");
  if (typeof u.id !== "string" || u.id === "") fail("id is missing or empty");
' "$out"
echo " ✓ bot identity confirmed directly against Discord"
