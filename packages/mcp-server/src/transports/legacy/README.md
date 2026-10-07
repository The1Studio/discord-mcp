# legacy/

`http.legacy.ts` is the pre-studio-auth `http.ts`, frozen byte for byte except for two import specifiers
(`../lib/activity.js` -> `../../lib/activity.js`, `../otel.js` -> `../../otel.js`) because it sits one directory
deeper. It is a TEST ORACLE: `http.differential.test.ts` runs the same requests against it and against the real
`http.ts` with the studio flag off and asserts identical responses. Nothing in production imports it, and the
build entry (`src/cli.ts`) never reaches it.

Do not edit it. The differential spec pins its sha256 and the sha256 of the original blob it was derived from
(git blob `f20f0ed...` at `bf1bb51`), so an edit fails the suite.
