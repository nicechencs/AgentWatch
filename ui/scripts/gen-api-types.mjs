/**
 * Regenerates src/api/schema.d.ts from the daemon's OpenAPI document.
 * The hand-written src/api/types.ts stays the source the UI imports: the
 * daemon is developed in parallel and may not be serving yet. Run this once
 * it is, then diff schema.d.ts against types.ts.
 *
 *   node scripts/gen-api-types.mjs [url]
 *
 * openapi-typescript is an MIT dev tool; it is not a runtime dependency, so it
 * is not in package.json. Install it on demand: pnpm -C ui add -D openapi-typescript
 */
import { spawnSync } from "node:child_process";
import process from "node:process";

const url = process.argv[2] ?? "http://127.0.0.1:7456/api/v1/openapi.json";
const result = spawnSync(
  "pnpm",
  ["exec", "openapi-typescript", url, "-o", "src/api/schema.d.ts"],
  { stdio: "inherit", shell: true },
);
process.exit(result.status ?? 1);
