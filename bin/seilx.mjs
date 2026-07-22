#!/usr/bin/env node
// Thin launcher so the CLI can be invoked as `./bin/seilx.mjs <cmd>` from a
// checkout without a build step. Requires Node >= 22.6 for --experimental-strip-types.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const entry = join(here, "..", "src", "cli.ts");
const r = spawnSync(process.execPath, ["--experimental-strip-types", entry, ...process.argv.slice(2)], {
  stdio: "inherit",
});
process.exit(r.status ?? 1);