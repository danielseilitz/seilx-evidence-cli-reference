// RFC 3161 timestamp handling: we shell out to `openssl ts` for every
// security-relevant operation. We never parse or generate ASN.1 by hand.
//
// Flow:
//   1. `tsq(dataPath)` -> creates `<dataPath>.tsq` via `openssl ts -query`
//   2. Operator submits the .tsq to a real TSA (e.g. freetsa.org) and
//      places the returned .tsr next to the artifact.
//   3. `verifyTsr(dataPath, tsrPath, caFile)` -> `openssl ts -verify`
//   4. `readGenTime(tsrPath)` -> parses `openssl ts -reply -text` output
//      to extract genTime for construction-order checks.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";

function run(cmd: string, args: string[]): { code: number; stdout: string; stderr: string } {
  const r = spawnSync(cmd, args, { encoding: "utf8" });
  return { code: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

export function haveOpenssl(): boolean {
  return run("openssl", ["version"]).code === 0;
}

export function createTimestampQuery(dataPath: string, outPath: string): void {
  // A fresh .tsq every call: `openssl ts -query` generates a new random
  // nonce for each invocation, and the nonce binds the request to the
  // response. NEVER reuse an old .tsq — a valid .tsr for a prior nonce is
  // not a valid .tsr for this artifact-and-moment.
  const r = run("openssl", [
    "ts",
    "-query",
    "-data",
    dataPath,
    "-sha256",
    "-cert", // ask the TSA to include its signing certificate in the response
    "-out",
    outPath,
  ]);
  if (r.code !== 0) throw new Error(`openssl ts -query failed: ${r.stderr}`);
}

export interface VerifyResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  command: string;
}

export function verifyTimestamp(
  dataPath: string,
  tsrPath: string,
  caFile: string,
  untrustedCert?: string,
): VerifyResult {
  if (!existsSync(caFile)) {
    return { ok: false, stdout: "", stderr: `TSA CA file not found: ${caFile}`, command: "" };
  }
  const args = ["ts", "-verify", "-data", dataPath, "-in", tsrPath, "-CAfile", caFile];
  if (untrustedCert && existsSync(untrustedCert)) {
    args.push("-untrusted", untrustedCert);
  }
  const r = run("openssl", args);
  return {
    ok: r.code === 0 && /Verification: OK/i.test(r.stdout + r.stderr),
    stdout: r.stdout.trim(),
    stderr: r.stderr.trim(),
    command: `openssl ${args.join(" ")}`,
  };
}

export function readTimestampGenTime(tsrPath: string): Date | null {
  const r = run("openssl", ["ts", "-reply", "-in", tsrPath, "-text"]);
  if (r.code !== 0) return null;
  const m = r.stdout.match(/Time stamp:\s*(.+)$/m);
  if (!m) return null;
  const parsed = new Date(m[1]);
  return isNaN(parsed.getTime()) ? null : parsed;
}

export function sha256HexOfFile(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}