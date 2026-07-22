// SEILX Reference Evidence Packet — hardening test matrix.
//
// Runs:
//   * Cross-implementation JCS vectors (positive + must_reject).
//   * Value-level SEILX profile rules.
//   * Full packet build + tamper detection.
//   * Identity-binding rule (packet-local key = WARN, never PASS from URLs alone).
//   * TSA rule (no .tsr = WARN/SKIP).
//
// Output is a compact table plus a JSON summary with exact canonical bytes
// and SHA-256 for every vector so a reviewer can diff against Python.

import { readFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { canonicalJson } from "./canonicalize.ts";
import { parseSeilxJson, SeilxProfileError } from "./profile.ts";
import { sha256Hex } from "./hash.ts";
import { buildEvidencePacket } from "./build.ts";
import { verifyPacket, checkAnchorOrder } from "./verify.ts";

interface Row {
  test: string;
  expected: string;
  actual: string;
  status: "PASS" | "FAIL";
}

const here = dirname(fileURLToPath(import.meta.url));

export async function runTestMatrix(): Promise<{ rows: Row[]; vectorDetails: unknown[]; ok: boolean }> {
  const rows: Row[] = [];
  const vectorDetails: unknown[] = [];
  const record = (test: string, expected: string, actual: string, pass: boolean) => {
    rows.push({ test, expected, actual, status: pass ? "PASS" : "FAIL" });
  };

  // ---- 1. Cross-implementation JCS vectors ----
  const vectorsPath = join(here, "..", "tests", "vectors.json");
  const raw = await readFile(vectorsPath, "utf8");
  const vec = JSON.parse(raw) as {
    vectors: Array<{ name: string; input: unknown; canonical: string; sha256: string }>;
    must_reject: Array<{ name: string; text: string; expected_rule: string }>;
  };

  for (const v of vec.vectors) {
    let actualCanonical = "";
    let actualHash = "";
    let err: string | null = null;
    try {
      const bytes = canonicalJson(v.input);
      actualCanonical = bytes.toString("utf8");
      actualHash = sha256Hex(bytes);
    } catch (e) {
      err = (e as Error).message;
    }
    const bytesMatch = !err && actualCanonical === v.canonical;
    const hashMatch = !err && actualHash === v.sha256;
    vectorDetails.push({
      name: v.name,
      expected_canonical: v.canonical,
      actual_canonical: actualCanonical,
      expected_sha256: v.sha256,
      actual_sha256: actualHash,
      bytes_match: bytesMatch,
      hash_match: hashMatch,
      error: err,
    });
    record(
      `JCS vector: ${v.name} (bytes)`,
      v.canonical,
      err ?? actualCanonical,
      bytesMatch,
    );
    record(
      `JCS vector: ${v.name} (sha256)`,
      v.sha256,
      err ?? actualHash,
      hashMatch,
    );
  }

  for (const r of vec.must_reject) {
    let rule: string | null = null;
    let msg = "accepted (should have been rejected)";
    try {
      parseSeilxJson(r.text);
    } catch (e) {
      if (e instanceof SeilxProfileError) {
        rule = e.rule;
        msg = `${e.rule}: ${e.message}`;
      } else {
        rule = "unknown_error";
        msg = (e as Error).message;
      }
    }
    record(
      `must_reject: ${r.name}`,
      `rejected(${r.expected_rule})`,
      rule ? `rejected(${rule})` : msg,
      rule === r.expected_rule,
    );
  }

  // ---- 2. Full packet build + tamper detection ----
  const packetDir = await mkdtemp(join(tmpdir(), "seilx-test-"));
  await buildEvidencePacket({ outDir: packetDir });
  const clean = await verifyPacket(packetDir);
  const cleanCrypto = clean.checks.every((c) => c.ok || c.warn);
  record(
    "Untampered packet: integrity + signature pass",
    "all crypto checks pass",
    cleanCrypto ? "all crypto checks pass" : "FAIL: " + clean.checks.filter((c) => !c.ok).map((c) => c.name).join(", "),
    cleanCrypto,
  );

  // Tamper evidence.json
  {
    const evPath = join(packetDir, "evidence.json");
    const orig = await readFile(evPath);
    const tampered = Buffer.concat([orig.subarray(0, orig.length - 1), Buffer.from("X}")]);
    await writeFile(evPath, tampered);
    const r = await verifyPacket(packetDir);
    const namedFail = r.checks.some(
      (c) => !c.ok && c.file === "evidence.json",
    );
    record(
      "Tampered evidence.json: verification fails and names the file",
      "FAIL naming evidence.json",
      namedFail ? "FAIL naming evidence.json" : "did not name evidence.json",
      namedFail,
    );
    await writeFile(evPath, orig); // restore
  }

  // Tamper association.json — a SEMANTIC edit (change a value), not
  // whitespace. Whitespace is stripped by canonicalization and would leave
  // the signature valid (which is correct behaviour: the signature covers
  // canonical bytes, not raw bytes). A byte flip inside a value forces
  // both the raw hash and the recomputed signature check to disagree.
  {
    const asPath = join(packetDir, "association.json");
    const orig = await readFile(asPath);
    // Flip one hex digit inside the first artifact hash.
    const text = orig.toString("utf8");
    const marker = "sha256:";
    const at = text.indexOf(marker);
    const flipAt = at + marker.length; // first hex digit of the hash
    const orig0 = text[flipAt];
    const flipped = orig0 === "0" ? "1" : "0";
    const tamperedText = text.slice(0, flipAt) + flipped + text.slice(flipAt + 1);
    const tampered = Buffer.from(tamperedText, "utf8");
    await writeFile(asPath, tampered);
    const r = await verifyPacket(packetDir);
    const hashFail = r.checks.some((c) => !c.ok && c.file === "association.json");
    const sigFail = r.checks.some((c) => !c.ok && c.name === "signature");
    record(
      "Tampered association.json: hash AND signature both fail",
      "hash+signature both fail",
      `hash=${hashFail ? "fail" : "pass"} sig=${sigFail ? "fail" : "pass"}`,
      hashFail && sigFail,
    );
    await writeFile(asPath, orig);
  }

  // ---- 3. Identity binding rule ----
  {
    const r = await verifyPacket(packetDir);
    const identity = r.checks.find((c) => c.name === "identity");
    const isWarn = !!identity && identity.ok && !!identity.warn;
    record(
      "Packet-local identity: WARN (never PASS from URLs alone)",
      "WARN",
      identity ? (identity.ok ? (identity.warn ? "WARN" : "PASS") : "FAIL") : "missing",
      isWarn,
    );
  }

  // ---- 4. TSA rule when no .tsr present ----
  {
    const r = await verifyPacket(packetDir);
    const tsa = r.checks.find((c) => c.name === "timestamps");
    const isWarn = !!tsa && tsa.ok && !!tsa.warn;
    record(
      "No RFC 3161 tokens present: WARN/SKIP (not PASS)",
      "WARN",
      tsa ? (tsa.ok ? (tsa.warn ? "WARN" : "PASS") : "FAIL") : "missing",
      isWarn,
    );
  }

  // ---- 5. Anchor-order regression tests (pure function) ----
  {
    const base = Date.parse("2026-01-15T13:47:50Z");
    // Case A: association strictly later than both sources -> PASS
    {
      const r = checkAnchorOrder(new Date(base + 3000), {
        "evidence.tsr": new Date(base),
        "neomundi.tsr": new Date(base + 1000),
      });
      record(
        "Anchor order: association strictly later than both sources -> PASS",
        "PASS",
        r.status,
        r.status === "PASS",
      );
    }
    // Case B: same-second timestamps -> WARN
    {
      const r = checkAnchorOrder(new Date(base), {
        "evidence.tsr": new Date(base),
        "neomundi.tsr": new Date(base),
      });
      record(
        "Anchor order: same-second association+source -> WARN",
        "WARN",
        r.status,
        r.status === "WARN",
      );
    }
    // Case C: association earlier than a source -> FAIL
    {
      const r = checkAnchorOrder(new Date(base), {
        "evidence.tsr": new Date(base - 1000),
        "neomundi.tsr": new Date(base + 1000),
      });
      record(
        "Anchor order: association earlier than a source -> FAIL",
        "FAIL",
        r.status,
        r.status === "FAIL",
      );
    }
    // Case D: mixed strictly-earlier + tie -> WARN (tie dominates over PASS,
    // FAIL still wins if present).
    {
      const r = checkAnchorOrder(new Date(base + 1000), {
        "evidence.tsr": new Date(base),
        "neomundi.tsr": new Date(base + 1000),
      });
      record(
        "Anchor order: one strictly earlier + one tie -> WARN",
        "WARN",
        r.status,
        r.status === "WARN",
      );
    }
  }

  const ok = rows.every((r) => r.status === "PASS");
  return { rows, vectorDetails, ok };
}

export function formatMatrix(rows: Row[]): string {
  const headers = ["Test", "Expected", "Actual", "Status"];
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => truncate([r.test, r.expected, r.actual, r.status][i], 60).length)));
  const line = (cells: string[]) =>
    cells.map((c, i) => truncate(c, 60).padEnd(widths[i])).join("  ");
  const sep = widths.map((w) => "-".repeat(w)).join("  ");
  const out: string[] = [];
  out.push(line(headers));
  out.push(sep);
  for (const r of rows) {
    out.push(line([r.test, r.expected, r.actual, r.status]));
  }
  return out.join("\n");
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}