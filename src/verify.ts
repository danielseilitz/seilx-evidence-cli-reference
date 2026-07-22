import { readFile, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "./canonicalize.ts";
import { sha256Hex } from "./hash.ts";
import { loadPublicKey, verifyBytes } from "./sign.ts";
import { haveOpenssl, readTimestampGenTime, verifyTimestamp } from "./tsr.ts";

export interface VerifyReport {
  ok: boolean;
  checks: Array<{ name: string; ok: boolean; warn?: boolean; detail: string; file?: string }>;
}

export type OrderStatus = "PASS" | "WARN" | "FAIL";

/**
 * Pure construction-order check. Given the association anchor time and a
 * map of source-artifact anchor times, return PASS only when association
 * is strictly later than every source, WARN on any tie (order not
 * demonstrable at TSA granularity), FAIL if any source is later than
 * association.
 */
export function checkAnchorOrder(
  associationTime: Date,
  sourceTimes: Record<string, Date>,
): { status: OrderStatus; detail: string } {
  const at = associationTime.getTime();
  let status: OrderStatus = "PASS";
  let detail = "association strictly later than every source anchor.";
  for (const [name, t] of Object.entries(sourceTimes)) {
    const dt = t.getTime();
    if (dt > at) {
      return {
        status: "FAIL",
        detail: `${name} genTime (${t.toISOString()}) is AFTER association genTime (${associationTime.toISOString()}).`,
      };
    }
    if (dt === at && status !== "FAIL") {
      status = "WARN";
      detail = `anchor order not demonstrable at TSA time granularity: ${name} and association share the same asserted second (${associationTime.toISOString()}).`;
    }
  }
  return { status, detail };
}

export interface VerifyOptions {
  externalKeyPath?: string;
  /**
   * Fetch the external key over HTTPS. The tool downloads the PEM, records the
   * URL and byte-length in the report, and treats it exactly like an
   * `externalKeyPath` for fingerprint comparison. Convenience only — the
   * evidence value comes from the fingerprint match, not from the URL.
   */
  externalKeyUrl?: string;
  /**
   * A SHA-256 fingerprint (hex, of the trimmed PEM) supplied out-of-band
   * (release notes, DNS TXT, signed announcement). If set, the packet's
   * public key must match this value; if `externalKeyPath` / `externalKeyUrl`
   * is also set, the downloaded key must ALSO match. Any mismatch → FAIL.
   */
  externalFingerprint?: string;
}

export async function verifyPacket(dir: string, opts: VerifyOptions = {}): Promise<VerifyReport> {
  const checks: VerifyReport["checks"] = [];
  const fail = (name: string, detail: string, file?: string) =>
    checks.push({ name, ok: false, detail, file });
  const pass = (name: string, detail: string, file?: string) =>
    checks.push({ name, ok: true, detail, file });
  const warn = (name: string, detail: string, file?: string) =>
    checks.push({ name, ok: true, warn: true, detail, file });

  // 1. hashes.sha256
  try {
    const raw = await readFile(join(dir, "hashes.sha256"), "utf8");
    for (const line of raw.split(/\r?\n/).filter((l) => l.trim())) {
      const m = line.match(/^([a-f0-9]{64})\s{2}(.+)$/);
      if (!m) {
        fail("hashes.sha256:format", `Malformed line: ${line}`);
        continue;
      }
      const [, expected, file] = m;
      const p = join(dir, file);
      if (!existsSync(p)) {
        fail("hashes.sha256:missing", `File referenced by hashes.sha256 is missing`, file);
        continue;
      }
      const actual = sha256Hex(await readFile(p));
      if (actual !== expected) {
        fail(
          "hashes.sha256:mismatch",
          `SHA-256 mismatch for ${file}. Expected ${expected}, got ${actual}. This file has been modified.`,
          file,
        );
      } else {
        pass("hashes.sha256", `OK ${file}`, file);
      }
    }
  } catch (e) {
    fail("hashes.sha256:load", `Could not read hashes.sha256: ${(e as Error).message}`);
  }

  // 2. Association references artifacts by their canonical SHA-256.
  let associationBytes: Buffer | null = null;
  try {
    associationBytes = await readFile(join(dir, "association.json"));
    const association = JSON.parse(associationBytes.toString("utf8"));
    if (association.canonicalization !== "RFC8785") {
      fail(
        "association:canonicalization",
        `association.canonicalization is ${association.canonicalization}, expected RFC8785`,
        "association.json",
      );
    }
    for (const ref of association.artifacts ?? []) {
      const refFile = ref.file as string;
      const expectedHash = String(ref.hash).replace(/^sha256:/, "");
      const p = join(dir, refFile);
      if (!existsSync(p)) {
        fail("association:missing", `Association references missing file`, refFile);
        continue;
      }
      // The referenced artifact is itself canonical JSON — re-canonicalise and hash.
      const parsed = JSON.parse(await readFile(p, "utf8"));
      const canonBytes = canonicalJson(parsed);
      const actual = sha256Hex(canonBytes);
      if (actual !== expectedHash) {
        fail(
          "association:hash",
          `Association hash mismatch for ${refFile}. Expected ${expectedHash}, got ${actual}. Artifact modified or not RFC 8785 canonical.`,
          refFile,
        );
      } else {
        pass("association:hash", `OK ${refFile} matches association hash`, refFile);
      }
    }
  } catch (e) {
    fail("association:load", `Could not read association.json: ${(e as Error).message}`, "association.json");
  }

  // 3. Signature over canonical(association.json).
  try {
    if (!associationBytes) throw new Error("association.json unavailable");
    // Signature is over the RFC 8785 canonical bytes of association.json.
    // Re-parse + re-canonicalise so a re-serialisation cannot slip past.
    const canon = canonicalJson(JSON.parse(associationBytes.toString("utf8")));
    const sig = await readFile(join(dir, "signature.sig"));
    const pub = await loadPublicKey(join(dir, "public_key.pem"));
    const ok = verifyBytes(pub, canon, sig);
    if (ok) {
      pass("signature", "Ed25519 signature over canonical association.json is valid.", "signature.sig");
    } else {
      fail(
        "signature",
        "Ed25519 signature over canonical association.json is INVALID. Association or signature has been modified.",
        "signature.sig",
      );
    }
  } catch (e) {
    fail("signature", `Could not verify signature: ${(e as Error).message}`, "signature.sig");
  }

  // 3b. Identity binding — is the public key tied to a published identity,
  // or was it generated ad-hoc for this packet? A signature by a packet-local
  // key proves only "whoever built this packet built this packet"; it does
  // NOT prove authorship by SEILX unless the key can be recognised
  // independently of the packet.
  try {
    const infoRaw = await readFile(join(dir, "signing_info.json"), "utf8");
    const info = JSON.parse(infoRaw);
    const binding = info.identity_binding;
    const packetPubPem = await readFile(join(dir, "public_key.pem"), "utf8");
    const packetFp = sha256Hex(packetPubPem.trim());

    // Load an external key from either a file or an HTTPS URL (or both — they
    // must agree). Downloaded content is compared to the packet key in the
    // same way as a locally-supplied file: the security value is the
    // fingerprint match, not the transport.
    let externalPem: string | null = null;
    let externalSource = "";
    if (opts.externalKeyPath) {
      externalPem = (await readFile(opts.externalKeyPath, "utf8")).trim();
      externalSource = opts.externalKeyPath;
    }
    if (opts.externalKeyUrl) {
      if (!/^https:\/\//i.test(opts.externalKeyUrl)) {
        fail(
          "identity",
          `--external-key-url must be https:// (got ${opts.externalKeyUrl}).`,
          "signing_info.json",
        );
      } else {
        try {
          const resp = await fetch(opts.externalKeyUrl);
          if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
          const fetched = (await resp.text()).trim();
          if (externalPem && externalPem !== fetched) {
            fail(
              "identity",
              `--external-key file and --external-key-url returned DIFFERENT public keys. Reject.`,
              "signing_info.json",
            );
            externalPem = null;
          } else {
            externalPem = fetched;
            externalSource = externalSource
              ? `${externalSource} + ${opts.externalKeyUrl}`
              : opts.externalKeyUrl;
          }
        } catch (e) {
          fail(
            "identity",
            `Failed to download --external-key-url ${opts.externalKeyUrl}: ${(e as Error).message}`,
            "signing_info.json",
          );
        }
      }
    }

    // Optional out-of-band fingerprint. Must match the packet key AND (if
    // supplied) the external key.
    if (opts.externalFingerprint) {
      const expected = opts.externalFingerprint.toLowerCase().replace(/^sha256:/, "");
      if (expected !== packetFp) {
        fail(
          "identity",
          `Out-of-band fingerprint (${expected}) does NOT match packet public_key.pem fingerprint (${packetFp}). Reject.`,
          "signing_info.json",
        );
      } else if (externalPem && sha256Hex(externalPem) !== expected) {
        fail(
          "identity",
          `Out-of-band fingerprint (${expected}) does NOT match externally supplied key (sha256=${sha256Hex(externalPem)}).`,
          "signing_info.json",
        );
      } else if (!externalPem) {
        pass(
          "identity",
          `Packet public_key.pem fingerprint matches out-of-band SHA-256 (${expected}). Identity independently verified by fingerprint.`,
          "signing_info.json",
        );
      }
    }

    if (externalPem) {
      // Independent retrieval was performed by the operator. Compare fingerprints.
      const externalFp = sha256Hex(externalPem);
      if (externalFp === packetFp) {
        pass(
          "identity",
          `External public key (${externalSource}) fingerprint matches packet public_key.pem (sha256=${packetFp}). Identity independently verified.`,
          "signing_info.json",
        );
      } else {
        fail(
          "identity",
          `External public key fingerprint (${externalFp}) does NOT match packet fingerprint (${packetFp}). Signing key is not the claimed identity.`,
          "signing_info.json",
        );
      }
    } else if (opts.externalFingerprint) {
      // Already handled above.
    } else if (binding === "published") {
      const id = info.identity ?? {};
      const sources = Array.isArray(id.source_urls) ? id.source_urls.join(", ") : "(none listed)";
      warn(
        "identity",
        `Signing key claims to be published as "${id.key_id ?? "?"}" by "${id.publisher ?? "?"}", but this verifier did not perform independent retrieval. An identity.json full of URLs is metadata, not verification — it cannot upgrade identity to PASS on its own. Fetch the key from: ${sources} and re-run with --external-key <path> to compare fingerprints (packet fingerprint sha256=${packetFp}).`,
        "signing_info.json",
      );
    } else if (binding === "ephemeral-packet-local" || !binding) {
      warn(
        "identity",
        `Signing key is packet-local (ephemeral). The signature proves internal consistency of this packet only — it is NOT bound to a published SEILX identity. Publish the key at a stable location and re-run with --external-key <path>. Packet fingerprint sha256=${packetFp}.`,
        "signing_info.json",
      );
    } else {
      warn("identity", `Unknown identity_binding value: ${binding}`, "signing_info.json");
    }
  } catch (e) {
    warn("identity", `Could not read signing_info.json: ${(e as Error).message}`, "signing_info.json");
  }

  // 4. RFC 3161 timestamps (optional).
  const tsDir = join(dir, "timestamps");
  if (existsSync(tsDir)) {
    const files = (await readdir(tsDir)).filter((f) => f.endsWith(".tsr"));
    const caFile = join(tsDir, "tsa_ca.pem");
    if (files.length === 0) {
      warn(
        "timestamps",
        "No .tsr responses present. Temporal anchoring is UNVERIFIED — the packet has no cryptographic proof it existed at any specific moment. Obtain RFC 3161 tokens from a trusted TSA and re-run.",
      );
    } else if (!haveOpenssl()) {
      fail("timestamps:openssl", "openssl not found on PATH — cannot verify RFC 3161 timestamps.");
    } else {
      const genTimes: Record<string, Date> = {};
      const untrusted = join(tsDir, "tsa.crt");
      for (const tsr of files) {
        const dataFile = tsr.replace(/\.tsr$/, tsr.startsWith("neomundi") ? "_artifact.json" : ".json");
        const explicit = join(tsDir, tsr + ".for");
        const dataPath = existsSync(explicit)
          ? join(dir, (await readFile(explicit, "utf8")).trim())
          : join(dir, dataFile);
        if (!existsSync(dataPath)) {
          fail("timestamps:target", `Cannot find file to timestamp for ${tsr} (looked for ${dataFile})`, tsr);
          continue;
        }
        const v = verifyTimestamp(dataPath, join(tsDir, tsr), caFile, untrusted);
        if (v.ok) {
          pass("timestamps:verify", `openssl ts -verify OK for ${tsr}`, tsr);
        } else {
          fail(
            "timestamps:verify",
            `RFC 3161 verify failed for ${tsr}.\ncommand: ${v.command}\nstdout: ${v.stdout}\nstderr: ${v.stderr}`,
            tsr,
          );
        }
        const gt = readTimestampGenTime(join(tsDir, tsr));
        if (gt) genTimes[tsr] = gt;
      }

      // Construction order: association.tsr genTime MUST be strictly later
      // than every source .tsr. RFC 3161 proves existence-no-later-than the
      // asserted time; ordering is only proven when the TSA's time
      // resolution (1 second for freetsa.org) actually distinguishes the
      // events. Equal seconds => WARN (order not demonstrable), not PASS.
      const assocTs = Object.entries(genTimes).find(([n]) => n.startsWith("association"));
      if (assocTs) {
        for (const [name, t] of Object.entries(genTimes)) {
          if (name === assocTs[0]) continue;
          const dt = t.getTime();
          const at = assocTs[1].getTime();
          if (dt > at) {
            fail(
              "timestamps:order",
              `Construction-order violation: ${name} genTime (${t.toISOString()}) is AFTER association.tsr genTime (${assocTs[1].toISOString()}). Association claims to cover artifacts that did not yet exist.`,
              name,
            );
          } else if (dt === at) {
            warn(
              "timestamps:order",
              `Anchor order not demonstrable at TSA time granularity: ${name} and association.tsr share the same asserted second (${t.toISOString()}). RFC 3161 proves existence-no-later-than the asserted time; equal seconds do not prove which came first. Re-anchor association after a delay greater than the TSA's time resolution.`,
              name,
            );
          } else {
            pass(
              "timestamps:order",
              `${name} genTime strictly before association.tsr genTime (${t.toISOString()} < ${assocTs[1].toISOString()}).`,
              name,
            );
          }
        }
      } else if (files.length > 0) {
        fail("timestamps:order", "No association.tsr present — cannot check construction order.");
      }
    }
  }
  else {
    warn(
      "timestamps",
      "No timestamps/ directory. Temporal anchoring is UNVERIFIED.",
    );
  }

  return { ok: checks.every((c) => c.ok), checks };
}

export function formatReport(r: VerifyReport): string {
  const lines: string[] = [];
  for (const c of r.checks) {
    const tag = !c.ok ? "FAIL" : c.warn ? "WARN" : "PASS";
    lines.push(`${tag}  ${c.name}${c.file ? `  [${c.file}]` : ""}: ${c.detail}`);
  }
  const warns = r.checks.filter((c) => c.ok && c.warn);
  lines.push("");
  if (!r.ok) {
    lines.push("VERIFICATION FAILED — see FAIL lines above.");
  } else if (warns.length > 0) {
    lines.push(
      `VERIFIED with ${warns.length} warning(s) — cryptographic checks passed, but see WARN lines above. Do not read the result as proof of authorship until every warning is resolved.`,
    );
  } else {
    lines.push("VERIFIED — all checks passed.");
  }
  return lines.join("\n");
}

/**
 * Machine-readable verification report. Stable shape intended for CI,
 * downstream tooling and audit logs. Human-facing formatter output is
 * NOT a supported interface — parse this instead.
 */
export interface VerifyReportJson {
  schema_version: "seilx-verify-report/0.1";
  tool: { name: "seilx"; version: string };
  verified_at: string;
  packet_dir: string;
  ok: boolean;
  summary: {
    pass: number;
    warn: number;
    fail: number;
    status: "PASS" | "WARN" | "FAIL";
  };
  checks: Array<{
    name: string;
    status: "PASS" | "WARN" | "FAIL";
    detail: string;
    file?: string;
  }>;
}

export function toJsonReport(
  r: VerifyReport,
  packetDir: string,
  toolVersion: string,
): VerifyReportJson {
  const checks = r.checks.map((c) => ({
    name: c.name,
    status: (!c.ok ? "FAIL" : c.warn ? "WARN" : "PASS") as "PASS" | "WARN" | "FAIL",
    detail: c.detail,
    ...(c.file ? { file: c.file } : {}),
  }));
  const pass = checks.filter((c) => c.status === "PASS").length;
  const warn = checks.filter((c) => c.status === "WARN").length;
  const fail = checks.filter((c) => c.status === "FAIL").length;
  const status: "PASS" | "WARN" | "FAIL" = fail > 0 ? "FAIL" : warn > 0 ? "WARN" : "PASS";
  return {
    schema_version: "seilx-verify-report/0.1",
    tool: { name: "seilx", version: toolVersion },
    verified_at: new Date().toISOString(),
    packet_dir: packetDir,
    ok: r.ok,
    summary: { pass, warn, fail, status },
    checks,
  };
}