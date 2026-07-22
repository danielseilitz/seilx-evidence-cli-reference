#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { canonicalJson } from "./canonicalize.ts";
import { buildEvidencePacket } from "./build.ts";
import { verifyPacket, formatReport, toJsonReport } from "./verify.ts";
import { generateEd25519Keypair } from "./sign.ts";
import { runTestMatrix, formatMatrix } from "./test.ts";
import { acquireTimestamps, formatTimestampReport } from "./timestamp.ts";
import { packagePacket, formatPackageReport } from "./package.ts";
import { exportPublicKey, formatExportReport } from "./export.ts";

const TOOL_VERSION = "0.1.0";

const HELP = `seilx — SEILX reference implementation v0.1 (synthetic, not production)

Usage:
  seilx build <outDir> [--key <private_key.pem>]
      Build a synthetic Evidence_Packet at <outDir>.
      Optional: --identity <identity.json> to declare a published-identity
      binding (only meaningful together with --key). Without it, the packet
      is signed with a build-time ephemeral key and marked accordingly.
      Optional: --source-date <ISO8601> (or env SOURCE_DATE_EPOCH) to freeze
      embedded timestamps. Combined with --key, the build becomes
      byte-for-byte reproducible.
  seilx verify <packetDir>
      Verify hashes, association references, Ed25519 signature,
      and (if timestamps/ contains .tsr files) RFC 3161 responses
      plus construction-order consistency.
      Optional: --external-key <public_key.pem> to bind identity out-of-band.
      Optional: --external-key-url <https://...> to fetch the key over HTTPS
      (convenience; the security value is still the fingerprint match).
      Optional: --external-fingerprint <sha256 hex> to match the packet key
      against an out-of-band-quoted fingerprint (release notes, DNS TXT).
      Only when one of these matches can identity status become PASS;
      otherwise it stays WARN.
      Optional: --json to emit a machine-readable verification report
      (schema seilx-verify-report/0.1). Non-zero exit on FAIL.
  seilx package <packetDir> [--out <archive.tar.gz>]
      Bundle a packet into a portable review archive (tar.gz) with a
      REVIEW.md checklist and the SHA-256 of the archive itself for
      out-of-band comparison. Deterministic tar options are used so the
      archive bytes match across rebuilds of the same input.
  seilx test
      Run the SEILX hardening test matrix: cross-implementation JCS
      vectors, must-reject SEILX profile rules, tamper detection,
      identity-binding rule, and TSA-absence rule. Emits a table and
      a JSON summary with exact canonical bytes and SHA-256 per vector.
  seilx timestamp <packetDir> [--tsa-url <url>] [--json]
      Acquire fresh RFC 3161 timestamps for the packet's artifacts from a
      public TSA (default: https://freetsa.org/tsr). A new .tsq (fresh
      nonce) is generated per artifact; responses are saved as .tsr and
      verified with 'openssl ts -verify' against an explicitly trusted CA.
      Reports TSA URL, exact OpenSSL commands, artifact SHA-256, asserted
      time, chain-verify result, and final PASS/WARN/FAIL status.
  seilx canonicalize <file.json>
      Emit the RFC 8785 canonical UTF-8 bytes of the given JSON file to stdout.
  seilx keygen <outDir>
      Emit a fresh Ed25519 keypair (public_key.pem, private_key.pem) to outDir.
  seilx export-pubkey <packetDir> [--out <dir>] [--json]
      Copy the packet's public_key.pem out to a separate, publishable
      location together with its SHA-256 fingerprint. The result is meant
      to be published at a stable URL (e.g. GitHub repo, SEILX domain) so
      independent verifiers can run:
        seilx verify <packetDir> --external-key <exported_public_key.pem>
      Never touches, reads, or emits any private key material. Refuses to
      run if a private_key.pem is found next to the packet's public key.
  seilx demo
      Alias for: build examples/Evidence_Packet_001

Nothing here claims legal admissibility, content truth or production
readiness. All artifacts are marked synthetic.`;

function arg(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function main() {
  const [, , cmd, ...rest] = process.argv;
  switch (cmd) {
    case "build": {
      const outDir = rest[0];
      if (!outDir) return usage();
      const key = arg(rest, "--key");
      const identity = arg(rest, "--identity");
      const sourceDate = arg(rest, "--source-date");
      const out = await buildEvidencePacket({
        outDir,
        privateKeyPath: key,
        identityPath: identity,
        sourceDate,
      });
      console.log(`Built Evidence_Packet at ${out}`);
      return;
    }
    case "demo": {
      const out = await buildEvidencePacket({ outDir: "examples/Evidence_Packet_001" });
      console.log(`Built demo packet at ${out}`);
      return;
    }
    case "verify": {
      const dir = rest[0];
      if (!dir) return usage();
      const externalKey = arg(rest, "--external-key");
      const externalKeyUrl = arg(rest, "--external-key-url");
      const externalFingerprint = arg(rest, "--external-fingerprint");
      const asJson = rest.includes("--json");
      const r = await verifyPacket(dir, {
        externalKeyPath: externalKey,
        externalKeyUrl,
        externalFingerprint,
      });
      if (asJson) {
        const jr = toJsonReport(r, dir, TOOL_VERSION);
        console.log(JSON.stringify(jr, null, 2));
      } else {
        console.log(formatReport(r));
      }
      process.exit(r.ok ? 0 : 1);
      return;
    }
    case "package": {
      const dir = rest[0];
      if (!dir) return usage();
      const out = arg(rest, "--out");
      const report = await packagePacket({ packetDir: dir, outPath: out });
      console.log(formatPackageReport(report));
      return;
    }
    case "test": {
      const { rows, vectorDetails, ok } = await runTestMatrix();
      console.log(formatMatrix(rows));
      console.log("");
      console.log("Vector details (JSON):");
      console.log(JSON.stringify(vectorDetails, null, 2));
      console.log("");
      console.log(ok ? "TEST MATRIX: ALL PASS" : "TEST MATRIX: FAILURES ABOVE");
      process.exit(ok ? 0 : 1);
      return;
    }
    case "timestamp": {
      const dir = rest[0];
      if (!dir) return usage();
      const tsaUrl = arg(rest, "--tsa-url");
      const asJson = rest.includes("--json");
      const report = await acquireTimestamps({ packetDir: dir, tsaUrl });
      if (asJson) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log(formatTimestampReport(report));
      }
      process.exit(report.final_status === "PASS" ? 0 : 1);
      return;
    }
    case "canonicalize": {
      const file = rest[0];
      if (!file) return usage();
      const parsed = JSON.parse(await readFile(file, "utf8"));
      process.stdout.write(canonicalJson(parsed));
      return;
    }
    case "keygen": {
      const outDir = rest[0];
      if (!outDir) return usage();
      const { publicPem, privatePem } = generateEd25519Keypair();
      await writeFile(`${outDir}/public_key.pem`, publicPem);
      await writeFile(`${outDir}/private_key.pem`, privatePem, { mode: 0o600 });
      console.log(`Wrote public_key.pem and private_key.pem to ${outDir}`);
      console.log("Reminder: never commit private_key.pem.");
      return;
    }
    case "export-pubkey": {
      const dir = rest[0];
      if (!dir) return usage();
      const out = arg(rest, "--out");
      const asJson = rest.includes("--json");
      const report = await exportPublicKey({ packetDir: dir, outDir: out });
      if (asJson) console.log(JSON.stringify(report, null, 2));
      else console.log(formatExportReport(report));
      return;
    }
    case "-h":
    case "--help":
    case "help":
    case undefined:
      return usage();
    default:
      console.error(`Unknown command: ${cmd}\n`);
      usage();
      process.exit(2);
  }
}

function usage() {
  console.log(HELP);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});