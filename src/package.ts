import { readFile, writeFile, readdir, stat, mkdir, cp } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, basename, dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { sha256Hex } from "./hash.ts";

export interface PackageOptions {
  packetDir: string;
  /** Output archive path. Defaults to <packetDir>.tar.gz next to the source. */
  outPath?: string;
}

export interface PackageReport {
  packet_dir: string;
  archive: string;
  archive_sha256: string;
  top_level_hashes: Array<{ file: string; sha256: string }>;
  files_included: string[];
  review_md: string;
  archive_format: "tar.gz";
}

/**
 * Bundle a packet directory into a portable review archive that an
 * independent reviewer can verify offline. Adds:
 *   - REVIEW.md   — reviewer checklist with expected top-level hashes
 *   - Preserves the packet's own hashes.sha256, manifest.json, etc.
 * Emits a tar.gz (portable, deterministic ordering) and prints the
 * archive's own SHA-256 for out-of-band comparison.
 */
export async function packagePacket(opts: PackageOptions): Promise<PackageReport> {
  const packetDir = resolve(opts.packetDir);
  if (!existsSync(packetDir)) throw new Error(`No such packet directory: ${packetDir}`);
  const base = basename(packetDir);
  const outPath = resolve(opts.outPath ?? `${packetDir}.tar.gz`);

  // Collect top-level files for reviewer checklist.
  const entries = await readdir(packetDir, { withFileTypes: true });
  const topFiles: string[] = [];
  for (const e of entries) if (e.isFile()) topFiles.push(e.name);
  topFiles.sort();
  const topHashes: Array<{ file: string; sha256: string }> = [];
  for (const f of topFiles) {
    const buf = await readFile(join(packetDir, f));
    topHashes.push({ file: f, sha256: sha256Hex(buf) });
  }

  const review = renderReviewMd(base, topHashes);
  await writeFile(join(packetDir, "REVIEW.md"), review);

  // tar with sorted paths for reproducible archive bytes.
  const parent = dirname(packetDir);
  const r = spawnSync(
    "tar",
    [
      "--sort=name",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      "--mtime=UTC 2020-01-01",
      "-czf",
      outPath,
      "-C",
      parent,
      base,
    ],
    { encoding: "utf8" },
  );
  if (r.status !== 0) {
    throw new Error(`tar failed: ${r.stderr || r.stdout}`);
  }

  const archiveHash = sha256Hex(await readFile(outPath));

  // Walk directory for the files_included listing.
  const included: string[] = [];
  await walk(packetDir, packetDir, included);
  included.sort();

  return {
    packet_dir: packetDir,
    archive: outPath,
    archive_sha256: archiveHash,
    top_level_hashes: topHashes,
    files_included: included,
    review_md: join(packetDir, "REVIEW.md"),
    archive_format: "tar.gz",
  };
}

async function walk(root: string, dir: string, out: string[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const p = join(dir, e.name);
    const rel = p.slice(root.length + 1);
    if (e.isDirectory()) {
      out.push(rel + "/");
      await walk(root, p, out);
    } else {
      out.push(rel);
    }
  }
}

function renderReviewMd(name: string, hashes: Array<{ file: string; sha256: string }>): string {
  const table = hashes.map((h) => `| \`${h.file}\` | \`${h.sha256}\` |`).join("\n");
  return `# Review bundle — ${name}

**Synthetic. Reference implementation v0.1. Not a production system.**

This directory is a self-contained verification package. A reviewer
with only \`openssl\` and \`sha256sum\` can confirm every claim below
without contacting the packet author.

## What to check, in order

1. **File integrity (hashes.sha256)**
   \`\`\`sh
   sha256sum -c hashes.sha256
   \`\`\`
   Every line must print \`OK\`. Any \`FAILED\` line names the tampered file.

2. **Association hashes match artifacts**
   Each \`artifacts[].hash\` in \`association.json\` must equal the
   SHA-256 of the RFC 8785 canonical encoding of the referenced file.
   The bundled \`seilx verify .\` performs this check; it can also be
   done with any RFC 8785 (JCS) implementation.

3. **Signature over the association**
   \`\`\`sh
   seilx canonicalize association.json > /tmp/assoc.canonical
   openssl pkeyutl -verify -pubin -inkey public_key.pem \\
     -rawin -in /tmp/assoc.canonical -sigfile signature.sig
   \`\`\`
   Expected: \`Signature Verified Successfully\`.

4. **Identity (out-of-band)**
   The signature above proves internal consistency, NOT authorship. To
   upgrade identity from WARN to PASS, fetch the claimed public key
   from a stable, out-of-packet source and run:
   \`\`\`sh
   seilx verify . --external-key ./published_key.pem
   \`\`\`

5. **RFC 3161 timestamps** (if \`timestamps/*.tsr\` present)
   \`\`\`sh
   openssl ts -verify -data <artifact> -in timestamps/<artifact>.tsr \\
     -CAfile timestamps/tsa_ca.pem -untrusted timestamps/tsa.crt
   \`\`\`
   Also confirm \`association.tsr\` \`genTime\` is strictly later than
   every source \`.tsr\` \`genTime\` — same-second results are WARN, not PASS.

6. **Machine-readable report** (for CI or logging)
   \`\`\`sh
   seilx verify . --json > verify-report.json
   \`\`\`
   Stable schema: \`seilx-verify-report/0.1\`.

## Expected top-level hashes

If the bundle you received is intact, these are the SHA-256 hashes of
every top-level file at build time:

| file | sha256 |
|------|--------|
${table}

A mismatch on any of these means the bundle was modified after
packaging — reject it and request a fresh one.

## Reproducibility

If this packet was built with \`--source-date\` and \`--key\`, rebuilding
with the same inputs must produce byte-identical files. Check
\`manifest.json\` → \`reproducibility.mode\`. If \`deterministic\`, run:

\`\`\`sh
seilx build /tmp/rebuild --source-date <manifest.built_at> --key <same_private_key>
diff -r /tmp/rebuild ./   # must be empty modulo REVIEW.md
\`\`\`

## Nothing in this bundle claims

- legal admissibility;
- truth of the referenced measurement;
- production readiness;
- that a valid signature identifies SEILX (see step 4).
`;
}

export function formatPackageReport(r: PackageReport): string {
  const lines: string[] = [];
  lines.push(`PACKAGED: ${r.archive}`);
  lines.push(`format:   ${r.archive_format}`);
  lines.push(`sha256:   ${r.archive_sha256}`);
  lines.push("");
  lines.push("Top-level file hashes (share these out-of-band):");
  for (const h of r.top_level_hashes) {
    lines.push(`  ${h.sha256}  ${h.file}`);
  }
  lines.push("");
  lines.push(`REVIEW.md written to: ${r.review_md}`);
  return lines.join("\n");
}