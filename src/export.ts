import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { sha256Hex } from "./hash.ts";

export interface ExportOptions {
  packetDir: string;
  /** Where to write the exported artifacts. Defaults to <packetDir>/../<packet>-pubkey/. */
  outDir?: string;
}

export interface ExportReport {
  schema_version: "seilx-pubkey-export/0.1";
  packet_dir: string;
  out_dir: string;
  public_key_file: string;
  fingerprint_file: string;
  fingerprint_sha256: string;
  algorithm: "Ed25519";
  usage_hint: string;
  private_key_scan: {
    scanned_paths: string[];
    private_key_present: false;
  };
}

/**
 * Copy the packet's public_key.pem out to a separate directory ready for
 * publication, together with its SHA-256 fingerprint. Refuses to run if any
 * private_key.pem is discovered in the packet directory or the chosen out
 * directory — the whole point of this step is that the published artifact is
 * bindable to an identity WITHOUT leaking key material.
 */
export async function exportPublicKey(opts: ExportOptions): Promise<ExportReport> {
  const packetDir = resolve(opts.packetDir);
  if (!existsSync(packetDir)) throw new Error(`No such packet directory: ${packetDir}`);
  const pubPath = join(packetDir, "public_key.pem");
  if (!existsSync(pubPath)) {
    throw new Error(`public_key.pem not found in ${packetDir}`);
  }
  const outDir = resolve(opts.outDir ?? `${packetDir}-pubkey`);
  await mkdir(outDir, { recursive: true });

  // Safety scan: refuse if any private key material is present in the packet
  // or in the chosen output directory.
  const scanned: string[] = [];
  await scanForPrivate(packetDir, scanned);
  await scanForPrivate(outDir, scanned);

  const pemRaw = await readFile(pubPath, "utf8");
  const pem = pemRaw.trim() + "\n";
  if (/BEGIN (?:.*)PRIVATE KEY/.test(pem)) {
    throw new Error(
      `Refusing to export: ${pubPath} contains a PRIVATE KEY block. Only public keys may be exported.`,
    );
  }
  if (!/BEGIN PUBLIC KEY/.test(pem)) {
    throw new Error(`Refusing to export: ${pubPath} is not a PEM-encoded public key.`);
  }
  // Fingerprint is over the trimmed PEM text (matches verify.ts identity check).
  const fingerprint = sha256Hex(pem.trim());

  const outPub = join(outDir, "seilx_public.pem");
  const outFp = join(outDir, "seilx_public.pem.sha256");
  const outMeta = join(outDir, "PUBLISH.md");

  await writeFile(outPub, pem);
  // sha256sum -c compatible line.
  await writeFile(outFp, `${fingerprint}  seilx_public.pem\n`);
  await writeFile(outMeta, renderPublishMd(fingerprint));

  return {
    schema_version: "seilx-pubkey-export/0.1",
    packet_dir: packetDir,
    out_dir: outDir,
    public_key_file: outPub,
    fingerprint_file: outFp,
    fingerprint_sha256: fingerprint,
    algorithm: "Ed25519",
    usage_hint:
      "Publish seilx_public.pem at a stable URL and quote the SHA-256 fingerprint out-of-band. Verifiers run: seilx verify <packet> --external-key seilx_public.pem",
    private_key_scan: {
      scanned_paths: scanned,
      private_key_present: false,
    },
  };
}

async function scanForPrivate(dir: string, scanned: string[]): Promise<void> {
  if (!existsSync(dir)) return;
  const stack: string[] = [dir];
  while (stack.length) {
    const d = stack.pop()!;
    const entries = await readdir(d, { withFileTypes: true });
    for (const e of entries) {
      const p = join(d, e.name);
      scanned.push(p);
      if (e.isDirectory()) {
        stack.push(p);
      } else if (/private_key\.pem$/i.test(e.name) || /\.key$/i.test(e.name)) {
        throw new Error(
          `Refusing to export: found ${p}. Remove any private key material before exporting the public key.`,
        );
      } else if (e.isFile() && /\.pem$/i.test(e.name)) {
        const txt = await readFile(p, "utf8").catch(() => "");
        if (/BEGIN (?:.*)PRIVATE KEY/.test(txt)) {
          throw new Error(
            `Refusing to export: ${p} contains a PRIVATE KEY block. Remove or move it before running export-pubkey.`,
          );
        }
      }
    }
  }
}

function renderPublishMd(fp: string): string {
  return `# SEILX signing key — publication artifact

**Synthetic reference implementation v0.1.**

This directory holds the SEILX signing key in a form suitable for
publication at a stable, out-of-packet URL (GitHub repo, SEILX domain,
etc.). It contains NO private key material.

| file | role |
|------|------|
| \`seilx_public.pem\` | Ed25519 public key (SPKI PEM) |
| \`seilx_public.pem.sha256\` | \`sha256sum -c\` compatible fingerprint |

## Fingerprint

\`\`\`
SHA-256(seilx_public.pem trimmed): ${fp}
\`\`\`

Quote this fingerprint separately from the file itself (README, release
notes, DNS TXT record, signed announcement). A verifier accepts the key
only when both the file hash and the quoted fingerprint agree.

## How reviewers use this

1. Download \`seilx_public.pem\` from the stable location.
2. Confirm its SHA-256 matches the fingerprint above:
   \`\`\`sh
   sha256sum -c seilx_public.pem.sha256
   \`\`\`
3. Run identity-bound verification on a received packet:
   \`\`\`sh
   seilx verify <packet_dir> --external-key seilx_public.pem
   \`\`\`
   The identity check reaches \`PASS\` only when the packet's
   \`public_key.pem\` fingerprint equals the fingerprint above.

## What this does NOT prove

- That the key belongs to a specific legal entity (that's out-of-band trust).
- That measurements referenced by any signed packet are true.
- Legal admissibility of any packet signed with this key.
`;
}

export function formatExportReport(r: ExportReport): string {
  const lines: string[] = [];
  lines.push(`EXPORTED public key: ${r.public_key_file}`);
  lines.push(`fingerprint file:    ${r.fingerprint_file}`);
  lines.push(`SHA-256:             ${r.fingerprint_sha256}`);
  lines.push(`algorithm:           ${r.algorithm}`);
  lines.push("");
  lines.push("private_key_scan: no PRIVATE KEY material found in packet or output directory.");
  lines.push("");
  lines.push("Next: publish seilx_public.pem at a stable URL, quote the fingerprint separately,");
  lines.push("and run: seilx verify <packet> --external-key seilx_public.pem");
  return lines.join("\n");
}