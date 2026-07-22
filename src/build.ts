import { mkdir, writeFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "./canonicalize.ts";
import { sha256Hex } from "./hash.ts";
import { generateEd25519Keypair, signBytes, loadPrivateKey } from "./sign.ts";
import { createPrivateKey, createPublicKey } from "node:crypto";

/**
 * Resolve the deterministic build timestamp.
 * Precedence: explicit --source-date > SOURCE_DATE_EPOCH env > wall clock.
 */
function resolveBuildTime(explicit?: string): string {
  if (explicit) return new Date(explicit).toISOString();
  const env = process.env.SOURCE_DATE_EPOCH;
  if (env && /^\d+$/.test(env)) {
    return new Date(parseInt(env, 10) * 1000).toISOString();
  }
  return new Date().toISOString();
}

const README = `# Evidence_Packet_001 — SEILX reference implementation v0.1

**Synthetic. Reference only. Not a production system.**

This packet demonstrates the SEILX dual-anchor architecture:

- Each originating system (SEILX, NeoMundi) produces its own artifact.
- A neutral \`association.json\` references those artifacts by their
  RFC 8785 canonical SHA-256 hashes.
- The association is signed (Ed25519) and independently timestamped
  (RFC 3161) by SEILX.

No claim is made about legal admissibility, content truth or the
measurement correctness of any referenced artifact.

## Contents

| File | Role |
|------|------|
| \`evidence.json\` | Synthetic SEILX evidence artifact |
| \`neomundi_artifact.json\` | Synthetic NeoMundi measurement artifact |
| \`association.json\` | Neutral association object (references artifacts by hash) |
| \`signature.sig\` | Ed25519 signature over RFC 8785 canonical \`association.json\` |
| \`public_key.pem\` | Verifier public key |
| \`signing_info.json\` | Signature metadata (algorithm, canonicalization, covered file) |
| \`hashes.sha256\` | Plain \`sha256sum -c\` compatible checksum file |
| \`manifest.json\` | External manifest — listing of all files with hashes and roles |
| \`verify.md\` | Step-by-step verification with standard tools |
| \`timestamps/\` | Place RFC 3161 \`.tsr\` responses here after obtaining them |

## Verifying

See \`verify.md\`. The SEILX verifier is a convenience only; every
security-relevant claim is independently checkable with \`openssl\` and
\`sha256sum\`.

## Tamper test

Open \`evidence.json\` in a text editor, change a single digit, save,
then re-run the verifier. Verification MUST fail and MUST name the
affected file.
`;

const VERIFY = `# Verification — standard tools only

All commands below use \`openssl\` and \`sha256sum\`. The SEILX verifier
(\`seilx verify .\`) is a convenience wrapper that runs the same checks.

## 1. Verify file hashes

\`\`\`sh
sha256sum -c hashes.sha256
\`\`\`

Every line must report \`OK\`. A one-byte change to any listed file
produces a \`FAILED\` line naming that file.

## 2. Verify the signature over the association

The signature is Ed25519 over the **RFC 8785 canonical UTF-8 encoding**
of \`association.json\`. Canonicalise it, then verify:

\`\`\`sh
# Re-canonicalise association.json with any RFC 8785 tool (jcs, our CLI,
# or a scripted equivalent) and write the bytes to association.canonical.
seilx canonicalize association.json > association.canonical

openssl pkeyutl -verify -pubin -inkey public_key.pem \\
  -rawin -in association.canonical \\
  -sigfile signature.sig
\`\`\`

Expected output: \`Signature Verified Successfully\`.

## 3. Verify the RFC 3161 timestamps (once obtained)

For each \`.tsr\` in \`timestamps/\` (produced by a real TSA against the
matching \`.tsq\`), run:

\`\`\`sh
openssl ts -verify -data <artifact> -in timestamps/<artifact>.tsr \\
  -CAfile timestamps/tsa_ca.pem
\`\`\`

Expected: \`Verification: OK\`.

## 4. Verify construction order

Extract the \`genTime\` from each response:

\`\`\`sh
openssl ts -reply -in timestamps/association.tsr -text | grep 'Time stamp'
\`\`\`

\`association.tsr.genTime\` MUST be greater than or equal to every
artifact \`.tsr.genTime\`. If it is earlier, the association claims to
cover artifacts that did not yet exist — reject the packet.

## 5. Tamper test

Open any listed file, flip one byte, save, re-run step 1. The output
MUST include a \`FAILED\` line for that file.
`;

export interface BuildOptions {
  outDir: string;
  privateKeyPath?: string; // if omitted, a fresh ephemeral keypair is generated
  privateKeyPassphrase?: string;
  identityPath?: string; // optional JSON file declaring a published-identity binding
  synthetic?: boolean;
  /**
   * If set, all embedded timestamps (evidence.observed_at,
   * neomundi.measured_at, association.created_at) use this ISO-8601 value
   * instead of `new Date()`. Combined with `privateKeyPath`, this makes
   * `seilx build` byte-for-byte deterministic — repeated builds produce
   * identical `hashes.sha256`. Also honoured via `SOURCE_DATE_EPOCH`.
   */
  sourceDate?: string;
}

export async function buildEvidencePacket(opts: BuildOptions): Promise<string> {
  const { outDir } = opts;
  await mkdir(outDir, { recursive: true });
  await mkdir(join(outDir, "timestamps"), { recursive: true });

  // 1. Synthetic artifacts.
  const now = resolveBuildTime(opts.sourceDate);

  const deterministic = Boolean(opts.sourceDate && opts.privateKeyPath);

  const evidence = {
    schema_version: "seilx-evidence/0.1",
    synthetic: true,
    event_id: "evt_synth_0001",
    observed_at: now,
    subject: {
      kind: "synthetic-subject",
      id: "subj_synth_0001",
    },
    observation: {
      type: "synthetic",
      note: "Reference implementation v0.1. Not a real observation.",
    },
  };

  const neomundi = {
    schema_version: "neomundi-measurement/0.1",
    synthetic: true,
    measurement_id: "meas_synth_0001",
    measured_at: now,
    subject_id: "subj_synth_0001",
    signal: {
      metric: "synthetic_metric",
      value: 0.42,
      unit: "au",
    },
    provenance: {
      system: "NeoMundi",
      note: "Generated and asserted by the NeoMundi measurement system but not independently recomputed by SEILX.",
    },
  };

  const evidenceBytes = canonicalJson(evidence);
  const neomundiBytes = canonicalJson(neomundi);
  const evidenceHash = sha256Hex(evidenceBytes);
  const neomundiHash = sha256Hex(neomundiBytes);

  await writeFile(join(outDir, "evidence.json"), evidenceBytes);
  await writeFile(join(outDir, "neomundi_artifact.json"), neomundiBytes);

  // 2. Neutral association object.
  const association = {
    schema_version: "seilx-association/0.1",
    synthetic: true,
    created_at: now,
    hash_algorithm: "SHA-256",
    canonicalization: "RFC8785",
    artifacts: [
      { role: "seilx.evidence", file: "evidence.json", hash: `sha256:${evidenceHash}` },
      { role: "neomundi.measurement", file: "neomundi_artifact.json", hash: `sha256:${neomundiHash}` },
    ],
    liability_note:
      "SEILX asserts integrity and linkage of the referenced artifacts. It does NOT attest to measurement correctness or content truth.",
  };
  const associationBytes = canonicalJson(association);
  await writeFile(join(outDir, "association.json"), associationBytes);

  // 3. Signature over canonical(association.json).
  let privateKey;
  let publicPem: string;
  let identityBinding: "published" | "ephemeral-packet-local" = "ephemeral-packet-local";
  let identityMeta: unknown = null;
  if (opts.privateKeyPath) {
    privateKey = await loadPrivateKey(
  opts.privateKeyPath,
  opts.privateKeyPassphrase
);
    // Derive public key from private.
    publicPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" }) as string;
    if (opts.identityPath) {
      identityMeta = await loadAndValidateIdentity(opts.identityPath, publicPem);
      identityBinding = "published";
    }
  } else {
    if (opts.identityPath) {
      throw new Error(
        "Refusing to build: --identity was supplied without --key. " +
          "A published identity binding requires the caller to provide the " +
          "permanent private key from outside the repository. This build " +
          "will not generate a signing key when an identity is declared.",
      );
    }
    const kp = generateEd25519Keypair();
    privateKey = createPrivateKey(kp.privatePem);
    publicPem = kp.publicPem;
    // We do NOT write the private key into the packet. It is printed to
    // stderr only when explicitly requested via --emit-ephemeral-key.
  }
  const signature = signBytes(privateKey, associationBytes);
  await writeFile(join(outDir, "signature.sig"), signature);
  await writeFile(join(outDir, "public_key.pem"), publicPem);

  const signingInfo: Record<string, unknown> = {
    schema_version: "seilx-signing-info/0.1",
    algorithm: "Ed25519",
    canonicalization: "RFC8785 (JCS)",
    signed_file: "association.json",
    signature_file: "signature.sig",
    public_key_file: "public_key.pem",
    identity_binding: identityBinding,
    note: "Signature is computed over the RFC 8785 canonical UTF-8 encoding of association.json.",
  };
  if (identityBinding === "ephemeral-packet-local") {
    signingInfo.warning =
      "This packet was signed with a key generated at build time. The signature proves internal consistency of the packet, NOT authorship by SEILX. A verifier must not treat a valid signature as proof of origin until the signing public key is published at a stable location and its fingerprint verified out-of-band.";
  }
  if (identityMeta) signingInfo.identity = identityMeta;
  await writeFile(join(outDir, "signing_info.json"), canonicalJson(signingInfo));

  // 4. hashes.sha256 (sha256sum -c compatible)
  const filesForHashes = [
    "evidence.json",
    "neomundi_artifact.json",
    "association.json",
    "signature.sig",
    "public_key.pem",
    "signing_info.json",
  ];
  const hashLines: string[] = [];
  for (const f of filesForHashes) {
    const buf = await readFile(join(outDir, f));
    hashLines.push(`${sha256Hex(buf)}  ${f}`);
  }
  await writeFile(join(outDir, "hashes.sha256"), hashLines.join("\n") + "\n");

  // 5. External manifest (not covered by its own hash).
  const manifest = {
    schema_version: "seilx-manifest/0.1",
    synthetic: true,
    reference_implementation_version: "v0.1",
    canonicalization: "RFC8785",
    hash_algorithm: "SHA-256",
    built_at: now,
    reproducibility: deterministic
      ? {
          mode: "deterministic",
          note: "Built with a fixed --source-date and --key. Repeating the same build command with the same inputs MUST produce byte-identical files and identical hashes.sha256.",
          source_date: now,
        }
      : {
          mode: "non-deterministic",
          note: "Built with wall-clock time and/or an ephemeral key. Rebuilds will produce different bytes. For a reproducible build pass --source-date <ISO> AND --key <private_key.pem>.",
        },
    files: [
      ...filesForHashes.map((f, i) => ({
        path: f,
        hash: hashLines[i].split("  ")[0],
        role: fileRole(f),
      })),
      { path: "hashes.sha256", role: "checksums" },
      { path: "verify.md", role: "documentation" },
      { path: "README.md", role: "documentation" },
      { path: "timestamps/", role: "rfc3161-responses" },
    ],
    disclaimers: [
      "Synthetic. Reference implementation v0.1.",
      "No claim of legal admissibility.",
      "No claim of content truth.",
      "No claim of production readiness.",
    ],
  };
  await writeFile(join(outDir, "manifest.json"), canonicalJson(manifest));

  // 6. Docs.
  await writeFile(join(outDir, "README.md"), README);
  await writeFile(join(outDir, "verify.md"), VERIFY);
  await writeFile(
    join(outDir, "timestamps", "README.md"),
    "# Timestamps\n\n" +
      "Place RFC 3161 responses here after obtaining them from a real TSA:\n\n" +
      "- `evidence.tsr`      — timestamp of `../evidence.json`\n" +
      "- `neomundi.tsr`      — timestamp of `../neomundi_artifact.json`\n" +
      "- `association.tsr`   — timestamp of `../association.json`\n" +
      "- `tsa_ca.pem`        — TSA CA chain used for `openssl ts -verify`\n\n" +
      "Generate a request with:\n\n" +
      "```sh\n" +
      "openssl ts -query -data ../evidence.json -sha256 -cert -out evidence.tsq\n" +
      "curl -sS -H 'Content-Type: application/timestamp-query' \\\n" +
      "  --data-binary @evidence.tsq https://freetsa.org/tsr > evidence.tsr\n" +
      "```\n\n" +
      "Construction-order rule: `association.tsr.genTime` MUST be >= every artifact `.tsr.genTime`.\n",
  );

  return outDir;
}

function fileRole(f: string): string {
  switch (f) {
    case "evidence.json":
      return "seilx.evidence";
    case "neomundi_artifact.json":
      return "neomundi.measurement";
    case "association.json":
      return "seilx.association";
    case "signature.sig":
      return "seilx.signature";
    case "public_key.pem":
      return "seilx.public_key";
    case "signing_info.json":
      return "seilx.signing_info";
    default:
      return "unknown";
  }
}

/**
 * Load a `seilx-signing-identity/0.1` file and confirm that the private key
 * the build is signing with truly matches the declared public identity.
 *
 * Fails hard on:
 *  - Unfilled placeholders (`REPLACE_WITH_*`).
 *  - Missing required fields.
 *  - Mismatched public key PEM (byte comparison of the trimmed SPKI PEM).
 *  - Mismatched SHA-256 fingerprint (`sha256(trimmed PEM)`).
 *  - Any embedded PRIVATE KEY block.
 *
 * On success returns the identity object with only public fields, for
 * inclusion in `signing_info.json`.
 */
async function loadAndValidateIdentity(
  identityPath: string,
  builtPublicPem: string,
): Promise<Record<string, unknown>> {
  const raw = await readFile(identityPath, "utf8");
  if (/BEGIN (?:.*)PRIVATE KEY/.test(raw)) {
    throw new Error(
      `Refusing to build: ${identityPath} contains a PRIVATE KEY block. ` +
        "Identity metadata must contain public material only.",
    );
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(`Identity file is not valid JSON (${identityPath}): ${(e as Error).message}`);
  }

  const required = [
    "schema_version",
    "key_id",
    "algorithm",
    "status",
    "valid_from",
    "issuer",
    "publication_url",
    "fingerprint_sha256",
    "public_key_pem",
  ] as const;
  for (const k of required) {
    if (parsed[k] === undefined || parsed[k] === null || parsed[k] === "") {
      throw new Error(`Identity file missing required field '${k}' (${identityPath}).`);
    }
  }
  if (parsed.schema_version !== "seilx-signing-identity/0.1") {
    throw new Error(
      `Identity schema_version must be 'seilx-signing-identity/0.1' (got ${String(parsed.schema_version)}).`,
    );
  }
  if (parsed.algorithm !== "Ed25519") {
    throw new Error(`Identity algorithm must be 'Ed25519' (got ${String(parsed.algorithm)}).`);
  }
  if (parsed.status !== "active") {
    throw new Error(
      `Refusing to build: identity status is '${String(parsed.status)}'. Only 'active' keys may sign new packets.`,
    );
  }
  const flat = JSON.stringify(parsed);
  if (/REPLACE_WITH_/.test(flat)) {
    throw new Error(
      `Identity file still contains 'REPLACE_WITH_*' placeholders (${identityPath}). ` +
        "Fill in every field with values from 'seilx export-pubkey' before building.",
    );
  }

  // Byte-compare public key PEMs after canonicalising whitespace.
  const norm = (pem: string) => pem.replace(/\r\n/g, "\n").trim() + "\n";
  const declaredPem = norm(String(parsed.public_key_pem));
  const actualPem = norm(builtPublicPem);
  if (!/BEGIN PUBLIC KEY/.test(declaredPem)) {
    throw new Error("Identity 'public_key_pem' is not a PEM-encoded PUBLIC KEY block.");
  }
  if (declaredPem !== actualPem) {
    // Also compare via decoded DER as a fallback — different line endings
    // etc. Reject unless DER-equal to give a clean diagnostic.
    try {
      const der1 = createPublicKey(declaredPem).export({ type: "spki", format: "der" }) as Buffer;
      const der2 = createPublicKey(actualPem).export({ type: "spki", format: "der" }) as Buffer;
      if (der1.equals(der2)) {
        // Same key, differing PEM formatting. Still reject: reproducibility
        // requires byte-identical PEM in the identity file.
        throw new Error(
          "Identity public_key_pem decodes to the same key but its PEM bytes differ from the private key's derived PEM. " +
            "Update the identity file with the exact PEM produced by 'seilx export-pubkey' to keep builds reproducible.",
        );
      }
    } catch {
      // fall through to generic mismatch
    }
    throw new Error(
      "Identity public key does not match the private key supplied via --key. " +
        "The declared identity and the signing key must be the same permanent SEILX key.",
    );
  }

  const expectedFp = sha256Hex(
  createPublicKey(declaredPem).export({ type: "spki", format: "der" }) as Buffer
);
  if (String(parsed.fingerprint_sha256).toLowerCase() !== expectedFp) {
    throw new Error(
      `Identity fingerprint_sha256 does not match sha256(trimmed public_key_pem).\n` +
        `  declared: ${String(parsed.fingerprint_sha256)}\n` +
        `  computed: ${expectedFp}\n` +
        "Regenerate the identity file from 'seilx export-pubkey'.",
    );
  }

  // Return only public metadata for embedding.
  const out: Record<string, unknown> = {
    schema_version: parsed.schema_version,
    key_id: parsed.key_id,
    algorithm: parsed.algorithm,
    status: parsed.status,
    valid_from: parsed.valid_from,
    valid_until: parsed.valid_until ?? null,
    issuer: parsed.issuer,
    publication_url: parsed.publication_url,
    fingerprint_sha256: expectedFp,
  };
  if (parsed.notes) out.notes = parsed.notes;
  return out;
}
