import { createPublicKey } from "node:crypto";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export async function sha256File(path: string): Promise<string> {
  const buf = await readFile(path);
  return sha256Hex(buf);
}

/**
 * Decode a PEM-encoded SPKI public key to its DER (SubjectPublicKeyInfo) bytes.
 *
 * Node's createPublicKey() on a raw PEM string throws
 * `DECODER routines::unsupported` for Ed25519 under OpenSSL 3 providers.
 * Decoding PEM -> base64 -> DER and reading it as {format:"der",type:"spki"}
 * is the reliable path.
 */
export function spkiDerFromPem(pem: string): Buffer {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const der = Buffer.from(b64, "base64");
  // Validate it really is a well-formed SPKI key; throws on garbage input.
  createPublicKey({ key: der, format: "der", type: "spki" });
  return der;
}

/**
 * Canonical SEILX public-key fingerprint:
 * SHA-256 over the DER-encoded SubjectPublicKeyInfo (SPKI-DER) bytes.
 * Never over the PEM text, so whitespace or line-ending variants of the
 * same key produce the same fingerprint.
 */
export function publicKeyFingerprintSpkiSha256(pem: string): string {
  return sha256Hex(spkiDerFromPem(pem));
}
