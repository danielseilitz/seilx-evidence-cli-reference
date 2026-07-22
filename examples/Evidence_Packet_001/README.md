# Evidence_Packet_001 — SEILX reference implementation v0.1

**Synthetic. Reference only. Not a production system.**

This packet demonstrates the SEILX dual-anchor architecture:

- Each originating system (SEILX, NeoMundi) produces its own artifact.
- A neutral `association.json` references those artifacts by their
  RFC 8785 canonical SHA-256 hashes.
- The association is signed (Ed25519) and independently timestamped
  (RFC 3161) by SEILX.

No claim is made about legal admissibility, content truth or the
measurement correctness of any referenced artifact.

## Contents

| File | Role |
|------|------|
| `evidence.json` | Synthetic SEILX evidence artifact |
| `neomundi_artifact.json` | Synthetic NeoMundi measurement artifact |
| `association.json` | Neutral association object (references artifacts by hash) |
| `signature.sig` | Ed25519 signature over RFC 8785 canonical `association.json` |
| `public_key.pem` | Verifier public key |
| `signing_info.json` | Signature metadata (algorithm, canonicalization, covered file) |
| `hashes.sha256` | Plain `sha256sum -c` compatible checksum file |
| `manifest.json` | External manifest — listing of all files with hashes and roles |
| `verify.md` | Step-by-step verification with standard tools |
| `timestamps/` | Place RFC 3161 `.tsr` responses here after obtaining them |

## Verifying

See `verify.md`. The SEILX verifier is a convenience only; every
security-relevant claim is independently checkable with `openssl` and
`sha256sum`.

## Tamper test

Open `evidence.json` in a text editor, change a single digit, save,
then re-run the verifier. Verification MUST fail and MUST name the
affected file.
