# SEILX signing-identity metadata

**Synthetic reference implementation v0.1.**

This directory holds the **public** identity descriptor for a SEILX
signing key. It contains no private key material and never will.

A signing-identity file (`seilx-signing-key-YYYY-MM.json`) binds a
published Ed25519 public key to a stable key-id and publication URL.
It is consumed by `seilx build --identity <file>` to:

1. Refuse to sign unless the caller also provides a matching `--key`
   (private key path outside the repository).
2. Validate that the supplied private key derives a public key whose
   PEM and SHA-256 fingerprint match the values declared in this file
   **exactly** — otherwise the build fails.
3. Embed the declared identity (`key_id`, `fingerprint_sha256`,
   `publication_url`, `valid_from`, `issuer`) into
   `signing_info.json` inside the packet.

## Rotation model

- Each identity file describes ONE key generation, e.g. `2026-01`.
- When a key is rotated, add a new file (`…-2027-01.json`) and mark
  the old one `status: "retired"` with a `retired_at` date.
- **Retired public keys stay published forever** so that packets
  signed while the key was active remain independently verifiable.
- The private key is created and stored **outside** this repository
  and outside Lovable. Lovable, Git, CI, and Evidence Packets never
  see it.

## Fields

| field | required | meaning |
|-------|----------|---------|
| `schema_version` | yes | `seilx-signing-identity/0.1` |
| `key_id` | yes | stable ID, e.g. `seilx-signing-key-2026-01` |
| `algorithm` | yes | `Ed25519` |
| `public_key_pem` | yes | SPKI PEM, trimmed with trailing `\n` |
| `fingerprint_sha256` | yes | `sha256(public_key_pem trimmed)` — must match `export-pubkey` output |
| `valid_from` | yes | ISO-8601 UTC |
| `valid_until` | no | ISO-8601 UTC; omit for open-ended |
| `status` | yes | `active` \| `retired` |
| `publication_url` | yes | stable HTTPS URL where the public key is published |
| `issuer` | yes | free-form identity string (e.g. `SEILX / <person or org>`) |
| `notes` | no | free-form |

`build.ts` also rejects the file if any value still contains the
string `REPLACE_WITH_` — the template must be filled in before use.

## Never in this directory

- `*.key`, `private_key.pem`, or any PEM containing `BEGIN … PRIVATE KEY`.
- Passphrases, HSM PINs, or recovery phrases.

`seilx export-pubkey` scans for and refuses to run in the presence of
private key material; the same discipline applies here manually.