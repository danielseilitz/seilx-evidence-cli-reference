# Verification — standard tools only

All commands below use `openssl` and `sha256sum`. The SEILX verifier
(`seilx verify .`) is a convenience wrapper that runs the same checks.

## 1. Verify file hashes

```sh
sha256sum -c hashes.sha256
```

Every line must report `OK`. A one-byte change to any listed file
produces a `FAILED` line naming that file.

## 2. Verify the signature over the association

The signature is Ed25519 over the **RFC 8785 canonical UTF-8 encoding**
of `association.json`. Canonicalise it, then verify:

```sh
# Re-canonicalise association.json with any RFC 8785 tool (jcs, our CLI,
# or a scripted equivalent) and write the bytes to association.canonical.
seilx canonicalize association.json > association.canonical

openssl pkeyutl -verify -pubin -inkey public_key.pem \
  -rawin -in association.canonical \
  -sigfile signature.sig
```

Expected output: `Signature Verified Successfully`.

## 3. Verify the RFC 3161 timestamps (once obtained)

For each `.tsr` in `timestamps/` (produced by a real TSA against the
matching `.tsq`), run:

```sh
openssl ts -verify -data <artifact> -in timestamps/<artifact>.tsr \
  -CAfile timestamps/tsa_ca.pem
```

Expected: `Verification: OK`.

## 4. Verify construction order

Extract the `genTime` from each response:

```sh
openssl ts -reply -in timestamps/association.tsr -text | grep 'Time stamp'
```

`association.tsr.genTime` MUST be greater than or equal to every
artifact `.tsr.genTime`. If it is earlier, the association claims to
cover artifacts that did not yet exist — reject the packet.

## 5. Tamper test

Open any listed file, flip one byte, save, re-run step 1. The output
MUST include a `FAILED` line for that file.
