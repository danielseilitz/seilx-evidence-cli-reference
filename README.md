# SEILX Evidence CLI — reference implementation v0.1

**Synthetic. Reference only. Not a production system.**

This is the reference implementation of the SEILX dual-anchor evidence
model. It produces a self-contained `Evidence_Packet_001/` directory
that anyone can verify with standard tools (`openssl`, `sha256sum`).

No claims are made about legal admissibility, content truth, or
production readiness.

## Design commitments

- **Canonicalisation** — RFC 8785 (JCS) via the established
  [`canonicalize`](https://www.npmjs.com/package/canonicalize) library.
  No hand-rolled canonicalisation.
- **Hashing** — SHA-256 via Node's built-in `crypto`.
- **Signature** — Ed25519 via Node's built-in `crypto` (OpenSSL under
  the hood). Signed bytes are the RFC 8785 canonical UTF-8 encoding of
  `association.json`, so the signature is independently verifiable with
  `openssl pkeyutl -verify`.
- **Timestamping** — RFC 3161 via `openssl ts`. This CLI does not
  parse or generate ASN.1 by hand; it only orchestrates `openssl`.
- **No hash-in-covered-object** — `association.json` contains hashes of
  *other* files; `manifest.json` is external and is itself listed in
  `hashes.sha256` but not self-referential.
- **No committed secrets** — `.gitignore` excludes `private_key.pem`.
  Keys are ephemeral by default; only the public key is written into
  the packet.

## Requirements

- Node.js >= 22.6 (for `--experimental-strip-types`)
- `openssl` on `PATH` (only required for RFC 3161 timestamp operations)

## Install & use

```sh
cd cli
npm install

# Build a synthetic evidence packet
./bin/seilx.mjs build examples/Evidence_Packet_001

# Verify a packet
./bin/seilx.mjs verify examples/Evidence_Packet_001

# Emit RFC 8785 canonical bytes of a JSON file
./bin/seilx.mjs canonicalize examples/Evidence_Packet_001/association.json

# Fresh Ed25519 keypair (never commit private_key.pem)
./bin/seilx.mjs keygen ./keys
```

## Getting real RFC 3161 timestamps

### Automated (recommended)

```sh
./bin/seilx.mjs timestamp examples/Evidence_Packet_001
```

For each artifact (`evidence.json`, `neomundi_artifact.json`,
`association.json`) the CLI:

1. Generates a **fresh** `.tsq` with `openssl ts -query -sha256 -cert`
   (a new random nonce per artifact; old queries are never reused —
   the nonce binds request to response).
2. Fetches the TSA CA (`https://freetsa.org/files/cacert.pem`) and the
   TSA signing certificate (`https://freetsa.org/files/tsa.crt`) once.
3. POSTs the `.tsq` to `https://freetsa.org/tsr` and saves the `.tsr`.
4. Runs `openssl ts -verify -data <artifact> -in <name>.tsr -CAfile
   tsa_ca.pem -untrusted tsa.crt` and reports the full `openssl`
   stdout/stderr, TSA-asserted `genTime`, artifact SHA-256, and a
   final `PASS/WARN/FAIL`.

The CLI inserts a deliberate delay (> 1 s) before anchoring
`association.json` so its TSA-asserted second is strictly later than
every source anchor. Without this, all three tokens can land in the same
asserted second and construction order is not demonstrable at TSA
granularity — see below.

### Anchor ordering — what RFC 3161 actually proves

RFC 3161 proves that a byte string existed **no later than** the TSA's
asserted `genTime`. It does NOT prove that two tokens with the same
asserted second occurred in any particular order — freetsa.org resolves
to whole seconds, so two anchors in the same second are simultaneous as
far as the TSA is concerned.

The verifier therefore treats construction order as three distinct
states, not a boolean:

- **PASS** — `association` genTime is strictly later than every source
  genTime. Order is independently demonstrable.
- **WARN — anchor order not demonstrable at TSA time granularity** —
  `association` shares an asserted second with at least one source. The
  packet may be correctly built, but the TSA's resolution cannot
  distinguish the events. Re-anchor `association` after a delay greater
  than the TSA's resolution.
- **FAIL** — a source genTime is strictly later than `association`.
  Association claims to cover artifacts that did not yet exist.

A same-second result is honestly ambiguous, not a build error. The
demo generator inserts a > 1 s delay to keep the default flow in PASS,
but the WARN state is the intended behaviour if a caller anchors
everything back-to-back.

### Manual (equivalent)

```sh
cd examples/Evidence_Packet_001/timestamps

for f in evidence.json neomundi_artifact.json association.json; do
  name=$(basename "$f" .json)
  openssl ts -query -data "../$f" -sha256 -cert -out "$name.tsq"
  curl -sS -H 'Content-Type: application/timestamp-query' \
    --data-binary "@$name.tsq" https://freetsa.org/tsr > "$name.tsr"
done

curl -sS https://freetsa.org/files/cacert.pem -o tsa_ca.pem
curl -sS https://freetsa.org/files/tsa.crt   -o tsa.crt
```

Then re-run `seilx verify` — it verifies each `.tsr` and enforces
construction order (`association.tsr` >= every artifact `.tsr`).
`seilx verify` passes `tsa.crt` as `-untrusted` automatically when the
file is present.

## Tamper test

```sh
./bin/seilx.mjs build /tmp/pkt
./bin/seilx.mjs verify /tmp/pkt          # -> VERIFIED

sed -i.bak 's/0.42/0.43/' /tmp/pkt/neomundi_artifact.json

./bin/seilx.mjs verify /tmp/pkt          # -> FAILED, names neomundi_artifact.json
```

## Roadmap

1. CLI + evidence packet (v0.1) — this repo.
2. Technical review + real TSA integration in CI.
3. Web app as a user-friendly shell over the same core.
4. Landing page.

The web app is the sales surface. The CLI packet is the proof
mechanism.

## Identity binding (READ THIS BEFORE TRUSTING A SIGNATURE)

By default `seilx build` generates a fresh Ed25519 keypair and embeds
the public key in the packet. That signature proves the packet is
internally consistent — it does NOT prove authorship by SEILX. Anyone
can generate a keypair, sign a zip, and ship the public key inside it.

The verifier reports this explicitly:

```
WARN  identity  [signing_info.json]: Signing key is packet-local (ephemeral)…
```

A signature is only meaningful once the public key is published at a
stable location (repo, `seil.group`, a certificate) so a verifier can
recognise it without asking the packet's author. To mark a packet as
bound to a published identity, pass `--key` and `--identity`:

```sh
seilx build ./out --key ./keys/private_key.pem --identity ./identity.json
```

`identity.json` shape (all fields free-form, verifier surfaces them):

```json
{
  "key_id": "seilx-signing-2026-01",
  "publisher": "SEILX",
  "published_at": "2026-01-15",
  "source_urls": [
    "https://github.com/…/public_key.pem",
    "https://seil.group/keys/seilx-signing-2026-01.pem"
  ],
  "fingerprint_sha256": "…"
}
```

The verifier still cannot fetch and compare the key for you — that step
is out-of-band by design. It surfaces the URLs so a reviewer knows
where to look.

## Cross-implementation JCS check

RFC 8785 has one correctness bar that matters: two independent
implementations must produce the same bytes for the same input. If you
have a second implementation (e.g. a Python `rfc8785` reference), run:

```sh
# This CLI
seilx canonicalize examples/Evidence_Packet_001/evidence.json | sha256sum

# Other implementation
python3 -c 'import rfc8785, json, hashlib, sys; \
  print(hashlib.sha256(rfc8785.dumps(json.load(open(sys.argv[1])))).hexdigest())' \
  examples/Evidence_Packet_001/evidence.json
```

Both digests MUST match. A mismatch is a canonicalisation bug — find it
here, not mid-pilot.

## Hardening test matrix (`seilx test`)

```sh
./bin/seilx.mjs test
```

Runs the full v0.1 hardening matrix and returns a table plus a JSON
summary. It exercises:

- **JCS vectors** (`cli/tests/vectors.json`) — canonical bytes and
  SHA-256 supplied by an independent Python `rfc8785` implementation.
  Every positive vector must produce the exact same bytes and hash.
- **SEILX profile must-reject rules** — unsafe integers
  (outside `-(2^53-1) .. 2^53-1`), duplicate JSON property names, lone
  Unicode surrogates, `NaN`, `Infinity`.
- **Tamper tests** — a one-byte semantic change in `evidence.json`
  produces a `FAILED` line naming the file; a semantic change inside
  `association.json` produces BOTH a hash mismatch AND a signature
  failure.
- **Identity binding** — a packet-local key produces `WARN`, never
  `PASS`. An `identity.json` full of URLs is metadata and does NOT
  upgrade identity to `PASS`. Only `seilx verify --external-key <pem>`
  (out-of-band retrieval) can upgrade it, after fingerprints match.
- **Temporal anchoring** — absence of RFC 3161 tokens produces
  `WARN/SKIP`, never `PASS`. A valid `.tsr` verified against a
  configured CA is required for `PASS`.

## SEILX numeric interoperability profile

SEILX layers a strict input profile on top of RFC 8785 to guarantee
cross-implementation determinism:

> Values outside the interoperable integer range may lose precision
> when represented as IEEE 754 numbers, and libraries may enforce
> different input-domain restrictions. The SEILX profile therefore
> prohibits unsafe integers.

Concretely, the profile rejects, before canonicalisation:

- integer literals outside `-(2^53-1) .. 2^53-1` (represent as strings if you need them);
- exponent notation in numeric literals (`1e+30`, `1e-7`, etc.) — represent as
  a decimal within the safe range, or as a string;
- duplicate JSON property names;
- lone Unicode surrogate code points;
- `NaN`, `+Infinity`, `-Infinity`;
- non-JSON runtime values: `undefined`, `BigInt`, functions, symbols.

These are SEILX interoperability constraints, **not direct RFC 8785
requirements**. RFC 8785 defines how to serialize valid JSON; SEILX
narrows the acceptable input so two languages cannot silently disagree.

> **Note on exponent notation.** RFC 8785 permits and specifies exponent
> output for very large / very small floats. SEILX v0.1 disallows it on
> input so canonical output never uses `e`/`E`, removing one class of
> cross-implementation disagreement about when the exponent form kicks
> in. The profile can be relaxed in a later version if a real need
> appears; v0.1 chooses the smaller, sharper rule.

## Identity verification (external key)

Identity status is `WARN` by default — a signature from a
packet-local key proves internal consistency, nothing about
authorship. To upgrade to `PASS`, fetch the claimed public key from a
published, out-of-packet location and pass it to the verifier:

```sh
seilx verify ./Evidence_Packet_001 --external-key ./published_key.pem
```

The verifier computes the SHA-256 fingerprint of the external key and
compares it to the packet's `public_key.pem`. `PASS` requires an exact
match; `FAIL` on mismatch. No URL list inside the packet can substitute
for this step.

## Reproducible builds

`seilx build` is byte-for-byte reproducible when given a fixed key and a
fixed timestamp:

```sh
seilx keygen ./keys
seilx build /tmp/pkt-a --key ./keys/private_key.pem \
  --source-date 2026-07-01T00:00:00Z
seilx build /tmp/pkt-b --key ./keys/private_key.pem \
  --source-date 2026-07-01T00:00:00Z
diff /tmp/pkt-a/hashes.sha256 /tmp/pkt-b/hashes.sha256   # empty
```

`--source-date` freezes every embedded timestamp
(`evidence.observed_at`, `neomundi.measured_at`, `association.created_at`,
`manifest.built_at`). The env var `SOURCE_DATE_EPOCH` (integer seconds)
is honoured when `--source-date` is absent. Ed25519 signatures are
deterministic by definition, so a fixed key + fixed input produces the
same `signature.sig`. `manifest.reproducibility.mode` records whether
the build was `deterministic` or `non-deterministic`.

Rebuilds by an independent party using the same command and inputs must
produce identical hashes — that is the reproducibility claim.

## Machine-readable verification report

```sh
seilx verify ./Evidence_Packet_001 --json > verify-report.json
```

Stable schema `seilx-verify-report/0.1`:

```json
{
  "schema_version": "seilx-verify-report/0.1",
  "tool": { "name": "seilx", "version": "0.1.0" },
  "verified_at": "…",
  "packet_dir": "…",
  "ok": true,
  "summary": { "pass": 9, "warn": 2, "fail": 0, "status": "WARN" },
  "checks": [ { "name": "…", "status": "PASS|WARN|FAIL", "detail": "…", "file": "…" } ]
}
```

Intended for CI, audit logging, and downstream tooling. The human-facing
text output is not a stable interface — parse the JSON instead. Exit
code is non-zero only on FAIL; WARN exits zero.

## Review package (bundle for an independent reviewer)

```sh
seilx package ./Evidence_Packet_001 --out ./Evidence_Packet_001.tar.gz
```

Produces a portable `tar.gz` (deterministic ordering, fixed mtime, no
owner metadata) plus a `REVIEW.md` inside the packet with:

- an ordered reviewer checklist (`sha256sum -c`, signature verify,
  identity out-of-band, RFC 3161, `--json` report);
- the expected SHA-256 of every top-level file at packaging time, for
  out-of-band comparison;
- reproducibility instructions when the packet was built deterministically.

The command also prints the SHA-256 of the archive itself. Send that
hash out-of-band (email, signed message, published on `seil.group`) so
the reviewer can confirm the archive was not modified in transit before
they even open it.