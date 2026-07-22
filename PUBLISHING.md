# SEILX v0.1 — Reviewer's guide (5-minute reproduction)

**Synthetic reference implementation. Not a production system.**
This guide is for an independent reviewer (e.g. Ramon, Sébastien) who
has received a SEILX Evidence Packet and wants to reproduce every
verification claim from scratch, without contacting the packet author.

You need only three things:

- the packet directory (e.g. `Evidence_Packet_001/` or its `.tar.gz`),
- the SEILX public key (`seilx_public.pem`), fetched from a stable URL
  published separately by SEILX (GitHub repo / SEILX domain),
- the SEILX public-key fingerprint (SHA-256), quoted separately from
  the file itself (release notes / signed announcement / DNS TXT).

And two standard tools: `openssl` and `sha256sum` (both preinstalled on
macOS and Linux). The SEILX CLI is optional convenience.

---

## 0. Get the packet

```sh
# Either receive a .tar.gz and unpack:
tar -xzf Evidence_Packet_001.tar.gz
cd Evidence_Packet_001

# Or clone/download the directory directly.
```

## 1. Get the SEILX public key (out-of-packet)

Fetch the key from the URL SEILX publishes it at — NOT from inside the
packet. The whole point is that the key is retrievable independently.

```sh
curl -o seilx_public.pem https://<seilx-stable-url>/seilx_public.pem
```

## 2. Verify the fingerprint of the downloaded key

Take the SHA-256 fingerprint SEILX quoted out-of-band and confirm it
matches the file you just downloaded. If it does not match, STOP — you
have the wrong key.

```sh
# Expected fingerprint (example — replace with the one SEILX quoted):
EXPECTED=975dc0d6c03ce5c083c0f2b0913a420d8365c739baba512164e1c9fff826c9d2

# Compute the actual fingerprint of the trimmed PEM:
ACTUAL=$(awk 'NF' seilx_public.pem | sha256sum | awk '{print $1}')
echo "expected=$EXPECTED"
echo "actual  =$ACTUAL"
test "$EXPECTED" = "$ACTUAL" && echo "FINGERPRINT OK" || echo "FINGERPRINT MISMATCH — STOP"
```

## 3. Run the verifier

### With the SEILX CLI (recommended, 1 command):

```sh
seilx verify . \
  --external-key ../seilx_public.pem \
  --external-fingerprint "$EXPECTED"
```

### Without the CLI, using only standard tools:

```sh
# 3a. File integrity
sha256sum -c hashes.sha256   # every line must print OK

# 3b. Signature over the association
#   (any RFC 8785 (JCS) canonicaliser works; seilx canonicalize is one)
seilx canonicalize association.json > /tmp/assoc.canonical
openssl pkeyutl -verify -pubin -inkey public_key.pem \
  -rawin -in /tmp/assoc.canonical -sigfile signature.sig
# expected: Signature Verified Successfully

# 3c. Identity binding
sha256sum public_key.pem              # must equal $EXPECTED
diff public_key.pem ../seilx_public.pem   # must be empty

# 3d. RFC 3161 timestamps (if timestamps/*.tsr present)
for tsr in timestamps/*.tsr; do
  base=$(basename "$tsr" .tsr)
  case "$base" in
    evidence)    data=evidence.json ;;
    neomundi)    data=neomundi_artifact.json ;;
    association) data=association.json ;;
  esac
  openssl ts -verify -data "$data" -in "$tsr" \
    -CAfile timestamps/tsa_ca.pem -untrusted timestamps/tsa.crt
  openssl ts -reply -in "$tsr" -text | grep 'Time stamp'
done
# association.tsr's genTime MUST be strictly later than every other .tsr.
```

## 4. How to read the result

| Line             | Meaning                                                                                                                        |
|------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `PASS  identity` | The packet's signing key matches SEILX's independently-published key. The signature therefore identifies SEILX.                |
| `PASS  signature`| The signed bytes are the RFC 8785 canonical bytes of `association.json`. Any tampering with the association breaks this.       |
| `PASS  hashes`   | Every file on disk matches the checksum SEILX recorded at build time.                                                          |
| `PASS  association:hash` | Each artifact's canonical SHA-256 equals the hash the association references. Substituting a file would break this.    |
| `PASS  timestamps:verify` | A trusted TSA cryptographically attests that each artifact existed no later than the asserted `genTime`.              |
| `PASS  timestamps:order`  | The association's `genTime` is strictly later than every source artifact's `genTime`. Construction order is proven.    |
| `WARN`           | A check the packet does not currently answer (e.g. no timestamps supplied). Not a failure, but not proof either.               |
| `FAIL`           | A cryptographic check failed. The packet has been modified, is malformed, or the identity does not match. **Reject the packet.** |

The final line summarises:

- `VERIFIED — all checks passed.` — full green run.
- `VERIFIED with N warning(s)` — cryptography holds, but some claim is
  not yet provable from the material provided. Read the WARN lines.
- `VERIFICATION FAILED` — at least one FAIL. Do not treat the packet
  as evidence.

For CI / logging:

```sh
seilx verify . --external-key seilx_public.pem --json > verify-report.json
```

Schema: `seilx-verify-report/0.1`. Exit code is non-zero on FAIL.

## 5. Tamper test (optional, ~10 seconds)

Prove to yourself the verifier actually catches modification:

```sh
cp evidence.json evidence.json.bak
sed -i.bak 's/0.42/0.43/' evidence.json      # flip one digit
seilx verify . --external-key ../seilx_public.pem
# expected: FAIL hashes.sha256 [evidence.json] + FAIL association:hash
mv evidence.json.bak evidence.json           # restore
```

## 6. What a PASS does and does NOT prove

A fully green run proves:

- the packet has not been modified since SEILX built it;
- the association references exactly the artifacts on disk (by canonical SHA-256);
- the association was signed by the key SEILX publishes;
- each artifact existed no later than its TSA-asserted `genTime`;
- the association was anchored strictly after the source artifacts.

It does NOT prove:

- that any referenced measurement is *true* (SEILX asserts linkage, not content correctness);
- that the signing key belongs to any specific legal entity (out-of-band trust decision);
- legal admissibility.

---

## 7. If you get stuck

Report back with:

- the exact command you ran,
- the full stdout/stderr,
- `seilx verify . --json` output if you have the CLI,
- the SHA-256 of the `.tar.gz` you received (`sha256sum Evidence_Packet_001.tar.gz`).

Independent reproduction is the point. If something differs on your
machine from what the packet claims, that's the signal — do not paper
over it.