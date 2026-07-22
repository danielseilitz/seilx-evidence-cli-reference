# Timestamps

Place RFC 3161 responses here after obtaining them from a real TSA:

- `evidence.tsr`      — timestamp of `../evidence.json`
- `neomundi.tsr`      — timestamp of `../neomundi_artifact.json`
- `association.tsr`   — timestamp of `../association.json`
- `tsa_ca.pem`        — TSA CA chain used for `openssl ts -verify`

Generate a request with:

```sh
openssl ts -query -data ../evidence.json -sha256 -cert -out evidence.tsq
curl -sS -H 'Content-Type: application/timestamp-query' \
  --data-binary @evidence.tsq https://freetsa.org/tsr > evidence.tsr
```

Construction-order rule: `association.tsr.genTime` MUST be >= every artifact `.tsr.genTime`.
