// RFC 3161 timestamp acquisition against a public TSA.
//
// Design commitments:
//   * Every artifact gets a FRESH .tsq (a fresh nonce). We never reuse an
//     old query — the nonce binds request to response, and reusing one
//     would produce a response that can't be tied to the current data.
//   * -cert is passed to `openssl ts -query` so the TSA response includes
//     the TSA signing certificate where supported (freetsa.org does).
//   * We ALSO fetch the TSA signing certificate separately and pass it
//     via `-untrusted` to `openssl ts -verify`, which is required by
//     freetsa.org's chain. Verification is against an explicitly trusted
//     CA file — no implicit system trust.
//   * We shell out to `openssl` for every ASN.1-touching operation.
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, basename } from "node:path";
import { createTimestampQuery, verifyTimestamp, readTimestampGenTime, sha256HexOfFile, haveOpenssl } from "./tsr.ts";

export interface TimestampOptions {
  packetDir: string;
  tsaUrl?: string; // default: https://freetsa.org/tsr
  caUrl?: string; // default: https://freetsa.org/files/cacert.pem
  tsaCertUrl?: string; // default: https://freetsa.org/files/tsa.crt
  artifacts?: string[]; // default: evidence.json, neomundi_artifact.json, association.json
}

export interface TimestampReport {
  tsa_url: string;
  ca_source: string;
  tsa_cert_source: string;
  results: TimestampArtifactReport[];
  final_status: "PASS" | "WARN" | "FAIL";
  order_status: "PASS" | "WARN" | "FAIL";
  order_detail: string;
}

export interface TimestampArtifactReport {
  artifact: string;
  artifact_sha256: string;
  tsq_file: string;
  tsr_file: string;
  query_command: string;
  verify_command: string;
  tsa_gen_time: string | null;
  verify_ok: boolean;
  verify_stdout: string;
  verify_stderr: string;
}

async function fetchToFile(url: string, path: string): Promise<void> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status} ${res.statusText}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(path, buf);
}

async function submitTsq(url: string, tsqPath: string, tsrPath: string): Promise<void> {
  const body = await readFile(tsqPath);
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: new Uint8Array(body),
  });
  if (!res.ok) throw new Error(`POST ${url} -> HTTP ${res.status} ${res.statusText}`);
  const ct = res.headers.get("content-type") ?? "";
  if (!/application\/timestamp-reply/i.test(ct)) {
    // Some TSAs still return the reply without the exact content-type;
    // don't hard-fail here, but include it in output for debugging.
  }
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(tsrPath, buf);
}

export async function acquireTimestamps(opts: TimestampOptions): Promise<TimestampReport> {
  if (!haveOpenssl()) {
    throw new Error("openssl not found on PATH — required for RFC 3161 operations.");
  }
  const tsaUrl = opts.tsaUrl ?? "https://freetsa.org/tsr";
  const caUrl = opts.caUrl ?? "https://freetsa.org/files/cacert.pem";
  const tsaCertUrl = opts.tsaCertUrl ?? "https://freetsa.org/files/tsa.crt";
  const artifacts = opts.artifacts ?? [
    "evidence.json",
    "neomundi_artifact.json",
    "association.json",
  ];

  const tsDir = join(opts.packetDir, "timestamps");
  await mkdir(tsDir, { recursive: true });

  const caPath = join(tsDir, "tsa_ca.pem");
  const tsaCertPath = join(tsDir, "tsa.crt");
  if (!existsSync(caPath)) await fetchToFile(caUrl, caPath);
  if (!existsSync(tsaCertPath)) await fetchToFile(tsaCertUrl, tsaCertPath);

  const results: TimestampArtifactReport[] = [];
  // Enforced anchor delay: association.json must be anchored strictly
  // after every source artifact by more than the TSA's time resolution
  // (1 s for freetsa.org). Otherwise construction order is not
  // demonstrable at TSA granularity. Two seconds is the minimum honest
  // margin; we sleep BEFORE association.json.
  const ANCHOR_DELAY_MS = 2500;
  for (const artifact of artifacts) {
    if (artifact === "association.json") {
      await new Promise((r) => setTimeout(r, ANCHOR_DELAY_MS));
    }
    const artifactPath = join(opts.packetDir, artifact);
    if (!existsSync(artifactPath)) throw new Error(`Artifact not found: ${artifactPath}`);
    const stem = basename(artifact, ".json").replace(/_artifact$/, "");
    const tsqPath = join(tsDir, `${stem}.tsq`);
    const tsrPath = join(tsDir, `${stem}.tsr`);

    // Fresh nonce every call.
    createTimestampQuery(artifactPath, tsqPath);
    const queryCommand = `openssl ts -query -data ${artifact} -sha256 -cert -out timestamps/${stem}.tsq`;

    await submitTsq(tsaUrl, tsqPath, tsrPath);

    const v = verifyTimestamp(artifactPath, tsrPath, caPath, tsaCertPath);
    const gt = readTimestampGenTime(tsrPath);
    results.push({
      artifact,
      artifact_sha256: sha256HexOfFile(artifactPath),
      tsq_file: `timestamps/${stem}.tsq`,
      tsr_file: `timestamps/${stem}.tsr`,
      query_command: queryCommand,
      verify_command: v.command,
      tsa_gen_time: gt ? gt.toISOString() : null,
      verify_ok: v.ok,
      verify_stdout: v.stdout,
      verify_stderr: v.stderr,
    });
  }

  // Construction-order check: association.tsr genTime must be >= every other.
  const assoc = results.find((r) => r.artifact === "association.json");
  let order_status: "PASS" | "WARN" | "FAIL" = "PASS";
  let order_detail = "association strictly later than every source anchor.";
  if (assoc && assoc.tsa_gen_time) {
    const assocT = new Date(assoc.tsa_gen_time).getTime();
    for (const r of results) {
      if (r === assoc || !r.tsa_gen_time) continue;
      const t = new Date(r.tsa_gen_time).getTime();
      if (t > assocT) {
        order_status = "FAIL";
        order_detail = `${r.artifact} genTime (${r.tsa_gen_time}) is AFTER association.json genTime (${assoc.tsa_gen_time}).`;
        break;
      } else if (t === assocT && order_status !== "FAIL") {
        order_status = "WARN";
        order_detail = `anchor order not demonstrable at TSA time granularity: ${r.artifact} and association.json share the same asserted second (${assoc.tsa_gen_time}).`;
      }
    }
  } else {
    order_status = "FAIL";
    order_detail = "association.json has no parseable genTime.";
  }

  const allVerified = results.every((r) => r.verify_ok);
  const final_status: "PASS" | "WARN" | "FAIL" = !allVerified
    ? "FAIL"
    : order_status === "FAIL"
    ? "FAIL"
    : order_status === "WARN"
    ? "WARN"
    : "PASS";

  return {
    tsa_url: tsaUrl,
    ca_source: caUrl,
    tsa_cert_source: tsaCertUrl,
    results,
    final_status,
    order_status,
    order_detail,
  };
}

export function formatTimestampReport(r: TimestampReport): string {
  const out: string[] = [];
  out.push(`RFC 3161 timestamp acquisition report`);
  out.push(`====================================`);
  out.push(`TSA URL:          ${r.tsa_url}`);
  out.push(`CA source:        ${r.ca_source}  -> timestamps/tsa_ca.pem`);
  out.push(`TSA cert source:  ${r.tsa_cert_source}  -> timestamps/tsa.crt`);
  out.push("");
  for (const a of r.results) {
    out.push(`Artifact:              ${a.artifact}`);
    out.push(`  SHA-256:             ${a.artifact_sha256}`);
    out.push(`  Query command:       ${a.query_command}`);
    out.push(`  Verify command:      ${a.verify_command}`);
    out.push(`  TSA asserted time:   ${a.tsa_gen_time ?? "(unparseable)"}`);
    out.push(`  Chain verify:        ${a.verify_ok ? "OK" : "FAIL"}`);
    if (a.verify_stdout) out.push(`  openssl stdout:\n${indent(a.verify_stdout, "    ")}`);
    if (a.verify_stderr) out.push(`  openssl stderr:\n${indent(a.verify_stderr, "    ")}`);
    out.push("");
  }
  out.push(`FINAL STATUS: ${r.final_status}`);
  out.push(`Order status: ${r.order_status} — ${r.order_detail}`);
  out.push(
    "Note: RFC 3161 proves existence-no-later-than the asserted time. Ordering is only proven where the TSA's time resolution (typically 1 s) distinguishes the events.",
  );
  return out.join("\n");
}

function indent(s: string, pad: string): string {
  return s
    .split("\n")
    .map((l) => pad + l)
    .join("\n");
}