// RFC 8785 (JSON Canonicalization Scheme) via the established `canonicalize`
// library. We deliberately do NOT implement canonicalization by hand.
import canonicalize from "canonicalize";
import { assertSeilxProfileValue } from "./profile.ts";

export function canonicalJson(value: unknown): Buffer {
  // SEILX profile guard: reject NaN/Infinity, unsafe integers, lone
  // surrogates, and non-JSON runtime values before canonicalization so we
  // never emit bytes that another conformant implementation would reject
  // or hash differently.
  assertSeilxProfileValue(value);
  const str = canonicalize(value);
  if (typeof str !== "string") {
    throw new Error("canonicalize returned non-string; input is not JSON-serialisable");
  }
  // RFC 8785 §3.2.1 — output is UTF-8 encoded.
  return Buffer.from(str, "utf8");
}