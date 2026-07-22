// SEILX profile constraints on JSON values.
//
// These are SEILX interoperability rules, NOT direct RFC 8785 requirements.
// RFC 8785 defines canonicalization; SEILX layers a strict input profile on
// top so that independent implementations (TypeScript here, Python at the
// reviewer's side, other languages later) cannot silently disagree on what
// they canonicalize.
//
// Values outside the interoperable integer range may lose precision when
// represented as IEEE 754 numbers, and libraries may enforce different
// input-domain restrictions. The SEILX profile therefore prohibits unsafe
// integers. It also rejects NaN/Infinity, lone Unicode surrogates,
// duplicate JSON property names, and non-JSON runtime values.

export class SeilxProfileError extends Error {
  rule: string;
  path?: string;
  constructor(message: string, rule: string, path?: string) {
    super(message);
    this.name = "SeilxProfileError";
    this.rule = rule;
    this.path = path;
  }
}

export const SEILX_SAFE_INT_MAX = Number.MAX_SAFE_INTEGER; // 2^53 - 1
export const SEILX_SAFE_INT_MIN = -Number.MAX_SAFE_INTEGER;

function assertNoLoneSurrogate(s: string, path: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) {
        throw new SeilxProfileError(
          `Lone high surrogate U+${c.toString(16).toUpperCase()} at ${path}`,
          "lone_surrogate",
          path,
        );
      }
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new SeilxProfileError(
        `Lone low surrogate U+${c.toString(16).toUpperCase()} at ${path}`,
        "lone_surrogate",
        path,
      );
    }
  }
}

/** Value-level SEILX profile check on a runtime JS value. */
export function assertSeilxProfileValue(value: unknown, path = "$"): void {
  if (value === null) return;
  const t = typeof value;
  if (t === "boolean") return;
  if (t === "string") {
    assertNoLoneSurrogate(value as string, path);
    return;
  }
  if (t === "number") {
    const n = value as number;
    if (Number.isNaN(n)) throw new SeilxProfileError(`NaN not allowed at ${path}`, "nan", path);
    if (!Number.isFinite(n))
      throw new SeilxProfileError(`Infinity not allowed at ${path}`, "infinity", path);
      // SEILX v0.1 forbids values whose canonical JCS emission uses exponent
      // notation. JSON.stringify (which the canonicalize library relies on
      // for numbers) switches to exponent form for |n| >= 1e21 and for
      // non-zero |n| < 1e-6. Reject those at value-scan time so canonical
      // output never contains 'e'/'E'. See scanSeilxJsonText for the same
      // rule applied to raw JSON text.
      if (n !== 0 && /[eE]/.test(String(n))) {
        throw new SeilxProfileError(
          `Number ${String(n)} at ${path} would canonicalize to exponent notation. ` +
            `Exponent notation is disallowed in SEILX v0.1 (interoperability constraint, ` +
            `not an RFC 8785 requirement). Represent the value as a string, or use one ` +
            `whose decimal form fits without exponent (|n| < 1e21 and |n| >= 1e-6).`,
          "exponent_notation",
          path,
        );
      }
    // Note: we intentionally do NOT reject Number.isInteger(n) && !isSafeInteger
    // at the value level. A JS runtime number cannot distinguish the source
    // literal `1e30` (a valid RFC 8785 float) from an integer larger than
    // 2^53-1 — both surface as the same double. The unsafe-integer rule is
    // enforced at the JSON TEXT level (see scanSeilxJsonText), where the
    // literal form is unambiguous. Callers passing raw JS values are trusted
    // to have already validated their inputs against the SEILX profile.
    return;
  }
  if (t === "bigint") throw new SeilxProfileError(`BigInt not allowed at ${path}`, "bigint", path);
  if (t === "undefined")
    throw new SeilxProfileError(`undefined not allowed at ${path}`, "undefined", path);
  if (t === "function")
    throw new SeilxProfileError(`function not allowed at ${path}`, "function", path);
  if (t === "symbol") throw new SeilxProfileError(`symbol not allowed at ${path}`, "symbol", path);
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertSeilxProfileValue(v, `${path}[${i}]`));
    return;
  }
  if (t === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      assertNoLoneSurrogate(k, `${path}.<key>`);
      assertSeilxProfileValue(v, `${path}.${k}`);
    }
    return;
  }
}

/**
 * Text-level SEILX profile scan. Catches things a subsequent JSON.parse
 * would silently absorb: duplicate keys (JSON.parse keeps the last), integer
 * literals outside the safe range (JSON.parse rounds to IEEE 754), and
 * NaN/Infinity identifiers (some parsers permit them via reviver hacks).
 */
export function scanSeilxJsonText(text: string): void {
  let i = 0;
  const n = text.length;
  type Frame = { type: "obj"; keys: Set<string> } | { type: "arr" };
  const stack: Frame[] = [];
  let expectingKey = false;

  const skipWs = () => {
    while (i < n && (text[i] === " " || text[i] === "\n" || text[i] === "\r" || text[i] === "\t"))
      i++;
  };

  while (i < n) {
    skipWs();
    if (i >= n) break;
    const c = text[i];

    if (c === "{") {
      stack.push({ type: "obj", keys: new Set() });
      i++;
      skipWs();
      if (text[i] === "}") {
        stack.pop();
        i++;
        expectingKey = false;
        continue;
      }
      expectingKey = true;
      continue;
    }
    if (c === "[") {
      stack.push({ type: "arr" });
      i++;
      expectingKey = false;
      continue;
    }
    if (c === "}" || c === "]") {
      stack.pop();
      i++;
      expectingKey = false;
      continue;
    }
    if (c === ",") {
      i++;
      const top = stack[stack.length - 1];
      expectingKey = top?.type === "obj";
      continue;
    }
    if (c === ":") {
      i++;
      expectingKey = false;
      continue;
    }

    if (c === '"') {
      // Consume a JSON string literal, preserving raw escapes so we can
      // decode it via JSON.parse (surrogate check runs on the decoded form).
      i++;
      let raw = "";
      while (i < n) {
        const ch = text[i];
        if (ch === "\\") {
          if (i + 1 >= n) throw new SeilxProfileError("Truncated escape", "malformed_json");
          raw += ch + text[i + 1];
          i += 2;
          continue;
        }
        if (ch === '"') {
          i++;
          break;
        }
        raw += ch;
        i++;
      }
      let decoded: string;
      try {
        decoded = JSON.parse('"' + raw + '"');
      } catch {
        throw new SeilxProfileError("Malformed JSON string", "malformed_json");
      }
      assertNoLoneSurrogate(decoded, "string");
      const top = stack[stack.length - 1];
      if (top && top.type === "obj" && expectingKey) {
        if (top.keys.has(decoded)) {
          throw new SeilxProfileError(
            `Duplicate JSON property name: ${JSON.stringify(decoded)}`,
            "duplicate_key",
          );
        }
        top.keys.add(decoded);
      }
      continue;
    }

    // Numeric literal.
    if (c === "-" || (c >= "0" && c <= "9")) {
      const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i));
      if (!m) {
        throw new SeilxProfileError(`Malformed number at offset ${i}`, "malformed_json");
      }
      const tok = m[0];
      i += tok.length;
      // SEILX v0.1: forbid exponent notation in JSON text. RFC 8785 permits
      // exponent form for very large or very small floats, but SEILX narrows
      // the input profile so two implementations cannot disagree on when a
      // number is emitted as `1e+30` vs `1000000000000000000000000000000`.
      // This is a SEILX interoperability constraint, NOT an RFC 8785
      // requirement. Represent such values as strings if you need them.
      if (/[eE]/.test(tok)) {
        throw new SeilxProfileError(
          `Exponent notation not allowed in SEILX v0.1 (token: ${tok}). ` +
            `RFC 8785 permits it, but SEILX narrows the input profile for ` +
            `cross-implementation determinism. Represent as a decimal ` +
            `literal inside the safe range, or as a string.`,
          "exponent_notation",
        );
      }
      if (!/[.eE]/.test(tok)) {
        try {
          const b = BigInt(tok);
          if (b > BigInt(SEILX_SAFE_INT_MAX) || b < BigInt(SEILX_SAFE_INT_MIN)) {
            throw new SeilxProfileError(
              `Unsafe integer literal ${tok}: outside SEILX safe-integer range [-(2^53-1), 2^53-1]. ` +
                `Represent as a string, or use a value inside the safe range. This is a SEILX ` +
                `interoperability constraint, not an RFC 8785 requirement.`,
              "unsafe_integer",
            );
          }
        } catch (e) {
          if (e instanceof SeilxProfileError) throw e;
        }
      }
      continue;
    }

    // Identifier (true/false/null/NaN/Infinity/-Infinity)
    const idm = /^[A-Za-z]+/.exec(text.slice(i));
    if (idm) {
      const id = idm[0];
      if (id === "NaN" || id === "Infinity")
        throw new SeilxProfileError(`${id} not allowed in JSON`, "nan_or_infinity");
      if (id !== "true" && id !== "false" && id !== "null")
        throw new SeilxProfileError(`Unknown token: ${id}`, "malformed_json");
      i += id.length;
      continue;
    }

    // Anything else is malformed.
    throw new SeilxProfileError(`Unexpected character ${JSON.stringify(c)} at offset ${i}`, "malformed_json");
  }
}

/** Strict JSON parse under the SEILX profile. */
export function parseSeilxJson(text: string): unknown {
  scanSeilxJsonText(text);
  const value = JSON.parse(text);
  assertSeilxProfileValue(value);
  return value;
}