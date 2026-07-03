// Fail-closed function-definition signature verification for the recipe executor.
//
// The encodingRecipe drives how cleartext domain data is laid out before the
// toolkit encrypts it, so an unsigned or altered function-def must NOT be trusted
// here. This mirrors the C++ toolkit (core/src/registry/{canonical_json,signature,
// trust_root}) byte-for-byte: the platform registry Ed25519 signature is verified
// over the ALLOWLIST canonical bytes (incl. opsHash, which we take verbatim - the
// toolkit never sees `ops`) against the PINNED registry public key.

import { createPublicKey, verify as edVerify } from "node:crypto";

// Pinned platform registry Ed25519 public key (32 raw bytes, hex). Pinned, never
// fetched from the server we are verifying. Rotating it is a toolkit release.
const REGISTRY_PUBLIC_KEY_HEX =
  "8f421fa667a2f6702e425b6be1b2f3604e1a7fbf57a01415d7951b4ce477d836";

function canonicalJson(obj) {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj === "boolean" || typeof obj === "number") return JSON.stringify(obj);
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys
    .filter((k) => obj[k] !== undefined)
    .map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k]))
    .join(",") + "}";
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj && obj[k] !== undefined) out[k] = obj[k];
  return out;
}

const INPUT_KEYS = ["name", "role", "encoding", "layout", "schema", "schemaParams"];

// Allowlist fingerprint - MUST stay byte-identical to the platform + C++ toolkit.
export function functionDefinitionCanonicalBytes(def) {
  const inputs = Array.isArray(def.inputs)
    ? def.inputs.map((inp) => (inp && typeof inp === "object" ? pick(inp, INPUT_KEYS) : inp))
    : def.inputs;
  const output = def.output && typeof def.output === "object"
    ? pick(def.output, ["name", "layout"]) : def.output;
  const fp = {
    slug: def.slug,
    version: def.version,
    scheme: def.scheme,
    cryptoContextSpec: def.cryptoContextSpec,
    requiredEvalKeys: def.requiredEvalKeys ?? null,
    inputs,
    opsHash: def.opsHash,
    output,
  };
  return Buffer.from(canonicalJson(fp), "utf-8");
}

// True iff `def` carries a valid platform-registry signature over its canonical bytes.
export function verifyFunctionDefSignature(def) {
  const sigB64 = def && def.registry && def.registry.signature;
  if (typeof sigB64 !== "string" || sigB64.length === 0) return false;
  let sig;
  try { sig = Buffer.from(sigB64, "base64"); } catch { return false; }
  if (sig.length !== 64) return false;
  const msg = functionDefinitionCanonicalBytes(def);
  const spki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(REGISTRY_PUBLIC_KEY_HEX, "hex"),
  ]);
  let key;
  try { key = createPublicKey({ key: spki, format: "der", type: "spki" }); }
  catch { return false; }
  try { return edVerify(null, msg, key, sig); } catch { return false; }
}
