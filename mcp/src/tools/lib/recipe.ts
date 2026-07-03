// Recipe executor + function-def signature verification for the MCP encrypt path.
// TypeScript port of examples/_core/recipe/{executor,verify-def}.mjs so the MCP can
// run a function-def input's encodingRecipe (encrypted-bundle layout) into the
// toolkit's generic bundle-input BEFORE crypto encrypt, fail-closed on the def's
// registry signature (pinned key). Keep in sync with the .mjs versions.

import { createPublicKey, verify as edVerify } from 'node:crypto';

export const REGISTRY_VERSION = 1;
const REGISTRY_PUBLIC_KEY_HEX = '8f421fa667a2f6702e425b6be1b2f3604e1a7fbf57a01415d7951b4ce477d836';

type Scope = { root: any; item: any };

function resolveToken(tpl: unknown, scope: Scope): unknown {
  if (typeof tpl !== 'string') return tpl;
  const m = tpl.match(/^\{([^}]+)\}$/);
  if (!m) return tpl;
  const key = m[1];
  if (key === '.') return scope.item;
  if (scope.item && typeof scope.item === 'object' && !Array.isArray(scope.item) && scope.item[key] !== undefined) return scope.item[key];
  if (scope.root && scope.root[key] !== undefined) return scope.root[key];
  throw new Error(`unresolved template '{${key}}' (not on current item or source root)`);
}

function resolveHeaderLine(line: string, root: any): string {
  return line.replace(/\{([^}]+)\}/g, (_m, k) => {
    if (root[k] === undefined) throw new Error(`unresolved header token '{${k}}'`);
    return String(root[k]);
  });
}

const PRIMITIVES: Record<string, (args: any, scope: Scope) => unknown[]> = {
  'one-hot'({ index, length }, scope) {
    const i = Number(resolveToken(index, scope));
    const n = Number(resolveToken(length, scope));
    if (!Number.isInteger(n) || n <= 0) throw new Error(`one-hot length must be a positive int, got ${n}`);
    if (i < 0 || i >= n) throw new Error(`one-hot index ${i} out of range [0,${n})`);
    const v = new Array(n).fill(0); v[i] = 1; return [v];
  },
  fill({ value, length }, scope) {
    const x = Number(resolveToken(value, scope));
    const len = resolveToken(length, scope);
    if (len === 'slotCount') return [{ fill: x }];
    const n = Number(len);
    if (!Number.isInteger(n) || n <= 0) throw new Error('fill length must be "slotCount" or a positive int');
    return [new Array(n).fill(x)];
  },
  'to-slots'({ values }, scope) {
    const arr = resolveToken(values, scope);
    if (!Array.isArray(arr)) throw new Error('to-slots values must resolve to an array');
    return [arr.map(Number)];
  },
  'one-hot-scalars'({ index, length }, scope) {
    const i = Number(resolveToken(index, scope));
    const n = Number(resolveToken(length, scope));
    if (!Number.isInteger(n) || n <= 0) throw new Error(`one-hot-scalars length must be a positive int, got ${n}`);
    if (i < 0 || i >= n) throw new Error(`one-hot-scalars index ${i} out of range [0,${n})`);
    const out: unknown[] = [];
    for (let k = 0; k < n; k++) out.push({ fill: k === i ? 1 : 0 });
    return out;
  },
};

function emit(spec: any, scope: Scope, ctx: { root: any; vectors: unknown[] }) {
  const name = Object.keys(spec)[0];
  const fn = PRIMITIVES[name];
  if (!fn) throw new Error(`unknown primitive '${name}'`);
  for (const v of fn(spec[name], scope)) ctx.vectors.push(v);
}

function runStep(step: any, ctx: { root: any; vectors: unknown[] }) {
  const name = Object.keys(step)[0];
  if (name === 'map-over') {
    const { path, emit: emitList } = step['map-over'];
    const arr = ctx.root[path];
    if (!Array.isArray(arr)) throw new Error(`map-over path '${path}' is not an array`);
    for (const item of arr) { const scope = { root: ctx.root, item }; for (const sub of emitList) emit(sub, scope, ctx); }
    return;
  }
  if (name === 'collect-bundle') return;
  emit(step, { root: ctx.root, item: ctx.root }, ctx);
}

export function runRecipe(recipe: any, source: any): { header: string[]; vectors: unknown[] } {
  if (recipe.version !== REGISTRY_VERSION) throw new Error(`unsupported encodingRecipe.version ${recipe.version} (executor supports ${REGISTRY_VERSION})`);
  if (recipe.target !== 'encrypted-bundle') throw new Error(`this executor handles target "encrypted-bundle"; got "${recipe.target}"`);
  const ctx = { root: source, vectors: [] as unknown[] };
  for (const step of recipe.steps || []) runStep(step, ctx);
  const header = (recipe.header || []).map((l: string) => resolveHeaderLine(l, source));
  return { header, vectors: ctx.vectors };
}

// ---- fail-closed function-def signature verification (port of verify-def.mjs) ----
function canonicalJson(obj: unknown): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean' || typeof obj === 'number') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']';
  const rec = obj as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return '{' + keys.filter((k) => rec[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canonicalJson(rec[k])).join(',') + '}';
}
function pick(obj: any, keys: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of keys) if (obj && obj[k] !== undefined) out[k] = obj[k];
  return out;
}
const INPUT_KEYS = ['name', 'role', 'encoding', 'layout', 'schema', 'schemaParams'];
function functionDefinitionCanonicalBytes(def: any): Buffer {
  const inputs = Array.isArray(def.inputs) ? def.inputs.map((inp: any) => (inp && typeof inp === 'object' ? pick(inp, INPUT_KEYS) : inp)) : def.inputs;
  const output = def.output && typeof def.output === 'object' ? pick(def.output, ['name', 'layout']) : def.output;
  const fp = { slug: def.slug, version: def.version, scheme: def.scheme, cryptoContextSpec: def.cryptoContextSpec, requiredEvalKeys: def.requiredEvalKeys ?? null, inputs, opsHash: def.opsHash, output };
  return Buffer.from(canonicalJson(fp), 'utf-8');
}
export function verifyFunctionDefSignature(def: any): boolean {
  const sigB64 = def?.registry?.signature;
  if (typeof sigB64 !== 'string' || sigB64.length === 0) return false;
  let sig: Buffer;
  try { sig = Buffer.from(sigB64, 'base64'); } catch { return false; }
  if (sig.length !== 64) return false;
  const msg = functionDefinitionCanonicalBytes(def);
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(REGISTRY_PUBLIC_KEY_HEX, 'hex')]);
  let key;
  try { key = createPublicKey({ key: spki, format: 'der', type: 'spki' }); } catch { return false; }
  try { return edVerify(null, msg, key, sig); } catch { return false; }
}
