// Executor for a function-def input's `encodingRecipe` (registry v1).
//
// PURE CLEARTEXT data wrangling: turns a raw domain object + a recipe into the
// toolkit's generic bundle-input { header:[...], vectors:[...] }. No keys, no
// crypto. The toolkit's `crypto encrypt` (layout=encrypted-bundle) then encrypts
// the result. Keeping this OUT of the toolkit is what lets new functions ship
// without a toolkit rebuild. Mirrors the MCP server's executor; both implement
// the same versioned primitive registry (see .plans/recipe-executor/registry.md).
//
// Template scope: "{key}" resolves against the CURRENT item first, then the
// source ROOT. "{.}" is the current item itself. Other strings are literals.

export const REGISTRY_VERSION = 1;

function resolveToken(tpl, scope) {
  if (typeof tpl !== "string") return tpl;
  const m = tpl.match(/^\{([^}]+)\}$/);
  if (!m) return tpl; // literal (e.g. "slotCount")
  const key = m[1];
  if (key === ".") return scope.item;
  if (scope.item && typeof scope.item === "object" && !Array.isArray(scope.item)
      && scope.item[key] !== undefined) return scope.item[key];
  if (scope.root && scope.root[key] !== undefined) return scope.root[key];
  throw new Error(`unresolved template '{${key}}' (not on current item or source root)`);
}

function resolveHeaderLine(line, root) {
  return line.replace(/\{([^}]+)\}/g, (_, k) => {
    if (root[k] === undefined) throw new Error(`unresolved header token '{${k}}'`);
    return String(root[k]);
  });
}

const PRIMITIVES = {
  "one-hot"({ index, length }, scope) {
    const i = Number(resolveToken(index, scope));
    const n = Number(resolveToken(length, scope));
    if (!Number.isInteger(n) || n <= 0) throw new Error(`one-hot length must be a positive int, got ${n}`);
    if (i < 0 || i >= n) throw new Error(`one-hot index ${i} out of range [0,${n})`);
    const v = new Array(n).fill(0);
    v[i] = 1;
    return [v];
  },
  fill({ value, length }, scope) {
    const x = Number(resolveToken(value, scope));
    const len = resolveToken(length, scope);
    if (len === "slotCount") return [{ fill: x }]; // toolkit replicates across all slots
    const n = Number(len);
    if (!Number.isInteger(n) || n <= 0) throw new Error(`fill length must be "slotCount" or a positive int`);
    return [new Array(n).fill(x)];
  },
  "to-slots"({ values }, scope) {
    const arr = resolveToken(values, scope);
    if (!Array.isArray(arr)) throw new Error(`to-slots values must resolve to an array, got ${JSON.stringify(arr)}`);
    return [arr.map(Number)];
  },
  // one-hot-scalars: emit `length` SEPARATE broadcast-scalar ciphertexts; the one
  // at `index` is 1.0, the rest 0.0. Rotation-free feature selection (each feature
  // is its own ciphertext; selection is a sum of scalar*feature, no cross-slot sum).
  // Replaces the single slot-packed `one-hot` vector for the decision-tree model.
  "one-hot-scalars"({ index, length }, scope) {
    const i = Number(resolveToken(index, scope));
    const n = Number(resolveToken(length, scope));
    if (!Number.isInteger(n) || n <= 0) throw new Error(`one-hot-scalars length must be a positive int, got ${n}`);
    if (i < 0 || i >= n) throw new Error(`one-hot-scalars index ${i} out of range [0,${n})`);
    const out = [];
    for (let k = 0; k < n; k++) out.push({ fill: k === i ? 1 : 0 }); // broadcast scalar per feature
    return out;
  },
};

function emit(spec, scope, ctx) {
  const name = Object.keys(spec)[0];
  const fn = PRIMITIVES[name];
  if (!fn) throw new Error(`unknown primitive '${name}'`);
  for (const v of fn(spec[name], scope)) ctx.vectors.push(v);
}

function runStep(step, ctx) {
  const name = Object.keys(step)[0];
  if (name === "map-over") {
    const { path, emit: emitList } = step["map-over"];
    const arr = ctx.root[path];
    if (!Array.isArray(arr)) throw new Error(`map-over path '${path}' is not an array`);
    for (const item of arr) {
      const scope = { root: ctx.root, item };
      for (const sub of emitList) emit(sub, scope, ctx);
    }
    return;
  }
  if (name === "collect-bundle") return; // marker: vectors already collected in emission order
  emit(step, { root: ctx.root, item: ctx.root }, ctx); // bare top-level primitive
}

// recipe: the function-def input's `encodingRecipe`. source: parsed domain object.
export function runRecipe(recipe, source) {
  if (recipe.version !== REGISTRY_VERSION)
    throw new Error(`unsupported encodingRecipe.version ${recipe.version} (executor supports ${REGISTRY_VERSION})`);
  if (recipe.target !== "encrypted-bundle")
    throw new Error(`this executor handles target "encrypted-bundle"; got "${recipe.target}"`);
  const ctx = { root: source, vectors: [] };
  for (const step of recipe.steps || []) runStep(step, ctx);
  const header = (recipe.header || []).map((l) => resolveHeaderLine(l, source));
  return { header, vectors: ctx.vectors };
}
