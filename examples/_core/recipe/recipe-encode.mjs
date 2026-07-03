#!/usr/bin/env node
// recipe-encode: run a function-def input's `encodingRecipe` against a source
// file and write the toolkit's generic bundle-input JSON. Cleartext, no keys.
// The _core encrypt step calls this, then hands the output to
// `julenny-fhe crypto encrypt` (which encrypts it under the joint key).
//
// usage: node recipe-encode.mjs <function-def.json> <input-name> <source> <out.json>
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runRecipe } from "./executor.mjs";
import { verifyFunctionDefSignature } from "./verify-def.mjs";

const [, , defPath, inputName, srcPath, outPath] = process.argv;
if (!defPath || !inputName || !srcPath || !outPath) {
  console.error("usage: recipe-encode <function-def.json> <input-name> <source> <out.json>");
  process.exit(2);
}

const def = JSON.parse(readFileSync(defPath, "utf8"));
if (!verifyFunctionDefSignature(def)) {
  console.error(`recipe-encode: function-definition signature verification FAILED for ${defPath}`);
  console.error("  refusing to run the encodingRecipe: the definition is unsigned or has been altered.");
  console.error("  the function id must carry a valid JuLenny registry signature.");
  process.exit(1);
}
const input = (def.inputs || []).find((i) => i.name === inputName);
if (!input) { console.error(`recipe-encode: no input named '${inputName}' in function-def`); process.exit(1); }

const recipe = input.encodingRecipe;
if (!recipe) {
  console.error(`recipe-encode: input '${inputName}' has no encodingRecipe in the function-def.`);
  console.error("  The platform must serve encodingRecipe on /api/functions/<slug>/<ver>/definition.");
  process.exit(1);
}

let source;
if (recipe.source === "json") {
  source = JSON.parse(readFileSync(srcPath, "utf8"));
} else {
  console.error(`recipe-encode: unsupported recipe.source '${recipe.source}' (this build handles 'json')`);
  process.exit(1);
}

const bundleInput = runRecipe(recipe, source);
writeFileSync(outPath, JSON.stringify(bundleInput, null, 2) + "\n");
console.error(`recipe-encode: ${bundleInput.vectors.length} vectors -> ${outPath}`);
