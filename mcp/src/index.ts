#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { JulennyApiClient } from './api-client.js';
import { registerFunctionTools } from './tools/functions.js';
import { registerCollaborationTools } from './tools/collaborations.js';
import { registerPermissionTools } from './tools/permissions.js';
import { registerExecutionTools } from './tools/executions.js';
import { registerDatasetTools } from './tools/datasets.js';
import { registerAuditTools } from './tools/audit.js';
import { registerToolkitTools } from './tools/toolkit.js';
import { registerPipelineTools } from './tools/pipeline.js';
import { registerGuideTools } from './tools/guide.js';
import { workdir } from './tools/lib/paths.js';

const apiKey = process.env.JULENNY_API_KEY;
if (!apiKey) {
  console.error('JULENNY_API_KEY environment variable is required');
  process.exit(1);
}

const api = new JulennyApiClient(apiKey, process.env.JULENNY_API_URL);

// Server instructions: the canonical multi-party flow and its branch points.
// The verbs are ATOMIC primitives (one platform call or one local crypto op
// each) and BLIND by design (they return paths + status, never plaintext or
// secret bytes). This block is the map that tells an agent which verb to call
// when. For a live, state-derived answer at any moment, call `next_step` with
// your permissionId; this text is the reference it points back to.
const SERVER_INSTRUCTIONS = `JuLenny FHE toolkit - customer-side client for the JuLenny FHE Platform.

Two parties run a privacy-preserving computation (e.g. decision-tree inference)
where neither reveals its data and the platform only ever sees ciphertext. Each
party drives its own side with these verbs. They are atomic and blind: results
are file paths and status, never plaintext or secret key bytes.

THE WORKING FOLDER
  ${workdir()}

Every file argument is a NAME relative to that folder ("customers.csv"), never a
path. The server is confined there by design: absolute paths, '..' segments and
symlinks pointing outside are all rejected. Keys, inputs, ciphertexts and
results all live in that folder or below it.

This means you cannot read a file anywhere else on the user's machine, and there
is no permission you can request that would change that.

NEVER ask the user to grant filesystem or folder access, and never ask them to paste a
data file into the conversation. Blindness is the product, not a limitation to work
around: the user is paying for the guarantee that their plaintext never reaches a model.
Every verb here is designed so you do not need to see the contents of anything - if you
believe you are stuck without reading a file, you have missed a verb. Say so plainly and
name what you are missing, rather than asking for access. If the user offers it anyway,
decline and explain why. If the user's input
file is not in the working folder, do NOT ask them for its path and do NOT ask
for filesystem access. Tell them to copy it into the folder named above, then
refer to it by filename alone.

You do NOT have to memorize the sequence. At any point call
  next_step(permissionId)
to get your current stage and the exact next verb to call, derived from live
platform state. The stages below are the reference map.

KEY BRANCH POINTS (read these off the function-def and permission):
  - requiredEvalKeys (on the function-def): which evaluation keys keysetup must
    build. "relinearization" is always present; "sum" and "rotation" appear only
    for functions that need them. This controls how many keysetup rounds run -
    do NOT generate a key the def does not list.
  - resultVisibility (on the permission): who may see the plaintext result.
    Exactly ONE side sees it: "dataConsumer" (default) or "dataOwner". There is
    no mode in which both parties see the answer - never offer that as a choice.
    If it names YOUR role you are the VIEWER (you combine partials and read the
    answer). If it names the other party you are the RELEASER (you upload your
    partial so they can view, without seeing it yourself). Fixed at keysetup time.
  - input.role / input.layout (on the function-def): which inputs YOU own, and
    whether each is an encrypted-bundle (run its encodingRecipe, then encrypt)
    or a plaintext input (upload as-is, e.g. a rule list).

STAGE 0 - DISCOVER
  list_collaborations, list_permissions_received, list_permissions_granted to
  find your permissionId. get_function_definition(slug, saveAs=...) to fetch the
  registry-signed function-def to your workdir (encode_recipe and encrypt read
  it; its signature is verified against the pinned registry key, fail-closed).

STAGE 1 - KEYSETUP (once per permission; both parties contribute)
  register_signing_key(cryptoContextSpec, signingPublicKey) once per crypto
  context, then build the joint keys round by round:
  keysetup_contribute (public-key share), relin_contribute / relin_combine
  (relinearization rounds), and sum_/rotation_ only if requiredEvalKeys lists
  them. Exchange each round with the peer via publish_keysetup_message and
  download_keysetup_message (size-aware: large blobs go through object storage
  automatically). The keysetup LEAD finalizes with publish_final_keys (joint
  public key + relin key, plus sum/rotation keys only if required). When the
  manifest's rounds are all in, the permission flips to "active".

STAGE 2 - PROVIDE INPUTS (each party, for the inputs your role owns)
  For an encrypted-bundle input: encode_recipe(functionDef, inputName, source,
  output) to run its encodingRecipe over your cleartext JSON into a bundle, then
  encrypt(...) under the joint key. For a plaintext input, skip encoding. Then
  upload(...) the dataset (large datasets take the signed-URL path), and finally
  declare_input_dataset(permissionId, inputName, datasetId). Triggering is
  blocked until EVERY function-def input is declared by its owning party.

STAGE 3 - RUN
  The consumer (queryAnalyst role) calls trigger_execution (estimate_execution
  first if you want a cost preview). Track it with get_execution_status /
  list_executions.

STAGE 4 - DECRYPT (threshold; both parties contribute one partial)
  Branch on resultVisibility:
  - RELEASER: wait for execution state "awaiting-release", then release (this
    partial-decrypts and uploads your partial so the viewer can combine).
  - VIEWER: wait for state "released", then download_result and download_partial
    (the releaser's partial), partial_decrypt (your own share; pass lead:true if
    you were the keysetup lead), and decrypt_result (combine both partials). The
    plaintext is written to a workdir file - read it from the filesystem; the
    verb returns only the path, never the values.

SOLO SELF-TEST (one company, no partner) - a DIFFERENT sequence
  A trial account can only create an INTERNAL permission: its own company granting
  to itself. Use create_self_test_permission. There is no counterparty, so there is
  no keysetup exchange, no release step, and you decrypt your own result.

  THE TRAP: the platform marks an internal permission's keysetup "complete" at
  creation, but it holds NO KEYS. The maths still needs them: any function that
  multiplies two ciphertexts requires a relinearization key, and that key only
  exists after a 4-round protocol. If you skip this, estimate_execution succeeds,
  trigger_execution consumes a credit, and the run fails inside the engine with
  "Call EvalMultKeyGen()". Only federated-average needs no evaluation keys.

  So YOU play both parties, locally:
   1. signing_keygen, then register_signing_key for the crypto context.
   2. keysetup_contribute role 'lead'  -> skA + pkA
      keysetup_contribute role 'main' with peerShare=pkA -> skB + the JOINT public
      key. KEEP BOTH SECRETS; losing either makes every result unreadable.
   3. relin_contribute round 1 role 'lead'   (secretKey skA)
      relin_contribute round 1 role 'main'   (secretKey skB, peerShare = the above)
      relin_combine    round 1               -> combined round 1
      relin_contribute round 2 for EACH secret (skA, skB), passing combinedR1 and
      the joint public key
      relin_combine    round 2               -> the FINAL relin key
      Do NOT register a round-1 output as the final key. It is a partial; the
      platform accepts it, the run succeeds, and the answer is garbage.
      sum_/rotation_ verbs follow the same shape, only where requiredEvalKeys asks.
   4. publish_final_keys with the JOINT public key and the FINAL relin key.
      For an internal grant your single submission is compared against itself and
      completes immediately.
   5. encrypt under the JOINT public key (not the lead's contribution), upload,
      declare_input_dataset. A two-input function needs BOTH inputs from you.
      Use list_workdir_files and ASK THE USER which file is which input.
   6. estimate_execution, trigger_execution. Internal runs go straight to
      'succeeded' - there is no awaiting-release.
   7. download_result, then partial_decrypt TWICE (once per secret share, with
      lead:true on the one from the 'lead' keypair), then decrypt_result to
      combine both partials.
   8. For an -itemized function, resolve_matches to name the records, then TELL THE
      USER the file path it returns. Do not try to read the file.

  EVERY function supports a self-test, not just record overlap, and the work varies with
  requiredEvalKeys. Read it off the function-def and build exactly those keys - building
  one it does not list is as wrong as skipping one it does. In rough order of effort:
  federated-average (no evaluation keys at all - the easiest first test), then the
  relinearization-only functions (joint-record-overlap-itemized, negotiation-matrix-itemized,
  decision-tree-inference), then the ones that add sum (joint-record-overlap-count,
  negotiation-matrix-count), then rule-based-cross-match (relin + sum + rotation, and its
  rotation indices must be derived from the rule_pairs file first).

  ALWAYS CHECK THE ANSWER. Every function ships sample data with a documented expected
  result in examples/SELF-TEST.md. A run that merely completes proves the pipeline works;
  only a run that MATCHES the expected value proves the encoding, keys, circuit and
  decryption are all correct. Partial data corruption produces a successful run with a
  plausible wrong answer, and without a reference there is no way to tell them apart. If
  the user supplied their own data instead, say plainly that the result cannot be verified.

  Input CSVs for the overlap functions need a HEADER ROW: the definition sets
  skipHeader, so the first line is always discarded. Keep the sets small - records
  are hashed into slots, so expected false matches are roughly
  (rows_A x rows_B) / slots. There are never false negatives.

SCRIPTS PARITY: the two-party flow also ships as interactive shell scripts (the
00-06 example scripts) and the two paths produce byte-identical keys and results.
The scripts CANNOT drive a solo self-test: they hardcode an external grant type.`;

const server = new McpServer({
  name: 'JuLenny',
  version: '0.1.0',
}, {
  capabilities: {
    tools: {},
  },
  instructions: SERVER_INSTRUCTIONS,
});

registerFunctionTools(server, api);
registerCollaborationTools(server, api);
registerPermissionTools(server, api);
registerExecutionTools(server, api);
registerDatasetTools(server, api);
registerAuditTools(server, api);
registerToolkitTools(server);
registerPipelineTools(server, api);
registerGuideTools(server, api);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('MCP server error:', err);
  process.exit(1);
});
