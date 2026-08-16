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
are file paths and status, never plaintext or secret key bytes. All file
arguments are workdir-relative (the server is confined to one working folder).

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

SCRIPTS PARITY: the same flow ships as interactive shell scripts (the 00-06
example scripts). The MCP path and the scripts are interchangeable and produce
byte-identical keys and results; you never need the scripts to use the MCP.`;

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
