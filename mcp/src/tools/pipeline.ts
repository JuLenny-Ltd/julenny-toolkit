// Platform-exchange pipeline MCP verbs — the API half of the agent pipeline,
// plus the gated `release`. Family 1 (platform API) + a release verb that
// composes family 2 (local crypto) with a family 1 upload.
//
// These verbs move CIPHERTEXT and ENCRYPTED key material only:
//   - upload                  encrypted dataset bytes -> /api/fhe-data-upload
//   - download_result         the result CIPHERTEXT (still encrypted) -> workdir
//   - publish_keysetup_message  a signed key-exchange envelope (+ payload) via
//                               the signed-URL flow -> /keysetup/messages
//   - publish_final_keys        the signed final-keys envelope (+ blobs) via the
//                               signed-URL flow -> /keysetup/final-keys
//   - release              partial-decrypt + sign + upload the partial. This is
//                          the one verb that exposes the result to the other
//                          party, but it is deliberately NOT host-gated: the
//                          toolkit is meant to be driven unattended by an agent,
//                          and a forced prompt would break that. The grant is the
//                          control, and the platform enforces it. See the note at
//                          the implementation.
//
// Built to the same contract as toolkit.ts:
//   - every path param goes through resolveInWorkdir (workdir-confined names)
//   - bodies wrapped in try/catch -> fail(...)
//   - returns references + status only; NEVER plaintext, secret bytes, or the
//     API key, in results, errors, or logs. download_result returns a path,
//     never contents.
//   - argv arrays for all CLI calls (via runCli); never a shell string.
//
// Request shapes mirror examples/_core (the scripts that make these exact
// calls): main/04-encrypt.sh (data upload), lib.sh request_upload_url /
// wrap_and_upload (keysetup messages), lead/03-finalize-keysetup.sh (final
// keys), lib.sh releaser_flow (release: partial-decrypt + sign + multipart
// POST with x-jl-signature = 128-hex Ed25519 over the raw partial bytes).
//
// NOTE on MCP key scope: `upload` and `release` WRITE to the platform, so they
// need a read-write MCP key. The default MCP key is read-only and the backend
// will 403 these calls; this is enforced server-side, not here.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { readFile, writeFile, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { JulennyApiClient } from '../api-client.js';
import { runCli } from './lib/cli.js';
import { resolveInWorkdir } from './lib/paths.js';
import { runRecipe, verifyFunctionDefSignature } from './lib/recipe.js';

const ok = (obj: Record<string, unknown>) => ({
  content: [{ type: 'text' as const, text: JSON.stringify({ ok: true, ...obj }, null, 2) }],
});
const fail = (error: string, extra: Record<string, unknown> = {}) => ({
  content: [{ type: 'text' as const, text: JSON.stringify({ ok: false, error, ...extra }, null, 2) }],
  isError: true,
});

export function registerPipelineTools(server: McpServer, api: JulennyApiClient) {
  // ---- register_signing_key (keysetup prerequisite) ----
  // Mirrors _core/00-init's POST /api/companies/me/fhe-public-keys. Registers
  // THIS company's Ed25519 signing PUBLIC key with the platform for a crypto
  // context, so the platform can verify the signed keysetup envelopes. Must run
  // once per crypto context before publish_keysetup_message. Sends only the hex
  // public key; the signing secret never leaves the workdir.
  server.tool(
    'register_signing_key',
    "Register this company's Ed25519 signing PUBLIC key with the platform for a crypto context (POST /api/companies/me/fhe-public-keys). Required once per crypto context before publishing keysetup messages, otherwise the platform rejects them with 'No signing key registered for this crypto context'. Reads the public key from the workdir and sends only its hex; the signing secret is never read or sent.",
    {
      cryptoContextSpec: z.string().describe('Crypto context spec (e.g. ckks-tree-v1)'),
      signingPublicKey: z.string().describe('Workdir-relative Ed25519 signing PUBLIC key file name (32 raw bytes)'),
    },
    async (p) => {
      try {
        const pub = await readFile(resolveInWorkdir(p.signingPublicKey));
        if (pub.length !== 32) return fail(`signing public key must be 32 bytes, got ${pub.length}`);
        const signingPublicKeyHex = pub.toString('hex');
        const data = await api.post('/api/companies/me/fhe-public-keys', {
          cryptoContextSpec: p.cryptoContextSpec,
          signingPublicKeyHex,
        });
        return ok({ registered: true, cryptoContextSpec: p.cryptoContextSpec, response: data });
      } catch (e) {
        return fail(`register_signing_key failed: ${(e as Error).message}`);
      }
    },
  );

  // ---- encode_recipe (cleartext bundle prep for encrypted-bundle inputs) ----
  // Mirrors examples/_core/recipe/recipe-encode.mjs: verify the def's registry
  // signature (fail-closed), then run the named input's encodingRecipe over a
  // cleartext JSON source into the toolkit's generic bundle-input. The agent then
  // passes that bundle-input to `encrypt`. Pure cleartext data-structuring, no keys.
  server.tool(
    'encode_recipe',
    "Run a function-def input's encodingRecipe over a cleartext JSON source into the toolkit bundle-input (for encrypted-bundle layout inputs, e.g. decision-tree model/features). Verifies the def's registry signature first (fail-closed). Returns the bundle-input path + vector count.",
    {
      functionDef: z.string().describe('Workdir-relative signed function-def JSON file'),
      inputName: z.string().describe('Input name whose encodingRecipe to run (e.g. model, features)'),
      source: z.string().describe('Workdir-relative cleartext JSON source file the recipe maps over'),
      output: z.string().describe('Workdir-relative output bundle-input JSON file name'),
    },
    async (p) => {
      try {
        const def = JSON.parse(await readFile(resolveInWorkdir(p.functionDef), 'utf8'));
        if (!verifyFunctionDefSignature(def)) {
          return fail('function-definition signature verification FAILED; refusing to run the encodingRecipe');
        }
        const input = (def.inputs || []).find((i: any) => i?.name === p.inputName);
        if (!input) return fail(`function-def has no input named '${p.inputName}'`);
        const recipe = input.encodingRecipe;
        if (!recipe) return fail(`input '${p.inputName}' has no encodingRecipe`);
        const source = JSON.parse(await readFile(resolveInWorkdir(p.source), 'utf8'));
        const bundle = runRecipe(recipe, source);
        const out = resolveInWorkdir(p.output);
        await writeFile(out, JSON.stringify(bundle, null, 2) + '\n');
        return ok({ output: out, vectors: bundle.vectors.length, header: bundle.header });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'encode_recipe failed');
      }
    },
  );

  // ---- declare_input_dataset (preferred-datasets mapping) ----
  // Mirrors main/04-encrypt.sh's PUT /preferred-datasets/{inputName}. The execution
  // trigger requires EVERY function-def input to have a declared dataset pick by its
  // owning party first; uploading the dataset is not enough. Non-secret metadata only.
  server.tool(
    'declare_input_dataset',
    'Declare which uploaded dataset to use for a function-def input on a permission (PUT /fhe-permissions/{id}/preferred-datasets/{inputName}). Required before triggering: each party must declare its own inputs. Returns the mapping.',
    {
      permissionId: z.string().describe('Permission id'),
      inputName: z.string().describe('Function-def input name (e.g. features, model)'),
      datasetId: z.string().describe('Uploaded dataset id to bind to this input'),
    },
    async (p) => {
      try {
        const data = await api.put(
          `/api/fhe-permissions/${p.permissionId}/preferred-datasets/${p.inputName}`,
          { datasetId: p.datasetId },
        );
        return ok({ inputName: p.inputName, datasetId: p.datasetId, response: data });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'declare_input_dataset failed');
      }
    },
  );

  // ---- fetch_joint_public_key (reused keysetup / consumer side) ----
  // A party that REUSES an existing collaboration's joint key (it did not run this
  // keysetup itself - e.g. the MCP as consumer on a collab set up elsewhere) still
  // needs the joint PUBLIC key to encrypt its inputs. Mirrors lead/04-encrypt's
  // fetch: resolve the permission's jointKeyId, then GET the public-key bytes. The
  // joint public key is NOT secret; this is a plain read to a workdir file.
  server.tool(
    'fetch_joint_public_key',
    "Fetch the collaboration's joint PUBLIC key for a permission into a workdir file, so you can encrypt inputs under it without having run this keysetup yourself (reused keysetup, or the consumer side). Returns the file path; the key is public, never secret.",
    {
      permissionId: z.string().describe('Permission id whose joint key to fetch'),
      output: z.string().describe('Workdir-relative output file for the joint public key'),
      jointKeyId: z.string().optional().describe('Explicit joint key id; only needed if auto-resolution fails'),
    },
    async (p) => {
      try {
        // The MCP may be the owner OR the consumer for a permission, and the
        // role-scoped list differs (api-key default view is owner-scoped), so
        // check both the received and granted views to find this permission.
        let jointKeyId = p.jointKeyId as string | undefined;
        if (!jointKeyId) {
          for (const q of ['view=received', 'view=granted']) {
            const list = await api.get(`/api/fhe-permissions?${q}&status=active`) as Record<string, unknown>;
            const perms = (list.permissions as Array<Record<string, unknown>>) || [];
            const perm = perms.find((x) => x.id === p.permissionId);
            if (perm?.jointKeyId) { jointKeyId = perm.jointKeyId as string; break; }
          }
        }
        if (!jointKeyId) return fail(`could not resolve jointKeyId for permission ${p.permissionId} (pass jointKeyId explicitly, or keysetup may be incomplete)`);
        const bytes = await api.getBytes(`/api/fhe-joint-keys/${jointKeyId}/public-key`);
        if (!bytes || bytes.length === 0) return fail('joint public key download returned no bytes');
        const out = resolveInWorkdir(p.output);
        await writeFile(out, bytes);
        return ok({ outputPath: out, jointKeyId, bytes: bytes.length });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'fetch_joint_public_key failed');
      }
    },
  );

  // ---- get_declared_datasets (read the preferred-datasets map) ----
  // The consumer needs every input's declared datasetId (its own + the peer's) to
  // assemble inputDatasetIds for estimate/trigger in the function-def input order.
  // Read-only, non-secret metadata. Mirrors GET /preferred-datasets.
  server.tool(
    'get_declared_datasets',
    'Read the declared input->dataset map for a permission (GET /fhe-permissions/{id}/preferred-datasets). Use it to assemble inputDatasetIds in function-def input order before estimate_execution / trigger_execution. Returns the map { inputName: { datasetId, declaredAt } }.',
    {
      permissionId: z.string().describe('Permission id'),
    },
    async (p) => {
      try {
        const data = await api.get(`/api/fhe-permissions/${p.permissionId}/preferred-datasets`);
        return ok({ declared: data });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'get_declared_datasets failed');
      }
    },
  );

  // ---- upload (auto: moves encrypted/opaque dataset bytes) ----
  // Mirrors lib.sh upload_plaintext_dataset: SIZE-AWARE. Files under the ~32MB
  // Cloud Run body cap go inline as a multipart POST to /api/fhe-data-upload;
  // larger files (e.g. the ~190MB decision-tree model bundle) take the signed-URL
  // flow (POST /upload-url -> PUT bytes to object storage -> POST /confirm), which
  // bypasses the cap. The bytes are ciphertext or an opaque encrypted bundle; the
  // platform treats them opaquely. Returns the new dataset id only.
  // NEEDS A READ-WRITE MCP KEY (the default read-only key will 403).
  server.tool(
    'upload',
    'Upload an encrypted dataset file to the platform (size-aware: inline multipart for small files, signed-URL object-storage flow for large ones past the ~32MB cap). Bytes are ciphertext; returns the dataset id, never the contents. Requires a read-write MCP key (the default read-only key will 403).',
    {
      file: z.string().describe('Workdir-relative ciphertext/bundle file name to upload'),
      name: z.string().describe('Display name for the dataset'),
      description: z.string().optional().describe('Optional dataset description'),
      permissionId: z.string().optional().describe('Permission id to scope the upload to'),
      projectId: z.string().optional().describe('Project id to scope the upload to'),
      kind: z.string().optional().describe('Dataset kind tag (e.g. "ciphertext", "plaintext")'),
      retentionDays: z.number().int().positive().optional().describe('Retention window in days'),
    },
    async (p) => {
      try {
        if (!p.permissionId && !p.projectId) {
          return fail('provide permissionId and/or projectId to scope the upload');
        }
        const resolved = resolveInWorkdir(p.file);
        const { size } = await stat(resolved);
        const INLINE_DATASET_THRESHOLD_BYTES = 15 * 1024 * 1024;

        if (size < INLINE_DATASET_THRESHOLD_BYTES) {
          // Small file: buffering is fine, and multipart needs the bytes in hand.
          const bytes = await readFile(resolved);
          const form = new FormData();
          form.append('file', new Blob([new Uint8Array(bytes)]), p.file);
          form.append('name', p.name);
          if (p.description) form.append('description', p.description);
          if (p.permissionId) form.append('permissionId', p.permissionId);
          if (p.projectId) form.append('projectId', p.projectId);
          if (p.kind) form.append('kind', p.kind);
          if (p.retentionDays !== undefined) form.append('retentionDays', String(p.retentionDays));
          const data = await api.postMultipart('/api/fhe-data-upload', form) as Record<string, unknown>;
          if (!data.datasetId) return fail('upload succeeded but no datasetId returned');
          return ok({ datasetId: data.datasetId, via: 'multipart', bytes: size });
        }

        // Large dataset: signed-URL flow (upload-url -> PUT to object storage -> confirm).
        // The file is STREAMED to object storage, never read fully into memory.
        const urlBody: Record<string, unknown> = { name: p.name };
        if (p.permissionId) urlBody.permissionId = p.permissionId;
        if (p.projectId) urlBody.projectId = p.projectId;
        const urlResp = await api.post('/api/fhe-data-upload/upload-url', urlBody) as Record<string, unknown>;
        const uploadUrl = urlResp.uploadUrl as string | undefined;
        const datasetId = urlResp.datasetId as string | undefined;
        if (!uploadUrl || !datasetId) return fail(`upload-url did not return uploadUrl/datasetId: ${JSON.stringify(urlResp)}`);
        await api.putSignedUrlFromFile(uploadUrl, resolved);
        const confirmBody: Record<string, unknown> = {
          datasetId,
          name: p.name,
          kind: p.kind || 'ciphertext',
          fileName: p.file,
          retentionDays: p.retentionDays ?? 90,
        };
        if (p.permissionId) confirmBody.permissionId = p.permissionId;
        if (p.projectId) confirmBody.projectId = p.projectId;
        const confirmResp = await api.post('/api/fhe-data-upload/confirm', confirmBody) as Record<string, unknown>;
        return ok({ datasetId: (confirmResp.datasetId as string) || datasetId, via: 'signed-url', bytes: size });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'upload failed');
      }
    },
  );

  // ---- download_result (auto: the result is still ciphertext) ----
  // Mirrors releaser_flow / viewer_flow: GET /api/executions/{id}/result -> the
  // encrypted result bytes. Writes them to a confined workdir file and returns
  // the path. The result reveals nothing without threshold decryption, so this
  // is not gated. NEVER returns the bytes.
  server.tool(
    'download_result',
    'Download an execution result (still-encrypted ciphertext) to a local workdir file. Returns the file path, never the contents.',
    {
      executionId: z.string().describe('Execution id'),
      output: z.string().describe('Workdir-relative output file name for the result ciphertext'),
    },
    async (p) => {
      try {
        const out = resolveInWorkdir(p.output);
        const bytes = await api.getBytes(`/api/executions/${p.executionId}/result`);
        if (!bytes || bytes.length === 0) return fail('result download returned no bytes');
        await writeFile(out, bytes);
        return ok({ outputPath: out, bytes: bytes.length });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'download_result failed');
      }
    },
  );

  // ---- download_partial (viewer flow: the releaser's partial decryption) ----
  // Mirrors viewer_flow step 3: GET /api/executions/{id}/partial -> the peer
  // (releaser) side's partial-decryption bytes. The viewer needs BOTH partials
  // (this one + its own from partial_decrypt) to combine via decrypt_result. A
  // single partial reveals nothing, so this is not gated. NEVER returns bytes.
  server.tool(
    'download_partial',
    "Download the releaser side's partial decryption for a released execution (GET /api/executions/{id}/partial) to a local workdir file. The viewer combines this with its own partial_decrypt output via decrypt_result. Returns the file path, never the contents.",
    {
      executionId: z.string().describe('Execution id'),
      output: z.string().describe("Workdir-relative output file name for the peer's partial"),
    },
    async (p) => {
      try {
        const out = resolveInWorkdir(p.output);
        const bytes = await api.getBytes(`/api/executions/${p.executionId}/partial`);
        if (!bytes || bytes.length === 0) return fail('partial download returned no bytes');
        await writeFile(out, bytes);
        return ok({ outputPath: out, bytes: bytes.length });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'download_partial failed');
      }
    },
  );

  // ---- publish_keysetup_message (auto: encrypted key-exchange material) ----
  // Mirrors lib.sh request_upload_url + wrap_and_upload (object-storage path):
  //   1. POST /keysetup/messages/upload-url  body {round}  -> {objectKey, uploadUrl}
  //   2. PUT the raw payload bytes to the signed uploadUrl (no api key)
  //   3. POST /keysetup/messages  body = the SIGNED ENVELOPE produced by the
  //      `wrap_envelope` toolkit verb in payloadRef mode (it embeds objectKey,
  //      sizeBytes, permissionId, round, messageType + the Ed25519 signature).
  // The pipeline verb does NOT sign (signing is toolkit-owned, in wrap_envelope);
  // it just performs the upload-url -> PUT -> register glue. Pass the signed
  // envelope as `envelope` and the raw share bytes as `payload`. The
  // `wrap_envelope` call must use the objectKey this verb obtained, so this verb
  // returns the objectKey for the agent to wrap against, OR (single-call form)
  // accepts a pre-signed envelope whose objectKey it echoes.
  // Size-aware, mirroring _core/lib.sh wrap_and_upload: payloads UNDER the inline
  // threshold are signed inline (payload embedded in the envelope); payloads at or
  // ABOVE it are uploaded to object storage and signed BY REFERENCE (objectKey +
  // sizeBytes), so the registered envelope stays tiny and never exceeds the API
  // request-body limit. The verb owns the reference-mode wrap because the objectKey
  // only exists after the upload-url step (a pre-wrapped envelope can't reference it).
  const INLINE_THRESHOLD_BYTES = 15 * 1024 * 1024;

  // One keysetup message: wrap (inline or by reference), upload if large, register.
  // Shared by publish_keysetup_message and publish_rotation_key so the two cannot drift.
  async function publishMessage(
    permissionId: string, round: number, messageType: string,
    payloadPath: string, signingPath: string,
  ): Promise<{ ok: true; objectKey: string; mode: string; message?: unknown } | { ok: false; error: string }> {
    const envPath = resolveInWorkdir(`ks-msg-${messageType}-${round}.envelope.json`);
    const size = (await stat(payloadPath)).size;
    const common = [
      '--secret-key', signingPath,
      '--output', envPath,
      '--permission-id', permissionId,
      '--round', String(round),
      '--message-type', messageType,
    ];
    let objectKey = 'inline';
    let mode = 'inline';
    if (size < INLINE_THRESHOLD_BYTES) {
      const r = await runCli(['crypto', 'wrap-envelope', '--payload', payloadPath, ...common]);
      if (!r.ok) return { ok: false, error: `wrap-envelope (inline) failed: ${r.error ?? 'unknown error'}` };
    } else {
      mode = 'objectStorage';
      const urlResp = await api.post(
        `/api/fhe-permissions/${permissionId}/keysetup/messages/upload-url`,
        { round },
      ) as Record<string, unknown>;
      const uploadUrl = urlResp.uploadUrl as string | undefined;
      const key = urlResp.objectKey as string | undefined;
      if (!uploadUrl || !key) return { ok: false, error: 'upload-url did not return uploadUrl + objectKey' };
      objectKey = key;
      // Stream from disk. readFile pulled the whole payload into memory and
      // putSignedUrl then copied it again into a Uint8Array and a Blob, so a
      // 320MB rotation key cost about a gigabyte of churn before the first byte
      // went out. That stall, not the network, is what ran the call past the
      // client's timeout.
      await api.putSignedUrlFromFile(uploadUrl, payloadPath);
      const r = await runCli(['crypto', 'wrap-envelope', '--object-key', objectKey, '--size-bytes', String(size), ...common]);
      if (!r.ok) return { ok: false, error: `wrap-envelope (reference) failed: ${r.error ?? 'unknown error'}` };
    }
    const envelope = JSON.parse(await readFile(envPath, 'utf8'));
    const regResp = await api.post(
      `/api/fhe-permissions/${permissionId}/keysetup/messages`,
      envelope,
    ) as Record<string, unknown>;
    return { ok: true, objectKey, mode, message: regResp.message };
  }

  server.tool(
    'publish_keysetup_message',
    'Publish a signed keysetup key-exchange message. Size-aware: small payloads are signed inline; large payloads are uploaded to object storage and signed BY REFERENCE so the registered envelope stays small (mirrors the scripts wrap_and_upload). Encrypted key material only; returns the objectKey/status, no secrets.',
    {
      permissionId: z.string().describe('Permission id this message belongs to'),
      payload: z.string().describe('Workdir-relative raw share/payload file name'),
      signingKey: z.string().describe('Workdir-relative Ed25519 signing-secret file name (used to sign the envelope)'),
      round: z.number().int().positive().describe('Manifest round number'),
      messageType: z.string().describe('Keysetup message type (e.g. pk-share, relin-round1, sum-round1)'),
    },
    async (p) => {
      try {
        const r = await publishMessage(
          p.permissionId, p.round, p.messageType,
          resolveInWorkdir(p.payload), resolveInWorkdir(p.signingKey),
        );
        if (!r.ok) return fail(r.error);
        return ok({ objectKey: r.objectKey, mode: r.mode, messageType: p.messageType, message: r.message });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'publish_keysetup_message failed');
      }
    },
  );

  // ---- download_keysetup_message (peer share GET) ----
  // Mirrors lib.sh download_peer_share: GET the peer's keysetup messages, pick the
  // one matching messageType, and write its payload to a workdir file (inline
  // base64, or an object-storage signed URL). Without this the local contribute/
  // combine verbs have no way to obtain the peer share they consume. Encrypted key
  // material only; returns the path + mode, never secrets.
  server.tool(
    'download_keysetup_message',
    "Download a peer's signed keysetup message payload to a workdir file (GET /keysetup/messages?from=peer, select by messageType; handles inline base64 or an object-storage signed URL). Mirrors the scripts' download_peer_share. Returns the output path + mode, never secrets.",
    {
      permissionId: z.string().describe('Permission id'),
      messageType: z.string().describe('Peer message type to fetch (e.g. pk-share, relin-round1-continue, relin-round2, sum-round1-continue)'),
      output: z.string().describe('Workdir-relative file name to write the payload to'),
    },
    async (p) => {
      try {
        const data = await api.get(
          `/api/fhe-permissions/${p.permissionId}/keysetup/messages?from=peer`,
        ) as Record<string, unknown>;
        const messages = (data.messages as Array<Record<string, unknown>> | undefined) ?? [];
        const msg = messages.find((m) => m.messageType === p.messageType);
        if (!msg) return fail(`peer has not submitted a '${p.messageType}' message yet`);
        const out = resolveInWorkdir(p.output);
        const b64 = msg.payloadB64 as string | undefined;
        const url = msg.downloadUrl as string | undefined;
        if (b64) {
          await writeFile(out, Buffer.from(b64, 'base64'));
          return ok({ output: out, mode: 'inline', messageType: p.messageType });
        }
        if (url) {
          const resp = await fetch(url);
          if (!resp.ok) return fail(`object-storage GET failed: HTTP ${resp.status}`);
          const buf = Buffer.from(await resp.arrayBuffer());
          await writeFile(out, buf);
          return ok({ output: out, mode: 'objectStorage', bytes: buf.length, messageType: p.messageType });
        }
        return fail(`peer '${p.messageType}' message has neither payloadB64 nor downloadUrl`);
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'download_keysetup_message failed');
      }
    },
  );

  // ---- publish_final_keys (auto: encrypted final key blobs) ----
  // Mirrors lead/03-finalize-keysetup.sh:
  //   1. POST /keysetup/final-keys/upload-url  body {keyType}  -> {objectKey, uploadUrl}
  //      (one per keyType: joint_public_key, joint_relin_key, eval_sum_key)
  //   2. PUT each key blob to its signed uploadUrl (no api key)
  //   3. POST /keysetup/final-keys  body = the SIGNED ENVELOPE produced by the
  //      `wrap_final_keys_envelope` toolkit verb (it carries the keys[] array of
  //      {keyType, objectKey, sha256Hex}, permissionId, timestamp + signature).
  // The agent obtains the objectKeys from this verb's per-key upload-url step,
  // wraps the final-keys envelope against them (toolkit), then registers it here.
  // To keep this a single faithful call, pass the already-signed envelope plus
  // the blob files keyed by keyType; the verb requests an upload-url per keyType,
  // PUTs the blob, and registers the supplied envelope.
  server.tool(
    'publish_final_keys',
    'Publish the final joint keys: per keyType upload the blob to object storage (collecting objectKey + sha256), then build, SIGN, and register the final-keys envelope. The envelope must reference the objectKeys, so this verb signs it itself AFTER upload (like the scripts). Encrypted key material only; returns objectKeys + state, no secrets.',
    {
      permissionId: z.string().describe('Permission id'),
      signingKey: z.string().describe('Workdir-relative Ed25519 signing-secret file name (signs the final-keys envelope)'),
      keys: z.array(z.object({
        keyType: z.enum(['joint_public_key', 'joint_relin_key', 'eval_sum_key']).describe('Which final key this blob is. Rotation keys are NOT submitted here; they go through the keysetup messages endpoint.'),
        file: z.string().describe('Workdir-relative key blob file name to PUT'),
      })).min(1).describe('Final key blobs to upload, one per keyType'),
    },
    async (p) => {
      try {
        const { createHash } = await import('node:crypto');
        const uploaded: { keyType: string; objectKey: string; sha256Hex: string }[] = [];
        for (const k of p.keys) {
          // Hash by streaming rather than buffering: the eval-sum key is ~71MB and
          // there is no reason to hold it whole.
          const keyPath = resolveInWorkdir(k.file);
          const sha256Hex = await new Promise<string>((resolve, reject) => {
            const h = createHash('sha256');
            const rs = createReadStream(keyPath);
            rs.on('data', (c) => h.update(c));
            rs.on('end', () => resolve(h.digest('hex')));
            rs.on('error', reject);
          });
          const urlResp = await api.post(
            `/api/fhe-permissions/${p.permissionId}/keysetup/final-keys/upload-url`,
            { keyType: k.keyType },
          ) as Record<string, unknown>;
          const uploadUrl = urlResp.uploadUrl as string | undefined;
          const objectKey = urlResp.objectKey as string | undefined;
          if (!uploadUrl || !objectKey) {
            return fail(`upload-url for ${k.keyType} did not return uploadUrl + objectKey`);
          }
          await api.putSignedUrlFromFile(uploadUrl, keyPath);
          uploaded.push({ keyType: k.keyType, objectKey, sha256Hex });
        }
        // Build the to-sign, sign with the toolkit (it extracts the fields and signs
        // a canonical form, so JSON formatting here is irrelevant), then register it.
        const toSign = { keys: uploaded, permissionId: p.permissionId, timestamp: new Date().toISOString() };
        const toSignPath = resolveInWorkdir('final-keys-to-sign.json');
        const signedPath = resolveInWorkdir('final-keys-signed.json');
        await writeFile(toSignPath, JSON.stringify(toSign));
        const r = await runCli(['crypto', 'wrap-final-keys-envelope',
          '--to-sign', toSignPath,
          '--secret-key', resolveInWorkdir(p.signingKey),
          '--output', signedPath]);
        if (!r.ok) return fail(`wrap-final-keys-envelope failed: ${r.error ?? 'unknown error'}`);
        const envelope = JSON.parse(await readFile(signedPath, 'utf8'));
        const regResp = await api.post(
          `/api/fhe-permissions/${p.permissionId}/keysetup/final-keys`,
          envelope,
        ) as Record<string, unknown>;
        const state = regResp.permissionState ?? regResp.state;
        return ok({ objectKeys: uploaded.map((u) => ({ keyType: u.keyType, objectKey: u.objectKey })), state, message: regResp.message });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'publish_final_keys failed');
      }
    },
  );

  // ---- publish_rotation_key ----
  // Rotation keys do NOT go through publish_final_keys (its keyType enum has no slot for
  // them, by design). They are three keysetup messages instead. Getting that sequence
  // right means knowing the message types AND the round numbers, which only appear in the
  // manifest after rule_pairs is declared - so an agent could not discover it, and the
  // only alternative on offer was to register the rotation key in the eval_sum_key slot,
  // which the platform accepts and which silently produces a wrong answer. One verb.
  server.tool(
    'publish_rotation_key',
    "Submit a joint rotation key: publishes the two contributions and the combined key as the three rotation keysetup rounds, then reports whether the platform completed the rotation setup. Use this INSTEAD of publish_final_keys for rotation keys - publish_final_keys has no rotation slot and putting a rotation key in another slot is accepted by the platform but produces a wrong answer. Round numbers are read from the permission's own manifest.",
    {
      permissionId: z.string().describe('Permission id'),
      leadContribution: z.string().describe("Workdir-relative rotation-contribute output for role 'lead'"),
      mainContribution: z.string().describe("Workdir-relative rotation-contribute output for role 'main'"),
      combined: z.string().describe('Workdir-relative rotation-combine output (the final joint rotation key)'),
      signingKey: z.string().describe('Workdir-relative Ed25519 signing-secret file name'),
    },
    async (p) => {
      try {
        const ks = await api.get(`/api/fhe-permissions/${p.permissionId}/keysetup`) as Record<string, unknown>;
        const manifest = (ks.roundManifest as Array<{ round: number; messageType: string }>) || [];
        const roundFor = (mt: string) => manifest.find((e) => e.messageType === mt)?.round;

        const steps: Array<[string, string]> = [
          ['rotation-round1', p.leadContribution],
          ['rotation-round1-continue', p.mainContribution],
          ['rotation-combine', p.combined],
        ];
        const missing = steps.map(([mt]) => mt).filter((mt) => roundFor(mt) === undefined);
        if (missing.length) {
          return fail(
            `this permission's manifest has no rotation rounds (${missing.join(', ')}). Rotation rounds only appear AFTER the rule-list input is declared, because the platform derives the index set from it. Declare that input first, then call this again.`,
          );
        }

        // ONE round per call, resumable. The three rotation payloads are ~320MB each,
        // so uploading all three inside a single tool call ran past the MCP client's
        // timeout every time, and the operator had to fall back to publishing the
        // rounds by hand. Publish the first outstanding round, report what is left,
        // and let the caller call again.
        const contributed = new Set<number>(
          Object.values((ks.contributions as Record<string, number[]>) || {}).flat(),
        );
        const outstanding = steps.filter(([mt]) => !contributed.has(roundFor(mt)!));

        const signingPath = resolveInWorkdir(p.signingKey);
        const published: Array<Record<string, unknown>> = [];
        if (outstanding.length) {
          const [messageType, file] = outstanding[0];
          const round = roundFor(messageType)!;
          const r = await publishMessage(
            p.permissionId, round, messageType, resolveInWorkdir(file), signingPath,
          );
          if (!r.ok) return fail(`${messageType} (round ${round}): ${r.error}`);
          published.push({ round, messageType, mode: r.mode });
        }
        const remaining = outstanding.slice(1).map(([mt]) => ({ round: roundFor(mt)!, messageType: mt }));

        // Report the gate rather than leaving the caller to guess: keysetupState reads
        // "complete" on an internal grant from the moment it is created, so it is not
        // evidence of anything here.
        const after = await api.get(`/api/fhe-permissions/${p.permissionId}/keysetup`) as Record<string, unknown>;
        const rot = (after.pendingRotationKeySetup as Record<string, unknown>) || {};
        const status = (rot.status as string) ?? 'unknown';
        return ok({
          published,
          remaining,
          rotationStatus: status,
          completedAt: rot.completedAt ?? null,
          ready: status === 'complete',
          summary: remaining.length
            ? `Published round ${published[0]?.round}. ${remaining.length} rotation round(s) still to publish: ${remaining.map((r) => `${r.round} (${r.messageType})`).join(', ')}. Call publish_rotation_key again to send the next one. Each call uploads one ~320MB payload, which is why they are not batched.`
            : status === 'complete'
            ? 'Rotation key setup is COMPLETE. The permission can now run.'
            : `Rotation key setup reports '${status}', not 'complete'. Do NOT trigger an execution yet: it would spend a credit and fail inside the engine. Call get_rotation_status again, and if it does not reach 'complete', report that rather than retrying.`,
        });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'publish_rotation_key failed');
      }
    },
  );

  // ---- get_rotation_status ----
  // Read-only view of the one gate nothing else exposed. Without it an agent that had
  // correctly submitted all three rounds had no way to confirm the platform accepted
  // them, and had to ask a human to read the database.
  server.tool(
    'get_rotation_status',
    "Report whether rotation key setup is complete for a permission, for functions whose requiredEvalKeys include 'rotation'. Returns the status, the derived rotation indices count, and whether it is safe to trigger. Note that keysetupState is NOT a substitute: on an internal (solo) grant it reads 'complete' from creation, before any key exists.",
    { permissionId: z.string().describe('Permission id') },
    async (p) => {
      try {
        const ks = await api.get(`/api/fhe-permissions/${p.permissionId}/keysetup`) as Record<string, unknown>;
        const rot = ks.pendingRotationKeySetup as Record<string, unknown> | null | undefined;
        if (!rot) {
          return ok({
            rotationRequired: false,
            summary: 'No rotation key setup is pending for this permission. Either the function does not need rotation keys, or the input the indices are derived from has not been declared yet.',
          });
        }
        const status = (rot.status as string) ?? 'unknown';
        const indices = (rot.indices as unknown[]) || [];
        return ok({
          rotationRequired: true,
          status,
          indexCount: indices.length,
          completedAt: rot.completedAt ?? null,
          ready: status === 'complete',
          summary: status === 'complete'
            ? 'Rotation key setup is complete; it is safe to trigger.'
            : `Rotation key setup is '${status}'. Triggering now would spend a credit and fail inside the engine.`,
        });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'get_rotation_status failed');
      }
    },
  );

  // ---- release (NOT host-gated; see the header note and the rationale below) ----
  // Composes family 2 (local crypto) + a family 1 upload, mirroring
  // lib.sh releaser_flow:
  //   1. host-approval gate (fail-closed): this is the verb that exposes the
  //      result to the OTHER party (the viewer), so it must be confirmed.
  //   2. crypto partial-decrypt --context-spec --input <result> --secret-key
  //      <share> --output <partial> [--lead] --json
  //   3. crypto sign --input <partial> --secret-key <signing> --output <sig> --json
  //      (sign writes the RAW 64-byte signature to --output; its --json does NOT
  //       emit hex, so we read the sig file and hex-encode -> 128 hex chars,
  //       exactly like the script's `xxd -p`.)
  //   4. multipart POST /api/executions/{id}/partial-decrypt  file=<partial bytes>
  //      header x-jl-signature=<hex>. Server enforces state==awaiting-release and
  //      caller==releaser (the releaser is whoever is NOT the result viewer,
  //      derived from resultVisibility). On success state -> released.
  // Returns the resulting state only; never plaintext/secret bytes/api key.
  // NEEDS A READ-WRITE MCP KEY (the default read-only key will 403).
  server.tool(
    'release',
    'Release an execution result to the other party: partial-decrypt the result, sign the partial, and upload it. The grant governs this (function, runs remaining, expiry, named partner, result visibility) and the platform enforces it; the releasing agent should validate the request against the grant before calling. The MCP never sees plaintext. Returns the new state only. Requires a read-write MCP key (the default read-only key will 403).',
    {
      executionId: z.string().describe('Execution id (must be awaiting-release; caller must be the releaser)'),
      resultCiphertext: z.string().describe('Workdir-relative downloaded result-ciphertext file name'),
      secretKey: z.string().describe('Workdir-relative FHE secret-share file name'),
      signingKey: z.string().describe('Workdir-relative Ed25519 signing-secret file name'),
      contextSpec: z.string().describe('Crypto context spec'),
      partialOutput: z.string().optional().describe('Workdir-relative output partial file name (default: release-partial.bin)'),
      signatureOutput: z.string().optional().describe('Workdir-relative output signature file name (default: release-partial.sig)'),
      lead: z.boolean().optional().describe('True if this party has the keysetup-lead role'),
    },
    async (p) => {
      // No forced human prompt. The grant governs release (function, runs
      // remaining, expiry, named partner, result visibility) and the platform
      // enforces it (awaiting-release state + releaser identity + expiry/count).
      // The releasing agent should validate the request against the grant first;
      // the MCP never sees plaintext - this only uploads an encrypted partial.
      try {
        const resultPath = resolveInWorkdir(p.resultCiphertext);
        const secretPath = resolveInWorkdir(p.secretKey);
        const signingPath = resolveInWorkdir(p.signingKey);
        const partialName = p.partialOutput ?? 'release-partial.bin';
        const sigName = p.signatureOutput ?? 'release-partial.sig';
        const partialPath = resolveInWorkdir(partialName);
        const sigPath = resolveInWorkdir(sigName);

        // 2. partial-decrypt
        const pdArgs = [
          'crypto', 'partial-decrypt',
          '--context-spec', p.contextSpec,
          '--input', resultPath,
          '--secret-key', secretPath,
          '--output', partialPath,
        ];
        if (p.lead) pdArgs.push('--lead');
        pdArgs.push('--json');
        const pd = await runCli(pdArgs);
        if (!pd.ok) return fail(pd.error || 'partial-decrypt failed', { exitCode: pd.exitCode });

        // 3. sign the partial bytes (raw 64-byte sig to disk)
        const signArgs = [
          'crypto', 'sign',
          '--input', partialPath,
          '--secret-key', signingPath,
          '--output', sigPath,
          '--json',
        ];
        const sign = await runCli(signArgs);
        if (!sign.ok) return fail(sign.error || 'sign failed', { exitCode: sign.exitCode });

        // 4. read sig bytes, hex-encode (Ed25519 = 64 bytes -> 128 hex chars),
        //    matching the script's `xxd -p`.
        const sigBytes = await readFile(sigPath);
        const sigHex = sigBytes.toString('hex');
        if (sigHex.length !== 128) {
          return fail(`signature is ${sigHex.length} hex chars, expected 128`);
        }

        // 5. multipart upload of the partial + signature header
        const partialBytes = await readFile(partialPath);
        const form = new FormData();
        form.append('file', new Blob([new Uint8Array(partialBytes)]), partialName);
        const resp = await api.postMultipart(
          `/api/executions/${p.executionId}/partial-decrypt`,
          form,
          { 'x-jl-signature': sigHex },
        ) as Record<string, unknown>;
        return ok({ state: resp.state });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'release failed');
      }
    },
  );
}
