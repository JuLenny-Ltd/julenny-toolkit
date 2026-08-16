// Local toolkit (crypto) MCP verbs — family 2 of the security contract.
//
// These wrap specific `julenny-toolkit` CLI commands so an agent can run the local
// crypto half of the pipeline. The crypto runs on the user's machine; the agent
// never sees keys or plaintext.
//
// Built to cowork-mcp-security-guidelines.md:
//   - spawned via argv array (lib/cli.ts), pinned binary, no shell string
//   - path params are workdir-relative names, confined (lib/paths.ts)
//   - returns references + status only; never plaintext/keys/API key
//   - reveal steps (decrypt_result here, release in pipeline.ts) are governed by the
//     grant + audit log + platform enforcement, NOT a forced human prompt (David, 2026-06-21).
//     The releasing/viewing agent validates the request against the grant (function, runs
//     remaining, expiry, partner, state) before acting; lib/approval.ts is kept for an
//     optional, off-by-default manual-confirm toggle.
//
// Wired into index.ts; compiles clean (tsc). Built to the VS-approved mapping in
// .plans/mcp-verb-mapping.md. Runtime-untested end-to-end pending a configured
// JULENNY_WORKDIR + an installed julenny-toolkit on the host.
// CLI gaps closed in the same v0.5.6 work (pending NUC build of the new CLI):
// `crypto inspect --json` (so `inspect` returns non-secret metadata) and
// `crypto combine --out-file` (so `decrypt_result` writes plaintext to disk and
// stays blind). Both verbs are now registered. `release` (family 1 + 2
// composition) is still pending VS open-question 2; left unregistered.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { runCli } from './lib/cli.js';
import { resolveInWorkdir } from './lib/paths.js';

const ok = (obj: Record<string, unknown>) => ({
  content: [{ type: 'text' as const, text: JSON.stringify({ ok: true, ...obj }, null, 2) }],
});
const fail = (error: string, extra: Record<string, unknown> = {}) => ({
  content: [{ type: 'text' as const, text: JSON.stringify({ ok: false, error, ...extra }, null, 2) }],
  isError: true,
});

export function registerToolkitTools(server: McpServer) {
  // ---- selftest (auto) ----
  server.tool(
    'selftest',
    'Run an OpenFHE round-trip sanity check (solo flow). Returns ok + context spec; no secrets.',
    {
      contextSpec: z.string().optional().describe('Crypto context spec to test'),
      multiParty: z.boolean().optional().describe('Exercise the multi-party path'),
    },
    async (p) => {
      try {
        const args = ['crypto', 'self-test'];
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        if (p.multiParty) args.push('--multi-party');
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'self-test failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ contextSpec: j.contextSpec ?? p.contextSpec, multiParty: j.multiParty ?? p.multiParty });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- signing_keygen (auto) ----
  server.tool(
    'signing_keygen',
    'Generate an Ed25519 identity keypair (one per company). Returns the public-key path only; the secret stays on disk and is never returned.',
    {
      outputSecret: z.string().describe('Workdir-relative output secret-key file name'),
      outputPublic: z.string().describe('Workdir-relative output public-key file name'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'signing-keygen',
          '--output-secret', resolveInWorkdir(p.outputSecret),
          '--output-public', resolveInWorkdir(p.outputPublic),
          '--json',
        ];
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'signing-keygen failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ publicKeyPath: j.publicKeyPath ?? p.outputPublic });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- generate_keys (auto) ----
  server.tool(
    'generate_keys',
    'Ensure a local FHE keypair exists for this crypto context (keys never leave the machine; returns the alias, not the bytes). Idempotent: if keys already exist this succeeds and leaves them untouched, so it is safe to call again and there is never a reason to retry it.',
    {
      contextSpec: z.enum(['bfv-default-v1', 'ckks-default-v1']).describe('Crypto context spec'),
      force: z.boolean().optional().describe('DESTRUCTIVE. Replaces existing keys for this context, which permanently breaks every collaboration already using them. Never pass this to resolve an error or because keys already exist; only when the user has explicitly asked to start over.'),
    },
    async ({ contextSpec, force }) => {
      // Passphrase comes from the environment (FHE_TOOLKIT_PASSPHRASE); never a
      // tool parameter, never returned.
      const args = ['keys', 'generate', '--context-spec', contextSpec, '--json'];
      if (force) args.push('--force');
      const r = await runCli(args);
      if (!r.ok) {
        // Keys already existing is the desired end state, not a failure.
        // Reporting it as one made clients retry in a loop, and the CLI's
        // "pass --force to overwrite" hint invites a destructive "fix".
        if (/already exist/i.test(r.error || '')) {
          return ok({
            contextSpec,
            alreadyExisted: true,
            note: 'Keys for this context already exist and were left untouched. Nothing further is needed; do not retry and do not pass force.',
          });
        }
        return fail(r.error || 'generate failed', { exitCode: r.exitCode });
      }
      const j = (r.json ?? {}) as Record<string, unknown>;
      return ok({ contextSpec, alreadyExisted: false, publicKeyAlias: j.publicKeyKey, secretKeyAlias: j.secretKeyKey });
    },
  );

  // ---- encrypt (auto) ----
  server.tool(
    'encrypt',
    'Encrypt a local input file under a joint public key. Returns the ciphertext path, never contents.',
    {
      input: z.string().describe('Workdir-relative input file name'),
      jointPublicKey: z.string().describe('Workdir-relative joint public key file name'),
      output: z.string().describe('Workdir-relative output ciphertext file name'),
      functionDef: z.string().optional().describe('Workdir-relative function-def JSON name (mode A)'),
      inputName: z.string().optional().describe('Function-def input name (mode A; required with functionDef)'),
      schema: z.enum(['indicator-hash', 'weight-vector', 'binary-indicator']).optional().describe('Encoding schema (mode B)'),
      contextSpec: z.string().optional().describe('Crypto context spec override'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'encrypt',
          '--input', resolveInWorkdir(p.input),
          '--joint-public-key', resolveInWorkdir(p.jointPublicKey),
          '--output', resolveInWorkdir(p.output),
        ];
        if (p.functionDef) {
          if (!p.inputName) return fail('inputName is required with functionDef (mode A)');
          args.push('--function-def', resolveInWorkdir(p.functionDef), '--input-name', p.inputName);
        } else if (p.schema) {
          args.push('--schema', p.schema);
        } else {
          return fail('provide either functionDef+inputName (mode A) or schema (mode B)');
        }
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'encrypt failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ outputPath: j.outputPath ?? p.output, slotCount: j.slotCount, ciphertextBytes: j.ciphertextBytes });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- partial_decrypt (auto: a partial reveals nothing on its own) ----
  server.tool(
    'partial_decrypt',
    "Produce this party's partial decryption of a result ciphertext. Returns the partial's path; a single partial reveals nothing.",
    {
      input: z.string().describe('Workdir-relative result ciphertext file name'),
      secretKey: z.string().describe('Workdir-relative secret-share file name'),
      output: z.string().describe('Workdir-relative output partial file name'),
      contextSpec: z.string().describe('Crypto context spec'),
      lead: z.boolean().optional().describe('True for the keysetup-lead party'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'partial-decrypt',
          '--context-spec', p.contextSpec,
          '--input', resolveInWorkdir(p.input),
          '--secret-key', resolveInWorkdir(p.secretKey),
          '--output', resolveInWorkdir(p.output),
        ];
        if (p.lead) args.push('--lead');
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'partial-decrypt failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ partialPath: j.outputPath ?? p.output });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- keysetup_contribute (auto: publishes a public contribution; secret stays local) ----
  server.tool(
    'keysetup_contribute',
    'Produce this party\'s joint-public-key contribution (lead/main). Returns the public output path; the secret share stays on disk and is never returned.',
    {
      role: z.enum(['lead', 'main']).describe('This party\'s keysetup role'),
      outputSecret: z.string().describe('Workdir-relative output secret-share file name'),
      outputPublic: z.string().describe('Workdir-relative output public-contribution file name'),
      peerShare: z.string().optional().describe('Workdir-relative peer public-share file name (main role)'),
      contextSpec: z.string().optional().describe('Crypto context spec'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'keysetup-contribute',
          '--role', p.role,
          '--output-secret', resolveInWorkdir(p.outputSecret),
          '--output-public', resolveInWorkdir(p.outputPublic),
        ];
        if (p.peerShare) args.push('--peer-share', resolveInWorkdir(p.peerShare));
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'keysetup-contribute failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ publicOutPath: j.outputPath ?? p.outputPublic });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- relin_contribute (auto: contribution ciphertext, reveals nothing alone) ----
  server.tool(
    'relin_contribute',
    'Produce a relinearization-key contribution for the given round (2-round protocol). Returns the output path.',
    {
      round: z.enum(['1', '2']).describe('Protocol round'),
      secretKey: z.string().describe('Workdir-relative secret-share file name'),
      output: z.string().describe('Workdir-relative output contribution file name'),
      role: z.enum(['lead', 'main']).optional().describe('This party\'s role'),
      peerShare: z.string().optional().describe('Workdir-relative peer share file name'),
      combinedR1: z.string().optional().describe('Workdir-relative combined round-1 file name (round 2)'),
      jointPk: z.string().optional().describe('Workdir-relative joint public key file name'),
      contextSpec: z.string().optional().describe('Crypto context spec'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'relin-contribute',
          '--round', p.round,
          '--secret-key', resolveInWorkdir(p.secretKey),
          '--output', resolveInWorkdir(p.output),
        ];
        if (p.role) args.push('--role', p.role);
        if (p.peerShare) args.push('--peer-share', resolveInWorkdir(p.peerShare));
        if (p.combinedR1) args.push('--combined-r1', resolveInWorkdir(p.combinedR1));
        if (p.jointPk) args.push('--joint-pk', resolveInWorkdir(p.jointPk));
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'relin-contribute failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ outputPath: j.outputPath ?? p.output });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- relin_combine (auto: deterministic combine of two contributions) ----
  server.tool(
    'relin_combine',
    'Deterministically combine two relinearization-key contributions for the given round. Returns the output path.',
    {
      round: z.enum(['1', '2']).describe('Protocol round'),
      shareA: z.string().describe('Workdir-relative contribution A file name'),
      shareB: z.string().describe('Workdir-relative contribution B file name'),
      output: z.string().describe('Workdir-relative output file name'),
      jointPk: z.string().optional().describe('Workdir-relative joint public key file name'),
      combinedR1: z.string().optional().describe('Workdir-relative combined round-1 file name (round 2)'),
      contextSpec: z.string().optional().describe('Crypto context spec'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'relin-combine',
          '--round', p.round,
          '--share-a', resolveInWorkdir(p.shareA),
          '--share-b', resolveInWorkdir(p.shareB),
          '--output', resolveInWorkdir(p.output),
        ];
        if (p.jointPk) args.push('--joint-pk', resolveInWorkdir(p.jointPk));
        if (p.combinedR1) args.push('--combined-r1', resolveInWorkdir(p.combinedR1));
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'relin-combine failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ outputPath: j.outputPath ?? p.output });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- sum_contribute (auto) ----
  server.tool(
    'sum_contribute',
    'Produce a sum-key contribution. Returns the output path; the secret share stays local.',
    {
      role: z.enum(['lead', 'main']).describe('This party\'s role'),
      secretKey: z.string().describe('Workdir-relative secret-share file name'),
      output: z.string().describe('Workdir-relative output contribution file name'),
      peerShare: z.string().optional().describe('Workdir-relative peer share file name'),
      jointPk: z.string().optional().describe('Workdir-relative joint public key file name'),
      contextSpec: z.string().optional().describe('Crypto context spec'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'sum-contribute',
          '--role', p.role,
          '--secret-key', resolveInWorkdir(p.secretKey),
          '--output', resolveInWorkdir(p.output),
        ];
        if (p.peerShare) args.push('--peer-share', resolveInWorkdir(p.peerShare));
        if (p.jointPk) args.push('--joint-pk', resolveInWorkdir(p.jointPk));
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'sum-contribute failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ outputPath: j.outputPath ?? p.output });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- sum_combine (auto) ----
  server.tool(
    'sum_combine',
    'Deterministically combine two sum-key contributions. Returns the output path.',
    {
      shareA: z.string().describe('Workdir-relative contribution A file name'),
      shareB: z.string().describe('Workdir-relative contribution B file name'),
      jointPk: z.string().describe('Workdir-relative joint public key file name'),
      output: z.string().describe('Workdir-relative output file name'),
      contextSpec: z.string().optional().describe('Crypto context spec'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'sum-combine',
          '--share-a', resolveInWorkdir(p.shareA),
          '--share-b', resolveInWorkdir(p.shareB),
          '--joint-pk', resolveInWorkdir(p.jointPk),
          '--output', resolveInWorkdir(p.output),
        ];
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'sum-combine failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ outputPath: j.outputPath ?? p.output });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- rotation_contribute (auto) ----
  server.tool(
    'rotation_contribute',
    'Produce a rotation-key contribution for the given slot indices. Returns the output path; the secret share stays local.',
    {
      role: z.enum(['lead', 'main']).describe('This party\'s role'),
      secretKey: z.string().describe('Workdir-relative secret-share file name'),
      indices: z.string().describe('Rotation slot indices (CLI-format string, e.g. comma-separated)'),
      output: z.string().describe('Workdir-relative output contribution file name'),
      peerShare: z.string().optional().describe('Workdir-relative peer share file name'),
      jointPk: z.string().optional().describe('Workdir-relative joint public key file name'),
      contextSpec: z.string().optional().describe('Crypto context spec'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'rotation-contribute',
          '--role', p.role,
          '--secret-key', resolveInWorkdir(p.secretKey),
          '--indices', p.indices,
          '--output', resolveInWorkdir(p.output),
        ];
        if (p.peerShare) args.push('--peer-share', resolveInWorkdir(p.peerShare));
        if (p.jointPk) args.push('--joint-pk', resolveInWorkdir(p.jointPk));
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'rotation-contribute failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ outputPath: j.outputPath ?? p.output });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- rotation_combine (auto) ----
  server.tool(
    'rotation_combine',
    'Deterministically combine two rotation-key contributions. Returns the output path.',
    {
      shareA: z.string().describe('Workdir-relative contribution A file name'),
      shareB: z.string().describe('Workdir-relative contribution B file name'),
      jointPk: z.string().describe('Workdir-relative joint public key file name'),
      output: z.string().describe('Workdir-relative output file name'),
      contextSpec: z.string().optional().describe('Crypto context spec'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'rotation-combine',
          '--share-a', resolveInWorkdir(p.shareA),
          '--share-b', resolveInWorkdir(p.shareB),
          '--joint-pk', resolveInWorkdir(p.jointPk),
          '--output', resolveInWorkdir(p.output),
        ];
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'rotation-combine failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ outputPath: j.outputPath ?? p.output });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- wrap_envelope (auto: signs a keysetup-message upload body) ----
  server.tool(
    'wrap_envelope',
    'Sign a keysetup-message upload body (a key-exchange contribution). Two modes: INLINE embeds a small payload file in the envelope; REFERENCE signs an already-uploaded large payload by objectKey + sizeBytes, so the registered envelope stays tiny instead of carrying a copy of the bytes. Provide EITHER payload OR objectKey+sizeBytes. Returns the signed envelope path.',
    {
      secretKey: z.string().describe('Workdir-relative Ed25519 signing-secret file name'),
      output: z.string().describe('Workdir-relative output envelope file name'),
      permissionId: z.string().describe('Permission id this message belongs to'),
      round: z.string().describe('Keysetup round identifier'),
      messageType: z.string().describe('Keysetup message type'),
      payload: z.string().optional().describe('INLINE mode: workdir-relative payload file to embed and sign. For small payloads. Mutually exclusive with objectKey.'),
      objectKey: z.string().optional().describe('REFERENCE mode: object-storage key of an already-uploaded payload to sign BY REFERENCE (keeps the envelope small for large payloads). Requires sizeBytes.'),
      sizeBytes: z.number().int().positive().optional().describe('REFERENCE mode: byte size of the referenced payload. Required with objectKey.'),
    },
    async (p) => {
      try {
        const usingRef = p.objectKey !== undefined;
        if (usingRef === (p.payload !== undefined)) {
          return fail('provide EITHER payload (inline) OR objectKey+sizeBytes (reference), not both or neither');
        }
        if (usingRef && p.sizeBytes === undefined) {
          return fail('reference mode (objectKey) requires sizeBytes');
        }
        const modeArgs = usingRef
          ? ['--object-key', p.objectKey as string, '--size-bytes', String(p.sizeBytes)]
          : ['--payload', resolveInWorkdir(p.payload as string)];
        const args = [
          'crypto', 'wrap-envelope',
          ...modeArgs,
          '--secret-key', resolveInWorkdir(p.secretKey),
          '--output', resolveInWorkdir(p.output),
          '--permission-id', p.permissionId,
          '--round', p.round,
          '--message-type', p.messageType,
          '--json',
        ];
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'wrap-envelope failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ envelopePath: j.outputPath ?? p.output, mode: usingRef ? 'reference' : 'inline' });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- wrap_final_keys_envelope (auto: signs the final-keys finalization body) ----
  server.tool(
    'wrap_final_keys_envelope',
    'Sign the final-keys finalization body. Returns the signed envelope path.',
    {
      toSign: z.string().describe('Workdir-relative file name to sign'),
      secretKey: z.string().describe('Workdir-relative Ed25519 signing-secret file name'),
      output: z.string().describe('Workdir-relative output envelope file name'),
    },
    async (p) => {
      try {
        const args = [
          'crypto', 'wrap-final-keys-envelope',
          '--to-sign', resolveInWorkdir(p.toSign),
          '--secret-key', resolveInWorkdir(p.secretKey),
          '--output', resolveInWorkdir(p.output),
          '--json',
        ];
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'wrap-final-keys-envelope failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ envelopePath: j.outputPath ?? p.output });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- decrypt_result (no forced gate; grant-governed) ----
  // The viewer is the party the grant authorizes to see the result. Uses the CLI's
  // --out-file so the plaintext goes to disk and stdout stays blind; the MCP never
  // returns the contents. No human prompt: the grant + the audit log govern this.
  server.tool(
    'decrypt_result',
    'Combine partial decryptions and write the plaintext result to a local file (only the result viewer the grant authorizes). Returns the file path, NEVER the contents.',
    {
      partials: z.array(z.string()).min(2).describe('Workdir-relative partial-decryption file names'),
      output: z.string().describe('Workdir-relative output plaintext file name'),
      contextSpec: z.string().describe('Crypto context spec'),
      real: z.boolean().optional().describe('CKKS: emit raw real values (no integer rounding)'),
    },
    async (p) => {
      try {
        const args = ['crypto', 'combine', '--context-spec', p.contextSpec];
        for (const name of p.partials) args.push('--partials', resolveInWorkdir(name));
        if (p.real) args.push('--real');
        // --out-file writes the plaintext result to disk; the CLI then prints
        // only references on stdout (no values), so this verb stays blind.
        args.push('--out-file', resolveInWorkdir(p.output));
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'combine failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ outputPath: j.outputPath ?? p.output });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );

  // ---- release (HUMAN-GATED) — NOT IMPLEMENTED YET ----
  // release = partial-decrypt + sign + POST /executions/{id}/partial-decrypt
  // (multipart file=partial bytes, header x-jl-signature=hex Ed25519 over the raw
  // bytes). This needs API-client composition (it spans family 1 + family 2) and
  // the exact endpoint shape is pending VS open-question 2
  // (.plans/mcp-verb-mapping.md). Left unregistered until that is settled; it must
  // ship HUMAN-gated (exposes the result to the other party).

  // ---- inspect (auto: non-secret ciphertext/context metadata) ----
  server.tool(
    'inspect',
    'Inspect a ciphertext file and return its non-secret metadata (ring/context parameters). No keys, no plaintext.',
    {
      input: z.string().describe('Workdir-relative ciphertext file name'),
      contextSpec: z.string().optional().describe('Context spec for the deserialization shim'),
    },
    async (p) => {
      try {
        const args = ['crypto', 'inspect', '--input', resolveInWorkdir(p.input)];
        if (p.contextSpec) args.push('--context-spec', p.contextSpec);
        args.push('--json');
        const r = await runCli(args);
        if (!r.ok) return fail(r.error || 'inspect failed', { exitCode: r.exitCode });
        const j = (r.json ?? {}) as Record<string, unknown>;
        return ok({ fileBytes: j.fileBytes, contextSpec: j.contextSpec, metadata: j.describe });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'invalid parameters');
      }
    },
  );
}
