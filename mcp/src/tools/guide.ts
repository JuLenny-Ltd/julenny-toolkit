// next_step - the navigation verb. Given a permissionId, it reads LIVE platform
// state (permission detail, keysetup manifest, declared inputs, executions) and
// returns the caller's current stage plus the exact next verb(s) to call. It is
// a family-1 read only: no crypto, no secret material, no plaintext. It does not
// replace the per-verb security checks (the platform stays the backstop); it
// just lets an agent navigate the flow without carrying the example scripts.
//
// Stage model mirrors the server instructions block:
//   discover -> keysetup -> provide-inputs -> run -> decrypt
//
// Role mapping (the platform uses two naming systems):
//   permission.role  : 'dataOwner' | 'dataConsumer'
//   keysetup party   : 'owner'     | 'consumer'      (owner == keysetup LEAD)
//   function-def role : 'dataOwner' | 'queryAnalyst' (queryAnalyst == consumer)

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { JulennyApiClient } from '../api-client.js';

const ok = (obj: Record<string, unknown>) => ({
  content: [{ type: 'text' as const, text: JSON.stringify({ ok: true, ...obj }, null, 2) }],
});
const fail = (error: string, extra: Record<string, unknown> = {}) => ({
  content: [{ type: 'text' as const, text: JSON.stringify({ ok: false, error, ...extra }, null, 2) }],
  isError: true,
});

interface RoundEntry { round: number; messageType: string; description: string; expectedParty: 'both' | 'owner' | 'consumer'; }

export function registerGuideTools(server: McpServer, api: JulennyApiClient) {
  server.tool(
    'next_step',
    "Navigate the multi-party FHE flow: given a permissionId, read live platform state and report your current stage (discover/keysetup/provide-inputs/run/decrypt) and the exact next verb(s) to call. Read-only and blind; the platform still enforces every action independently. Call this whenever you are unsure what to do next.",
    {
      permissionId: z.string().describe('Permission id to evaluate'),
    },
    async (p) => {
      try {
        const perm = await api.get(`/api/fhe-permissions/${p.permissionId}`);

        const role: string = perm.role; // 'dataOwner' | 'dataConsumer'
        const myParty: 'owner' | 'consumer' = role === 'dataOwner' ? 'owner' : 'consumer';
        const fnRole: string = role === 'dataOwner' ? 'dataOwner' : 'queryAnalyst';
        const amViewer: boolean = perm.resultVisibility === role;
        const leadFlag: boolean = role === 'dataOwner'; // owner == keysetup lead

        // An INTERNAL grant is a solo self-test: one company on both sides. It follows a
        // different sequence (see SOLO SELF-TEST in the server instructions) and, critically,
        // its keysetup is reported COMPLETE at creation while holding no keys. The stage
        // machine below is built for the two-party flow, so flag the difference rather than
        // silently routing a solo caller down it.
        const isSolo = perm.grantType === 'internal';

        const base = {
          permissionId: p.permissionId,
          role,
          resultVisibility: perm.resultVisibility,
          youAre: isSolo ? 'both parties (solo self-test)' : (amViewer ? 'result viewer' : 'result releaser'),
          function: perm.fheFunction,
          functionVersion: perm.functionVersion,
          ...(isSolo ? {
            grantType: 'internal',
            soloWarning: 'SOLO SELF-TEST. Keysetup shows complete but this grant may hold NO KEYS - that is how internal grants are created. Before encrypting or running, confirm you have built and registered the joint public key and the final relinearization key yourself (SOLO SELF-TEST in the server instructions). Skipping that spends a credit and fails inside the engine. There is no release step and no peer to wait for; decrypt with TWO partial_decrypt calls (one per secret share) and decrypt_result.',
          } : {}),
        };

        // ---- expiry / terminal ----
        if (perm.isExpired || perm.status === 'expired') {
          return ok({ ...base, stage: 'expired', summary: 'This permission has expired; no further actions are possible.', nextActions: [] });
        }

        // ---- STAGE 1: keysetup (permission not active, OR keysetup unfinished) ----
        //
        // Gate on keysetupState as well as status. A permission can be
        // status:'active' - a valid, granted permission - while its joint keys
        // are still being built. Checking status alone skipped this entire stage
        // and reported 'provide-inputs', sending the agent to encrypt under a
        // joint key that does not exist yet. run.sh branches on keysetupState for
        // exactly this reason.
        const ksState = String(perm.keysetupState || '');
        const keysetupUnfinished = ksState !== '' && ksState !== 'complete';
        if (perm.status !== 'active' || keysetupUnfinished) {
          let ks: any;
          try { ks = await api.get(`/api/fhe-permissions/${p.permissionId}/keysetup`); }
          catch {
            return ok({ ...base, stage: 'keysetup', summary: `Keysetup is in progress (permission status: ${perm.status}). Follow STAGE 1 in the server instructions.`, nextActions: ['register_signing_key (once per crypto context)', 'keysetup_contribute / relin_contribute per round', 'publish_keysetup_message / download_keysetup_message to exchange'] });
          }

          const myCollab: string | undefined = ks?.participants?.[myParty]?.collaborationId;
          const myContribs: number[] = (myCollab && ks.contributions?.[myCollab]) || [];

          if (ks.state === 'AWAITING_FINALIZATION') {
            const iFinalized = !!(myCollab && ks.finalKeySubmissions?.[myCollab]);
            if (iFinalized) {
              return ok({ ...base, stage: 'keysetup-finalize-wait', keysetup: { state: ks.state }, summary: 'You have submitted final keys. BLOCKED on the other party to finalize theirs before the permission activates. TELL THE USER to ask them to run their finalize step; polling alone will not unblock it.', nextActions: ['TELL THE USER to ask the other party to finalize', 'then call next_step again'] });
            }
            return ok({ ...base, stage: 'keysetup-finalize', keysetup: { state: ks.state }, summary: 'All keysetup rounds are in. Finalize the joint keys.', nextActions: ['publish_final_keys (joint public key + relin key, plus sum/rotation keys only if requiredEvalKeys lists them)'] });
          }

          const entry: RoundEntry | undefined = (ks.roundManifest || []).find((e: RoundEntry) => e.round === ks.currentRound);
          const ksInfo = { state: ks.state, currentRound: ks.currentRound, totalRounds: ks.totalRounds, round: entry ? { messageType: entry.messageType, description: entry.description, expectedParty: entry.expectedParty } : null };

          // Report EVERY round this party still owes, not just currentRound.
          //
          // currentRound only advances once the round it names is satisfied, so when it sits on a
          // round the peer owes, this side looked "blocked" - even when a LATER round is ours alone
          // and needs nothing from them. That is exactly why the example scripts bundle pk-share
          // with relin-round1 and publish both at once: relin-round1 is owner-only and does not
          // depend on the peer's pk-share at all.
          //
          // Gating on currentRound alone stopped an agent one message short and stalled the whole
          // collaboration, with each side waiting on the other. Scan the manifest instead.
          const owed: RoundEntry[] = (ks.roundManifest || []).filter((e: RoundEntry) =>
            (e.expectedParty === 'both' || e.expectedParty === myParty) && !myContribs.includes(e.round),
          ).sort((a: RoundEntry, b: RoundEntry) => a.round - b.round);

          if (owed.length > 0) {
            const first = owed[0];
            const alsoOwed = owed.slice(1);
            return ok({
              ...base,
              stage: 'keysetup',
              keysetup: { ...ksInfo, roundsYouOwe: owed.map(e => ({ round: e.round, messageType: e.messageType, expectedParty: e.expectedParty })) },
              summary: owed.length === 1
                ? `Your turn: keysetup round ${first.round}/${ks.totalRounds} (${first.messageType} - ${first.description}). Contribute it, then publish the round message for the peer.`
                : `You owe ${owed.length} keysetup rounds: ${owed.map(e => `${e.round} (${e.messageType})`).join(', ')}. Do them ALL now, in order, publishing each. Do not stop after the first and wait: the later ones do not depend on the peer, and stopping early stalls both sides.`,
              nextActions: [
                'register_signing_key first if you have not for this crypto context',
                ...owed.map(e => `contribute round ${e.round} (${e.messageType}) via the matching keysetup verb, then publish_keysetup_message`),
                ...(alsoOwed.length > 0 ? ['then call next_step again to confirm nothing else is outstanding'] : []),
              ],
            });
          }
          return ok({ ...base, stage: 'keysetup-wait', keysetup: ksInfo, summary: `BLOCKED on the ${entry ? entry.expectedParty : 'other'} party for keysetup round ${ks.currentRound}/${ks.totalRounds}. Nothing on this side can progress until they act, and polling alone will never unblock it. TELL THE USER to contact the other party and ask them to run their side now, naming the round that is outstanding. Do not call further keysetup verbs until their message has landed.`, nextActions: ['TELL THE USER to ask the other party to run their side for this round', 'download_keysetup_message (from=peer) once it has landed', 'then call next_step again'] });
        }

        // A solo (internal) grant is created with keysetupState already 'complete' while
        // holding NO keys, so the two-party gate above never fires and the caller was routed
        // straight to 'provide-inputs' - told to encrypt under a joint key that does not
        // exist. The soloWarning said the opposite in the same response, leaving the agent to
        // reconcile a contradiction against its own tool. Settle it from live state instead:
        // if no final keys are registered, this IS the keysetup stage, whatever state claims.
        if (isSolo) {
          let soloKs: any = null;
          try {
            soloKs = await api.get('/api/fhe-permissions/' + p.permissionId + '/keysetup');
          } catch { soloKs = null; }
          const finalSubs = (soloKs && soloKs.finalKeySubmissions) || {};
          if (Object.keys(finalSubs).length === 0) {
            return ok({
              ...base,
              stage: 'keysetup',
              summary: 'SOLO SELF-TEST: no final keys are registered for this permission yet, even though keysetup reports complete. You hold BOTH sides, so nothing is blocked on anyone else - build and register the keys yourself before encrypting. Follow SOLO SELF-TEST in the server instructions.',
              nextActions: [
                'signing_keygen, then register_signing_key for the crypto context',
                "keysetup_contribute role 'lead', then role 'main' with peerShare - keep BOTH secrets",
                'relin_contribute / relin_combine rounds 1 and 2 (plus sum_/rotation_ verbs only if requiredEvalKeys lists them)',
                'publish_final_keys with the JOINT public key and the FINAL relin key',
                'then call next_step again',
              ],
            });
          }
        }

        // ---- permission is active: fetch def inputs + declared datasets ----
        const v = perm.functionVersion || '1.0.0';
        let def: any;
        try { def = await api.get(`/api/functions/${perm.fheFunction}/${v}/definition`); }
        catch (e) { return fail(`could not load function definition for ${perm.fheFunction} ${v}: ${(e as Error).message}`); }
        const inputs: Array<{ name: string; role: string; layout?: string; encodingRecipe?: unknown }> = def.inputs || [];

        // Rotation state lives on the keysetup document, not the permission, and nothing
        // else in the MCP surfaced it - an agent that had submitted all three rounds had
        // no way to confirm the platform accepted them.
        let ksRotation: unknown = null;
        let rotationRounds: Array<{ round: number; messageType: string }> = [];
        try {
          const ksDoc = await api.get(`/api/fhe-permissions/${p.permissionId}/keysetup`) as Record<string, unknown>;
          ksRotation = ksDoc.pendingRotationKeySetup ?? null;
          rotationRounds = ((ksDoc.roundManifest as Array<{ round: number; messageType: string }>) || [])
            .filter((e) => typeof e.messageType === 'string' && e.messageType.startsWith('rotation-'));
        } catch { ksRotation = null; }

        let declared: Record<string, { datasetId?: string }> = {};
        try { declared = await api.get(`/api/fhe-permissions/${p.permissionId}/preferred-datasets`); }
        catch { declared = {}; }
        const isDeclared = (name: string) => !!declared?.[name]?.datasetId;

        // Solo means one company holds BOTH roles, so every input is yours. Filtering by
        // fnRole listed only dataset_a and silently hid dataset_b, which the caller must also
        // provide - the run then blocks on an input nothing ever asked them for.
        const myInputs = isSolo ? inputs : inputs.filter(i => i.role === fnRole);
        const missingMine = myInputs.filter(i => !isDeclared(i.name));
        const allDeclared = inputs.every(i => isDeclared(i.name));

        // ---- STAGE 2: provide your inputs ----
        if (missingMine.length > 0) {
          const actions = missingMine.map(i => {
            const bundle = i.layout === 'encrypted-bundle' && i.encodingRecipe;
            const steps = bundle
              ? `encode_recipe -> encrypt -> upload -> declare_input_dataset`
              : `encrypt (or upload as-is if plaintext) -> upload -> declare_input_dataset`;
            return `input '${i.name}' (layout ${i.layout || 'n/a'}): ${steps}`;
          });
          return ok({ ...base, stage: 'provide-inputs', summary: `Provide your ${missingMine.length} undeclared input(s). Get the signed def first with get_function_definition(saveAs) if you have not.`, yourUndeclaredInputs: missingMine.map(i => i.name), nextActions: actions });
        }

        // ---- your inputs are in; look at executions ----
        let execs: any[] = [];
        try { const r = await api.get(`/api/fhe-permissions/${p.permissionId}/executions`); execs = r.executions || r || []; }
        catch { execs = []; }
        const byState = (s: string) => execs.find(e => e.state === s);
        const released = byState('released');
        const awaitingRelease = byState('awaiting-release');
        const inFlight = execs.find(e => !['released', 'failed', 'completed', 'viewed', 'expired'].includes(e.state) && e.state !== 'awaiting-release');

        // ---- STAGE 4: decrypt / release ----
        if (released && amViewer) {
          return ok({ ...base, stage: 'decrypt', executionId: released.id, summary: 'The result is released and you are the viewer. Download both partials and combine.', nextActions: [`download_result(executionId=${released.id})`, `download_partial(executionId=${released.id}) for the releaser's partial`, `partial_decrypt your own share (lead:${leadFlag})`, 'decrypt_result to combine; the plaintext is written to a workdir file you read from disk'] });
        }
        if (awaitingRelease && !amViewer) {
          return ok({ ...base, stage: 'release', executionId: awaitingRelease.id, summary: 'An execution is awaiting release and you are the releaser. Release your partial so the viewer can combine.', nextActions: [`release(executionId=${awaitingRelease.id})`] });
        }
        if (awaitingRelease && amViewer) {
          return ok({ ...base, stage: 'decrypt-wait', executionId: awaitingRelease.id, summary: 'BLOCKED on the releaser: they must upload their partial decryption before you can combine and see the answer. TELL THE USER to ask the other party to run their release step; polling alone will not unblock it.', nextActions: ['TELL THE USER to ask the other party to release', 'then call next_step again'] });
        }
        if (released && !amViewer) {
          return ok({ ...base, stage: 'done', executionId: released.id, summary: 'Released. The other party is the viewer; nothing left on your side for this execution.', nextActions: [] });
        }
        if (inFlight) {
          return ok({ ...base, stage: 'running', executionId: inFlight.id, summary: `Execution ${inFlight.id} is in state '${inFlight.state}'. Poll until it releases.`, nextActions: [`get_execution_status(executionId=${inFlight.id})`, 'then call next_step again'] });
        }

        // ---- STAGE 3: ready to run (no pending execution) ----
        // Solo callers never reach here with undeclared inputs (myInputs covers both roles
        // above), and there is no peer to be blocked on regardless.
        if (!allDeclared && !isSolo) {
          return ok({ ...base, stage: 'await-peer-inputs', summary: 'Your inputs are declared. BLOCKED on the other party to declare theirs before an execution can run. TELL THE USER to ask them to upload and declare their input; polling alone will not unblock it.', nextActions: ['TELL THE USER to ask the other party to declare their inputs', 'then call next_step again'] });
        }
        // Rotation is the last gate and the only one with no round of its own until the
        // rule-list input is declared: the platform derives the index set from that file,
        // then grows the manifest. Until this reads 'complete' an execution will spend a
        // credit and fail inside the engine, so check it before ever reporting 'run'.
        {
          const rot = ksRotation as Record<string, unknown> | null | undefined;
          if (rot && rot.status !== 'complete') {
            const status = String(rot.status ?? 'unknown');
            const outstanding = (rotationRounds.length ? rotationRounds : [
              { round: '?', messageType: 'rotation-round1' },
              { round: '?', messageType: 'rotation-round1-continue' },
              { round: '?', messageType: 'rotation-combine' },
            ]).map((e) => `round ${e.round}: ${e.messageType}`);
            return ok({
              ...base,
              stage: 'rotation-keysetup',
              rotation: { status, indexCount: ((rot.indices as unknown[]) || []).length },
              summary: `This function needs a ROTATION key and its setup is '${status}', not 'complete'. Do NOT trigger: it would spend a credit and fail inside the engine. Build the rotation key and submit it with publish_rotation_key, which handles all three rounds. Rotation keys are NOT accepted by publish_final_keys, and putting one in another key's slot is accepted by the platform but silently produces a wrong answer.`,
              outstandingRounds: outstanding,
              nextActions: [
                'derive_rotation_indices(rulePairs, contextSpec) to get the index set - do NOT read the rule file or ask for filesystem access',
                'rotation_contribute for each secret share, then rotation_combine',
                'publish_rotation_key(leadContribution, mainContribution, combined, signingKey)',
                'get_rotation_status to confirm it reads complete, then call next_step again',
              ],
            });
          }
        }

        if (role === 'dataConsumer') {
          if ((perm.remainingExecutions ?? 1) <= 0) {
            return ok({ ...base, stage: 'exhausted', summary: 'All inputs are declared but this permission has no remaining executions.', nextActions: ['request more executions from the data owner (add_executions on their side)'] });
          }
          return ok({ ...base, stage: 'run', remainingExecutions: perm.remainingExecutions, summary: 'All inputs are declared. You are the consumer; trigger the execution.', nextActions: ['estimate_execution (optional cost preview)', 'trigger_execution'] });
        }
        if (isSolo) {
          // There is no consumer to ask: the caller holds both roles. Telling a solo tester to
          // go and chase a counterparty is advice for a person who does not exist.
          return ok({ ...base, stage: 'run', remainingExecutions: perm.remainingExecutions, summary: 'All inputs are declared. This is a solo self-test, so you are the consumer as well - trigger the execution yourself. There is nobody to wait for.', nextActions: ['estimate_execution (optional cost preview)', 'trigger_execution'] });
        }
        return ok({ ...base, stage: 'await-trigger', summary: 'All inputs are declared. You are the data owner. BLOCKED on the consumer to trigger the execution; you then release or they view, per resultVisibility. TELL THE USER to ask the consumer to run it; polling alone will not unblock it.', nextActions: ['TELL THE USER to ask the consumer to trigger the execution', 'then call next_step again'] });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'next_step failed');
      }
    },
  );
}
