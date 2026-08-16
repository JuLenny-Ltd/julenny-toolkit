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

        const base = {
          permissionId: p.permissionId,
          role,
          resultVisibility: perm.resultVisibility,
          youAre: amViewer ? 'result viewer' : 'result releaser',
          function: perm.fheFunction,
          functionVersion: perm.functionVersion,
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
          const myTurn = !!entry && (entry.expectedParty === 'both' || entry.expectedParty === myParty) && !myContribs.includes(ks.currentRound);
          const ksInfo = { state: ks.state, currentRound: ks.currentRound, totalRounds: ks.totalRounds, round: entry ? { messageType: entry.messageType, description: entry.description, expectedParty: entry.expectedParty } : null };

          if (myTurn) {
            return ok({ ...base, stage: 'keysetup', keysetup: ksInfo, summary: `Your turn: keysetup round ${ks.currentRound}/${ks.totalRounds} (${entry!.messageType} - ${entry!.description}). Contribute it, then publish the round message for the peer.`, nextActions: ['register_signing_key first if you have not for this crypto context', `contribute round ${ks.currentRound} (${entry!.messageType}) via the matching keysetup verb`, 'publish_keysetup_message to send it to the peer'] });
          }
          return ok({ ...base, stage: 'keysetup-wait', keysetup: ksInfo, summary: `BLOCKED on the ${entry ? entry.expectedParty : 'other'} party for keysetup round ${ks.currentRound}/${ks.totalRounds}. Nothing on this side can progress until they act, and polling alone will never unblock it. TELL THE USER to contact the other party and ask them to run their side now, naming the round that is outstanding. Do not call further keysetup verbs until their message has landed.`, nextActions: ['TELL THE USER to ask the other party to run their side for this round', 'download_keysetup_message (from=peer) once it has landed', 'then call next_step again'] });
        }

        // ---- permission is active: fetch def inputs + declared datasets ----
        const v = perm.functionVersion || '1.0.0';
        let def: any;
        try { def = await api.get(`/api/functions/${perm.fheFunction}/${v}/definition`); }
        catch (e) { return fail(`could not load function definition for ${perm.fheFunction} ${v}: ${(e as Error).message}`); }
        const inputs: Array<{ name: string; role: string; layout?: string; encodingRecipe?: unknown }> = def.inputs || [];

        let declared: Record<string, { datasetId?: string }> = {};
        try { declared = await api.get(`/api/fhe-permissions/${p.permissionId}/preferred-datasets`); }
        catch { declared = {}; }
        const isDeclared = (name: string) => !!declared?.[name]?.datasetId;

        const myInputs = inputs.filter(i => i.role === fnRole);
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
        if (!allDeclared) {
          return ok({ ...base, stage: 'await-peer-inputs', summary: 'Your inputs are declared. BLOCKED on the other party to declare theirs before an execution can run. TELL THE USER to ask them to upload and declare their input; polling alone will not unblock it.', nextActions: ['TELL THE USER to ask the other party to declare their inputs', 'then call next_step again'] });
        }
        if (role === 'dataConsumer') {
          if ((perm.remainingExecutions ?? 1) <= 0) {
            return ok({ ...base, stage: 'exhausted', summary: 'All inputs are declared but this permission has no remaining executions.', nextActions: ['request more executions from the data owner (add_executions on their side)'] });
          }
          return ok({ ...base, stage: 'run', remainingExecutions: perm.remainingExecutions, summary: 'All inputs are declared. You are the consumer; trigger the execution.', nextActions: ['estimate_execution (optional cost preview)', 'trigger_execution'] });
        }
        return ok({ ...base, stage: 'await-trigger', summary: 'All inputs are declared. You are the data owner. BLOCKED on the consumer to trigger the execution; you then release or they view, per resultVisibility. TELL THE USER to ask the consumer to run it; polling alone will not unblock it.', nextActions: ['TELL THE USER to ask the consumer to trigger the execution', 'then call next_step again'] });
      } catch (e) {
        return fail(e instanceof Error ? e.message : 'next_step failed');
      }
    },
  );
}
