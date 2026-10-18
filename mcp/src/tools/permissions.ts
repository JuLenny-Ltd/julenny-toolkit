import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { JulennyApiClient } from '../api-client.js';
import { datasetSizeOfFile, isLargerSize } from './lib/dataset-size.js';

const DATA_FILE_HELP = "Large-dataset functions only (Joint Record Overlap for Large Datasets): the NAME of the "
  + "user's data file in the working folder. ASK THE USER which file it is; never read it. The local "
  + "toolkit counts its records and works out the dataset size; you learn only the size, never the count.";
const COLUMNS_HELP = "Optional, with dataFile: the columns that identify a record, exactly as you will pass to "
  + "encrypt ('all' or 1-based numbers like '1,3'), so the same rows are counted.";

/**
 * A large-dataset permission's size in the words the user is shown, or undefined for every other
 * function (the platform sends null). Whose move a proposed size waits on follows the list: the
 * data owner proposes it (granted), the partner confirms or increases it (received).
 */
function datasetSizeText(p: Record<string, unknown>, view: 'granted' | 'received'): string | undefined {
  const d = p.datasetSize as { size?: string; status?: string } | null | undefined;
  if (!d?.size) return undefined;
  if (d.status === 'confirmed') return `Up to ${d.size} records, confirmed by both companies`;
  return view === 'granted'
    ? `Up to ${d.size} records, waiting for your partner to confirm`
    : `Up to ${d.size} records, proposed by your partner: confirm it or increase it`;
}

function fail(text: string) {
  return { content: [{ type: 'text' as const, text }], isError: true };
}

export function registerPermissionTools(server: McpServer, api: JulennyApiClient) {
  server.tool(
    'list_permissions_granted',
    'List permissions you have granted to partners',
    {},
    async () => {
      const data = await api.get('/api/fhe-permissions?view=granted');
      const perms = (data.permissions || []).map((p: Record<string, unknown>) => ({
        id: p.id,
        function: p.fheFunctionName,
        partner: p.dataConsumerCompanyName,
        collaboration: p.projectName,
        status: p.status,
        keysetupState: p.keysetupState,
        resultVisibility: p.resultVisibility,
        executionsUsed: (p.allowedExecutions as number) - (p.remainingExecutions as number),
        executionsTotal: p.allowedExecutions,
        expirationDate: p.expirationDate,
        datasetSize: datasetSizeText(p, 'granted'),
      }));
      return { content: [{ type: 'text' as const, text: JSON.stringify(perms, null, 2) }] };
    },
  );

  server.tool(
    'list_permissions_received',
    'List permissions you have received from partners',
    {},
    async () => {
      const data = await api.get('/api/fhe-permissions?view=received');
      const perms = (data.permissions || []).map((p: Record<string, unknown>) => ({
        id: p.id,
        function: p.fheFunctionName,
        from: p.dataOwnerCompanyName,
        collaboration: p.projectName,
        status: p.status,
        keysetupState: p.keysetupState,
        resultVisibility: p.resultVisibility,
        executionsUsed: (p.allowedExecutions as number) - (p.remainingExecutions as number),
        executionsTotal: p.allowedExecutions,
        expirationDate: p.expirationDate,
        datasetSize: datasetSizeText(p, 'received'),
      }));
      return { content: [{ type: 'text' as const, text: JSON.stringify(perms, null, 2) }] };
    },
  );

  server.tool(
    'create_permission',
    'Grant a partner permission to run an FHE function on your data',
    {
      partnerCollaborationId: z.string().describe('Partner collaboration ID (XXXX-XXXX)'),
      functionSlug: z.string().describe('Function slug. Many functions come in -count and -itemized variants: -count returns a single number, -itemized returns which entries matched. Confirm which the user wants rather than picking one.'),
      allowedExecutions: z.number().describe('Max number of executions allowed. ASK THE USER; do not guess a value. Each execution costs credits, and running out means the data owner must top up before the consumer can run again (see add_executions). A permission cannot be created without this, so confirm it up front.'),
      resultVisibility: z.enum(['dataOwner', 'dataConsumer']).optional().describe('Who decrypts and sees the plaintext result. Exactly one side sees it: dataConsumer (default) or dataOwner. There is NO mode where both sides see the result - do not offer that as a choice. The other side contributes its half of the threshold decryption without ever seeing the answer.'),
      expirationDate: z.string().optional().describe('ISO date when the permission expires. Ask the user whether they want one; omit it for no expiry. Unlike allowedExecutions this cannot be extended later, so a short expiry silently strands the collaboration.'),
      projectId: z.string().optional().describe('Existing collaboration/project ID to add permission to'),
      jointKeyId: z.string().optional().describe('Joint key ID from an existing collaboration'),
      dataFile: z.string().optional().describe(DATA_FILE_HELP + ' The size proposed is the smallest that holds this file; your partner confirms it, or increases it if their data is larger. Omit it for every other function.'),
      columns: z.string().optional().describe(COLUMNS_HELP),
    },
    async (params) => {
      let datasetSize: string | undefined;
      if (params.dataFile) {
        const sized = await datasetSizeOfFile(api, {
          dataFile: params.dataFile, slug: params.functionSlug, role: 'dataOwner', columns: params.columns,
        });
        if ('error' in sized) return fail(sized.error);
        datasetSize = sized.size;
      }
      const data = await api.post('/api/fhe-permissions', {
        grantType: 'external',
        dataConsumerCompanyId: params.partnerCollaborationId,
        fheFunction: params.functionSlug,
        allowedExecutions: params.allowedExecutions,
        resultVisibility: params.resultVisibility || 'dataConsumer',
        expirationDate: params.expirationDate || null,
        projectId: params.projectId || null,
        jointKeyId: params.jointKeyId || null,
        ...(datasetSize ? { datasetSize } : {}),
      });
      return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
    },
  );

  // ---- confirm_dataset_size (the partner's answer to a proposed size) ----
  // A large-dataset permission is created with a PROPOSED size; until the partner confirms or
  // increases it, nothing can be set up or encrypted. Once, and only the partner (the data
  // consumer). The agent decides nothing: the local toolkit sizes the partner's file, and the
  // answer is the same size (confirm), a larger one (increase to exactly that) or a smaller one
  // (confirm the proposed size, which can never go down). An increase is final.
  server.tool(
    'confirm_dataset_size',
    "Large-dataset permissions only, and only for the partner (data consumer): settle the dataset size the data owner proposed. Call next_step first; its stage 'size-confirm' says a size is waiting. ASK THE USER which file in the working folder holds their data (its name only). The local toolkit checks it: if it fits the proposed size the size is confirmed, and if it is larger the size is increased to the smallest that holds it. You learn only the size. Once done, the size is locked for the permission.",
    {
      permissionId: z.string().describe('The permission whose dataset size to settle'),
      dataFile: z.string().describe(DATA_FILE_HELP),
      columns: z.string().optional().describe(COLUMNS_HELP),
    },
    async (params) => {
      const perm = await api.get(`/api/fhe-permissions/${params.permissionId}`) as {
        fheFunction?: string; functionVersion?: string;
        datasetSize?: { size?: string; status?: string } | null;
      };
      const proposed = perm.datasetSize?.size;
      if (!perm.datasetSize || !proposed) return fail('This permission has no dataset size.');
      if (perm.datasetSize.status !== 'proposed') {
        return fail(`The dataset size is already confirmed (up to ${proposed} records).`);
      }
      const sized = await datasetSizeOfFile(api, {
        dataFile: params.dataFile, slug: String(perm.fheFunction), version: perm.functionVersion,
        role: 'dataConsumer', columns: params.columns,
      });
      if ('error' in sized) return fail(sized.error);
      const increase = isLargerSize(sized.size, proposed);
      const data = await api.post(`/api/fhe-permissions/${params.permissionId}/dataset-size`,
        increase ? { action: 'increase', datasetSize: sized.size } : { action: 'confirm' });
      return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
    },
  );

  // ---- create_self_test_permission (internal grant; no partner) ----
  // A separate verb rather than a flag on create_permission, because the two have
  // disjoint requirements: external needs a partner collaboration id and a result
  // visibility choice, internal needs neither (one company holds both roles and
  // decrypts its own result). The platform also takes them on different request
  // shapes - internal MUST use the `grants` array form, and the legacy single-grant
  // shape is external-only and rejects grantType 'internal' outright.
  server.tool(
    'create_self_test_permission',
    "Create an INTERNAL (solo self-test) permission: your own company granting to itself, no partner, no counterparty. This is what a trial account uses. It skips the two-party keysetup handshake, which means YOU must build and register the evaluation keys yourself afterwards - follow SOLO SELF-TEST in the server instructions. Without them, any function that multiplies ciphertexts fails inside the engine AFTER consuming a credit. Ask the user which function(s) and how many executions before calling.",
    {
      functionSlugs: z.array(z.string()).min(1).describe('One or more function slugs. One permission is created per slug, so a single call can set up a whole self-test sweep. ASK THE USER which functions they want.'),
      allowedExecutions: z.number().describe('Max executions per function. ASK THE USER; each execution costs credits.'),
      expirationDate: z.string().optional().describe('ISO expiry date. Omit for none. Cannot be extended later.'),
      dataFiles: z.array(z.string()).min(1).max(2).optional().describe('Large-dataset functions only: the NAMES of the two data files in the working folder, first input then second (ASK THE USER; never read them). The local toolkit works out the smallest dataset size that holds both; you learn only the size. With no partner it is confirmed at once. Omit it for every other function.'),
      columns: z.string().optional().describe(COLUMNS_HELP),
    },
    async (params) => {
      // One size per slug: the larger of what each file needs, each counted as its own input.
      const sizes: Record<string, string> = {};
      if (params.dataFiles) {
        for (const slug of params.functionSlugs) {
          let largest: string | undefined;
          for (const [i, file] of params.dataFiles.entries()) {
            const sized = await datasetSizeOfFile(api, {
              dataFile: file, slug, role: i === 0 ? 'dataOwner' : 'dataConsumer', columns: params.columns,
            });
            if ('error' in sized) return fail(sized.error);
            if (!largest || isLargerSize(sized.size, largest)) largest = sized.size;
          }
          if (largest) sizes[slug] = largest;
        }
      }
      const data = await api.post('/api/fhe-permissions', {
        grantType: 'internal',
        grants: params.functionSlugs.map(slug => ({
          fheFunction: slug,
          allowedExecutions: params.allowedExecutions,
          // Datasets are attached afterwards via declare_input_dataset, exactly as in
          // the external flow. Binding them at creation is impossible anyway: the
          // upload endpoint requires a permissionId, so no dataset can exist yet.
          allowedDatasetIds: [],
          ...(sizes[slug] ? { datasetSize: sizes[slug] } : {}),
        })),
        expirationDate: params.expirationDate || null,
      }) as { permissionIds?: string[] };
      return { content: [{ type: 'text' as const, text: JSON.stringify({
        permissionIds: data.permissionIds ?? [],
        note: 'Created. Keysetup reports COMPLETE but NO keys exist yet. Build and register them (SOLO SELF-TEST in the server instructions) before encrypting or running.',
      }, null, 2) }] };
    },
  );

  server.tool(
    'add_executions',
    'Add more executions to an existing permission. Use this when a permission has run out rather than creating a new one: it tops up the existing grant, so the joint keys are kept and no new keysetup is needed. Only the data owner can do this.',
    {
      permissionId: z.string().describe('Permission ID'),
      count: z.number().describe('Number of executions to add'),
    },
    async ({ permissionId, count }) => {
      const data = await api.patch('/api/fhe-permissions', {
        permissionId,
        action: 'add-executions',
        count,
      });
      return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
    },
  );

  server.tool(
    'revoke_permission',
    'Revoke a permission you previously granted',
    { permissionId: z.string().describe('Permission ID to revoke') },
    async ({ permissionId }) => {
      const data = await api.patch('/api/fhe-permissions', {
        permissionId,
        action: 'revoke',
      });
      return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
    },
  );
}
