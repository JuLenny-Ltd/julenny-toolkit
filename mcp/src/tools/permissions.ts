import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { JulennyApiClient } from '../api-client.js';

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
    },
    async (params) => {
      const data = await api.post('/api/fhe-permissions', {
        grantType: 'external',
        dataConsumerCompanyId: params.partnerCollaborationId,
        fheFunction: params.functionSlug,
        allowedExecutions: params.allowedExecutions,
        resultVisibility: params.resultVisibility || 'dataConsumer',
        expirationDate: params.expirationDate || null,
        projectId: params.projectId || null,
        jointKeyId: params.jointKeyId || null,
      });
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
    },
    async (params) => {
      const data = await api.post('/api/fhe-permissions', {
        grantType: 'internal',
        grants: params.functionSlugs.map(slug => ({
          fheFunction: slug,
          allowedExecutions: params.allowedExecutions,
          // Datasets are attached afterwards via declare_input_dataset, exactly as in
          // the external flow. Binding them at creation is impossible anyway: the
          // upload endpoint requires a permissionId, so no dataset can exist yet.
          allowedDatasetIds: [],
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
