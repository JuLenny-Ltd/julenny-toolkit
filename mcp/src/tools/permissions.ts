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
      functionSlug: z.string().describe('Function slug'),
      allowedExecutions: z.number().describe('Max number of executions allowed'),
      resultVisibility: z.enum(['dataOwner', 'dataConsumer']).optional().describe('Who sees results (default: dataConsumer)'),
      expirationDate: z.string().optional().describe('ISO date when permission expires'),
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

  server.tool(
    'add_executions',
    'Add more executions to an existing permission',
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
