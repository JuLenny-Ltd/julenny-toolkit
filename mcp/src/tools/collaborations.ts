import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { JulennyApiClient } from '../api-client.js';

export function registerCollaborationTools(server: McpServer, api: JulennyApiClient) {
  server.tool(
    'list_collaborations',
    'List all collaborations (active and archived) with partner names, keysetup state, and permission count',
    { includeArchived: z.boolean().optional().describe('Include archived collaborations (default false)') },
    async ({ includeArchived }) => {
      const qs = includeArchived ? '?includeArchived=true' : '';
      const data = await api.get(`/api/fhe-projects${qs}`);
      const collabs = (data.projects || []).map((p: Record<string, unknown>) => ({
        id: p.id,
        name: p.name,
        yourRole: p.yourRole,
        partnerCompanyName: p.partnerCompanyName,
        status: p.status,
        keysetupState: p.keysetupState,
        grantCount: p.grantCount,
        scheme: (p.cryptoContextSpec as string)?.startsWith('ckks') ? 'CKKS' : 'BFV',
        createdAt: p.createdAt,
      }));
      return { content: [{ type: 'text' as const, text: JSON.stringify(collabs, null, 2) }] };
    },
  );

  server.tool(
    'create_collaboration',
    'Create a new collaboration with a partner company. Requires their collaboration ID (XXXX-XXXX format).',
    {
      name: z.string().describe('Name for the collaboration'),
      partnerCollaborationId: z.string().describe('Partner company collaboration ID (XXXX-XXXX)'),
      cryptoContextSpec: z.string().optional().describe('Crypto context (e.g. "bfv-default-v1", "ckks-default-v1")'),
    },
    async ({ name, partnerCollaborationId, cryptoContextSpec }) => {
      const data = await api.post('/api/fhe-projects', {
        name,
        partnerCompanyId: partnerCollaborationId,
        cryptoContextSpec: cryptoContextSpec || null,
      });
      return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
    },
  );
}
