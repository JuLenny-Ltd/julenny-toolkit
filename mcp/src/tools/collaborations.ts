import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { JulennyApiClient } from '../api-client.js';

export function registerCollaborationTools(server: McpServer, api: JulennyApiClient) {
  server.tool(
    'list_collaborations',
    "List all collaborations (active and archived) with the peer's collaboration id, keysetup state, and permission count",
    { includeArchived: z.boolean().optional().describe('Include archived collaborations (default false)') },
    async ({ includeArchived }) => {
      const qs = includeArchived ? '?includeArchived=true' : '';
      const data = await api.get(`/api/fhe-projects${qs}`);
      const collabs = (data.projects || []).map((p: Record<string, unknown>) => ({
        id: p.id,
        name: p.name,
        yourRole: p.yourRole,
        // The peer is identified by collaboration id, the public handle the two sides
        // exchanged to set this up. The API does not give company names to API keys, so
        // that an agent driving these steps never learns who you are working with.
        peerCollaborationId: p.partnerCollaborationId ?? p.ownerCollaborationId ?? null,
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
    'Create a new collaboration with a partner company. Requires their collaboration ID (XXXX-XXXX format). ASK THE USER for the collaboration name and the partner collaboration ID before calling this; do not invent a name. The name is what BOTH companies see in their collaboration list, so a made-up one leaves the partner unable to recognise what they have been invited to.',
    {
      name: z.string().describe('Name for the collaboration. Ask the user for this; never invent one.'),
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
