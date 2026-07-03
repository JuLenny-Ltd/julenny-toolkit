import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { JulennyApiClient } from '../api-client.js';

export function registerDatasetTools(server: McpServer, api: JulennyApiClient) {
  server.tool(
    'list_datasets',
    'List your uploaded encrypted datasets',
    {},
    async () => {
      const data = await api.get('/api/fhe-datasets');
      const datasets = (data.datasets || []).map((d: Record<string, unknown>) => ({
        id: d.id,
        name: d.name,
        description: d.description,
        fileName: d.fileName,
        kind: d.kind || 'ciphertext',
        sizeBytes: d.sizeBytes,
        status: d.status,
        projectId: d.projectId,
        createdAt: d.createdAt,
        expiresAt: d.expiresAt,
      }));
      return { content: [{ type: 'text' as const, text: JSON.stringify(datasets, null, 2) }] };
    },
  );

  server.tool(
    'list_collaboration_datasets',
    'List all datasets in a collaboration (yours and your partner\'s)',
    { permissionId: z.string().describe('Permission ID to list datasets for') },
    async ({ permissionId }) => {
      const data = await api.get(`/api/fhe-permissions/${permissionId}/datasets`);
      const datasets = (data.datasets || []).map((d: Record<string, unknown>) => ({
        id: d.id,
        name: d.name,
        role: d.role,
        isYours: d.isYours,
        kind: d.kind,
        fileName: d.fileName,
        createdAt: d.createdAt,
      }));
      return { content: [{ type: 'text' as const, text: JSON.stringify(datasets, null, 2) }] };
    },
  );
}
