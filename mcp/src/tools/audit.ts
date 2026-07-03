import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { JulennyApiClient } from '../api-client.js';

export function registerAuditTools(server: McpServer, api: JulennyApiClient) {
  server.tool(
    'get_audit_log',
    'Get audit log entries for a collaboration or across all collaborations',
    {
      projectId: z.string().optional().describe('Filter by collaboration/project ID'),
      permissionId: z.string().optional().describe('Filter by permission ID'),
      scope: z.enum(['company']).optional().describe('Set to "company" for all logs'),
      eventType: z.string().optional().describe('Filter by event category (keysetup, execution, dataset, permission)'),
      limit: z.number().optional().describe('Max entries to return (default 50)'),
    },
    async ({ projectId, permissionId, scope, eventType, limit }) => {
      const params = new URLSearchParams();
      if (permissionId) params.set('permissionId', permissionId);
      else if (projectId) params.set('projectId', projectId);
      else params.set('scope', scope || 'company');
      if (eventType) params.set('eventType', eventType);
      if (limit) params.set('limit', String(limit));
      const data = await api.get(`/api/fhe-audit-log?${params}`);
      return { content: [{ type: 'text' as const, text: JSON.stringify(data.entries || [], null, 2) }] };
    },
  );
}
