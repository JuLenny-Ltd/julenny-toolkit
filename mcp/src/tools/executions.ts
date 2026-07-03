import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { JulennyApiClient } from '../api-client.js';

export function registerExecutionTools(server: McpServer, api: JulennyApiClient) {
  server.tool(
    'list_executions',
    'List executions for a permission, showing state, duration, and timing',
    { permissionId: z.string().describe('Permission ID') },
    async ({ permissionId }) => {
      const data = await api.get(`/api/fhe-permissions/${permissionId}/executions`);
      const execs = (data.executions || []).map((e: Record<string, unknown>) => ({
        id: e.id,
        state: e.state,
        triggeredAt: e.triggeredAt,
        completedAt: e.completedAt,
        measuredDurationSec: e.measuredDurationSec,
        yourRole: e.yourRole,
        triggeredBy: e.triggeredBy,
        resultVisibility: e.resultVisibility,
      }));
      return { content: [{ type: 'text' as const, text: JSON.stringify(execs, null, 2) }] };
    },
  );

  server.tool(
    'estimate_execution',
    'Get a cost estimate for running an execution. Returns pricing options and a quote token.',
    {
      permissionId: z.string().describe('Permission (grant) ID'),
      inputDatasetIds: z.array(z.string()).describe('Array of dataset IDs to use as inputs'),
      engine: z.string().optional().describe('Engine to estimate for (e.g. "openfhe-cpu", "fideslib-ckks-gpu")'),
    },
    async ({ permissionId, inputDatasetIds, engine }) => {
      const body: Record<string, unknown> = { inputDatasetIds };
      if (engine) body.engine = engine;
      const data = await api.post(`/api/grants/${permissionId}/estimate`, body);
      return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
    },
  );

  server.tool(
    'trigger_execution',
    'Trigger an FHE computation. Requires dataset IDs and optionally a quote token from estimate.',
    {
      permissionId: z.string().describe('Permission (grant) ID'),
      inputDatasetIds: z.array(z.string()).describe('Array of dataset IDs'),
      quoteToken: z.string().optional().describe('Quote token from estimate (locks in price)'),
      engine: z.string().optional().describe('Engine override (e.g. "fideslib-ckks-gpu")'),
    },
    async ({ permissionId, inputDatasetIds, quoteToken, engine }) => {
      const body: Record<string, unknown> = { inputDatasetIds };
      if (quoteToken) body.quoteToken = quoteToken;
      if (engine) body.engine = engine;
      const data = await api.post(`/api/grants/${permissionId}/execute`, body);
      return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
    },
  );

  server.tool(
    'get_execution_status',
    'Check the current state of an execution',
    { executionId: z.string().describe('Execution ID') },
    async ({ executionId }) => {
      const data = await api.get(`/api/executions/${executionId}`);
      return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
    },
  );
}
