import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { writeFile } from 'node:fs/promises';
import { JulennyApiClient } from '../api-client.js';
import { resolveInWorkdir } from './lib/paths.js';

export function registerFunctionTools(server: McpServer, api: JulennyApiClient) {
  server.tool(
    'list_functions',
    'List all available FHE functions with descriptions, schemes, and supported engines',
    {},
    async () => {
      const data = await api.get('/api/functions');
      const fns = (data.functions || []).map((fn: Record<string, unknown>) => ({
        slug: fn.slug,
        name: fn.name,
        description: fn.description,
        scheme: fn.scheme,
        category: fn.category,
        inputs: (fn.inputs as Array<{ name: string; role: string }>)?.length || 0,
        supportedEngines: fn.supportedEngines,
      }));
      return { content: [{ type: 'text' as const, text: JSON.stringify(fns, null, 2) }] };
    },
  );

  server.tool(
    'get_function_definition',
    'Get the full, registry-signed definition of an FHE function (inputs, output, opsHash, requiredEvalKeys, cryptoContextSpec, and the registry signature block). Optionally write it verbatim to a workdir file via saveAs so `crypto encrypt` mode A (and the recipe executor) can consume it; the registry signature + opsHash are preserved so the toolkit can verify the function id.',
    {
      slug: z.string().describe('Function slug (e.g. "joint-record-overlap-itemized")'),
      version: z.string().optional().describe('Version (default "1.0.0")'),
      saveAs: z.string().optional().describe('Optional workdir-relative filename to write the full definition JSON to (e.g. "function-def.json"). Required for mode-A encryption, which reads the signed def from a file.'),
    },
    async ({ slug, version, saveAs }) => {
      const v = version || '1.0.0';
      const data = await api.get(`/api/functions/${slug}/${v}/definition`);
      const json = JSON.stringify(data, null, 2);
      if (saveAs) {
        const out = resolveInWorkdir(saveAs);
        await writeFile(out, json);
        return { content: [{ type: 'text' as const, text: JSON.stringify({ ok: true, savedTo: out, slug, version: v }, null, 2) }] };
      }
      return { content: [{ type: 'text' as const, text: json }] };
    },
  );
}
