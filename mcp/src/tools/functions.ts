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
        // The current version. Without it the version was not discoverable anywhere, and
        // get_function_definition had to be guessed at. A PERMISSION pins its own version,
        // which next_step reports and which may be older than this one; when working on a
        // permission, use that.
        version: fn.version,
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
      version: z.string().optional().describe('Version, e.g. "1.0.1". Omit to use the function\'s current version. Working on a PERMISSION? Pass the version that permission pinned (next_step reports it) - it may be older than the current one, and the ciphertext was verified against that exact definition.'),
      saveAs: z.string().optional().describe('Optional workdir-relative filename to write the full definition JSON to (e.g. "function-def.json"). Required for mode-A encryption, which reads the signed def from a file.'),
    },
    async ({ slug, version, saveAs }) => {
      // Ask the registry rather than assuming. This defaulted to "1.0.0", which is wrong
      // for every function that has ever been bumped: on 2026-09-19 an agent asking for
      // joint-record-overlap-count (then at 1.0.1) got a 404 and started guessing version
      // numbers. The endpoint is version-exact by design, because a permission must get
      // the definition it agreed to, so the default has to be resolved, not guessed.
      let v = version;
      if (!v) {
        const list = await api.get('/api/functions') as { functions?: Array<Record<string, unknown>> };
        const fn = (list.functions || []).find(f => f.slug === slug);
        if (!fn?.version) {
          throw new Error(`Cannot resolve a version for '${slug}'. Call list_functions to see the available slugs and versions, or pass version explicitly.`);
        }
        v = fn.version as string;
      }
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
