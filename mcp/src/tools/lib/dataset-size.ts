// The dataset size of a large-dataset permission, worked out from a data file by the LOCAL toolkit.
// The agent cannot know how many records a file holds and must never learn it: it names the file,
// the toolkit counts the records exactly as encryption will, and only the size ("1K") comes back.
// The connector itself never reads the file either.
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { JulennyApiClient } from '../../api-client.js';
import { runCli } from './cli.js';
import { resolveInWorkdir } from './paths.js';

/** Smallest first, as the platform and the toolkit order them. */
export const DATASET_SIZES = ['1K', '2K', '4K', '8K', '16K', '32K', '64K'] as const;

export function isLargerSize(a: string, b: string): boolean {
  return DATASET_SIZES.indexOf(a as typeof DATASET_SIZES[number])
    > DATASET_SIZES.indexOf(b as typeof DATASET_SIZES[number]);
}

/** The function's current version, as get_function_definition resolves it. */
async function currentVersion(api: JulennyApiClient, slug: string): Promise<string> {
  const list = await api.get('/api/functions') as { functions?: Array<Record<string, unknown>> };
  const fn = (list.functions ?? []).find(f => f.slug === slug);
  if (!fn?.version) throw new Error(`Unknown function '${slug}'. Call list_functions to see the available ones.`);
  return String(fn.version);
}

export interface SizeRequest {
  /** Workdir-relative name of the data file. Never read here: the toolkit reads it. */
  dataFile: string;
  slug: string;
  /** The version the permission pinned; omitted when creating one (the current version). */
  version?: string;
  /** Which of the function's two record inputs the file is for. */
  role: 'dataOwner' | 'dataConsumer';
  /** As the user will pass to encrypt; the same rows must be counted. */
  columns?: string;
}

export async function datasetSizeOfFile(
  api: JulennyApiClient,
  req: SizeRequest,
): Promise<{ size: string } | { error: string }> {
  const version = req.version ?? await currentVersion(api, req.slug);
  const def = await api.get(`/api/functions/${req.slug}/${version}/definition`) as {
    inputs?: Array<{ name?: string; role?: string; schema?: string }>;
  };
  const records = (def.inputs ?? []).filter(i => i.schema === 'signature-table');
  if (records.length === 0) return { error: `'${req.slug}' does not take a dataset size.` };
  // The data owner's input is the one its role names; the partner's is the other one.
  const input = req.role === 'dataOwner'
    ? records.find(i => i.role === 'dataOwner')
    : records.find(i => i.role !== 'dataOwner');
  if (!input?.name) return { error: `'${req.slug}' has no input for this side.` };

  // Saved verbatim, signature intact: the toolkit verifies it before trusting how to read rows.
  const defName = `function-defs/${req.slug}-${version}.json`;
  const defPath = resolveInWorkdir(defName);
  await mkdir(dirname(defPath), { recursive: true });
  await writeFile(defPath, JSON.stringify(def, null, 2));

  const columns = (req.columns ?? '').trim();
  if (columns && columns !== 'all' && !/^\d+(,\d+)*$/.test(columns)) {
    return { error: `columns must be 'all' or 1-based column numbers like '1,3' (got '${columns}')` };
  }
  const args = [
    'crypto', 'dataset-size',
    '--input', resolveInWorkdir(req.dataFile),
    '--function-def', defPath,
    '--input-name', input.name,
    ...(columns && columns !== 'all' ? ['--columns', columns] : []),
    '--json',
  ];
  const r = await runCli(args);
  const j = (r.json ?? {}) as { status?: string; datasetSize?: string; message?: string };
  if (r.ok && j.status === 'ok' && j.datasetSize) return { size: j.datasetSize };
  // The toolkit's messages here carry no record count, by design (crypto dataset-size).
  return { error: j.message || r.error || 'The dataset size could not be worked out from this file.' };
}
