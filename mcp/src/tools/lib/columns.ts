// Which columns of a CSV were hashed, remembered per dataset.
//
// WHY THIS EXISTS. Hash-based matching (`indicator-hash`) can match on a subset of a
// file's columns. Resolution RE-HASHES the local file to name the rows that matched, so
// it has to compose each row exactly as encryption did. Get that wrong and nothing
// matches: no error, no warning, just an empty result that looks like an honest "no
// overlap". The choice therefore has to be remembered at encrypt time, not guessed later.
//
// SHARED WITH THE SCRIPTS. Both surfaces read and write the same two files, with
// the same names, the same keys and the same values, at the top of the working folder:
//
//   dataset_columns.json   { "<datasetId>": "all" | "1,3" }
//   dataset_csv_map.json   { "<datasetId>": "<the local file that was encrypted>" }
//
// They sit at the ROOT rather than inside collabs/<jointKeyId>/ because dataset ids are
// unique platform-wide and the connector does not know the joint key id at upload time.
// Root also means one file to look at, whichever surface wrote it.
//
// EVERY encrypt is recorded, including "all". That is what lets resolution tell "this
// file was encrypted with all columns" apart from "nobody knows how this file was
// encrypted" - and refuse in the second case rather than silently matching nothing.

import { readFile, writeFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { workdir } from './paths.js';

export const COLUMNS_MAP = 'dataset_columns.json';
export const CSV_MAP = 'dataset_csv_map.json';

/** Choices made by `encrypt` that do not have a dataset id yet, keyed by the ciphertext
 *  file encrypt produced. `upload` moves them across once the platform assigns an id.
 *  Connector-internal, which is why the name is not one the scripts know about. */
const PENDING_MAP = '.julenny-pending-columns.json';

export interface PendingEncrypt {
  /** The column spec passed to the CLI: 'all', or something like '1,3'. */
  columns: string;
  /** The local file that was encrypted, so resolution can find it again by name. */
  input: string;
}

async function readMap(name: string): Promise<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(await readFile(join(workdir(), name), 'utf8')) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    // Missing or unreadable is the normal first-run case, and a corrupt file must not
    // stop a run: the worst outcome is that resolution asks which columns were used.
    return {};
  }
}

/** Merge one entry into a JSON map at the top of the working folder.
 *
 *  Read-modify-write through a temporary file in the same folder, so a crash cannot
 *  leave a half-written map behind and take the other entries with it. Two surfaces
 *  writing at the same instant could still lose one entry, but they are driven by one
 *  person at a keyboard, and the cost of a lost entry is a question, not a wrong answer. */
async function setMapEntry(name: string, key: string, value: unknown): Promise<void> {
  const dir = workdir();
  const target = join(dir, name);
  const map = await readMap(name);
  map[key] = value;
  const tmp = join(dir, `.${name}.tmp`);
  await writeFile(tmp, JSON.stringify(map, null, 2) + '\n', 'utf8');
  await rename(tmp, target);
}

/** Record a column choice that has no dataset id yet, keyed by the ciphertext file. */
export async function rememberPendingColumns(ciphertextFile: string, entry: PendingEncrypt): Promise<void> {
  await setMapEntry(PENDING_MAP, ciphertextFile, entry);
}

/** Promote a pending choice to a real dataset id, once the upload has one.
 *
 *  Silently does nothing when this ciphertext was not produced by `encrypt` in this
 *  working folder - an upload of something built elsewhere is legitimate, and there is
 *  nothing truthful to record about it. */
export async function promotePendingColumns(ciphertextFile: string, datasetId: string): Promise<PendingEncrypt | undefined> {
  const pending = await readMap(PENDING_MAP);
  const entry = pending[ciphertextFile] as PendingEncrypt | undefined;
  if (!entry || typeof entry.columns !== 'string') return undefined;
  await setMapEntry(COLUMNS_MAP, datasetId, entry.columns);
  if (entry.input) await setMapEntry(CSV_MAP, datasetId, entry.input);
  return entry;
}

/** The column spec recorded for a dataset id, or undefined if none was. */
export async function columnsForDataset(datasetId: string): Promise<string | undefined> {
  const value = (await readMap(COLUMNS_MAP))[datasetId];
  return typeof value === 'string' && value ? value : undefined;
}

/** The column spec recorded for a local file, found through the dataset that was made
 *  from it. Used when the caller names the CSV but not the dataset.
 *
 *  A file can legitimately back more than one dataset - the same customer list encrypted
 *  for two permissions. When every one of them agrees on the columns, which is the normal
 *  case, the answer is unambiguous and is returned. When they disagree, this returns
 *  undefined rather than picking one: the caller then asks, which is the only safe move. */
export async function columnsForFile(file: string): Promise<string | undefined> {
  const csvMap = await readMap(CSV_MAP);
  const columnsMap = await readMap(COLUMNS_MAP);
  const found = new Set<string>();
  for (const [datasetId, input] of Object.entries(csvMap)) {
    if (input !== file) continue;
    const spec = columnsMap[datasetId];
    if (typeof spec === 'string' && spec) found.add(spec);
  }
  return found.size === 1 ? [...found][0] : undefined;
}
