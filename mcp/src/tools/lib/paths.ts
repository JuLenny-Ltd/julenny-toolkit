// Working-directory path confinement for toolkit verbs.
//
// Security contract (cowork-mcp-security-guidelines.md §3): path-like inputs are
// workdir-relative NAMES, resolved and confined to an allowed working directory.
// Reject `..`, absolute paths outside the workdir, and symlink escapes. The
// agent never supplies an arbitrary absolute path.

import { realpathSync, mkdirSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir } from 'node:os';
import { isAbsolute, resolve, relative, dirname, join } from 'node:path';

/** The single allowed working directory, and the SAME folder the scripts use.
 *
 *  Until v0.7.5 the two surfaces had roots of their own - the connector here, the
 *  scripts under ~/.julenny-collab - so a collaboration started on one could not be
 *  continued on the other, and key material had to be copied by hand. They now resolve
 *  ONE root, in the same order:
 *
 *    1. JULENNY_WORKDIR   - the folder the user picked at install time
 *    2. the saved setting - HKCU\Software\JuLenny\Toolkit\WorkDir on Windows,
 *                           $XDG_CONFIG_HOME/julenny/workdir elsewhere
 *    3. ~/julenny-workdir
 *
 *  Keep in step with scripts/_core/lib.sh and scripts/_core/lib.ps1. A mismatch does
 *  not fail loudly: each surface simply works in a different folder and reports that
 *  the other one's files are not there.
 *
 *  Confinement is unchanged and still applies through resolveInWorkdir. The root is
 *  never chosen by a tool parameter, so the model cannot move it. */
export function workdir(): string {
  const wd = process.env.JULENNY_WORKDIR || savedWorkdir() || defaultWorkdir();
  mkdirSync(wd, { recursive: true });   // create on first run; no-op if it exists
  // Canonicalize so symlink comparisons below are sound.
  return realpathSync(wd);
}

/** The folder the installer recorded, or undefined when nothing was recorded.
 *
 *  Windows keeps it in the registry, which is what the installer writes and what
 *  lib.ps1 reads. Every other platform keeps it in a one-line text file written by the
 *  .deb postinst. Node has no registry API, so the Windows path shells out to `reg`;
 *  it runs once, at the first path resolution, and any failure falls through to the
 *  default rather than stopping the server. */
function savedWorkdir(): string | undefined {
  try {
    if (process.platform === 'win32') {
      const out = execFileSync(
        'reg',
        ['query', 'HKCU\\Software\\JuLenny\\Toolkit', '/v', 'WorkDir'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true },
      );
      // A REG_SZ line looks like:  "    WorkDir    REG_SZ    C:\Users\you\julenny-workdir"
      const m = out.match(/WorkDir\s+REG_[A-Z_]+\s+(.+?)\s*$/m);
      const value = m?.[1]?.trim();
      return value ? value : undefined;
    }
    const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
    const value = readFileSync(join(base, 'julenny', 'workdir'), 'utf8').split(/\r?\n/)[0].trim();
    return value ? value : undefined;
  } catch {
    // Nothing recorded, or no installer has ever run here. Not an error: the connector
    // must still work from a plain checkout.
    return undefined;
  }
}

/** Where the working folder goes when nothing is set and nothing was recorded. The same
 *  path lib.sh and lib.ps1 fall back to, so two un-installed checkouts still meet. */
function defaultWorkdir(): string {
  return join(homedir(), 'julenny-workdir');
}

/** Resolve the realpath of the nearest existing ancestor of `p` (so we can
 *  detect symlink escapes even when the target file does not exist yet). */
function realExistingPrefix(p: string): string {
  let cur = p;
  // Walk up until realpathSync succeeds.
  // Guard against infinite loop at filesystem root.
  for (let i = 0; i < 4096; i++) {
    try {
      return realpathSync(cur);
    } catch {
      const parent = dirname(cur);
      if (parent === cur) return parent; // reached root
      cur = parent;
    }
  }
  return cur;
}

/**
 * Resolve a workdir-relative `name` to an absolute path, confined to the
 * working directory. Throws on any escape. Use for every path-like verb input.
 *
 * @param name  a workdir-relative name (NOT an absolute path, no `..` segments)
 */
export function resolveInWorkdir(name: string): string {
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('path name must be a non-empty string');
  }
  if (isAbsolute(name)) {
    throw new Error(`absolute paths are not allowed: ${name}`);
  }
  if (name.split(/[\\/]/).some((seg) => seg === '..')) {
    throw new Error(`parent-directory segments ('..') are not allowed: ${name}`);
  }

  const wd = workdir();
  const candidate = resolve(wd, name);

  // 1) lexical containment
  const rel = relative(wd, candidate);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
    throw new Error(`path escapes the working directory: ${name}`);
  }

  // 2) symlink containment (resolve the nearest existing ancestor)
  const realPrefix = realExistingPrefix(candidate);
  const realRel = relative(wd, realPrefix);
  if (realRel.startsWith('..') || isAbsolute(realRel)) {
    throw new Error(`path resolves (via symlink) outside the working directory: ${name}`);
  }

  // 3) Create the parent directory. A caller naming an output like
  // 'keysetup/peer-pk-share.bin' is asking for a subfolder, and every write verb used to
  // fail with a bare ENOENT because nothing created it. Containment is proven above, so
  // this can only ever create directories inside the workdir.
  const parent = dirname(candidate);
  if (parent !== wd) {
    try { mkdirSync(parent, { recursive: true }); } catch { /* a genuinely bad path still fails at the write */ }
  }

  return candidate;
}
