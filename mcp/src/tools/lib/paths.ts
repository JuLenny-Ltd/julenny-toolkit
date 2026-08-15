// Working-directory path confinement for toolkit verbs.
//
// Security contract (cowork-mcp-security-guidelines.md §3): path-like inputs are
// workdir-relative NAMES, resolved and confined to an allowed working directory.
// Reject `..`, absolute paths outside the workdir, and symlink escapes. The
// agent never supplies an arbitrary absolute path.
//
// DRAFT (2026-06-15): unbuilt/untested while the sandbox shell is down.

import { realpathSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, resolve, relative, dirname, join } from 'node:path';

/** The single allowed working directory. JULENNY_WORKDIR is OPTIONAL (VS-agreed
 *  2026-06-21): if unset, default to a per-OS app-data path and create it on
 *  first run. Confinement still applies via resolveInWorkdir; defaulting only
 *  removes the requirement to set the env var. Never chosen by a tool parameter. */
export function workdir(): string {
  const wd = process.env.JULENNY_WORKDIR || defaultWorkdir();
  mkdirSync(wd, { recursive: true });   // create on first run; no-op if it exists
  // Canonicalize so symlink comparisons below are sound.
  return realpathSync(wd);
}

/** Per-OS default working directory, used when JULENNY_WORKDIR is unset.
 *  Windows: %LOCALAPPDATA%\julenny-toolkit\workdir
 *  else:    $XDG_DATA_HOME/julenny-toolkit/workdir (or ~/.local/share/...) */
function defaultWorkdir(): string {
  if (process.platform === 'win32') {
    const base = process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local');
    return join(base, 'julenny-toolkit', 'workdir');
  }
  const base = process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share');
  return join(base, 'julenny-toolkit', 'workdir');
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

  return candidate;
}
