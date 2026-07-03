// Argv-array runner for the julenny-fhe CLI.
//
// Security contract (cowork-mcp-security-guidelines.md §3): invoke the CLI by
// passing arguments as an argv ARRAY (never a shell string), with a pinned
// executable resolved once (not chosen by any tool parameter). No `sh -c`, no
// interpolation. This eliminates command injection via a parameter value.
//
// Blind-by-design (§4): callers return references/status only. This runner
// never logs argv values that might be sensitive and never surfaces raw stdout
// (which could carry plaintext) into an error; it returns parsed JSON to the
// verb, which then picks only non-secret fields.
//
// DRAFT (2026-06-15): unbuilt/untested while the sandbox shell is down.

import { execFile } from 'node:child_process';

// Pinned once at module load. Override only via a trusted env var, never via a
// tool parameter. Defaults to resolving `julenny-fhe` on PATH at spawn time.
const CLI_BIN = process.env.JULENNY_FHE_BIN || 'julenny-fhe';

export interface CliResult {
  ok: boolean;
  exitCode: number;
  /** Parsed JSON from stdout when the command was run with --json. */
  json?: unknown;
  /** Short, sanitized error summary (first stderr line). Never the full output. */
  error?: string;
}

/**
 * Run a julenny-fhe command. `args` is a fully-formed argv array built by the
 * caller from validated, typed parameters (resolved paths, whitelisted enums).
 * Always pass `--json` in `args` for machine-readable output.
 */
export function runCli(args: string[]): Promise<CliResult> {
  return new Promise((resolvePromise) => {
    execFile(
      CLI_BIN,
      args,
      { maxBuffer: 64 * 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) => {
        let json: unknown;
        if (stdout) {
          try {
            json = JSON.parse(stdout);
          } catch {
            // Non-JSON stdout (e.g. a command without --json, or a crash). Do
            // NOT surface raw stdout — it can contain plaintext. Leave json
            // undefined; the verb decides how to report.
          }
        }
        if (err) {
          const code = typeof (err as { code?: number }).code === 'number'
            ? (err as { code: number }).code
            : 1;
          // Surface only the first stderr line, capped. CLI errors are about
          // validation/paths, but cap defensively so nothing large leaks.
          const firstLine = (stderr || '').split('\n')[0]?.slice(0, 300) || 'command failed';
          resolvePromise({ ok: false, exitCode: code, json, error: firstLine });
          return;
        }
        resolvePromise({ ok: true, exitCode: 0, json });
      },
    );
  });
}
