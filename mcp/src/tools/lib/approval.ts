// Host-enforced human approval for sensitive verbs.
//
// Security contract (cowork-mcp-security-guidelines.md §6): decrypt_* and
// release_* MUST require explicit per-call human approval enforced by the MCP
// host/client, NOT by an instruction to the model and NOT by a model-suppliable
// `confirm: true` parameter. The approval must come from the user.
//
// Mechanism: MCP "elicitation" — the server asks the client to collect a
// confirmation from the user, who answers out-of-band from the model. If the
// connected client does not support elicitation (no approval channel), we FAIL
// CLOSED: deny the action. Never auto-approve.
//
// DRAFT (2026-06-15): the exact elicitation API surface must be validated
// against the installed @modelcontextprotocol/sdk version AND each target
// client (Claude Desktop, Cursor). Do NOT ship until a real, user-driven
// confirmation is verified end-to-end. Until then this denies by default.

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

export interface ApprovalRequest {
  /** Verb name, e.g. "decrypt_result" or "release". */
  verb: string;
  /** Human-readable summary of exactly what will run (verb + key params), so the
   *  user is not click-fatigued into approving exfiltration. */
  summary: string;
}

/**
 * Returns true only if a human explicitly approved. Fails closed (false) if no
 * host approval channel is available.
 */
export async function requireHumanApproval(
  server: McpServer,
  req: ApprovalRequest,
): Promise<boolean> {
  // The SDK exposes the low-level server (with client capabilities) under
  // server.server. Elicitation is only usable if the client advertised it.
  const low = (server as unknown as { server?: any }).server;
  const elicit = low?.elicitInput?.bind(low);

  if (typeof elicit !== 'function') {
    // No elicitation API in this SDK build — fail closed.
    return false;
  }

  try {
    const result = await elicit({
      message:
        `Approve ${req.verb}? This is a sensitive action.\n${req.summary}\n` +
        `Approving will run it now.`,
      requestedSchema: {
        type: 'object',
        properties: {
          approve: {
            type: 'boolean',
            description: 'Set true to approve this specific action.',
          },
        },
        required: ['approve'],
      },
    });
    // Only an explicit accept + approve:true counts.
    return result?.action === 'accept' && result?.content?.approve === true;
  } catch {
    // Client declined, cancelled, or errored -> fail closed.
    return false;
  }
}
