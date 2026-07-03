# JuLenny FHE Multi-Party Demo - Development Plan

**Status: v0.1 draft, 2026-05-14. Internal planning artifact, not for
public release.** A collaborative working document for the Cowork
session (Windows app + Linux CLI) and VS Code session (platform,
frontend, backend, wrapper, web UI). Edits welcome from either side.

## Scope

Deliver the two-party joint compute demo per `docs/demo-script.md`:

- Two companies (Acme as data owner, BetaCorp as consumer) collaborate
  on running a function against each other's data without either side
  ever seeing the other's plaintext.
- App is offline-only (file-based); web UI and REST API are the customer-
  facing surfaces.
- Joint cryptographic key is established once per company-pair (shared
  across multiple permissions until rotated).
- Result ciphertext is gated: visible to data owner only during her
  approval stage, visible to consumer only after data owner has
  contributed her partial decryption.
- Six visible user steps in the demo. ~4-6 minute live demo length.

## Caveat on current-state knowledge

The Cowork session knows the toolkit codebase well. The VS Code session
knows the platform (frontend, backend, wrapper, Firestore, web UI) well.
Where this doc says "needed" or "proposed", VS Code may already have
some or all of it. Where it says "we believe", that's a guess that VS
Code may want to confirm or correct. Treat the proposals as starting
points, not specifications.

## 1. Firestore schema

### 1a. New collection: `fhe_joint_keys`

Holds the per-company-pair joint key state. One document per
collaboration relationship.

Proposed fields:

```
{
  id: string (uuid),
  companyAId: string,
  companyBId: string,
  // The actual joint public key bytes (or a storagePath pointer if
  // big). The combined output of both parties' keysetup contributions.
  publicKeyData: string (base64) OR storagePath: string,
  // Eval keys (relinearization, sum) similarly produced from the
  // multi-round protocol.
  evalKeysData: string OR storagePath: string,
  // Lifecycle
  status: "pending-setup" | "active" | "rotated" | "revoked",
  createdAt: string,
  activatedAt: string (when status moved to active),
  rotatedAt: string | null,
  revokedAt: string | null,
  // Audit
  createdByCompanyId: string (whichever side initiated),
  cryptoContextSpec: string (e.g., "bfv-default-v1")
}
```

**Open question for VS Code**: should we use a deterministic ID like
`companyA_companyB` (sorted) or a UUID? Deterministic makes lookup
simpler ("does Acme+Beta already have an active joint key?"); UUID
allows multiple historical keys to coexist for the same pair across
rotations.

### 1b. New collection: `fhe_keysetup_sessions`

Tracks the multi-round protocol contributions during keysetup. One
document per (joint key, round) tuple, or one document per joint key
with a contributions sub-array. Either works.

Proposed shape (sub-array approach):

```
{
  jointKeyId: string,
  rounds: [
    {
      roundNumber: int,
      contributions: [
        {
          fromCompanyId: string,
          storagePath: string (path to the contribution blob),
          submittedAt: string
        }
      ],
      combinedStorage: string | null,
      combinedAt: string | null
    }
  ],
  status: "in-progress" | "complete",
  startedAt: string,
  completedAt: string | null
}
```

**Open question for VS Code**: does the multi-round structure need to
be exposed to the customer, or can we hide it (the customer just sees
"keysetup in progress" / "keysetup complete")? OpenFHE's relin-key
protocol is 2 sub-rounds; sum-key is 2 sub-rounds. We can collapse the
UX to "submit your share once" and the platform orchestrates the rounds
behind the scenes if it's easier.

### 1c. `fhe_permissions` - additions

Add fields to existing documents:

```
{
  ...existing fields...,
  jointKeyId: string,           // NEW - reference to fhe_joint_keys doc
}
```

Existing fields already in place: `dataOwnerCompanyId`,
`dataConsumerCompanyId`, `fheFunction`, `allowedDatasetIds`,
`allowedExecutions`, `remainingExecutions`, `status`, `expirationDate`.

### 1d. `fhe_datasets` - additions

Add fields:

```
{
  ...existing fields...,
  permissionId: string,         // NEW - reference to fhe_permissions
  cryptoContextSpec: string,    // NEW - which OpenFHE context the ciphertext is encoded under (denormalized for the wrapper)
  isEncrypted: bool,            // NEW - distinguish encrypted blobs from any plaintext fixtures
}
```

`permissionId` lets the wrapper find the right joint key (via
permission -> jointKeyId). Without it the wrapper can't know which key
the ciphertext is under.

**Open question for VS Code**: does the existing dataset model already
cover this somehow (e.g., encryption metadata stored alongside the
storagePath), or is this truly additive?

### 1e. New collection: `fhe_results`

Per-execution result, with the state machine that gates visibility.

Proposed fields:

```
{
  id: string (uuid),
  permissionId: string,
  triggeredByCompanyId: string,
  triggeredAt: string,
  // The encrypted result ciphertext
  resultStoragePath: string,
  resultSizeBytes: int,
  // Data owner's partial decryption (uploaded during their approval)
  dataOwnerPartialStoragePath: string | null,
  dataOwnerPartialSubmittedAt: string | null,
  // State machine
  status: "computing" | "pending-data-owner-approval" |
          "decryption-ready" | "decrypted" | "expired" | "errored",
  computedAt: string | null,
  decryptionReadyAt: string | null,
  decryptedAt: string | null,
  expiresAt: string,  // platform-configured retention
  // Error info if errored
  error: string | null
}
```

The status field is what the API uses to gate visibility (see API
section).

### 1f. Notifications - new event types

If there's an `fhe_notifications` or similar collection, add event types:

- `keysetup_share_needed`: to a company when the other side has started
  a keysetup and they need to contribute their share.
- `keysetup_complete`: to both parties when the joint key is ready.
- `permission_accepted` / `permission_rejected`: already may exist.
- `result_awaiting_approval`: to data owner when consumer ran execute.
- `result_ready`: to consumer when data owner has approved decryption.
- `result_expired`: to either party if the result timed out unapproved.

**Open question for VS Code**: how does the existing notifications
system work and what shape are events in? May already have a generic
event type that just needs new sub-types added.

## 2. Backend API endpoints

Customer-facing URLs are all under `/api/*` on the frontend. The
frontend proxies FHE routes to the backend.

### 2a. Joint key lifecycle

```
POST /api/joint-keys
  body: { counterpartyCompanyId, cryptoContextSpec, initiatorShareFile }
  - Data owner (or either party who initiates) creates the keysetup
    session. They've already generated their share locally using their
    app; this endpoint receives the share blob and creates the
    fhe_joint_keys + fhe_keysetup_sessions documents.
  - Notifies counterparty: "keysetup_share_needed".
  - Returns: jointKeyId, status: "pending-setup".

POST /api/joint-keys/:id/contribute
  body: { shareFile }
  - Counterparty contributes their share. Platform combines and produces
    the joint public key + eval keys. status -> "active".
  - For multi-round protocols, this endpoint may be called multiple
    times; each call advances the round. Platform handles round
    bookkeeping internally and only signals "active" once the joint
    key is fully built.
  - Returns: status, current round if multi-round.

GET /api/joint-keys/:id
  - Returns metadata + signed URL to download the joint public key blob.
  - Both parties can read; outsiders cannot.

POST /api/joint-keys/:id/rotate
  - Triggers a fresh keysetup. Old key marked "rotated". New keysetup
    session starts.
  - Either party can initiate.

POST /api/joint-keys/:id/revoke
  - Marks key revoked. Any active permissions using it should be
    flagged or auto-suspended.
```

### 2b. Permissions (existing endpoints, possibly extended)

Existing endpoints likely cover create/accept/list/cancel. One change:

```
POST /api/permissions
  - Validates that an active jointKey exists between the two
    companies. If not, returns 412 Precondition Failed with a hint:
    "establish a joint key first".
```

Alternatively, creating a permission could *trigger* keysetup if one
doesn't exist. Either pattern works.

**Question for VS Code**: rename `/api/access-requests` to
`/api/permissions` to match data-owner-initiates semantics, or keep
the existing name? Toolkit CLI command rename would follow whichever
the platform decides.

### 2c. Datasets

Existing endpoints likely cover upload/list. Additions:

```
POST /api/datasets
  body: { permissionId, fileName, ciphertextFile }
  - Requires permissionId so the platform records which joint key the
    ciphertext is encrypted under.
  - Uploads to GCP storage (per existing storagePath pattern).
  - Returns datasetId.
```

### 2d. Execute

Existing endpoint should work; one change:

```
POST /api/permissions/:id/execute
  - Resolves: permission -> jointKeyId, allowedDatasetIds.
  - Wrapper is called with the encrypted datasets and the joint key.
  - Wrapper returns encrypted result.
  - Creates fhe_results document, status: "pending-data-owner-approval".
  - Notifies data owner: "result_awaiting_approval".
  - Returns: resultId, status.
```

### 2e. Results - gated access

```
GET /api/results/:id
  - Returns result document metadata + signed URL to download
    resultStoragePath ONLY IF:
    - Caller is data owner AND status is "pending-data-owner-approval"
    - Caller is consumer AND status is "decryption-ready" or later
  - 403 otherwise.

POST /api/results/:id/partial-decrypt
  body: { partialFile }
  - Only the data owner can call.
  - Only valid when status is "pending-data-owner-approval".
  - Stores partial, transitions status to "decryption-ready".
  - Notifies consumer: "result_ready".

GET /api/results/:id/partials
  - Returns signed URLs for the data owner's partial.
  - Only the consumer can call (data owner already has their own
    partial since they produced it).
  - Only valid when status is "decryption-ready" or later.

POST /api/results/:id/acknowledge-decryption
  body: { plaintextSize: int, decryptedAt: string }
  - Consumer signals they completed the local combine and got
    plaintext. Status -> "decrypted". Optional but useful for audit.
```

### 2f. Function catalog (already added, per VS Code's earlier message)

```
GET /api/functions
  - Public read; returns available functions with slug, name, scheme,
    inputs, output, cryptoContextSpec. Already live per earlier note.
```

## 3. Web UI flows

We don't know the current state of the web UI's permissions area in
detail. The Cowork session believes (from prior conversations) that the
permissions UI exists with some adjustments needed. Below is the target
state; VS Code please indicate what's already in place vs needed.

### 3a. Joint key setup flow (likely new)

New "Joint Key" page or section. Customer scenarios:

- "No joint key yet with BetaCorp" -> initiator flow:
  - Form: counterparty (search/pick company), crypto context spec
    (dropdown, default bfv-default-v1)
  - "Generate your share" step: instructions to download a state file
    (zero bytes - just a setup-state-init marker), drop it into the
    JuLenny app, app produces share file, upload it back.
  - On submit, creates fhe_joint_keys + sends notification to
    counterparty. UI shows "waiting for counterparty".
- "BetaCorp has started a keysetup with you" -> responder flow:
  - Notification surface in inbox.
  - Click into it: shows what BetaCorp proposed.
  - Same "produce your share via the app, upload it" step.
  - On submit, platform combines, status -> active.

### 3b. Permission creation flow (likely exists with adjustments)

The existing permissions page. Changes:

- Require an active jointKey before allowing permission creation. If
  none exists, link to "Joint Key" page.
- On submit, just creates permission referencing existing jointKeyId.
  No keysetup happens here.

### 3c. Permission detail page

For an active permission, show:

- Metadata (function, parties, datasets allowed, executions remaining)
- Datasets section: list of datasets uploaded under this permission
  (with file picker / upload button for adding new ones)
- Execute button: triggers the function
- Results section: list of results, each linkable to its result page

### 3d. Result page (likely new with status gating)

For a given result, render based on user's role and status:

- If status = `pending-data-owner-approval` AND user is data owner:
  - "BetaCorp ran a computation on your data. Approve decryption to
    release the result."
  - Download button for the result ciphertext (data owner only).
  - "After approving, upload your unlock share here" - file picker for
    the partial-decrypt blob.
- If status = `pending-data-owner-approval` AND user is consumer:
  - "Computation completed. Waiting for Acme's approval to release the
    result."
  - No download button.
- If status = `decryption-ready` AND user is consumer:
  - "Acme has approved the decryption. Download the result and Acme's
    unlock share to view the answer."
  - Two download buttons.
- If status = `decryption-ready` AND user is data owner:
  - "Decryption ready. BetaCorp will see the result now."
  - Audit log of when consumer downloaded etc.
- If status = `decrypted`:
  - Terminal state. Audit details only.

### 3e. Dataset upload (likely exists)

Form: pick permission, pick ciphertext file (binary upload), submit.
Backend records permissionId.

### 3f. Notifications inbox

If exists, add the new event types. If not, the result page and the
joint-key page can poll/refresh and surface their states directly.

## 4. Toolkit (apps + CLI)

### 4a. Windows app (Cowork to build)

HTTP wiring has been stripped (v0.4.0): no PlatformClient, no httplib,
no Config struct. The app is pure offline.

Build five action screens:

- Generate FHE keypair (one-time per company)
- Generate keysetup share (input: state file from platform; output:
  contribution file)
- Encrypt dataset (input: plaintext + joint pubkey; output: ciphertext)
- Produce partial decryption (input: result ciphertext; output: partial)
- Combine partials (input: result ciphertext + all partials; output:
  plaintext displayed)

Plus Settings (config, key fingerprints, version).

NavigationView at top with these as menu items. No dashboard, no
notifications, no platform URL.

Phasing (estimate 2-3 weeks):

- Phase A (3-4 days): scaffold the NavigationView, Settings, Generate
  keypair screen. Test against the existing core lib's keygen
  primitives.
- Phase B (4-5 days): Encrypt + Partial decrypt screens. These are
  straightforward file picker -> core call -> file output.
- Phase C (4-5 days): Generate keysetup share screen + Combine partials
  screen. Slightly more complex because keysetup may involve multi-round
  protocol orchestration locally; combine needs to validate inputs.
- Phase D (2-3 days): polish, error states, branding.

### 4b. Linux CLI (Cowork or VS Code to extend)

Currently has: init, health, keys, crypto, poll, functions,
access-requests, grants. Need to add the crypto-only command group
mirroring the Windows app's actions:

```
julenny-fhe crypto keysetup-share \
  --input <state-file> --output <share-file>

julenny-fhe crypto encrypt \
  --input <plaintext-file> --key <joint-pubkey-file> --output <ciphertext-file>

julenny-fhe crypto partial-decrypt \
  --input <result-ciphertext-file> --output <partial-file>

julenny-fhe crypto combine \
  --result <result-ciphertext-file> --partials <p1>,<p2>,... \
  [--output <plaintext-file>]
```

v0.4.0 removed all platform-touching CLI subcommands (init, health,
poll, functions, access-requests, grants) along with the HTTP client
in the core library. The CLI is now strictly offline: only `keys` and
`crypto` subcommands remain. Anything that needs to talk to the
platform lives in the web UI or in a customer-written script using the
platform's REST API directly.

Phasing (~1 week):

- Day 1-2: keysetup-share, encrypt, partial-decrypt commands
- Day 3: combine command
- Day 4: CLI rename + cleanup
- Day 5: integration testing against the platform endpoints

**Open question**: who owns this work? It's toolkit territory (where
Cowork already operates) but VS Code might find it faster since they
know what platform endpoints the CLI consumes. Either way works; just
flag who's doing it so we don't duplicate.

## 5. Cross-cutting

### 5a. Audit trail

Each step (permission created, accepted, dataset uploaded, execute
triggered, partial submitted, consumer downloaded result) should be
auditable. If the platform already does this generally, good. If not,
worth adding for the regulated-industries pitch.

### 5b. Error states

What happens when:

- Acme refuses to approve decryption (never uploads partial). Result
  expires. `allowedExecutions` count should NOT decrement? Or it
  should, since compute was used? Policy question.
- Joint keysetup fails midway (one party never contributes their
  share). Joint key sits in pending forever. Should expire after some
  time?
- Wrapper errors during execute. fhe_results.status = "errored",
  notification to consumer, no change to permission's execution count?
- Beta uploads a "partial" that's malformed. Validation needed on the
  partial-decrypt endpoint.

Worth a short pass to enumerate these and decide policies before the
demo can be considered production-ready. Pre-demo: pre-stage past
failure modes.

### 5c. Demo function

`add-two-numbers` is the existing smoke-test function. For the investor
demo, seed Firestore with one of:

- `joint-record-overlap`: count of common customer IDs between two
  retailers' lists
- `joint-fraud-count`: similar for banks
- `joint-patient-cohort-count`: similar for healthcare

VS Code to seed in Firestore + ensure the wrapper knows how to execute.
Function should signature-verify (Ed25519 signed) so the demo can
include "the function definition itself is signed and verified by
both parties' clients before execution" as a security beat if useful.

### 5d. Branding / visual polish

Web UI: needs design pass at minimum for the new flows (joint key page,
result page with status gating). Lower priority than functional
correctness for the demo.

App: brand colors, typography. Currently scaffold only. Lower priority
than functional correctness for the demo.

## 6. Phase ordering / dependencies

Approximate parallel timeline:

| Week | Cowork (toolkit) | VS Code (platform) |
|------|------------------|--------------------|
| W1 | App Phase A (NavView, keygen) | Firestore schema additions (joint_keys, results, dataset fields) |
| W2 | App Phase B (encrypt, partial) | Web UI: joint key page, result page with status gating |
| W3 | App Phase C (keysetup, combine); CLI crypto cmds | API endpoints for joint key lifecycle + result state machine |
| W4 | App Phase D (polish); integration testing | Demo function seeded + wrapper updates; integration testing |
| W5 | Bug fixes, demo rehearsal | Bug fixes, demo rehearsal |

Critical-path dependencies:

- App keygen unblocks customer FHE keypair generation. Web UI for
  pubkey registration needs to be ready first.
- Joint key web UI + API need to be ready before app keysetup-share
  screen can be end-to-end tested.
- Result state machine + APIs need to be ready before app
  partial-decrypt screen can be end-to-end tested.
- Wrapper's support for the demo function (not just add-two-numbers)
  unblocks an interesting investor demo.

## 7. Open questions / requests for VS Code

Consolidating what we'd like to confirm or learn:

1. **What's the current state of joint keysetup on the platform?** Any
   schema, API, or UI in place yet?
2. **`fhe_permissions` already has the right fields?** We see
   `dataOwnerCompanyId`, `dataConsumerCompanyId`, `fheFunction`,
   `allowedDatasetIds`, `allowedExecutions`. Anything else
   relevant for the multi-party flow?
3. **Notifications system shape today?** What collection, what event
   schema?
4. **`fhe_datasets` encryption metadata - already covered somehow?**
   E.g., is the encryption-context info embedded in the cereal-
   serialized binary, making the `permissionId` association optional?
5. **CLI ownership for new crypto commands**: VS Code or Cowork? Either
   works; we just need to assign.
6. **Demo function seed**: agreement on which (joint-fraud-count,
   joint-record-overlap, joint-patient-cohort-count, or another)?
   Whichever has the easiest wrapper implementation given OpenFHE's
   current capabilities.
7. **Permission semantics rename**: align platform UI / API / CLI on
   one term (probably `permissions` since that's what Firestore uses).
8. **Failure-mode policies**: what happens when Acme never approves a
   decryption? When keysetup is abandoned? When wrapper errors? Worth
   a quick policy doc.

## 8. Doc history

- 2026-05-14 v0.1: initial draft. Reflects the architecture decisions
  agreed today: 4-service deployment, app crypto-only and offline,
  joint keys shared across permissions per company-pair, gated result
  visibility (data owner approves, consumer sees the result only
  after).
