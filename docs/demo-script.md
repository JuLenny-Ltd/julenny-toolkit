# JuLenny FHE Platform - Investor Demo Script (Internal)

**Internal document, not for public release.** Plain-English narration
of the two-party joint compute demo. Read the "Open questions" section
first if you haven't reviewed this since 2026-05-14, several details
still depend on platform-side decisions.

## Audience and goals

- **Audience**: investors, prospects, non-technical reviewers (financial
  services, healthcare, insurance buyers).
- **Goal**: show a real two-company privacy-preserving collaboration end
  to end, in plain language, in 5-8 minutes. The cryptography is behind
  the scenes; the story is the business outcome.
- **One-line product pitch**: *Two companies want to combine data to
  answer a question. Neither side ever sees the other's raw data. Not
  even our platform sees it. Today we do it with cryptography in a way
  that's mathematically guaranteed, not policy-promised.*

## Cast

- **Acme Bank** (the data owner in the demo). Driven by a web browser.
  Has sensitive customer data. Wants to let BetaCorp run an analysis on
  it without exposing the raw data.
- **BetaCorp** (the data consumer in the demo). Driven by a Linux
  terminal, simulating an enterprise integration / automation. Will run
  the analysis. Also contributes its own data to the joint compute.
- **JuLenny platform** (julenny.net web UI and behind-the-scenes services).
- **The JuLenny app** (Windows GUI on Acme's side; CLI on BetaCorp's
  side). Lives on the user's machine, never talks to the internet, only
  reads and writes files.

## The function

The two companies want to run **`joint-fraud-count`** (or whichever
function we seed in Firestore for the demo). Reads two datasets of
flagged customer IDs, computes how many customers are in both lists.

Plain English narrative: *"Both banks have lists of customers flagged
for fraud. Sharing those lists is illegal under GDPR. They want to
know: how many fraud cases do we have in common, without anyone
revealing who their flagged customers are. Our platform answers that
question."*

Alternative demo functions worth seeding instead:

- `joint-record-overlap` (retailers): unique customers two retailers
  share.
- `joint-salary-average` (HR): average salary across two companies'
  payroll datasets, none of the individual salaries exposed.
- `joint-patient-cohort-count` (healthcare): patients meeting a clinical
  criterion across two hospital systems.

Pick the one whose use case lands hardest with whoever is in the room.

## Open questions blocking final demo polish

1. **Joint keysetup is not yet in the platform's web UI.** Needs to be
   built and folded into the permission create / accept flow. The
   keysetup share generation happens in the customer's app; the
   platform's job is to (a) ask for each party's share as part of the
   permission lifecycle, (b) combine the shares into the joint public
   key, (c) make the joint public key available for download. Spec
   informally laid out in step 2 below. **Owner: VS Code session.**
2. **`fhe_datasets` schema doesn't currently record which permission
   the ciphertext is encrypted under.** Resolution: add a
   `permissionId` field to the `fhe_datasets` document. Since each
   permission references one `jointKeyId`, `permissionId` transitively
   identifies which key was used. Without this, the wrapper can't pick
   the right key to do math under. **Owner: VS Code session.**

   Also need a new collection: **`fhe_joint_keys`**, keyed on company
   pair, with lifecycle fields (createdAt, rotatedAt, revokedAt,
   status). Permissions reference `jointKeyId`. **Owner: VS Code.**

8. **Result-state machine and gated visibility.** The encrypted result
   ciphertext should NOT be downloadable by the consumer until the
   data owner has uploaded her partial decryption. States needed on
   the result document:
   - `pending-data-owner-approval`: result exists, visible to data
     owner only (so she can download it for her partial-decrypt step).
   - `decryption-ready`: data owner's partial uploaded; result and
     partial both downloadable by consumer.
   - `decrypted` (terminal) or `expired` (terminal).
   Plus notifications: `result_awaiting_approval` to the data owner,
   `result_ready` to the consumer. Same `permissionId`-based access
   control. **Owner: VS Code session.**
3. ~~Keysetup-per-permission vs shared-keys~~ **Resolved 2026-05-14:**
   joint key is **shared across permissions between the same company
   pair**, established once when the two companies first set up a
   collaboration, rotatable on demand. Each permission references its
   `jointKeyId`. Datasets are encrypted under that joint key. Reversing
   the earlier "fresh per permission" guidance because the UX cost of
   redoing keysetup on every permission outweighs the marginal
   security benefit (the private key share already lives on the
   customer's machine, so blast radius is set by machine-compromise
   risk regardless of per-permission freshness). Revocation = rotate
   the joint key when desired.
4. **CLI subcommands for the crypto-only flow don't exist yet.** Need
   keysetup-share generation, encrypt-file, partial-decrypt-file,
   combine-partials. Crypto primitives are in core; CLI commands need
   wiring. **Owner: VS Code session or Cowork - to be decided.**
5. **Demo function seeded in Firestore.** Currently we have
   `add-two-numbers`, which is a smoke test, not a story. Seed one of
   the alternatives above instead. **Owner: VS Code session.**
6. **The "joint-fraud-count" / equivalent function's wrapper
   implementation.** Function definition can be in Firestore but the
   wrapper has to know how to run it. **Owner: VS Code session.**
7. **Pre-stage vs live**: what parts to pre-stage (already done before
   the camera rolls) and what parts to run live. Suggestion below.

## The demo flow

### Pre-staged (already done before the demo starts)

- Both companies have accounts on julenny.net with API keys.
- Both have generated an FHE keypair using the JuLenny app. Each app
  holds the company's private key locally; each company has registered
  its public key with the platform.
- **The two companies have a shared joint key established** (one-time
  keysetup ritual, done when they first set up a collaboration
  relationship). Every permission between them reuses this shared key
  until it's rotated.
- The function `joint-fraud-count` is defined in the platform's function
  catalog, signed and verified.

### Live (this is what the audience watches)

The flow is presented from two screens side by side: Acme's browser
showing julenny.net on the left, BetaCorp's Linux terminal on the right.

**Step 1: Acme grants access.** [Acme's browser]

Acme logs into julenny.net, goes to Permissions, clicks "Grant access."

- Who can use my data: **BetaCorp**
- Which function they can run: **joint-fraud-count**
- Which of my datasets they can use: **Q4 fraud flags**
- How many times they can run it: **1**
- Expires after: **30 days**

Acme submits. One screen, one click. The shared key between Acme and
BetaCorp was already established; the new permission reuses it.

*[Narration: "Acme is not sending her data here, just permission to use
it. She and BetaCorp set up their secure cryptographic relationship
once, when they first decided to collaborate. From now on, every new
permission is just a click."]*

**Step 2: BetaCorp accepts.** [BetaCorp's terminal]

```
julenny-fhe permissions accept <permission-id>
```

One command.

**Step 3: Each side encrypts and uploads their data.** [Both, in parallel]

Acme uses the app: pick the CSV with the fraud flags, click "Encrypt."
Out pops `acme-flags.encrypted`. Acme uploads it through the web UI as
the dataset for this permission.

BetaCorp does the equivalent on the CLI:

```
julenny-fhe encrypt --input beta-flags.csv --out beta-flags.enc
julenny-fhe datasets upload beta-flags.enc --permission <id>
```

*[Narration: "Each company encrypts its own data locally, on its own
machine, then uploads only the encrypted version. No plaintext ever
touches our servers. The encryption key they're both using is the joint
key they established when they first agreed to collaborate."]*

**Step 4: Run the analysis.** [BetaCorp]

BetaCorp clicks Run on the permission's page (or POSTs to the API). The
platform's compute service runs `joint-fraud-count` on the two
encrypted datasets, producing an encrypted result.

*[Narration: "Behind the scenes, our compute service is running the
function directly on the encrypted data. It's solving the puzzle
without ever seeing the puzzle pieces. The technical name for this is
fully homomorphic encryption. The plain-English name is: we cannot see
your data even if we wanted to."]*

Takes a few seconds. The status flips to **"Awaiting data owner
approval."** BetaCorp can see that a result was produced, but the
result file itself is not yet downloadable by him. Acme is notified.

**Step 5: Acme blesses the decryption.** [Acme]

Acme's dashboard shows a new notification: "BetaCorp has run a
computation on your fraud-flags dataset and is awaiting your approval
to release the result." She clicks in, sees:

- Permission: the one she explicitly granted (review the function,
  consumer, dataset, expiration)
- Status: result awaiting her approval

Acme downloads the encrypted result file (only accessible to her at
this stage - BetaCorp cannot see it yet), drops it into the JuLenny
app, clicks "Approve decryption." The app produces a small unlock-share
file. Acme uploads it through the web UI.

*[Narration: "Acme is consenting to this specific decryption. The
unlock share she's producing is mathematically useless on its own.
Importantly: **Acme never sees what the answer is**. She gave
permission, contributed her cryptographic signature, but the result
itself is BetaCorp's to read. This is enforced by the math, not by
policy."]*

The platform's status now flips to **"Decryption ready."** Now -
and only now - BetaCorp can download.

**Step 6: BetaCorp sees the answer.** [BetaCorp]

BetaCorp downloads the encrypted result and Acme's unlock share, then
runs:

```
julenny-fhe results decrypt <result-id>
```

His app combines everything locally, plaintext appears in his terminal:

```
joint-fraud-count: 47
```

*[Narration: "BetaCorp now knows there are 47 customers in common on
their fraud lists. He doesn't know which 47. Acme doesn't know the
answer at all. We don't know either. The only thing that exists is the
number 47, on BetaCorp's machine."]*

## The takeaway slide

After the demo, advance to a slide that says:

- Acme uploaded data: **never seen in plaintext by anyone except Acme.**
- BetaCorp uploaded data: **never seen in plaintext by anyone except BetaCorp.**
- JuLenny saw: **encrypted blobs. No plaintext at any point.**
- BetaCorp ran computation: **on encrypted data. Result was encrypted.**
- Acme's role in the result: **gave per-execution consent, never saw the answer.**
- BetaCorp learned: **the answer to the joint question, and only the answer
  (no per-customer breakdown of Acme's data).**

*This is what "privacy by construction" means. It's not a policy
promise. It's a mathematical guarantee.*

## Behind the scenes (technical sidebar, for the inevitable CTO in the room)

- The cryptography is **threshold fully homomorphic encryption (TFHE-
  family)**, specifically BFV scheme via OpenFHE. Each party holds a
  share of a private key that was never assembled in one place. The
  shared public key is built by exchanging public protocol messages.
- The compute service uses **OpenFHE for CPU paths and FidesLib for GPU-
  accelerated paths**. Both libraries are linked into a single service
  (the "wrapper") for latency reasons. Process isolation provides
  defense-in-depth without the overhead of inter-service calls.
- The platform's services run on **Google Cloud Run** in the EU
  (europe-west4). GPU acceleration via NVIDIA L4 cards. EU data
  residency for the platform; customer plaintext never leaves the
  customer's machine, full stop.
- The client app is a **pure offline tool**: zero network calls, reads
  and writes local files only. Even capture of the customer's machine
  doesn't expose a live network credential. Customer data movement
  (uploads, downloads) is handled by the customer's choice of channel
  (web UI for humans, REST API for automation), separate from the
  cryptography.
- **No private key share ever leaves a customer's device.** Not to us,
  not to the other party, not to a hardware enclave, not to a network
  cache.
- We can show the source code (toolkit is open source) and walk through
  what each side computes and what crosses the wire.

## Length variants

- **5 minutes**: pre-stage through step 2. Live: 3-6. Spend most time on
  step 6 (the reveal) and the takeaway slide.
- **8-10 minutes**: pre-stage steps 1-2. Live: 3-6 with extra narration
  in step 4 (the FHE explanation moment).
- **15 minutes**: live from step 1. More time to show the permission
  creation, the file picker UX, the CLI commands scrolling. Risk of
  losing pace.
- **2 minutes (elevator)**: just the takeaway slide with verbal
  description, no live demo. Use if a meeting derails.

## What NOT to do during the demo

- Don't use the words "homomorphic", "threshold", "lattice", "BFV",
  "CKKS", "ciphertext", "polynomial" unless you're answering a direct
  technical question. Investors and buyers don't need them. They make
  the product sound complex and academic.
- Don't show error states or progress bars longer than 5 seconds. If
  something is going to take longer than that, pre-stage it.
- Don't apologize for pre-staging. Every demo pre-stages. Just say "in
  the real flow this part takes a few minutes; we've already done it so
  we can spend our time on the part that matters."
- Don't claim ownership of the cryptographic invention. We use audited,
  academic-grade cryptographic libraries (OpenFHE, FidesLib). Our
  contribution is the platform that makes them usable by non-experts.
- Don't compare to competitors by name during the demo. Save that for
  the Q&A. ("How is this different from Snowflake clean rooms?" gets a
  great answer in Q&A; nobody needs to hear it in your demo flow.)

## Comparable companies for the Q&A

The investor will ask "how is this different from X." Stock answers:

- **vs. AWS Clean Rooms / Snowflake Clean Rooms / LiveRamp / Habu**:
  those require trusting the operator. The operator sees the data
  inside their secure enclave. Insider threats, vendor compromise, and
  subpoenas all reach the plaintext. With JuLenny, we cannot see the
  data because the cryptography makes it impossible, not because policy
  says we won't.
- **vs. confidential computing (Intel SGX, AMD SEV, AWS Nitro)**: those
  rely on trusting the chip vendor. Past attacks (e.g., the SGX
  rollback attacks, AMD SEV-SNP issues) showed those trust assumptions
  are not absolute. We use cryptography that doesn't trust the
  hardware.
- **vs. Zama**: closest direct comp. Zama builds an FHE platform on
  similar foundations. Differentiation comes from go-to-market (we
  focus on enterprise data collaboration; they focus on the underlying
  FHE libraries / developer toolkit), customer onboarding (we have a
  full-stack solution including web UI; they emphasize developer
  primitives), and EU data residency.

## Document history

- 2026-05-14 v0.1: initial draft, post-architecture-confirmation
  conversation. Pending VS Code session's answers on the open questions
  above.
