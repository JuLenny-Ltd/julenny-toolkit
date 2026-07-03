# Rule-based cross-match demo

End-to-end shell walkthrough of a two-party JuLenny collaboration over the **rule-based-cross-match** function (CKKS). Two organizations - "Acme" (data owner) and "Beta" (data consumer) - each hold a private indicator over a shared name space; the platform counts how many entries from a rule list are matched on both sides, without revealing either side's data to the other.

## How this folder works

This is a **thin scenario folder**. It holds only this collaboration's data and a one-line-per-side launcher. All of the actual logic (keysetup, encrypt, rotation-key augmentation, execute, release, decrypt) lives in the shared driver at `examples/_core/`, which is fully function-def-driven and shared by every scenario. There is nothing function-specific in the scripts here.

```
examples/rule-based-cross-match/
├── README.md            (this file)
├── acme/                DATA OWNER side (keysetup lead)
│   ├── run.sh           thin bootstrap: sets side = data-owner, hands off to _core
│   └── data/            Acme's private input file(s)
└── beta/                DATA CONSUMER side (keysetup main)
    ├── run.sh           thin bootstrap: sets side = data-consumer, hands off to _core
    └── data/            Beta's input files (rule list + private indicator source)
```

Each `run.sh` exports `JULENNY_OUR_SIDE` and `JL_DATA_DIR=$HERE/data`, locates `_core` (either alongside the scenario on the demo hosts, or two levels up in the repo), and `exec`s `_core/run.sh`. The exact function and version are picked from the platform at `00-init` time, so the same folder works for any rule-based-cross-match version.

## Inputs

The inputs, their roles, and their encodings come from the function-def fetched at `00-init` (saved to the workdir as `function-def.json`); that file is the source of truth. In short:

- `rule_pairs` (queryAnalyst / Beta): a plaintext CSV of the rule list, uploaded raw.
- `left_indicator` (queryAnalyst / Beta): Beta's private membership, encrypted.
- `right_indicator` (dataOwner / Acme): Acme's private membership, encrypted.

The encrypted indicators use `indicator-binary` encoding: each name maps to a slot via an FNV-1a hash (`slot = fnv1a_64(name) % slotCount`), pinned identically on both sides, so no shared dictionary is exchanged. At Beta's encrypt step you are prompted once per queryAnalyst input to pick its file from `data/`; at Acme's encrypt step, once for the dataOwner input.

## Running it

Acme creates the collaboration (web UI or API) and Beta is added as the data consumer. Then, on each machine:

```bash
cd examples/rule-based-cross-match/acme   # (or beta)
./run.sh
```

`run.sh` inspects platform state and resumes whichever phase is not yet done - keysetup, encrypt, rotation-key augmentation, then execute (Beta) / release (Acme), then decrypt. Re-run it on each side as the other side progresses; it is safe to re-run.

Because rule-based-cross-match is CKKS, it can run on either compute engine. If the function is configured for both CPU and GPU and the platform exposes `supportedEngines` on the definition, Beta's trigger step offers an engine choice (`openfhe-cpu` / `fideslib-ckks-gpu`); otherwise it defaults to CPU.
