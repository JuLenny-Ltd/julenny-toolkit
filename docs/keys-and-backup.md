# Your keys: where they live and how to protect them

When you run a JuLenny collaboration, the toolkit creates a local working folder
that holds your cryptographic material. Some of it is **irreplaceable**. Read
this once before you run anything important.

## Where the toolkit keeps things

Each collaboration gets its own folder under your home directory:

```
~/.julenny-collab/
  signing/
    signing_secret_key.bin      # your company signing identity (per company)
    signing_public_key.bin
  collabs/
    <collaboration-id>/
      config.env                # which permission/function this folder targets
      function-def.json         # the signed function definition (re-fetchable)
      keys/
        fhe_secret_key.bin      # YOUR secret share  (data-owner side)
        my_share_secret.bin     # YOUR secret share  (data-consumer side)
        joint_public_key.bin    # the joint public key (re-fetchable from the platform)
        ...                     # round artifacts, partials, results (regenerable)
```

The file name of your secret share depends on which side you ran:
the data **owner** side stores it as `fhe_secret_key.bin`, the data
**consumer** side as `my_share_secret.bin`. Either way it is **your half of the
joint key**, and it never leaves your machine.

## What is irreplaceable, and what is not

- **Irreplaceable: your secret share** (`fhe_secret_key.bin` or
  `my_share_secret.bin`) and your **signing secret** (`signing_secret_key.bin`).
  These are generated locally during keysetup and are **never uploaded to the
  platform** - by design, so the platform can never decrypt your data by itself.
  If you lose them, there is no way to recover them: you cannot decrypt results
  for that collaboration, and you would have to create a new collaboration and
  run a fresh keysetup.
- **Re-fetchable / regenerable:** the joint public key (the platform stores it),
  the function definition, and any round artifacts, partial decryptions, or
  downloaded results. Losing these is not a problem - the toolkit re-downloads or
  re-derives them.

## Back up the irreplaceable parts

Back up the whole `~/.julenny-collab/` directory (or at minimum the `signing/`
folder and every `keys/` folder's secret share) somewhere safe and private:

```bash
tar czf julenny-collab-backup-$(date +%Y%m%d).tgz -C "$HOME" .julenny-collab
# store the .tgz on encrypted, access-controlled storage
```

Restore by extracting it back into your home directory before running the
scripts again on a new or rebuilt machine.

## "Joint key is complete but this machine is missing its share"

If a run stops with a message like *"Joint key is complete on the platform, but
this machine is missing <path>/<secret share>"*, it means keysetup for that
collaboration was completed on a **different machine** (or a machine that was
since wiped) and this one does not have your secret share. The share cannot be
downloaded - it only ever existed on the machine that ran keysetup. Recover by:

1. **Restore** `~/.julenny-collab/` from your backup (or copy the secret share
   from the machine that participated in the keysetup), or
2. **Create a new collaboration** so a fresh keysetup generates a new secret
   share on this machine.

## One tool, one machine, per party

In normal use, each party drives its side from a single tool on a single machine,
so the secret share is created there and never needs to move. Moving a secret
share between machines is only necessary in unusual setups (for example, doing
keysetup with one tool and later running on a different machine). When you must
move it, copy it - never expose it - and treat it like any other secret.
