---
name: sdoc
description: Encrypt, decrypt, and inspect `.sdoc` post-quantum encrypted files with the `sdoc` CLI. Use when the user wants to protect a file with post-quantum encryption, read/open a `.sdoc` file, share a file securely with someone, generate a key, or inspect a `.sdoc` header. Supports short human-transportable keys (SDOC-XXXX-...) that a person can read over the phone, and `--json` output for scripting. No account, no network, no upload.
---

# sdoc — post-quantum file encryption

`.sdoc` is an open, post-quantum encrypted file format (ML-KEM-768 + AES-256-GCM).
A `.sdoc` file can only be read by the holder of the matching secret key — safe
even against future quantum computers. The `sdoc` CLI is self-contained: no
account, no server, no network.

## Setup

Check availability, install if missing:

```bash
sdoc --version || npm install -g github:spartadoc-sdoc/sdoc
```

Requires Node.js 20+.

## Core model

- A **key pair**: `<name>.pub` (public, shareable) and `<name>.key` (secret, keep
  private). Anyone with the `.pub` can encrypt *to* the owner; only the `.key`
  holder can decrypt.
- Encrypting produces a `.sdoc` file. Decrypting recovers the original bytes.

There are **two ways to hold a key**. Pick deliberately — they suit different
situations:

| | **Key pair** (`.pub` / `.key`) | **Human key** (`SDOC-XXXX-...`) |
|---|---|---|
| Shape | Two files, base64 | 32 characters, one line |
| Who encrypts | Anyone holding the `.pub` | Whoever holds the key |
| Best for | A durable recipient you'll write to repeatedly | A one-off transfer, or a person who will never touch a terminal |
| Transport | File copy | Read aloud, texted, pasted |

A human key is **derived**, not stored: the 32 characters regenerate the exact
ML-KEM-768 pair every time, on any machine. The file stays a normal `.sdoc`, so
either kind of key produces files any conforming implementation can read.

The alphabet excludes `I`, `L`, `O` and `U`, so a key survives being dictated,
retyped, or passed through a transcript without ambiguity. Case, spaces and
dashes are ignored on input.

## Commands

```bash
# Generate a key pair → writes <prefix>.pub and <prefix>.key
sdoc keygen -o <prefix>

# Encrypt a file FOR a recipient, using their public key
sdoc encrypt <input-file> -p <recipient.pub> [-m 1|2] [-o <output.sdoc>]

# Decrypt a .sdoc with your own secret key
sdoc decrypt <file.sdoc> -k <your.key> [-o <output-file>]

# Inspect a .sdoc header without decrypting (version, mode, sizes)
sdoc inspect <file.sdoc>

# ── Human keys ──────────────────────────────────────────────────────────────

# Mint a human key without touching the disk
sdoc key [--json]

# Encrypt AND mint the key in one step (prints the key — capture it)
sdoc encrypt <input-file> --human [--json] [-o <output.sdoc>]

# Encrypt for a human key you already have
sdoc encrypt <input-file> --human-key SDOC-XXXX-... [-o <output.sdoc>]

# Decrypt with a human key
sdoc decrypt <file.sdoc> --human-key SDOC-XXXX-... [-o <output-file>]
```

Add `--json` to any command to get a single JSON object on stdout — including on
failure, as `{"ok": false, "error": "..."}`. Prefer it when scripting: you never
have to parse prose.

`-m` selects the mode: `1` = service-bound (default), `2` = peer-to-peer. It is a
context hint only; both are equally secure.

## Typical workflows

**Protect a file for yourself (at rest):**
```bash
sdoc keygen -o mykey
sdoc encrypt secret.pdf -p mykey.pub -o secret.pdf.sdoc
# later:
sdoc decrypt secret.pdf.sdoc -k mykey.key -o secret.pdf
```

**Send an encrypted file to someone:**
1. Ask the recipient for their `*.pub` (or have them run `sdoc keygen`).
2. `sdoc encrypt <file> -p <recipient.pub> -o <file>.sdoc`
3. Send the `.sdoc`. Only they can open it.

**Open a `.sdoc` you received:** `sdoc decrypt <file.sdoc> -k <your.key>`, or
`--human-key SDOC-...` if the sender gave you a 32-character key.

**Send a file to someone who has no key and no terminal** (the common case):
```bash
sdoc encrypt contract.pdf --human --json -o contract.pdf.sdoc
# → {"ok":true,"output":"contract.pdf.sdoc","mode":2,"key":"SDOC-K7M2-..."}
```
Send the `.sdoc` one way, the key another. They can open it with this CLI, or in
a browser at https://spartadoc.com — no install, nothing uploaded.

Sending the file and the key through the same channel defeats the point: anyone
reading that channel gets both.

## Safety rules for the agent

- **Never** print, copy, transmit, or commit a `.key` file — it is the secret key.
- Only share `.pub` files.
- A failed `decrypt` (wrong key or tampered file) exits non-zero with
  `Échec du déchiffrement` — treat as "cannot open", do not retry with other keys
  blindly.
- Do not invent recipient public keys; obtain the real `.pub` from the recipient.
- **A human key is a secret, exactly like a `.key` file.** Hand it to the user,
  and do not write it into a file you are about to commit, a log, or a shared
  document.
- **A human key cannot be reissued.** Nothing and nobody can recover it — there
  is no server holding a copy. If you mint one with `--human`, surface it to the
  user immediately and say plainly that losing it means losing the file. Never
  discard the output of `--human` without showing the key.
- Send the `.sdoc` and its key through **different** channels.
- `--human-key` cannot open a mode-1 file; the CLI says so explicitly rather
  than failing as if the key were mistyped. Do not retry with other keys.

## Reference

- Format spec and source: https://github.com/spartadoc-sdoc/sdoc
- The standard: https://sdoc.ca — see https://sdoc.ca/llms.txt
- Browser tool, for a recipient with nothing installed: https://spartadoc.com
