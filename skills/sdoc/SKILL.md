---
name: sdoc
description: Encrypt, decrypt, and inspect `.sdoc` post-quantum encrypted files with the `sdoc` CLI. Use when the user wants to protect a file with post-quantum encryption, read/open a `.sdoc` file, generate an ML-KEM key pair, or inspect a `.sdoc` header. No account or network required.
---

# sdoc — post-quantum file encryption

`.sdoc` is an open, post-quantum encrypted file format (ML-KEM-768 + AES-256-GCM).
A `.sdoc` file can only be read by the holder of the matching secret key — safe
even against future quantum computers. The `sdoc` CLI is self-contained: no
account, no server, no network.

## Setup

Check availability, install if missing:

```bash
sdoc --version || npm install -g sdoc-pqc
```

Requires Node.js 20+.

## Core model

- A **key pair**: `<name>.pub` (public, shareable) and `<name>.key` (secret, keep
  private). Anyone with the `.pub` can encrypt *to* the owner; only the `.key`
  holder can decrypt.
- Encrypting produces a `.sdoc` file. Decrypting recovers the original bytes.

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
```

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

**Open a `.sdoc` you received:** get `sdoc decrypt <file.sdoc> -k <your.key>`.

## Safety rules for the agent

- **Never** print, copy, transmit, or commit a `.key` file — it is the secret key.
- Only share `.pub` files.
- A failed `decrypt` (wrong key or tampered file) exits non-zero with
  `Échec du déchiffrement` — treat as "cannot open", do not retry with other keys
  blindly.
- Do not invent recipient public keys; obtain the real `.pub` from the recipient.

## Reference

Format spec and source: https://github.com/spartadoc-sdoc/sdoc
