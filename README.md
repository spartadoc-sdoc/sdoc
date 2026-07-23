# sdoc

**English** · [Français](./README.fr.md)

[![CI](https://github.com/spartadoc-sdoc/sdoc/actions/workflows/ci.yml/badge.svg)](https://github.com/spartadoc-sdoc/sdoc/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**The open post-quantum encrypted document / e-mail format.**

`.sdoc` is a container for encrypted data that stays secure even against a future
quantum computer: hybrid **ML-KEM-768** (FIPS 203) + **AES-256-GCM**. Only the
holder of the secret key can read a `.sdoc` — nobody else, ever.

This repository is the **reference implementation**: a portable codec and a CLI
with no service dependency. The [format specification](./spec/sdoc-format.md) is
public so that third parties can build interoperable implementations.

> Cryptographic sovereignty: keys stay with their owner. Open format, hosted in
> Canada — [sdoc.ca](https://sdoc.ca).

## Install

```bash
npm install -g sdoc      # global CLI
# or, as a library:
npm install sdoc
```

Requires Node.js 20+.

## CLI — quick start

```bash
# 1. Generate a key pair (bob.pub is shareable, bob.key stays private)
sdoc keygen -o bob

# 2. Alice encrypts a file for Bob using Bob's public key
sdoc encrypt letter.pdf -p bob.pub -o letter.pdf.sdoc

# 3. Bob decrypts with his secret key
sdoc decrypt letter.pdf.sdoc -k bob.key -o letter.pdf

# Inspect the header without decrypting
sdoc inspect letter.pdf.sdoc
```

## Library

```ts
import { encode, decode, generateKemKeyPair, MODE_SPARTADOC } from 'sdoc';

const { publicKey, secretKey } = await generateKemKeyPair();

const blob = await encode(new TextEncoder().encode('Hello'), publicKey, MODE_SPARTADOC);
const { plaintext } = await decode(blob, secretKey);

console.log(new TextDecoder().decode(plaintext)); // "Hello"
```

Exported API: `encode`, `decode`, `generateKemKeyPair`, `parseHeader`,
`writeBlob`, the constants `MODE_SPARTADOC` / `MODE_P2P`, and typed errors
(`SdocError`, `DecryptionError`, …).

## Format

See [`spec/sdoc-format.md`](./spec/sdoc-format.md) for the full binary format
(v1 legacy read, v1.2 read/write), key derivation, and security considerations.

## Agent skill

Driving `sdoc` from an AI agent? See [`skills/sdoc`](./skills/sdoc/SKILL.md) — a
ready-made skill teaching an agent to encrypt/decrypt/inspect `.sdoc` files.

## Security

- **Post-quantum**: confidentiality via ML-KEM-768 (covers "harvest now, decrypt
  later"), integrity via AES-256-GCM.
- The v1.x key derivation is frozen for interoperability; v2.0 will adopt RFC 5869
  HKDF-SHA256 for standards conformance. See spec §4.
- The v1.x format carries **no sender signature** (authenticity is a separate
  layer). Do not use it alone as proof of origin.

Found a vulnerability? Contact us privately via [sdoc.ca](https://sdoc.ca), not a
public issue.

## License

[Apache-2.0](./LICENSE) — © 2026 Spartadoc Inc.
