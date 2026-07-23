# `.sdoc` format specification — v1.2

A container format for **post-quantum** encrypted data, designed for exchanging
documents and e-mails. Hybrid encryption: **ML-KEM-768** (FIPS 203) +
**AES-256-GCM** (FIPS 197 / SP 800-38D).

Status: v1.x stable (interoperability frozen). This document describes exactly
what the reference implementation (`sdoc`) produces and reads, so that third
parties can build byte-for-byte compatible implementations.

## 1. Overview

An `.sdoc` file contains a message encrypted for **one recipient**, identified by
their ML-KEM-768 public key. Nobody but the holder of the corresponding secret
key can decrypt it — including an adversary with a quantum computer.

Hybrid construction:

```
  ML-KEM-768.encapsulate(recipient_public_key)  →  (kemCiphertext, sharedSecret)
  aesKey = KDF(sharedSecret, salt)                        (see §4)
  ciphertext‖authTag = AES-256-GCM(aesKey, iv, plaintext, AAD)   (see §5)
```

## 2. Value types

- Multi-byte integers are **big-endian**.
- Fixed sizes: `salt` = 16 bytes, `iv` = 12 bytes, `authTag` = 16 bytes,
  AES key = 32 bytes.
- ML-KEM-768: public key 1184 B, secret key 2400 B, KEM ciphertext 1088 B,
  shared secret 32 B.

## 3. Wire format

### 3.1 v1.2 (read + write)

```
┌─────────┬──────┬────────┬───────────┬──────────┬──────┬──────────┬─────────┐
│ version │ mode │  salt  │ kemCtLen  │  kemCt   │  iv  │ authTag  │ payload │
│  0x02   │ 1 B  │  16 B  │  2 B BE   │  N B     │ 12 B │  16 B    │  rest   │
└─────────┴──────┴────────┴───────────┴──────────┴──────┴──────────┴─────────┘
```

- `version` = `0x02`
- `mode` = `0x01` (service-bound) or `0x02` (peer-to-peer). See §6.
- `kemCtLen` = length of `kemCt` in bytes (max 65535).
- `payload` = AES-GCM ciphertext **without** the tag (the tag is stored
  separately in `authTag`).

### 3.2 v1 (legacy — read only)

```
┌─────────┬────────┬───────────┬──────────┬──────┬──────────┬─────────┐
│ version │  salt  │ kemCtLen  │  kemCt   │  iv  │ authTag  │ payload │
│  0x01   │  16 B  │  2 B BE   │  N B     │ 12 B │  16 B    │  rest   │
└─────────┴────────┴───────────┴──────────┴──────┴──────────┴─────────┘
```

No `mode` byte (implicit mode = 1). Implementations **must** read v1 but **must
only produce v1.2**.

## 4. Key derivation (KDF)

The AES key is derived from the ML-KEM shared secret with SHA-256, using the
per-message `salt`:

```
PRK = SHA-256( sharedSecret ‖ salt )
OKM = SHA-256( PRK ‖ INFO ‖ 0x01 )
aesKey = OKM[0:32]
```

where `INFO = "spartadoc-q-v1"` (14 ASCII bytes — a fixed domain-separation
label, not a secret). The input keying material is a uniformly random 256-bit
ML-KEM shared secret, for which this construction is cryptographically sound.
The derivation is frozen for v1.x interoperability; v2.0 will adopt RFC 5869
HKDF-SHA256 for standards conformance.

## 5. Authenticated encryption (AEAD)

AES-256-GCM with a random 12-byte `iv` and **associated data (AAD)** binding the
header to the ciphertext (anti-downgrade):

```
  v1.2 : AAD = version(1) ‖ mode(1) ‖ salt(16) ‖ kemCtLen(2 BE) ‖ kemCt
  v1   : AAD = ∅ (empty)
```

Any change to `version`, `mode`, `salt`, or `kemCt` therefore invalidates GCM
verification on decrypt (prevents a v1.2→v1 or mode 2→1 downgrade).

WebCrypto/OpenSSL return `ciphertext‖authTag` concatenated; the format splits
them (`payload` excludes the tag, which goes in the `authTag` field).

## 6. Modes

| Mode | Byte | Meaning |
|---|---|---|
| 1 | `0x01` | Message destined for a service (recipient key managed service-side) |
| 2 | `0x02` | Peer-to-peer: the recipient holds their own secret key |

The mode does **not** change the cryptography — it is a key-management context
hint. A conformant reader accepts both.

## 7. Key generation

`generateKemKeyPair()` = `ML-KEM-768.keygen()` (system cryptographic randomness).
The public key is shareable; the secret key (2400 B) must be kept private.

## 8. Security considerations

- **Post-quantum**: confidentiality relies on ML-KEM-768 ("harvest now, decrypt
  later" covered). Integrity relies on AES-GCM (128-bit tag).
- **Implicit rejection**: ML-KEM does not necessarily fail at `decapsulate` with
  a wrong key (it returns a pseudo-random secret); the GCM tag is what rejects.
- **Nonce/key freshness**: `salt` and `iv` are drawn at random on each encryption
  → two blobs of the same plaintext differ.
- **No signature** in the v1.x container: sender authenticity is not provided by
  the format itself (separate layer: a signed key registry using SLH-DSA, out of
  scope for this spec).
- The v1.x KDF (§4) is cryptographically sound for its high-entropy KEM input;
  v2.0 will move to RFC 5869 HKDF-SHA256 for standards conformance.

## 9. File extension and MIME type

- File extension: `.sdoc`
- Proposed MIME type: `application/vnd.sdoc`
