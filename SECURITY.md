# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Report privately via **GitHub Security Advisories**
([Report a vulnerability](https://github.com/spartadoc-sdoc/sdoc/security/advisories/new))
or through [sdoc.ca](https://sdoc.ca).

We aim to acknowledge reports within 72 hours.

## Scope

- The `.sdoc` codec (`src/`) and CLI, as specified in [`spec/sdoc-format.md`](./spec/sdoc-format.md).
- Cryptographic primitives themselves (ML-KEM-768, AES-256-GCM) are provided by
  [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) and
  the platform's Web Crypto implementation; issues in those belong upstream.

## Supported versions

| Version | Supported |
|---|---|
| 0.x (latest `main`) | ✅ |

The v1.x wire format is frozen; cryptographic hardening lands in v2.0 (see spec §4).
