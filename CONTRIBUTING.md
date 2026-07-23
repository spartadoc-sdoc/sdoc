# Contributing to sdoc

Thank you for your interest in the open `.sdoc` format.

## Local development

```bash
git clone https://github.com/spartadoc-sdoc/sdoc.git
cd sdoc
npm install
npm run build      # compile src/ → dist/
npm test           # codec + CLI (round-trip) tests
npm run typecheck  # type check without emitting
```

## Scope

This repository is the **reference implementation of a standard**. Priorities:

1. **Interoperability**: any change to the binary format must be reflected in
   `spec/sdoc-format.md` and remain backward-compatible on read.
2. **No product coupling**: the codec and CLI depend on no service. No
   authentication, no network calls.
3. **Minimal dependencies**: the codec depends only on `@noble/post-quantum`.

## Format compatibility

The v1.x format is **frozen** (including key derivation, see spec §4). Crypto
evolutions (e.g. strict RFC 5869 HKDF) will go through a **v2.0** with a new
`version` byte, while keeping read support for earlier versions.

## Security

Please do **not** open a public issue for a vulnerability. Contact the team
privately (see https://sdoc.ca).

## License of contributions

By contributing, you agree that your contribution is distributed under Apache-2.0
(see LICENSE §5).
