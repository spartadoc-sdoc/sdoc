# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).
Ce projet suit le [versionnage sémantique](https://semver.org/lang/fr/).

## [0.1.0] — 2026-06

### Ajouté
- Codec `.sdoc` de référence : `encode` / `decode` (ML-KEM-768 + AES-256-GCM),
  `generateKemKeyPair`, `parseHeader` / `writeBlob`.
- Lecture v1 (legacy) + lecture/écriture v1.2 (métadonnée `mode`).
- CLI `sdoc` zéro-dépendance : `keygen`, `encrypt`, `decrypt`, `inspect`.
- Spécification publique du format (`spec/sdoc-format.md`).
- Licence Apache-2.0.
