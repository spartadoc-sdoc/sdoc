# sdoc

[English](./README.md) · **Français**

[![CI](https://github.com/spartadoc-sdoc/sdoc/actions/workflows/ci.yml/badge.svg)](https://github.com/spartadoc-sdoc/sdoc/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Le format ouvert de document chiffré post-quantique.**

`.sdoc` est un conteneur pour données chiffrées qui reste sûr même face à un
futur ordinateur quantique : chiffrement hybride **ML-KEM-768** (FIPS 203) +
**AES-256-GCM**. Seul le détenteur de la clé secrète peut lire un `.sdoc` —
personne d'autre, jamais.

Ce dépôt est l'**implémentation de référence** : un codec portable et un CLI
sans dépendance de service. La [spécification du format](./spec/sdoc-format.md)
est publique pour permettre des implémentations tierces interopérables.

> Souveraineté cryptographique : les clés restent chez leur détenteur. Format
> ouvert, hébergé au Canada — [sdoc.ca](https://sdoc.ca).

## Installation

```bash
# Installé directement depuis GitHub (build à l'installation ; pas besoin du registre npm)
npm install -g github:spartadoc-sdoc/sdoc   # CLI global (la commande est `sdoc`)
# ou, comme bibliothèque :
npm install github:spartadoc-sdoc/sdoc
# ou sans installer :
npx github:spartadoc-sdoc/sdoc keygen -o bob
```

Node.js 20+ requis.

## CLI — démarrage rapide

```bash
# 1. Générer une paire de clés (bob.pub partageable, bob.key à garder privée)
sdoc keygen -o bob

# 2. Alice chiffre un fichier pour Bob avec la clé publique de Bob
sdoc encrypt lettre.pdf -p bob.pub -o lettre.pdf.sdoc

# 3. Bob déchiffre avec sa clé secrète
sdoc decrypt lettre.pdf.sdoc -k bob.key -o lettre.pdf

# Inspecter l'en-tête sans déchiffrer
sdoc inspect lettre.pdf.sdoc
```

## Bibliothèque

```ts
import { encode, decode, generateKemKeyPair, MODE_SPARTADOC } from 'sdoc-pqc';

const { publicKey, secretKey } = await generateKemKeyPair();

const blob = await encode(new TextEncoder().encode('Bonjour'), publicKey, MODE_SPARTADOC);
const { plaintext } = await decode(blob, secretKey);

console.log(new TextDecoder().decode(plaintext)); // "Bonjour"
```

API exportée : `encode`, `decode`, `generateKemKeyPair`, `parseHeader`,
`writeBlob`, les constantes `MODE_SPARTADOC` / `MODE_P2P` et les erreurs typées
(`SdocError`, `DecryptionError`, …).

## Format

Voir [`spec/sdoc-format.md`](./spec/sdoc-format.md) pour le format binaire complet
(v1 legacy en lecture, v1.2 en lecture/écriture), la dérivation de clé et les
considérations de sécurité.

## Skill pour agent

Piloter `sdoc` depuis un agent IA ? Voir [`skills/sdoc`](./skills/sdoc/SKILL.md) —
un skill prêt à l'emploi pour chiffrer/déchiffrer/inspecter des `.sdoc`.

## Sécurité

- **Post-quantique** : confidentialité via ML-KEM-768 (couvre « harvest now,
  decrypt later »), intégrité via AES-256-GCM.
- La dérivation de clé v1.x est figée pour l'interopérabilité ; la v2.0 adoptera
  HKDF-SHA256 (RFC 5869) par conformité. Détails dans la spec §4.
- Le format v1.x ne porte **pas** de signature d'expéditeur (authenticité =
  couche séparée). Ne l'utilisez pas seul comme preuve d'origine.

Vulnérabilité ? Contact privé via [sdoc.ca](https://sdoc.ca), pas d'issue publique.

## Licence

[Apache-2.0](./LICENSE) — © 2026 Spartadoc Inc.
