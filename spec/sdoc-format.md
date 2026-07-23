# Spécification du format `.sdoc` — v1.2

Format de conteneur pour données chiffrées **post-quantiques**, conçu pour
l'échange de documents et de courriels. Chiffrement hybride **ML-KEM-768**
(FIPS 203) + **AES-256-GCM** (FIPS 197 / SP 800-38D).

Statut : v1.x stable (interop figée). Ce document décrit exactement ce que
produit et lit l'implémentation de référence (`sdoc`), afin de permettre des
implémentations tierces bit-à-bit compatibles.

## 1. Vue d'ensemble

Un fichier `.sdoc` contient un message chiffré pour **un destinataire**, identifié
par sa clé publique ML-KEM-768. Personne d'autre que le détenteur de la clé
secrète correspondante ne peut le déchiffrer — y compris un adversaire disposant
d'un ordinateur quantique.

Construction hybride :

```
  ML-KEM-768.encapsulate(clé_publique_dest)  →  (kemCiphertext, sharedSecret)
  clé_AES = KDF(sharedSecret, salt)                    (voir §4)
  ciphertext‖authTag = AES-256-GCM(clé_AES, iv, plaintext, AAD)   (voir §5)
```

## 2. Types de valeurs

- Les entiers multi-octets sont **big-endian**.
- Tailles fixes : `salt` = 16 octets, `iv` = 12 octets, `authTag` = 16 octets,
  clé AES = 32 octets.
- ML-KEM-768 : clé publique 1184 o, clé secrète 2400 o, ciphertext KEM 1088 o,
  secret partagé 32 o.

## 3. Format binaire (wire format)

### 3.1 v1.2 (lecture + écriture)

```
┌─────────┬──────┬────────┬───────────┬──────────┬──────┬──────────┬─────────┐
│ version │ mode │  salt  │ kemCtLen  │  kemCt   │  iv  │ authTag  │ payload │
│  0x02   │ 1 o  │  16 o  │  2 o BE   │  N o     │ 12 o │  16 o    │  reste  │
└─────────┴──────┴────────┴───────────┴──────────┴──────┴──────────┴─────────┘
```

- `version` = `0x02`
- `mode` = `0x01` (lié à un service) ou `0x02` (pair-à-pair). Voir §6.
- `kemCtLen` = longueur de `kemCt` en octets (65535 max).
- `payload` = ciphertext AES-GCM **sans** le tag (le tag est stocké séparément).

### 3.2 v1 (legacy — lecture seule)

```
┌─────────┬────────┬───────────┬──────────┬──────┬──────────┬─────────┐
│ version │  salt  │ kemCtLen  │  kemCt   │  iv  │ authTag  │ payload │
│  0x01   │  16 o  │  2 o BE   │  N o     │ 12 o │  16 o    │  reste  │
└─────────┴────────┴───────────┴──────────┴──────┴──────────┴─────────┘
```

Pas d'octet `mode` (mode implicite = 1). Les implémentations **doivent** lire le
v1 mais **ne doivent produire que du v1.2**.

## 4. Dérivation de clé (KDF)

⚠️ La v1.x utilise une dérivation **figée, non RFC 5869**, conservée pour
l'interopérabilité. À durcir en v2.0.

```
PRK = SHA-256( sharedSecret ‖ salt )
OKM = SHA-256( PRK ‖ INFO ‖ 0x01 )
clé_AES = OKM[0:32]
```

où `INFO = "spartadoc-q-v1"` (14 octets ASCII). Ce n'est **pas** un HKDF strict
(pas de HMAC à l'extract step) : une v2 introduira HKDF-SHA256 conforme.

## 5. Chiffrement authentifié (AEAD)

AES-256-GCM avec `iv` (12 o aléatoire) et **données associées (AAD)** liant
l'en-tête au ciphertext (anti-downgrade) :

```
  v1.2 : AAD = version(1) ‖ mode(1) ‖ salt(16) ‖ kemCtLen(2 BE) ‖ kemCt
  v1   : AAD = ∅ (vide)
```

Toute modification de `version`, `mode`, `salt` ou `kemCt` invalide donc la
vérification GCM au déchiffrement (empêche un downgrade v1.2→v1 ou 2→1).

WebCrypto/OpenSSL renvoient `ciphertext‖authTag` concaténés ; le format les
sépare (le `payload` exclut le tag, stocké dans le champ `authTag`).

## 6. Modes

| Mode | Octet | Sémantique |
|---|---|---|
| 1 | `0x01` | Message destiné à un service (clé du destinataire gérée côté service) |
| 2 | `0x02` | Pair-à-pair : le destinataire détient lui-même sa clé secrète |

Le mode ne change **pas** la cryptographie — c'est une métadonnée de contexte de
gestion de clés. Un lecteur conforme accepte les deux.

## 7. Génération de clés

`generateKemKeyPair()` = `ML-KEM-768.keygen()` (aléa cryptographique du système).
La clé publique est partageable ; la clé secrète (2400 o) doit rester privée.

## 8. Considérations de sécurité

- **Post-quantique** : la confidentialité repose sur ML-KEM-768 (« harvest now,
  decrypt later » couvert). L'intégrité repose sur AES-GCM (128 bits de tag).
- **Rejet implicite** : ML-KEM ne lève pas à `decapsulate` avec une mauvaise clé
  (il retourne un secret pseudo-aléatoire) ; c'est le tag GCM qui rejette.
- **Non-rejeu de clé** : `salt` et `iv` sont tirés aléatoirement à chaque
  chiffrement → deux blobs du même plaintext diffèrent.
- **Pas de signature** dans le conteneur v1.x : l'authenticité de l'expéditeur
  n'est pas fournie par le format lui-même (couche séparée : registre de clés
  signées SLH-DSA hors périmètre de cette spec).
- La KDF v1.x (§4) est un point à durcir (v2.0 → HKDF-SHA256 RFC 5869).

## 9. Extension `.sdoc` et type MIME

- Extension de fichier : `.sdoc`
- Type MIME proposé : `application/vnd.sdoc`
