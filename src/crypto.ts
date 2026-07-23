/**
 * Hybride ML-KEM-768 + HKDF-SHA256 + AES-256-GCM.
 *
 * La dérivation utilise `info = "spartadoc-q-v1"` (figé pour l'interopérabilité
 * entre toutes les implémentations `.sdoc` v1.x — voir spec/sdoc-format.md).
 *
 * Noble (`@noble/post-quantum`) est lazy-loadé au premier chiffrement pour
 * minimiser le coût d'initialisation en environnement contraint (add-ins e-mail).
 */

import { parseHeader, writeBlob } from './codec.js';
import { DecryptionError } from './errors.js';
import {
  MODE_SPARTADOC,
  VERSION_V1,
  VERSION_V1_2,
  type SdocDecodeResult,
  type SdocMode,
} from './types.js';

const HKDF_INFO = new TextEncoder().encode('spartadoc-q-v1');
const SALT_LEN = 16;
const IV_LEN = 12;
const AES_KEY_LEN = 32;
const AUTH_TAG_LEN = 16;

interface MlKem768 {
  keygen(): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array;
}

let mlKemCache: MlKem768 | null = null;

async function loadMlKem(): Promise<MlKem768> {
  if (mlKemCache !== null) return mlKemCache;
  const mod = await import('@noble/post-quantum/ml-kem');
  // ml_kem768 exposed at runtime by @noble/post-quantum
  const kem = (mod as unknown as { ml_kem768: MlKem768 }).ml_kem768;
  if (!kem || typeof kem.keygen !== 'function') {
    throw new Error('@noble/post-quantum/ml-kem: ml_kem768 introuvable (mauvaise version ?)');
  }
  mlKemCache = kem;
  return kem;
}

function getCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || !c.subtle) {
    throw new Error('Web Crypto API indisponible (Node 20+ ou navigateur moderne requis)');
  }
  return c;
}

function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len);
  getCrypto().getRandomValues(out);
  return out;
}

/**
 * WebCrypto exige `BufferSource` strictement basé sur `ArrayBuffer` (pas
 * `SharedArrayBuffer`). Nos `Uint8Array` sortent de `randomBytes`, `slice()`
 * et `new Uint8Array(N)` — toujours backed par `ArrayBuffer` en pratique.
 * Le cast est donc sûr ; le helper centralise la suppression du warning TS5.x.
 */
function asBufferSource(u: Uint8Array): BufferSource {
  return u as unknown as BufferSource;
}

/**
 * HKDF avec PRK = sha256(sharedSecret || salt) puis HMAC-step in-line.
 *
 * Note implémentation : dérivation figée v1.x pour interop bit-à-bit entre
 * implémentations. Ce n'est PAS un HKDF RFC5869 strict (pas de HMAC à l'extract
 * step) — voir spec/sdoc-format.md §Dérivation. À durcir en v2.0.
 */
async function deriveAesKey(sharedSecret: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  const subtle = getCrypto().subtle;
  const prkInput = new Uint8Array(sharedSecret.length + salt.length);
  prkInput.set(sharedSecret, 0);
  prkInput.set(salt, sharedSecret.length);
  const prk = new Uint8Array(await subtle.digest('SHA-256', asBufferSource(prkInput)));

  const hmacInput = new Uint8Array(prk.length + HKDF_INFO.length + 1);
  hmacInput.set(prk, 0);
  hmacInput.set(HKDF_INFO, prk.length);
  hmacInput[prk.length + HKDF_INFO.length] = 0x01;
  const okm = new Uint8Array(await subtle.digest('SHA-256', asBufferSource(hmacInput)));

  return okm.slice(0, AES_KEY_LEN);
}

async function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return getCrypto().subtle.importKey('raw', asBufferSource(rawKey), { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

/**
 * AAD lie au ciphertext les bytes de framing {version || mode || salt || kemCtLen(2BE) || kemCt}.
 * Empêche les attaques de downgrade (v1.2→v1, mode P2P→Spartadoc) et toute manipulation
 * silencieuse de l'en-tête : un flip de version ou mode invalide la vérification GCM.
 * v1 (legacy CLI) : AAD vide pour préserver la lecture seule des blobs CLI existants.
 */
function buildAad(version: number, mode: SdocMode | null, salt: Uint8Array, kemCt: Uint8Array): Uint8Array {
  if (version === VERSION_V1) return new Uint8Array(0);
  const out = new Uint8Array(2 + salt.length + 2 + kemCt.length);
  out[0] = version;
  out[1] = mode ?? 0;
  out.set(salt, 2);
  out[2 + salt.length] = (kemCt.length >> 8) & 0xff;
  out[2 + salt.length + 1] = kemCt.length & 0xff;
  out.set(kemCt, 2 + salt.length + 2);
  return out;
}

/**
 * Chiffre `plaintext` pour `recipientPublicKey` (ML-KEM-768) en mode 1 ou 2.
 * Produit un blob `.sdoc` v1.2.
 */
export async function encode(
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array,
  mode: SdocMode = MODE_SPARTADOC,
): Promise<Uint8Array> {
  const kem = await loadMlKem();
  const { cipherText: kemCt, sharedSecret } = kem.encapsulate(recipientPublicKey);

  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const aesKeyRaw = await deriveAesKey(sharedSecret, salt);
  const aesKey = await importAesKey(aesKeyRaw);

  const aad = buildAad(VERSION_V1_2, mode, salt, kemCt);
  const ctWithTag = new Uint8Array(
    await getCrypto().subtle.encrypt(
      { name: 'AES-GCM', iv: asBufferSource(iv), additionalData: asBufferSource(aad) },
      aesKey,
      asBufferSource(plaintext),
    ),
  );

  // WebCrypto retourne ciphertext || authTag concaténés ; on les sépare pour
  // le framing v1/v1.2 (qui stocke authTag séparément, iso CLI v1).
  const splitAt = ctWithTag.length - AUTH_TAG_LEN;
  const payload = ctWithTag.slice(0, splitAt);
  const authTag = ctWithTag.slice(splitAt);

  return writeBlob({
    version: VERSION_V1_2,
    mode,
    salt,
    kemCiphertext: kemCt,
    iv,
    authTag,
    payload,
  });
}

/**
 * Déchiffre un blob `.sdoc` v1 (legacy CLI) ou v1.2.
 * Retourne `mode = null` pour v1 (mode implicite = Mode 1 Spartadoc).
 */
export async function decode(
  blob: Uint8Array,
  recipientSecretKey: Uint8Array,
): Promise<SdocDecodeResult> {
  const header = parseHeader(blob);
  const kem = await loadMlKem();
  const sharedSecret = kem.decapsulate(header.kemCiphertext, recipientSecretKey);

  const aesKeyRaw = await deriveAesKey(sharedSecret, header.salt);
  const aesKey = await importAesKey(aesKeyRaw);

  const combined = new Uint8Array(header.payload.length + header.authTag.length);
  combined.set(header.payload, 0);
  combined.set(header.authTag, header.payload.length);

  const aad = buildAad(header.version, header.mode, header.salt, header.kemCiphertext);
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await getCrypto().subtle.decrypt(
        { name: 'AES-GCM', iv: asBufferSource(header.iv), additionalData: asBufferSource(aad) },
        aesKey,
        asBufferSource(combined),
      ),
    );
  } catch (err) {
    throw new DecryptionError(err);
  }

  return {
    plaintext,
    version: header.version === VERSION_V1 ? VERSION_V1 : VERSION_V1_2,
    mode: header.mode,
  };
}
