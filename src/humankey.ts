/**
 * Clé humaine — un secret court d'où l'on redérive la paire ML-KEM-768.
 *
 * Le problème résolu : un secret ML-KEM-768 fait 2400 octets. On ne l'affiche
 * pas à l'écran, on ne le dicte pas au téléphone, on ne le met pas dans un SMS.
 * On remet donc 160 bits de hasard sous forme lisible, et on regénère la paire
 * de façon DÉTERMINISTE à partir de ce secret.
 *
 *   clé affichée  SDOC-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX   (32 car. base32)
 *   décodage      20 octets
 *   HKDF-SHA256   graine de 64 octets (d || z de FIPS 203)
 *   keygen(graine) paire ML-KEM-768
 *
 * Conséquence structurante : le `.sdoc` produit reste un `.sdoc` ORDINAIRE. Le
 * format binaire n'est pas touché. Toute implémentation conforme à
 * spec/sdoc-format.md peut donc l'ouvrir, pourvu qu'elle dérive la paire de la
 * même façon — c'est pourquoi la dérivation est décrite dans la spécification
 * et non laissée à l'implémentation.
 *
 * ⚠️ Invariant non négociable : `ml_kem768.keygen(graine)` DOIT rester
 * déterministe, et `HKDF_INFO` ne doit JAMAIS changer sans changer aussi le
 * préfixe de la clé. Si l'un ou l'autre bougeait, tout fichier déjà chiffré
 * deviendrait indéchiffrable, partout, sans avertissement.
 *
 * ⚠️ La clé n'est ni stockée, ni transmise, ni récupérable. Clé perdue égale
 * fichier perdu. C'est la contrepartie du fait que le serveur ne l'a jamais eue.
 *
 * Alphabet : base32 de Crockford. Choisi pour ce qu'il RETIRE — ni I, ni L, ni
 * O, ni U. Les trois premiers parce qu'ils se confondent avec 1 et 0 quand on
 * recopie à la main ; le U pour éviter de composer un juron par accident.
 */

import { MalformedKeyError } from './errors.js';

/** Alphabet base32 Crockford, dans l'ordre des valeurs 0 à 31. */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** 20 octets = 160 bits d'entropie. */
const HUMAN_KEY_BYTES = 20;

/** 20 octets en base32 = 32 caractères, sans remplissage. */
export const HUMAN_KEY_BODY_LENGTH = 32;

/** Préfixe d'affichage — repérage visuel, retiré à la normalisation. */
export const HUMAN_KEY_PREFIX = 'SDOC';

/**
 * Versionné dans l'`info` HKDF : si la dérivation devait changer un jour, les
 * clés émises sous v1 resteraient dérivables en gardant cette constante.
 */
const HKDF_INFO = 'spartadoc-sdoc-humankey-v1';

/** Graine ML-KEM-768 de FIPS 203 : d (32) || z (32). */
const KEM_SEED_LEN = 64;

interface MlKem768Keygen {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
}

let kemCache: MlKem768Keygen | null = null;

async function loadKem(): Promise<MlKem768Keygen> {
  if (kemCache !== null) return kemCache;
  const mod = await import('@noble/post-quantum/ml-kem');
  const kem = (mod as unknown as { ml_kem768: MlKem768Keygen }).ml_kem768;
  if (!kem || typeof kem.keygen !== 'function') {
    throw new Error('@noble/post-quantum/ml-kem: ml_kem768 introuvable');
  }
  kemCache = kem;
  return kem;
}

function getCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || !c.subtle) {
    throw new Error('Web Crypto API indisponible (Node 20+ ou navigateur moderne requis)');
  }
  return c;
}

/** WebCrypto refuse un `Uint8Array` adossé à un SharedArrayBuffer ; les nôtres ne le sont jamais. */
function asBufferSource(u: Uint8Array): BufferSource {
  return u as unknown as BufferSource;
}

// ─── Encodage base32 Crockford ────────────────────────────────────────────

function encodeCrockford(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD[(value << (5 - bits)) & 31];
  return out;
}

function decodeCrockford(text: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of text) {
    const idx = CROCKFORD.indexOf(ch);
    if (idx < 0) throw new MalformedKeyError(`caractère « ${ch} » hors alphabet`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// ─── API publique ─────────────────────────────────────────────────────────

/**
 * Met une clé canonique en forme d'affichage : préfixe et groupes de 4.
 * Les groupes ne sont pas cosmétiques — ils rendent la clé dictable au
 * téléphone et repérable à l'œil quand on la recopie.
 */
export function formatHumanKey(canonical: string): string {
  const groupes = canonical.match(/.{1,4}/g) ?? [];
  return [HUMAN_KEY_PREFIX, ...groupes].join('-');
}

/** Génère une clé humaine fraîche, prête à afficher. */
export function generateHumanKey(): string {
  const octets = new Uint8Array(HUMAN_KEY_BYTES);
  getCrypto().getRandomValues(octets);
  return formatHumanKey(encodeCrockford(octets));
}

/**
 * Ramène une saisie humaine à sa forme canonique (32 caractères, sans préfixe
 * ni séparateur). Tolère ce qu'une personne fait réellement : minuscules,
 * espaces, tirets, préfixe oublié, et les confusions que Crockford prévoit.
 *
 * @throws {MalformedKeyError} longueur fausse ou caractère hors alphabet.
 */
export function normalizeHumanKey(input: string): string {
  let s = (input ?? '').toUpperCase().replace(/[^0-9A-Z]/g, '');
  if (s.startsWith(HUMAN_KEY_PREFIX)) s = s.slice(HUMAN_KEY_PREFIX.length);

  // Substitutions Crockford. À faire AVANT le contrôle de longueur : elles ne
  // changent pas le nombre de caractères, mais elles doivent précéder le
  // contrôle d'alphabet, sinon un « O » recopié à la main serait rejeté.
  s = s.replace(/O/g, '0').replace(/[IL]/g, '1');

  if (s.length !== HUMAN_KEY_BODY_LENGTH) {
    throw new MalformedKeyError(`${s.length} caractères utiles, ${HUMAN_KEY_BODY_LENGTH} attendus`);
  }
  for (const ch of s) {
    if (CROCKFORD.indexOf(ch) < 0) throw new MalformedKeyError(`caractère « ${ch} » hors alphabet`);
  }
  return s;
}

/** Vrai si la saisie est une clé humaine recevable. Ne lève jamais. */
export function isValidHumanKey(input: string): boolean {
  try {
    normalizeHumanKey(input);
    return true;
  } catch {
    return false;
  }
}

/**
 * Dérive la paire ML-KEM-768 d'une clé humaine. Déterministe : la même clé
 * redonne toujours la même paire, sur n'importe quelle machine.
 *
 * @throws {MalformedKeyError} si la clé n'est pas recevable — on ne dérive pas
 *         une paire depuis une saisie douteuse, on le dit.
 */
export async function deriveKeyPairFromHumanKey(
  humanKey: string,
): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
  const canonical = normalizeHumanKey(humanKey);
  const ikm = decodeCrockford(canonical);

  const subtle = getCrypto().subtle;
  const base = await subtle.importKey('raw', asBufferSource(ikm), 'HKDF', false, ['deriveBits']);
  const graine = new Uint8Array(
    await subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: asBufferSource(new TextEncoder().encode(HKDF_INFO)),
      },
      base,
      KEM_SEED_LEN * 8,
    ),
  );

  const kem = await loadKem();
  const { publicKey, secretKey } = kem.keygen(graine);
  return { publicKey, secretKey };
}
