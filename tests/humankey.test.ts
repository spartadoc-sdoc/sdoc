/**
 * Clé humaine — dérivation déterministe d'une paire ML-KEM-768 depuis 160 bits.
 *
 * L'enjeu tenu ici : le secret ML-KEM-768 fait 2400 octets, illisible à l'écran
 * et intransportable par SMS. On remet donc 160 bits et on regénère la paire.
 * Si `keygen(graine)` cessait d'être déterministe, TOUT fichier déjà chiffré
 * deviendrait indéchiffrable — c'est le test 4 qui garde cet invariant.
 */

import { describe, it, expect } from 'vitest';
import {
  generateHumanKey,
  normalizeHumanKey,
  deriveKeyPairFromHumanKey,
  HUMAN_KEY_BODY_LENGTH,
} from '../src/humankey.js';
import { MalformedKeyError } from '../src/errors.js';
import { encode, decode } from '../src/crypto.js';
import { parseHeader } from '../src/codec.js';
import { MODE_P2P, VERSION_V1_2 } from '../src/types.js';

describe('genererCleHumaine', () => {
  it('1. produit un préfixe SDOC et 32 caractères Crockford groupés par 4', () => {
    const cle = generateHumanKey();
    expect(cle).toMatch(/^SDOC-[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
    expect(normalizeHumanKey(cle)).toHaveLength(HUMAN_KEY_BODY_LENGTH);
  });

  it('1b. ne se répète pas', () => {
    const vues = new Set(Array.from({ length: 200 }, () => generateHumanKey()));
    expect(vues.size).toBe(200);
  });
});

describe('normaliserCleHumaine', () => {
  it('2. tolère minuscules, espaces, tirets et absence de préfixe', () => {
    const cle = generateHumanKey();
    const canon = normalizeHumanKey(cle);
    const corps = cle.slice('SDOC-'.length);

    expect(normalizeHumanKey(cle.toLowerCase())).toBe(canon);
    expect(normalizeHumanKey(cle.replace(/-/g, ' '))).toBe(canon);
    expect(normalizeHumanKey(cle.replace(/-/g, ''))).toBe(canon);
    expect(normalizeHumanKey(`  ${cle}  `)).toBe(canon);
    expect(normalizeHumanKey(corps)).toBe(canon);
  });

  it('2b. confond O avec 0 et I/L avec 1, comme le veut Crockford', () => {
    // L'alphabet Crockford exclut I, L, O et U — une clé émise n'en contient
    // jamais. Une personne qui recopie à la main, elle, en écrit.
    const sujet = 'SDOC-OOOO-IIII-LLLL-0000-1111-2222-3333-4444';
    expect(normalizeHumanKey(sujet)).toBe('00001111111100001111222233334444');
  });

  it('3. rejette une longueur fausse', () => {
    expect(() => normalizeHumanKey('SDOC-ABCD')).toThrow(MalformedKeyError);
    expect(() => normalizeHumanKey('')).toThrow(MalformedKeyError);
    expect(() => normalizeHumanKey(generateHumanKey() + 'AB')).toThrow(MalformedKeyError);
  });

  it('3b. rejette un caractère hors alphabet', () => {
    // 'U' est volontairement absent de Crockford et n'est pas substituable.
    expect(() => normalizeHumanKey('U'.repeat(32))).toThrow(MalformedKeyError);
  });
});

describe('deriverPaire', () => {
  it('4. est déterministe — deux appels, même secret', async () => {
    const cle = generateHumanKey();
    const a = await deriveKeyPairFromHumanKey(cle);
    const b = await deriveKeyPairFromHumanKey(cle);

    expect(Buffer.from(a.secretKey).equals(Buffer.from(b.secretKey))).toBe(true);
    expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(true);
    expect(a.publicKey).toHaveLength(1184);
    expect(a.secretKey).toHaveLength(2400);
  });

  it('4b. est insensible au formatage de la clé saisie', async () => {
    const cle = generateHumanKey();
    const a = await deriveKeyPairFromHumanKey(cle);
    const b = await deriveKeyPairFromHumanKey(cle.toLowerCase().replace(/-/g, ' '));
    expect(Buffer.from(a.secretKey).equals(Buffer.from(b.secretKey))).toBe(true);
  });

  it('5. deux clés distinctes donnent deux secrets distincts', async () => {
    const a = await deriveKeyPairFromHumanKey(generateHumanKey());
    const b = await deriveKeyPairFromHumanKey(generateHumanKey());
    expect(Buffer.from(a.secretKey).equals(Buffer.from(b.secretKey))).toBe(false);
  });

  it('5b. propage MalformedKeyError sans tenter de dériver', async () => {
    await expect(deriveKeyPairFromHumanKey('pas une clé')).rejects.toThrow(MalformedKeyError);
  });
});

describe('interopérabilité du blob produit', () => {
  it('13. le blob se reparse en Mode 2, version v1.2', async () => {
    const cle = generateHumanKey();
    const { publicKey } = await deriveKeyPairFromHumanKey(cle);
    const blob = await encode(new TextEncoder().encode('bonjour'), publicKey, MODE_P2P);

    const entete = parseHeader(blob);
    expect(entete.version).toBe(VERSION_V1_2);
    expect(entete.mode).toBe(MODE_P2P);
  });

  it('12. un blob chiffré depuis la clé publique dérivée se déchiffre par le secret dérivé', async () => {
    // C'est l'invariant d'interopérabilité : le CLI consomme le MÊME codec
    // (encode/decode de src/crypto.ts). Si la dérivation navigateur et le
    // codec divergeaient, ce test casserait avant la production.
    const cle = generateHumanKey();
    const { publicKey } = await deriveKeyPairFromHumanKey(cle);
    const clair = new TextEncoder().encode('document confidentiel');

    const blob = await encode(clair, publicKey, MODE_P2P);

    // On re-dérive depuis la CHAÎNE seule, comme le ferait une autre machine
    // à qui la personne a lu sa clé au téléphone.
    const { secretKey } = await deriveKeyPairFromHumanKey(cle);
    const { plaintext, mode } = await decode(blob, secretKey);

    expect(new TextDecoder().decode(plaintext)).toBe('document confidentiel');
    expect(mode).toBe(MODE_P2P);
  });
});

describe('vecteur de conformité (spec §7.1)', () => {
  // ⚠️ VECTEUR FIGÉ. Ces valeurs sont la spécification rendue exécutable.
  //
  // Si ce test casse, ce n'est PAS le test qu'il faut corriger : la dérivation
  // a changé, et tout fichier déjà chiffré par une clé humaine vient de devenir
  // indéchiffrable, partout, sans message d'erreur. Une dérivation nouvelle
  // exige un `info` HKDF nouveau ET un préfixe de clé nouveau (spec §7.1,
  // « Versioning »), pas une mise à jour de ces constantes.
  //
  // C'est aussi ce qui permet à une implémentation tierce de se vérifier :
  // même clé, mêmes octets.
  const CLE = 'SDOC-0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ';
  const PK_SHA256 = 'a9163d808ebe166d279929d7628927cf287bf203ee3f09c374da46b873785455';
  const SK_SHA256 = 'ef7612fcfcec8acae6c327150b8b2f35f39b7711939794b70ccd0f5abb1dd664';

  it('dérive exactement la paire attendue', async () => {
    const { createHash } = await import('node:crypto');
    const { publicKey, secretKey } = await deriveKeyPairFromHumanKey(CLE);
    expect(createHash('sha256').update(publicKey).digest('hex')).toBe(PK_SHA256);
    expect(createHash('sha256').update(secretKey).digest('hex')).toBe(SK_SHA256);
  });

  it('la normalisation de la spec donne bien la forme canonique attendue', () => {
    expect(normalizeHumanKey(CLE)).toBe('0123456789ABCDEFGHJKMNPQRSTVWXYZ');
  });
});
