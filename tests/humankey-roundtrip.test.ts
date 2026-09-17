/**
 * Aller-retour par clé humaine.
 *
 * Ce qui est réellement mis à l'épreuve ici : la promesse faite à l'écran.
 * « Une clé de 32 caractères, et elle seule, rouvre le fichier. »
 * Chaque test ci-dessous correspond à une façon dont cette phrase pourrait
 * devenir fausse en production.
 */

import { describe, it, expect } from 'vitest';
import { generateHumanKey, deriveKeyPairFromHumanKey } from '../src/humankey.js';
import { encode, decode } from '../src/crypto.js';
import { DecryptionError, TruncatedBlobError } from '../src/errors.js';
import { MODE_P2P, MODE_SPARTADOC } from '../src/types.js';

/** Chiffre comme le fait l'atelier : charge utile brute, Mode 2, aucune enveloppe. */
async function chiffrer(clair: Uint8Array): Promise<{ blob: Uint8Array; cle: string }> {
  const cle = generateHumanKey();
  const { publicKey } = await deriveKeyPairFromHumanKey(cle);
  return { blob: await encode(clair, publicKey, MODE_P2P), cle };
}

async function dechiffrer(blob: Uint8Array, cle: string): Promise<Uint8Array> {
  const { secretKey } = await deriveKeyPairFromHumanKey(cle);
  const { plaintext } = await decode(blob, secretKey);
  return plaintext;
}

describe('aller-retour', () => {
  it('6. redonne les octets d’origine, exactement', async () => {
    const clair = new TextEncoder().encode('Entente de confidentialité — 12 345,67 $ CAD. Àéèêçù.');
    const { blob, cle } = await chiffrer(clair);
    const rendu = await dechiffrer(blob, cle);
    expect(Buffer.from(rendu).equals(Buffer.from(clair))).toBe(true);
  });

  it('7. tient sur un fichier d’un seul octet', async () => {
    const clair = new Uint8Array([0x42]);
    const { blob, cle } = await chiffrer(clair);
    expect(Buffer.from(await dechiffrer(blob, cle)).equals(Buffer.from(clair))).toBe(true);
  });

  it('8. tient sur du binaire — octets nuls et haut de table', async () => {
    // Un PDF ou un .docx contient les 256 valeurs. Un aller-retour qui ne
    // passerait que sur du texte laisserait passer une corruption d’encodage.
    const clair = new Uint8Array(256 * 4);
    for (let i = 0; i < clair.length; i++) clair[i] = i % 256;
    const { blob, cle } = await chiffrer(clair);
    expect(Buffer.from(await dechiffrer(blob, cle)).equals(Buffer.from(clair))).toBe(true);
  });

  it('8b. tient sur un fichier de 2 Mo', async () => {
    const clair = new Uint8Array(2 * 1024 * 1024);
    crypto.getRandomValues(clair.subarray(0, 65536));
    const { blob, cle } = await chiffrer(clair);
    expect(Buffer.from(await dechiffrer(blob, cle)).equals(Buffer.from(clair))).toBe(true);
  });
});

describe('chemins d’erreur', () => {
  it('9. une mauvaise clé lève, et ne rend JAMAIS d’octets', async () => {
    const { blob } = await chiffrer(new TextEncoder().encode('secret'));
    const autre = generateHumanKey();
    // AES-GCM authentifie : il n'existe pas de cas où une mauvaise clé
    // produirait un clair faux plutôt qu'une erreur.
    await expect(dechiffrer(blob, autre)).rejects.toThrow(DecryptionError);
  });

  it('10. un blob tronqué lève TruncatedBlobError, pas DecryptionError', async () => {
    // La distinction porte une distinction qui compte : « fichier abîmé » et « mauvaise clé »
    // ne doivent pas se présenter sous le même message.
    const { blob, cle } = await chiffrer(new TextEncoder().encode('secret'));
    const tronque = blob.slice(0, blob.length - 40);
    await expect(dechiffrer(tronque, cle)).rejects.toThrow(TruncatedBlobError);
  });

  it('10b. un octet retourné dans la charge utile lève DecryptionError', async () => {
    const { blob, cle } = await chiffrer(new TextEncoder().encode('secret'));
    const altere = new Uint8Array(blob);
    altere[altere.length - 1] ^= 0xff;
    await expect(dechiffrer(altere, cle)).rejects.toThrow(DecryptionError);
  });

  it('11. un .sdoc de séquestre (Mode 1) est reconnaissable avant toute tentative', async () => {
    // Un Mode 1 est chiffré pour le destinataire d'un service : aucune clé
    // humaine ne l'ouvre, et il faut le dire plutôt que d'échouer sur la clé.
    const { publicKey } = await deriveKeyPairFromHumanKey(generateHumanKey());
    const sequestre = await encode(new TextEncoder().encode('x'), publicKey, MODE_SPARTADOC);
    const atelier = await encode(new TextEncoder().encode('x'), publicKey, MODE_P2P);

    const { parseHeader } = await import('../src/codec.js');
    expect(parseHeader(sequestre).mode).toBe(MODE_SPARTADOC);
    expect(parseHeader(atelier).mode).toBe(MODE_P2P);
  });
});
