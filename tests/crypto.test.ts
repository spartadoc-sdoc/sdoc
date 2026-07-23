/**
 * Tests E2E : encode → decode roundtrip, validation des modes,
 * détection de manipulation (tag GCM).
 */

import { describe, expect, it } from 'vitest';
import { decode, encode } from '../src/crypto.js';
import { generateKemKeyPair } from '../src/keys.js';
import {
  MODE_P2P,
  MODE_SPARTADOC,
  VERSION_V1_2,
} from '../src/types.js';
import { DecryptionError } from '../src/errors.js';

describe('crypto — encode/decode roundtrip', () => {
  it('chiffre et déchiffre un message court (mode Spartadoc)', async () => {
    const { publicKey, secretKey } = await generateKemKeyPair();
    const plaintext = new TextEncoder().encode('Bonjour Spartadoc — accents : éàèùç');
    const blob = await encode(plaintext, publicKey, MODE_SPARTADOC);

    const result = await decode(blob, secretKey);
    expect(result.version).toBe(VERSION_V1_2);
    expect(result.mode).toBe(MODE_SPARTADOC);
    expect(new TextDecoder().decode(result.plaintext)).toBe(
      'Bonjour Spartadoc — accents : éàèùç',
    );
  }, 30_000);

  it('chiffre et déchiffre un blob 1 MiB (mode p2p)', async () => {
    const { publicKey, secretKey } = await generateKemKeyPair();
    const plaintext = new Uint8Array(1024 * 1024);
    // getRandomValues : limite 65536B par appel — remplir par chunks
    for (let off = 0; off < plaintext.length; off += 65536) {
      const chunk = plaintext.subarray(off, Math.min(off + 65536, plaintext.length));
      crypto.getRandomValues(chunk);
    }
    const blob = await encode(plaintext, publicKey, MODE_P2P);

    const result = await decode(blob, secretKey);
    expect(result.mode).toBe(MODE_P2P);
    expect(result.plaintext.length).toBe(plaintext.length);
    expect(result.plaintext).toEqual(plaintext);
  }, 60_000);

  it('rejette un blob altéré (auth tag GCM)', async () => {
    const { publicKey, secretKey } = await generateKemKeyPair();
    const plaintext = new TextEncoder().encode('payload sensible');
    const blob = await encode(plaintext, publicKey, MODE_SPARTADOC);

    // Flip 1 bit dans le payload chiffré (dernier octet)
    blob[blob.length - 1] ^= 0x01;

    await expect(decode(blob, secretKey)).rejects.toBeInstanceOf(DecryptionError);
  }, 30_000);

  it('échoue avec une clé secrète différente', async () => {
    const a = await generateKemKeyPair();
    const b = await generateKemKeyPair();
    const blob = await encode(new TextEncoder().encode('top secret'), a.publicKey, MODE_P2P);
    // ML-KEM-768 ne lève pas forcément à decapsulate (implicit rejection : retourne un secret pseudo-aléatoire),
    // mais le tag GCM va invalider.
    await expect(decode(blob, b.secretKey)).rejects.toBeInstanceOf(DecryptionError);
  }, 30_000);

  it('produit des blobs différents pour le même plaintext (IV/salt aléatoires)', async () => {
    const { publicKey } = await generateKemKeyPair();
    const plaintext = new TextEncoder().encode('même message');
    const a = await encode(plaintext, publicKey, MODE_SPARTADOC);
    const b = await encode(plaintext, publicKey, MODE_SPARTADOC);
    expect(a).not.toEqual(b);
  }, 30_000);
});
