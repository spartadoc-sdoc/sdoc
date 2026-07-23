/**
 * Tests framing : v1 (legacy CLI lecture seule) + v1.2 (lecture/écriture).
 * Aucune crypto ici — on valide juste la sérialisation.
 */

import { describe, expect, it } from 'vitest';
import {
  parseHeader,
  writeBlob,
} from '../src/codec.js';
import {
  InvalidModeError,
  TruncatedBlobError,
  UnsupportedVersionError,
} from '../src/errors.js';
import {
  MODE_P2P,
  MODE_SPARTADOC,
  VERSION_V1,
  VERSION_V1_2,
} from '../src/types.js';

function bytes(...nums: number[]): Uint8Array {
  return new Uint8Array(nums);
}

function fill(len: number, byte: number): Uint8Array {
  const out = new Uint8Array(len);
  out.fill(byte);
  return out;
}

describe('codec — parseHeader v1 (legacy CLI)', () => {
  it('parse un blob v1 minimal correctement', () => {
    const salt = fill(16, 0xaa);
    const kemCt = fill(8, 0xbb); // ML-KEM réel = 1088B, on prend 8B pour le test
    const iv = fill(12, 0xcc);
    const authTag = fill(16, 0xdd);
    const payload = fill(4, 0xee);
    const blob = new Uint8Array([
      VERSION_V1,
      ...salt,
      0x00, kemCt.length, // 2BE
      ...kemCt,
      ...iv,
      ...authTag,
      ...payload,
    ]);

    const h = parseHeader(blob);
    expect(h.version).toBe(VERSION_V1);
    expect(h.mode).toBeNull();
    expect(Array.from(h.salt)).toEqual(Array.from(salt));
    expect(Array.from(h.kemCiphertext)).toEqual(Array.from(kemCt));
    expect(Array.from(h.iv)).toEqual(Array.from(iv));
    expect(Array.from(h.authTag)).toEqual(Array.from(authTag));
    expect(Array.from(h.payload)).toEqual(Array.from(payload));
  });
});

describe('codec — parseHeader v1.2', () => {
  it('parse un blob v1.2 mode Spartadoc', () => {
    const blob = writeBlob({
      version: VERSION_V1_2,
      mode: MODE_SPARTADOC,
      salt: fill(16, 0x01),
      kemCiphertext: fill(10, 0x02),
      iv: fill(12, 0x03),
      authTag: fill(16, 0x04),
      payload: fill(20, 0x05),
    });
    const h = parseHeader(blob);
    expect(h.version).toBe(VERSION_V1_2);
    expect(h.mode).toBe(MODE_SPARTADOC);
    expect(h.payload.length).toBe(20);
  });

  it('parse un blob v1.2 mode p2p', () => {
    const blob = writeBlob({
      version: VERSION_V1_2,
      mode: MODE_P2P,
      salt: fill(16, 0x01),
      kemCiphertext: fill(5, 0x02),
      iv: fill(12, 0x03),
      authTag: fill(16, 0x04),
      payload: new Uint8Array(),
    });
    const h = parseHeader(blob);
    expect(h.mode).toBe(MODE_P2P);
    expect(h.payload.length).toBe(0);
  });

  it('rejette un mode inconnu', () => {
    const blob = bytes(VERSION_V1_2, 0x99, ...fill(16, 0).values());
    expect(() => parseHeader(blob)).toThrow(InvalidModeError);
  });

  it('rejette une version inconnue', () => {
    const blob = bytes(0x42);
    expect(() => parseHeader(blob)).toThrow(UnsupportedVersionError);
  });

  it('détecte un blob tronqué au champ salt', () => {
    const blob = bytes(VERSION_V1_2, MODE_SPARTADOC, 0x01, 0x02);
    expect(() => parseHeader(blob)).toThrow(TruncatedBlobError);
  });

  it('détecte un blob tronqué au champ kemCiphertext', () => {
    const blob = new Uint8Array([
      VERSION_V1_2,
      MODE_SPARTADOC,
      ...fill(16, 0),
      0x00, 0x10, // annonce 16 octets de kemCt
      0x01, 0x02, // mais n'en fournit que 2
    ]);
    expect(() => parseHeader(blob)).toThrow(TruncatedBlobError);
  });
});

describe('codec — writeBlob', () => {
  it('round-trip v1.2 préserve tous les champs', () => {
    const original = {
      version: VERSION_V1_2,
      mode: MODE_P2P,
      salt: fill(16, 0xaa),
      kemCiphertext: fill(1088, 0xbb), // taille ML-KEM-768 réelle
      iv: fill(12, 0xcc),
      authTag: fill(16, 0xdd),
      payload: fill(1024, 0xee),
    } as const;
    const blob = writeBlob(original);
    const parsed = parseHeader(blob);
    expect(parsed.version).toBe(original.version);
    expect(parsed.mode).toBe(original.mode);
    expect(parsed.salt).toEqual(original.salt);
    expect(parsed.kemCiphertext).toEqual(original.kemCiphertext);
    expect(parsed.iv).toEqual(original.iv);
    expect(parsed.authTag).toEqual(original.authTag);
    expect(parsed.payload).toEqual(original.payload);
  });

  it('refuse de produire du v1', () => {
    expect(() =>
      writeBlob({
        version: VERSION_V1,
        mode: MODE_SPARTADOC,
        salt: fill(16, 0),
        kemCiphertext: fill(0, 0),
        iv: fill(12, 0),
        authTag: fill(16, 0),
        payload: new Uint8Array(),
      } as never),
    ).toThrow(/v1.2/);
  });

  it('refuse mode null en v1.2', () => {
    expect(() =>
      writeBlob({
        version: VERSION_V1_2,
        mode: null,
        salt: fill(16, 0),
        kemCiphertext: fill(0, 0),
        iv: fill(12, 0),
        authTag: fill(16, 0),
        payload: new Uint8Array(),
      } as never),
    ).toThrow(/mode requis/);
  });
});
