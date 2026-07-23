/**
 * Types publics du codec .sdoc.
 *
 * Le format porte un octet `version` (1 = legacy CLI, 2 = v1.2 avec mode metadata)
 * et, pour v1.2, un octet `mode` distinguant Mode 1 (Spartadoc-bound) et Mode 2 (p2p).
 */

export type SdocMode = 1 | 2;
export type SdocVersion = 1 | 2;

export const MODE_SPARTADOC: SdocMode = 1;
export const MODE_P2P: SdocMode = 2;

export const VERSION_V1: SdocVersion = 1;
export const VERSION_V1_2: SdocVersion = 2;

export interface SdocHeader {
  version: SdocVersion;
  mode: SdocMode | null; // null pour v1 legacy (mode implicite Mode 1)
  salt: Uint8Array;      // 16 bytes
  kemCiphertext: Uint8Array;
  iv: Uint8Array;        // 12 bytes
  authTag: Uint8Array;   // 16 bytes
  payload: Uint8Array;   // ciphertext AES-GCM (sans tag)
}

export interface SdocDecodeResult {
  plaintext: Uint8Array;
  version: SdocVersion;
  mode: SdocMode | null;
}
