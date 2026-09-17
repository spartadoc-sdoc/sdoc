/**
 * sdoc — codec post-quantique `.sdoc` (ML-KEM-768 + AES-256-GCM).
 *
 * Implémentation de référence du format ouvert `.sdoc` (voir spec/sdoc-format.md).
 * Portable : navigateur, Node 20+, add-ins e-mail — interop bidirectionnelle.
 *
 * Usage minimal :
 *
 *   import { encode, decode, generateKemKeyPair, MODE_SPARTADOC } from 'sdoc-pqc';
 *
 *   const { publicKey, secretKey } = await generateKemKeyPair();
 *   const blob = await encode(plaintextBytes, publicKey, MODE_SPARTADOC);
 *   const { plaintext, mode, version } = await decode(blob, secretKey);
 */

export { encode, decode } from './crypto.js';
export { generateKemKeyPair, type KemKeyPair } from './keys.js';
export { parseHeader, writeBlob } from './codec.js';
export {
  SdocError,
  UnsupportedVersionError,
  InvalidModeError,
  TruncatedBlobError,
  DecryptionError,
  MalformedKeyError,
} from './errors.js';
export {
  MODE_SPARTADOC,
  MODE_P2P,
  VERSION_V1,
  VERSION_V1_2,
  type SdocMode,
  type SdocVersion,
  type SdocHeader,
  type SdocDecodeResult,
} from './types.js';
export {
  generateHumanKey,
  normalizeHumanKey,
  formatHumanKey,
  isValidHumanKey,
  deriveKeyPairFromHumanKey,
  HUMAN_KEY_BODY_LENGTH,
  HUMAN_KEY_PREFIX,
} from './humankey.js';
