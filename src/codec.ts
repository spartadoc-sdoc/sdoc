/**
 * Framing du format .sdoc.
 *
 * v1 (legacy CLI, lecture seule depuis cette lib) :
 *   [version=0x01][salt 16][kemCtLen 2BE][kemCt N][iv 12][authTag 16][data]
 *
 * v1.2 (lecture + écriture) :
 *   [version=0x02][mode 1][salt 16][kemCtLen 2BE][kemCt N][iv 12][authTag 16][data]
 *
 * mode = 0x01 (MODE_SPARTADOC) ou 0x02 (MODE_P2P).
 */

import {
  InvalidModeError,
  TruncatedBlobError,
  UnsupportedVersionError,
} from './errors.js';
import {
  MODE_P2P,
  MODE_SPARTADOC,
  VERSION_V1,
  VERSION_V1_2,
  type SdocHeader,
  type SdocMode,
} from './types.js';

const SALT_LEN = 16;
const IV_LEN = 12;
const AUTH_TAG_LEN = 16;
const KEM_CT_LEN_FIELD = 2;

function readU16BE(buf: Uint8Array, offset: number): number {
  return (buf[offset]! << 8) | buf[offset + 1]!;
}

function writeU16BE(value: number): Uint8Array {
  const out = new Uint8Array(2);
  out[0] = (value >> 8) & 0xff;
  out[1] = value & 0xff;
  return out;
}

function concat(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function ensureAvailable(blob: Uint8Array, offset: number, needed: number, field: string): void {
  if (offset + needed > blob.length) {
    throw new TruncatedBlobError(needed, blob.length - offset, field);
  }
}

function isSdocMode(byte: number): byte is SdocMode {
  return byte === MODE_SPARTADOC || byte === MODE_P2P;
}

/**
 * Parse l'en-tête + payload .sdoc, sans déchiffrer.
 * Détecte automatiquement v1 (legacy) et v1.2.
 */
export function parseHeader(blob: Uint8Array): SdocHeader {
  ensureAvailable(blob, 0, 1, 'version');
  const version = blob[0]!;

  let offset: number;
  let mode: SdocMode | null;

  if (version === VERSION_V1) {
    mode = null;
    offset = 1;
  } else if (version === VERSION_V1_2) {
    ensureAvailable(blob, 1, 1, 'mode');
    const modeByte = blob[1]!;
    if (!isSdocMode(modeByte)) {
      throw new InvalidModeError(modeByte);
    }
    mode = modeByte;
    offset = 2;
  } else {
    throw new UnsupportedVersionError(version);
  }

  ensureAvailable(blob, offset, SALT_LEN, 'salt');
  const salt = blob.slice(offset, offset + SALT_LEN);
  offset += SALT_LEN;

  ensureAvailable(blob, offset, KEM_CT_LEN_FIELD, 'kemCtLen');
  const kemCtLen = readU16BE(blob, offset);
  offset += KEM_CT_LEN_FIELD;

  ensureAvailable(blob, offset, kemCtLen, 'kemCiphertext');
  const kemCiphertext = blob.slice(offset, offset + kemCtLen);
  offset += kemCtLen;

  ensureAvailable(blob, offset, IV_LEN, 'iv');
  const iv = blob.slice(offset, offset + IV_LEN);
  offset += IV_LEN;

  ensureAvailable(blob, offset, AUTH_TAG_LEN, 'authTag');
  const authTag = blob.slice(offset, offset + AUTH_TAG_LEN);
  offset += AUTH_TAG_LEN;

  const payload = blob.slice(offset);

  return {
    version: version === VERSION_V1 ? VERSION_V1 : VERSION_V1_2,
    mode,
    salt,
    kemCiphertext,
    iv,
    authTag,
    payload,
  };
}

/**
 * Sérialise un en-tête + payload en blob .sdoc v1.2.
 */
export function writeBlob(header: SdocHeader): Uint8Array {
  if (header.version !== VERSION_V1_2) {
    throw new Error('writeBlob ne produit que du v1.2 — v1 est lecture seule');
  }
  if (header.mode === null) {
    throw new Error('mode requis pour v1.2');
  }
  if (header.salt.length !== SALT_LEN) {
    throw new Error(`salt doit faire ${SALT_LEN} octets`);
  }
  if (header.iv.length !== IV_LEN) {
    throw new Error(`iv doit faire ${IV_LEN} octets`);
  }
  if (header.authTag.length !== AUTH_TAG_LEN) {
    throw new Error(`authTag doit faire ${AUTH_TAG_LEN} octets`);
  }
  if (header.kemCiphertext.length > 0xffff) {
    throw new Error('kemCiphertext > 65535 octets non supporté en v1.2');
  }

  return concat([
    new Uint8Array([VERSION_V1_2, header.mode]),
    header.salt,
    writeU16BE(header.kemCiphertext.length),
    header.kemCiphertext,
    header.iv,
    header.authTag,
    header.payload,
  ]);
}
