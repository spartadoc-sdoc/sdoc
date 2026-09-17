/**
 * Erreurs typées du codec .sdoc.
 */

export class SdocError extends Error {
  override readonly name: string = 'SdocError';
}

export class UnsupportedVersionError extends SdocError {
  override readonly name = 'UnsupportedVersionError';
  constructor(public readonly version: number) {
    super(`Version .sdoc non supportée : 0x${version.toString(16).padStart(2, '0')}`);
  }
}

export class InvalidModeError extends SdocError {
  override readonly name = 'InvalidModeError';
  constructor(public readonly mode: number) {
    super(`Mode .sdoc invalide : 0x${mode.toString(16).padStart(2, '0')} (attendu : 0x01 Spartadoc ou 0x02 p2p)`);
  }
}

export class TruncatedBlobError extends SdocError {
  override readonly name = 'TruncatedBlobError';
  constructor(needed: number, available: number, atField: string) {
    super(`Blob .sdoc tronqué au champ "${atField}" : ${needed} octets attendus, ${available} disponibles`);
  }
}

export class DecryptionError extends SdocError {
  override readonly name = 'DecryptionError';
  constructor(cause?: unknown) {
    super(`Échec du déchiffrement .sdoc (auth tag invalide ou clé incorrecte)`);
    if (cause !== undefined) {
      (this as { cause?: unknown }).cause = cause;
    }
  }
}

/**
 * Clé humaine mal formée : mauvaise longueur ou caractère hors alphabet.
 *
 * Volontairement DISTINCTE de DecryptionError. « Cette clé n'a pas le bon
 * format » et « cette clé ne déchiffre pas ce fichier » sont deux situations
 * différentes : la première se corrige en recopiant mieux, la seconde veut dire
 * qu'on n'a pas la bonne clé.
 */
export class MalformedKeyError extends SdocError {
  override readonly name = 'MalformedKeyError';
  constructor(public readonly detail: string) {
    super(`Clé mal formée : ${detail}`);
  }
}
