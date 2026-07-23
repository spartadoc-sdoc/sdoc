/**
 * Génération de paires de clés ML-KEM-768.
 *
 * Utilisé par l'onboarding des add-ins (Sprint 4) pour créer la paire
 * destinataire (kem) — distincte de la paire de signature SLH-DSA
 * (Sprint 3, registre keys.sdoc.ca).
 */

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

export interface KemKeyPair {
  publicKey: Uint8Array; // ML-KEM-768 = 1184 octets
  secretKey: Uint8Array; // ML-KEM-768 = 2400 octets
}

/**
 * Génère une paire ML-KEM-768 fraîche.
 * Source d'aléa = randomBytes interne de Noble (ou via Web Crypto si fourni).
 */
export async function generateKemKeyPair(): Promise<KemKeyPair> {
  const kem = await loadKem();
  const { publicKey, secretKey } = kem.keygen();
  return { publicKey, secretKey };
}
