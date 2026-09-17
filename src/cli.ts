#!/usr/bin/env node
/**
 * sdoc — CLI de référence du format `.sdoc` (post-quantique).
 *
 * Zéro dépendance externe (uniquement le codec + Node). Manipule des fichiers
 * `.sdoc` localement : générer une paire de clés, chiffrer, déchiffrer, inspecter.
 * Aucune authentification, aucun serveur — c'est l'outil du standard, pas un
 * client produit.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { argv, exit, stderr } from 'node:process';
import { encode, decode } from './crypto.js';
import { generateKemKeyPair } from './keys.js';
import { parseHeader } from './codec.js';
import { MODE_SPARTADOC, MODE_P2P, type SdocMode } from './types.js';
import { SdocError } from './errors.js';
import { generateHumanKey, deriveKeyPairFromHumanKey } from './humankey.js';

const VERSION = '0.1.0';

const HELP = `sdoc — codec .sdoc post-quantique (ML-KEM-768 + AES-256-GCM)

Deux façons de détenir une clé :

  A. PAIRE DE FICHIERS (.pub / .key) — pour un destinataire durable.
  B. CLÉ HUMAINE (SDOC-XXXX-…) — 32 caractères, transportables de vive voix,
     par message ou dans un presse-papiers. La paire en est redérivée.

Usage :
  sdoc key     [--json]                           Génère une clé humaine
  sdoc keygen  [-o <préfixe>]                     Génère une paire de fichiers
  sdoc encrypt <fichier> --human                  Chiffre + génère la clé humaine
  sdoc encrypt <fichier> --human-key <clé>        Chiffre pour une clé humaine
  sdoc encrypt <fichier> -p <clé.pub> [options]   Chiffre pour une clé publique
  sdoc decrypt <fichier.sdoc> --human-key <clé>   Déchiffre avec une clé humaine
  sdoc decrypt <fichier.sdoc> -k <clé.key>        Déchiffre avec un fichier
  sdoc inspect <fichier.sdoc>                     Affiche l'en-tête sans déchiffrer

Options :
  -o, --out <chemin>     Fichier/préfixe de sortie
  -p, --pub <chemin>     Fichier de clé publique (base64)
  -k, --key <chemin>     Fichier de clé secrète (base64)
      --human            Génère une clé humaine et chiffre pour elle
      --human-key <clé>  Clé humaine SDOC-XXXX-… (casse et tirets indifférents)
  -m, --mode <1|2>       1 = lié à un service (défaut), 2 = pair-à-pair
  -f, --force            Écraser les fichiers de sortie existants
      --json             Sortie JSON sur stdout (agents, scripts)
  -h, --help             Cette aide
  -v, --version          Version

Exemples :
  sdoc encrypt contrat.pdf --human --json
  sdoc decrypt contrat.pdf.sdoc --human-key SDOC-K7M2-9QX4-... --json

  sdoc keygen -o bob
  sdoc encrypt lettre.pdf -p bob.pub -o lettre.pdf.sdoc
  sdoc decrypt lettre.pdf.sdoc -k bob.key -o lettre.pdf

Une clé humaine perdue est un fichier perdu : rien ni personne ne peut la
réémettre. C'est la contrepartie de l'absence de serveur.
`;

/**
 * Mode JSON — pour les agents et les scripts. Quand il est actif, TOUT ce qui
 * sort sur stdout est un objet JSON unique, et les erreurs aussi. Un appelant
 * automatisé ne doit jamais avoir à interpréter de la prose.
 */
let jsonMode = false;

function emit(human: string, data: Record<string, unknown>): void {
  process.stdout.write(jsonMode ? JSON.stringify(data) + '\n' : human);
}

function fail(msg: string): never {
  if (jsonMode) {
    process.stdout.write(JSON.stringify({ ok: false, error: msg }) + '\n');
  } else {
    stderr.write(`sdoc: ${msg}\n`);
  }
  exit(1);
}

function toB64(u: Uint8Array): string {
  return Buffer.from(u).toString('base64');
}
function fromB64(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text.trim(), 'base64'));
}

interface Parsed {
  positional: string[];
  out?: string;
  pub?: string;
  key?: string;
  mode?: string;
  force?: boolean;
  human?: boolean;
  humanKey?: string;
  json?: boolean;
}

/** Refuse d'écraser un fichier existant sans --force (sécurité anti-perte). */
function guardOverwrite(path: string, force: boolean | undefined): void {
  if (!force && existsSync(path)) {
    fail(`${path} existe déjà — utilisez -f/--force pour écraser`);
  }
}

function parseArgs(args: string[]): Parsed {
  const p: Parsed = { positional: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const next = (): string => {
      const v = args[++i];
      if (v === undefined) fail(`option ${a} attend une valeur`);
      return v;
    };
    switch (a) {
      case '-o': case '--out': p.out = next(); break;
      case '-p': case '--pub': p.pub = next(); break;
      case '-k': case '--key': p.key = next(); break;
      case '-m': case '--mode': p.mode = next(); break;
      case '-f': case '--force': p.force = true; break;
      case '--human': p.human = true; break;
      case '--human-key': p.humanKey = next(); break;
      case '--json': p.json = true; jsonMode = true; break;
      default:
        if (a.startsWith('-')) fail(`option inconnue : ${a}`);
        p.positional.push(a);
    }
  }
  return p;
}

/**
 * `sdoc key` — frappe une clé humaine, sans rien écrire sur le disque.
 *
 * Utile pour préparer une clé avant de chiffrer, ou pour qu'un agent en
 * obtienne une sans effet de bord.
 */
function cmdKey(_p: Parsed): void {
  const cle = generateHumanKey();
  emit(
    `${cle}\n\nCette clé ne peut pas être réémise. Sans elle, rien ne s'ouvre.\n`,
    { ok: true, key: cle },
  );
}

async function cmdKeygen(p: Parsed): Promise<void> {
  const prefix = p.out ?? 'sdoc-key';
  // Écraser une clé secrète = perte DÉFINITIVE d'accès à tout ce qui a été
  // chiffré pour elle. Jamais silencieux.
  guardOverwrite(`${prefix}.key`, p.force);
  guardOverwrite(`${prefix}.pub`, p.force);
  const { publicKey, secretKey } = await generateKemKeyPair();
  writeFileSync(`${prefix}.pub`, toB64(publicKey) + '\n');
  writeFileSync(`${prefix}.key`, toB64(secretKey) + '\n', { mode: 0o600 });
  process.stdout.write(
    `Paire ML-KEM-768 générée :\n` +
    `  ${prefix}.pub  (clé publique — partageable)\n` +
    `  ${prefix}.key  (clé secrète — À GARDER PRIVÉE, chmod 600)\n`,
  );
}

async function cmdEncrypt(p: Parsed): Promise<void> {
  const infile = p.positional[0];
  if (!infile) fail('encrypt : fichier d\'entrée manquant');
  if (p.human && p.humanKey) fail('encrypt : --human et --human-key s\'excluent');
  if (!p.pub && !p.human && !p.humanKey) {
    fail('encrypt : fournissez -p <clé.pub>, --human, ou --human-key <clé>');
  }

  const plaintext = new Uint8Array(readFileSync(infile));
  const out = p.out ?? `${infile}.sdoc`;

  // ── Chemin clé humaine ───────────────────────────────────────────────────
  // Mode 2 (pair-à-pair) IMPOSÉ : une clé humaine est une clé au porteur, elle
  // ne désigne aucun service. Laisser choisir le mode ici produirait des
  // fichiers dont l'en-tête ment sur la façon de les ouvrir.
  if (p.human || p.humanKey) {
    if (p.mode !== undefined && p.mode !== '2') {
      fail('encrypt : une clé humaine implique le mode 2 (pair-à-pair)');
    }
    const cle = p.humanKey ?? generateHumanKey();
    const { publicKey } = await deriveKeyPairFromHumanKey(cle);
    const blob = await encode(plaintext, publicKey, MODE_P2P);
    guardOverwrite(out, p.force);
    writeFileSync(out, blob);
    emit(
      `Chiffré → ${out} (${blob.length} octets, mode 2)\n` +
      (p.humanKey ? '' : `\nClé : ${cle}\n\nCette clé ne peut pas être réémise. Sans elle, le fichier reste chiffré.\n`),
      { ok: true, output: out, bytes: blob.length, mode: 2, key: cle },
    );
    return;
  }

  // ── Chemin paire de fichiers ─────────────────────────────────────────────
  const mode: SdocMode = p.mode === '2' ? MODE_P2P : p.mode === '1' || p.mode === undefined ? MODE_SPARTADOC : fail(`mode invalide : ${p.mode} (1 ou 2)`);
  const publicKey = fromB64(readFileSync(p.pub!, 'utf8'));
  const blob = await encode(plaintext, publicKey, mode);
  guardOverwrite(out, p.force);
  writeFileSync(out, blob);
  emit(
    `Chiffré → ${out} (${blob.length} octets, mode ${mode})\n`,
    { ok: true, output: out, bytes: blob.length, mode },
  );
}

async function cmdDecrypt(p: Parsed): Promise<void> {
  const infile = p.positional[0];
  if (!infile) fail('decrypt : fichier .sdoc manquant');
  if (!p.key && !p.humanKey) {
    fail('decrypt : clé requise (-k <clé.key> ou --human-key <clé>)');
  }
  const blob = new Uint8Array(readFileSync(infile));

  // Un Mode 1 est chiffré pour le destinataire d'un service : aucune clé
  // humaine ne peut l'ouvrir. On le dit AVANT d'essayer, sinon l'échec
  // ressemblerait à une clé mal recopiée et on chercherait au mauvais endroit.
  if (p.humanKey && parseHeader(blob).mode === MODE_SPARTADOC) {
    fail('ce .sdoc est en mode 1 (lié à un service) : il s\'ouvre avec la clé secrète du destinataire, pas avec une clé humaine');
  }

  const secretKey = p.humanKey
    ? (await deriveKeyPairFromHumanKey(p.humanKey)).secretKey
    : fromB64(readFileSync(p.key!, 'utf8'));

  const { plaintext, version, mode } = await decode(blob, secretKey);
  const out = p.out ?? (infile.endsWith('.sdoc') ? infile.slice(0, -5) : `${infile}.out`);
  guardOverwrite(out, p.force);
  writeFileSync(out, plaintext);
  emit(
    `Déchiffré → ${out} (v1.${version === 1 ? '0' : '2'}, mode ${mode ?? 'implicite'})\n`,
    { ok: true, output: out, bytes: plaintext.length, version, mode },
  );
}

function cmdInspect(p: Parsed): void {
  const infile = p.positional[0];
  if (!infile) fail('inspect : fichier .sdoc manquant');
  const blob = new Uint8Array(readFileSync(infile));
  const h = parseHeader(blob);
  process.stdout.write(
    `Fichier   : ${infile} (${blob.length} octets)\n` +
    `Version   : ${h.version === 1 ? '1 (legacy, lecture seule)' : '1.2'}\n` +
    `Mode      : ${h.mode === null ? 'implicite (Mode 1)' : h.mode === MODE_SPARTADOC ? '1 (lié service)' : '2 (pair-à-pair)'}\n` +
    `Salt      : ${h.salt.length} octets\n` +
    `KEM ct    : ${h.kemCiphertext.length} octets\n` +
    `IV        : ${h.iv.length} octets\n` +
    `Auth tag  : ${h.authTag.length} octets\n` +
    `Payload   : ${h.payload.length} octets (chiffré)\n`,
  );
}

async function main(): Promise<void> {
  const [cmd, ...rest] = argv.slice(2);
  if (cmd === undefined || cmd === '-h' || cmd === '--help' || cmd === 'help') {
    process.stdout.write(HELP);
    return;
  }
  if (cmd === '-v' || cmd === '--version' || cmd === 'version') {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  const p = parseArgs(rest);
  switch (cmd) {
    case 'key': return cmdKey(p);
    case 'keygen': return cmdKeygen(p);
    case 'encrypt': return cmdEncrypt(p);
    case 'decrypt': return cmdDecrypt(p);
    case 'inspect': return cmdInspect(p);
    default: fail(`commande inconnue : ${cmd} (voir « sdoc --help »)`);
  }
}

main().catch((err: unknown) => {
  if (err instanceof SdocError) fail(err.message);
  fail(err instanceof Error ? err.message : String(err));
});
