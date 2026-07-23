#!/usr/bin/env node
/**
 * sdoc — CLI de référence du format `.sdoc` (post-quantique).
 *
 * Zéro dépendance externe (uniquement le codec + Node). Manipule des fichiers
 * `.sdoc` localement : générer une paire de clés, chiffrer, déchiffrer, inspecter.
 * Aucune authentification, aucun serveur — c'est l'outil du standard, pas un
 * client produit.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { argv, exit, stderr } from 'node:process';
import { encode, decode } from './crypto.js';
import { generateKemKeyPair } from './keys.js';
import { parseHeader } from './codec.js';
import { MODE_SPARTADOC, MODE_P2P, type SdocMode } from './types.js';
import { SdocError } from './errors.js';

const VERSION = '0.1.0';

const HELP = `sdoc — codec .sdoc post-quantique (ML-KEM-768 + AES-256-GCM)

Usage :
  sdoc keygen  [-o <préfixe>]                     Génère une paire de clés ML-KEM-768
  sdoc encrypt <fichier> -p <clé.pub> [options]   Chiffre un fichier en .sdoc
  sdoc decrypt <fichier.sdoc> -k <clé.key> [-o <sortie>]
  sdoc inspect <fichier.sdoc>                     Affiche l'en-tête sans déchiffrer

Options :
  -o, --out <chemin>     Fichier/préfixe de sortie
  -p, --pub <chemin>     Fichier de clé publique (base64)
  -k, --key <chemin>     Fichier de clé secrète (base64)
  -m, --mode <1|2>       1 = lié à un service (défaut), 2 = pair-à-pair
  -h, --help             Cette aide
  -v, --version          Version

Exemple :
  sdoc keygen -o bob
  sdoc encrypt lettre.pdf -p bob.pub -o lettre.pdf.sdoc
  sdoc decrypt lettre.pdf.sdoc -k bob.key -o lettre.pdf
`;

function fail(msg: string): never {
  stderr.write(`sdoc: ${msg}\n`);
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
      default:
        if (a.startsWith('-')) fail(`option inconnue : ${a}`);
        p.positional.push(a);
    }
  }
  return p;
}

async function cmdKeygen(p: Parsed): Promise<void> {
  const prefix = p.out ?? 'sdoc-key';
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
  if (!p.pub) fail('encrypt : clé publique requise (-p <clé.pub>)');
  const mode: SdocMode = p.mode === '2' ? MODE_P2P : p.mode === '1' || p.mode === undefined ? MODE_SPARTADOC : fail(`mode invalide : ${p.mode} (1 ou 2)`);
  const plaintext = new Uint8Array(readFileSync(infile));
  const publicKey = fromB64(readFileSync(p.pub, 'utf8'));
  const blob = await encode(plaintext, publicKey, mode);
  const out = p.out ?? `${infile}.sdoc`;
  writeFileSync(out, blob);
  process.stdout.write(`Chiffré → ${out} (${blob.length} octets, mode ${mode})\n`);
}

async function cmdDecrypt(p: Parsed): Promise<void> {
  const infile = p.positional[0];
  if (!infile) fail('decrypt : fichier .sdoc manquant');
  if (!p.key) fail('decrypt : clé secrète requise (-k <clé.key>)');
  const blob = new Uint8Array(readFileSync(infile));
  const secretKey = fromB64(readFileSync(p.key, 'utf8'));
  const { plaintext, version, mode } = await decode(blob, secretKey);
  const out = p.out ?? (infile.endsWith('.sdoc') ? infile.slice(0, -5) : `${infile}.out`);
  writeFileSync(out, plaintext);
  process.stdout.write(`Déchiffré → ${out} (v1.${version === 1 ? '0' : '2'}, mode ${mode ?? 'implicite'})\n`);
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
