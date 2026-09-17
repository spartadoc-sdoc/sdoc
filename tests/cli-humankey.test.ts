/**
 * Test E2E du CLI par CLÉ HUMAINE (`--human`, `--human-key`, `--json`).
 *
 * Ce que ces tests protègent, et qui n'est pas évident : la clé humaine est le
 * SEUL point de contact entre un outil en ligne de commande et une personne qui
 * n'en utilisera jamais. Elle est recopiée à la main, dictée au téléphone,
 * collée depuis un message. Tout ce qui suit décrit une façon dont ce transport
 * pourrait échouer en silence.
 *
 * Lance le binaire compilé (dist/cli.js) ; la suite est ignorée sans build.
 */

import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const hasBuild = existsSync(CLI);

function run(args: string[], cwd: string): string {
  return execFileSync('node', [CLI, ...args], { cwd, encoding: 'utf8' });
}

/** Exécute en tolérant un code de sortie non nul, et rend stdout. */
function runFailing(args: string[], cwd: string): string {
  try {
    return execFileSync('node', [CLI, ...args], { cwd, encoding: 'utf8' });
  } catch (e) {
    return (e as { stdout?: string }).stdout ?? '';
  }
}

function json(out: string): Record<string, unknown> {
  return JSON.parse(out.trim().split('\n').pop()!);
}

describe.skipIf(!hasBuild)('cli — clé humaine', () => {
  it('chiffre avec --human, remet la clé, et rouvre à l\'identique', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-hk-'));
    const message = 'Entente de confidentialité — 12 345,67 $. Àéèêçù.\x00\x01\xff';
    writeFileSync(join(dir, 'in.txt'), message);

    const chiffre = json(run(['encrypt', 'in.txt', '--human', '--json', '-o', 'in.sdoc'], dir));
    expect(chiffre.ok).toBe(true);
    // Mode 2 IMPOSÉ : une clé humaine est une clé au porteur.
    expect(chiffre.mode).toBe(2);
    expect(String(chiffre.key)).toMatch(/^SDOC-[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);

    const ouvert = json(run(['decrypt', 'in.sdoc', '--human-key', String(chiffre.key), '--json', '-o', 'out.txt'], dir));
    expect(ouvert.ok).toBe(true);
    expect(readFileSync(join(dir, 'out.txt'), 'utf8')).toBe(message);
  }, 60_000);

  it('accepte une clé recopiée salement — minuscules, espaces, sans préfixe', () => {
    // Le cas réel : quelqu'un dicte sa clé au téléphone, l'autre la retape.
    // Si le CLI exigeait la forme exacte, il échouerait sur une clé JUSTE.
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-hk-'));
    writeFileSync(join(dir, 'in.txt'), 'secret');

    const { key } = json(run(['encrypt', 'in.txt', '--human', '--json', '-o', 'in.sdoc'], dir)) as { key: string };

    const sale = key.toLowerCase().replace(/-/g, ' ');
    expect(json(run(['decrypt', 'in.sdoc', '--human-key', sale, '--json', '-o', 'a.txt'], dir)).ok).toBe(true);
    expect(readFileSync(join(dir, 'a.txt'), 'utf8')).toBe('secret');

    const sansPrefixe = key.slice('SDOC-'.length).replace(/-/g, '');
    expect(json(run(['decrypt', 'in.sdoc', '--human-key', sansPrefixe, '--json', '-o', 'b.txt'], dir)).ok).toBe(true);
  }, 60_000);

  it('`sdoc key` frappe une clé sans rien écrire sur le disque', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-hk-'));
    const r = json(run(['key', '--json'], dir));
    expect(r.ok).toBe(true);
    expect(String(r.key)).toMatch(/^SDOC-/);

    // Cette clé doit être utilisable telle quelle pour chiffrer.
    writeFileSync(join(dir, 'in.txt'), 'x');
    run(['encrypt', 'in.txt', '--human-key', String(r.key), '-o', 'in.sdoc'], dir);
    expect(json(run(['decrypt', 'in.sdoc', '--human-key', String(r.key), '--json', '-o', 'out.txt'], dir)).ok).toBe(true);
  }, 60_000);

  it('distingue « clé mal formée » de « mauvaise clé »', () => {
    // Deux gestes différents pour la personne : recopier mieux, ou aller
    // chercher la bonne clé. Un message unique les enverrait au mauvais endroit.
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-hk-'));
    writeFileSync(join(dir, 'in.txt'), 'secret');
    run(['encrypt', 'in.txt', '--human', '-o', 'in.sdoc'], dir);

    const malFormee = json(runFailing(['decrypt', 'in.sdoc', '--human-key', 'pas-une-cle', '--json', '-o', 'x'], dir));
    expect(malFormee.ok).toBe(false);
    expect(String(malFormee.error)).toMatch(/mal formée/);

    const fausse = json(runFailing(
      ['decrypt', 'in.sdoc', '--human-key', 'SDOC-0000-0000-0000-0000-0000-0000-0000-0000', '--json', '-o', 'x'],
      dir,
    ));
    expect(fausse.ok).toBe(false);
    expect(String(fausse.error)).toMatch(/déchiffrement/);
    expect(String(fausse.error)).not.toMatch(/mal formée/);
  }, 60_000);

  it('refuse une clé humaine sur un .sdoc de mode 1, en expliquant pourquoi', () => {
    // Sans ce contrôle, l'échec ressemblerait à une clé mal recopiée et on
    // chercherait le problème au mauvais endroit.
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-hk-'));
    writeFileSync(join(dir, 'in.txt'), 'x');
    run(['keygen', '-o', 'svc'], dir);
    run(['encrypt', 'in.txt', '-p', 'svc.pub', '-m', '1', '-o', 'm1.sdoc'], dir);

    const r = json(runFailing(['decrypt', 'm1.sdoc', '--human-key', 'SDOC-0000-0000-0000-0000-0000-0000-0000-0000', '--json', '-o', 'x'], dir));
    expect(r.ok).toBe(false);
    expect(String(r.error)).toMatch(/mode 1/);
  }, 60_000);

  it('rejette les combinaisons d\'options contradictoires', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-hk-'));
    writeFileSync(join(dir, 'in.txt'), 'x');

    const deuxCles = json(runFailing(
      ['encrypt', 'in.txt', '--human', '--human-key', 'SDOC-0000-0000-0000-0000-0000-0000-0000-0000', '--json'],
      dir,
    ));
    expect(deuxCles.ok).toBe(false);

    // Une clé humaine avec --mode 1 produirait un fichier dont l'en-tête ment
    // sur la façon de l'ouvrir.
    const modeIncompatible = json(runFailing(['encrypt', 'in.txt', '--human', '-m', '1', '--json'], dir));
    expect(modeIncompatible.ok).toBe(false);
    expect(String(modeIncompatible.error)).toMatch(/mode 2/);

    const sansRien = json(runFailing(['encrypt', 'in.txt', '--json'], dir));
    expect(sansRien.ok).toBe(false);
  }, 60_000);

  it('en mode --json, stdout ne contient QUE du JSON, même en erreur', () => {
    // Un agent qui parse stdout ne doit jamais tomber sur de la prose.
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-hk-'));
    writeFileSync(join(dir, 'in.txt'), 'x');

    const ok = run(['encrypt', 'in.txt', '--human', '--json', '-o', 'in.sdoc'], dir);
    expect(() => JSON.parse(ok.trim())).not.toThrow();

    const ko = runFailing(['decrypt', 'in.sdoc', '--human-key', 'zzz', '--json', '-o', 'x'], dir);
    expect(() => JSON.parse(ko.trim())).not.toThrow();
  }, 60_000);
});
