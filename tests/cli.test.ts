/**
 * Test E2E du CLI : keygen → encrypt → decrypt → round-trip + inspect.
 * Lance le binaire compilé (dist/cli.js). Nécessite `npm run build` au préalable
 * (le CI build avant de tester) ; sinon la suite est ignorée.
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

describe.skipIf(!hasBuild)('cli — round-trip keygen/encrypt/decrypt', () => {
  it('chiffre puis déchiffre un fichier à l\'identique', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-cli-'));
    const message = 'Message de test — accents éàèùç + binaire\x00\x01\x02';
    writeFileSync(join(dir, 'in.txt'), message);

    run(['keygen', '-o', 'k'], dir);
    expect(existsSync(join(dir, 'k.pub'))).toBe(true);
    expect(existsSync(join(dir, 'k.key'))).toBe(true);

    run(['encrypt', 'in.txt', '-p', 'k.pub', '-o', 'in.sdoc'], dir);
    expect(existsSync(join(dir, 'in.sdoc'))).toBe(true);

    run(['decrypt', 'in.sdoc', '-k', 'k.key', '-o', 'out.txt'], dir);
    expect(readFileSync(join(dir, 'out.txt'), 'utf8')).toBe(message);
  }, 60_000);

  it('inspect affiche la version 1.2 sans déchiffrer', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-cli-'));
    writeFileSync(join(dir, 'in.txt'), 'x');
    run(['keygen', '-o', 'k'], dir);
    run(['encrypt', 'in.txt', '-p', 'k.pub', '-o', 'in.sdoc'], dir);
    const out = run(['inspect', 'in.sdoc'], dir);
    expect(out).toMatch(/Version\s+: 1\.2/);
    expect(out).toMatch(/Mode\s+: 1/);
  }, 60_000);

  it('decrypt échoue proprement avec une mauvaise clé', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sdoc-cli-'));
    writeFileSync(join(dir, 'in.txt'), 'secret');
    run(['keygen', '-o', 'good'], dir);
    run(['keygen', '-o', 'bad'], dir);
    run(['encrypt', 'in.txt', '-p', 'good.pub', '-o', 'in.sdoc'], dir);
    expect(() => run(['decrypt', 'in.sdoc', '-k', 'bad.key', '-o', 'out.txt'], dir)).toThrow();
  }, 60_000);
});
