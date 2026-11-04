// Cross-checks the browser inspector against `simplesign inspect --json` on the sample PDFs.
// Runs when SIMPLESIGN_CLI points to the CLI (e.g. src/SimpleSign.Cli/bin/Release/net8.0/simplesign.dll).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { analyze } from '../assets/js/inspector/analyze.js';

const cli = process.env.SIMPLESIGN_CLI;
const samplesDir = new URL('../samples/', import.meta.url);
const LEVELS = { BaselineB: 'B-B', BaselineT: 'B-T', BaselineLT: 'B-LT', BaselineLTA: 'B-LTA' };

const files = (await readdir(samplesDir)).filter((f) => f.endsWith('.pdf') && f !== 'tampered.pdf');

for (const name of files) {
  test(`inspector matches the CLI for ${name}`, { skip: !cli && 'SIMPLESIGN_CLI is not set' }, async () => {
    const path = fileURLToPath(new URL(name, samplesDir));
    const expected = JSON.parse(execFileSync('dotnet', [cli, 'inspect', path, '--json'], { encoding: 'utf8' }));
    const actual = await analyze(new Uint8Array(await readFile(path)));

    assert.equal(actual.signatures.length, expected.signatures.length);
    for (const [i, cliSig] of expected.signatures.entries()) {
      const sig = actual.signatures[i];
      assert.equal(sig.subFilter, cliSig.subFilter);
      assert.equal(sig.level, LEVELS[cliSig.level] ?? cliSig.level);
      assert.equal(sig.cms.hash, cliSig.digestAlgorithm.name);
      assert.equal(sig.cms.signer.subject.text, cliSig.signer.subject);
      assert.equal(sig.cms.signer.thumbprint, cliSig.signer.thumbprint);
      assert.equal(sig.cms.signer.keySize ?? null, cliSig.signer.keyAlgorithm === 'RSA' ? cliSig.signer.keySizeBits : null);
      assert.deepEqual(sig.byteRange, [cliSig.byteRange.offset1, cliSig.byteRange.length1, cliSig.byteRange.offset2, cliSig.byteRange.length2]);
      assert.equal(sig.cms.timestamps.length > 0, cliSig.timestamp != null);
    }
  });
}
