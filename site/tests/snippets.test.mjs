// Code builder model: choice normalization and snippet rendering.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalize, DEFAULTS, allCombinations, renderCli, renderCSharp } from '../assets/js/snippets.js';

test('builder: partial or invalid URL choices fall back to defaults', () => {
  assert.deepEqual(normalize({ key: 'pkcs11', format: undefined, level: null }), { ...DEFAULTS, key: 'pkcs11' });
  assert.deepEqual(normalize({ level: 'b-xyz', format: 'pdf' }), DEFAULTS);
  assert.equal(normalize({ format: 'cades', key: 'deferred' }).key, 'pfx');
  assert.equal(normalize({ format: 'xades', stamp: true }).stamp, false);
});

test('builder: every combination renders C# and a CLI command or note', () => {
  for (const o of allCombinations()) {
    assert.match(renderCSharp(o), /SignAsync\(\)|CompleteAsync\(/);
    const cli = renderCli(o);
    assert.ok(cli.command || cli.note, JSON.stringify(o));
    // A bash line continuation must be the last character of the line.
    for (const line of (cli.command ?? '').split('\n')) assert.ok(!/\\\s+\S/.test(line), line);
  }
});
