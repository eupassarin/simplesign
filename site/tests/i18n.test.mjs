// Every string the pages and scripts use must exist in both languages.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { CHOICES } from '../assets/js/snippets.js';

const site = new URL('../', import.meta.url);
const load = async (lang) => JSON.parse(await readFile(new URL(`i18n/${lang}.json`, site), 'utf8'));
const en = await load('en');
const pt = await load('pt-BR');

async function usedKeys() {
  const keys = new Set();
  for (const file of (await readdir(site)).filter((f) => f.endsWith('.html'))) {
    const html = await readFile(new URL(file, site), 'utf8');
    for (const [, key] of html.matchAll(/data-i18n(?:-html)?="([^"]+)"/g)) keys.add(key);
    for (const [, key] of html.matchAll(/data-explain="([^"]+)"/g)) keys.add(key);
    for (const [, pairs] of html.matchAll(/data-i18n-attr="([^"]+)"/g)) {
      for (const pair of pairs.split(';')) keys.add(pair.split(':')[1].trim());
    }
    for (const [, key] of html.matchAll(/name="ss-title" content="([^"]+)"/g)) keys.add(key);
  }
  for (const dir of ['assets/js/', 'assets/js/inspector/']) {
    for (const file of (await readdir(new URL(dir, site))).filter((f) => f.endsWith('.js'))) {
      const js = await readFile(new URL(dir + file, site), 'utf8');
      for (const [, key] of js.matchAll(/['`]((?:common|nav|home|learn|build|inspect)\.[A-Za-z0-9.#-]+)['`]/g)) keys.add(key);
    }
  }
  // Keys built at run time.
  for (const k of CHOICES.key) keys.add(`build.keyhint.${k}`).add(`build.guide.${k}`);
  for (const l of CHOICES.level) keys.add(`build.levelhint.${l}`).add(`learn.c4.e.${l}`);
  for (const s of ['ok', 'tampered', 'unknown', 'offline', 'revoked']) keys.add(`learn.c5.x.${s}`);
  for (const l of ['B-B', 'B-T', 'B-LT', 'B-LTA', 'DocTimeStamp', 'PKCS#7', 'CMS']) keys.add(`inspect.level.${l}`);
  for (const r of ['sha3', 'digest', 'algorithm', 'curve', 'noSignedAttrs', 'webcrypto']) keys.add(`inspect.unsupported.${r}`);
  return keys;
}

test('both languages have the same keys', () => {
  assert.deepEqual(Object.keys(pt).sort(), Object.keys(en).sort());
});

test('every key used by the site exists', async () => {
  const missing = [...await usedKeys()].filter((k) => !(k in en));
  assert.deepEqual(missing, []);
});

test('placeholders match between languages', () => {
  for (const key of Object.keys(en)) {
    const vars = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    assert.deepEqual(vars(pt[key]), vars(en[key]), key);
  }
});
