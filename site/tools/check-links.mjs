// Checks that every local link in the site points to a file (or an element id) that exists.
// Links into docs/ are checked against the docfx sources (docs/**/*.md), since the HTML is built later.
// Usage: node site/tools/check-links.mjs
import { readFile, readdir, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const site = fileURLToPath(new URL('../', import.meta.url));
const repo = join(site, '..');
const exists = (path) => stat(path).then(() => true, () => false);
const problems = [];

const pages = (await readdir(site)).filter((f) => f.endsWith('.html'));
const ids = new Map();
for (const page of pages) {
  const html = await readFile(join(site, page), 'utf8');
  ids.set(page, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
}

async function check(from, link) {
  if (/^(https?:|mailto:|data:)/.test(link) || link.startsWith('#') && link.length === 1) return;
  const [pathAndQuery, hash] = link.split('#');
  const path = pathAndQuery.split('?')[0];
  if (path.startsWith('docs/')) {
    const source = path === 'docs/' ? 'docs/index.md' : path.replace(/\.html$/, '.md');
    if (!await exists(join(repo, source))) problems.push(`${from}: ${link} (no ${source})`);
    return;
  }
  const target = path === '' ? from : path;
  if (!await exists(join(site, target))) {
    problems.push(`${from}: ${link} (missing file)`);
  } else if (hash && ids.has(target) && !ids.get(target).has(hash)) {
    problems.push(`${from}: ${link} (no element #${hash})`);
  }
}

for (const page of pages) {
  const html = await readFile(join(site, page), 'utf8');
  for (const [, link] of html.matchAll(/\s(?:href|src)="([^"]+)"/g)) await check(page, link);
}

// Links built in scripts and translations.
const builder = await readFile(join(site, 'assets/js/builder.js'), 'utf8');
for (const [, link] of builder.matchAll(/'(docs\/[^']+)'/g)) await check('assets/js/builder.js', link);
const inspect = await readFile(join(site, 'assets/js/inspect.js'), 'utf8');
for (const [, link] of inspect.matchAll(/`learn\.html#\$\{[^}]+'([a-z]+)'\s*:\s*'([a-z]+)'/g)) {
  await check('assets/js/inspect.js', `learn.html#${link}`);
}
for (const lang of ['en', 'pt-BR']) {
  const strings = JSON.parse(await readFile(join(site, 'i18n', `${lang}.json`), 'utf8'));
  for (const [key, value] of Object.entries(strings)) {
    for (const [, link] of value.matchAll(/href="([^"]+)"/g)) await check(`i18n/${lang}.json ${key}`, link);
  }
}
for (const sample of ['signed-rsa.pdf', 'signed-timestamped.pdf', 'signed-ecdsa.pdf', 'signed-pss.pdf', 'tampered.pdf']) {
  await check('inspect.html samples', `samples/${sample}`);
}

if (problems.length) {
  console.error(`Broken links:\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
console.log(`Links OK (${pages.length} pages).`);
