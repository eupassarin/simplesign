// Builds the GitHub Pages artifact: the site at the root and the docfx output under /docs/.
// Every page docfx used to publish at the root gets a small redirect to its new /docs/ address,
// so links already on NuGet, in issues and in search engines keep working.
// Usage (after `dotnet docfx docs/docfx.json`): node site/tools/assemble-pages.mjs [outDir]
import { cp, mkdir, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const out = process.argv[2] ?? join(root, '_pages');
const siteDir = join(root, 'site');
const docsDir = join(root, 'docs', '_site');
const SITE_EXCLUDE = new Set(['tools', 'tests', 'package.json']);

async function walk(dir) {
  const files = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else files.push(path);
  }
  return files;
}

function redirectPage(target) {
  const escaped = target.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=${escaped}">
<link rel="canonical" href="${escaped}">
<meta name="robots" content="noindex">
<title>Moved</title>
</head>
<body><p>This page moved to <a href="${escaped}">${escaped}</a>.</p></body>
</html>
`;
}

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

for (const entry of await readdir(siteDir)) {
  if (!SITE_EXCLUDE.has(entry)) await cp(join(siteDir, entry), join(out, entry), { recursive: true });
}

await stat(docsDir).catch(() => { throw new Error('docs/_site not found: run `dotnet docfx docs/docfx.json` first.'); });
await cp(docsDir, join(out, 'docs'), { recursive: true });

let redirects = 0;
for (const file of await walk(docsDir)) {
  const rel = relative(docsDir, file).split(sep).join('/');
  if (!rel.endsWith('.html') || rel === 'index.html') continue;
  const stub = join(out, rel);
  const exists = await stat(stub).then(() => true, () => false);
  if (exists) continue; // never overwrite a site page
  const depth = rel.split('/').length - 1;
  await mkdir(dirname(stub), { recursive: true });
  await writeFile(stub, redirectPage(`${'../'.repeat(depth)}docs/${rel}`));
  redirects++;
}

await writeFile(join(out, '.nojekyll'), '');
console.log(`Pages artifact in ${out}: site + docs, ${redirects} redirects.`);
