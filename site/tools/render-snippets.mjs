// Writes every code-builder combination as a C# file into
// tests/site/SimpleSign.Site.SnippetTests/Generated/, wrapped in a method so they all compile together.
// Usage: node site/tools/render-snippets.mjs && dotnet build tests/site/SimpleSign.Site.SnippetTests
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { allCombinations, buildCSharp } from '../assets/js/snippets.js';

const out = new URL('../../tests/site/SimpleSign.Site.SnippetTests/Generated/', import.meta.url);
await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

const indent = (lines) => lines.map((l) => (l ? `        ${l}` : l));
for (const o of allCombinations()) {
  const name = `Snippet_${o.format}_${o.key}_${o.level}_${o.stamp ? 'stamp' : 'nostamp'}_${o.validate}`;
  const { usings, setup, body, helpers } = buildCSharp(o);
  const file = [
    `// Generated from site/assets/js/snippets.js: ${JSON.stringify(o)}`,
    ...usings.map((u) => `using ${u};`),
    '',
    'namespace SimpleSign.Site.SnippetTests.Generated;',
    '',
    `internal static class ${name}`,
    '{',
    '    public static async Task RunAsync()',
    '    {',
    ...indent([...setup, ...body, ...helpers]),
    '    }',
    '}',
    '',
  ].join('\n');
  await writeFile(new URL(`${name}.cs`, out), file);
}
console.log(`Wrote ${allCombinations().length} snippets to ${out.pathname}`);
