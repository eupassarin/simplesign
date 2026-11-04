// Code builder page: keeps the choices in the URL (shareable) and renders C#, CLI and install lines.
import { ready, t, highlight } from './site.js';
import { DEFAULTS, normalize, isValid, renderCSharp, renderCli, packages } from './snippets.js';

const form = document.getElementById('choices');
const GUIDES = {
  pfx: 'docs/articles/getting-started.html',
  store: 'docs/articles/getting-started.html',
  pkcs11: 'docs/articles/pkcs11.html',
  psc: 'docs/articles/cloud-signing.html',
  csc: 'docs/articles/cloud-signing.html',
  deferred: 'docs/articles/deferred-signing.html',
};

function readUrl() {
  const p = new URLSearchParams(location.search);
  return normalize({
    format: p.get('format') ?? undefined,
    key: p.get('key') ?? undefined,
    level: p.get('level') ?? undefined,
    stamp: p.has('stamp') ? p.get('stamp') === '1' : undefined,
    validate: p.get('validate') ?? undefined,
  });
}

function readForm() {
  const data = new FormData(form);
  return normalize({
    format: data.get('format'),
    key: data.get('key'),
    level: data.get('level'),
    stamp: data.get('stamp') === 'on',
    validate: data.get('validate'),
  });
}

function writeForm(o) {
  for (const input of form.querySelectorAll('input')) {
    if (input.type === 'checkbox') input.checked = !!o[input.name];
    else input.checked = String(o[input.name]) === input.value;
  }
  for (const input of form.querySelectorAll('input[name="key"]')) {
    input.disabled = !isValid({ ...o, key: input.value, stamp: false });
  }
  form.querySelector('input[name="stamp"]').disabled = !isValid({ ...o, stamp: true });
}

function render() {
  const o = readForm();
  writeForm(o);
  history.replaceState(null, '', `?${new URLSearchParams({ ...o, stamp: o.stamp ? '1' : '0' })}`);

  document.getElementById('out-cs').innerHTML = highlight(renderCSharp(o), 'csharp');
  const cli = renderCli(o);
  document.getElementById('out-cli').innerHTML = cli.command
    ? highlight(cli.command, 'bash')
    : highlight(`# ${t(cli.note)}`, 'bash');
  document.getElementById('out-install').innerHTML = highlight(
    packages(o).map((p) => `dotnet add package ${p}`).join('\n'), 'bash');

  document.getElementById('key-hint').textContent = t(`build.keyhint.${o.key}`);
  document.getElementById('level-hint').textContent = t(`build.levelhint.${o.level}`);
  const guide = document.getElementById('guide');
  guide.replaceChildren(document.createTextNode(`${t('build.guide')} `));
  const link = document.createElement('a');
  link.href = GUIDES[o.key];
  link.textContent = t(`build.guide.${o.key}`);
  guide.append(link);
}

function initTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  for (const tab of tabs) {
    tab.addEventListener('click', () => {
      for (const other of tabs) {
        const selected = other === tab;
        other.setAttribute('aria-selected', String(selected));
        document.getElementById(other.getAttribute('aria-controls')).hidden = !selected;
      }
    });
  }
}

await ready;
writeForm({ ...DEFAULTS, ...readUrl() });
initTabs();
form.addEventListener('change', render);
document.addEventListener('ss:lang', render);
render();
