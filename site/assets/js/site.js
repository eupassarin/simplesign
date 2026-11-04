// Shared behavior: language (PT-BR / EN), theme, copy buttons and a tiny syntax highlighter.
// Strings live in /i18n/<lang>.json and are applied to elements with data-i18n attributes.

const LANGS = ['pt-BR', 'en'];
let strings = {};
let lang = 'en';

function pickLanguage() {
  const saved = localStorage.getItem('ss-lang');
  if (LANGS.includes(saved)) return saved;
  return (navigator.language || 'en').toLowerCase().startsWith('pt') ? 'pt-BR' : 'en';
}

/** Returns the translation for a key, replacing {name} placeholders. */
export function t(key, vars = {}) {
  const value = strings[key] ?? key;
  return value.replace(/\{(\w+)\}/g, (_, name) => (name in vars ? String(vars[name]) : `{${name}}`));
}

export function currentLanguage() { return lang; }

function apply(root = document) {
  for (const el of root.querySelectorAll('[data-i18n]')) el.textContent = t(el.dataset.i18n);
  // Only our own JSON is rendered as HTML (for <code>/<strong> inside sentences); never page input.
  for (const el of root.querySelectorAll('[data-i18n-html]')) el.innerHTML = t(el.dataset.i18nHtml);
  for (const el of root.querySelectorAll('[data-i18n-attr]')) {
    for (const pair of el.dataset.i18nAttr.split(';')) {
      const [attr, key] = pair.split(':');
      el.setAttribute(attr.trim(), t(key.trim()));
    }
  }
  document.documentElement.lang = lang;
  const title = document.querySelector('meta[name="ss-title"]')?.content;
  if (title) document.title = `${t(title)} · SimpleSign`;
  const toggle = document.getElementById('lang-toggle');
  if (toggle) toggle.textContent = lang === 'pt-BR' ? 'EN' : 'PT';
}

async function load(next) {
  const response = await fetch(new URL(`../../i18n/${next}.json`, import.meta.url));
  strings = await response.json();
  lang = next;
  apply();
  document.dispatchEvent(new CustomEvent('ss:lang', { detail: lang }));
}

function initTheme() {
  const saved = localStorage.getItem('ss-theme');
  if (saved === 'dark' || saved === 'light') document.documentElement.dataset.theme = saved;
  const button = document.getElementById('theme-toggle');
  if (!button) return;
  const isDark = () => document.documentElement.dataset.theme === 'dark'
    || (!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: dark)').matches);
  const label = () => { button.textContent = isDark() ? '☀︎' : '☾'; };
  label();
  button.addEventListener('click', () => {
    const next = isDark() ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('ss-theme', next);
    label();
  });
}

function initCopy() {
  document.addEventListener('click', async (event) => {
    const button = event.target.closest('.copy');
    if (!button) return;
    const pre = button.closest('.code')?.querySelector('pre');
    if (!pre) return;
    await navigator.clipboard.writeText(pre.textContent);
    button.textContent = t('common.copied');
    setTimeout(() => { button.textContent = t('common.copy'); }, 1500);
  });
}

function initNav() {
  const page = document.body.dataset.page;
  for (const a of document.querySelectorAll('.nav a')) {
    if (a.dataset.page === page) a.setAttribute('aria-current', 'page');
  }
}

const KEYWORDS = new Set(('using var await new async return if else foreach in public static class string byte int bool null true false '
  + 'try catch finally throw void').split(' '));

/** Escapes text and wraps C# / shell tokens in spans. Input is our own snippets, escaped first. */
export function highlight(code, language) {
  const escape = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  if (language === 'bash') {
    return code.split('\n').map((line) => line.trimStart().startsWith('#')
      ? `<span class="tok-c">${escape(line)}</span>`
      : escape(line).replace(/(--[\w-]+)/g, '<span class="tok-t">$1</span>')).join('\n');
  }

  const pattern = /(\/\/[^\n]*)|("(?:[^"\\]|\\.)*")|(\b\d+\b)|(\b[A-Za-z_][\w]*\b)|([^A-Za-z_"\/\d]+|\/)/g;
  let out = '';
  for (const [, comment, str, num, word, other] of code.matchAll(pattern)) {
    if (comment) out += `<span class="tok-c">${escape(comment)}</span>`;
    else if (str) out += `<span class="tok-s">${escape(str)}</span>`;
    else if (num) out += `<span class="tok-n">${num}</span>`;
    else if (word) out += KEYWORDS.has(word) ? `<span class="tok-k">${word}</span>`
      : /^[A-Z]/.test(word) ? `<span class="tok-t">${word}</span>` : word;
    else out += escape(other);
  }
  return out;
}

function initStaticCode() {
  for (const pre of document.querySelectorAll('pre[data-lang]')) {
    pre.innerHTML = highlight(pre.textContent, pre.dataset.lang);
  }
}

export const ready = (async () => {
  initTheme();
  initCopy();
  initNav();
  initStaticCode();
  await load(pickLanguage());
  document.getElementById('lang-toggle')?.addEventListener('click', async () => {
    const next = lang === 'pt-BR' ? 'en' : 'pt-BR';
    localStorage.setItem('ss-lang', next);
    await load(next);
  });
})();
