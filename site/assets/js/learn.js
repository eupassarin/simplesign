// Interactions of the Learn page: live hash + real ECDSA signature, clickable diagrams,
// the PAdES level stepper and the validation scenarios.
import { ready, t, highlight } from './site.js';

const subtle = globalThis.crypto.subtle;
const hex = (buffer) => [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');

// ── Chapter 1: hash and signature ──────────────────────────────────

let keyPair = null;
let signed = null; // { text, signature }
let baseline = null;

function renderHash(current) {
  const out = document.getElementById('hash-out');
  out.replaceChildren();
  for (let i = 0; i < current.length; i++) {
    const span = document.createElement('span');
    span.textContent = current[i];
    if (baseline && baseline[i] !== current[i]) span.className = 'diff';
    out.append(span);
  }
}

async function updateHash() {
  const text = document.getElementById('hash-input').value;
  const digest = hex(await subtle.digest('SHA-256', new TextEncoder().encode(text)));
  baseline ??= digest;
  renderHash(digest);
  await updateVerdict(text);
}

async function updateVerdict(text) {
  const out = document.getElementById('verify-out');
  out.replaceChildren();
  if (!signed) return;
  const valid = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.publicKey, signed.signature, new TextEncoder().encode(text));
  const badge = document.createElement('span');
  badge.className = `verdict ${valid ? 'ok' : 'bad'}`;
  badge.textContent = valid ? `✓ ${t('learn.c1.valid')}` : `✗ ${t('learn.c1.invalid')}`;
  out.append(badge);
}

async function sign() {
  keyPair ??= await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const text = document.getElementById('hash-input').value;
  const data = new TextEncoder().encode(text);
  signed = { text, signature: await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, data) };
  baseline = hex(await subtle.digest('SHA-256', data));
  await updateHash();
}

// ── Chapters 2 and 3: clickable diagrams ───────────────────────────

function initHotspots(figureId, explainId) {
  const explain = document.getElementById(explainId);
  const hots = document.querySelectorAll(`#${figureId} .hot`);
  const select = (hot) => {
    for (const other of hots) other.classList.toggle('on', other === hot);
    explain.dataset.i18n = hot.dataset.explain;
    explain.textContent = t(hot.dataset.explain);
  };
  for (const hot of hots) {
    hot.setAttribute('role', 'button');
    hot.addEventListener('click', () => select(hot));
    hot.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(hot); }
    });
  }
}

// ── Chapter 4: levels ──────────────────────────────────────────────

const ORDER = ['bb', 'bt', 'blt', 'blta'];
const LEVEL_CODE = {
  bb: 'var level = AdesBaselineProfile.Basic();   // default',
  bt: 'var level = AdesBaselineProfile.Timestamped(TimestampOptions.DigiCert);',
  blt: 'var level = AdesBaselineProfile.LongTerm(TimestampOptions.DigiCert, new LongTermValidationOptions());',
  blta: 'var level = AdesBaselineProfile.Archive(TimestampOptions.DigiCert, new LongTermValidationOptions());',
};
let currentLevel = 'bb';

function showLevel(level) {
  currentLevel = level;
  const upTo = ORDER.indexOf(level);
  for (const layer of document.querySelectorAll('#levels .layer')) {
    layer.classList.toggle('off', ORDER.indexOf(layer.dataset.from) > upTo);
  }
  for (const button of document.querySelectorAll('[data-level]')) {
    button.setAttribute('aria-pressed', String(button.dataset.level === level));
  }
  document.getElementById('levels-explain').textContent = t(`learn.c4.e.${level}`);
  document.getElementById('levels-code').innerHTML = highlight(
    `${LEVEL_CODE[level]}\n\nbyte[] signed = await PadesSigner.Document(pdf)\n    .WithCertificateFile("me.pfx", password)\n    .WithLevel(level)\n    .SignAsync();`,
    'csharp');
}

// ── Chapter 5: validation scenarios ────────────────────────────────

const SCENARIOS = {
  ok: 'ok', tampered: 'bad', unknown: 'warn', offline: 'warn', revoked: 'bad',
};

function showScenario() {
  const value = document.getElementById('scenario').value;
  const verdict = document.getElementById('scenario-verdict');
  verdict.className = `verdict ${SCENARIOS[value]}`;
  verdict.textContent = { ok: '✓ Valid', bad: '✗ Invalid', warn: '? Indeterminate' }[SCENARIOS[value]];
  document.getElementById('scenario-explain').textContent = t(`learn.c5.x.${value}`);
}

// ── Table of contents ──────────────────────────────────────────────

function initToc() {
  const links = new Map([...document.querySelectorAll('.toc a')].map((a) => [a.hash.slice(1), a]));
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        for (const a of links.values()) a.classList.remove('active');
        links.get(entry.target.id)?.classList.add('active');
      }
    }
  }, { rootMargin: '-30% 0px -60% 0px' });
  for (const id of links.keys()) {
    const section = document.getElementById(id);
    if (section) observer.observe(section);
  }
}

await ready;

document.getElementById('hash-input').addEventListener('input', updateHash);
document.getElementById('sign-btn').addEventListener('click', sign);
await updateHash();

document.querySelector('#pdf .figure svg').id = 'pdf-figure';
document.querySelector('#cms .figure svg').id = 'cms-figure';
initHotspots('pdf-figure', 'pdf-explain');
initHotspots('cms-figure', 'cms-explain');

for (const button of document.querySelectorAll('[data-level]')) {
  button.addEventListener('click', () => showLevel(button.dataset.level));
}
showLevel('bb');

document.getElementById('scenario').addEventListener('change', showScenario);
showScenario();
initToc();

document.addEventListener('ss:lang', () => {
  showLevel(currentLevel);
  showScenario();
  updateVerdict(document.getElementById('hash-input').value);
});
