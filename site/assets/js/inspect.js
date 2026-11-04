// Inspector page: reads a PDF locally and renders what analyze() found.
// Everything that comes from the file is inserted with textContent, never as HTML.
import { ready, t, currentLanguage } from './site.js';
import { analyze } from './inspector/analyze.js';

const result = document.getElementById('result');
let last = null;

function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) node.append(kid);
  return node;
}

const fmtDate = (d) => (d ? new Intl.DateTimeFormat(currentLanguage(), { dateStyle: 'medium', timeStyle: 'medium' }).format(d) : '—');
const fmtBytes = (n) => new Intl.NumberFormat(currentLanguage()).format(n);

function verdict(check, okKey, failKey) {
  if (!check) return null;
  const cls = check.status === 'ok' ? 'ok' : check.status === 'fail' ? 'bad' : 'warn';
  const icon = check.status === 'ok' ? '✓' : check.status === 'fail' ? '✗' : '?';
  const text = check.status === 'ok' ? t(okKey) : check.status === 'fail' ? t(failKey) : t(`inspect.unsupported.${check.reason}`);
  return el('span', { class: `verdict ${cls}`, text: `${icon} ${text}` });
}

function byteBar(sig, size) {
  const [a, b, c, d] = sig.byteRange;
  const pct = (n) => `${(n / size) * 100}%`;
  const bar = el('div', { class: 'bytebar', role: 'img', 'aria-label': t('inspect.bar.label', { signed: fmtBytes(b + d), total: fmtBytes(size) }) });
  const seg = (cls, start, length) => {
    const s = el('span', { class: `seg ${cls}` });
    s.style.left = pct(start);
    s.style.width = pct(length);
    return s;
  };
  bar.append(seg('signed', a, b), seg('contents', a + b, c - a - b), seg('signed', c, d));
  if (c + d < size) bar.append(seg('after', c + d, size - c - d));
  const legend = el('div', { class: 'legend' },
    el('span', {}, el('i', { class: 'seg signed' }), t('inspect.bar.signed')),
    el('span', {}, el('i', { class: 'seg contents' }), t('inspect.bar.contents')),
    c + d < size ? el('span', {}, el('i', { class: 'seg after' }), t('inspect.bar.after')) : null);
  return [bar, legend];
}

function kv(pairs) {
  const dl = el('dl', { class: 'kv' });
  for (const [key, val, mono] of pairs) {
    if (val == null || val === '') continue;
    dl.append(el('dt', { text: t(key) }), el('dd', { class: mono ? 'mono' : '', text: String(val) }));
  }
  return dl;
}

function levelText(level) {
  return t(`inspect.level.${level}`, { level });
}

function renderSignature(sig, index, file) {
  const card = el('article', { class: 'card sig-card' });
  const isDocTs = sig.subFilter === 'ETSI.RFC3161';
  card.append(el('h2', { text: isDocTs ? t('inspect.docts', { n: index + 1 }) : t('inspect.signature', { n: index + 1 }) }));

  if (sig.checks) {
    card.append(el('div', { class: 'checks' },
      verdict(sig.checks.integrity, 'inspect.check.integrity.ok', 'inspect.check.integrity.fail'),
      verdict(sig.checks.signature, 'inspect.check.signature.ok', 'inspect.check.signature.fail'),
      sig.checks.timestamps.map((c) => verdict(c, 'inspect.check.ts.ok', 'inspect.check.ts.fail'))));
  }
  for (const error of sig.errors) card.append(el('p', { class: 'err', text: `${t('inspect.error.cms')} (${error})` }));

  card.append(...byteBar(sig, file.size));
  card.append(el('p', { class: 'hint', text: sig.coversWholeFile ? t('inspect.covers.all') : t('inspect.covers.partial') }));

  const cms = sig.cms;
  const signer = cms?.signer;
  card.append(kv([
    ['inspect.f.level', levelText(sig.level)],
    ['inspect.f.subfilter', sig.subFilter, true],
    ['inspect.f.signer', signer?.subject.cn ?? signer?.subject.text],
    ['inspect.f.cpf', signer?.icpBrasil.cpf],
    ['inspect.f.cnpj', signer?.icpBrasil.cnpj],
    ['inspect.f.issuer', signer?.issuer.text],
    ['inspect.f.validity', signer ? `${fmtDate(signer.notBefore)} → ${fmtDate(signer.notAfter)}` : null],
    ['inspect.f.key', signer ? `${signer.curve ? `EC ${signer.curve}` : signer.keySize ? `RSA ${signer.keySize}` : signer.keyAlgorithm}` : null],
    ['inspect.f.thumbprint', signer?.thumbprint, true],
    ['inspect.f.algorithm', cms ? `${cms.signatureAlgorithmName} · ${cms.hash ?? cms.digestAlgorithm}` : null],
    ['inspect.f.time', sig.signingTime ? fmtDate(sig.signingTime) : null],
    ['inspect.f.reason', sig.reason],
    ['inspect.f.location', sig.location],
    ['inspect.f.certs', cms ? String(cms.certificates.length) : null],
    ['inspect.f.size', cms ? t('inspect.f.size.value', { used: fmtBytes(sig.contents.length), reserved: fmtBytes(sig.contentsCapacity) }) : null],
  ]));

  for (const ts of cms?.timestamps ?? []) {
    card.append(el('h3', { text: t('inspect.ts.title') }), kv([
      ['inspect.ts.time', fmtDate(ts.genTime)],
      ['inspect.ts.tsa', ts.tsa],
      ['inspect.ts.hash', ts.hashAlgorithm],
    ]));
  }
  if (isDocTs && sig.tst) {
    card.append(kv([['inspect.ts.time', fmtDate(sig.tst.genTime)], ['inspect.ts.tsa', sig.tst.tsa]]));
  }

  card.append(el('p', { class: 'hint' }, el('a', { href: `learn.html#${sig.level.startsWith('B-') ? 'levels' : 'pdf'}`, text: t('inspect.learnmore') })));
  return card;
}

function render(file, name) {
  result.replaceChildren();
  const summary = el('div', { class: 'card sig-card' },
    el('h2', { text: name }),
    kv([
      ['inspect.f.filesize', `${fmtBytes(file.size)} bytes`],
      ['inspect.f.pdfversion', file.version],
      ['inspect.f.count', String(file.signatures.length)],
      ['inspect.f.dss', file.hasDss ? t(file.dssHasRevocation ? 'inspect.dss.rev' : 'inspect.dss.yes') : t('inspect.dss.no')],
    ]));
  result.append(summary);
  if (file.signatures.length === 0) {
    result.append(el('p', { class: 'err', text: t('inspect.none') }));
    return;
  }
  file.signatures.forEach((sig, i) => result.append(renderSignature(sig, i, file)));
}

async function inspect(bytes, name) {
  result.replaceChildren(el('p', { class: 'hint', text: t('inspect.reading') }));
  try {
    last = { file: await analyze(bytes), name };
    render(last.file, last.name);
  } catch (error) {
    last = null;
    result.replaceChildren(el('p', { class: 'err', text: `${t('inspect.error.file')} (${error.message})` }));
  }
}

await ready;

const input = document.getElementById('file');
const drop = document.getElementById('drop');
input.addEventListener('change', async () => {
  const file = input.files?.[0];
  if (file) await inspect(new Uint8Array(await file.arrayBuffer()), file.name);
});
for (const type of ['dragenter', 'dragover']) {
  drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.add('over'); });
}
for (const type of ['dragleave', 'drop']) {
  drop.addEventListener(type, () => drop.classList.remove('over'));
}
drop.addEventListener('drop', async (e) => {
  e.preventDefault();
  const file = e.dataTransfer?.files?.[0];
  if (file) await inspect(new Uint8Array(await file.arrayBuffer()), file.name);
});
for (const button of document.querySelectorAll('[data-sample]')) {
  button.addEventListener('click', async () => {
    const response = await fetch(`samples/${button.dataset.sample}`);
    await inspect(new Uint8Array(await response.arrayBuffer()), button.dataset.sample);
  });
}
document.addEventListener('ss:lang', () => { if (last) render(last.file, last.name); });
