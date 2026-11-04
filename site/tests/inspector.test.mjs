// Unit tests for the browser inspector. Run: node --test site/tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readNode, children, oid, time, fromHex, Asn1Error, MAX_DEPTH } from '../assets/js/inspector/asn1.js';
import { decodePdfString, parsePdfDate, findSignatures, PdfError } from '../assets/js/inspector/pdf.js';
import { analyze, ecdsaDerToRaw } from '../assets/js/inspector/analyze.js';

const sample = async (name) => new Uint8Array(await readFile(new URL(`../samples/${name}`, import.meta.url)));

test('asn1: decodes OIDs, including the first-two-arcs rule', () => {
  assert.equal(oid(readNode(fromHex('06092a864886f70d010702'))), '1.2.840.113549.1.7.2');
  assert.equal(oid(readNode(fromHex('0603551d11'))), '2.5.29.17');
  assert.equal(oid(readNode(fromHex('0609608648016503040201'))), '2.16.840.1.101.3.4.2.1');
});

test('asn1: reads indefinite-length (BER) constructed values', () => {
  const node = readNode(fromHex('3080020101020102 0000'.replace(' ', '')));
  assert.equal(children(node).length, 2);
  assert.equal(node.end, 10);
});

test('asn1: parses UTCTime and GeneralizedTime', () => {
  const utc = '170d' + Buffer.from('260131235959Z').toString('hex');
  assert.equal(time(readNode(fromHex(utc))).toISOString(), '2026-01-31T23:59:59.000Z');
  const gen = '1812' + Buffer.from('20991231120000.25Z').toString('hex');
  assert.equal(time(readNode(fromHex(gen))).toISOString(), '2099-12-31T12:00:00.250Z');
});

test('asn1: rejects truncated and overlong values', () => {
  assert.throws(() => readNode(fromHex('3005020101')), Asn1Error);
  assert.throws(() => readNode(fromHex('02857fffffffff')), Asn1Error);
});

test('asn1: refuses nesting deeper than the limit', () => {
  const deep = '30 80 '.repeat(MAX_DEPTH + 2) + '00 00 '.repeat(MAX_DEPTH + 2);
  assert.throws(() => readNode(fromHex(deep)), Asn1Error);
});

test('pdf: decodes literal, hex and UTF-16BE strings', () => {
  assert.equal(decodePdfString('(a\\(b\\)\\\\c\\101)'), 'a(b)\\cA');
  assert.equal(decodePdfString('<48656C6C6F>'), 'Hello');
  assert.equal(decodePdfString('<FEFF00E7006100E7>'), 'çaç');
  assert.equal(decodePdfString('(S\\343o Paulo)'), 'São Paulo');
});

test('pdf: parses dates with time zone offsets', () => {
  assert.equal(parsePdfDate("D:20261104154120-03'00'").toISOString(), '2026-11-04T18:41:20.000Z');
  assert.equal(parsePdfDate('D:20261104184120Z').toISOString(), '2026-11-04T18:41:20.000Z');
  assert.equal(parsePdfDate('garbage'), null);
});

test('pdf: rejects files that are not PDFs', () => {
  assert.throws(() => findSignatures(new TextEncoder().encode('hello')), PdfError);
});

test('pdf: an unsigned PDF has no signatures', () => {
  const pdf = new TextEncoder().encode('%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\n%%EOF');
  assert.equal(findSignatures(pdf).signatures.length, 0);
});

test('ecdsa: converts DER to fixed-size r||s', () => {
  const raw = ecdsaDerToRaw(fromHex('3007020101020200ff'), 32);
  assert.equal(raw.length, 64);
  assert.equal(raw[31], 1);
  assert.equal(raw[63], 0xff);
});

test('analyze: RSA sample is intact, verified, B-B, with ICP-Brasil CPF and dictionary fields', async () => {
  const result = await analyze(await sample('signed-rsa.pdf'));
  const [sig] = result.signatures;
  assert.equal(result.signatures.length, 1);
  assert.equal(sig.checks.integrity.status, 'ok');
  assert.equal(sig.checks.signature.status, 'ok');
  assert.equal(sig.level, 'B-B');
  assert.equal(sig.subFilter, 'ETSI.CAdES.detached');
  assert.equal(sig.reason, 'Aprovação do contrato');
  assert.equal(sig.location, 'São Paulo, BR');
  assert.equal(sig.cms.signer.subject.cn, 'Fulana de Tal (TESTE):12345678909');
  assert.equal(sig.cms.signer.icpBrasil.cpf, '12345678909');
  assert.equal(sig.cms.hash, 'SHA-256');
  assert.ok(sig.coversWholeFile);
});

test('analyze: ECDSA and RSASSA-PSS samples verify', async () => {
  for (const name of ['signed-ecdsa.pdf', 'signed-pss.pdf']) {
    const [sig] = (await analyze(await sample(name))).signatures;
    assert.equal(sig.checks.integrity.status, 'ok', name);
    assert.equal(sig.checks.signature.status, 'ok', name);
  }
  const [ec] = (await analyze(await sample('signed-ecdsa.pdf'))).signatures;
  assert.equal(ec.cms.signer.curve, 'P-256');
  const [pss] = (await analyze(await sample('signed-pss.pdf'))).signatures;
  assert.equal(pss.cms.signatureAlgorithmName, 'RSASSA-PSS');
});

test('analyze: timestamped sample is B-T and its timestamp covers the signature', async () => {
  const [sig] = (await analyze(await sample('signed-timestamped.pdf'))).signatures;
  assert.equal(sig.level, 'B-T');
  assert.equal(sig.cms.timestamps.length, 1);
  assert.equal(sig.checks.timestamps[0].status, 'ok');
  assert.ok(sig.cms.timestamps[0].genTime instanceof Date);
  assert.match(sig.cms.timestamps[0].tsa, /DigiCert/);
});

test('analyze: tampered sample fails integrity but the signature over the attributes still verifies', async () => {
  const [sig] = (await analyze(await sample('tampered.pdf'))).signatures;
  assert.equal(sig.checks.integrity.status, 'fail');
  assert.equal(sig.checks.integrity.reason, 'mismatch');
  assert.equal(sig.checks.signature.status, 'ok');
});

test('analyze: a corrupted CMS is reported, not thrown', async () => {
  const bytes = await sample('signed-rsa.pdf');
  const text = new TextDecoder('latin1').decode(bytes);
  const at = text.indexOf('/Contents <') + '/Contents <'.length;
  const broken = bytes.slice();
  for (let i = 0; i < 8; i++) broken[at + i] = 0x30; // "0" hex digits
  const [sig] = (await analyze(broken)).signatures;
  assert.equal(sig.cms, null);
  assert.ok(sig.errors.length > 0);
});
