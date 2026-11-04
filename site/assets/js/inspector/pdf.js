// Locates PDF signature dictionaries by their /ByteRange and reads the fields the inspector shows.
// This is a lexical scan, not a full PDF parser: it is meant for explanation, not validation.
import { fromHex } from './asn1.js';

export const MAX_FILE_BYTES = 50 * 1024 * 1024;
export const MAX_SIGNATURES = 50;

export class PdfError extends Error {}

/** Decodes a PDF literal or hex string token, including UTF-16BE (BOM FE FF) text strings. */
export function decodePdfString(token) {
  if (!token) return null;
  let bytes;
  if (token.startsWith('<')) {
    bytes = fromHex(token.slice(1, -1));
  } else {
    const body = token.slice(1, -1);
    const out = [];
    for (let i = 0; i < body.length; i++) {
      let c = body[i];
      if (c !== '\\') { out.push(body.charCodeAt(i) & 0xff); continue; }
      c = body[++i];
      const map = { n: 10, r: 13, t: 9, b: 8, f: 12, '(': 40, ')': 41, '\\': 92 };
      if (c in map) out.push(map[c]);
      else if (/[0-7]/.test(c)) {
        let oct = c;
        while (oct.length < 3 && /[0-7]/.test(body[i + 1])) oct += body[++i];
        out.push(parseInt(oct, 8) & 0xff);
      } else if (c === '\r' || c === '\n') {
        if (c === '\r' && body[i + 1] === '\n') i++;
      } else if (c !== undefined) out.push(body.charCodeAt(i) & 0xff);
    }
    bytes = Uint8Array.from(out);
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let s = '';
    for (let i = 2; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    return s;
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return new TextDecoder('utf-8').decode(bytes.subarray(3));
  }
  return new TextDecoder('latin1').decode(bytes);
}

/** Matches a string token (literal with balanced parentheses, or hex) right after `key`. */
function readStringAfter(text, key) {
  const m = new RegExp(`/${key}\\s*([(<])(?!<)`).exec(text);
  if (!m) return null;
  const i = m.index + m[0].length - 1;
  if (text[i] === '<') {
    const end = text.indexOf('>', i);
    return end < 0 ? null : text.slice(i, end + 1);
  }
  let depth = 0;
  for (let j = i; j < text.length; j++) {
    if (text[j] === '\\') { j++; continue; }
    if (text[j] === '(') depth++;
    if (text[j] === ')' && --depth === 0) return text.slice(i, j + 1);
  }
  return null;
}

function readName(text, key) {
  const m = new RegExp(`/${key}\\s*/([^\\s/<>\\[\\]()]+)`).exec(text);
  return m ? m[1] : null;
}

/** Parses a PDF date (D:YYYYMMDDHHmmSSOHH'mm') to a Date, or null. */
export function parsePdfDate(s) {
  const m = /^D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+-])?(\d{2})?'?(\d{2})?/.exec(s ?? '');
  if (!m) return null;
  const [, y, mo = '01', d = '01', h = '00', mi = '00', se = '00', sign, oh = '00', om = '00'] = m;
  let ms = Date.UTC(+y, +mo - 1, +d, +h, +mi, +se);
  if (sign === '+' || sign === '-') ms -= (sign === '+' ? 1 : -1) * ((+oh * 60) + +om) * 60000;
  return new Date(ms);
}

/**
 * Finds every signature in the file. Each entry has the byte range, the CMS bytes from
 * /Contents and the dictionary fields (/SubFilter, /Type, /Name, /M, /Reason, /Location).
 */
export function findSignatures(bytes) {
  if (bytes.length > MAX_FILE_BYTES) throw new PdfError('File too large');
  const text = new TextDecoder('latin1').decode(bytes);
  if (!text.startsWith('%PDF-')) throw new PdfError('Not a PDF file');

  const signatures = [];
  const pattern = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  for (const match of text.matchAll(pattern)) {
    if (signatures.length >= MAX_SIGNATURES) break;
    const range = match.slice(1, 5).map(Number);
    const [a, b, c, d] = range;
    if (a !== 0 || b <= 0 || c <= b || c + d > bytes.length) continue;
    const gap = text.slice(a + b, c);
    if (!/^<[0-9A-Fa-f\s]*>$/.test(gap)) continue;

    const objStart = text.lastIndexOf(' obj', Math.min(match.index, a + b));
    const objEndRaw = text.indexOf('endobj', Math.max(match.index + match[0].length, c));
    const objEnd = objEndRaw < 0 ? text.length : objEndRaw;
    const dict = text.slice(Math.max(objStart, 0), a + b) + text.slice(c, objEnd);

    const contents = stripTrailingZeros(fromHex(gap.slice(1, -1)));
    signatures.push({
      byteRange: range,
      signedLength: b + d,
      coversWholeFile: c + d === bytes.length,
      contents,
      contentsCapacity: Math.floor((c - a - b - 2) / 2),
      subFilter: readName(dict, 'SubFilter'),
      type: readName(dict, 'Type'),
      name: decodePdfString(readStringAfter(dict, 'Name')),
      reason: decodePdfString(readStringAfter(dict, 'Reason')),
      location: decodePdfString(readStringAfter(dict, 'Location')),
      signingTime: parsePdfDate(decodePdfString(readStringAfter(dict, 'M'))),
    });
  }

  signatures.sort((x, y) => x.signedLength - y.signedLength);
  return {
    size: bytes.length,
    version: text.slice(5, 8),
    signatures,
    hasDss: /\/DSS\s*(\d+\s+\d+\s+R|<<)/.test(text),
    dssHasRevocation: /\/(OCSPs|CRLs)\s*(\[|\d+\s+\d+\s+R)/.test(text),
    encrypted: /\/Encrypt\s/.test(text),
  };
}

/** The bytes covered by a signature's /ByteRange, concatenated. */
export function signedBytes(bytes, [a, b, c, d]) {
  const out = new Uint8Array(b + d);
  out.set(bytes.subarray(a, a + b), 0);
  out.set(bytes.subarray(c, c + d), b);
  return out;
}

/** /Contents is zero-padded to its reserved size; drop the padding after the DER structure. */
function stripTrailingZeros(der) {
  if (der.length < 2 || der[0] !== 0x30) return der;
  let length = der[1];
  let header = 2;
  if (length === 0x80) return der;
  if (length & 0x80) {
    const n = length & 0x7f;
    length = 0;
    for (let i = 0; i < n; i++) length = (length * 256) + der[2 + i];
    header += n;
  }
  return header + length <= der.length ? der.subarray(0, header + length) : der;
}
