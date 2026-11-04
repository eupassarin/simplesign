// Minimal ASN.1 BER/DER reader for CMS and X.509 inspection. Pure JS, no dependencies.
// Nodes are { tag, cls, constructed, number, start, headerLength, length, end, bytes }:
// `start` is the first byte of the TLV, the value is bytes[start + headerLength, end).

export const MAX_DEPTH = 64;

export class Asn1Error extends Error {}

/** Reads one TLV at `offset`. Supports indefinite lengths (BER), which some signers emit. */
export function readNode(bytes, offset = 0, limit = bytes.length, depth = 0) {
  if (depth > MAX_DEPTH) throw new Asn1Error('ASN.1 nesting too deep');
  if (offset >= limit) throw new Asn1Error('Unexpected end of ASN.1 data');

  const first = bytes[offset];
  let pos = offset + 1;
  let number = first & 0x1f;
  if (number === 0x1f) {
    number = 0;
    let b;
    do {
      if (pos >= limit) throw new Asn1Error('Truncated ASN.1 tag');
      b = bytes[pos++];
      number = (number * 128) + (b & 0x7f);
    } while (b & 0x80);
  }

  if (pos >= limit) throw new Asn1Error('Truncated ASN.1 length');
  let length = bytes[pos++];
  let indefinite = false;
  if (length === 0x80) {
    indefinite = true;
  } else if (length & 0x80) {
    const count = length & 0x7f;
    if (count > 4 || pos + count > limit) throw new Asn1Error('Unsupported ASN.1 length');
    length = 0;
    for (let i = 0; i < count; i++) length = (length * 256) + bytes[pos++];
  }

  const constructed = (first & 0x20) !== 0;
  const headerLength = pos - offset;
  let end;
  if (indefinite) {
    if (!constructed) throw new Asn1Error('Indefinite length on a primitive value');
    let child = pos;
    while (true) {
      if (child + 1 >= limit) throw new Asn1Error('Unterminated indefinite length');
      if (bytes[child] === 0 && bytes[child + 1] === 0) { end = child + 2; break; }
      child = readNode(bytes, child, limit, depth + 1).end;
    }
    length = end - pos - 2;
  } else {
    end = pos + length;
    if (end > limit) throw new Asn1Error('ASN.1 value exceeds its container');
  }

  return { tag: first, cls: first >> 6, constructed, number, start: offset, headerLength, length, end, indefinite, bytes, depth };
}

/** Returns the children of a constructed node. */
export function children(node) {
  if (!node.constructed) throw new Asn1Error('Not a constructed ASN.1 value');
  const result = [];
  let pos = node.start + node.headerLength;
  const stop = node.indefinite ? node.end - 2 : node.end;
  while (pos < stop) {
    const child = readNode(node.bytes, pos, stop, node.depth + 1);
    result.push(child);
    pos = child.end;
  }
  return result;
}

/** The value bytes of a node. */
export function value(node) {
  return node.bytes.subarray(node.start + node.headerLength, node.start + node.headerLength + node.length);
}

/** The full TLV bytes of a node. */
export function raw(node) {
  return node.bytes.subarray(node.start, node.end);
}

/** Context-specific tag helper: [n]. */
export const isContext = (node, n) => node.cls === 2 && node.number === n;

/** Universal tag numbers used here. */
export const TAG = { INTEGER: 2, BIT_STRING: 3, OCTET_STRING: 4, NULL: 5, OID: 6, UTF8: 12, SEQUENCE: 16, SET: 17,
  PRINTABLE: 19, T61: 20, IA5: 22, UTC_TIME: 23, GENERALIZED_TIME: 24, BMP: 30 };

export function expect(node, number, what) {
  if (node.cls !== 0 || node.number !== number) throw new Asn1Error(`Expected ${what}`);
  return node;
}

/** Decodes an OBJECT IDENTIFIER. */
export function oid(node) {
  const v = value(node);
  if (v.length === 0) throw new Asn1Error('Empty OID');
  const parts = [];
  let n = 0;
  for (let i = 0; i < v.length; i++) {
    n = (n * 128) + (v[i] & 0x7f);
    if (!(v[i] & 0x80)) {
      if (parts.length === 0) {
        const first = n < 80 ? Math.floor(n / 40) : 2;
        parts.push(first, n - (first * 40));
      } else {
        parts.push(n);
      }
      n = 0;
    }
  }
  return parts.join('.');
}

/** Hex of an INTEGER's bytes (serial numbers), without a redundant leading zero. */
export function integerHex(node) {
  let v = value(node);
  if (v.length > 1 && v[0] === 0) v = v.subarray(1);
  return toHex(v);
}

/** Small INTEGER as a number. */
export function integer(node) {
  let n = 0;
  for (const b of value(node)) n = (n * 256) + b;
  return n;
}

/** Decodes string types (UTF8String, PrintableString, IA5String, BMPString, T61 as Latin-1). */
export function string(node) {
  const v = value(node);
  if (node.number === TAG.BMP) {
    let s = '';
    for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]);
    return s;
  }
  if (node.number === TAG.UTF8) return new TextDecoder('utf-8').decode(v);
  return new TextDecoder('latin1').decode(v);
}

/** Decodes UTCTime / GeneralizedTime to a Date. */
export function time(node) {
  const s = new TextDecoder('latin1').decode(value(node));
  const m = node.number === TAG.UTC_TIME
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s)
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,](\d+))?Z$/.exec(s);
  if (!m) throw new Asn1Error(`Unsupported time format: ${s}`);
  let year = Number(m[1]);
  if (node.number === TAG.UTC_TIME) year += year < 50 ? 2000 : 1900;
  const ms = m[7] ? Math.round(Number(`0.${m[7]}`) * 1000) : 0;
  return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0), ms));
}

export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
