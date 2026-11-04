// CMS SignedData (RFC 5652), X.509 (RFC 5280) and RFC 3161 TSTInfo parsing for the inspector.
import { readNode, children, value, raw, oid, integerHex, integer, string, time, isContext, expect, TAG, Asn1Error, toHex, equalBytes } from './asn1.js';

export const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  signingCertificate: '1.2.840.113549.1.9.16.2.12',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  signatureTimestamp: '1.2.840.113549.1.9.16.2.14',
  signaturePolicy: '1.2.840.113549.1.9.16.2.15',
  commitmentType: '1.2.840.113549.1.9.16.2.16',
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsaPss: '1.2.840.113549.1.1.10',
  ecPublicKey: '1.2.840.10045.2.1',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  icpBrasilPf: '2.16.76.1.3.1',
  icpBrasilPjCnpj: '2.16.76.1.3.3',
};

export const HASHES = {
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
  '2.16.840.1.101.3.4.2.8': 'SHA3-256',
  '2.16.840.1.101.3.4.2.9': 'SHA3-384',
  '2.16.840.1.101.3.4.2.10': 'SHA3-512',
};

export const SIGNATURE_ALGORITHMS = {
  '1.2.840.113549.1.1.1': { name: 'RSA', scheme: 'pkcs1' },
  '1.2.840.113549.1.1.5': { name: 'RSA with SHA-1', scheme: 'pkcs1', hash: 'SHA-1' },
  '1.2.840.113549.1.1.11': { name: 'RSA with SHA-256', scheme: 'pkcs1', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { name: 'RSA with SHA-384', scheme: 'pkcs1', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { name: 'RSA with SHA-512', scheme: 'pkcs1', hash: 'SHA-512' },
  '1.2.840.113549.1.1.10': { name: 'RSASSA-PSS', scheme: 'pss' },
  '1.2.840.10045.2.1': { name: 'ECDSA', scheme: 'ecdsa' },
  '1.2.840.10045.4.3.2': { name: 'ECDSA with SHA-256', scheme: 'ecdsa', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { name: 'ECDSA with SHA-384', scheme: 'ecdsa', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { name: 'ECDSA with SHA-512', scheme: 'ecdsa', hash: 'SHA-512' },
  '1.3.101.112': { name: 'Ed25519', scheme: 'eddsa' },
};

const CURVES = { '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521' };

const NAME_ATTRIBUTES = {
  '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
  '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.12': 'T', '2.5.4.42': 'G', '1.2.840.113549.1.9.1': 'E',
};

/** Parses a DER Name into "CN=..., O=..." (most specific first, like .NET's X500DistinguishedName). */
export function parseName(node) {
  const parts = [];
  for (const rdn of children(node)) {
    for (const atv of children(rdn)) {
      const [type, val] = children(atv);
      const key = NAME_ATTRIBUTES[oid(type)] ?? oid(type);
      parts.push({ key, value: string(val) });
    }
  }
  return {
    // Values with separators are quoted, as .NET's X500DistinguishedName does.
    text: parts.slice().reverse().map((p) => `${p.key}=${/[,+="<>#;]/.test(p.value) ? `"${p.value}"` : p.value}`).join(', '),
    cn: parts.find((p) => p.key === 'CN')?.value ?? null,
    raw: raw(node),
  };
}

/** Parses an X.509 certificate. */
export function parseCertificate(node) {
  const [tbs, sigAlg] = children(node);
  const fields = children(tbs);
  let i = 0;
  if (isContext(fields[0], 0)) i++; // version
  const serial = integerHex(fields[i++]);
  i++; // signature algorithm
  const issuer = parseName(fields[i++]);
  const [notBefore, notAfter] = children(fields[i++]).map(time);
  const subject = parseName(fields[i++]);
  const spkiNode = fields[i++];
  const [algorithm] = children(spkiNode);
  const [keyOid, params] = children(algorithm);
  const keyAlgorithm = oid(keyOid);
  const curve = keyAlgorithm === OID.ecPublicKey && params?.number === TAG.OID ? CURVES[oid(params)] ?? oid(params) : null;
  let keySize = null;
  if (keyAlgorithm === OID.rsaEncryption || keyAlgorithm === OID.rsaPss) {
    const bits = value(children(spkiNode)[1]).subarray(1);
    const [modulus] = children(readNode(bits));
    const m = value(modulus);
    keySize = (m[0] === 0 ? m.length - 1 : m.length) * 8;
  }

  let isCa = false;
  const icpBrasil = {};
  for (const field of fields.slice(i)) {
    if (!isContext(field, 3)) continue;
    for (const ext of children(children(field)[0])) {
      const parts = children(ext);
      const extOid = oid(parts[0]);
      const extValue = readNode(value(parts[parts.length - 1]));
      if (extOid === OID.basicConstraints) {
        const bc = children(extValue);
        isCa = bc.length > 0 && bc[0].number === 1 && value(bc[0])[0] !== 0;
      } else if (extOid === OID.subjectAltName) {
        Object.assign(icpBrasil, parseIcpBrasilSan(extValue));
      }
    }
  }

  return {
    raw: raw(node), serial, issuer, subject, notBefore, notAfter, isCa,
    spki: raw(spkiNode), keyAlgorithm, curve, keySize,
    signatureAlgorithm: oid(children(sigAlg)[0]),
    icpBrasil,
  };
}

/** Reads the ICP-Brasil otherName fields of a SubjectAltName (CPF in 2.16.76.1.3.1, CNPJ in 2.16.76.1.3.3). */
function parseIcpBrasilSan(node) {
  const result = {};
  for (const name of children(node)) {
    if (!isContext(name, 0) || !name.constructed) continue;
    const [typeId, wrapped] = children(name);
    const type = oid(typeId);
    let text;
    try {
      text = string(children(wrapped)[0]);
    } catch {
      continue;
    }
    if (type === OID.icpBrasilPf && text.length >= 19) result.cpf = text.substring(8, 19);
    if (type === OID.icpBrasilPjCnpj && text.length >= 14) result.cnpj = text.substring(0, 14);
  }
  return result;
}

function parseAttributes(node) {
  const attributes = [];
  for (const attr of children(node)) {
    const [type, values] = children(attr);
    attributes.push({ oid: oid(type), values: children(values) });
  }
  return attributes;
}

/** Parses an RFC 3161 TSTInfo. */
export function parseTstInfo(bytes) {
  const fields = children(readNode(bytes));
  const [hashAlg, digest] = children(fields[2]);
  const genTime = fields.find((f) => f.number === TAG.GENERALIZED_TIME);
  return {
    policy: oid(fields[1]),
    hashAlgorithm: HASHES[oid(children(hashAlg)[0])] ?? oid(children(hashAlg)[0]),
    messageImprint: value(digest),
    serial: integerHex(fields[3]),
    genTime: genTime ? time(genTime) : null,
  };
}

/**
 * Parses a CMS ContentInfo containing SignedData. Returns the signer, certificates and the
 * pieces needed to verify: signedAttrsDer (re-tagged as SET), signature, digest algorithm.
 */
export function parseSignedData(bytes) {
  const contentInfo = readNode(bytes);
  const [type, wrapper] = children(contentInfo);
  if (oid(type) !== OID.signedData) throw new Asn1Error('Not a CMS SignedData');
  const fields = children(children(wrapper)[0]);
  let i = 1; // version
  i++; // digestAlgorithms
  const encap = children(fields[i++]);
  const eContentType = oid(encap[0]);
  const eContent = encap[1] ? flattenOctets(children(encap[1])[0]) : null;

  let certificates = [];
  if (fields[i] && isContext(fields[i], 0)) certificates = children(fields[i++]).filter((c) => c.number === TAG.SEQUENCE).map(parseCertificate);
  if (fields[i] && isContext(fields[i], 1)) i++; // crls
  const signerInfos = children(expect(fields[i], TAG.SET, 'signerInfos'));
  if (signerInfos.length === 0) throw new Asn1Error('CMS has no SignerInfo');

  const si = children(signerInfos[0]);
  let j = 1; // version
  const sid = si[j++];
  const digestAlgorithm = oid(children(si[j++])[0]);
  let signedAttrs = [];
  let signedAttrsDer = null;
  if (isContext(si[j], 0)) {
    const node = si[j++];
    signedAttrsDer = new Uint8Array(raw(node));
    signedAttrsDer[0] = 0x31; // [0] IMPLICIT SET OF → SET OF for the signature input (RFC 5652 §5.4)
    signedAttrs = parseAttributes(node);
  }
  const sigAlgParts = children(si[j++]);
  const signatureAlgorithm = oid(sigAlgParts[0]);
  const signatureParams = sigAlgParts[1] && sigAlgParts[1].number !== TAG.NULL ? sigAlgParts[1] : null;
  const signature = value(si[j++]);
  const unsignedAttrs = si[j] && isContext(si[j], 1) ? parseAttributes(si[j]) : [];

  const signer = findSigner(sid, certificates);
  const attr = (list, id) => list.find((a) => a.oid === id);
  const messageDigest = attr(signedAttrs, OID.messageDigest);
  const signingTime = attr(signedAttrs, OID.signingTime);

  const timestamps = [];
  for (const ts of attr(unsignedAttrs, OID.signatureTimestamp)?.values ?? []) {
    try {
      timestamps.push(parseTimestampToken(raw(ts)));
    } catch {
      // An unreadable timestamp is reported as missing rather than failing the whole inspection.
    }
  }

  return {
    eContentType,
    eContent,
    certificates,
    signer,
    digestAlgorithm,
    hash: HASHES[digestAlgorithm] ?? null,
    signatureAlgorithm,
    signatureAlgorithmName: SIGNATURE_ALGORITHMS[signatureAlgorithm]?.name ?? signatureAlgorithm,
    pss: signatureParams && signatureAlgorithm === OID.rsaPss ? parsePssParams(signatureParams) : null,
    signature,
    signedAttrsDer,
    messageDigest: messageDigest ? value(messageDigest.values[0]) : null,
    signingTime: signingTime ? time(signingTime.values[0]) : null,
    hasSigningCertificateV2: !!attr(signedAttrs, OID.signingCertificateV2),
    hasSigningCertificateV1: !!attr(signedAttrs, OID.signingCertificate),
    hasSignaturePolicy: !!attr(signedAttrs, OID.signaturePolicy),
    signedAttributeOids: signedAttrs.map((a) => a.oid),
    timestamps,
  };
}

/** Parses a TimeStampToken (a CMS SignedData whose content is a TSTInfo). */
export function parseTimestampToken(bytes) {
  const cms = parseSignedData(bytes);
  if (cms.eContentType !== OID.tstInfo || !cms.eContent) throw new Asn1Error('Not a timestamp token');
  return { ...parseTstInfo(cms.eContent), tsa: cms.signer?.subject.text ?? null, cms };
}

function parsePssParams(node) {
  const result = { hash: 'SHA-1', saltLength: 20 };
  for (const field of children(node)) {
    if (isContext(field, 0)) result.hash = HASHES[oid(children(children(field)[0])[0])] ?? result.hash;
    if (isContext(field, 2)) result.saltLength = integer(children(field)[0]);
  }
  return result;
}

function findSigner(sid, certificates) {
  if (sid.number === TAG.SEQUENCE) {
    const [issuer, serial] = children(sid);
    const issuerDer = raw(issuer);
    const serialHex = integerHex(serial);
    return certificates.find((c) => c.serial === serialHex && equalBytes(c.issuer.raw, issuerDer)) ?? null;
  }
  return certificates.length === 1 ? certificates[0] : null;
}

/** OCTET STRING content, joining BER constructed segments. */
function flattenOctets(node) {
  if (!node.constructed) return value(node);
  const parts = children(node).map(flattenOctets);
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let pos = 0;
  for (const p of parts) { out.set(p, pos); pos += p.length; }
  return out;
}

export { toHex };
