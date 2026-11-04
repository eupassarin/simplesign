// Inspects a signed PDF entirely in the browser (or Node): finds the signatures, decodes the CMS
// and checks integrity and the cryptographic signature with WebCrypto. It does NOT check that
// the certificate chain is trusted or unrevoked; that needs trust anchors and network access.
import { findSignatures, signedBytes } from './pdf.js';
import { parseSignedData, parseTimestampToken, SIGNATURE_ALGORITHMS, OID } from './cms.js';
import { readNode, children, value, equalBytes, toHex } from './asn1.js';

const subtle = globalThis.crypto?.subtle;
const WEBCRYPTO_HASHES = new Set(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']);
const CURVE_BYTES = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };

/** Result of one check: 'ok', 'fail' or 'unsupported' (with a reason key). */
const ok = () => ({ status: 'ok' });
const fail = (reason) => ({ status: 'fail', reason });
const unsupported = (reason) => ({ status: 'unsupported', reason });

export async function digest(hash, data) {
  return new Uint8Array(await subtle.digest(hash, data));
}

/** Converts a DER ECDSA signature to the raw r||s form WebCrypto expects. */
export function ecdsaDerToRaw(der, size) {
  const [r, s] = children(readNode(der)).map(value);
  const out = new Uint8Array(size * 2);
  const put = (v, at) => {
    const trimmed = v.length > size ? v.subarray(v.length - size) : v;
    out.set(trimmed, at + size - trimmed.length);
  };
  put(r, 0);
  put(s, size);
  return out;
}

async function checkIntegrity(bytes, sig, cms) {
  // A document timestamp proves the bytes through its message imprint; a signature through messageDigest.
  const hash = cms.eContentType === OID.tstInfo ? sig.tst.hashAlgorithm : cms.hash;
  if (!hash) return unsupported('digest');
  if (!WEBCRYPTO_HASHES.has(hash)) return unsupported('sha3');
  const actual = await digest(hash, signedBytes(bytes, sig.byteRange));
  if (cms.eContentType === OID.tstInfo) {
    return equalBytes(actual, sig.tst.messageImprint) ? ok() : fail('imprint');
  }
  if (!cms.messageDigest) return fail('noDigest');
  return equalBytes(actual, cms.messageDigest) ? ok() : fail('mismatch');
}

/** Verifies the signature over the signed attributes with the signer's public key. */
export async function checkSignature(cms) {
  const cert = cms.signer;
  if (!cert) return fail('noSigner');
  if (!cms.signedAttrsDer) return unsupported('noSignedAttrs');
  const algorithm = SIGNATURE_ALGORITHMS[cms.signatureAlgorithm];
  const hash = algorithm?.hash ?? cms.pss?.hash ?? cms.hash;
  if (!algorithm || !WEBCRYPTO_HASHES.has(hash)) return unsupported('algorithm');

  try {
    if (algorithm.scheme === 'pkcs1') {
      const key = await subtle.importKey('spki', cert.spki, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
      return (await subtle.verify('RSASSA-PKCS1-v1_5', key, cms.signature, cms.signedAttrsDer)) ? ok() : fail('signature');
    }
    if (algorithm.scheme === 'pss') {
      const key = await subtle.importKey('spki', cert.spki, { name: 'RSA-PSS', hash }, false, ['verify']);
      const saltLength = cms.pss?.saltLength ?? 32;
      return (await subtle.verify({ name: 'RSA-PSS', saltLength }, key, cms.signature, cms.signedAttrsDer)) ? ok() : fail('signature');
    }
    if (algorithm.scheme === 'ecdsa') {
      const size = CURVE_BYTES[cert.curve];
      if (!size) return unsupported('curve');
      const key = await subtle.importKey('spki', cert.spki, { name: 'ECDSA', namedCurve: cert.curve }, false, ['verify']);
      const raw = ecdsaDerToRaw(cms.signature, size);
      return (await subtle.verify({ name: 'ECDSA', hash }, key, raw, cms.signedAttrsDer)) ? ok() : fail('signature');
    }
  } catch {
    return unsupported('webcrypto');
  }
  return unsupported('algorithm');
}

/** Checks that a timestamp's message imprint is the hash of the signature value. */
async function checkTimestamp(ts, signature) {
  if (!WEBCRYPTO_HASHES.has(ts.hashAlgorithm)) return unsupported('sha3');
  const imprint = await digest(ts.hashAlgorithm, signature);
  return equalBytes(imprint, ts.messageImprint) ? ok() : fail('imprint');
}

/** Approximates the PAdES baseline level from what the file contains (ETSI EN 319 142-1). */
export function detectLevel(sig, index, all, file) {
  if (sig.subFilter === 'ETSI.RFC3161') return 'DocTimeStamp';
  if (sig.subFilter !== 'ETSI.CAdES.detached') return 'PKCS#7';
  if (!sig.cms?.hasSigningCertificateV2 && !sig.cms?.hasSigningCertificateV1) return 'CMS';
  const laterDocTimestamp = all.slice(index + 1).some((s) => s.subFilter === 'ETSI.RFC3161');
  const timestamped = (sig.cms.timestamps.length > 0) || laterDocTimestamp;
  if (!timestamped) return 'B-B';
  if (!file.hasDss) return 'B-T';
  return laterDocTimestamp ? 'B-LTA' : 'B-LT';
}

/** Inspects a PDF. Never throws for a malformed signature: errors are reported per signature. */
export async function analyze(bytes) {
  const file = findSignatures(bytes);
  for (const sig of file.signatures) {
    sig.errors = [];
    try {
      if (sig.subFilter === 'ETSI.RFC3161') {
        sig.tst = parseTimestampToken(sig.contents);
        sig.cms = sig.tst.cms;
      } else {
        sig.cms = parseSignedData(sig.contents);
      }
    } catch (error) {
      sig.errors.push(`cms:${error.message}`);
      sig.cms = null;
    }
  }

  for (const [index, sig] of file.signatures.entries()) {
    sig.level = detectLevel(sig, index, file.signatures, file);
    if (!sig.cms) continue;
    sig.checks = {
      integrity: await checkIntegrity(bytes, sig, sig.cms),
      signature: await checkSignature(sig.cms),
      timestamps: await Promise.all(sig.cms.timestamps.map((ts) => checkTimestamp(ts, sig.cms.signature))),
    };
    if (sig.cms.signer) {
      sig.cms.signer.thumbprint = toHex(await digest('SHA-1', sig.cms.signer.raw)).toUpperCase();
    }
  }

  return file;
}
