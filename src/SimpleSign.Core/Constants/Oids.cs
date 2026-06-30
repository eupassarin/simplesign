#pragma warning disable CA1707 // Identifiers should not contain underscores — OID names follow crypto notation

namespace SimpleSign.Core.Constants;

/// <summary>
/// Standard OID (Object Identifier) constants used across the SimpleSign library.
/// Centralizes all OIDs to avoid duplication and improve discoverability.
/// </summary>
public static class Oids
{
    #region Hash Algorithms

    /// <summary>SHA-256 (id-sha256) — default for ICP-Brasil and PAdES.</summary>
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";

    /// <summary>SHA-384 (id-sha384).</summary>
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";

    /// <summary>SHA-512 (id-sha512).</summary>
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";

    /// <summary>SHA3-256 (id-sha3-256).</summary>
    public const string Sha3_256 = "2.16.840.1.101.3.4.2.8";

    /// <summary>SHA3-384 (id-sha3-384).</summary>
    public const string Sha3_384 = "2.16.840.1.101.3.4.2.9";

    /// <summary>SHA3-512 (id-sha3-512).</summary>
    public const string Sha3_512 = "2.16.840.1.101.3.4.2.10";

    /// <summary>SHA-1 (id-sha1) — deprecated since 2016, supported for legacy validation.</summary>
    public const string Sha1 = "1.3.14.3.2.26";

    #endregion

    #region Signature Algorithms

    /// <summary>RSA with SHA-256 (sha256WithRSAEncryption).</summary>
    public const string RsaSha256 = "1.2.840.113549.1.1.11";

    /// <summary>RSA with SHA-384 (sha384WithRSAEncryption).</summary>
    public const string RsaSha384 = "1.2.840.113549.1.1.12";

    /// <summary>RSA with SHA-512 (sha512WithRSAEncryption).</summary>
    public const string RsaSha512 = "1.2.840.113549.1.1.13";

    /// <summary>RSA with SHA-1 (sha1WithRSAEncryption) — legacy.</summary>
    public const string RsaSha1 = "1.2.840.113549.1.1.5";

    /// <summary>RSA with SHA3-256 (id-rsassa-pkcs1-v1_5-with-sha3-256).</summary>
    public const string RsaSha3_256 = "2.16.840.1.101.3.4.3.14";

    /// <summary>RSA with SHA3-384 (id-rsassa-pkcs1-v1_5-with-sha3-384).</summary>
    public const string RsaSha3_384 = "2.16.840.1.101.3.4.3.15";

    /// <summary>RSA with SHA3-512 (id-rsassa-pkcs1-v1_5-with-sha3-512).</summary>
    public const string RsaSha3_512 = "2.16.840.1.101.3.4.3.16";

    /// <summary>ECDSA with SHA-256.</summary>
    public const string EcdsaSha256 = "1.2.840.10045.4.3.2";

    /// <summary>ECDSA with SHA-384.</summary>
    public const string EcdsaSha384 = "1.2.840.10045.4.3.3";

    /// <summary>ECDSA with SHA-512.</summary>
    public const string EcdsaSha512 = "1.2.840.10045.4.3.4";

    /// <summary>ECDSA with SHA3-256 (id-ecdsa-with-sha3-256).</summary>
    public const string EcdsaSha3_256 = "2.16.840.1.101.3.4.3.10";

    /// <summary>ECDSA with SHA3-384 (id-ecdsa-with-sha3-384).</summary>
    public const string EcdsaSha3_384 = "2.16.840.1.101.3.4.3.11";

    /// <summary>ECDSA with SHA3-512 (id-ecdsa-with-sha3-512).</summary>
    public const string EcdsaSha3_512 = "2.16.840.1.101.3.4.3.12";

    /// <summary>RSA-PSS (id-RSASSA-PSS) — signature algorithm with PSS padding.</summary>
    public const string RsaPss = "1.2.840.113549.1.1.10";

    /// <summary>id-mgf1 — Mask Generation Function 1 (RFC 4055 §3.1).</summary>
    public const string Mgf1 = "1.2.840.113549.1.1.8";

    /// <summary>RSA encryption (rsaEncryption) — public key algorithm OID.</summary>
    public const string RsaEncryption = "1.2.840.113549.1.1.1";

    /// <summary>EdDSA with Ed25519 (id-EdDSA).</summary>
    public const string Ed25519 = "1.3.101.112";

    /// <summary>EdDSA with Ed448.</summary>
    public const string Ed448 = "1.3.101.113";

    #endregion

    #region CMS / PKCS#7 Content Types

    /// <summary>id-data — CMS content type for arbitrary data.</summary>
    public const string Data = "1.2.840.113549.1.7.1";

    /// <summary>id-signedData — CMS content type for signed data.</summary>
    public const string SignedData = "1.2.840.113549.1.7.2";

    #endregion

    #region CMS Signed Attributes

    /// <summary>id-contentType — identifies the content type of the signed data.</summary>
    public const string ContentType = "1.2.840.113549.1.9.3";

    /// <summary>id-messageDigest — hash of the signed content.</summary>
    public const string MessageDigest = "1.2.840.113549.1.9.4";

    /// <summary>id-signingTime — time the signer claims to have signed.</summary>
    public const string SigningTime = "1.2.840.113549.1.9.5";

    /// <summary>id-aa-signingCertificate (RFC 2634) — older version that uses SHA-1 hash.</summary>
    public const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";

    /// <summary>id-aa-signingCertificateV2 (RFC 5035) — binds certificate to signature, required by PAdES-B-B.</summary>
    public const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";

    /// <summary>id-aa-signatureTimeStampToken (RFC 3161) — timestamp token on the signature value.</summary>
    public const string SignatureTimestampToken = "1.2.840.113549.1.9.16.2.14";

    /// <summary>id-aa-ets-commitmentType (RFC 5126 §5.11.1) — commitment type indication.</summary>
    public const string CommitmentTypeIndication = "1.2.840.113549.1.9.16.2.16";

    /// <summary>id-aa-ets-sigPolicyId (RFC 5126 §5.8.1) — signature policy identifier.</summary>
    public const string SignaturePolicyIdentifier = "1.2.840.113549.1.9.16.2.15";

    /// <summary>id-cti-ets-proofOfOrigin — signer is the author.</summary>
    public const string ProofOfOrigin = "1.2.840.113549.1.9.16.6.1";

    /// <summary>id-cti-ets-proofOfReceipt — signer acknowledges receipt.</summary>
    public const string ProofOfReceipt = "1.2.840.113549.1.9.16.6.2";

    /// <summary>id-cti-ets-proofOfDelivery — signer confirms delivery.</summary>
    public const string ProofOfDelivery = "1.2.840.113549.1.9.16.6.3";

    /// <summary>id-cti-ets-proofOfSender — signer confirms sending.</summary>
    public const string ProofOfSender = "1.2.840.113549.1.9.16.6.4";

    /// <summary>id-cti-ets-proofOfApproval — signer approves the content.</summary>
    public const string ProofOfApproval = "1.2.840.113549.1.9.16.6.5";

    /// <summary>id-cti-ets-proofOfCreation — signer created the content.</summary>
    public const string ProofOfCreation = "1.2.840.113549.1.9.16.6.6";

    /// <summary>
    /// SimpleSign signature manifest — JSON-encoded AEA evidence (name, CPF, email, IP, auth method).
    /// OID arc: 2.16.76 (Brazil) / 1.12 (electronic signature extensions) / 1.1 (manifest v1).
    /// Embedded as a CMS signed attribute to be tamper-proof.
    /// </summary>
    public const string SignatureManifest = "2.16.76.1.12.1.1";

    #endregion

    #region X.509 Extensions

    /// <summary>id-pe-authorityInfoAccess — AIA extension for OCSP and CA Issuers.</summary>
    public const string AuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";

    /// <summary>id-ad-ocsp — OCSP responder access method within AIA.</summary>
    public const string AdOcsp = "1.3.6.1.5.5.7.48.1";

    /// <summary>id-ad-caIssuers — CA Issuers access method within AIA.</summary>
    public const string AdCaIssuers = "1.3.6.1.5.5.7.48.2";

    #endregion

    #region X.509 Standard Extensions

    /// <summary>id-ce-subjectAltName (SAN).</summary>
    public const string SubjectAltName = "2.5.29.17";

    /// <summary>id-ce-cRLDistributionPoints (CDP).</summary>
    public const string CrlDistributionPoints = "2.5.29.31";

    /// <summary>id-ce-certificatePolicies.</summary>
    public const string CertificatePolicies = "2.5.29.32";

    /// <summary>EC public key algorithm OID (id-ecPublicKey).</summary>
    public const string EcPublicKey = "1.2.840.10045.2.1";

    #endregion

    #region OCSP

    /// <summary>id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1) — marks OCSP responder certs as exempt from revocation checking.</summary>
    public const string OcspNoCheck = "1.3.6.1.5.5.7.48.1.5";

    #endregion

    #region Extended Key Usage

    /// <summary>Microsoft Document Signing EKU.</summary>
    public const string EkuDocumentSigning = "1.3.6.1.4.1.311.10.3.12";

    /// <summary>id-kp-emailProtection — S/MIME signing.</summary>
    public const string EkuEmailProtection = "1.3.6.1.5.5.7.3.4";

    /// <summary>id-kp-clientAuth — TLS client authentication.</summary>
    public const string EkuClientAuth = "1.3.6.1.5.5.7.3.2";

    #endregion

    #region CAdES XL/A Validation References

    /// <summary>id-aa-ets-certificateRefs (RFC 5126 §5.4.2) — CAdES-X/L.</summary>
    public const string CertificateRefs = "1.2.840.113549.1.9.16.2.21";

    /// <summary>id-aa-ets-revocationRefs (RFC 5126 §5.4.3) — CAdES-X/L.</summary>
    public const string RevocationRefs = "1.2.840.113549.1.9.16.2.22";

    /// <summary>id-aa-ets-certValues (RFC 5126 §5.5.1) — CAdES-XL.</summary>
    public const string CertValues = "1.2.840.113549.1.9.16.2.23";

    /// <summary>id-aa-ets-revocationValues (RFC 5126 §5.5.2) — CAdES-XL.</summary>
    public const string RevocationValues = "1.2.840.113549.1.9.16.2.24";

    /// <summary>id-aa-ets-archiveTimeStamp (RFC 5126 §6.3) — CAdES-A.</summary>
    public const string ArchiveTimeStamp = "1.2.840.113549.1.9.16.2.48";

    #endregion

    #region ICP-Brasil

    /// <summary>ICP-Brasil SAN: holder data containing CPF at positions 8–18.</summary>
    public const string IcpBrasilSanHolderData = "2.16.76.1.3.1";

    /// <summary>ICP-Brasil SAN: CNPJ (14 digits).</summary>
    public const string IcpBrasilSanCnpj = "2.16.76.1.3.3";

    #endregion
}
