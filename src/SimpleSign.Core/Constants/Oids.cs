namespace SimpleSign.Core.Constants;

/// <summary>
/// Standard OID (Object Identifier) constants used across the SimpleSign library.
/// Centralizes all OIDs to avoid duplication and improve discoverability.
/// </summary>
internal static class Oids
{
    #region Hash Algorithms

    /// <summary>SHA-256 (id-sha256) — default for ICP-Brasil and PAdES.</summary>
    internal const string Sha256 = "2.16.840.1.101.3.4.2.1";

    /// <summary>SHA-512 (id-sha512).</summary>
    internal const string Sha512 = "2.16.840.1.101.3.4.2.3";

    /// <summary>SHA-1 (id-sha1) — deprecated since 2016, supported for legacy validation.</summary>
    internal const string Sha1 = "1.3.14.3.2.26";

    #endregion

    #region Signature Algorithms

    /// <summary>RSA with SHA-256 (sha256WithRSAEncryption).</summary>
    internal const string RsaSha256 = "1.2.840.113549.1.1.11";

    /// <summary>RSA with SHA-384 (sha384WithRSAEncryption).</summary>
    internal const string RsaSha384 = "1.2.840.113549.1.1.12";

    /// <summary>RSA with SHA-512 (sha512WithRSAEncryption).</summary>
    internal const string RsaSha512 = "1.2.840.113549.1.1.13";

    /// <summary>RSA with SHA-1 (sha1WithRSAEncryption) — legacy.</summary>
    internal const string RsaSha1 = "1.2.840.113549.1.1.5";

    /// <summary>ECDSA with SHA-256.</summary>
    internal const string EcdsaSha256 = "1.2.840.10045.4.3.2";

    /// <summary>ECDSA with SHA-384.</summary>
    internal const string EcdsaSha384 = "1.2.840.10045.4.3.3";

    /// <summary>ECDSA with SHA-512.</summary>
    internal const string EcdsaSha512 = "1.2.840.10045.4.3.4";

    /// <summary>RSA-PSS (id-RSASSA-PSS) — signature algorithm with PSS padding.</summary>
    internal const string RsaPss = "1.2.840.113549.1.1.10";

    /// <summary>RSA encryption (rsaEncryption) — public key algorithm OID.</summary>
    internal const string RsaEncryption = "1.2.840.113549.1.1.1";

    /// <summary>EdDSA with Ed25519 (id-EdDSA).</summary>
    internal const string Ed25519 = "1.3.101.112";

    /// <summary>EdDSA with Ed448.</summary>
    internal const string Ed448 = "1.3.101.113";

    #endregion

    #region CMS / PKCS#7 Content Types

    /// <summary>id-data — CMS content type for arbitrary data.</summary>
    internal const string Data = "1.2.840.113549.1.7.1";

    /// <summary>id-signedData — CMS content type for signed data.</summary>
    internal const string SignedData = "1.2.840.113549.1.7.2";

    #endregion

    #region CMS Signed Attributes

    /// <summary>id-contentType — identifies the content type of the signed data.</summary>
    internal const string ContentType = "1.2.840.113549.1.9.3";

    /// <summary>id-messageDigest — hash of the signed content.</summary>
    internal const string MessageDigest = "1.2.840.113549.1.9.4";

    /// <summary>id-signingTime — time the signer claims to have signed.</summary>
    internal const string SigningTime = "1.2.840.113549.1.9.5";

    /// <summary>id-aa-signingCertificate (RFC 2634) — older version that uses SHA-1 hash.</summary>
    internal const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";

    /// <summary>id-aa-signingCertificateV2 (RFC 5035) — binds certificate to signature, required by PAdES-B-B.</summary>
    internal const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";

    /// <summary>id-aa-signatureTimeStampToken (RFC 3161) — timestamp token on the signature value.</summary>
    internal const string SignatureTimestampToken = "1.2.840.113549.1.9.16.2.14";

    /// <summary>id-aa-ets-commitmentType (RFC 5126 §5.11.1) — commitment type indication.</summary>
    internal const string CommitmentTypeIndication = "1.2.840.113549.1.9.16.2.16";

    /// <summary>id-aa-ets-sigPolicyId (RFC 5126 §5.8.1) — signature policy identifier.</summary>
    internal const string SignaturePolicyIdentifier = "1.2.840.113549.1.9.16.2.15";

    /// <summary>id-cti-ets-proofOfOrigin — signer is the author.</summary>
    internal const string ProofOfOrigin = "1.2.840.113549.1.9.16.6.1";

    /// <summary>id-cti-ets-proofOfApproval — signer approves the content.</summary>
    internal const string ProofOfApproval = "1.2.840.113549.1.9.16.6.5";

    /// <summary>
    /// SimpleSign signature manifest — JSON-encoded AEA evidence (name, CPF, email, IP, auth method).
    /// OID arc: 2.16.76 (Brazil) / 1.12 (electronic signature extensions) / 1.1 (manifest v1).
    /// Embedded as a CMS signed attribute to be tamper-proof.
    /// </summary>
    internal const string SignatureManifest = "2.16.76.1.12.1.1";

    #endregion

    #region X.509 Extensions

    /// <summary>id-pe-authorityInfoAccess — AIA extension for OCSP and CA Issuers.</summary>
    internal const string AuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";

    /// <summary>id-ad-ocsp — OCSP responder access method within AIA.</summary>
    internal const string AdOcsp = "1.3.6.1.5.5.7.48.1";

    /// <summary>id-ad-caIssuers — CA Issuers access method within AIA.</summary>
    internal const string AdCaIssuers = "1.3.6.1.5.5.7.48.2";

    #endregion

    #region X.509 Standard Extensions

    /// <summary>id-ce-subjectAltName (SAN).</summary>
    internal const string SubjectAltName = "2.5.29.17";

    /// <summary>id-ce-cRLDistributionPoints (CDP).</summary>
    internal const string CrlDistributionPoints = "2.5.29.31";

    /// <summary>id-ce-certificatePolicies.</summary>
    internal const string CertificatePolicies = "2.5.29.32";

    /// <summary>SHA-384 hash algorithm OID.</summary>
    internal const string Sha384 = "2.16.840.1.101.3.4.2.2";

    /// <summary>EC public key algorithm OID (id-ecPublicKey).</summary>
    internal const string EcPublicKey = "1.2.840.10045.2.1";

    #endregion

    #region Extended Key Usage

    /// <summary>Microsoft Document Signing EKU.</summary>
    internal const string EkuDocumentSigning = "1.3.6.1.4.1.311.10.3.12";

    /// <summary>id-kp-emailProtection — S/MIME signing.</summary>
    internal const string EkuEmailProtection = "1.3.6.1.5.5.7.3.4";

    /// <summary>id-kp-clientAuth — TLS client authentication.</summary>
    internal const string EkuClientAuth = "1.3.6.1.5.5.7.3.2";

    #endregion

    #region ICP-Brasil

    /// <summary>ICP-Brasil SAN: holder data containing CPF at positions 8–18.</summary>
    internal const string IcpBrasilSanHolderData = "2.16.76.1.3.1";

    /// <summary>ICP-Brasil SAN: CNPJ (14 digits).</summary>
    internal const string IcpBrasilSanCnpj = "2.16.76.1.3.3";

    #endregion
}
