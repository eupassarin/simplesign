namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// PAdES conformance level of a digital signature, as defined by ETSI EN 319 142.
/// </summary>
public enum PAdESConformanceLevel
{
    /// <summary>Conformance level could not be determined.</summary>
    Unknown = 0,

    /// <summary>
    /// A CMS signature that is not a PAdES baseline signature: it has no ESS signing-certificate attribute, or its
    /// SubFilter is not ETSI.CAdES.detached (adbe.pkcs7.detached, PBAD.PAdES), which EN 319 142-1 requires.
    /// It may still be a valid signature. Common in older or simpler signing tools (including some Gov.br signers),
    /// in signatures kept compatible with PDF/A-1, and in the ICP-Brasil signature dictionary.
    /// </summary>
    CmsOnly = 1,

    /// <summary>
    /// PAdES-B-B (Basic): CMS signature with signingCertificateV2 attribute.
    /// Minimum viable PAdES signature.
    /// </summary>
    BaselineB = 2,

    /// <summary>
    /// PAdES-B-T (Timestamp): B-B plus an RFC 3161 signature timestamp token.
    /// Provides proof of existence at a given time.
    /// </summary>
    BaselineT = 3,

    /// <summary>
    /// PAdES-B-LT (Long-Term): B-T plus a DSS dictionary with embedded revocation data.
    /// Enables offline validation without network access.
    /// </summary>
    BaselineLT = 4,

    /// <summary>
    /// PAdES-B-LTA (Long-Term Archival): B-LT plus a document-level timestamp.
    /// Highest conformance level — survives certificate expiration.
    /// </summary>
    BaselineLTA = 5
}
