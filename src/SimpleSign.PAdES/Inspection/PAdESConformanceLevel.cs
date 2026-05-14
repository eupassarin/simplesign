namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// PAdES conformance level of a digital signature, as defined by ETSI EN 319 142.
/// </summary>
public enum PAdESConformanceLevel
{
    /// <summary>Conformance level could not be determined.</summary>
    Unknown = 0,

    /// <summary>
    /// CMS signature (adbe.pkcs7.detached) without PAdES-specific attributes.
    /// Valid signature but does not meet PAdES baseline requirements.
    /// Common in older or simpler signing tools (including some Gov.br signers).
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
