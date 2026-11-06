using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Summary of the Document Security Store (DSS) dictionary embedded in the PDF.
/// The DSS contains revocation data for offline/archival validation (PAdES-B-LT/LTA).
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class DssInfo
{
    /// <summary>Number of CRL objects embedded in the DSS /CRLs array.</summary>
    public int CrlCount { get; init; }

    /// <summary>Number of OCSP response objects embedded in the DSS /OCSPs array.</summary>
    public int OcspResponseCount { get; init; }

    /// <summary>Number of certificate objects embedded in the DSS /Certs array.</summary>
    public int CertificateCount { get; init; }

    /// <summary>Whether the DSS contains a /VRI (Validation Related Information) dictionary.</summary>
    public bool HasVri { get; init; }

    /// <summary>Number of VRI entries found in the DSS /VRI dictionary.</summary>
    public int VriEntryCount { get; init; }

    /// <summary>Whether all VRI entries contain a /TU (time of validation) field (ISO 32000-2 §12.8.4.4).</summary>
    public bool VriHasTimestamps { get; init; }

    /// <summary>Warnings about VRI structure issues.</summary>
    public IReadOnlyList<string> VriWarnings { get; init; } = [];

    /// <summary>Whether any DSS data was found at all.</summary>
    public bool IsPresent => CrlCount > 0 || OcspResponseCount > 0 || CertificateCount > 0;

    /// <inheritdoc />
    public override string ToString() =>
        IsPresent
            ? $"DSS: {CrlCount} CRLs, {OcspResponseCount} OCSPs, {CertificateCount} certs"
            : "DSS: not present";
}
