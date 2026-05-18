namespace SimpleSign.PAdES.Signing;

/// <summary>Options for creating a PDF signature field.</summary>
public sealed class SignatureFieldOptions
{
    /// <summary>PDF field name for the signature. Defaults to "Signature1".</summary>
    public string FieldName { get; init; } = "Signature1";

    /// <summary>Signer name to embed in the signature dictionary /Name entry.</summary>
    public string? SignerName { get; init; }

    /// <summary>Signing reason to embed in the signature dictionary /Reason entry.</summary>
    public string? Reason { get; init; }

    /// <summary>Signing location to embed in the signature dictionary /Location entry.</summary>
    public string? Location { get; init; }

    /// <summary>Contact information to embed in the signature dictionary /ContactInfo entry. Shown in Adobe's "Signature Properties".</summary>
    public string? ContactInfo { get; init; }

    /// <summary>Number of bytes reserved for the /Contents value. Defaults to 16384 (16 KB).</summary>
    public int ContentsReservedBytes { get; init; } = 16384;

    /// <summary>SubFilter value identifying the CMS format. Defaults to <see cref="PdfSignatureSubFilter.EtsiCadesDetached"/>.</summary>
    public PdfSignatureSubFilter SubFilter { get; init; } = PdfSignatureSubFilter.EtsiCadesDetached;

    /// <summary>Optional visual appearance settings. When null, an invisible signature is created.</summary>
    public SignatureAppearance? Appearance { get; init; }

    /// <summary>
    /// When set, creates a certification (DocMDP) signature that restricts subsequent modifications.
    /// Only the first signature in a document can be a certification signature.
    /// </summary>
    public CertificationLevel? CertificationLevel { get; init; }

    /// <summary>
    /// When set, signs an existing empty signature field instead of creating a new one.
    /// The field must exist and have an empty /V value.
    /// </summary>
    public string? ExistingFieldName { get; init; }
}
