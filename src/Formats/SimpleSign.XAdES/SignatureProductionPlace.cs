namespace SimpleSign.XAdES;

/// <summary>
/// Where the signer was when signing: the SignatureProductionPlaceV2 signed property
/// (ETSI EN 319 132-1 §5.2.5), or the SignatureProductionPlace of XAdES 1.3.2 when the signature
/// uses <see cref="XadesSigningCertificateForm.V1"/>. At least one field must be set.
/// </summary>
public sealed record SignatureProductionPlace
{
    /// <summary>The city.</summary>
    public string? City { get; init; }

    /// <summary>The street address. Not available in the XAdES 1.3.2 form.</summary>
    public string? StreetAddress { get; init; }

    /// <summary>The state or province.</summary>
    public string? StateOrProvince { get; init; }

    /// <summary>The postal code.</summary>
    public string? PostalCode { get; init; }

    /// <summary>The country name.</summary>
    public string? CountryName { get; init; }
}
