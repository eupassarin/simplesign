using SimpleSign.Signers.Pkcs11;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>
/// The cryptographic module the operator declares: its manufacturer and model as the PKCS#11 driver reports them
/// (<c>simplesign pkcs11 list</c>), and its certification. The token in use must be that module; the certification
/// itself (guide Req. 15: FIPS 140-2 or Common Criteria EAL 4+) is a statement of the operator, which software cannot
/// check: it is what the accreditation audit confirms against the certificate number given here.
/// </summary>
/// <param name="Manufacturer">The manufacturer, as the driver reports it.</param>
/// <param name="Model">The model, as the driver reports it.</param>
/// <param name="Certification">The certification of the module (e.g. <c>FIPS 140-2 Level 3</c>).</param>
/// <param name="CertificateNumber">The number of the certificate of that certification.</param>
public sealed record IofeModuleDeclaration(string Manufacturer, string Model, string Certification, string CertificateNumber)
{
    // The lengths of manufacturerID and model in CK_TOKEN_INFO: a longer name is cut there by the driver.
    private const int ManufacturerFieldLength = 32;
    private const int ModelFieldLength = 16;

    /// <summary>Whether <paramref name="token"/> is the declared module.</summary>
    /// <param name="token">The token in use.</param>
    /// <returns>True when its manufacturer and model are the declared ones.</returns>
    public bool Matches(Pkcs11Signer token)
    {
        ArgumentNullException.ThrowIfNull(token);
        return Matches(token.TokenManufacturer, token.TokenModel);
    }

    /// <summary>Whether a token reporting this manufacturer and model is the declared module.</summary>
    internal bool Matches(string reportedManufacturer, string reportedModel) =>
        Same(Manufacturer, reportedManufacturer, ManufacturerFieldLength) && Same(Model, reportedModel, ModelFieldLength);

    private static bool Same(string declared, string reported, int fieldLength)
    {
        string a = declared.Trim();
        string b = reported.Trim();
        return b.Length > 0
            && (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)
                || (b.Length == fieldLength && a.StartsWith(b, StringComparison.OrdinalIgnoreCase)));
    }
}

/// <summary>The cryptographic module a signer of this package uses.</summary>
/// <param name="TokenLabel">The label of the token.</param>
/// <param name="Manufacturer">Its manufacturer, as the driver reports it.</param>
/// <param name="Model">Its model, as the driver reports it.</param>
/// <param name="SerialNumber">Its serial number.</param>
/// <param name="KeyProtection">How it protects the signing key.</param>
/// <param name="Declaration">What the operator declared about it.</param>
public sealed record IofeModuleInfo(
    string TokenLabel,
    string Manufacturer,
    string Model,
    string SerialNumber,
    Pkcs11KeyProtection KeyProtection,
    IofeModuleDeclaration Declaration);
