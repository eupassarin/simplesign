using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Policies;
using SimpleSign.XAdES;

namespace SimpleSign.Brazil.Fiscal;

/// <summary>
/// The XML-DSig profile of a fiscal layout: which element is signed (by its Id attribute, or the whole document), the
/// hash, the canonicalization and where the signature goes. Every profile makes an enveloped signature with the
/// enveloped-signature and canonicalization transforms, RSA, and only the signer certificate in <c>KeyInfo/X509Data</c>.
/// Create your own record for a layout or a version that differs (<c>FiscalDocumentProfile.NFSeDps with { HashAlgorithm = … }</c>).
/// </summary>
/// <param name="Name">Display name of the layout.</param>
/// <param name="SignedElement">Local name of the signed element (any namespace); <c>*</c> = any element carrying
/// <paramref name="IdAttribute"/>; null = the whole document (<c>URI=""</c>).</param>
/// <param name="IdAttribute">Name of the Id attribute the Reference points to (<c>Id</c>; <c>id</c> in EFD-Reinf); null with <c>URI=""</c>.</param>
/// <param name="HashAlgorithm">Digest and RSA signature hash (SHA-1 in the SEFAZ layouts, SHA-256 in eSocial/Reinf).</param>
/// <param name="Placement">Where the Signature element is inserted.</param>
/// <param name="Canonicalization">Canonicalization of SignedInfo and of the reference (C14N 1.0 in every layout).</param>
public sealed record FiscalDocumentProfile(
    string Name,
    string? SignedElement,
    string? IdAttribute,
    HashAlgorithmName HashAlgorithm,
    XmlDsigPlacement Placement,
    XadesCanonicalization Canonicalization = XadesCanonicalization.Inclusive)
{
    /// <summary>NF-e / NFC-e 4.00 (MOC): <c>infNFe@Id</c>, RSA-SHA1, Signature after infNFe.</summary>
    public static FiscalDocumentProfile NFe { get; } = new("NF-e", "infNFe", "Id", HashAlgorithmName.SHA1, XmlDsigPlacement.AfterSignedElement);

    /// <summary>NF-e / CT-e / MDF-e events (<c>infEvento@Id</c>), RSA-SHA1.</summary>
    public static FiscalDocumentProfile Evento { get; } = new("Evento", "infEvento", "Id", HashAlgorithmName.SHA1, XmlDsigPlacement.AfterSignedElement);

    /// <summary>NF-e number voiding (<c>infInut@Id</c>), RSA-SHA1.</summary>
    public static FiscalDocumentProfile Inutilizacao { get; } = new("Inutilização", "infInut", "Id", HashAlgorithmName.SHA1, XmlDsigPlacement.AfterSignedElement);

    /// <summary>CT-e / CT-e OS 4.00 (<c>infCte@Id</c>), RSA-SHA1.</summary>
    public static FiscalDocumentProfile CTe { get; } = new("CT-e", "infCte", "Id", HashAlgorithmName.SHA1, XmlDsigPlacement.AfterSignedElement);

    /// <summary>MDF-e 3.00 (<c>infMDFe@Id</c>), RSA-SHA1.</summary>
    public static FiscalDocumentProfile MDFe { get; } = new("MDF-e", "infMDFe", "Id", HashAlgorithmName.SHA1, XmlDsigPlacement.AfterSignedElement);

    /// <summary>
    /// NFS-e Padrão Nacional DPS (<c>infDPS@Id</c>), RSA-SHA256. Integrators report both SHA-1 and SHA-256; confirm with
    /// the current ADN/Sefin Nacional manual (use <c>with { HashAlgorithm = … }</c>).
    /// </summary>
    public static FiscalDocumentProfile NFSeDps { get; } = new("NFS-e DPS", "infDPS", "Id", HashAlgorithmName.SHA256, XmlDsigPlacement.AfterSignedElement);

    /// <summary>eSocial S-1.x events: the whole document (<c>URI=""</c>), RSA-SHA256, Signature as the last child of <c>eSocial</c>.</summary>
    public static FiscalDocumentProfile ESocial { get; } = new("eSocial", null, null, HashAlgorithmName.SHA256, XmlDsigPlacement.LastChildOfRoot);

    /// <summary>EFD-Reinf 2.1 events: the event element by its <c>id</c> attribute (lowercase), RSA-SHA256, Signature as the last child of <c>Reinf</c>.</summary>
    public static FiscalDocumentProfile Reinf { get; } = new("EFD-Reinf", "*", "id", HashAlgorithmName.SHA256, XmlDsigPlacement.LastChildOfRoot);

    /// <summary>The built-in profiles by short name: nfe, nfce, evento, inutilizacao, cte, mdfe, nfse, esocial, reinf.</summary>
    public static IReadOnlyDictionary<string, FiscalDocumentProfile> ByName { get; } = new Dictionary<string, FiscalDocumentProfile>(StringComparer.OrdinalIgnoreCase)
    {
        ["nfe"] = NFe,
        ["nfce"] = NFe,
        ["evento"] = Evento,
        ["inutilizacao"] = Inutilizacao,
        ["cte"] = CTe,
        ["mdfe"] = MDFe,
        ["nfse"] = NFSeDps,
        ["esocial"] = ESocial,
        ["reinf"] = Reinf,
    };

    /// <summary>
    /// The signing policy the layout is signed under: <see cref="FiscalPolicies.Sefaz"/> when the layout mandates SHA-1,
    /// <see cref="IcpBrasilPolicies.Signing"/> otherwise.
    /// </summary>
    public SigningPolicy SigningPolicy => HashAlgorithm == HashAlgorithmName.SHA1 ? FiscalPolicies.Sefaz : IcpBrasilPolicies.Signing;

    /// <summary>Sets on <paramref name="builder"/> what the layout fixes: the signed element, the placement, the hash and the canonicalization.</summary>
    /// <param name="builder">A one-call XML-DSig builder.</param>
    /// <returns>The configured builder.</returns>
    [RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
    [RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
    public XmlDsigSignerBuilder Apply(XmlDsigSignerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var target = SignedElement is null ? builder.WithWholeDocument() : builder.WithSignedElement(SignedElement, IdAttribute ?? "Id");
        return target.WithPlacement(Placement).WithHashAlgorithm(HashAlgorithm).WithCanonicalization(Canonicalization);
    }
}
