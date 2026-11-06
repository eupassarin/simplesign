using System.Security.Cryptography;
using SimpleSign.Core.Constants;

namespace SimpleSign.Brasil.Fiscal;

/// <summary>Where the <c>Signature</c> element goes.</summary>
public enum FiscalSignaturePlacement
{
    /// <summary>Right after the signed element, as its sibling (NF-e: <c>&lt;NFe&gt;&lt;infNFe/&gt;&lt;Signature/&gt;&lt;/NFe&gt;</c>).</summary>
    AfterSignedElement,

    /// <summary>As the last child of the document element (eSocial, EFD-Reinf).</summary>
    LastChildOfRoot,
}

/// <summary>
/// The XMLDSig profile of a fiscal XML layout: which element is signed (by its Id attribute,
/// or the whole document), the hash algorithm, the canonicalization and where the signature goes.
/// Every profile uses an enveloped signature with the enveloped-signature and canonicalization
/// transforms and puts only the signer certificate in <c>KeyInfo/X509Data</c>.
/// Create your own record for a layout or a version that differs.
/// </summary>
/// <param name="Name">Display name of the layout.</param>
/// <param name="SignedElement">Local name of the signed element (any namespace); <c>*</c> = any element carrying <paramref name="IdAttribute"/>; null = the whole document (<c>URI=""</c>).</param>
/// <param name="IdAttribute">Name of the Id attribute the Reference points to (<c>Id</c>, or <c>id</c> in EFD-Reinf); null with <c>URI=""</c>.</param>
/// <param name="HashAlgorithm">Digest and RSA signature hash (SHA-1 in the SEFAZ layouts, SHA-256 in eSocial/Reinf).</param>
/// <param name="Placement">Where the Signature element is inserted.</param>
/// <param name="CanonicalizationMethod">Canonicalization of SignedInfo and of the reference (C14N 1.0 by default).</param>
public sealed record FiscalDocumentProfile(
    string Name,
    string? SignedElement,
    string? IdAttribute,
    HashAlgorithmName HashAlgorithm,
    FiscalSignaturePlacement Placement,
    string CanonicalizationMethod = XmlDSigUrls.C14N)
{
    /// <summary>NF-e / NFC-e 4.00 (MOC): <c>infNFe@Id</c>, RSA-SHA1, Signature after infNFe.</summary>
    public static FiscalDocumentProfile NFe { get; } = new("NF-e", "infNFe", "Id", HashAlgorithmName.SHA1, FiscalSignaturePlacement.AfterSignedElement);

    /// <summary>NF-e / CT-e / MDF-e events (<c>infEvento@Id</c>), RSA-SHA1.</summary>
    public static FiscalDocumentProfile Evento { get; } = new("Evento", "infEvento", "Id", HashAlgorithmName.SHA1, FiscalSignaturePlacement.AfterSignedElement);

    /// <summary>NF-e number voiding (<c>infInut@Id</c>), RSA-SHA1.</summary>
    public static FiscalDocumentProfile Inutilizacao { get; } = new("Inutilização", "infInut", "Id", HashAlgorithmName.SHA1, FiscalSignaturePlacement.AfterSignedElement);

    /// <summary>CT-e / CT-e OS 4.00 (<c>infCte@Id</c>), RSA-SHA1.</summary>
    public static FiscalDocumentProfile CTe { get; } = new("CT-e", "infCte", "Id", HashAlgorithmName.SHA1, FiscalSignaturePlacement.AfterSignedElement);

    /// <summary>MDF-e 3.00 (<c>infMDFe@Id</c>), RSA-SHA1.</summary>
    public static FiscalDocumentProfile MDFe { get; } = new("MDF-e", "infMDFe", "Id", HashAlgorithmName.SHA1, FiscalSignaturePlacement.AfterSignedElement);

    /// <summary>
    /// NFS-e Padrão Nacional DPS (<c>infDPS@Id</c>), RSA-SHA256. Integrators report both SHA-1 and
    /// SHA-256; confirm with the current ADN/Sefin Nacional manual (use <c>with { HashAlgorithm = … }</c>).
    /// </summary>
    public static FiscalDocumentProfile NFSeDps { get; } = new("NFS-e DPS", "infDPS", "Id", HashAlgorithmName.SHA256, FiscalSignaturePlacement.AfterSignedElement);

    /// <summary>eSocial S-1.x events: whole document (<c>URI=""</c>), RSA-SHA256, Signature as the last child of <c>eSocial</c>.</summary>
    public static FiscalDocumentProfile ESocial { get; } = new("eSocial", null, null, HashAlgorithmName.SHA256, FiscalSignaturePlacement.LastChildOfRoot);

    /// <summary>EFD-Reinf 2.1 events: the event element by its <c>id</c> attribute (lowercase), RSA-SHA256, Signature as the last child of <c>Reinf</c>.</summary>
    public static FiscalDocumentProfile Reinf { get; } = new("EFD-Reinf", "*", "id", HashAlgorithmName.SHA256, FiscalSignaturePlacement.LastChildOfRoot);

    /// <summary>The built-in profiles by short name: nfe, evento, inutilizacao, cte, mdfe, nfse, esocial, reinf.</summary>
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
}
