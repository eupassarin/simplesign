using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Xml;

/// <summary>Which XML signature the page makes.</summary>
public enum XmlMode
{
    /// <summary>XAdES (ETSI EN 319 132) with <c>XadesSigner</c>.</summary>
    Xades,

    /// <summary>Plain XML-DSig of the Brazilian fiscal layouts with <c>FiscalXmlSigner</c>.</summary>
    Fiscal,
}

/// <summary>XAdES packaging (<c>XadesForm</c>).</summary>
public enum XadesFormChoice
{
    Enveloped,
    Detached,
    Enveloping,
}

public enum XadesKind
{
    Baseline,
    IcpBrasil,
    CustomPolicy,
}

/// <summary>ICP-Brasil XAdES policies (DOC-ICP-15.03).</summary>
public enum XadesIcpPolicy
{
    AdRb,
    AdRt,
    AdRv,
    AdRc,
    AdRa,
}

/// <summary><c>XadesExtendedForm</c>: XAdES-C/X, X-L and A.</summary>
public enum XadesExtendedChoice
{
    None,
    CompleteReferences,
    ExtendedLong,
    Archive,
}

/// <summary>Everything the XML page can choose. Evaluated by <see cref="XmlCompatibility"/>.</summary>
public sealed record XmlOptions
{
    public EnvironmentMode Environment { get; init; } = EnvironmentMode.Sandbox;

    public XmlMode Mode { get; init; } = XmlMode.Xades;

    public string? DataId { get; init; }

    public string? CredentialId { get; init; }

    // ── XAdES ──
    public XadesFormChoice Form { get; init; } = XadesFormChoice.Enveloped;

    /// <summary>The Reference URI of a detached signature (where the data will be found).</summary>
    public string DataUri { get; init; } = "document.xml";

    public XadesKind Kind { get; init; } = XadesKind.Baseline;

    public BaselineLevel Level { get; init; } = BaselineLevel.BB;

    public XadesIcpPolicy IcpPolicy { get; init; } = XadesIcpPolicy.AdRb;

    public string PolicyOid { get; init; } = "1.2.3.4.5";

    public string? PolicyUri { get; init; }

    public XadesExtendedChoice ExtendedForm { get; init; } = XadesExtendedChoice.None;

    public TimestampChoice Timestamp { get; init; } = new();

    public HashChoice Hash { get; init; } = HashChoice.Sha256;

    public RsaPadding Padding { get; init; } = RsaPadding.Pkcs1;

    /// <summary>XAdES 1.3.2 SigningCertificate (V1) instead of SigningCertificateV2.</summary>
    public bool SigningCertificateV1 { get; init; }

    public IReadOnlyList<string> SignerRoles { get; init; } = [];

    /// <summary>DataObjectFormat MIME type (null: none).</summary>
    public string? MimeType { get; init; }

    public string? Commitment { get; init; }

    public DateTimeOffset? SigningTime { get; init; }

    public string? OperationId { get; init; }

    // ── Fiscal ──

    /// <summary>A <c>FiscalDocumentProfile.ByName</c> key: nfe, evento, inutilizacao, cte, mdfe, nfse, esocial, reinf.</summary>
    public string Profile { get; init; } = "nfe";

    /// <summary>The Id of the element to sign when the document has several (Sign).</summary>
    public string? ElementId { get; init; }

    /// <summary><c>FiscalXmlSigner.SignAll</c>: every unsigned element of the profile.</summary>
    public bool SignAll { get; init; }

    public bool Validate { get; init; } = true;

    public ValidationSettings? Validation { get; init; }
}
