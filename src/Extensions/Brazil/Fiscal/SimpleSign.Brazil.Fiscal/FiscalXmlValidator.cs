using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.XAdES;

namespace SimpleSign.Brazil.Fiscal;

/// <summary>One XML-DSig signature of a fiscal XML.</summary>
public sealed class FiscalSignatureResult
{
    /// <summary>What the XML-DSig check found: digest, signature value, chain, certificate.</summary>
    public required XmlDsigSignatureResult Signature { get; init; }

    /// <summary>CNPJ of an e-CNPJ signer.</summary>
    public string? Cnpj { get; init; }

    /// <summary>CPF of an e-CPF signer (or of the person responsible for an e-CNPJ).</summary>
    public string? Cpf { get; init; }

    /// <summary>What the layout requires and the signature does not do (another element signed, another hash).</summary>
    public IReadOnlyList<string> LayoutErrors { get; init; } = [];

    /// <summary>Every problem: the signature's and the layout's.</summary>
    public IReadOnlyList<string> Errors => [.. Signature.Errors, .. LayoutErrors];

    /// <summary>The signature is valid and follows the layout.</summary>
    public bool IsValid => Signature.IsValid && LayoutErrors.Count == 0;
}

/// <summary>The signatures found in a fiscal XML.</summary>
public sealed class FiscalValidationResult
{
    /// <summary>Every ds:Signature of the document, in document order.</summary>
    public IReadOnlyList<FiscalSignatureResult> Signatures { get; init; } = [];

    /// <summary>Errors about the document itself (unreadable XML, no signature).</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>The document has at least one signature and all of them are valid.</summary>
    public bool IsValid => Errors.Count == 0 && Signatures.Count > 0 && Signatures.All(s => s.IsValid);
}

/// <summary>
/// Validates the XML-DSig signatures of fiscal XML: the reference digest (with the enveloped-signature transform), the
/// SignatureValue, a duplicate Id refused (signature wrapping) and, with <see cref="ValidateAsync"/>, the ICP-Brasil
/// chain of the signer with its revocation. Given the layout, each signature must also sign the layout's element with
/// its hash.
/// </summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class FiscalXmlValidator
{
    private readonly XmlDsigValidator _validator;

    /// <summary>Creates a validator under <paramref name="profile"/> (default: <see cref="IcpBrasilProfile.Create"/>).</summary>
    /// <param name="profile">The trust profile whose chain validation checks the signers.</param>
    public FiscalXmlValidator(TrustProfile? profile = null)
    {
        _validator = new XmlDsigValidator(profile ?? IcpBrasilProfile.Create());
    }

    /// <summary>Creates a validator under ICP-Brasil with <paramref name="options"/> (the HTTP client of the LCR/OCSP checks).</summary>
    /// <param name="options">The ICP-Brasil options.</param>
    public FiscalXmlValidator(IcpBrasilExtensionOptions options)
        : this(IcpBrasilProfile.Create(options))
    {
    }

    /// <summary>Checks digests, signature values and, given it, the layout (offline: no chain, no network).</summary>
    /// <param name="xml">The signed XML.</param>
    /// <param name="layout">The layout the signatures must follow, or null.</param>
    /// <returns>The signatures found.</returns>
    public static FiscalValidationResult VerifySignatures(byte[] xml, FiscalDocumentProfile? layout = null) =>
        From(XmlDsigValidator.VerifySignatures(xml), layout);

    /// <summary>Checks digests, signature values, the layout and the ICP-Brasil chain of each signer.</summary>
    /// <param name="xml">The signed XML.</param>
    /// <param name="layout">The layout the signatures must follow, or null.</param>
    /// <param name="checkRevocation">Whether to check LCR/OCSP online.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signatures found.</returns>
    public async Task<FiscalValidationResult> ValidateAsync(
        byte[] xml, FiscalDocumentProfile? layout = null, bool checkRevocation = true, CancellationToken cancellationToken = default) =>
        From(await _validator.ValidateAsync(xml, checkRevocation, cancellationToken).ConfigureAwait(false), layout);

    private static FiscalValidationResult From(XmlDsigValidationResult result, FiscalDocumentProfile? layout) => new()
    {
        Errors = result.Errors,
        Signatures = [.. result.Signatures.Select(s => new FiscalSignatureResult
        {
            Signature = s,
            Cnpj = Identifier(s, SignerIdentifierTypes.Cnpj),
            Cpf = Identifier(s, SignerIdentifierTypes.Cpf) ?? Identifier(s, SignerIdentifierTypes.ResponsibleCpf),
            LayoutErrors = layout is null ? [] : LayoutErrors(s, layout),
        })],
    };

    private static string? Identifier(XmlDsigSignatureResult signature, string type)
    {
        if (signature.SignerIdentifiers.TryGetValue(type, out var values) && values.Count > 0)
        {
            return values[0];
        }

        return signature.Certificate is { } certificate && BrazilSignerIdentityReader.Instance.Read(certificate, type) is [var first, ..]
            ? first
            : null;
    }

    private static List<string> LayoutErrors(XmlDsigSignatureResult signature, FiscalDocumentProfile layout)
    {
        var errors = new List<string>();
        bool wholeDocument = layout.SignedElement is null;
        bool signsAnother = wholeDocument
            ? signature.ReferenceUri.Length != 0
            : signature.ReferenceUri.Length == 0
                || (layout.SignedElement != "*" && signature.SignedElement is { } element && element != layout.SignedElement);
        if (signsAnother)
        {
            errors.Add($"The {layout.Name} layout signs {(wholeDocument ? "the whole document" : layout.SignedElement)}; this signature signs {(signature.ReferenceUri.Length == 0 ? "the whole document" : signature.SignedElement ?? signature.ReferenceUri)}.");
        }

        if (signature.HashAlgorithm is { } hash && new HashAlgorithmName(hash) != layout.HashAlgorithm)
        {
            errors.Add($"The {layout.Name} layout signs with {layout.HashAlgorithm.Name}; this signature uses {hash}.");
        }

        return errors;
    }
}
