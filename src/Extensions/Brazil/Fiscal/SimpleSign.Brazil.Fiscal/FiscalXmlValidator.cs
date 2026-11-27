using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Xml;
using SimpleSign.Brazil.Fiscal.Internal;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.XAdES;

namespace SimpleSign.Brazil.Fiscal;

/// <summary>One XML-DSig signature of a fiscal XML.</summary>
public sealed class FiscalSignatureResult
{
    /// <summary>What the XML-DSig check found: digest, signature value, chain, certificate.</summary>
    public required XmlDsigSignatureResult Signature { get; init; }

    /// <summary>
    /// In an eSocial or EFD-Reinf batch (<c>envioLoteEventos</c>), the Id of the <c>evento</c> that holds this
    /// signature; null outside a batch. Each event of a batch is validated as the document it was when signed.
    /// </summary>
    public string? BatchEventId { get; init; }

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

    /// <summary>Errors about the document itself (unreadable XML, no signature; in a batch, an event not signed or the batch signed itself).</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>The document has at least one signature and all of them are valid.</summary>
    public bool IsValid => Errors.Count == 0 && Signatures.Count > 0 && Signatures.All(s => s.IsValid);
}

/// <summary>
/// Validates the XML-DSig signatures of fiscal XML: the reference digest (with the enveloped-signature transform), the
/// SignatureValue, a duplicate Id refused (signature wrapping) and, with <see cref="ValidateAsync"/>, the ICP-Brasil
/// chain of the signer with its revocation. Given the layout, each signature must also sign the layout's element with
/// its hash. In an eSocial or EFD-Reinf batch (<c>envioLoteEventos</c>) each event is validated on its own, as the
/// document it was when signed (<see cref="FiscalSignatureResult.BatchEventId"/>): its <c>URI=""</c> means the event,
/// not the batch.
/// </summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class FiscalXmlValidator
{
    private readonly XmlDsigValidator _validator;

    /// <summary>Creates a validator under <paramref name="profile"/> (default: <see cref="IcpBrasilProfile.Create"/>).</summary>
    /// <param name="profile">The trust profile whose chain validation checks the signers.</param>
    /// <param name="httpClientProvider">The HTTP of the AIA downloads of a chain outside the profile's providers.</param>
    public FiscalXmlValidator(TrustProfile? profile = null, SimpleSign.Core.Http.IHttpClientProvider? httpClientProvider = null)
    {
        _validator = new XmlDsigValidator(profile ?? IcpBrasilProfile.Create(), httpClientProvider);
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
    public static FiscalValidationResult VerifySignatures(byte[] xml, FiscalDocumentProfile? layout = null)
    {
        ArgumentNullException.ThrowIfNull(xml);
        if (Batch(xml) is not { } batch)
        {
            return From(XmlDsigValidator.VerifySignatures(xml), layout);
        }

        var (document, events) = batch;
        return FromBatch(document, events, [.. events.Select(e => e.Xml is null ? null : XmlDsigValidator.VerifySignatures(e.Xml))], layout);
    }

    /// <summary>Checks digests, signature values, the layout and the ICP-Brasil chain of each signer.</summary>
    /// <param name="xml">The signed XML.</param>
    /// <param name="layout">The layout the signatures must follow, or null.</param>
    /// <param name="checkRevocation">Whether to check LCR/OCSP online.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signatures found.</returns>
    public async Task<FiscalValidationResult> ValidateAsync(
        byte[] xml, FiscalDocumentProfile? layout = null, bool checkRevocation = true, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(xml);
        if (Batch(xml) is not { } batch)
        {
            return From(await _validator.ValidateAsync(xml, checkRevocation, cancellationToken).ConfigureAwait(false), layout);
        }

        var (document, events) = batch;
        var results = new List<XmlDsigValidationResult?>(events.Count);
        foreach (var batchEvent in events)
        {
            results.Add(batchEvent.Xml is null ? null : await _validator.ValidateAsync(batchEvent.Xml, checkRevocation, cancellationToken).ConfigureAwait(false));
        }

        return FromBatch(document, events, results, layout);
    }

    /// <summary>The document and its events when <paramref name="xml"/> is an eSocial or EFD-Reinf batch; null otherwise.</summary>
    private static (XmlDocument Document, List<FiscalBatchEvent> Events)? Batch(byte[] xml) =>
        FiscalEventBatch.Load(xml) is { } document && FiscalEventBatch.Batch(document) is { } batch
            ? (document, FiscalEventBatch.Events(batch))
            : null;

    private static FiscalValidationResult From(XmlDsigValidationResult result, FiscalDocumentProfile? layout) => new()
    {
        Errors = result.Errors,
        Signatures = [.. Map(result.Signatures, layout, batchEventId: null)],
    };

    /// <summary>The signatures of every event of a batch, and what is wrong with the batch: no event, an event not signed, a signature of the batch itself.</summary>
    private static FiscalValidationResult FromBatch(
        XmlDocument document, List<FiscalBatchEvent> events, IReadOnlyList<XmlDsigValidationResult?> results, FiscalDocumentProfile? layout)
    {
        var errors = new List<string>();
        var signatures = new List<FiscalSignatureResult>();
        if (events.Count == 0)
        {
            errors.Add("The eSocial/EFD-Reinf batch has no event.");
        }

        if (FiscalEventBatch.SignaturesOutsideEvents(document) > 0)
        {
            errors.Add("The batch itself is signed: eSocial and EFD-Reinf sign each event, not the batch.");
        }

        for (int i = 0; i < events.Count; i++)
        {
            string name = events[i].Id is { } id ? $"The event {id}" : $"Event {i + 1} of the batch";
            if (results[i] is not { } result)
            {
                errors.Add($"{name} is empty.");
            }
            else if (result.Signatures.Count == 0)
            {
                errors.Add($"{name} is not signed.");
            }
            else
            {
                errors.AddRange(result.Errors.Select(e => $"{name}: {e}"));
                signatures.AddRange(Map(result.Signatures, layout, events[i].Id));
            }
        }

        return new FiscalValidationResult { Errors = errors.AsReadOnly(), Signatures = signatures.AsReadOnly() };
    }

    private static IEnumerable<FiscalSignatureResult> Map(
        IEnumerable<XmlDsigSignatureResult> signatures, FiscalDocumentProfile? layout, string? batchEventId) =>
        signatures.Select(s => new FiscalSignatureResult
        {
            Signature = s,
            BatchEventId = batchEventId,
            Cnpj = Identifier(s, SignerIdentifierTypes.Cnpj),
            Cpf = Identifier(s, SignerIdentifierTypes.Cpf) ?? Identifier(s, SignerIdentifierTypes.ResponsibleCpf),
            LayoutErrors = layout is null ? [] : LayoutErrors(s, layout),
        });

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
