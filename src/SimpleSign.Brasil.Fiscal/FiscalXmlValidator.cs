using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Extensions.Logging;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Brasil.Fiscal;

/// <summary>One XMLDSig signature of a fiscal XML.</summary>
public sealed class FiscalSignatureResult
{
    /// <summary>The Reference URI (<c>#NFe…</c>, or empty for the whole document).</summary>
    public string ReferenceUri { get; init; } = string.Empty;

    /// <summary>Local name of the signed element (e.g. <c>infNFe</c>).</summary>
    public string? SignedElement { get; init; }

    /// <summary>The digest of the signed element matches (it was not changed after signing).</summary>
    public bool IsDigestValid { get; init; }

    /// <summary>The SignatureValue verifies over SignedInfo with the KeyInfo certificate.</summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>The ICP-Brasil chain of the certificate is valid; null when the chain was not checked.</summary>
    public bool? IsChainValid { get; init; }

    /// <summary>The signer certificate from KeyInfo.</summary>
    public X509Certificate2? Certificate { get; init; }

    /// <summary>CNPJ of an e-CNPJ signer.</summary>
    public string? Cnpj { get; init; }

    /// <summary>CPF of an e-CPF signer.</summary>
    public string? Cpf { get; init; }

    /// <summary>Hash algorithm of the signature (SHA1, SHA256…).</summary>
    public string? HashAlgorithm { get; init; }

    /// <summary>Problems found.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Digest and signature verify, and the chain is valid when it was checked.</summary>
    public bool IsValid => IsDigestValid && IsSignatureValid && IsChainValid != false && Errors.Count == 0;
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
/// Validates the XMLDSig signatures of fiscal XML (NF-e, CT-e, MDF-e, events, NFS-e, eSocial,
/// EFD-Reinf): the reference digest (with the enveloped-signature transform), the SignatureValue
/// and, optionally, the ICP-Brasil chain of the signer certificate. References must resolve to a
/// single element (duplicate Ids are rejected, against signature-wrapping attacks).
/// </summary>
public sealed class FiscalXmlValidator
{
    private readonly IcpBrasilChainValidator _chainValidator;

    /// <summary>Creates a validator; <paramref name="httpClient"/> is used for AIA/LCR/OCSP when the chain is checked.</summary>
    /// <param name="httpClient">HTTP client, or null for the shared one.</param>
    /// <param name="logger">Optional logger.</param>
    public FiscalXmlValidator(HttpClient? httpClient = null, ILogger? logger = null)
        : this(new IcpBrasilChainValidator(httpClient, logger))
    {
    }

    internal FiscalXmlValidator(IcpBrasilChainValidator chainValidator)
    {
        _chainValidator = chainValidator;
    }

    /// <summary>Checks digests and signature values only (no chain, no network).</summary>
    /// <param name="xml">The signed XML.</param>
    public static FiscalValidationResult VerifySignatures(byte[] xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        XmlDocument doc;
        try
        {
            doc = XmlDsig.Load(xml);
        }
        catch (XmlException ex)
        {
            return new FiscalValidationResult { Errors = [$"The XML cannot be read: {ex.Message}"] };
        }

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        var signatures = doc.SelectNodes("//ds:Signature", ns)!.Cast<XmlElement>().Select(s => Verify(doc, s, ns)).ToList();
        return signatures.Count == 0
            ? new FiscalValidationResult { Errors = ["The document has no XMLDSig signature."] }
            : new FiscalValidationResult { Signatures = signatures.AsReadOnly() };
    }

    /// <summary>Checks digests, signature values and the ICP-Brasil chain of each signer.</summary>
    /// <param name="xml">The signed XML.</param>
    /// <param name="checkRevocation">Whether to check LCR/OCSP online.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<FiscalValidationResult> ValidateAsync(byte[] xml, bool checkRevocation = true, CancellationToken cancellationToken = default)
    {
        var result = VerifySignatures(xml);
        var signatures = new List<FiscalSignatureResult>();
        foreach (var signature in result.Signatures)
        {
            if (signature.Certificate is null)
            {
                signatures.Add(signature);
                continue;
            }

            var chain = await _chainValidator.ValidateAsync(new ChainValidationContext
            {
                Certificate = signature.Certificate,
                CheckRevocation = checkRevocation,
            }, cancellationToken).ConfigureAwait(false);
            signatures.Add(new FiscalSignatureResult
            {
                ReferenceUri = signature.ReferenceUri,
                SignedElement = signature.SignedElement,
                IsDigestValid = signature.IsDigestValid,
                IsSignatureValid = signature.IsSignatureValid,
                IsChainValid = chain.IsValid,
                Certificate = signature.Certificate,
                Cnpj = signature.Cnpj,
                Cpf = signature.Cpf,
                HashAlgorithm = signature.HashAlgorithm,
                Errors = [.. signature.Errors, .. chain.Errors.Select(e => $"Chain: {e}")],
            });
        }

        return new FiscalValidationResult { Signatures = signatures.AsReadOnly(), Errors = result.Errors };
    }

    private static FiscalSignatureResult Verify(XmlDocument doc, XmlElement signature, XmlNamespaceManager ns)
    {
        var errors = new List<string>();
        var signedInfo = signature.SelectSingleNode("ds:SignedInfo", ns) as XmlElement;
        var reference = signedInfo?.SelectNodes("ds:Reference", ns)?.Cast<XmlElement>().ToList() ?? [];
        string canonicalization = (signedInfo?.SelectSingleNode("ds:CanonicalizationMethod", ns) as XmlElement)?.GetAttribute("Algorithm") ?? string.Empty;
        var signatureHash = XmlDsig.FromRsaSignatureUri((signedInfo?.SelectSingleNode("ds:SignatureMethod", ns) as XmlElement)?.GetAttribute("Algorithm"));
        var certificate = LoadCertificate(signature, ns, errors);

        if (signedInfo is null || reference.Count != 1 || signatureHash is null || !IsCanonicalization(canonicalization))
        {
            errors.Add("Unsupported SignedInfo: one Reference, an RSA SignatureMethod and C14N are required.");
            return new FiscalSignatureResult { Certificate = certificate, Errors = errors.AsReadOnly() };
        }

        string uri = reference[0].GetAttribute("URI");
        var target = Resolve(doc, uri, errors);
        bool digestValid = target is not null && CheckDigest(target, reference[0], signature, ns, errors);

        bool signatureValid = false;
        if (certificate is not null)
        {
            using var rsa = certificate.GetRSAPublicKey();
            byte[] canonicalSignedInfo = XmlDsig.Canonicalize(signedInfo, canonicalization);
            byte[] value = Convert.FromBase64String((signature.SelectSingleNode("ds:SignatureValue", ns)?.InnerText ?? string.Empty).Trim());
            signatureValid = rsa is not null && rsa.VerifyData(canonicalSignedInfo, value, signatureHash.Value, RSASignaturePadding.Pkcs1);
            if (!signatureValid)
            {
                errors.Add("The SignatureValue does not verify with the KeyInfo certificate.");
            }
        }

        var (cpf, cnpj) = certificate is null ? (null, null) : IcpBrasilChainValidator.ExtractCpfCnpj(certificate);
        return new FiscalSignatureResult
        {
            ReferenceUri = uri,
            SignedElement = target?.LocalName,
            IsDigestValid = digestValid,
            IsSignatureValid = signatureValid,
            Certificate = certificate,
            Cnpj = cnpj,
            Cpf = cpf,
            HashAlgorithm = signatureHash.Value.Name,
            Errors = errors.AsReadOnly(),
        };
    }

    private static bool IsCanonicalization(string algorithm) =>
        algorithm is XmlDSigUrls.C14N or XmlDSigUrls.C14NWithComments or XmlDSigUrls.ExcC14N or XmlDSigUrls.ExcC14NWithComments;

    private static XmlElement? Resolve(XmlDocument doc, string uri, List<string> errors)
    {
        if (uri.Length == 0)
        {
            return doc.DocumentElement;
        }

        if (!uri.StartsWith('#'))
        {
            errors.Add($"Unsupported Reference URI '{uri}'.");
            return null;
        }

        string id = uri[1..];
        var matches = doc.SelectNodes("//*")!.Cast<XmlElement>()
            .Where(e => e.GetAttribute("Id") == id || e.GetAttribute("id") == id || e.GetAttribute("ID") == id)
            .ToList();
        if (matches.Count != 1)
        {
            errors.Add(matches.Count == 0 ? $"No element with Id '{id}'." : $"{matches.Count} elements share the Id '{id}' (rejected).");
            return null;
        }

        return matches[0];
    }

    private static bool CheckDigest(XmlElement target, XmlElement reference, XmlElement signature, XmlNamespaceManager ns, List<string> errors)
    {
        var transforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns)!.Cast<XmlElement>().Select(t => t.GetAttribute("Algorithm")).ToList();
        if (transforms.Any(t => t != XmlDSigUrls.EnvelopedSignatureTransform && !IsCanonicalization(t)))
        {
            errors.Add("Unsupported transform in the Reference.");
            return false;
        }

        string canonicalization = transforms.LastOrDefault(IsCanonicalization) ?? XmlDSigUrls.C14N;
        bool enveloped = transforms.Contains(XmlDSigUrls.EnvelopedSignatureTransform);
        var digestHash = XmlDsig.FromDigestUri((reference.SelectSingleNode("ds:DigestMethod", ns) as XmlElement)?.GetAttribute("Algorithm"));
        if (digestHash is null)
        {
            errors.Add("Unsupported DigestMethod.");
            return false;
        }

        byte[] expected = Convert.FromBase64String((reference.SelectSingleNode("ds:DigestValue", ns)?.InnerText ?? string.Empty).Trim());
        byte[] actual = XmlDsig.Hash(digestHash.Value, XmlDsig.Canonicalize(target, canonicalization, enveloped ? signature : null));
        bool valid = CryptographicOperations.FixedTimeEquals(expected, actual);
        if (!valid)
        {
            errors.Add("The digest does not match: the signed content was changed after signing.");
        }

        return valid;
    }

    private static X509Certificate2? LoadCertificate(XmlElement signature, XmlNamespaceManager ns, List<string> errors)
    {
        string? base64 = signature.SelectSingleNode("ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns)?.InnerText;
        if (string.IsNullOrWhiteSpace(base64))
        {
            errors.Add("KeyInfo has no X509Certificate.");
            return null;
        }

        try
        {
            return SimpleSign.Core.Crypto.CertificateLoader.LoadCertificate(Convert.FromBase64String(base64.Trim()));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            errors.Add($"KeyInfo certificate cannot be read: {ex.Message}");
            return null;
        }
    }
}
