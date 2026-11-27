using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;

namespace SimpleSign.XAdES;

/// <summary>One plain XML-DSig signature of a document, checked by <see cref="XmlDsigValidator"/>.</summary>
public sealed class XmlDsigSignatureResult
{
    /// <summary>The Reference URI (<c>#NFe…</c>, or empty for the whole document).</summary>
    public string ReferenceUri { get; init; } = string.Empty;

    /// <summary>Local name of the signed element (e.g. <c>infNFe</c>); null when the reference did not resolve.</summary>
    public string? SignedElement { get; init; }

    /// <summary>The digest of the signed element matches: it was not changed after signing.</summary>
    public bool IsDigestValid { get; init; }

    /// <summary>The SignatureValue verifies over SignedInfo with the KeyInfo certificate.</summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>The chain of the signer certificate is trusted; null when the chain was not checked.</summary>
    public bool? IsChainValid { get; init; }

    /// <summary>The revocation status of the chain, when it was checked.</summary>
    public ChainRevocationStatus? RevocationStatus { get; init; }

    /// <summary>The signer certificate from KeyInfo.</summary>
    public X509Certificate2? Certificate { get; init; }

    /// <summary>The signer's identifiers the trust profile reads from the certificate, by type (CPF, CNPJ…).</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> SignerIdentifiers { get; init; } = new Dictionary<string, IReadOnlyList<string>>();

    /// <summary>Hash algorithm of the signature (SHA1, SHA256…).</summary>
    public string? HashAlgorithm { get; init; }

    /// <summary>The SignatureMethod URI.</summary>
    public string? SignatureMethod { get; init; }

    /// <summary>Problems found.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Digest and signature verify, and the chain is trusted when it was checked.</summary>
    public bool IsValid => IsDigestValid && IsSignatureValid && IsChainValid != false && Errors.Count == 0;
}

/// <summary>The plain XML-DSig signatures of a document.</summary>
public sealed class XmlDsigValidationResult
{
    /// <summary>Every ds:Signature of the document, in document order.</summary>
    public IReadOnlyList<XmlDsigSignatureResult> Signatures { get; init; } = [];

    /// <summary>Errors about the document itself (unreadable XML, no signature).</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>The document has at least one signature and all of them are valid.</summary>
    public bool IsValid => Errors.Count == 0 && Signatures.Count > 0 && Signatures.All(s => s.IsValid);
}

/// <summary>
/// Validates plain enveloped XML-DSig signatures (the fiscal layouts): each reference resolves to exactly one element
/// (a duplicate Id is refused, against signature wrapping), its digest matches after the enveloped-signature and
/// canonicalization transforms, the SignatureValue verifies with the KeyInfo certificate and, with a trust profile,
/// the signer chain is checked by the profile's chain validation (revocation included). Only the shapes a plain
/// signature has are accepted: one Reference, RSA or ECDSA, and no transform but enveloped-signature and C14N.
/// </summary>
/// <remarks>
/// A signature algorithm is checked here as the signature says, SHA-1 included: the fiscal layouts mandate it. Whether
/// SHA-1 is acceptable is the caller's rule (a fiscal profile accepts it, a general one would not).
/// </remarks>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class XmlDsigValidator
{
    private readonly TrustProfile? _profile;
    private readonly SimpleSign.Core.Http.IHttpClientProvider _http;

    /// <summary>Creates a validator; with <paramref name="profile"/>, the signer chain is checked by its chain validation.</summary>
    /// <param name="profile">The trust profile (e.g. <c>IcpBrasilProfile.Create()</c>), or null to check the signatures only.</param>
    /// <param name="httpClientProvider">
    /// The HTTP of the AIA downloads that complete a chain no provider takes (KeyInfo of the fiscal layouts carries the
    /// signer certificate only), under its outbound policy; default: <see cref="SimpleSign.Core.Http.DefaultHttpClientProvider"/>.
    /// </param>
    public XmlDsigValidator(TrustProfile? profile = null, SimpleSign.Core.Http.IHttpClientProvider? httpClientProvider = null)
    {
        _profile = profile;
        _http = httpClientProvider ?? SimpleSign.Core.Http.DefaultHttpClientProvider.Instance;
    }

    /// <summary>Checks digests and signature values only (no chain, no network).</summary>
    /// <param name="xml">The signed XML.</param>
    /// <returns>The signatures found.</returns>
    public static XmlDsigValidationResult VerifySignatures(byte[] xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        XmlDocument document;
        try
        {
            document = XmlDsigEngine.Load(xml);
        }
        catch (ArgumentException ex)
        {
            return new XmlDsigValidationResult { Errors = [ex.Message] };
        }

        var ns = XmlDsigEngine.Namespaces(document);
        var signatures = document.SelectNodes("//ds:Signature", ns)!.Cast<XmlElement>().Select(s => Verify(document, s, ns)).ToList();
        return signatures.Count == 0
            ? new XmlDsigValidationResult { Errors = ["The document has no XML-DSig signature."] }
            : new XmlDsigValidationResult { Signatures = signatures.AsReadOnly() };
    }

    /// <summary>Checks digests, signature values and, with a trust profile, the chain of each signer.</summary>
    /// <param name="xml">The signed XML.</param>
    /// <param name="checkRevocation">Whether the profile's chain validation checks revocation (CRL/OCSP, online).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signatures found.</returns>
    public async Task<XmlDsigValidationResult> ValidateAsync(byte[] xml, bool checkRevocation = true, CancellationToken cancellationToken = default)
    {
        var result = VerifySignatures(xml);
        if (_profile is null)
        {
            return result;
        }

        var signatures = new List<XmlDsigSignatureResult>(result.Signatures.Count);
        foreach (var signature in result.Signatures)
        {
            signatures.Add(signature.Certificate is null
                ? signature
                : await CheckChainAsync(signature, signature.Certificate, checkRevocation, cancellationToken).ConfigureAwait(false));
        }

        return new XmlDsigValidationResult { Signatures = signatures.AsReadOnly(), Errors = result.Errors };
    }

    private async Task<XmlDsigSignatureResult> CheckChainAsync(
        XmlDsigSignatureResult signature, X509Certificate2 certificate, bool checkRevocation, CancellationToken cancellationToken)
    {
        var profile = _profile!;
        var errors = new List<string>(signature.Errors);
        bool chainValid;
        ChainRevocationStatus? revocation = null;
        var provider = profile.ChainValidationProviders.FirstOrDefault(p => p.CanValidate(certificate));
        if (provider is not null)
        {
            var chain = await provider.ValidateAsync(new ChainValidationContext
            {
                Certificate = certificate,
                CheckRevocation = checkRevocation,
            }, cancellationToken).ConfigureAwait(false);
            chainValid = chain.IsTrusted;
            revocation = chain.RevocationStatus;
            errors.AddRange((chain.Errors ?? []).Select(e => $"Chain: {e}"));
        }
        else
        {
            // The issuers the profile does not hold come from the certificates' AIA caIssuers.
            var warnings = new List<string>();
            var downloaded = await SimpleSign.Core.Validation.CertificateChainUtility.DownloadAiaCertsAsync(
                _http.GetClient(), certificate, null, warnings, _http.OutboundPolicy, cancellationToken).ConfigureAwait(false);
            chainValid = ChainsToAnchor(certificate, profile, downloaded, errors);
        }

        var identifiers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var reader in profile.SignerIdentityReaders)
        {
            foreach (string type in reader.IdentifierTypes)
            {
                var values = reader.Read(certificate, type);
                if (values.Count > 0)
                {
                    identifiers.TryAdd(type, values);
                }
            }
        }

        return new XmlDsigSignatureResult
        {
            ReferenceUri = signature.ReferenceUri,
            SignedElement = signature.SignedElement,
            IsDigestValid = signature.IsDigestValid,
            IsSignatureValid = signature.IsSignatureValid,
            IsChainValid = chainValid,
            RevocationStatus = revocation,
            Certificate = certificate,
            SignerIdentifiers = identifiers,
            HashAlgorithm = signature.HashAlgorithm,
            SignatureMethod = signature.SignatureMethod,
            Errors = errors.AsReadOnly(),
        };
    }

    /// <summary>
    /// The chain of a signer no chain validation provider takes: built to one of the profile's anchors, which may be a
    /// root or a CA at any level (a trusted list names CAs), with every certificate valid now and correctly signed. No
    /// revocation here: that is the chain validation providers'.
    /// </summary>
    private static bool ChainsToAnchor(
        X509Certificate2 certificate, TrustProfile profile, IReadOnlyList<X509Certificate2> issuers, List<string> errors)
    {
        var anchors = profile.Anchors();
        var anchored = anchors.Select(a => a.Thumbprint).ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var chain = new X509Chain();
        // KeyInfo of the fiscal layouts carries the signer certificate only: the issuers come from the anchors' providers or
        // from the certificate's AIA, which the platform downloads (revocation stays off, as in the other validators).
        CryptoUtility.ConfigureChainPolicy(chain, TimeSpan.FromSeconds(15));
        chain.ChainPolicy.ExtraStore.AddRange(anchors.ToArray());
        chain.ChainPolicy.ExtraStore.AddRange(profile.TrustAnchorProviders.SelectMany(p => p.GetIntermediateCertificates()).ToArray());
        chain.ChainPolicy.ExtraStore.AddRange(issuers.ToArray());
        bool built = chain.Build(certificate);
        if (built && profile.TrustSystemRoots)
        {
            return true;
        }

        // Only the root being unknown is tolerated, and only when an anchor is on the path.
        bool sound = chain.ChainStatus.All(s => s.Status is X509ChainStatusFlags.NoError or X509ChainStatusFlags.UntrustedRoot
            or X509ChainStatusFlags.PartialChain or X509ChainStatusFlags.OfflineRevocation or X509ChainStatusFlags.RevocationStatusUnknown);
        if (sound && chain.ChainElements.Any(e => anchored.Contains(e.Certificate.Thumbprint)))
        {
            return true;
        }

        errors.Add($"Chain: the signer certificate does not chain to a trust anchor of the {profile.Title} profile"
            + (sound ? "." : $" ({string.Join(", ", chain.ChainStatus.Select(s => s.Status))})."));
        return false;
    }

    private static XmlDsigSignatureResult Verify(XmlDocument document, XmlElement signature, XmlNamespaceManager ns)
    {
        var errors = new List<string>();
        var signedInfo = signature.SelectSingleNode("ds:SignedInfo", ns) as XmlElement;
        var references = signedInfo?.SelectNodes("ds:Reference", ns)?.Cast<XmlElement>().ToList() ?? [];
        string canonicalization = (signedInfo?.SelectSingleNode("ds:CanonicalizationMethod", ns) as XmlElement)?.GetAttribute("Algorithm") ?? string.Empty;
        string? method = (signedInfo?.SelectSingleNode("ds:SignatureMethod", ns) as XmlElement)?.GetAttribute("Algorithm");
        var signatureHash = SignatureHash(method);
        var certificate = LoadCertificate(signature, ns, errors);

        if (signedInfo is null || references.Count != 1 || signatureHash is null || !XmlDsigEngine.IsCanonicalization(canonicalization))
        {
            errors.Add("Unsupported SignedInfo: one Reference, an RSA or ECDSA SignatureMethod and C14N are required.");
            return new XmlDsigSignatureResult { Certificate = certificate, SignatureMethod = method, Errors = errors.AsReadOnly() };
        }

        string uri = references[0].GetAttribute("URI");
        var (target, element) = Resolve(document, uri, errors);
        bool digestValid = element is not null && CheckDigest(document, target!, element, references[0], signature, ns, errors);

        bool signatureValid = false;
        if (certificate is not null)
        {
            byte[] canonical = XmlDsigEngine.CanonicalSignedInfo(signedInfo, canonicalization);
            byte[] value;
            try
            {
                value = Convert.FromBase64String((signature.SelectSingleNode("ds:SignatureValue", ns)?.InnerText ?? string.Empty).Trim());
            }
            catch (FormatException)
            {
                value = [];
            }

            signatureValid = VerifyValue(certificate, canonical, value, signatureHash.Value);
            if (!signatureValid)
            {
                errors.Add("The SignatureValue does not verify with the KeyInfo certificate.");
            }
        }

        return new XmlDsigSignatureResult
        {
            ReferenceUri = uri,
            SignedElement = element?.LocalName,
            IsDigestValid = digestValid,
            IsSignatureValid = signatureValid,
            Certificate = certificate,
            HashAlgorithm = signatureHash.Value.Name,
            SignatureMethod = method,
            Errors = errors.AsReadOnly(),
        };
    }

    private static bool VerifyValue(X509Certificate2 certificate, byte[] data, byte[] value, HashAlgorithmName hash)
    {
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            return rsa.VerifyData(data, value, hash, RSASignaturePadding.Pkcs1);
        }

        using var ecdsa = certificate.GetECDsaPublicKey();
        return ecdsa is not null && ecdsa.VerifyData(data, value, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static HashAlgorithmName? SignatureHash(string? uri) => uri switch
    {
        XmlDSigUrls.RsaSha1 => HashAlgorithmName.SHA1,
        XmlDSigUrls.RsaSha256 or XmlDSigUrls.EcdsaSha256 => HashAlgorithmName.SHA256,
        XmlDSigUrls.RsaSha384 or XmlDSigUrls.EcdsaSha384 => HashAlgorithmName.SHA384,
        XmlDSigUrls.RsaSha512 or XmlDSigUrls.EcdsaSha512 => HashAlgorithmName.SHA512,
        _ => null,
    };

    private static (XmlDsigTarget? Target, XmlElement? Element) Resolve(XmlDocument document, string uri, List<string> errors)
    {
        if (uri.Length == 0)
        {
            return (XmlDsigTarget.Document, document.DocumentElement);
        }

        if (!uri.StartsWith('#') || uri.Length == 1)
        {
            errors.Add($"Unsupported Reference URI '{uri}'.");
            return (null, null);
        }

        string id = uri[1..];
        var matches = XmlDsigEngine.ElementsWithId(document, id);
        if (matches.Count != 1)
        {
            errors.Add(matches.Count == 0 ? $"No element with the Id '{id}'." : $"{matches.Count} elements share the Id '{id}' (refused).");
            return (null, null);
        }

        var element = matches[0];
        string attribute = element.HasAttribute("Id") ? "Id" : element.HasAttribute("id") ? "id" : "ID";
        return (new XmlDsigTarget(element.LocalName, attribute), element);
    }

    private static bool CheckDigest(
        XmlDocument document, XmlDsigTarget target, XmlElement element, XmlElement reference, XmlElement signature,
        XmlNamespaceManager ns, List<string> errors)
    {
        var transforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns)!.Cast<XmlElement>().Select(t => t.GetAttribute("Algorithm")).ToList();
        if (transforms.Any(t => t != XmlDSigUrls.EnvelopedSignatureTransform && !XmlDsigEngine.IsCanonicalization(t)))
        {
            errors.Add("Unsupported transform in the Reference.");
            return false;
        }

        string canonicalization = transforms.LastOrDefault(XmlDsigEngine.IsCanonicalization) ?? XmlDSigUrls.C14N;
        bool enveloped = transforms.Contains(XmlDSigUrls.EnvelopedSignatureTransform);
        HashAlgorithmName digestHash;
        byte[] expected;
        try
        {
            digestHash = XmlDSigUrls.GetHashAlgorithmFromUri((reference.SelectSingleNode("ds:DigestMethod", ns) as XmlElement)?.GetAttribute("Algorithm") ?? string.Empty);
            expected = Convert.FromBase64String((reference.SelectSingleNode("ds:DigestValue", ns)?.InnerText ?? string.Empty).Trim());
        }
        catch (Exception ex) when (ex is NotSupportedException or FormatException)
        {
            errors.Add($"Unsupported DigestMethod or unreadable DigestValue: {ex.Message}");
            return false;
        }

        byte[] actual = XmlDsigEngine.Hash(
            digestHash, XmlDsigEngine.CanonicalizeReferenced(document, target, element, canonicalization, enveloped ? signature : null));
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
            return CertificateLoader.LoadCertificate(Convert.FromBase64String(base64.Trim()));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            errors.Add($"The KeyInfo certificate cannot be read: {ex.Message}");
            return null;
        }
    }
}
