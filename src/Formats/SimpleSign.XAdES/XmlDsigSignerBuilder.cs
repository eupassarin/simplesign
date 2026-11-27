using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>The options of an <see cref="XmlDsigSignerBuilder"/>.</summary>
internal sealed record XmlDsigSigningOptions
{
    public X509Certificate2? Certificate { get; init; }

    public IReadOnlyList<X509Certificate2> Chain { get; init; } = [];

    public IExternalSigner? ExternalSigner { get; init; }

    public XmlDsigTarget Target { get; init; } = XmlDsigTarget.Document;

    public string? ElementId { get; init; }

    public XmlDsigPlacement Placement { get; init; } = XmlDsigPlacement.AfterSignedElement;

    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    public XadesCanonicalization Canonicalization { get; init; } = XadesCanonicalization.Inclusive;

    public SigningPolicy SigningPolicy { get; init; } = SigningPolicy.Default;

    public IReadOnlyList<ITrustAnchorProvider> TrustAnchors { get; init; } = [];

    public IChainRevocationChecker? ChainRevocationChecker { get; init; }

    public IHttpClientProvider HttpClientProvider { get; init; } = DefaultHttpClientProvider.Instance;

    public ISignatureAuditSink? AuditSink { get; init; }

    public string? OperationId { get; init; }

    public ILogger Logger { get; init; } = NullLogger.Instance;
}

/// <summary>
/// Immutable fluent builder for a plain enveloped XML-DSig signature (W3C XML Signature 1.0, without the XAdES
/// qualifying properties), as the Brazilian fiscal layouts require: one Reference to an element by its Id (or to the
/// whole document), the enveloped-signature and canonicalization transforms, the signature after the element or at the
/// end of the root, and only the signer certificate in KeyInfo. The XML is not reformatted: send exactly the bytes
/// returned. The certificate is checked against the signing policy before anything is signed, as in XAdES.
/// </summary>
/// <example>
/// <code>
/// byte[] signed = await XmlDsigSigner.Document(nfe)
///     .WithSignedElement("infNFe")
///     .WithHashAlgorithm(HashAlgorithmName.SHA1)   // the signing policy must allow it
///     .WithCertificate(eCnpj)
///     .SignAsync();
/// </code>
/// </example>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class XmlDsigSignerBuilder
{
    /// <summary>The format name of the audit records.</summary>
    internal const string Format = "XMLDSig";

    internal XmlDsigSignerBuilder(byte[] xml, XmlDsigSigningOptions options)
    {
        Xml = xml;
        Options = options;
    }

    internal XmlDsigSigningOptions Options { get; }

    internal byte[] Xml { get; }

    /// <summary>The XML to sign, as given to <see cref="XmlDsigSigner.Document"/>. Extensions read it to check the input (a fiscal layout refuses a batch it cannot sign).</summary>
    public ReadOnlyMemory<byte> Document => Xml;

    /// <summary>The signer certificate given to WithCertificate or WithExternalSigner, or <see langword="null"/> before either is called. Extensions read it to pick policies.</summary>
    public X509Certificate2? SignerCertificate => Options.Certificate;

    /// <summary>The certificate chain given with the signer certificate (empty when none was given).</summary>
    public IReadOnlyList<X509Certificate2> SignerChain => Options.Chain;

    /// <summary>Sets the signing certificate (must have a private key).</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>A new builder with the local credential configured.</returns>
    public XmlDsigSignerBuilder WithCertificate(X509Certificate2 certificate) => WithCertificate(certificate, []);

    /// <summary>Sets the signing certificate and its chain (the chain is checked by the signing policy; KeyInfo carries the signer certificate only).</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <param name="chain">Intermediate CA certificates, from the issuer of <paramref name="certificate"/> up to (not including) the root.</param>
    /// <returns>A new builder with the local credential configured.</returns>
    public XmlDsigSignerBuilder WithCertificate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chain);
        return With(Options with { Certificate = certificate, Chain = [.. chain], ExternalSigner = null });
    }

    /// <summary>Configures external signing (A3 token through PKCS#11, cloud certificate, HSM): the signer receives the canonical SignedInfo.</summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="signer">The external signer implementation.</param>
    /// <returns>A new builder with the external credential configured.</returns>
    public XmlDsigSignerBuilder WithExternalSigner(X509Certificate2 certificate, IExternalSigner signer) =>
        WithExternalSigner(certificate, signer, []);

    /// <summary>Configures external signing with a pre-fetched certificate chain.</summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="signer">The external signer implementation.</param>
    /// <param name="chain">Intermediate CA certificates, from the issuer of <paramref name="certificate"/> up to (not including) the root.</param>
    /// <returns>A new builder with the external credential configured.</returns>
    public XmlDsigSignerBuilder WithExternalSigner(X509Certificate2 certificate, IExternalSigner signer, IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(chain);
        return With(Options with { Certificate = certificate, Chain = [.. chain], ExternalSigner = signer });
    }

    /// <summary>
    /// Signs an element by its Id attribute: the Reference is <c>URI="#…"</c>. Default: the whole document
    /// (<c>URI=""</c>).
    /// </summary>
    /// <param name="localName">Local name of the element, in any namespace (<c>infNFe</c>, <c>infEvento</c>…); <c>*</c> for any element that has <paramref name="idAttribute"/>.</param>
    /// <param name="idAttribute">The attribute that holds its Id (<c>Id</c>; <c>id</c> in EFD-Reinf).</param>
    /// <returns>A new builder with the signed element configured.</returns>
    public XmlDsigSignerBuilder WithSignedElement(string localName, string idAttribute = "Id")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(localName);
        ArgumentException.ThrowIfNullOrWhiteSpace(idAttribute);
        return With(Options with { Target = new XmlDsigTarget(localName, idAttribute) });
    }

    /// <summary>Signs the whole document (<c>URI=""</c>, the default); the signature goes at the end of the root.</summary>
    /// <returns>A new builder that signs the whole document.</returns>
    public XmlDsigSignerBuilder WithWholeDocument() => With(Options with { Target = XmlDsigTarget.Document, ElementId = null });

    /// <summary>Signs the element whose Id is <paramref name="id"/>, when the document has several (a batch).</summary>
    /// <param name="id">The Id of the element to sign.</param>
    /// <returns>A new builder with the element chosen.</returns>
    public XmlDsigSignerBuilder WithElementId(string id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        return With(Options with { ElementId = id });
    }

    /// <summary>Where the signature goes (default: right after the signed element).</summary>
    /// <param name="placement">The placement.</param>
    /// <returns>A new builder with the placement configured.</returns>
    public XmlDsigSignerBuilder WithPlacement(XmlDsigPlacement placement) => With(Options with { Placement = placement });

    /// <summary>
    /// Sets the digest and signature hash (default: SHA-256). SHA-1, which the SEFAZ layouts mandate, is made only when
    /// the signing policy allows it (<see cref="SigningPolicy"/>: <c>Cryptographic/AcceptableDigestAlgo</c>).
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>A new builder with the hash algorithm configured.</returns>
    public XmlDsigSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm.Name, nameof(algorithm));
        return With(Options with { HashAlgorithm = algorithm });
    }

    /// <summary>The canonicalization of SignedInfo and of the reference (default: Canonical XML 1.0, inclusive).</summary>
    /// <param name="canonicalization">The canonicalization.</param>
    /// <returns>A new builder with the canonicalization configured.</returns>
    public XmlDsigSignerBuilder WithCanonicalization(XadesCanonicalization canonicalization)
    {
        _ = XadesSignatureBuilder.CanonicalizationUri(canonicalization);
        return With(Options with { Canonicalization = canonicalization });
    }

    /// <summary>
    /// Signs under a trust profile (<c>IcpBrasilProfile</c>…): its signing policy and its trust anchors. A later
    /// <c>WithSigningPolicy</c> replaces the profile's policy; later anchors are added to its own.
    /// </summary>
    /// <param name="profile">The trust profile.</param>
    /// <returns>A new builder with the profile's policy and anchors.</returns>
    /// <exception cref="ArgumentException">The profile does not sign (Gov.br).</exception>
    public XmlDsigSignerBuilder WithProfile(TrustProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return WithSigningPolicy(profile.RequireSigningPolicy()).WithTrustAnchors([.. profile.TrustAnchorProviders]);
    }

    /// <summary>Sets the checks run before signing (chain, key usage, key size, digest, revocation). Default: <see cref="SigningPolicy.Default"/>.</summary>
    /// <param name="policy">The signing policy.</param>
    /// <returns>A new builder with the policy configured.</returns>
    public XmlDsigSignerBuilder WithSigningPolicy(SigningPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return With(Options with { SigningPolicy = policy });
    }

    /// <summary>Adds trust anchors for the checks made before signing.</summary>
    /// <param name="providers">The trust anchor providers.</param>
    /// <returns>A new builder with the anchors added.</returns>
    public XmlDsigSignerBuilder WithTrustAnchors(params ITrustAnchorProvider[] providers)
    {
        ArgumentNullException.ThrowIfNull(providers);
        return With(Options with { TrustAnchors = [.. Options.TrustAnchors, .. providers] });
    }

    /// <summary>Sets the checker used for the revocation check of the signing policy.</summary>
    /// <param name="checker">The chain revocation checker.</param>
    /// <returns>A new builder with the checker configured.</returns>
    public XmlDsigSignerBuilder WithChainRevocationChecker(IChainRevocationChecker checker)
    {
        ArgumentNullException.ThrowIfNull(checker);
        return With(Options with { ChainRevocationChecker = checker });
    }

    /// <summary>Sets the HTTP client provider of the revocation check made before signing.</summary>
    /// <param name="provider">The HTTP client provider.</param>
    /// <returns>A new builder with the provider configured.</returns>
    public XmlDsigSignerBuilder WithHttpClientProvider(IHttpClientProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return With(Options with { HttpClientProvider = provider });
    }

    /// <summary>Records every signing operation, signed or refused, with <paramref name="sink"/>.</summary>
    /// <param name="sink">The audit sink (e.g. <see cref="JsonLinesAuditSink"/>).</param>
    /// <returns>A new builder with the sink configured.</returns>
    public XmlDsigSignerBuilder WithAuditSink(ISignatureAuditSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        return With(Options with { AuditSink = sink });
    }

    /// <summary>Sets an operation ID for log correlation.</summary>
    /// <param name="operationId">The operation ID.</param>
    /// <returns>A new builder with the operation ID configured.</returns>
    public XmlDsigSignerBuilder WithOperationId(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return With(Options with { OperationId = operationId });
    }

    /// <summary>Sets the logger.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>A new builder with the logger configured.</returns>
    public XmlDsigSignerBuilder WithLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        return With(Options with { Logger = logger });
    }

    /// <summary>
    /// Signs the one element the builder designates (or the one chosen with <see cref="WithElementId"/>) and returns
    /// the signed XML.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed XML.</returns>
    /// <exception cref="ArgumentException">The XML cannot be read, has no such element, or several and no Id was chosen.</exception>
    /// <exception cref="SigningException">The signing policy refuses the certificate or the algorithm.</exception>
    public Task<byte[]> SignAsync(CancellationToken cancellationToken = default) => RunAsync(all: false, cancellationToken);

    /// <summary>
    /// Signs every element the builder designates that is not signed yet: each NF-e of an <c>enviNFe</c> batch, each
    /// event of an <c>envEvento</c>. A document whose elements are all signed comes back unchanged.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed XML.</returns>
    public Task<byte[]> SignAllAsync(CancellationToken cancellationToken = default) => RunAsync(all: true, cancellationToken);

    private Task<byte[]> RunAsync(bool all, CancellationToken cancellationToken) =>
        SignatureAudit.RunAsync(
            Options.AuditSink,
            () => SignatureAuditEvent.Start(Format, Options.OperationId, AdesBaselineLevel.Basic, Options.Certificate, Options.SigningPolicy, Xml),
            () => SignCoreAsync(all, cancellationToken),
            signed => (signed, AdesBaselineLevel.Basic),
            cancellationToken);

    private async Task<byte[]> SignCoreAsync(bool all, CancellationToken cancellationToken)
    {
        var start = await BeginAsync(cancellationToken).ConfigureAwait(false);
        var document = XmlDsigEngine.Load(Xml);
        var targets = SelectTargets(document, all);
        foreach (var element in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var pending = Insert(document, element, start);
            byte[] value = await SignValueAsync(pending.CanonicalSignedInfo, start, cancellationToken).ConfigureAwait(false);
            XmlDsigEngine.Complete(pending.Signature, value, start.Certificate);
        }

        return targets.Count == 0 ? (byte[])Xml.Clone() : XmlDsigEngine.Save(document);
    }

    /// <summary>What the checks made before signing resolved.</summary>
    internal sealed record Start(
        X509Certificate2 Certificate, HashAlgorithmName HashAlgorithm, string SignatureAlgorithmOid, string SignatureMethodUri,
        string Canonicalization, IReadOnlyList<SigningWarning> Warnings);

    /// <summary>
    /// The checks made before anything is signed: the credential, the certificate and its chain against the signing
    /// policy, and the algorithms (RSA PKCS#1 v1.5 or ECDSA with the chosen hash).
    /// </summary>
    internal async Task<Start> BeginAsync(CancellationToken cancellationToken, bool requirePrivateKey = true)
    {
        var certificate = Options.Certificate
            ?? throw new SigningException(
                "Certificate not set. Call WithCertificate() or WithExternalSigner() before signing.",
                SigningErrorReason.CredentialMissing);
        if (requirePrivateKey && Options.ExternalSigner is null && !certificate.HasPrivateKey)
        {
            throw new SigningException(
                "Certificate must have a private key for local signing. Use WithExternalSigner() instead.",
                SigningErrorReason.PrivateKeyMissing);
        }

        BaselineSigning.EnsureCertificateValidNow(certificate);
        var warnings = new List<SigningWarning>();
        await SignerAcceptance.EnsureSignerAcceptableAsync(
            certificate, Options.Chain, Options.SigningPolicy, Options.TrustAnchors, Options.ChainRevocationChecker,
            Options.HttpClientProvider, Options.Logger, warnings, cancellationToken).ConfigureAwait(false);
        SignerAcceptance.EnsureHashAllowed(Options.HashAlgorithm, Options.SigningPolicy, warnings, Options.Logger);

        string signatureOid = SignatureAlgorithmOid(certificate, Options.HashAlgorithm);
        string methodUri;
        try
        {
            methodUri = XmlDSigUrls.GetSignatureMethodUri(certificate, Options.HashAlgorithm);
        }
        catch (NotSupportedException ex)
        {
            throw new SigningException(ex.Message, SigningErrorReason.AlgorithmIncompatible, ex);
        }

        return new Start(certificate, Options.HashAlgorithm, signatureOid, methodUri,
            XadesSignatureBuilder.CanonicalizationUri(Options.Canonicalization), warnings);
    }

    /// <summary>The elements to sign: the chosen one, the only one, or (for <paramref name="all"/>) every one not signed yet.</summary>
    internal List<XmlElement> SelectTargets(XmlDocument document, bool all)
    {
        var target = Options.Target;
        var targets = XmlDsigEngine.FindTargets(document, target);
        string what = target.IsDocument ? "document" : target.ElementName == "*" ? $"element with an {target.IdAttribute} attribute" : $"{target.ElementName} element";
        if (Options.ElementId is { } id)
        {
            targets = [.. targets.Where(t => t.GetAttribute(target.IdAttribute ?? "Id") == id)];
            return targets.Count == 0
                ? throw new ArgumentException($"No {what} with the Id '{id}' to sign.")
                : targets;
        }

        if (all)
        {
            return targets.Count == 0
                ? throw new ArgumentException($"No {what} to sign.")
                : [.. targets.Where(t => !XmlDsigEngine.IsSigned(document, target.ReferenceUri(t)))];
        }

        return targets.Count switch
        {
            0 => throw new ArgumentException($"No {what} to sign."),
            1 => targets,
            _ => throw new ArgumentException(
                $"The document has {targets.Count} {what}s: choose one with WithElementId, or sign them all with SignAllAsync."),
        };
    }

    internal XmlDsigPendingSignature Insert(XmlDocument document, XmlElement element, Start start) =>
        XmlDsigEngine.Insert(document, Options.Target, element, Options.Placement, start.HashAlgorithm, start.SignatureMethodUri, start.Canonicalization);

    private async Task<byte[]> SignValueAsync(byte[] signedInfo, Start start, CancellationToken cancellationToken)
    {
        if (Options.ExternalSigner is { } external)
        {
            var request = new ExternalSigningRequest(
                signedInfo, start.HashAlgorithm, start.SignatureAlgorithmOid, ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo, Options.OperationId);
            var raw = await BaselineSigning.SignExternallyAsync(external, request, start.Certificate, cancellationToken).ConfigureAwait(false);
            return XadesSignatureBuilder.XmlSignatureValue(raw.ToArray(), start.Certificate);
        }

        using var rsa = start.Certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return rsa.SignData(signedInfo, start.HashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        using var ecdsa = start.Certificate.GetECDsaPrivateKey()
            ?? throw new SigningException("The certificate has neither an RSA nor an ECDSA private key.", SigningErrorReason.AlgorithmIncompatible);
        return ecdsa.SignData(signedInfo, start.HashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>The signature algorithm OID for the certificate's key and the hash (RSA PKCS#1 v1.5 or ECDSA).</summary>
    internal static string SignatureAlgorithmOid(X509Certificate2 certificate, HashAlgorithmName hash) =>
        (certificate.GetKeyAlgorithm(), hash.Name) switch
        {
            (Oids.RsaEncryption, "SHA1") => Oids.RsaSha1,
            (Oids.RsaEncryption, "SHA256") => Oids.RsaSha256,
            (Oids.RsaEncryption, "SHA384") => Oids.RsaSha384,
            (Oids.RsaEncryption, "SHA512") => Oids.RsaSha512,
            (Oids.EcPublicKey, "SHA256") => Oids.EcdsaSha256,
            (Oids.EcPublicKey, "SHA384") => Oids.EcdsaSha384,
            (Oids.EcPublicKey, "SHA512") => Oids.EcdsaSha512,
            var (key, name) => throw new SigningException(
                $"A plain XML-DSig signature is made with RSA PKCS#1 v1.5 or ECDSA and SHA-1/SHA-2; the key '{key}' with {name} is not supported.",
                SigningErrorReason.AlgorithmIncompatible),
        };

    private XmlDsigSignerBuilder With(XmlDsigSigningOptions options) => new(Xml, options);
}
