using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>
/// Two-phase plain XML-DSig signatures (ADR 0028): the server prepares the signature and keeps the session, the key
/// signs the canonical SignedInfo elsewhere (an A3 token behind a local agent, an HSM), and the server completes it,
/// possibly in another request and on another instance.
/// </summary>
/// <example>
/// <code>
/// var prepared = await XmlDsigDeferredSigner.Document(nfe).WithSignedElement("infNFe")
///     .WithHashAlgorithm(HashAlgorithmName.SHA1).WithSigningPolicy(fiscalPolicy)
///     .WithCertificate(publicCertificate).WithSessionIntegrityKey(key).PrepareAsync();
/// // … the signer signs prepared.DataToSign (prepared.ToSigningRequest()) …
/// byte[] signed = await XmlDsigDeferredSigner.Resume(prepared.SessionData, key).CompleteAsync(signature);
/// </code>
/// </example>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public static class XmlDsigDeferredSigner
{
    /// <summary>Starts phase one for <paramref name="xml"/>.</summary>
    /// <param name="xml">The XML document.</param>
    /// <returns>A builder that prepares the signature.</returns>
    public static XmlDsigDeferredSignerBuilder Document(byte[] xml) => From(XmlDsigSigner.Document(xml));

    /// <summary>The builder that prepares the signature a configured one-call builder would make.</summary>
    /// <param name="builder">The one-call builder (its external signer, if any, is not used).</param>
    /// <returns>A builder that prepares the same signature.</returns>
    public static XmlDsigDeferredSignerBuilder From(XmlDsigSignerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return new XmlDsigDeferredSignerBuilder(builder, session: null, sessionIntegrityKey: null);
    }

    /// <summary>Resumes a session to complete it with the signature.</summary>
    /// <param name="sessionData">The session returned by phase one.</param>
    /// <param name="sessionIntegrityKey">The key given to phase one.</param>
    /// <returns>A builder that completes the session.</returns>
    /// <exception cref="CryptographicException">The session was changed or the key is not the one of phase one.</exception>
    public static XmlDsigDeferredSignerBuilder Resume(byte[] sessionData, byte[] sessionIntegrityKey)
    {
        ArgumentNullException.ThrowIfNull(sessionData);
        ArgumentOutOfRangeException.ThrowIfZero(sessionData.Length);
        ArgumentNullException.ThrowIfNull(sessionIntegrityKey);
        var session = XmlDsigDeferredSession.Read(sessionData, sessionIntegrityKey);
        var inner = XmlDsigSigner.Document(session.PreparedXml);
        if (session.OperationId is { } operationId)
        {
            inner = inner.WithOperationId(operationId);
        }

        return new XmlDsigDeferredSignerBuilder(inner, session, sessionIntegrityKey: null);
    }
}

/// <summary>
/// The builder of a two-phase XML-DSig signature: the options of <see cref="XmlDsigSignerBuilder"/>, the session
/// integrity key, and the two phases. What the signature covers is set before <see cref="PrepareAsync"/>; on a resumed
/// builder those options throw.
/// </summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class XmlDsigDeferredSignerBuilder
{
    private readonly XmlDsigSignerBuilder _inner;
    private readonly XmlDsigDeferredSession? _session;
    private readonly byte[]? _sessionIntegrityKey;

    internal XmlDsigDeferredSignerBuilder(XmlDsigSignerBuilder inner, XmlDsigDeferredSession? session, byte[]? sessionIntegrityKey)
    {
        _inner = inner;
        _session = session;
        _sessionIntegrityKey = sessionIntegrityKey;
    }

    /// <summary>The signer certificate given to WithCertificate, or <see langword="null"/>. Extensions read it to pick policies.</summary>
    public X509Certificate2? SignerCertificate => _inner.SignerCertificate;

    /// <summary>The certificate chain given with the signer certificate.</summary>
    public IReadOnlyList<X509Certificate2> SignerChain => _inner.SignerChain;

    /// <summary>Sets the signer's public certificate. The private key is not needed: it signs between the two phases.</summary>
    /// <param name="certificate">The signer certificate.</param>
    /// <returns>A new builder with the certificate.</returns>
    public XmlDsigDeferredSignerBuilder WithCertificate(X509Certificate2 certificate) => PhaseOne(b => b.WithCertificate(certificate));

    /// <summary>Sets the signer's public certificate and its chain (checked by the signing policy).</summary>
    /// <param name="certificate">The signer certificate.</param>
    /// <param name="chain">Intermediate CA certificates.</param>
    /// <returns>A new builder with the certificate.</returns>
    public XmlDsigDeferredSignerBuilder WithCertificate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) =>
        PhaseOne(b => b.WithCertificate(certificate, chain));

    /// <summary>
    /// Sets the server-owned HMAC key that authenticates the session (at least 32 bytes, never written into it); give
    /// the same key to <see cref="XmlDsigDeferredSigner.Resume"/>.
    /// </summary>
    /// <param name="key">A server-owned key with at least 256 bits of entropy.</param>
    /// <returns>A new builder with a copy of the key.</returns>
    public XmlDsigDeferredSignerBuilder WithSessionIntegrityKey(byte[] key)
    {
        DeferredSessionEnvelope.ValidateKey(key, nameof(key));
        EnsurePhaseOne(nameof(WithSessionIntegrityKey));
        return new XmlDsigDeferredSignerBuilder(_inner, _session, [.. key]);
    }

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithSignedElement"/>
    public XmlDsigDeferredSignerBuilder WithSignedElement(string localName, string idAttribute = "Id") =>
        PhaseOne(b => b.WithSignedElement(localName, idAttribute));

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithWholeDocument"/>
    public XmlDsigDeferredSignerBuilder WithWholeDocument() => PhaseOne(b => b.WithWholeDocument());

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithElementId"/>
    public XmlDsigDeferredSignerBuilder WithElementId(string id) => PhaseOne(b => b.WithElementId(id));

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithPlacement"/>
    public XmlDsigDeferredSignerBuilder WithPlacement(XmlDsigPlacement placement) => PhaseOne(b => b.WithPlacement(placement));

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithHashAlgorithm"/>
    public XmlDsigDeferredSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) => PhaseOne(b => b.WithHashAlgorithm(algorithm));

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithCanonicalization"/>
    public XmlDsigDeferredSignerBuilder WithCanonicalization(XadesCanonicalization canonicalization) =>
        PhaseOne(b => b.WithCanonicalization(canonicalization));

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithProfile"/>
    public XmlDsigDeferredSignerBuilder WithProfile(TrustProfile profile) => PhaseOne(b => b.WithProfile(profile));

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithSigningPolicy"/>
    public XmlDsigDeferredSignerBuilder WithSigningPolicy(SigningPolicy policy) => PhaseOne(b => b.WithSigningPolicy(policy));

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithTrustAnchors"/>
    public XmlDsigDeferredSignerBuilder WithTrustAnchors(params ITrustAnchorProvider[] providers) => PhaseOne(b => b.WithTrustAnchors(providers));

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithChainRevocationChecker"/>
    public XmlDsigDeferredSignerBuilder WithChainRevocationChecker(IChainRevocationChecker checker) =>
        PhaseOne(b => b.WithChainRevocationChecker(checker));

    /// <inheritdoc cref="XmlDsigSignerBuilder.WithHttpClientProvider"/>
    public XmlDsigDeferredSignerBuilder WithHttpClientProvider(IHttpClientProvider provider) =>
        PhaseOne(b => b.WithHttpClientProvider(provider));

    /// <summary>Records the refusal of phase one, and the outcome of phase two, with <paramref name="sink"/>; give it in both phases.</summary>
    /// <param name="sink">The audit sink.</param>
    /// <returns>A new builder with the sink configured.</returns>
    public XmlDsigDeferredSignerBuilder WithAuditSink(ISignatureAuditSink sink) => With(_inner.WithAuditSink(sink));

    /// <summary>Sets an operation ID for log correlation (kept in the session).</summary>
    /// <param name="operationId">The operation ID.</param>
    /// <returns>A new builder with the operation ID configured.</returns>
    public XmlDsigDeferredSignerBuilder WithOperationId(string operationId) => PhaseOne(b => b.WithOperationId(operationId));

    /// <summary>Sets the logger, in either phase.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>A new builder with the logger configured.</returns>
    public XmlDsigDeferredSignerBuilder WithLogger(ILogger logger) => With(_inner.WithLogger(logger));

    /// <summary>
    /// Phase one: checks the certificate, the chain and the algorithms against the signing policy, places the signature
    /// in the document and returns the canonical SignedInfo with the session. A refusal is recorded by the audit sink.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The data to sign and the session to keep on the server.</returns>
    /// <exception cref="SigningException">The certificate or the key is missing, or the signing policy refused them.</exception>
    /// <exception cref="ArgumentException">The XML cannot be read, has no such element, or several and no Id was chosen.</exception>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public async Task<XmlDsigDeferredPrepareResult> PrepareAsync(CancellationToken cancellationToken = default)
    {
        if (_session is not null)
        {
            throw new InvalidOperationException("A resumed deferred signer can only complete an existing session.");
        }

        var options = _inner.Options;
        try
        {
            byte[] key = _sessionIntegrityKey ?? throw new SigningException(
                "A session integrity key is required. Call WithSessionIntegrityKey() before preparing a deferred signature.",
                SigningErrorReason.LevelDependenciesMissing);
            var start = await _inner.BeginAsync(cancellationToken, requirePrivateKey: false).ConfigureAwait(false);
            var document = XmlDsigEngine.Load(_inner.Xml);
            var element = _inner.SelectTargets(document, all: false)[0];
            var pending = _inner.Insert(document, element, start);
            var session = new XmlDsigDeferredSession
            {
                SignedInfo = pending.CanonicalSignedInfo,
                PreparedXml = XmlDsigEngine.Save(document),
                ReferenceUri = pending.ReferenceUri,
                CertificateDer = start.Certificate.RawData,
                HashAlgorithm = start.HashAlgorithm.Name!,
                SignatureAlgorithmOid = start.SignatureAlgorithmOid,
                InputSha256 = Convert.ToHexString(SHA256.HashData(_inner.Xml)),
                OperationId = options.OperationId,
            };
            return new XmlDsigDeferredPrepareResult
            {
                DataToSign = pending.CanonicalSignedInfo,
                SessionData = session.Protect(key),
                DigestAlgorithm = session.HashAlgorithm,
                SignatureAlgorithmOid = session.SignatureAlgorithmOid,
                ReferenceUri = session.ReferenceUri,
                Warnings = start.Warnings,
                OperationId = options.OperationId,
            };
        }
        catch (Exception ex) when (options.AuditSink is not null && ex is not OperationCanceledException)
        {
            var refused = SignatureAuditEvent.Start(
                XmlDsigSignerBuilder.Format, options.OperationId, AdesBaselineLevel.Basic, options.Certificate, options.SigningPolicy, _inner.Xml);
            await options.AuditSink.RecordAsync(
                refused with { Reason = (ex as SigningException)?.Reason, Message = ex.Message }, cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Phase two: verifies <paramref name="rawSignature"/> against the certificate of the session and writes it, with
    /// the certificate, into the signature. The outcome, signed or refused, is recorded by the audit sink.
    /// </summary>
    /// <param name="rawSignature">The raw signature over the data to sign: RSA PKCS#1 v1.5, or an ECDSA DER SEQUENCE { r, s }.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed XML.</returns>
    /// <exception cref="SigningException">The signature does not verify with the certificate of the session.</exception>
    /// <exception cref="InvalidOperationException">The builder was not returned by <see cref="XmlDsigDeferredSigner.Resume"/>.</exception>
    public Task<byte[]> CompleteAsync(byte[] rawSignature, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rawSignature);
        if (rawSignature.Length == 0)
        {
            throw new ArgumentException("Signature bytes cannot be empty.", nameof(rawSignature));
        }

        var session = _session ?? throw new InvalidOperationException(
            "Only a builder returned by XmlDsigDeferredSigner.Resume can complete a persisted session.");
        var options = _inner.Options;
        return CompleteCoreAsync(session, rawSignature, options, cancellationToken);
    }

    private static async Task<byte[]> CompleteCoreAsync(
        XmlDsigDeferredSession session, byte[] rawSignature, XmlDsigSigningOptions options, CancellationToken cancellationToken)
    {
        using var certificate = CertificateLoader.LoadCertificate(session.CertificateDer);
        return await SignatureAudit.RunAsync(
            options.AuditSink,
            () => SignatureAuditEvent.Start(XmlDsigSignerBuilder.Format, options.OperationId, AdesBaselineLevel.Basic, certificate, options.SigningPolicy, default)
                with
            { InputSha256 = session.InputSha256 },
            () => Task.FromResult(Complete(session, rawSignature, certificate)),
            signed => (signed, AdesBaselineLevel.Basic),
            cancellationToken).ConfigureAwait(false);
    }

    private static byte[] Complete(XmlDsigDeferredSession session, byte[] rawSignature, X509Certificate2 certificate)
    {
        var hash = new HashAlgorithmName(session.HashAlgorithm);
        if (!CmsSignatureBuilder.VerifyExternalSignature(session.SignedInfo, rawSignature, certificate, hash, session.SignatureAlgorithmOid))
        {
            throw new SigningException(
                "The signature does not verify with the certificate of the session.", SigningErrorReason.AlgorithmIncompatible);
        }

        var document = XmlDsigEngine.Load(session.PreparedXml);
        var ns = XmlDsigEngine.Namespaces(document);
        var signature = document.SelectNodes("//ds:Signature[not(ds:SignatureValue)]", ns)!.Cast<XmlElement>()
            .SingleOrDefault(s => (s.SelectSingleNode("ds:SignedInfo/ds:Reference", ns) as XmlElement)?.GetAttribute("URI") == session.ReferenceUri)
            ?? throw new SigningException("The prepared document of the session holds no pending signature.", SigningErrorReason.Unspecified);
        XmlDsigEngine.Complete(signature, XadesSignatureBuilder.XmlSignatureValue(rawSignature, certificate), certificate);
        return XmlDsigEngine.Save(document);
    }

    private XmlDsigDeferredSignerBuilder With(XmlDsigSignerBuilder inner) => new(inner, _session, _sessionIntegrityKey);

    private XmlDsigDeferredSignerBuilder PhaseOne(Func<XmlDsigSignerBuilder, XmlDsigSignerBuilder> configure, [CallerMemberName] string method = "")
    {
        EnsurePhaseOne(method);
        return With(configure(_inner));
    }

    private void EnsurePhaseOne(string method)
    {
        if (_session is not null)
        {
            throw new InvalidOperationException(
                $"{method} is set before PrepareAsync: a resumed session completes what phase one fixed.");
        }
    }
}
