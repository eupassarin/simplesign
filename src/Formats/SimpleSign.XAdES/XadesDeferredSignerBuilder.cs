using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>
/// Immutable fluent builder for two-phase (deferred) XAdES signing. Create it with
/// <see cref="XadesDeferredSigner.Document(byte[])"/> to prepare a signature, or with
/// <see cref="XadesDeferredSigner.Resume(byte[], byte[])"/> to complete one.
/// </summary>
/// <remarks>
/// <para>
/// Phase one (<see cref="PrepareAsync(CancellationToken)"/>) runs the signing policy and fixes everything
/// that is signed: the document and its form, the signed properties (signing time, commitment type,
/// signature policy, signer roles, production place) and the additional data objects. The methods that set
/// them have the same meaning as in <see cref="XadesSignerBuilder"/> and throw
/// <see cref="InvalidOperationException"/> on a resumed builder.
/// </para>
/// <para>
/// Phase two (<see cref="CompleteAsync(byte[], CancellationToken)"/>) verifies the signature and finishes the
/// level requested in phase one. The session stores values only, so what cannot be stored is given again on
/// the resumed builder: the HTTP provider, the signing policy and trust anchors that check the TSA, the audit
/// sink, the logger and, with <see cref="WithTimestampOptions(TimestampOptions, ArchiveTimestampOptions?)"/>,
/// the TSA credentials.
/// </para>
/// <para>
/// A countersignature is prepared with <see cref="XadesDeferredSigner.CounterSign"/>.
/// </para>
/// </remarks>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class XadesDeferredSignerBuilder
{
    private readonly XadesSignerBuilder _inner;
    private readonly XadesDeferredSession? _session;
    private readonly byte[]? _sessionIntegrityKey;

    /// <summary>Phase one: whether the session carries the detached document and the external data objects.</summary>
    private readonly bool _detachedDataInSession;

    /// <summary>Phase two: what the session does not carry and was given again ("" stands for the detached document).</summary>
    private readonly IReadOnlySet<string> _supplied;

    internal XadesDeferredSignerBuilder(XadesSignerBuilder inner, XadesDeferredSession? session, byte[]? sessionIntegrityKey)
        : this(inner, session, sessionIntegrityKey, detachedDataInSession: true, supplied: new HashSet<string>(StringComparer.Ordinal))
    {
    }

    private XadesDeferredSignerBuilder(
        XadesSignerBuilder inner, XadesDeferredSession? session, byte[]? sessionIntegrityKey, bool detachedDataInSession, IReadOnlySet<string> supplied)
    {
        _inner = inner;
        _session = session;
        _sessionIntegrityKey = sessionIntegrityKey;
        _detachedDataInSession = detachedDataInSession;
        _supplied = supplied;
    }

    /// <summary>The signer certificate given to <c>WithCertificate</c>, or <see langword="null"/> before it is called and on a resumed builder.</summary>
    public X509Certificate2? SignerCertificate => _inner.SignerCertificate;

    /// <summary>The certificate chain given with the signer certificate (empty when none was given).</summary>
    public IReadOnlyList<X509Certificate2> SignerChain => _inner.SignerChain;

    #region Phase one: what is signed

    /// <summary>Sets the signer's public certificate. The private key is not needed: it signs between the two phases.</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>A new builder with the certificate configured.</returns>
    public XadesDeferredSignerBuilder WithCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return PhaseOne(b => b.WithExternalSigner(certificate, DeferredPlaceholderSigner.Instance));
    }

    /// <summary>Sets the signer's public certificate and its chain, which is embedded in the signature.</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <param name="chain">
    /// Intermediate CA certificates, ordered from the issuer of <paramref name="certificate"/>
    /// up to (but not including) the root. May be empty. The collection is defensively copied.
    /// </param>
    /// <returns>A new builder with the certificate and chain configured.</returns>
    public XadesDeferredSignerBuilder WithCertificate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chain);
        return PhaseOne(b => b.WithExternalSigner(certificate, DeferredPlaceholderSigner.Instance, chain));
    }

    /// <summary>
    /// Sets the server-owned HMAC key that authenticates the session. The key must have at least 32 bytes
    /// and is never written into the session; give the same key to <see cref="XadesDeferredSigner.Resume(byte[], byte[])"/>.
    /// </summary>
    /// <param name="key">A server-owned key with at least 256 bits of entropy.</param>
    /// <returns>A new builder with a copy of the key.</returns>
    /// <exception cref="ArgumentException">The key has less than 32 bytes.</exception>
    /// <exception cref="InvalidOperationException">The builder was resumed: the key was given to <c>Resume</c>.</exception>
    public XadesDeferredSignerBuilder WithSessionIntegrityKey(byte[] key)
    {
        DeferredSessionEnvelope.ValidateKey(key, nameof(key));
        EnsurePhaseOne(nameof(WithSessionIntegrityKey));
        return new XadesDeferredSignerBuilder(_inner, _session, [.. key], _detachedDataInSession, _supplied);
    }

    /// <summary>
    /// Keeps out of the session the data the signature references outside the document: the signed document of
    /// the detached form and the external additional data objects. The session then carries only their SHA-256,
    /// and the builder that resumes it is given them again with <see cref="WithDetachedData(byte[])"/> and
    /// <see cref="WithExternalData(string, byte[])"/>. Data inside the signed document (enveloped and enveloping
    /// forms, embedded data objects) is part of the prepared XML and always travels in the session.
    /// </summary>
    /// <returns>A new builder that prepares a session without the detached data.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public XadesDeferredSignerBuilder WithDetachedDataOutsideSession()
    {
        EnsurePhaseOne(nameof(WithDetachedDataOutsideSession));
        return new XadesDeferredSignerBuilder(_inner, _session, _sessionIntegrityKey, detachedDataInSession: false, _supplied);
    }

    /// <summary>Explicitly sets the hash algorithm. Default: SHA-256.</summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>A new builder with the hash algorithm configured.</returns>
    public XadesDeferredSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        PhaseOne(b => b.WithHashAlgorithm(algorithm));

    /// <summary>Explicitly sets the signature algorithm OID (e.g. RSASSA-PSS). Default: chosen from the certificate key.</summary>
    /// <param name="signatureAlgorithmOid">The signature algorithm OID.</param>
    /// <returns>A new builder with the signature algorithm configured.</returns>
    public XadesDeferredSignerBuilder WithSignatureAlgorithm(string signatureAlgorithmOid) =>
        PhaseOne(b => b.WithSignatureAlgorithm(signatureAlgorithmOid));

    /// <summary>
    /// Sets the baseline level (B-B, B-T, B-LT or B-LTA). The session records the level and the TSA endpoints;
    /// phase two finishes that level.
    /// </summary>
    /// <param name="profile">The complete baseline profile.</param>
    /// <returns>A new builder with the profile configured.</returns>
    public XadesDeferredSignerBuilder WithLevel(AdesBaselineProfile profile) =>
        PhaseOne(b => b.WithLevel(profile));

    /// <summary>Sets the XAdES packaging form (Enveloped, Detached, Enveloping). Default: Enveloped.</summary>
    /// <param name="form">The XAdES packaging form.</param>
    /// <returns>A new builder with the form configured.</returns>
    public XadesDeferredSignerBuilder WithForm(XadesForm form) =>
        PhaseOne(b => b.WithForm(form));

    /// <summary>Sets the data URI for Detached form signatures.</summary>
    /// <param name="dataUri">The data object URI.</param>
    /// <returns>A new builder with the data URI configured.</returns>
    public XadesDeferredSignerBuilder WithDataUri(string dataUri) =>
        PhaseOne(b => b.WithDataUri(dataUri));

    /// <summary>Sets the claimed signing time written in the signed properties. Default: the moment of <see cref="PrepareAsync(CancellationToken)"/>.</summary>
    /// <param name="signingTime">The claimed signing time.</param>
    /// <returns>A new builder with the signing time configured.</returns>
    public XadesDeferredSignerBuilder WithSigningTime(DateTimeOffset signingTime) =>
        PhaseOne(b => b.WithSigningTime(signingTime));

    /// <summary>Sets the commitment type indication (e.g. ProofOfOrigin, ProofOfApproval).</summary>
    /// <param name="commitmentType">The commitment type.</param>
    /// <returns>A new builder with the commitment type configured.</returns>
    public XadesDeferredSignerBuilder WithCommitmentType(CommitmentType commitmentType) =>
        PhaseOne(b => b.WithCommitmentType(commitmentType));

    /// <summary>Sets the signature policy OID and optional policy document URI.</summary>
    /// <param name="oid">The signature policy OID.</param>
    /// <param name="uri">Optional policy document URI.</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    public XadesDeferredSignerBuilder WithSignaturePolicy(string oid, string? uri = null) =>
        PhaseOne(b => b.WithSignaturePolicy(oid, uri));

    /// <summary>Sets the signature policy with its hash (SigPolicyHash).</summary>
    /// <param name="policy">The policy reference (OID, hash algorithm, hash and optional URI).</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    public XadesDeferredSignerBuilder WithSignaturePolicy(SignaturePolicyReference policy) =>
        PhaseOne(b => b.WithSignaturePolicy(policy));

    /// <summary>
    /// Chooses the signing-certificate property: <see cref="XadesSigningCertificateForm.V2"/> (default) or the
    /// XAdES 1.3.2 <see cref="XadesSigningCertificateForm.V1"/>.
    /// </summary>
    /// <param name="form">The form.</param>
    /// <returns>A new builder with the form configured.</returns>
    public XadesDeferredSignerBuilder WithSigningCertificateForm(XadesSigningCertificateForm form) =>
        PhaseOne(b => b.WithSigningCertificateForm(form));

    /// <summary>
    /// Adds the XAdES extended forms of ETSI TS 101 903 v1.3.2 after the signature timestamp (XAdES-C/X, X-L
    /// or A). It needs a timestamped level; the form travels in the session and is built in phase two.
    /// </summary>
    /// <param name="form">The extended form.</param>
    /// <returns>A new builder with the form configured.</returns>
    public XadesDeferredSignerBuilder WithExtendedValidationData(XadesExtendedForm form) =>
        PhaseOne(b => b.WithExtendedValidationData(form));

    /// <summary>Sets the roles the signer claims (e.g. "Manager", "Approver").</summary>
    /// <param name="roles">The signer roles. The collection is defensively copied.</param>
    /// <returns>A new builder with the signer roles configured.</returns>
    public XadesDeferredSignerBuilder WithSignerRoles(IReadOnlyList<string> roles) =>
        PhaseOne(b => b.WithSignerRoles(roles));

    /// <summary>Sets a single role the signer claims.</summary>
    /// <param name="role">The signer role.</param>
    /// <returns>A new builder with the signer role configured.</returns>
    public XadesDeferredSignerBuilder WithSignerRole(string role) =>
        PhaseOne(b => b.WithSignerRole(role));

    /// <summary>
    /// Signs one more data object together with the document: a file carried inside the signature
    /// (<see cref="XadesDataObject.Embedded"/>) or kept outside it (<see cref="XadesDataObject.External"/>).
    /// An external object travels in the session, because phase two reads it back.
    /// </summary>
    /// <param name="dataObject">The data object.</param>
    /// <returns>A new builder with the data object added.</returns>
    /// <exception cref="ArgumentException">An external data object with the same URI was already added.</exception>
    public XadesDeferredSignerBuilder WithAdditionalDataObject(XadesDataObject dataObject) =>
        PhaseOne(b => b.WithAdditionalDataObject(dataObject));

    /// <summary>
    /// Adds the AllDataObjectsTimeStamp signed property (ETSI EN 319 132-1 §5.2.8.1). The TSA is asked in
    /// phase one, before the bytes to sign are produced; preparing fails when it does not answer.
    /// </summary>
    /// <param name="timestamp">The TSA that timestamps the data.</param>
    /// <returns>A new builder with the data objects timestamp configured.</returns>
    public XadesDeferredSignerBuilder WithDataObjectsTimestamp(TimestampOptions timestamp) =>
        PhaseOne(b => b.WithDataObjectsTimestamp(timestamp));

    /// <summary>
    /// Chooses the XML canonicalization of SignedInfo and of the signed references. Default:
    /// <see cref="XadesCanonicalization.Exclusive"/>.
    /// </summary>
    /// <param name="canonicalization">The canonicalization algorithm.</param>
    /// <returns>A new builder with the canonicalization configured.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="canonicalization"/> is not a defined value.</exception>
    public XadesDeferredSignerBuilder WithCanonicalization(XadesCanonicalization canonicalization) =>
        PhaseOne(b => b.WithCanonicalization(canonicalization));

    /// <summary>
    /// Adds the SignaturePolicyStore unsigned property (ETSI EN 319 132-1 §5.2.10). It needs the policy
    /// declared with its hash (<see cref="WithSignaturePolicy(SignaturePolicyReference)"/>).
    /// </summary>
    /// <param name="store">The policy document or its local URI.</param>
    /// <returns>A new builder with the policy store configured.</returns>
    public XadesDeferredSignerBuilder WithSignaturePolicyStore(SignaturePolicyStore store) =>
        PhaseOne(b => b.WithSignaturePolicyStore(store));

    /// <summary>Adds the SignatureProductionPlaceV2 signed property: where the signer was when signing.</summary>
    /// <param name="place">The place; at least one of its fields must be set.</param>
    /// <returns>A new builder with the production place configured.</returns>
    /// <exception cref="ArgumentException">Every field of <paramref name="place"/> is empty.</exception>
    public XadesDeferredSignerBuilder WithSignatureProductionPlace(SignatureProductionPlace place) =>
        PhaseOne(b => b.WithSignatureProductionPlace(place));

    /// <summary>
    /// Adds X.509 attribute certificates issued to the signer, as certified roles of SignerRoleV2. They are
    /// embedded as given: the library does not verify them.
    /// </summary>
    /// <param name="attributeCertificates">The DER-encoded attribute certificates (IETF RFC 5755).</param>
    /// <returns>A new builder with the attribute certificates configured.</returns>
    /// <exception cref="ArgumentException">An item is not one DER-encoded SEQUENCE.</exception>
    public XadesDeferredSignerBuilder WithAttributeCertificates(IReadOnlyList<ReadOnlyMemory<byte>> attributeCertificates) =>
        PhaseOne(b => b.WithAttributeCertificates(attributeCertificates));

    /// <summary>
    /// Adds assertions about the signer signed by third parties, as SignedAssertions of SignerRoleV2. Each
    /// one is an XML element, embedded as given: the library does not verify the third party's signature.
    /// </summary>
    /// <param name="assertions">The assertions, each as the text of one XML element.</param>
    /// <returns>A new builder with the signed assertions configured.</returns>
    /// <exception cref="ArgumentException">An assertion is not a well-formed XML element.</exception>
    public XadesDeferredSignerBuilder WithSignedAssertions(IReadOnlyList<string> assertions) =>
        PhaseOne(b => b.WithSignedAssertions(assertions));

    /// <summary>Sets the data object format (MIME type and object reference URI).</summary>
    /// <param name="format">The data object format.</param>
    /// <returns>A new builder with the data object format configured.</returns>
    public XadesDeferredSignerBuilder WithDataObjectFormat(DataObjectFormat format) =>
        PhaseOne(b => b.WithDataObjectFormat(format));

    #endregion

    #region Both phases: runtime dependencies

    /// <summary>
    /// Sets the HTTP provider used when no scoped provider is given: the revocation check and the data
    /// objects timestamp in phase one; the timestamps and the validation data in phase two. It is not stored
    /// in the session: set it again on the resumed builder.
    /// </summary>
    /// <param name="provider">The HTTP client provider.</param>
    /// <returns>A new builder with the provider configured.</returns>
    public XadesDeferredSignerBuilder WithHttpClientProvider(IHttpClientProvider provider) =>
        With(_inner.WithHttpClientProvider(provider));

    /// <summary>
    /// Signs under a trust profile (<c>IofeProfile</c>, <c>IcpBrasilProfile</c>…): its signing policy and its trust anchors,
    /// as <c>WithSigningPolicy</c> and <c>WithTrustAnchors</c> would set them. A later <c>WithSigningPolicy</c> replaces the
    /// profile's policy; later anchors are added to its own.
    /// </summary>
    /// <param name="profile">The trust profile.</param>
    /// <returns>A new builder with the profile's policy and anchors.</returns>
    /// <exception cref="ArgumentException">The profile does not sign (Gov.br).</exception>
    public XadesDeferredSignerBuilder WithProfile(SimpleSign.Core.Extensions.TrustProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return WithSigningPolicy(profile.RequireSigningPolicy()).WithTrustAnchors([.. profile.TrustAnchorProviders]);
    }

    /// <summary>
    /// Sets the signing policy (<see cref="SigningPolicy.Load"/>). Phase one runs its checks on the certificate,
    /// the chain and the algorithms before the bytes to sign are produced; phase two applies its <c>Timestamp</c>
    /// constraints to the timestamps it obtains. Default: <see cref="SigningPolicy.Default"/>.
    /// </summary>
    /// <param name="policy">The signing policy.</param>
    /// <returns>A new builder with the policy configured.</returns>
    public XadesDeferredSignerBuilder WithSigningPolicy(SigningPolicy policy) =>
        With(_inner.WithSigningPolicy(policy));

    /// <summary>
    /// Adds trust anchors: for the signing certificate in phase one, and for the TSA certificate in phase two,
    /// when the signing policy asks for a trusted chain.
    /// </summary>
    /// <param name="providers">The trust anchor providers.</param>
    /// <returns>A new builder with the anchors added.</returns>
    public XadesDeferredSignerBuilder WithTrustAnchors(params ITrustAnchorProvider[] providers) =>
        With(_inner.WithTrustAnchors(providers));

    /// <summary>Sets the checker used for the revocation check of the signing policy (<c>NotRevoked</c>, <c>RevocationDataAvailable</c>).</summary>
    /// <param name="checker">The chain revocation checker.</param>
    /// <returns>A new builder with the checker configured.</returns>
    public XadesDeferredSignerBuilder WithChainRevocationChecker(IChainRevocationChecker checker) =>
        With(_inner.WithChainRevocationChecker(checker));

    /// <summary>
    /// Records the operations of this builder with <paramref name="sink"/>: a refusal while preparing, and the
    /// outcome of the completion (the signature made, or the refusal). Set it on the builder that prepares and
    /// on the resumed one.
    /// </summary>
    /// <param name="sink">The audit sink.</param>
    /// <returns>A new builder with the sink configured.</returns>
    public XadesDeferredSignerBuilder WithAuditSink(ISignatureAuditSink sink) =>
        With(_inner.WithAuditSink(sink));

    /// <summary>
    /// Sets an operation id that correlates the audit records and the log messages of the two phases. The id
    /// given in phase one travels in the session; calling this on the resumed builder replaces it.
    /// </summary>
    /// <param name="operationId">The operation id.</param>
    /// <returns>A new builder with the operation id configured.</returns>
    public XadesDeferredSignerBuilder WithOperationId(string operationId) =>
        With(_inner.WithOperationId(operationId));

    /// <summary>Sets the logger for diagnostic output.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>A new builder with the logger configured.</returns>
    public XadesDeferredSignerBuilder WithLogger(ILogger logger) =>
        With(_inner.WithLogger(logger));

    #endregion

    #region Phase two

    /// <summary>
    /// Supplies the TSA settings a session cannot store: credentials (<see cref="TimestampOptions.Authorization"/>),
    /// the mutual-TLS client certificate, the expected TSA certificate and a scoped HTTP provider. Each endpoint
    /// must be the one recorded in phase one; the requested level does not change.
    /// </summary>
    /// <param name="timestamp">The signature TSA, at the endpoint the session recorded.</param>
    /// <param name="archiveTimestamp">The archive TSA for a B-LTA session; null keeps the session's (or inherits the signature TSA).</param>
    /// <returns>A new builder with the completed TSA settings.</returns>
    /// <exception cref="InvalidOperationException">The builder was not returned by <see cref="XadesDeferredSigner.Resume(byte[], byte[])"/>, or the session has no timestamp.</exception>
    /// <exception cref="ArgumentException">An endpoint differs from the one recorded in the session.</exception>
    public XadesDeferredSignerBuilder WithTimestampOptions(TimestampOptions timestamp, ArchiveTimestampOptions? archiveTimestamp = null)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        if (_session is null)
        {
            throw new InvalidOperationException(
                "WithTimestampOptions completes a resumed session; when preparing, pass the TSA in WithLevel.");
        }

        return With(_inner.WithLevel(DeferredProfile.WithTimestampOptions(_inner.Profile, timestamp, archiveTimestamp)));
    }

    /// <summary>
    /// Gives the signed document of a detached signature whose session was prepared with
    /// <see cref="WithDetachedDataOutsideSession"/>. It must be the document phase one signed: its SHA-256 is
    /// compared with the one the session carries.
    /// </summary>
    /// <param name="document">The document given to <see cref="XadesDeferredSigner.Document(byte[])"/> in phase one. The array is copied.</param>
    /// <returns>A new builder with the document.</returns>
    /// <exception cref="InvalidOperationException">The builder was not resumed, or its session does not wait for a detached document.</exception>
    /// <exception cref="ArgumentException">The data is not the document the session was prepared for.</exception>
    public XadesDeferredSignerBuilder WithDetachedData(byte[] document)
    {
        ArgumentNullException.ThrowIfNull(document);
        XadesDeferredSession session = _session ?? throw new InvalidOperationException(
            "WithDetachedData completes a resumed session; when preparing, the document is given to Document().");
        if (session.DetachedContentSha256 is not { } expected)
        {
            throw new InvalidOperationException(
                "The session does not wait for a detached document: WithDetachedData is for a detached signature prepared with WithDetachedDataOutsideSession().");
        }

        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(document), expected))
        {
            throw new ArgumentException("The data is not the document this session was prepared for.", nameof(document));
        }

        return new XadesDeferredSignerBuilder(
            _inner.WithDetachedDocument(document), _session, _sessionIntegrityKey, _detachedDataInSession, new HashSet<string>(_supplied, StringComparer.Ordinal) { string.Empty });
    }

    /// <summary>
    /// Gives an external additional data object of a session prepared with
    /// <see cref="WithDetachedDataOutsideSession"/>, by the URI of its reference. Its SHA-256 is compared with
    /// the one the session carries.
    /// </summary>
    /// <param name="uri">The URI given to <see cref="XadesDataObject.External"/> in phase one.</param>
    /// <param name="content">The data of the object. It is copied.</param>
    /// <returns>A new builder with the data object.</returns>
    /// <exception cref="InvalidOperationException">The builder was not resumed.</exception>
    /// <exception cref="ArgumentException">The session does not wait for an object with that URI, or the data is not the one it was prepared for.</exception>
    public XadesDeferredSignerBuilder WithExternalData(string uri, byte[] content)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uri);
        ArgumentNullException.ThrowIfNull(content);
        XadesDeferredSession session = _session ?? throw new InvalidOperationException(
            "WithExternalData completes a resumed session; when preparing, external data goes in WithAdditionalDataObject().");
        byte[] expected = (session.ExternalDataObjects ?? []).FirstOrDefault(o => o.Uri == uri && o.Sha256 is not null)?.Sha256
            ?? throw new ArgumentException($"The session does not wait for an external data object with the URI '{uri}'.", nameof(uri));
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(content), expected))
        {
            throw new ArgumentException($"The data is not the object '{uri}' this session was prepared for.", nameof(content));
        }

        return new XadesDeferredSignerBuilder(
            _inner.WithExternalDataObject(uri, content), _session, _sessionIntegrityKey, _detachedDataInSession, new HashSet<string>(_supplied, StringComparer.Ordinal) { uri });
    }

    #endregion

    #region Execution

    /// <summary>
    /// Phase one: checks the certificate, the chain and the algorithms against the signing policy and returns
    /// the bytes to sign with the session. A refusal is recorded by the audit sink.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The data to sign and the session to keep on the server.</returns>
    /// <exception cref="SigningException">The certificate or the session integrity key is missing, or the signing policy refused the certificate, the chain or an algorithm.</exception>
    /// <exception cref="ArgumentException">The document is not well-formed XML or has no root element.</exception>
    /// <exception cref="InvalidOperationException">The builder was resumed: it can only complete its session.</exception>
    public Task<XadesDeferredPrepareResult> PrepareAsync(CancellationToken cancellationToken = default)
    {
        if (_session is not null)
        {
            throw new InvalidOperationException("A resumed deferred signer can only complete an existing session.");
        }

        if (_inner.SignerCertificate is null)
        {
            throw new SigningException(
                "Certificate is required. Call WithCertificate() before preparing a deferred signature.",
                SigningErrorReason.CredentialMissing);
        }

        byte[] sessionIntegrityKey = _sessionIntegrityKey ?? throw new SigningException(
            "A session integrity key is required. Call WithSessionIntegrityKey() before preparing a deferred signature.",
            SigningErrorReason.LevelDependenciesMissing);
        return _inner.PrepareDeferredAsync(sessionIntegrityKey, _detachedDataInSession, cancellationToken);
    }

    /// <summary>
    /// Phase two: verifies <paramref name="rawSignature"/> against the certificate of the session, writes it
    /// into the signature and finishes the requested level. Throws when the profile allows a lower level: use
    /// <see cref="CompleteWithDetailsAsync(byte[], CancellationToken)"/> in that case.
    /// </summary>
    /// <param name="rawSignature">
    /// The raw signature over the data to sign: RSA PKCS#1 v1.5 or PSS, or an ECDSA DER SEQUENCE { r, s }.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed XML bytes.</returns>
    /// <exception cref="SigningException">The signature does not verify with the certificate, or the requested level could not be produced.</exception>
    /// <exception cref="InvalidOperationException">The builder was not returned by <see cref="XadesDeferredSigner.Resume(byte[], byte[])"/>.</exception>
    public async Task<byte[]> CompleteAsync(byte[] rawSignature, CancellationToken cancellationToken = default)
    {
        BaselineSigning.EnsureStrictProfile(_inner.Profile);
        XadesSigningResult result = await CompleteWithDetailsAsync(rawSignature, cancellationToken).ConfigureAwait(false);
        return result.SignedArtifact;
    }

    /// <summary>
    /// Phase two, with the signed document, the requested and achieved levels, what the artifact holds and the
    /// warnings. The outcome, signed or refused, is recorded by the audit sink.
    /// </summary>
    /// <param name="rawSignature">
    /// The raw signature over the data to sign: RSA PKCS#1 v1.5 or PSS, or an ECDSA DER SEQUENCE { r, s }.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The detailed XAdES signing result.</returns>
    /// <exception cref="SigningException">The signature does not verify with the certificate, or the requested level could not be produced.</exception>
    /// <exception cref="InvalidOperationException">The builder was not returned by <see cref="XadesDeferredSigner.Resume(byte[], byte[])"/>.</exception>
    public Task<XadesSigningResult> CompleteWithDetailsAsync(byte[] rawSignature, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rawSignature);
        if (rawSignature.Length == 0)
        {
            throw new ArgumentException("Signature bytes cannot be empty.", nameof(rawSignature));
        }

        XadesDeferredSession session = _session ?? throw new InvalidOperationException(
            "Only a builder returned by XadesDeferredSigner.Resume can complete a persisted session.");
        if (session.DetachedContentSha256 is not null && !_supplied.Contains(string.Empty))
        {
            throw new InvalidOperationException(
                "The session was prepared without its detached document: give it with WithDetachedData() before completing.");
        }

        if ((session.ExternalDataObjects ?? []).FirstOrDefault(o => o.Sha256 is not null && !_supplied.Contains(o.Uri)) is { } missing)
        {
            throw new InvalidOperationException(
                $"The session was prepared without the external data object '{missing.Uri}': give it with WithExternalData() before completing.");
        }

        return _inner.CompleteDeferredAsync(session, rawSignature, cancellationToken);
    }

    #endregion

    private XadesDeferredSignerBuilder With(XadesSignerBuilder inner) =>
        new(inner, _session, _sessionIntegrityKey, _detachedDataInSession, _supplied);

    private XadesDeferredSignerBuilder PhaseOne(Func<XadesSignerBuilder, XadesSignerBuilder> configure, [CallerMemberName] string method = "")
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
