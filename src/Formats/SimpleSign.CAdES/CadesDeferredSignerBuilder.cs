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

namespace SimpleSign.CAdES;

/// <summary>
/// Immutable fluent builder for two-phase (deferred) CAdES signing. Create it with
/// <see cref="CadesDeferredSigner.Document(byte[])"/> to prepare a signature, or with
/// <see cref="CadesDeferredSigner.Resume(byte[], byte[])"/> to complete one.
/// </summary>
/// <remarks>
/// <para>
/// Phase one (<see cref="PrepareAsync(CancellationToken)"/>) runs the signing policy and fixes everything
/// that is signed: the content, the signing time, the commitment type, the signature policy, the signer
/// attributes. The methods that set them have the same meaning as in <see cref="CadesSignerBuilder"/> and
/// throw <see cref="InvalidOperationException"/> on a resumed builder.
/// </para>
/// <para>
/// Phase two (<see cref="CompleteAsync(byte[], CancellationToken)"/>) verifies the signature and finishes the
/// level requested in phase one. The session stores values only, so what cannot be stored is given again on
/// the resumed builder: the HTTP provider, the signing policy and trust anchors that check the TSA, the audit
/// sink, the logger and, with <see cref="WithTimestampOptions(TimestampOptions, ArchiveTimestampOptions?)"/>,
/// the TSA credentials.
/// </para>
/// <para>
/// A co-signature and a countersignature are prepared with <see cref="CadesDeferredSigner.CoSign"/> and
/// <see cref="CadesDeferredSigner.CounterSign"/>; the existing signature travels in the session.
/// </para>
/// </remarks>
public sealed class CadesDeferredSignerBuilder
{
    private readonly CadesSignerBuilder _inner;
    private readonly CadesDeferredSession? _session;
    private readonly byte[]? _sessionIntegrityKey;

    /// <summary>Phase one: whether the session carries the content. Phase two: whether the builder has it.</summary>
    private readonly bool _hasContent;

    internal CadesDeferredSignerBuilder(CadesSignerBuilder inner, CadesDeferredSession? session, byte[]? sessionIntegrityKey)
        : this(inner, session, sessionIntegrityKey, hasContent: session is null || session.Content is not null)
    {
    }

    private CadesDeferredSignerBuilder(CadesSignerBuilder inner, CadesDeferredSession? session, byte[]? sessionIntegrityKey, bool hasContent)
    {
        _inner = inner;
        _session = session;
        _sessionIntegrityKey = sessionIntegrityKey;
        _hasContent = hasContent;
    }

    /// <summary>The signer certificate given to <c>WithCertificate</c>, or <see langword="null"/> before it is called and on a resumed builder.</summary>
    public X509Certificate2? SignerCertificate => _inner.SignerCertificate;

    /// <summary>The certificate chain given with the signer certificate (empty when none was given).</summary>
    public IReadOnlyList<X509Certificate2> SignerChain => _inner.SignerChain;

    #region Phase one: what is signed

    /// <summary>Sets the signer's public certificate. The private key is not needed: it signs between the two phases.</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>A new builder with the certificate configured.</returns>
    public CadesDeferredSignerBuilder WithCertificate(X509Certificate2 certificate)
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
    public CadesDeferredSignerBuilder WithCertificate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chain);
        return PhaseOne(b => b.WithExternalSigner(certificate, DeferredPlaceholderSigner.Instance, chain));
    }

    /// <summary>
    /// Sets the server-owned HMAC key that authenticates the session. The key must have at least 32 bytes
    /// and is never written into the session; give the same key to <see cref="CadesDeferredSigner.Resume(byte[], byte[])"/>.
    /// </summary>
    /// <param name="key">A server-owned key with at least 256 bits of entropy.</param>
    /// <returns>A new builder with a copy of the key.</returns>
    /// <exception cref="ArgumentException">The key has less than 32 bytes.</exception>
    /// <exception cref="InvalidOperationException">The builder was resumed: the key was given to <c>Resume</c>.</exception>
    public CadesDeferredSignerBuilder WithSessionIntegrityKey(byte[] key)
    {
        DeferredSessionEnvelope.ValidateKey(key, nameof(key));
        EnsurePhaseOne(nameof(WithSessionIntegrityKey));
        return new CadesDeferredSignerBuilder(_inner, _session, [.. key], _hasContent);
    }

    /// <summary>
    /// Keeps the content out of the session, which then carries only its SHA-256. Use it when the content is
    /// large or already stored: the builder that resumes the session is given it again with
    /// <see cref="WithContent(byte[])"/>, for a detached and for an attached signature alike.
    /// </summary>
    /// <returns>A new builder that prepares a session without the content.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public CadesDeferredSignerBuilder WithContentOutsideSession()
    {
        EnsurePhaseOne(nameof(WithContentOutsideSession));
        return new CadesDeferredSignerBuilder(_inner, _session, _sessionIntegrityKey, hasContent: false);
    }

    /// <summary>Explicitly sets the hash algorithm. Default: SHA-256.</summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>A new builder with the hash algorithm configured.</returns>
    public CadesDeferredSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        PhaseOne(b => b.WithHashAlgorithm(algorithm));

    /// <summary>Explicitly sets the signature algorithm OID (e.g. RSASSA-PSS). Default: chosen from the certificate key.</summary>
    /// <param name="signatureAlgorithmOid">The signature algorithm OID.</param>
    /// <returns>A new builder with the signature algorithm configured.</returns>
    public CadesDeferredSignerBuilder WithSignatureAlgorithm(string signatureAlgorithmOid) =>
        PhaseOne(b => b.WithSignatureAlgorithm(signatureAlgorithmOid));

    /// <summary>Sets the claimed signing time written in the signed attributes. Default: the moment of <see cref="PrepareAsync(CancellationToken)"/>.</summary>
    /// <param name="signingTime">The claimed signing time.</param>
    /// <returns>A new builder with the signing time configured.</returns>
    public CadesDeferredSignerBuilder WithSigningTime(DateTimeOffset signingTime) =>
        PhaseOne(b => b.WithSigningTime(signingTime));

    /// <summary>
    /// Sets the baseline level (B-B, B-T, B-LT or B-LTA). The session records the level and the TSA endpoints;
    /// phase two finishes that level.
    /// </summary>
    /// <param name="profile">The complete baseline profile.</param>
    /// <returns>A new builder with the profile configured.</returns>
    public CadesDeferredSignerBuilder WithLevel(AdesBaselineProfile profile) =>
        PhaseOne(b => b.WithLevel(profile));

    /// <summary>Sets the content type. Detached = .p7s (default), Enveloped = .p7m with the content inside.</summary>
    /// <param name="contentType">The CAdES content type.</param>
    /// <returns>A new builder with the content type configured.</returns>
    public CadesDeferredSignerBuilder WithContentType(CadesContentType contentType) =>
        PhaseOne(b => b.WithContentType(contentType));

    /// <summary>Sets the commitment type indication (e.g. ProofOfOrigin, ProofOfApproval).</summary>
    /// <param name="commitmentType">The commitment type.</param>
    /// <returns>A new builder with the commitment type configured.</returns>
    public CadesDeferredSignerBuilder WithCommitmentType(CommitmentType commitmentType) =>
        PhaseOne(b => b.WithCommitmentType(commitmentType));

    /// <summary>Sets the signature policy identifier and optional URI.</summary>
    /// <param name="oid">The signature policy OID.</param>
    /// <param name="uri">Optional policy document URI.</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    public CadesDeferredSignerBuilder WithSignaturePolicy(string oid, string? uri = null) =>
        PhaseOne(b => b.WithSignaturePolicy(oid, uri));

    /// <summary>Sets the signature policy with its hash (sigPolicyHash).</summary>
    /// <param name="policy">The policy OID, hash and optional URI.</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    public CadesDeferredSignerBuilder WithSignaturePolicy(SignaturePolicyReference policy) =>
        PhaseOne(b => b.WithSignaturePolicy(policy));

    /// <summary>
    /// Adds the content-time-stamp signed attribute (ETSI EN 319 122-1 §5.2.8). The TSA is asked in phase one,
    /// before the bytes to sign are produced; preparing fails when it does not answer.
    /// </summary>
    /// <param name="timestamp">The TSA that timestamps the content.</param>
    /// <returns>A new builder with the content timestamp configured.</returns>
    public CadesDeferredSignerBuilder WithContentTimestamp(TimestampOptions timestamp) =>
        PhaseOne(b => b.WithContentTimestamp(timestamp));

    /// <summary>
    /// Adds the signature-policy-store unsigned attribute (ETSI EN 319 122-1 §5.2.10). It needs the policy
    /// declared with its hash (<see cref="WithSignaturePolicy(SignaturePolicyReference)"/>); the store travels in the session.
    /// </summary>
    /// <param name="store">The policy document or its local URI.</param>
    /// <returns>A new builder with the policy store configured.</returns>
    public CadesDeferredSignerBuilder WithSignaturePolicyStore(SignaturePolicyStore store) =>
        PhaseOne(b => b.WithSignaturePolicyStore(store));

    /// <summary>Adds the signer-location attribute (ETSI EN 319 122-1 §5.2.5).</summary>
    /// <param name="location">The location; at least one of its fields must be set, with at most six postal address lines.</param>
    /// <returns>A new builder with the signer location configured.</returns>
    /// <exception cref="ArgumentException">No field is set, or the postal address has more than six lines or an empty line.</exception>
    public CadesDeferredSignerBuilder WithSignerLocation(CadesSignerLocation location) =>
        PhaseOne(b => b.WithSignerLocation(location));

    /// <summary>Adds the content-hints attribute, which describes the signed content (IETF RFC 2634 §2.9).</summary>
    /// <param name="hints">The content type and, optionally, its description.</param>
    /// <returns>A new builder with the content hints configured.</returns>
    /// <exception cref="ArgumentException">The content type OID is empty, or the description is an empty string.</exception>
    public CadesDeferredSignerBuilder WithContentHints(CadesContentHints hints) =>
        PhaseOne(b => b.WithContentHints(hints));

    /// <summary>Adds the mime-type attribute: the MIME type of the signed data, e.g. "application/pdf".</summary>
    /// <param name="mimeType">The MIME type.</param>
    /// <returns>A new builder with the MIME type configured.</returns>
    public CadesDeferredSignerBuilder WithMimeType(string mimeType) =>
        PhaseOne(b => b.WithMimeType(mimeType));

    /// <summary>Adds the roles the signer claims, in the signer-attributes-v2 attribute. Empty roles are left out.</summary>
    /// <param name="roles">The claimed roles.</param>
    /// <returns>A new builder with the signer roles configured.</returns>
    public CadesDeferredSignerBuilder WithSignerRoles(IReadOnlyList<string> roles) =>
        PhaseOne(b => b.WithSignerRoles(roles));

    /// <summary>Adds one role the signer claims (see <see cref="WithSignerRoles(IReadOnlyList{string})"/>).</summary>
    /// <param name="role">The claimed role.</param>
    /// <returns>A new builder with the signer role configured.</returns>
    public CadesDeferredSignerBuilder WithSignerRole(string role) =>
        PhaseOne(b => b.WithSignerRole(role));

    /// <summary>
    /// Adds X.509 attribute certificates issued to the signer, in the signer-attributes-v2 attribute. They are
    /// embedded as given: the library does not verify them.
    /// </summary>
    /// <param name="attributeCertificates">The DER-encoded attribute certificates (IETF RFC 5755).</param>
    /// <returns>A new builder with the attribute certificates configured.</returns>
    /// <exception cref="ArgumentException">An item is not one DER-encoded SEQUENCE.</exception>
    public CadesDeferredSignerBuilder WithAttributeCertificates(IReadOnlyList<ReadOnlyMemory<byte>> attributeCertificates) =>
        PhaseOne(b => b.WithAttributeCertificates(attributeCertificates));

    /// <summary>
    /// Adds assertions about the signer signed by third parties, in the signer-attributes-v2 attribute. They are
    /// embedded as given: the library does not verify the third party's signature.
    /// </summary>
    /// <param name="assertions">The signed assertions.</param>
    /// <returns>A new builder with the signed assertions configured.</returns>
    /// <exception cref="ArgumentException">An assertion has no OID.</exception>
    public CadesDeferredSignerBuilder WithSignedAssertions(IReadOnlyList<CadesSignedAssertion> assertions) =>
        PhaseOne(b => b.WithSignedAssertions(assertions));

    /// <summary>
    /// Adds RFC 5126 extended validation data after the signature timestamp (CAdES-C/X, X-L or A). It needs a
    /// timestamped level; the form travels in the session and is built in phase two.
    /// </summary>
    /// <param name="form">The extended form.</param>
    /// <returns>A new builder with the extended form configured.</returns>
    public CadesDeferredSignerBuilder WithExtendedValidationData(CadesExtendedForm form) =>
        PhaseOne(b => b.WithExtendedValidationData(form));

    #endregion

    #region Both phases: runtime dependencies

    /// <summary>
    /// Sets the HTTP provider used when no scoped provider is given: the revocation check and the content
    /// timestamp in phase one; the timestamps and the validation data in phase two. It is not stored in the
    /// session: set it again on the resumed builder.
    /// </summary>
    /// <param name="provider">The HTTP client provider.</param>
    /// <returns>A new builder with the provider configured.</returns>
    public CadesDeferredSignerBuilder WithHttpClientProvider(IHttpClientProvider provider) =>
        With(_inner.WithHttpClientProvider(provider));

    /// <summary>
    /// Sets the signing policy (<see cref="SigningPolicy.Load"/>). Phase one runs its checks on the certificate,
    /// the chain and the algorithms before the bytes to sign are produced; phase two applies its <c>Timestamp</c>
    /// constraints to the timestamps it obtains. Default: <see cref="SigningPolicy.Default"/>.
    /// </summary>
    /// <param name="policy">The signing policy.</param>
    /// <returns>A new builder with the policy configured.</returns>
    public CadesDeferredSignerBuilder WithSigningPolicy(SigningPolicy policy) =>
        With(_inner.WithSigningPolicy(policy));

    /// <summary>
    /// Adds trust anchors: for the signing certificate in phase one, and for the TSA certificate in phase two,
    /// when the signing policy asks for a trusted chain.
    /// </summary>
    /// <param name="providers">The trust anchor providers.</param>
    /// <returns>A new builder with the anchors added.</returns>
    public CadesDeferredSignerBuilder WithTrustAnchors(params ITrustAnchorProvider[] providers) =>
        With(_inner.WithTrustAnchors(providers));

    /// <summary>Sets the checker used for the revocation check of the signing policy (<c>NotRevoked</c>, <c>RevocationDataAvailable</c>).</summary>
    /// <param name="checker">The chain revocation checker.</param>
    /// <returns>A new builder with the checker configured.</returns>
    public CadesDeferredSignerBuilder WithChainRevocationChecker(IChainRevocationChecker checker) =>
        With(_inner.WithChainRevocationChecker(checker));

    /// <summary>
    /// Records the operations of this builder with <paramref name="sink"/>: a refusal while preparing, and the
    /// outcome of the completion (the signature made, or the refusal). Set it on the builder that prepares and
    /// on the resumed one.
    /// </summary>
    /// <param name="sink">The audit sink.</param>
    /// <returns>A new builder with the sink configured.</returns>
    public CadesDeferredSignerBuilder WithAuditSink(ISignatureAuditSink sink) =>
        With(_inner.WithAuditSink(sink));

    /// <summary>
    /// Sets an operation id that correlates the audit records and the log messages of the two phases. The id
    /// given in phase one travels in the session; calling this on the resumed builder replaces it.
    /// </summary>
    /// <param name="operationId">The operation id.</param>
    /// <returns>A new builder with the operation id configured.</returns>
    public CadesDeferredSignerBuilder WithOperationId(string operationId) =>
        With(_inner.WithOperationId(operationId));

    /// <summary>Sets the logger for diagnostic output.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>A new builder with the logger configured.</returns>
    public CadesDeferredSignerBuilder WithLogger(ILogger logger) =>
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
    /// <exception cref="InvalidOperationException">The builder was not returned by <see cref="CadesDeferredSigner.Resume(byte[], byte[])"/>, or the session has no timestamp.</exception>
    /// <exception cref="ArgumentException">An endpoint differs from the one recorded in the session.</exception>
    public CadesDeferredSignerBuilder WithTimestampOptions(TimestampOptions timestamp, ArchiveTimestampOptions? archiveTimestamp = null)
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
    /// Gives the content of a session prepared with <see cref="WithContentOutsideSession"/>. It must be the
    /// content phase one signed: its SHA-256 is compared with the one the session carries.
    /// </summary>
    /// <param name="data">The content given to <see cref="CadesDeferredSigner.Document(byte[])"/> in phase one. The array is copied.</param>
    /// <returns>A new builder with the content.</returns>
    /// <exception cref="InvalidOperationException">The builder was not resumed, or its session carries the content.</exception>
    /// <exception cref="ArgumentException">The data is not the content the session was prepared for.</exception>
    public CadesDeferredSignerBuilder WithContent(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (_session is null)
        {
            throw new InvalidOperationException("WithContent completes a resumed session; when preparing, the content is given to Document().");
        }

        if (_session.ContentSha256 is not { } expected)
        {
            throw new InvalidOperationException("The session carries its content: WithContent is for a session prepared with WithContentOutsideSession().");
        }

        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(data), expected))
        {
            throw new ArgumentException("The data is not the content this session was prepared for.", nameof(data));
        }

        return new CadesDeferredSignerBuilder(_inner.WithData(data), _session, _sessionIntegrityKey, hasContent: true);
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
    /// <exception cref="InvalidOperationException">The builder was resumed: it can only complete its session.</exception>
    public Task<CadesDeferredPrepareResult> PrepareAsync(CancellationToken cancellationToken = default)
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
        return _inner.PrepareDeferredAsync(sessionIntegrityKey, _hasContent, cancellationToken);
    }

    /// <summary>
    /// Phase two: verifies <paramref name="rawSignature"/> against the certificate of the session, assembles the
    /// signature and finishes the requested level. Throws when the profile allows a lower level: use
    /// <see cref="CompleteWithDetailsAsync(byte[], CancellationToken)"/> in that case.
    /// </summary>
    /// <param name="rawSignature">
    /// The raw signature over the data to sign: RSA PKCS#1 v1.5 or PSS, or an ECDSA DER SEQUENCE { r, s }.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The DER-encoded CMS signature.</returns>
    /// <exception cref="SigningException">The signature does not verify with the certificate, or the requested level could not be produced.</exception>
    /// <exception cref="InvalidOperationException">The builder was not returned by <see cref="CadesDeferredSigner.Resume(byte[], byte[])"/>.</exception>
    public async Task<byte[]> CompleteAsync(byte[] rawSignature, CancellationToken cancellationToken = default)
    {
        BaselineSigning.EnsureStrictProfile(_inner.Profile);
        CadesSigningResult result = await CompleteWithDetailsAsync(rawSignature, cancellationToken).ConfigureAwait(false);
        return result.SignedArtifact;
    }

    /// <summary>
    /// Phase two, with the signature, the requested and achieved levels, what the artifact holds and the
    /// warnings. The outcome, signed or refused, is recorded by the audit sink.
    /// </summary>
    /// <param name="rawSignature">
    /// The raw signature over the data to sign: RSA PKCS#1 v1.5 or PSS, or an ECDSA DER SEQUENCE { r, s }.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The detailed CAdES signing result.</returns>
    /// <exception cref="SigningException">The signature does not verify with the certificate, or the requested level could not be produced.</exception>
    /// <exception cref="InvalidOperationException">The builder was not returned by <see cref="CadesDeferredSigner.Resume(byte[], byte[])"/>.</exception>
    public Task<CadesSigningResult> CompleteWithDetailsAsync(byte[] rawSignature, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rawSignature);
        if (rawSignature.Length == 0)
        {
            throw new ArgumentException("Signature bytes cannot be empty.", nameof(rawSignature));
        }

        CadesDeferredSession session = _session ?? throw new InvalidOperationException(
            "Only a builder returned by CadesDeferredSigner.Resume can complete a persisted session.");
        if (!_hasContent)
        {
            throw new InvalidOperationException(
                "The session was prepared without its content: give it with WithContent() before completing.");
        }

        return _inner.CompleteDeferredAsync(session, rawSignature, cancellationToken);
    }

    #endregion

    private CadesDeferredSignerBuilder With(CadesSignerBuilder inner) =>
        new(inner, _session, _sessionIntegrityKey, _hasContent);

    private CadesDeferredSignerBuilder PhaseOne(Func<CadesSignerBuilder, CadesSignerBuilder> configure, [CallerMemberName] string method = "")
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
