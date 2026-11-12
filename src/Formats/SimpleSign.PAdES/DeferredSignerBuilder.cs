using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.PAdES;

/// <summary>
/// Fluent builder for deferred (two-phase) PAdES signing.
/// Immutable — each method returns a new instance with updated configuration.
/// </summary>
/// <remarks>
/// <para>
/// Create instances through <see cref="DeferredSigner.Document(byte[])"/> to prepare a signature, or through
/// <see cref="DeferredSigner.Resume(byte[], byte[])"/> to complete one. The builder takes the options of
/// <see cref="PadesSignerBuilder"/>, with the same meaning.
/// </para>
/// <para>
/// Phase one (<see cref="PrepareAsync(CancellationToken)"/>) fixes everything the signature covers: the
/// signature field and its appearance, the signing time, the document information entries, the signature
/// policy and the other signed attributes. The prepared PDF and the signed attributes travel in the session,
/// so these options are set before preparing; the ones added after the session format was first released
/// throw <see cref="InvalidOperationException"/> on a resumed builder.
/// </para>
/// <para>
/// What a session cannot store is given again on the resumed builder: the HTTP provider, the signing policy,
/// the trust anchors and country extensions that check the TSA, the audit sink, the logger and, with
/// <see cref="WithTimestampOptions(TimestampOptions, ArchiveTimestampOptions?)"/>, the TSA credentials.
/// </para>
/// <para>
/// Not available, because of what two-phase signing is: <c>WithExternalSigner</c> and
/// <c>WithCertificateFile</c> (the key signs on another machine, between the phases; give the public
/// certificate to <see cref="WithCertificate(X509Certificate2)"/>), signing to a stream, and
/// <c>SignWithDetailsAsync</c> (completion returns the PDF and takes a strict profile only).
/// </para>
/// </remarks>
public sealed class DeferredSignerBuilder
{
    private readonly State _state;

    /// <summary>Initializes a deferred builder without credentials.</summary>
    internal DeferredSignerBuilder(byte[] pdfBytes)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        _state = new State([.. pdfBytes], SessionData: null, SessionIntegrityKey: null, Profile: null);
    }

    /// <summary>Initializes a deferred builder that resumes phase two from serialized session data.</summary>
    internal DeferredSignerBuilder(byte[] sessionData, byte[] sessionIntegrityKey, AdesBaselineProfile profile, string? operationId)
    {
        ArgumentNullException.ThrowIfNull(sessionData);
        ArgumentNullException.ThrowIfNull(sessionIntegrityKey);
        _state = new State([], [.. sessionData], [.. sessionIntegrityKey], profile) { OperationId = operationId };
    }

    private DeferredSignerBuilder(State state)
    {
        _state = state;
    }

    /// <summary>
    /// The registered country extensions, whose trust anchors are used with the ones given to
    /// <see cref="WithTrustAnchors(ITrustAnchorProvider[])"/>.
    /// </summary>
    public IReadOnlyList<ICountryExtension> CountryExtensions => _state.CountryExtensions;

    #region Fluent Configuration

    /// <summary>Sets the certificate used to verify the raw external signature.</summary>
    public DeferredSignerBuilder WithCertificate(X509Certificate2 certificate) =>
        new(_state with { Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate)), ExtraCertificates = [] });

    /// <summary>Sets the certificate and certificate chain included in the CMS.</summary>
    public DeferredSignerBuilder WithCertificate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chain);
        return new(_state with { Certificate = certificate, ExtraCertificates = [.. chain] });
    }

    /// <summary>Sets the hash algorithm for the signature. Default: SHA-256.</summary>
    public DeferredSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        new(_state with { HashAlgorithm = algorithm, HashAlgorithmExplicitlySet = true });

    /// <summary>Replaces the complete PDF signature field configuration.</summary>
    public DeferredSignerBuilder WithFieldOptions(SignatureFieldOptions fieldOptions)
    {
        ArgumentNullException.ThrowIfNull(fieldOptions);
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldOptions.FieldName);
        return new(_state with { Field = fieldOptions.Snapshot() });
    }

    /// <summary>Specifies a custom signature algorithm OID. Default: auto-detected from certificate.</summary>
    public DeferredSignerBuilder WithSignatureAlgorithm(string oid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        return new(_state with { SignatureAlgorithmOid = oid });
    }

    /// <summary>Sets the complete ADeS baseline profile for completion.</summary>
    public DeferredSignerBuilder WithLevel(AdesBaselineProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return new(_state with { Profile = profile });
    }

    /// <summary>
    /// Supplies the TSA settings a resumed session cannot store: credentials
    /// (<see cref="TimestampOptions.Authorization"/>), the mutual-TLS client certificate and a
    /// scoped HTTP provider. The session keeps only the TSA endpoints, so each endpoint here must
    /// match the one recorded in phase one; the requested level does not change.
    /// </summary>
    /// <param name="timestamp">The signature TSA, at the endpoint the session recorded.</param>
    /// <param name="archiveTimestamp">
    /// The archive TSA for B-LTA sessions; null keeps the session's (or inherits the signature TSA).
    /// </param>
    /// <returns>A new builder with the completed TSA settings.</returns>
    /// <exception cref="InvalidOperationException">The builder was not returned by <see cref="DeferredSigner.Resume(byte[], byte[])"/>, or the session has no timestamp.</exception>
    /// <exception cref="ArgumentException">An endpoint differs from the one recorded in the session.</exception>
    public DeferredSignerBuilder WithTimestampOptions(TimestampOptions timestamp, ArchiveTimestampOptions? archiveTimestamp = null)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        if (_state.SessionData is null)
        {
            throw new InvalidOperationException(
                "WithTimestampOptions completes a resumed session; when preparing, pass the TSA in WithLevel.");
        }

        return new(_state with { Profile = DeferredProfile.WithTimestampOptions(_state.Profile, timestamp, archiveTimestamp) });
    }

    /// <summary>Sets the fallback HTTP provider used by timestamp and LTV completion.</summary>
    public DeferredSignerBuilder WithHttpClientProvider(IHttpClientProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return new(_state with { HttpClientProvider = provider });
    }

    /// <summary>
    /// Sets the checks run before the hash is prepared, read from a JSON signing policy (<see cref="SigningPolicy.Load"/>):
    /// validity of the chain, key usage, key size, digest algorithm and, when <c>NotRevoked</c> is not IGNORE, the
    /// revocation of the chain. Default: <see cref="SigningPolicy.Default"/>.
    /// </summary>
    public DeferredSignerBuilder WithSigningPolicy(SigningPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return new(_state with { SigningPolicy = policy });
    }

    /// <summary>
    /// Adds trust anchors for the checks made before the hash is prepared: the signing certificate must chain to one
    /// of them when the signing policy's <c>SigningCertificate/ProspectiveCertificateChain</c> is not IGNORE, and they
    /// complete a chain given without its root for the revocation check. The anchors of the country extensions
    /// (<see cref="WithCountryExtension(ICountryExtension)"/>) are used too.
    /// </summary>
    /// <param name="providers">The trust anchor providers.</param>
    /// <returns>A new builder with the anchors added.</returns>
    public DeferredSignerBuilder WithTrustAnchors(params ITrustAnchorProvider[] providers)
    {
        ArgumentNullException.ThrowIfNull(providers);
        return new(_state with { TrustAnchors = [.. _state.TrustAnchors, .. providers] });
    }

    /// <summary>
    /// Records the operations of this builder with <paramref name="sink"/>: a refusal while preparing, and the outcome of
    /// the completion (the signature made, or the refusal). Set it on the builder that prepares and on the one returned by
    /// <see cref="DeferredSigner.Resume(byte[], byte[])"/>.
    /// </summary>
    /// <param name="sink">The audit sink.</param>
    /// <returns>A new builder with the sink configured.</returns>
    public DeferredSignerBuilder WithAuditSink(ISignatureAuditSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        return new(_state with { AuditSink = sink });
    }

    /// <summary>Sets the checker used for the revocation check of the signing policy (<c>NotRevoked</c>, <c>RevocationDataAvailable</c>).</summary>
    public DeferredSignerBuilder WithChainRevocationChecker(SimpleSign.Core.Revocation.IChainRevocationChecker checker)
    {
        ArgumentNullException.ThrowIfNull(checker);
        return new(_state with { ChainRevocationChecker = checker });
    }

    /// <summary>Sets a custom logger for diagnostic output.</summary>
    public DeferredSignerBuilder WithLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        return new(_state with { Logger = logger });
    }

    /// <summary>
    /// Sets the server-owned HMAC key used to authenticate the deferred session.
    /// The key must contain at least 32 bytes and is never serialized into the session.
    /// </summary>
    /// <param name="key">A server-owned HMAC key with at least 256 bits of entropy.</param>
    /// <returns>A new preparation builder with the supplied key snapshot.</returns>
    /// <exception cref="InvalidOperationException">Thrown when called on a resumed builder.</exception>
    public DeferredSignerBuilder WithSessionIntegrityKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length < 32)
        {
            throw new ArgumentException("The deferred session HMAC key must contain at least 32 bytes.", nameof(key));
        }

        if (_state.SessionData is not null)
        {
            throw new InvalidOperationException("The session integrity key is supplied by DeferredSigner.Resume and cannot be replaced.");
        }

        return new(_state with { SessionIntegrityKey = [.. key] });
    }

    /// <summary>
    /// Sets an operation id that correlates the audit records and the log messages of the two phases, and is
    /// carried by <see cref="DeferredSigningPrepareResult.ToSigningRequest"/>. The id given in phase one travels
    /// in the session; calling this on the resumed builder replaces it.
    /// </summary>
    /// <param name="operationId">The operation id.</param>
    /// <returns>A new builder with the operation id configured.</returns>
    public DeferredSignerBuilder WithOperationId(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return new(_state with { OperationId = operationId });
    }

    /// <summary>
    /// Registers a country/region-specific extension package (e.g., ICP-Brasil, IOFE). Its trust anchors are
    /// used for the trust check made before the hash is prepared and for the TSA certificate of the timestamps
    /// obtained while completing, when the signing policy asks for them. An extension is not stored in the
    /// session: register it again on the resumed builder.
    /// </summary>
    /// <typeparam name="T">A concrete <see cref="ICountryExtension"/> with a parameterless constructor.</typeparam>
    /// <returns>A new builder with the extension registered.</returns>
    public DeferredSignerBuilder WithCountryExtension<T>()
        where T : ICountryExtension, new() =>
        new(_state with { CountryExtensions = [.. _state.CountryExtensions, new T()] });

    /// <summary>
    /// Registers a pre-configured country extension instance (see <see cref="WithCountryExtension{T}()"/>), for an
    /// extension that needs constructor-injected dependencies.
    /// </summary>
    /// <param name="extension">The country extension instance.</param>
    /// <returns>A new builder with the extension registered.</returns>
    public DeferredSignerBuilder WithCountryExtension(ICountryExtension extension)
    {
        ArgumentNullException.ThrowIfNull(extension);
        return new(_state with { CountryExtensions = [.. _state.CountryExtensions, extension] });
    }

    #endregion

    #region Phase one: what the signature covers

    /// <summary>
    /// Configures the claimed signing time written in the signature dictionary (<c>/M</c>). This is not trusted
    /// proof of time; B-T or higher still requires a signature timestamp. Default: the moment of
    /// <see cref="PrepareAsync(CancellationToken)"/>.
    /// </summary>
    /// <param name="signingTime">The claimed signing time.</param>
    /// <returns>A new builder with the signing time configured.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithSigningTime(DateTimeOffset signingTime) =>
        PhaseOne(_state with { SigningTime = signingTime });

    /// <summary>
    /// Sets the signature policy, with its hash, as the signature-policy-identifier signed
    /// attribute (ETSI EN 319 122-1 §5.2.9) — e.g. an ICP-Brasil AD-RB/AD-RT policy.
    /// </summary>
    /// <param name="policy">The policy OID, hash and optional URI.</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithSignaturePolicy(SignaturePolicyReference policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return PhaseOne(_state with { SignaturePolicy = policy });
    }

    /// <summary>
    /// Configures generic signer metadata for the signature. Replaces signer, reason, location, and contact
    /// field values (omitted values clear earlier ones) and adds the commitment type, the policy and the extra
    /// signed attributes of the metadata.
    /// </summary>
    /// <param name="metadata">The signer metadata.</param>
    /// <returns>A new builder with the metadata configured.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithMetadata(SignatureMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        return PhaseOne(_state with
        {
            Field = PadesSigningInputs.ApplyMetadata(_state.Field, metadata),
            Metadata = PadesSigningInputs.CopyMetadata(metadata),
        });
    }

    /// <summary>
    /// Sets an entry of the PDF document information dictionary (ISO 32000-1 §14.3.3) in the
    /// signing revision, so the signature covers it. Existing entries are kept; a key set
    /// twice keeps the last value. Not supported when signing an existing field.
    /// </summary>
    /// <param name="key">The key, without the leading slash (e.g. <c>Title</c>, or an OID).</param>
    /// <param name="value">The text value.</param>
    /// <returns>A new builder with the entry configured.</returns>
    /// <exception cref="ArgumentException">The key is empty or not a valid PDF name.</exception>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithDocumentInfo(string key, string value) =>
        PhaseOne(_state with { DocumentInfo = PadesSigningInputs.WithDocumentInfo(_state.DocumentInfo, key, value) });

    /// <summary>
    /// Enables PDF/A conformance checking while preparing. If the input document is a PDF/A file and the
    /// signature options are incompatible with that level, a <see cref="SigningException"/> is thrown by
    /// <see cref="PrepareAsync(CancellationToken)"/>, before anything is handed out to be signed.
    /// </summary>
    /// <returns>A new builder with PDF/A preservation enabled.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithPdfAPreservation() =>
        PhaseOne(_state with { EnforcePdfA = true });

    /// <summary>
    /// Adds extra streams to the Document Security Store written for B-LT/B-LTA: each one is listed in the DSS
    /// array <see cref="PdfDssArtifact.DssKey"/> and referenced from this signature's VRI as
    /// <see cref="PdfDssArtifact.VriKey"/>. Needs a B-LT or B-LTA profile. The artifacts travel in the session
    /// and are written in phase two.
    /// </summary>
    /// <param name="artifacts">The artifacts.</param>
    /// <returns>A new builder with the artifacts configured.</returns>
    /// <exception cref="ArgumentException">An artifact key is not usable.</exception>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithDssArtifacts(IEnumerable<PdfDssArtifact> artifacts)
    {
        var list = PadesSigningInputs.ValidatedArtifacts(artifacts);
        return PhaseOne(_state with { DssArtifacts = [.. _state.DssArtifacts, .. list] });
    }

    /// <summary>Sets the signature field name.</summary>
    /// <param name="fieldName">The PDF signature field name.</param>
    /// <returns>A new builder with the field name configured.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithFieldName(string fieldName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldName);
        return PhaseOne(_state with { Field = CloneField(fieldName: fieldName) });
    }

    /// <summary>
    /// Adds a visual appearance (stamp) to the signature on a specific page.
    /// The stamp displays the signer name, date/time, and other configured metadata.
    /// </summary>
    /// <param name="appearance">The visual appearance configuration.</param>
    /// <returns>A new builder with the appearance configured.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithAppearance(SignatureAppearance appearance)
    {
        ArgumentNullException.ThrowIfNull(appearance);
        return PhaseOne(_state with { Field = CloneField(appearance: appearance.Snapshot()) });
    }

    /// <summary>
    /// Creates a certification (DocMDP) signature that restricts subsequent document modifications.
    /// Only the first signature in a document can be a certification signature.
    /// </summary>
    /// <param name="level">The permitted modification level after certification.</param>
    /// <returns>A new builder with the certification level configured.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder AsCertification(CertificationLevel level = CertificationLevel.FormFilling) =>
        PhaseOne(_state with { Field = CloneField(certificationLevel: level) });

    /// <summary>
    /// Signs an existing empty signature field instead of creating a new one.
    /// The field must already exist in the PDF with an empty /V value.
    /// </summary>
    /// <param name="fieldName">The name of the existing signature field (the /T value).</param>
    /// <returns>A new builder with the existing field configured.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithExistingField(string fieldName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldName);
        return PhaseOne(_state with { Field = CloneField(existingFieldName: fieldName) });
    }

    /// <summary>
    /// Sets the signature SubFilter value. Default is <see cref="PdfSignatureSubFilter.EtsiCadesDetached"/>.
    /// Use <see cref="PdfSignatureSubFilter.AdbePkcs7Detached"/> for PDF/A-1 compatibility
    /// or when the target validator requires the legacy subfilter.
    /// </summary>
    /// <param name="subFilter">The signature SubFilter value.</param>
    /// <returns>A new builder with the SubFilter configured.</returns>
    /// <exception cref="InvalidOperationException">The builder was resumed.</exception>
    public DeferredSignerBuilder WithSubFilter(PdfSignatureSubFilter subFilter) =>
        PhaseOne(_state with { Field = CloneField(subFilter: subFilter) });

    #endregion

    #region Execution Methods

    /// <summary>
    /// One-shot signing: Prepares the hash and immediately completes the signature.
    /// Use this when the signing happens synchronously on the same machine.
    /// </summary>
    public async Task<byte[]> SignAsync(byte[] signature, CancellationToken cancellationToken = default)
    {
        EnsureStrictProfile();
        ArgumentNullException.ThrowIfNull(signature);
        if (signature.Length == 0)
        {
            throw new ArgumentException("Signature bytes cannot be empty.", nameof(signature));
        }

        var prepared = await PrepareAsync(cancellationToken).ConfigureAwait(false);
        return await CompleteCoreAsync(prepared.SessionData, signature, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Phase 1: Prepares the document and returns the hash to be signed.
    /// The hash must be signed by the external signer (e.g., hardware token, browser).
    /// </summary>
    public async Task<DeferredSigningPrepareResult> PrepareAsync(CancellationToken cancellationToken = default)
    {
        if (_state.SessionData is not null)
        {
            throw new InvalidOperationException("A resumed deferred signer can only complete an existing session.");
        }

        var certificate = _state.Certificate ?? throw new SigningException(
            "Certificate is required. Call WithCertificate() before preparing a deferred signature.",
            SigningErrorReason.CredentialMissing);
        var sessionIntegrityKey = _state.SessionIntegrityKey ?? throw new SigningException(
            "A session integrity key is required. Call WithSessionIntegrityKey() before preparing a deferred signature.",
            SigningErrorReason.LevelDependenciesMissing);
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = _state.HashAlgorithm,
            HashAlgorithmExplicitlySet = _state.HashAlgorithmExplicitlySet,
            FieldOptions = _state.Field,
            SignatureAlgorithmOid = _state.SignatureAlgorithmOid,
            ExtraCertificates = _state.ExtraCertificates,
            Profile = _state.Profile,
            SigningPolicy = _state.SigningPolicy,
            ChainRevocationChecker = _state.ChainRevocationChecker,
            TrustAnchors = _state.AllTrustAnchors,
            HttpClientProvider = _state.HttpClientProvider,
            OperationId = _state.OperationId,
            EnforcePdfA = _state.EnforcePdfA,
            SigningTime = _state.SigningTime,
            DocumentInfo = _state.DocumentInfo,
            ExtraAttributes = PadesSigningInputs.ExtraSignedAttributes(_state.Metadata, _state.SignaturePolicy),
            DssArtifacts = _state.DssArtifacts,
        };

        try
        {
            return await DeferredSigner.PrepareAsync(
                _state.PdfBytes, certificate, sessionIntegrityKey, options, _state.Logger, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (_state.AuditSink is not null && ex is not OperationCanceledException)
        {
            var refused = SignatureAuditEvent.Start(
                "PAdES", _state.OperationId, RequestedLevel, certificate, _state.SigningPolicy, _state.PdfBytes);
            await _state.AuditSink.RecordAsync(
                refused with { Reason = (ex as SigningException)?.Reason, Message = ex.Message }, cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    private async Task<byte[]> CompleteCoreAsync(byte[] sessionData, byte[] rawSignature, CancellationToken cancellationToken)
    {
        EnsureStrictProfile();
        ArgumentNullException.ThrowIfNull(sessionData);
        ArgumentNullException.ThrowIfNull(rawSignature);
        if (sessionData.Length == 0)
        {
            throw new ArgumentException("Session data cannot be empty.", nameof(sessionData));
        }

        if (rawSignature.Length == 0)
        {
            throw new ArgumentException("Signature bytes cannot be empty.", nameof(rawSignature));
        }

        var completeOptions = new DeferredSigningCompleteOptions
        {
            Profile = _state.Profile,
            HttpClientProvider = _state.HttpClientProvider,
            SigningPolicy = _state.SigningPolicy,
            TrustAnchors = _state.AllTrustAnchors,
            ChainRevocationChecker = _state.ChainRevocationChecker,
        };

        return await SignatureAudit.RunAsync(
            _state.AuditSink,
            () =>
            {
                var session = DeferredSigningSession.Deserialize(sessionData, RequireSessionIntegrityKey());
                using var certificate = CertificateLoader.LoadCertificate(session.CertificateDer);
                return SignatureAuditEvent.Start(
                    "PAdES", _state.OperationId ?? session.OperationId, RequestedLevel, certificate, _state.SigningPolicy, default);
            },
            () => DeferredSigner.CompleteAsync(
                sessionData, rawSignature, RequireSessionIntegrityKey(), completeOptions, _state.Logger, cancellationToken: cancellationToken),
            signed => (signed, RequestedLevel),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Completes the session supplied to <see cref="DeferredSigner.Resume(byte[], byte[])"/>.
    /// </summary>
    /// <param name="rawSignature">Raw signature bytes produced by the external signer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The completed signed PDF.</returns>
    public Task<byte[]> CompleteAsync(byte[] rawSignature, CancellationToken cancellationToken = default)
    {
        if (_state.SessionData is null)
        {
            throw new InvalidOperationException("Only a builder returned by DeferredSigner.Resume can complete a persisted session.");
        }

        return CompleteCoreAsync(_state.SessionData, rawSignature, cancellationToken);
    }

    #endregion

    #region Private Helpers

    private AdesBaselineLevel RequestedLevel => (_state.Profile ?? AdesBaselineProfile.Basic()).Level;

    private void EnsureStrictProfile()
    {
        if (_state.Profile?.FailureBehavior == SigningLevelFailureBehavior.ReturnLowerLevel)
        {
            throw new SigningException(
                "Deferred completion returns PDF bytes only. Use a strict baseline profile so successful completion cannot hide a level downgrade.",
                SigningErrorReason.DowngradeRequiresDetailedResult);
        }
    }

    private DeferredSignerBuilder PhaseOne(State state, [CallerMemberName] string method = "")
    {
        if (_state.SessionData is not null)
        {
            throw new InvalidOperationException(
                $"{method} is set before PrepareAsync: a resumed session completes what phase one fixed.");
        }

        return new(state);
    }

    private byte[] RequireSessionIntegrityKey()
    {
        return _state.SessionIntegrityKey ?? throw new InvalidOperationException(
            "A deferred completion builder must have a session integrity key.");
    }

    private SignatureFieldOptions CloneField(
        string? fieldName = null,
        SignatureAppearance? appearance = null,
        CertificationLevel? certificationLevel = null,
        string? existingFieldName = null,
        PdfSignatureSubFilter? subFilter = null)
    {
        var current = _state.Field;
        return new SignatureFieldOptions
        {
            FieldName = fieldName ?? current.FieldName,
            SignerName = current.SignerName,
            Reason = current.Reason,
            Location = current.Location,
            ContactInfo = current.ContactInfo,
            ContentsReservedBytes = current.ContentsReservedBytes,
            SubFilter = subFilter ?? current.SubFilter,
            Appearance = appearance ?? current.Appearance,
            CertificationLevel = certificationLevel ?? current.CertificationLevel,
            ExistingFieldName = existingFieldName ?? current.ExistingFieldName
        };
    }

    /// <summary>The immutable configuration of the builder; fluent calls replace it with a changed copy.</summary>
    private sealed record State(byte[] PdfBytes, byte[]? SessionData, byte[]? SessionIntegrityKey, AdesBaselineProfile? Profile)
    {
        public X509Certificate2? Certificate { get; init; }

        public IReadOnlyList<X509Certificate2> ExtraCertificates { get; init; } = [];

        public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

        public bool HashAlgorithmExplicitlySet { get; init; }

        public string? SignatureAlgorithmOid { get; init; }

        public SignatureFieldOptions Field { get; init; } = new();

        public ILogger Logger { get; init; } = NullLogger.Instance;

        public IHttpClientProvider? HttpClientProvider { get; init; }

        public SigningPolicy SigningPolicy { get; init; } = SigningPolicy.Default;

        public SimpleSign.Core.Revocation.IChainRevocationChecker? ChainRevocationChecker { get; init; }

        public IReadOnlyList<ITrustAnchorProvider> TrustAnchors { get; init; } = [];

        public IReadOnlyList<ICountryExtension> CountryExtensions { get; init; } = [];

        public ISignatureAuditSink? AuditSink { get; init; }

        public string? OperationId { get; init; }

        public bool EnforcePdfA { get; init; }

        public DateTimeOffset? SigningTime { get; init; }

        public SignaturePolicyReference? SignaturePolicy { get; init; }

        public SignatureMetadata? Metadata { get; init; }

        public IReadOnlyDictionary<string, string>? DocumentInfo { get; init; }

        public IReadOnlyList<PdfDssArtifact> DssArtifacts { get; init; } = [];

        /// <summary>The trust anchors given to the builder, then those of the country extensions.</summary>
        public IReadOnlyList<ITrustAnchorProvider> AllTrustAnchors =>
            [.. TrustAnchors, .. CountryExtensions.SelectMany(e => e.TrustAnchorProviders)];
    }

    #endregion
}
