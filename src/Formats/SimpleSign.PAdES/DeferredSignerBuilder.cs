using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
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
/// Create instances through <see cref="DeferredSigner.Document(byte[])"/>. Configure all
/// PDF-field data with <see cref="WithFieldOptions(SignatureFieldOptions)"/> and enrichment
/// with <see cref="WithLevel(AdesBaselineProfile)"/>.
/// </remarks>
public sealed class DeferredSignerBuilder
{
    private readonly byte[] _pdfBytes;
    private readonly byte[]? _sessionData;
    private readonly X509Certificate2? _certificate;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly bool _hashAlgorithmExplicitlySet;
    private readonly SignatureFieldOptions _fieldOptions;
    private readonly string? _signatureAlgorithmOid;
    private readonly IReadOnlyList<X509Certificate2>? _extraCertificates;
    private readonly ILogger _logger;
    private readonly AdesBaselineProfile? _profile;
    private readonly IHttpClientProvider? _httpClientProvider;
    private readonly byte[]? _sessionIntegrityKey;
    private readonly SigningPolicy _signingPolicy = SigningPolicy.Default;
    private readonly SimpleSign.Core.Revocation.IChainRevocationChecker? _chainRevocationChecker;

    /// <summary>Initializes a deferred builder without credentials.</summary>
    internal DeferredSignerBuilder(byte[] pdfBytes)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        _pdfBytes = [.. pdfBytes];
        _sessionData = null;
        _certificate = null;
        _hashAlgorithm = HashAlgorithmName.SHA256;
        _hashAlgorithmExplicitlySet = false;
        _fieldOptions = new SignatureFieldOptions();
        _signatureAlgorithmOid = null;
        _extraCertificates = [];
        _logger = NullLogger.Instance;
        _profile = null;
        _httpClientProvider = null;
        _sessionIntegrityKey = null;
    }

    /// <summary>Initializes a deferred builder that resumes phase two from serialized session data.</summary>
    internal DeferredSignerBuilder(byte[] sessionData, byte[] sessionIntegrityKey, AdesBaselineProfile profile, bool resume)
    {
        ArgumentNullException.ThrowIfNull(sessionData);
        ArgumentNullException.ThrowIfNull(sessionIntegrityKey);
        if (!resume)
        {
            throw new ArgumentException("Only the deferred resume entry point can create a completion builder.", nameof(resume));
        }

        _pdfBytes = [];
        _sessionData = [.. sessionData];
        _certificate = null;
        _hashAlgorithm = HashAlgorithmName.SHA256;
        _hashAlgorithmExplicitlySet = false;
        _fieldOptions = new SignatureFieldOptions();
        _signatureAlgorithmOid = null;
        _extraCertificates = [];
        _logger = NullLogger.Instance;
        _profile = profile;
        _httpClientProvider = null;
        _sessionIntegrityKey = [.. sessionIntegrityKey];
    }

    private DeferredSignerBuilder(
        byte[] pdfBytes,
        byte[]? sessionData,
        X509Certificate2? certificate,
        HashAlgorithmName hashAlgorithm,
        bool hashAlgorithmExplicitlySet,
        SignatureFieldOptions fieldOptions,
        string? signatureAlgorithmOid,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        ILogger logger,
        AdesBaselineProfile? profile,
        IHttpClientProvider? httpClientProvider,
        byte[]? sessionIntegrityKey,
        SigningPolicy signingPolicy,
        SimpleSign.Core.Revocation.IChainRevocationChecker? chainRevocationChecker)
    {
        _signingPolicy = signingPolicy;
        _chainRevocationChecker = chainRevocationChecker;
        _pdfBytes = pdfBytes;
        _sessionData = sessionData;
        _certificate = certificate;
        _hashAlgorithm = hashAlgorithm;
        _hashAlgorithmExplicitlySet = hashAlgorithmExplicitlySet;
        _fieldOptions = fieldOptions;
        _signatureAlgorithmOid = signatureAlgorithmOid;
        _extraCertificates = extraCertificates;
        _logger = logger;
        _profile = profile;
        _httpClientProvider = httpClientProvider;
        _sessionIntegrityKey = sessionIntegrityKey;
    }

    #region Fluent Configuration

    /// <summary>Sets the certificate used to verify the raw external signature.</summary>
    public DeferredSignerBuilder WithCertificate(X509Certificate2 certificate) =>
        With(certificate: certificate ?? throw new ArgumentNullException(nameof(certificate)), replaceCertificate: true, extraCertificates: []);

    /// <summary>Sets the certificate and certificate chain included in the CMS.</summary>
    public DeferredSignerBuilder WithCertificate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chain);
        return With(certificate: certificate, replaceCertificate: true, extraCertificates: [.. chain]);
    }

    /// <summary>Sets the hash algorithm for the signature. Default: SHA-256.</summary>
    public DeferredSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm)
        => With(hashAlgorithm: algorithm, hashAlgorithmExplicitlySet: true);

    /// <summary>Replaces the complete PDF signature field configuration.</summary>
    public DeferredSignerBuilder WithFieldOptions(SignatureFieldOptions fieldOptions)
    {
        ArgumentNullException.ThrowIfNull(fieldOptions);
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldOptions.FieldName);
        return With(fieldOptions: SnapshotFieldOptions(fieldOptions));
    }

    /// <summary>Specifies a custom signature algorithm OID. Default: auto-detected from certificate.</summary>
    public DeferredSignerBuilder WithSignatureAlgorithm(string oid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        return With(signatureAlgorithmOid: oid);
    }

    /// <summary>Sets the complete ADeS baseline profile for completion.</summary>
    public DeferredSignerBuilder WithLevel(AdesBaselineProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return With(profile: profile);
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
        if (_sessionData is null)
        {
            throw new InvalidOperationException(
                "WithTimestampOptions completes a resumed session; when preparing, pass the TSA in WithLevel.");
        }

        var current = _profile;
        if (current?.Timestamp is null)
        {
            throw new InvalidOperationException("The deferred session was prepared without a timestamp (B-B).");
        }

        if (timestamp.Endpoint != current.Timestamp.Endpoint)
        {
            throw new ArgumentException(
                $"The session was prepared for the TSA {current.Timestamp.Endpoint}; the resumed TSA must be the same.",
                nameof(timestamp));
        }

        if (archiveTimestamp?.Endpoint is { } archiveEndpoint && current.ArchiveTimestamp?.Endpoint is { } recorded && archiveEndpoint != recorded)
        {
            throw new ArgumentException(
                $"The session was prepared for the archive TSA {recorded}; the resumed archive TSA must be the same.",
                nameof(archiveTimestamp));
        }

        var profile = current.Level switch
        {
            AdesBaselineLevel.Timestamped => AdesBaselineProfile.Timestamped(timestamp, current.FailureBehavior),
            AdesBaselineLevel.LongTerm => AdesBaselineProfile.LongTerm(
                timestamp, current.LongTermValidation ?? new LongTermValidationOptions(), current.FailureBehavior),
            _ => AdesBaselineProfile.Archive(
                timestamp,
                current.LongTermValidation ?? new LongTermValidationOptions(),
                archiveTimestamp ?? current.ArchiveTimestamp,
                current.FailureBehavior),
        };
        return With(profile: profile);
    }

    /// <summary>Sets the fallback HTTP provider used by timestamp and LTV completion.</summary>
    public DeferredSignerBuilder WithHttpClientProvider(IHttpClientProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return With(httpClientProvider: provider);
    }

    /// <summary>
    /// Sets the checks run before the hash is prepared, read from a JSON signing policy (<see cref="SigningPolicy.Load"/>):
    /// validity of the chain, key usage, key size, digest algorithm and, when <c>NotRevoked</c> is not IGNORE, the
    /// revocation of the chain. Default: <see cref="SigningPolicy.Default"/>.
    /// </summary>
    public DeferredSignerBuilder WithSigningPolicy(SigningPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return With(signingPolicy: policy);
    }

    /// <summary>Sets the checker used for the revocation check of the signing policy (<c>NotRevoked</c>, <c>RevocationDataAvailable</c>).</summary>
    public DeferredSignerBuilder WithChainRevocationChecker(SimpleSign.Core.Revocation.IChainRevocationChecker checker)
    {
        ArgumentNullException.ThrowIfNull(checker);
        return With(chainRevocationChecker: checker);
    }

    /// <summary>Sets a custom logger for diagnostic output.</summary>
    public DeferredSignerBuilder WithLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        return With(logger: logger);
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

        if (_sessionData is not null)
        {
            throw new InvalidOperationException("The session integrity key is supplied by DeferredSigner.Resume and cannot be replaced.");
        }

        return With(sessionIntegrityKey: [.. key], replaceSessionIntegrityKey: true);
    }

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
        if (_sessionData is not null)
        {
            throw new InvalidOperationException("A resumed deferred signer can only complete an existing session.");
        }

        var certificate = _certificate ?? throw new SigningException(
            "Certificate is required. Call WithCertificate() before preparing a deferred signature.",
            SigningErrorReason.CredentialMissing);
        var sessionIntegrityKey = _sessionIntegrityKey ?? throw new SigningException(
            "A session integrity key is required. Call WithSessionIntegrityKey() before preparing a deferred signature.",
            SigningErrorReason.LevelDependenciesMissing);
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = _hashAlgorithm,
            HashAlgorithmExplicitlySet = _hashAlgorithmExplicitlySet,
            FieldOptions = _fieldOptions,
            SignatureAlgorithmOid = _signatureAlgorithmOid,
            ExtraCertificates = _extraCertificates,
            Profile = _profile,
            SigningPolicy = _signingPolicy,
            ChainRevocationChecker = _chainRevocationChecker,
            HttpClientProvider = _httpClientProvider
        };

        return await DeferredSigner.PrepareAsync(
            _pdfBytes, certificate, sessionIntegrityKey, options, _logger, cancellationToken).ConfigureAwait(false);
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
            Profile = _profile,
            HttpClientProvider = _httpClientProvider
        };

        return await DeferredSigner.CompleteAsync(
            sessionData, rawSignature, RequireSessionIntegrityKey(), completeOptions, _logger, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Completes the session supplied to <see cref="DeferredSigner.Resume(byte[], byte[])"/>.
    /// </summary>
    /// <param name="rawSignature">Raw signature bytes produced by the external signer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The completed signed PDF.</returns>
    public Task<byte[]> CompleteAsync(byte[] rawSignature, CancellationToken cancellationToken = default)
    {
        if (_sessionData is null)
        {
            throw new InvalidOperationException("Only a builder returned by DeferredSigner.Resume can complete a persisted session.");
        }

        return CompleteCoreAsync(_sessionData, rawSignature, cancellationToken);
    }

    #endregion

    #region Private Helpers

    private void EnsureStrictProfile()
    {
        if (_profile?.FailureBehavior == SigningLevelFailureBehavior.ReturnLowerLevel)
        {
            throw new SigningException(
                "Deferred completion returns PDF bytes only. Use a strict baseline profile so successful completion cannot hide a level downgrade.",
                SigningErrorReason.DowngradeRequiresDetailedResult);
        }
    }

    private DeferredSignerBuilder With(
        X509Certificate2? certificate = null,
        bool replaceCertificate = false,
        HashAlgorithmName? hashAlgorithm = null,
        bool? hashAlgorithmExplicitlySet = null,
        SignatureFieldOptions? fieldOptions = null,
        string? signatureAlgorithmOid = null,
        IReadOnlyList<X509Certificate2>? extraCertificates = null,
        ILogger? logger = null,
        AdesBaselineProfile? profile = null,
        IHttpClientProvider? httpClientProvider = null,
        byte[]? sessionIntegrityKey = null,
        bool replaceSessionIntegrityKey = false,
        SigningPolicy? signingPolicy = null,
        SimpleSign.Core.Revocation.IChainRevocationChecker? chainRevocationChecker = null)
    {
        return new(
            _pdfBytes,
            _sessionData,
            replaceCertificate ? certificate : _certificate,
            hashAlgorithm ?? _hashAlgorithm,
            hashAlgorithmExplicitlySet ?? _hashAlgorithmExplicitlySet,
            fieldOptions ?? _fieldOptions,
            signatureAlgorithmOid ?? _signatureAlgorithmOid,
            extraCertificates ?? _extraCertificates,
            logger ?? _logger,
            profile ?? _profile,
            httpClientProvider ?? _httpClientProvider,
            replaceSessionIntegrityKey ? sessionIntegrityKey : _sessionIntegrityKey,
            signingPolicy ?? _signingPolicy,
            chainRevocationChecker ?? _chainRevocationChecker);
    }

    private byte[] RequireSessionIntegrityKey()
    {
        return _sessionIntegrityKey ?? throw new InvalidOperationException(
            "A deferred completion builder must have a session integrity key.");
    }

    private static SignatureFieldOptions SnapshotFieldOptions(SignatureFieldOptions source)
    {
        return new SignatureFieldOptions
        {
            FieldName = source.FieldName,
            SignerName = source.SignerName,
            Reason = source.Reason,
            Location = source.Location,
            ContactInfo = source.ContactInfo,
            ContentsReservedBytes = source.ContentsReservedBytes,
            SubFilter = source.SubFilter,
            Appearance = source.Appearance?.Snapshot(),
            CertificationLevel = source.CertificationLevel,
            ExistingFieldName = source.ExistingFieldName
        };
    }

    #endregion
}
