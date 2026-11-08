using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Internal;

namespace SimpleSign.PAdES;

/// <summary>
/// Entry point for two-phase PAdES signing where the private key resides on a
/// different machine (for example, an A3 hardware token in a user's browser).
/// </summary>
/// <example>
/// <code>
/// // Phase 1 — Server: prepare PDF and get hash for external signing.
/// var signer = DeferredSigner.Document(pdfBytes).WithCertificate(publicCert);
/// var result = await signer.PrepareAsync();
/// // Send result.HashToSign to the client; store result.SessionData on server
///
/// // Phase 2 — Server: complete signing with the raw signature from client
/// byte[] signedPdf = await DeferredSigner.Resume(result.SessionData, sessionIntegrityKey).CompleteAsync(rawSignature);
/// </code>
/// </example>
public static class DeferredSigner
{
    /// <summary>
    /// Creates a deferred PAdES builder for the supplied PDF bytes.
    /// </summary>
    /// <param name="pdfBytes">PDF bytes to snapshot for the deferred operation.</param>
    /// <returns>A builder that requires <c>WithCertificate</c> before preparation.</returns>
    public static DeferredSignerBuilder Document(byte[] pdfBytes)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        return new DeferredSignerBuilder(pdfBytes);
    }

    /// <summary>
    /// Resumes phase two of a deferred signing operation from server-side session data.
    /// </summary>
    /// <param name="sessionData">Integrity-protected serialized session returned by phase one.</param>
    /// <param name="sessionIntegrityKey">The server-owned HMAC key used during phase one.</param>
    /// <returns>A builder that can configure completion and embed the returned external signature.</returns>
    public static DeferredSignerBuilder Resume(byte[] sessionData, byte[] sessionIntegrityKey)
    {
        ArgumentNullException.ThrowIfNull(sessionData);
        ArgumentOutOfRangeException.ThrowIfZero(sessionData.Length);
        ArgumentNullException.ThrowIfNull(sessionIntegrityKey);
        var session = DeferredSigningSession.Deserialize(sessionData, sessionIntegrityKey);
        return new DeferredSignerBuilder(sessionData, sessionIntegrityKey, RestoreProfile(session), resume: true);
    }

    /// <summary>
    /// Internal phase-one implementation shared by the immutable deferred builder.
    /// </summary>
    /// <param name="pdfBytes">The original PDF document bytes.</param>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="options">Optional signing configuration.</param>
    /// <param name="logger">Optional logger for debug diagnostics.</param>
    /// <param name="sessionIntegrityKey">Server-owned HMAC key used to authenticate the serialized session.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Prepare result containing the hash to sign and serialized session data.</returns>
    internal static async Task<DeferredSigningPrepareResult> PrepareAsync(
        byte[] pdfBytes,
        X509Certificate2 certificate,
        byte[] sessionIntegrityKey,
        DeferredSigningOptions? options = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        ArgumentNullException.ThrowIfNull(certificate);

        options ??= new DeferredSigningOptions();
        ArgumentNullException.ThrowIfNull(sessionIntegrityKey);

        if (options.HashAlgorithmExplicitlySet)
        {
            SignerAcceptance.EnsureHashAllowed(options.HashAlgorithm, options.SigningPolicy);
        }

        var resolvedAlgorithm = SigningAlgorithmResolver.Resolve(
            certificate, options.HashAlgorithm, options.HashAlgorithmExplicitlySet,
            options.SignatureAlgorithmOid);
        HashAlgorithmName effectiveHash = resolvedAlgorithm.HashAlgorithm;
        var warnings = new List<SigningWarning>();
        SignerAcceptance.EnsureHashAllowed(effectiveHash, options.SigningPolicy, warnings, logger);

        (logger ?? NullLogger.Instance).DeferredPrepareStarted(certificate.Subject, effectiveHash.Name!);

        var fieldOptions = options.FieldOptions ?? new SignatureFieldOptions();

        var operationTime = DateTimeOffset.UtcNow;
        if (certificate.NotBefore > operationTime)
        {
            throw new SigningException(
                $"Certificate '{certificate.Subject}' is not valid until {certificate.NotBefore:yyyy-MM-dd} UTC.",
                SigningErrorReason.CertificateNotCurrentlyValid);
        }

        if (certificate.NotAfter < operationTime)
        {
            throw new SigningException(
                $"Certificate '{certificate.Subject}' expired on {certificate.NotAfter:yyyy-MM-dd} UTC.",
                SigningErrorReason.CertificateExpired);
        }

        await SignerAcceptance.EnsureSignerAcceptableAsync(
            certificate, options.ExtraCertificates ?? [], options.SigningPolicy, options.ChainRevocationChecker,
            options.HttpClientProvider ?? DefaultHttpClientProvider.Instance, logger ?? NullLogger.Instance, warnings, cancellationToken).ConfigureAwait(false);

        string sigAlgOid = resolvedAlgorithm.SignatureAlgorithmOid;
        string digestOid = CmsSignatureBuilder.GetDigestOid(effectiveHash);

        // Check DocMDP lock
        using var inputCheck = new MemoryStream(pdfBytes);
        if (await PdfStructureReader.IsDocMdpLockedAsync(inputCheck, logger: logger, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            throw new SigningException(
                "This PDF has a certification signature (DocMDP) that prohibits further changes.");
        }

        // 1. Prepare PDF with signature placeholder
        using var inputStream = new MemoryStream(pdfBytes);
        using var outputStream = new MemoryStream();
        var prepareResult = await PdfSignatureWriter.PrepareAsync(
            inputStream, outputStream, fieldOptions, logger, cancellationToken: cancellationToken).ConfigureAwait(false);

        (logger ?? NullLogger.Instance).DeferredPdfPrepared();

        // 2. Read the bytes to be signed (ByteRange content)
        byte[] signedBytes = await PdfStructureReader.ReadSignedBytesAsync(
            outputStream, prepareResult.ByteRange, logger: logger, cancellationToken: cancellationToken).ConfigureAwait(false);

        // 3. Compute document hash and build signed attributes
        var signingTime = DateTimeOffset.UtcNow;
        byte[] contentHash = CmsSignatureBuilder.ComputeHash(signedBytes, effectiveHash);
        byte[] signedAttrs = CmsSignatureBuilder.BuildSignedAttributes(
            contentHash, digestOid, signingTime, certificate);

        // 4. Build session (all state needed for Phase 2)
        var session = new DeferredSigningSession
        {
            SignedAttributes = signedAttrs,
            PreparedPdf = outputStream.ToArray(),
            ByteRangeOffset1 = prepareResult.ByteRange.Offset1,
            ByteRangeLength1 = prepareResult.ByteRange.Length1,
            ByteRangeOffset2 = prepareResult.ByteRange.Offset2,
            ByteRangeLength2 = prepareResult.ByteRange.Length2,
            ContentsHexOffset = prepareResult.ContentsHexOffset,
            ContentsReservedBytes = prepareResult.ContentsReservedBytes,
            CertificateDer = certificate.RawData,
            ExtraCertificatesDer = options.ExtraCertificates?.Select(c => c.RawData).ToArray(),
            DigestOid = digestOid,
            SignatureAlgorithmOid = sigAlgOid,
            SigningTime = signingTime,
            SigDictObjectNumber = prepareResult.SigDictObjectNumber,
            RequestedLevel = options.Profile?.Level ?? AdesBaselineLevel.Basic,
            LevelFailureBehavior = options.Profile?.FailureBehavior ?? SigningLevelFailureBehavior.Throw,
            TimestampEndpoint = options.Profile?.Timestamp?.Endpoint.ToString(),
            ArchiveTimestampEndpoint = options.Profile?.ArchiveTimestamp?.Endpoint?.ToString(),
            RevocationPreference = options.Profile?.LongTermValidation?.RevocationPreference ?? RevocationPreference.OcspFirst,
        };

        var result = new DeferredSigningPrepareResult
        {
            HashToSign = signedAttrs,
            SessionData = session.Serialize(sessionIntegrityKey),
            DigestAlgorithm = effectiveHash.Name!,
            SignatureAlgorithmOid = sigAlgOid,
            Warnings = warnings.AsReadOnly(),
        };

        (logger ?? NullLogger.Instance).DeferredPrepareCompleted(result.HashToSign.Length, result.SessionData.Length);

        return result;
    }

    /// <summary>
    /// Internal phase-two implementation shared by the immutable deferred builder.
    /// </summary>
    /// <param name="sessionData">Serialized session from <see cref="DeferredSigningPrepareResult.SessionData"/>.</param>
    /// <param name="rawSignature">
    /// Raw signature bytes from the external signer. The signature is verified against
    /// the certificate and the resolved session algorithm before a CMS is written.
    /// For RSA: PKCS#1 v1.5 or PSS signature. For ECDSA: DER SEQUENCE { r, s }.
    /// </param>
    /// <param name="options">Optional completion configuration (e.g., timestamp).</param>
    /// <param name="logger">Optional logger for debug diagnostics.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="tsaFactory">Optional TSA client factory for DI integration.</param>
    /// <param name="sessionIntegrityKey">Server-owned HMAC key used to verify the serialized session.</param>
    /// <returns>The fully signed PDF bytes.</returns>
    internal static async Task<byte[]> CompleteAsync(
        byte[] sessionData,
        byte[] rawSignature,
        byte[] sessionIntegrityKey,
        DeferredSigningCompleteOptions? options = null,
        ILogger? logger = null,
        ITimestampClientFactory? tsaFactory = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sessionData);
        ArgumentNullException.ThrowIfNull(rawSignature);
        if (rawSignature.Length == 0)
        {
            throw new ArgumentException("Signature bytes cannot be empty.", nameof(rawSignature));
        }

        (logger ?? NullLogger.Instance).DeferredCompleteStarted(sessionData.Length, rawSignature.Length);

        options ??= new DeferredSigningCompleteOptions();
        ArgumentNullException.ThrowIfNull(sessionIntegrityKey);

        var session = DeferredSigningSession.Deserialize(sessionData, sessionIntegrityKey);
        using var certificate = CertificateLoader.LoadCertificate(session.CertificateDer);

        var extraCerts = session.ExtraCertificatesDer?
            .Select(der => CertificateLoader.LoadCertificate(der))
            .ToList() ?? [];

        try
        {
            List<X509Certificate2> allCerts = [certificate, .. extraCerts];
            HashAlgorithmName hashAlgorithm = HashAlgorithmFromDigestOid(session.DigestOid);
            ResolvedSigningAlgorithm resolvedAlgorithm = SigningAlgorithmResolver.Resolve(
                certificate, hashAlgorithm, hashAlgorithmExplicitlySet: true, session.SignatureAlgorithmOid);

            if (!CmsSignatureBuilder.VerifyExternalSignature(
                session.SignedAttributes,
                rawSignature,
                certificate,
                resolvedAlgorithm.HashAlgorithm,
                resolvedAlgorithm.SignatureAlgorithmOid))
            {
                throw new SigningException(
                    "The external signature does not verify with the configured certificate.",
                    SigningErrorReason.ExternalSignerReturnedInvalidSignature);
            }

            // Build complete CMS/SignedData with the externally-produced signature
            byte[] cms = CmsSignatureBuilder.BuildSignedData(
                session.DigestOid,
                session.SignatureAlgorithmOid,
                resolvedAlgorithm.HashAlgorithm,
                session.SignedAttributes,
                rawSignature,
                certificate,
                allCerts);

            (logger ?? NullLogger.Instance).DeferredCmsAssembled(cms.Length);

            // Apply the signature timestamp from the complete baseline profile.
            AdesBaselineProfile? profile = options.Profile;
            TimestampOptions? timestampOptions = profile?.Timestamp;
            byte[]? timestampToken = null;
            if (timestampOptions is not null)
            {
                string endpoint = timestampOptions.Endpoint.ToString();
                var provider = timestampOptions.HttpClientProvider ?? options.HttpClientProvider;
                var httpClient = provider?.GetClient() ?? DefaultHttpClientProvider.Instance.GetClient();
                var hashAlg = resolvedAlgorithm.HashAlgorithm;
                ITimestampClient tsaClient = timestampOptions.NeedsDedicatedClient
                    ? TimestampClient.Create(timestampOptions, provider ?? DefaultHttpClientProvider.Instance, logger)
                    : tsaFactory is not null
                        ? tsaFactory.Create(endpoint)
                        : new TimestampClient(httpClient, endpoint, logger)
                        {
                            OutboundPolicy = (provider ?? DefaultHttpClientProvider.Instance).OutboundPolicy ?? OutboundHttpPolicy.Default,
                        };
                timestampToken = await tsaClient.GetTimestampAsync(
                    TimestampClient.ExtractSignatureValue(cms), hashAlg, cancellationToken).ConfigureAwait(false);
                cms = TimestampClient.EmbedTimestampInCms(cms, timestampToken);
            }

            // Reconstruct PDF prepare result
            var prepareResult = new PdfSignaturePrepareResult
            {
                ByteRange = new PdfByteRange
                {
                    Offset1 = session.ByteRangeOffset1,
                    Length1 = session.ByteRangeLength1,
                    Offset2 = session.ByteRangeOffset2,
                    Length2 = session.ByteRangeLength2
                },
                ContentsHexOffset = session.ContentsHexOffset,
                ContentsReservedBytes = session.ContentsReservedBytes,
                SigDictObjectNumber = session.SigDictObjectNumber
            };

            // Write CMS into the prepared PDF's /Contents placeholder
            using var outputStream = new MemoryStream();
            await outputStream.WriteAsync(session.PreparedPdf, cancellationToken).ConfigureAwait(false);
            await PdfSignatureWriter.FinalizeAsync(outputStream, prepareResult, cms, logger, cancellationToken).ConfigureAwait(false);

            var signedPdf = outputStream.ToArray();

            if (profile?.Level >= AdesBaselineLevel.LongTerm)
            {
                if (timestampToken is null)
                {
                    throw new SigningException(
                        "B-LT/B-LTA deferred signing requires a signature timestamp token.",
                        SigningErrorReason.LevelNotAchievable);
                }

                var ltvProvider = profile.LongTermValidation!.HttpClientProvider ??
                    options.HttpClientProvider ?? DefaultHttpClientProvider.Instance;
                var ltvEmbedder = new LtvEmbedder(ltvProvider, logger)
                {
                    RevocationPreference = profile.LongTermValidation.RevocationPreference,
                    ClockSkewTolerance = profile.LongTermValidation.ClockSkewTolerance,
                };
                signedPdf = await ltvEmbedder.EmbedLtvDataAsync(
                    signedPdf, allCerts, timestampToken, cancellationToken).ConfigureAwait(false);

                var requiredCertificates = new List<X509Certificate2>(allCerts);
                var tsaCertificates = TsaCertificateExtractor.ExtractCertificates(timestampToken);
                try
                {
                    requiredCertificates.AddRange(tsaCertificates.Where(tsa => requiredCertificates.All(
                        certificateInChain => !string.Equals(certificateInChain.Thumbprint, tsa.Thumbprint, StringComparison.OrdinalIgnoreCase))));
                    await using var dssStream = new MemoryStream(signedPdf, writable: false);
                    var dss = await DssExtractor.TryReadFullDssDataAsync(dssStream, cancellationToken, logger).ConfigureAwait(false);
                    if (!LtvEmbedder.HasCompleteEvidence(dss, requiredCertificates))
                    {
                        throw new SigningException(
                            "B-LT deferred signing could not embed complete validation evidence for every signer and TSA certificate path.",
                            SigningErrorReason.LevelNotAchievable);
                    }
                }
                finally
                {
                    foreach (var tsaCertificate in tsaCertificates)
                    {
                        tsaCertificate.Dispose();
                    }
                }
            }

            if (profile?.Level >= AdesBaselineLevel.Archive)
            {
                var effective = profile.ArchiveTimestamp?.Resolve(profile.Timestamp!) ?? profile.Timestamp!;
                var endpoint = effective.Endpoint;
                var provider = effective.HttpClientProvider ?? options.HttpClientProvider ?? DefaultHttpClientProvider.Instance;
                ITimestampClientFactory? archiveFactory = effective.NeedsDedicatedClient
                    ? new FixedTimestampClientFactory(TimestampClient.Create(effective, provider, logger))
                    : tsaFactory ?? new TimestampClientFactory(provider, logger);
                await using var pdfStream = new MemoryStream(signedPdf, writable: false);
                var pdfALevel = await PdfStructureReader.DetectPdfALevelAsync(pdfStream, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                signedPdf = await DocTimeStampWriter.AppendDocTimeStampAsync(
                    signedPdf,
                    endpoint.ToString(),
                    provider.GetClient(),
                    resolvedAlgorithm.HashAlgorithm,
                    pdfALevel,
                    archiveFactory,
                    cancellationToken).ConfigureAwait(false);
            }

            (logger ?? NullLogger.Instance).DeferredCompleteFinished(signedPdf.Length);

            return signedPdf;
        }
        finally
        {
            foreach (var cert in extraCerts)
            {
                cert.Dispose();
            }
        }
    }

    /// <summary>
    /// Maps a digest algorithm OID (as stored in the deferred signing session) back to a
    /// <see cref="HashAlgorithmName"/>. Used to thread the hash through to
    /// <see cref="CmsSignatureBuilder.BuildSignedData"/> so the RSASSA-PSS-params
    /// structure (RFC 4055 §3.1) can be emitted for PSS signatures.
    /// </summary>
    private static HashAlgorithmName HashAlgorithmFromDigestOid(string digestOid) => digestOid switch
    {
        Oids.Sha256 => HashAlgorithmName.SHA256,
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
        Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
        Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
        Oids.Sha1 => HashAlgorithmName.SHA1,
        _ => throw new NotSupportedException(
            $"Unsupported digest OID '{digestOid}' in deferred signing session.")
    };

    private static AdesBaselineProfile RestoreProfile(DeferredSigningSession session)
    {
        if (session.RequestedLevel == AdesBaselineLevel.Basic)
        {
            return AdesBaselineProfile.Basic();
        }

        if (string.IsNullOrWhiteSpace(session.TimestampEndpoint) ||
            !Uri.TryCreate(session.TimestampEndpoint, UriKind.Absolute, out Uri? timestampEndpoint))
        {
            throw new ArgumentException(
                "The deferred session requests a timestamped baseline level but has no valid TSA endpoint.",
                nameof(session));
        }

        var timestamp = new TimestampOptions(timestampEndpoint);
        return session.RequestedLevel switch
        {
            AdesBaselineLevel.Timestamped => AdesBaselineProfile.Timestamped(timestamp, session.LevelFailureBehavior),
            AdesBaselineLevel.LongTerm => AdesBaselineProfile.LongTerm(
                timestamp,
                new LongTermValidationOptions { RevocationPreference = session.RevocationPreference },
                session.LevelFailureBehavior),
            AdesBaselineLevel.Archive => AdesBaselineProfile.Archive(
                timestamp,
                new LongTermValidationOptions { RevocationPreference = session.RevocationPreference },
                string.IsNullOrWhiteSpace(session.ArchiveTimestampEndpoint)
                    ? null
                    : new ArchiveTimestampOptions(new Uri(session.ArchiveTimestampEndpoint, UriKind.Absolute)),
                session.LevelFailureBehavior),
            _ => throw new ArgumentOutOfRangeException(
                nameof(session), "The deferred session contains an unsupported requested baseline level.")
        };
    }
}

/// <summary>Result of the deferred signing preparation phase.</summary>
public sealed class DeferredSigningPrepareResult
{
    /// <summary>
    /// DER-encoded signed attributes to be signed by the external signer.
    /// The external signer should sign these bytes directly (e.g., RSA PKCS#1 v1.5, ECDSA).
    /// </summary>
    public required byte[] HashToSign { get; init; }

    /// <summary>
    /// Serialized session data. Store this on the server (Redis, DB, etc.) and
    /// resume it through <see cref="DeferredSigner.Resume(byte[], byte[])"/> when the signature arrives.
    /// </summary>
    public required byte[] SessionData { get; init; }

    /// <summary>Name of the digest algorithm used (e.g., "SHA256").</summary>
    public required string DigestAlgorithm { get; init; }

    /// <summary>OID of the expected signature algorithm (e.g., "1.2.840.113549.1.1.11" for RSA-SHA256).</summary>
    public required string SignatureAlgorithmOid { get; init; }

    /// <summary>The WARN constraints of the signing policy the certificate or the algorithms did not meet.</summary>
    public IReadOnlyList<SigningWarning> Warnings { get; init; } = [];
}

/// <summary>Internal configuration used while a deferred builder prepares a signature.</summary>
internal sealed class DeferredSigningOptions
{
    /// <summary>Hash algorithm for the signature. Default: SHA-256.</summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>
    /// Set to <see langword="true"/> when the caller has explicitly chosen
    /// <see cref="HashAlgorithm"/>. When <see langword="false"/> (default), the library
    /// uses SHA-256 unless a combined signature-algorithm OID is configured. PSS restrictions
    /// are read only from an <c>id-RSASSA-PSS</c> subject public-key identifier; a certificate
    /// merely issued with a PSS signature does not restrict its RSA signing key.
    /// </summary>
    public bool HashAlgorithmExplicitlySet { get; init; }

    /// <summary>Signature field options (appearance, position, name, etc.).</summary>
    public SignatureFieldOptions? FieldOptions { get; init; }

    /// <summary>
    /// Explicit signature algorithm OID. If null, auto-detected from the certificate's public key.
    /// Use <see cref="SimpleSign.Core.Constants.Oids"/> for common values.
    /// </summary>
    public string? SignatureAlgorithmOid { get; init; }

    /// <summary>Extra certificates (chain) to include in the CMS.</summary>
    public IReadOnlyList<X509Certificate2>? ExtraCertificates { get; init; }

    /// <summary>Baseline profile persisted into the session for phase-two resumption.</summary>
    public AdesBaselineProfile? Profile { get; init; }

    /// <summary>The checks run on the certificate, chain and algorithms before the hash is prepared.</summary>
    public SigningPolicy SigningPolicy { get; init; } = SigningPolicy.Default;

    /// <summary>The checker for the revocation check; null creates one from <see cref="HttpClientProvider"/>.</summary>
    public SimpleSign.Core.Revocation.IChainRevocationChecker? ChainRevocationChecker { get; init; }

    /// <summary>The HTTP provider for the revocation check; null uses the default provider.</summary>
    public IHttpClientProvider? HttpClientProvider { get; init; }
}

/// <summary>Internal configuration used while a deferred builder completes a signature.</summary>
internal sealed class DeferredSigningCompleteOptions
{
    /// <summary>
    /// Complete baseline-level request and its scoped HTTP providers.
    /// </summary>
    public AdesBaselineProfile? Profile { get; init; }

    /// <summary>Builder-wide fallback provider for timestamp and validation-data retrieval.</summary>
    public IHttpClientProvider? HttpClientProvider { get; init; }

}
