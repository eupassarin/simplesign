using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES;

/// <summary>
/// Two-phase (deferred) signing API for web applications where the private key
/// resides on a different machine (e.g., A3 hardware token in user's browser).
/// </summary>
/// <example>
/// <code>
/// // Phase 1 — Server: prepare PDF and get hash for external signing
/// var result = await DeferredSigner.PrepareAsync(pdfBytes, publicCert);
/// // Send result.HashToSign to the client; store result.SessionData on server
///
/// // Phase 2 — Server: complete signing with the raw signature from client
/// byte[] signedPdf = await DeferredSigner.CompleteAsync(sessionData, rawSignature);
/// </code>
/// </example>
public static class DeferredSigner
{
    /// <summary>
    /// Phase 1: Prepares a PDF for signing and returns the signed attributes to be signed externally.
    /// The <see cref="DeferredSigningPrepareResult.HashToSign"/> is the DER-encoded signed attributes
    /// that the external signer must sign (RSA PKCS#1 v1.5, ECDSA DER, or EdDSA raw).
    /// </summary>
    /// <param name="pdfBytes">The original PDF document bytes.</param>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="options">Optional signing configuration.</param>
    /// <param name="logger">Optional logger for debug diagnostics.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Prepare result containing the hash to sign and serialized session data.</returns>
    /// <exception cref="SigningException">Certificate is expired or document is DocMDP-locked.</exception>
    public static async Task<DeferredSigningPrepareResult> PrepareAsync(
        byte[] pdfBytes,
        X509Certificate2 certificate,
        DeferredSigningOptions? options = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        ArgumentNullException.ThrowIfNull(certificate);

        options ??= new DeferredSigningOptions();

        (logger ?? NullLogger.Instance).DeferredPrepareStarted(certificate.Subject, options.HashAlgorithm.Name!);

        var fieldOptions = options.FieldOptions ?? new SignatureFieldOptions();

        if (certificate.NotAfter < DateTime.UtcNow)
        {
            throw new CertificateValidationException(
                $"Certificate '{certificate.Subject}' expired on {certificate.NotAfter:yyyy-MM-dd} UTC. Cannot prepare deferred signing.",
                certificate.Thumbprint,
                certificate.Subject);
        }

        string sigAlgOid = options.SignatureAlgorithmOid
                           ?? DetectSignatureAlgorithmOid(certificate, options.HashAlgorithm);
        string digestOid = CmsSignatureBuilder.GetDigestOid(options.HashAlgorithm);

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
            inputStream, outputStream, fieldOptions, logger, cancellationToken).ConfigureAwait(false);

        (logger ?? NullLogger.Instance).DeferredPdfPrepared();

        // 2. Read the bytes to be signed (ByteRange content)
        byte[] signedBytes = await PdfStructureReader.ReadSignedBytesAsync(
            outputStream, prepareResult.ByteRange, logger: logger, cancellationToken: cancellationToken).ConfigureAwait(false);

        // 3. Compute document hash and build signed attributes
        var signingTime = DateTimeOffset.UtcNow;
        byte[] contentHash = CmsSignatureBuilder.ComputeHash(signedBytes, options.HashAlgorithm);
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
            SigDictObjectNumber = prepareResult.SigDictObjectNumber
        };

        var result = new DeferredSigningPrepareResult
        {
            HashToSign = signedAttrs,
            SessionData = session.Serialize(),
            DigestAlgorithm = options.HashAlgorithm.Name!,
            SignatureAlgorithmOid = sigAlgOid
        };

        (logger ?? NullLogger.Instance).DeferredPrepareCompleted(result.HashToSign.Length, result.SessionData.Length);

        return result;
    }

    /// <summary>
    /// Phase 2: Completes the signing using the raw signature bytes produced by the external signer.
    /// </summary>
    /// <param name="sessionData">Serialized session from <see cref="DeferredSigningPrepareResult.SessionData"/>.</param>
    /// <param name="rawSignature">
    /// Raw signature bytes from the external signer.
    /// For RSA: PKCS#1 v1.5 signature. For ECDSA: DER SEQUENCE { r, s }. For EdDSA: raw signature.
    /// </param>
    /// <param name="options">Optional completion configuration (e.g., timestamp).</param>
    /// <param name="logger">Optional logger for debug diagnostics.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The fully signed PDF bytes.</returns>
    public static async Task<byte[]> CompleteAsync(
        byte[] sessionData,
        byte[] rawSignature,
        DeferredSigningCompleteOptions? options = null,
        ILogger? logger = null,
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

        var session = DeferredSigningSession.Deserialize(sessionData);
        using var certificate = CertificateLoader.LoadCertificate(session.CertificateDer);

        var extraCerts = session.ExtraCertificatesDer?
            .Select(der => CertificateLoader.LoadCertificate(der))
            .ToList() ?? [];

        try
        {
            List<X509Certificate2> allCerts = [certificate, .. extraCerts];

            // Build complete CMS/SignedData with the externally-produced signature
            byte[] cms = CmsSignatureBuilder.BuildSignedData(
                session.DigestOid,
                session.SignatureAlgorithmOid,
                session.SignedAttributes,
                rawSignature,
                certificate,
                allCerts);

            (logger ?? NullLogger.Instance).DeferredCmsAssembled(cms.Length);

            // Apply timestamp if configured
            if (options.TsaUrl is not null)
            {
                var httpClient = options.HttpClient ?? DefaultHttpClientProvider.Instance.GetClient();
                var hashAlg = session.DigestOid == Oids.Sha512
                    ? HashAlgorithmName.SHA512
                    : HashAlgorithmName.SHA256;
                var tsaClient = new TimestampClient(httpClient, options.TsaUrl);
                byte[] tsToken = await tsaClient.GetTimestampAsync(
                    TimestampClient.ExtractSignatureValue(cms), hashAlg, cancellationToken).ConfigureAwait(false);
                cms = TimestampClient.EmbedTimestampInCms(cms, tsToken);
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

    private static string DetectSignatureAlgorithmOid(X509Certificate2 cert, HashAlgorithmName hashAlg)
    {
        string keyAlg = cert.PublicKey.Oid.Value ?? string.Empty;

        if (cert.SignatureAlgorithm.Value == Oids.RsaPss)
        {
            return Oids.RsaPss;
        }

        return (keyAlg, hashAlg) switch
        {
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.RsaSha256,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.RsaSha384,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.RsaSha512,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.EcdsaSha256,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.EcdsaSha384,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.EcdsaSha512,
            (Oids.Ed25519, _) => Oids.Ed25519,
            (Oids.Ed448, _) => Oids.Ed448,
            _ => throw new NotSupportedException(
                $"Cannot detect signature OID for key '{cert.PublicKey.Oid.FriendlyName}' + hash '{hashAlg.Name}'. " +
                "Provide SignatureAlgorithmOid explicitly in DeferredSigningOptions.")
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
    /// Serialized session data. Store this on the server (Redis, DB, etc.)
    /// and pass it to <see cref="DeferredSigner.CompleteAsync"/> when the signature arrives.
    /// </summary>
    public required byte[] SessionData { get; init; }

    /// <summary>Name of the digest algorithm used (e.g., "SHA256").</summary>
    public required string DigestAlgorithm { get; init; }

    /// <summary>OID of the expected signature algorithm (e.g., "1.2.840.113549.1.1.11" for RSA-SHA256).</summary>
    public required string SignatureAlgorithmOid { get; init; }
}

/// <summary>Options for <see cref="DeferredSigner.PrepareAsync"/>.</summary>
public sealed class DeferredSigningOptions
{
    /// <summary>Hash algorithm for the signature. Default: SHA-256.</summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>Signature field options (appearance, position, name, etc.).</summary>
    public SignatureFieldOptions? FieldOptions { get; init; }

    /// <summary>
    /// Explicit signature algorithm OID. If null, auto-detected from the certificate's public key.
    /// Use <see cref="SimpleSign.Core.Constants.Oids"/> for common values.
    /// </summary>
    public string? SignatureAlgorithmOid { get; init; }

    /// <summary>Extra certificates (chain) to include in the CMS.</summary>
    public IReadOnlyList<X509Certificate2>? ExtraCertificates { get; init; }
}

/// <summary>Options for <see cref="DeferredSigner.CompleteAsync"/>.</summary>
public sealed class DeferredSigningCompleteOptions
{
    /// <summary>TSA URL to add a timestamp to the signature. Null to skip timestamping.</summary>
    public string? TsaUrl { get; init; }

    /// <summary>HttpClient to use for TSA requests. If null, a default instance is created.</summary>
    public HttpClient? HttpClient { get; init; }
}
