using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.PAdES;

/// <content>
/// Phase two of a deferred PAdES signature: the steps one-call signing runs after the signature exists,
/// applied to the PDF prepared in phase one.
/// </content>
public sealed partial class PadesSignerBuilder
{
    /// <summary>
    /// Takes the PDF prepared in phase one and the CMS assembled from the external signature to the level the
    /// session asks for, and reads the result back.
    /// </summary>
    /// <param name="session">The verified session.</param>
    /// <param name="cms">The CMS with the signer's signature, already verified against the certificate.</param>
    /// <param name="certificate">The signer certificate of the session.</param>
    /// <param name="chain">The certificates given with it.</param>
    /// <param name="hashAlgorithm">The resolved digest algorithm.</param>
    /// <param name="options">What the resumed builder supplies: the profile with its runtime settings, the policy, the anchors.</param>
    /// <param name="logger">The logger, or null.</param>
    /// <param name="tsaFactory">An injected TSA client factory, or null.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    internal static async Task<PadesSigningResult> CompleteDeferredAsync(
        DeferredSigningSession session,
        byte[] cms,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        HashAlgorithmName hashAlgorithm,
        DeferredSigningCompleteOptions options,
        ILogger? logger,
        ITimestampClientFactory? tsaFactory,
        CancellationToken cancellationToken)
    {
        using var prepared = new MemoryStream(session.PreparedPdf, writable: false);
        var pdfALevel = await PdfStructureReader.DetectPdfALevelAsync(prepared, cancellationToken: cancellationToken).ConfigureAwait(false);

        var builder = new PadesSignerBuilder(prepared, singleExecution: false, logger);
        string? operationId = options.OperationId ?? session.OperationId;
        builder = builder.With(builder._options with
        {
            Credential = new ExternalCredential(certificate, [.. chain], DeferredPlaceholderSigner.Instance),
            Profile = options.Profile ?? AdesBaselineProfile.Basic(),
            OperationId = operationId,
            SigningPolicy = options.SigningPolicy,
            TrustAnchors = options.TrustAnchors,
            DssArtifacts = session.DssArtifacts ?? [],
            Dependencies = builder._options.Dependencies with
            {
                TsaFactory = tsaFactory,
                HttpClientProvider = options.HttpClientProvider ?? DefaultHttpClientProvider.Instance,
                ChainRevocationChecker = options.ChainRevocationChecker,
            },
        });

        var prepareResult = new PdfSignaturePrepareResult
        {
            ByteRange = new PdfByteRange
            {
                Offset1 = session.ByteRangeOffset1,
                Length1 = session.ByteRangeLength1,
                Offset2 = session.ByteRangeOffset2,
                Length2 = session.ByteRangeLength2,
            },
            ContentsHexOffset = session.ContentsHexOffset,
            ContentsReservedBytes = session.ContentsReservedBytes,
            SigDictObjectNumber = session.SigDictObjectNumber,
        };

        using var output = new MemoryStream();
        await output.WriteAsync(session.PreparedPdf, cancellationToken).ConfigureAwait(false);
        PadesSigningResult result = await builder.FinishAsync(
            output, prepareResult, cms, hashAlgorithm, pdfALevel, [],
            operationId ?? System.Diagnostics.Activity.Current?.Id ?? Guid.NewGuid().ToString("N")[..8],
            System.Diagnostics.Stopwatch.StartNew(), cancellationToken).ConfigureAwait(false);
        return result with { SignedArtifact = output.ToArray() };
    }
}
