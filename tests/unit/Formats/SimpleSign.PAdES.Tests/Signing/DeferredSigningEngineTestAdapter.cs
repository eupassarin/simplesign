using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Test-only bridge to the deferred engine. Public workflow tests use
/// <see cref="global::SimpleSign.PAdES.DeferredSigner.Document(byte[])"/> and
/// <see cref="global::SimpleSign.PAdES.DeferredSigner.Resume(byte[], byte[])"/>; this bridge isolates
/// narrowly scoped engine tests while always supplying an authenticated session key.
/// </summary>
internal static class DeferredSigningEngineTestAdapter
{
    internal static readonly byte[] SessionIntegrityKey =
        [0x9C, 0x7D, 0x45, 0xBE, 0x6E, 0xA8, 0x61, 0x4D,
         0xD3, 0x1F, 0x2E, 0x80, 0x53, 0xC9, 0x24, 0xAA,
         0x42, 0x8E, 0x0B, 0xF5, 0x8C, 0x63, 0xDE, 0x90,
         0x14, 0x77, 0xB2, 0x39, 0x5F, 0xEA, 0xC4, 0x08];

    internal static Task<DeferredSigningPrepareResult> PrepareAsync(
        byte[] pdfBytes,
        X509Certificate2 certificate,
        DeferredSigningOptions? options = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        return global::SimpleSign.PAdES.DeferredSigner.PrepareAsync(
            pdfBytes,
            certificate,
            SessionIntegrityKey,
            options,
            logger,
            cancellationToken);
    }

    internal static Task<byte[]> CompleteAsync(
        byte[] sessionData,
        byte[] rawSignature,
        DeferredSigningCompleteOptions? options = null,
        ILogger? logger = null,
        ITimestampClientFactory? tsaFactory = null,
        CancellationToken cancellationToken = default)
    {
        return global::SimpleSign.PAdES.DeferredSigner.CompleteAsync(
            sessionData,
            rawSignature,
            SessionIntegrityKey,
            options,
            logger,
            tsaFactory,
            cancellationToken);
    }
}
