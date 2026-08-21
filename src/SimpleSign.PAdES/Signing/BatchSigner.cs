using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// High-performance batch signer that reuses certificate, HTTP connections, and TSA sessions
/// to sign multiple PDFs efficiently.
/// </summary>
public sealed class BatchSigner : IAsyncDisposable
{
    private readonly X509Certificate2 _certificate;
    private readonly IReadOnlyList<X509Certificate2>? _chain;
    private readonly Func<byte[], Task<byte[]>>? _externalSigner;
    private readonly string? _externalSignerOid;
    private readonly string? _tsaUrl;
    private readonly IHttpClientProvider _httpClientProvider;
    private readonly ILogger _logger;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly string? _signerName;
    private readonly string? _reason;
    private readonly string? _location;
    private readonly SignatureAppearance? _appearance;
    private readonly bool _enableLtv;
    private readonly string? _archivalTsaUrl;
    private readonly int _maxConcurrency;

    private int _successCount;
    private int _failureCount;
    private long _totalElapsedMs;

    private BatchSigner(BatchSignerBuilder builder)
    {
        _certificate = builder.Certificate ?? throw new InvalidOperationException("Certificate is required.");
        _chain = builder.Chain;
        _externalSigner = builder.ExternalSigner;
        _externalSignerOid = builder.ExternalSignerOid;
        _tsaUrl = builder.TsaUrl;
        _hashAlgorithm = builder.HashAlgorithm;
        _signerName = builder.SignerName;
        _reason = builder.Reason;
        _location = builder.Location;
        _appearance = builder.Appearance;
        _enableLtv = builder.EnableLtv;
        _archivalTsaUrl = builder.ArchivalTsaUrl;
        _maxConcurrency = builder.MaxConcurrency;
        _logger = builder.Logger ?? NullLogger.Instance;
        _httpClientProvider = builder.HttpClientProvider ?? DefaultHttpClientProvider.Instance;
    }

    /// <summary>Creates a new <see cref="BatchSignerBuilder"/> for configuring the batch signer.</summary>
    public static BatchSignerBuilder Create(X509Certificate2 certificate) => new(certificate);

    /// <summary>Number of PDFs successfully signed.</summary>
    public int SuccessCount => _successCount;

    /// <summary>Number of PDFs that failed to sign.</summary>
    public int FailureCount => _failureCount;

    /// <summary>Average signing time per document in milliseconds.</summary>
    public double AverageElapsedMs
    {
        get
        {
            var total = _successCount + _failureCount;
            return total > 0 ? (double)_totalElapsedMs / total : 0;
        }
    }

    /// <summary>
    /// Signs a single PDF using the pre-configured certificate and options.
    /// </summary>
    /// <param name="pdfStream">Seekable input PDF stream.</param>
    /// <param name="outputStream">Output stream for the signed PDF.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task SignAsync(Stream pdfStream, Stream outputStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        ArgumentNullException.ThrowIfNull(outputStream);

        var sw = Stopwatch.StartNew();
        try
        {
            var builder = ConfigureBuilder(PadesSigner.Document(pdfStream));
            await builder.SignAsync(outputStream, cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _successCount);
        }
        catch
        {
            Interlocked.Increment(ref _failureCount);
            throw;
        }
        finally
        {
            sw.Stop();
            Interlocked.Add(ref _totalElapsedMs, sw.ElapsedMilliseconds);
        }
    }

    /// <summary>
    /// Signs a single PDF and returns the signed bytes.
    /// </summary>
    /// <param name="pdfBytes">Input PDF bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Signed PDF bytes.</returns>
    public async Task<byte[]> SignAsync(byte[] pdfBytes, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var builder = ConfigureBuilder(PadesSigner.Document(pdfBytes));
            var result = await builder.SignAsync(cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _successCount);
            return result;
        }
        catch
        {
            Interlocked.Increment(ref _failureCount);
            throw;
        }
        finally
        {
            sw.Stop();
            Interlocked.Add(ref _totalElapsedMs, sw.ElapsedMilliseconds);
        }
    }

    /// <summary>
    /// Signs all PDFs from an async enumerable, yielding results as they complete.
    /// Respects <see cref="BatchSignerBuilder.MaxConcurrency"/> for parallel execution.
    /// </summary>
    /// <param name="inputs">Async enumerable of (identifier, PDF bytes) pairs.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Async enumerable of batch results.</returns>
    public async IAsyncEnumerable<BatchSignResult> SignAllAsync(
        IAsyncEnumerable<(string Id, byte[] PdfBytes)> inputs,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var semaphore = new SemaphoreSlim(_maxConcurrency, _maxConcurrency);
        var tasks = new List<Task<BatchSignResult>>();

        await foreach (var (id, pdfBytes) in inputs.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var signed = await SignAsync(pdfBytes, cancellationToken).ConfigureAwait(false);
                    return new BatchSignResult(id, signed, null);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Batch sign failed for {Id}", id);
                    return new BatchSignResult(id, null, ex);
                }
                finally
                {
                    semaphore.Release();
                }
            }, cancellationToken));

            // Yield completed tasks as they finish
            for (var i = tasks.Count - 1; i >= 0; i--)
            {
                if (tasks[i].IsCompleted)
                {
                    yield return await tasks[i].ConfigureAwait(false);
                    tasks.RemoveAt(i);
                }
            }
        }

        // Drain remaining
        foreach (var task in tasks)
        {
            yield return await task.ConfigureAwait(false);
        }
    }

    private PadesSignerBuilder ConfigureBuilder(PadesSignerBuilder builder)
    {
        if (_externalSigner is not null)
        {
            builder = builder.WithExternalSigner(_certificate, new FuncExternalSigner(_externalSigner), _chain ?? []);
            if (_externalSignerOid is not null)
            {
                builder = builder.WithSignatureAlgorithm(_externalSignerOid);
            }
        }
        else if (_chain is not null)
        {
            builder = builder.WithCertificate(_certificate, _chain);
        }
        else
        {
            builder = builder.WithCertificate(_certificate);
        }

        builder = builder.WithHashAlgorithm(_hashAlgorithm);

        if (_tsaUrl is not null)
        {
            var timestampOptions = new TimestampOptions(new Uri(_tsaUrl));
            var profile = _enableLtv
                ? _archivalTsaUrl is not null
                    ? AdesBaselineProfile.Archive(
                        timestampOptions,
                        new LongTermValidationOptions(),
                        new ArchiveTimestampOptions(new Uri(_archivalTsaUrl)))
                    : AdesBaselineProfile.LongTerm(timestampOptions, new LongTermValidationOptions())
                : AdesBaselineProfile.Timestamped(timestampOptions);
            builder = builder.WithLevel(profile);
        }

        builder = builder.WithHttpClientProvider(_httpClientProvider);

        if (_signerName is not null || _reason is not null || _location is not null)
        {
            builder = builder.WithMetadata(_signerName, _reason, _location);
        }

        if (_appearance is not null)
        {
            builder = builder.WithAppearance(_appearance);
        }

        return builder;
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    /// <summary>
    /// Resets the success/failure counters and average elapsed time.
    /// </summary>
    public void ResetMetrics()
    {
        Interlocked.Exchange(ref _successCount, 0);
        Interlocked.Exchange(ref _failureCount, 0);
        Interlocked.Exchange(ref _totalElapsedMs, 0);
    }

    /// <summary>Builder for configuring a <see cref="BatchSigner"/>.</summary>
    public sealed class BatchSignerBuilder
    {
        internal X509Certificate2? Certificate { get; }
        internal IReadOnlyList<X509Certificate2>? Chain { get; }
        internal Func<byte[], Task<byte[]>>? ExternalSigner { get; }
        internal string? ExternalSignerOid { get; }
        internal string? TsaUrl { get; }
        internal IHttpClientProvider? HttpClientProvider { get; }
        internal ILogger? Logger { get; }
        internal HashAlgorithmName HashAlgorithm { get; }
        internal string? SignerName { get; }
        internal string? Reason { get; }
        internal string? Location { get; }
        internal SignatureAppearance? Appearance { get; }
        internal bool EnableLtv { get; }
        internal string? ArchivalTsaUrl { get; }
        internal int MaxConcurrency { get; }

        internal BatchSignerBuilder(X509Certificate2 certificate)
        {
            Certificate = certificate;
            HashAlgorithm = HashAlgorithmName.SHA256;
            MaxConcurrency = 4;
        }

        private BatchSignerBuilder(
            X509Certificate2? certificate,
            IReadOnlyList<X509Certificate2>? chain,
            Func<byte[], Task<byte[]>>? externalSigner,
            string? externalSignerOid,
            string? tsaUrl,
            IHttpClientProvider? httpClientProvider,
            ILogger? logger,
            HashAlgorithmName hashAlgorithm,
            string? signerName,
            string? reason,
            string? location,
            SignatureAppearance? appearance,
            bool enableLtv,
            string? archivalTsaUrl,
            int maxConcurrency)
        {
            Certificate = certificate;
            Chain = chain;
            ExternalSigner = externalSigner;
            ExternalSignerOid = externalSignerOid;
            TsaUrl = tsaUrl;
            HttpClientProvider = httpClientProvider;
            Logger = logger;
            HashAlgorithm = hashAlgorithm;
            SignerName = signerName;
            Reason = reason;
            Location = location;
            Appearance = appearance;
            EnableLtv = enableLtv;
            ArchivalTsaUrl = archivalTsaUrl;
            MaxConcurrency = maxConcurrency;
        }

        private BatchSignerBuilder With(
            X509Certificate2? certificate = null,
            IReadOnlyList<X509Certificate2>? chain = null,
            Func<byte[], Task<byte[]>>? externalSigner = null,
            string? externalSignerOid = null,
            string? tsaUrl = null,
            IHttpClientProvider? httpClientProvider = null,
            ILogger? logger = null,
            HashAlgorithmName? hashAlgorithm = null,
            string? signerName = null,
            string? reason = null,
            string? location = null,
            SignatureAppearance? appearance = null,
            bool? enableLtv = null,
            string? archivalTsaUrl = null,
            int? maxConcurrency = null) =>
            new(
                certificate ?? Certificate,
                chain ?? Chain,
                externalSigner ?? ExternalSigner,
                externalSignerOid ?? ExternalSignerOid,
                tsaUrl ?? TsaUrl,
                httpClientProvider ?? HttpClientProvider,
                logger ?? Logger,
                hashAlgorithm ?? HashAlgorithm,
                signerName ?? SignerName,
                reason ?? Reason,
                location ?? Location,
                appearance ?? Appearance,
                enableLtv ?? EnableLtv,
                archivalTsaUrl ?? ArchivalTsaUrl,
                maxConcurrency ?? MaxConcurrency);

        /// <summary>Sets the certificate chain for LTV embedding.</summary>
        public BatchSignerBuilder WithChain(IReadOnlyList<X509Certificate2> chain) =>
            With(chain: chain);

        /// <summary>Uses an external signer (A3 token, HSM, cloud KMS).</summary>
        public BatchSignerBuilder WithExternalSigner(Func<byte[], Task<byte[]>> signer, string? signatureAlgorithmOid = null) =>
            With(externalSigner: signer, externalSignerOid: signatureAlgorithmOid);

        /// <summary>Configures TSA URL for timestamping.</summary>
        public BatchSignerBuilder WithTimestamp(string tsaUrl) =>
            With(tsaUrl: tsaUrl);

        /// <summary>Configures the HTTP client provider.</summary>
        public BatchSignerBuilder WithHttpClientProvider(IHttpClientProvider provider) =>
            With(httpClientProvider: provider);

        /// <summary>Configures the hash algorithm. Default: SHA-256.</summary>
        public BatchSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
            With(hashAlgorithm: algorithm);

        /// <summary>Configures signer metadata.</summary>
        public BatchSignerBuilder WithMetadata(string? signerName = null, string? reason = null, string? location = null) =>
            With(signerName: signerName, reason: reason, location: location);

        /// <summary>Configures visual signature appearance.</summary>
        public BatchSignerBuilder WithAppearance(SignatureAppearance appearance) =>
            With(appearance: appearance);

        /// <summary>Enables LTV (Long-Term Validation) with DSS embedding.</summary>
        public BatchSignerBuilder WithLtv() =>
            With(enableLtv: true);

        /// <summary>
        /// Enables archival timestamp (PAdES-B-LTA).
        /// Requires <see cref="WithLtv"/> to be called first.
        /// </summary>
        public BatchSignerBuilder WithArchivalTimestamp(string tsaUrl) =>
            With(archivalTsaUrl: tsaUrl);

        /// <summary>Sets maximum concurrent signing operations. Default: 4.</summary>
        public BatchSignerBuilder WithMaxConcurrency(int maxConcurrency)
        {
            if (maxConcurrency < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(maxConcurrency), "Must be at least 1.");
            }

            return With(maxConcurrency: maxConcurrency);
        }

        /// <summary>Sets the logger for diagnostic output.</summary>
        public BatchSignerBuilder WithLogger(ILogger logger) =>
            With(logger: logger);

        /// <summary>Builds the <see cref="BatchSigner"/> instance.</summary>
        public BatchSigner Build()
        {
            if (EnableLtv && TsaUrl is null && ArchivalTsaUrl is null)
            {
                throw new SigningException("LTV requires a timestamp. Call WithTimestamp() before enabling LTV, or use WithArchivalTimestamp().");
            }

            if (ArchivalTsaUrl is not null && !EnableLtv)
            {
                throw new SigningException("Archival timestamp (B-LTA) requires LTV. Call .WithLtv() before .WithArchivalTimestamp() to produce PAdES B-LTA.");
            }

            return new(this);
        }
    }
}

/// <summary>Result of a single batch signing operation.</summary>
/// <param name="Id">Identifier of the input PDF.</param>
/// <param name="SignedPdf">Signed PDF bytes, or null if signing failed.</param>
/// <param name="Error">Exception if signing failed, or null on success.</param>
public sealed record BatchSignResult(string Id, byte[]? SignedPdf, Exception? Error)
{
    /// <summary>Whether the signing operation succeeded.</summary>
    public bool IsSuccess => Error is null;
}
