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
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
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

        if (builder.HttpClientProvider is not null)
        {
            _httpClient = builder.HttpClientProvider.GetClient();
            _ownsHttpClient = false;
        }
        else
        {
            _httpClient = DefaultHttpClientProvider.Instance.GetClient();
            _ownsHttpClient = false;
        }
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
        var sw = Stopwatch.StartNew();
        try
        {
            var builder = ConfigureBuilder(SimpleSigner.Document(pdfStream, _logger));
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
            var builder = ConfigureBuilder(SimpleSigner.Document(pdfBytes, _logger));
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

    private SignerBuilder ConfigureBuilder(SignerBuilder builder)
    {
        if (_externalSigner is not null)
        {
            builder = _externalSignerOid is not null
                ? builder.WithExternalSigner(_certificate, _externalSigner, _externalSignerOid)
                : builder.WithExternalSigner(_certificate, _externalSigner);
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
            builder = builder.WithTimestamp(_tsaUrl, _httpClient);
        }

        if (_signerName is not null || _reason is not null || _location is not null)
        {
            builder = builder.WithMetadata(_signerName, _reason, _location);
        }

        if (_appearance is not null)
        {
            builder = builder.WithAppearance(_appearance);
        }

        if (_enableLtv)
        {
            builder = builder.WithLtv();
        }

        if (_archivalTsaUrl is not null)
        {
            builder = builder.WithArchivalTimestamp(_archivalTsaUrl);
        }

        return builder;
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }

        return ValueTask.CompletedTask;
    }

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
        internal X509Certificate2? Certificate { get; private set; }
        internal IReadOnlyList<X509Certificate2>? Chain { get; private set; }
        internal Func<byte[], Task<byte[]>>? ExternalSigner { get; private set; }
        internal string? ExternalSignerOid { get; private set; }
        internal string? TsaUrl { get; private set; }
        internal IHttpClientProvider? HttpClientProvider { get; private set; }
        internal ILogger? Logger { get; private set; }
        internal HashAlgorithmName HashAlgorithm { get; private set; } = HashAlgorithmName.SHA256;
        internal string? SignerName { get; private set; }
        internal string? Reason { get; private set; }
        internal string? Location { get; private set; }
        internal SignatureAppearance? Appearance { get; private set; }
        internal bool EnableLtv { get; private set; }
        internal string? ArchivalTsaUrl { get; private set; }
        internal int MaxConcurrency { get; private set; } = 4;

        internal BatchSignerBuilder(X509Certificate2 certificate)
        {
            Certificate = certificate;
        }

        /// <summary>Sets the certificate chain for LTV embedding.</summary>
        public BatchSignerBuilder WithChain(IReadOnlyList<X509Certificate2> chain)
        {
            Chain = chain;
            return this;
        }

        /// <summary>Uses an external signer (A3 token, HSM, cloud KMS).</summary>
        public BatchSignerBuilder WithExternalSigner(Func<byte[], Task<byte[]>> signer, string? signatureAlgorithmOid = null)
        {
            ExternalSigner = signer;
            ExternalSignerOid = signatureAlgorithmOid;
            return this;
        }

        /// <summary>Configures TSA URL for timestamping.</summary>
        public BatchSignerBuilder WithTimestamp(string tsaUrl)
        {
            TsaUrl = tsaUrl;
            return this;
        }

        /// <summary>Configures the HTTP client provider.</summary>
        public BatchSignerBuilder WithHttpClientProvider(IHttpClientProvider provider)
        {
            HttpClientProvider = provider;
            return this;
        }

        /// <summary>Configures the hash algorithm. Default: SHA-256.</summary>
        public BatchSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm)
        {
            HashAlgorithm = algorithm;
            return this;
        }

        /// <summary>Configures signer metadata.</summary>
        public BatchSignerBuilder WithMetadata(string? signerName = null, string? reason = null, string? location = null)
        {
            SignerName = signerName;
            Reason = reason;
            Location = location;
            return this;
        }

        /// <summary>Configures visual signature appearance.</summary>
        public BatchSignerBuilder WithAppearance(SignatureAppearance appearance)
        {
            Appearance = appearance;
            return this;
        }

        /// <summary>Enables LTV (Long-Term Validation) with DSS embedding.</summary>
        public BatchSignerBuilder WithLtv()
        {
            EnableLtv = true;
            return this;
        }

        /// <summary>Enables archival timestamp (PAdES-B-LTA). Implies LTV.</summary>
        public BatchSignerBuilder WithArchivalTimestamp(string tsaUrl)
        {
            ArchivalTsaUrl = tsaUrl;
            EnableLtv = true;
            return this;
        }

        /// <summary>Sets maximum concurrent signing operations. Default: 4.</summary>
        public BatchSignerBuilder WithMaxConcurrency(int maxConcurrency)
        {
            if (maxConcurrency < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(maxConcurrency), "Must be at least 1.");
            }

            MaxConcurrency = maxConcurrency;
            return this;
        }

        /// <summary>Sets the logger for diagnostic output.</summary>
        public BatchSignerBuilder WithLogger(ILogger logger)
        {
            Logger = logger;
            return this;
        }

        /// <summary>Builds the <see cref="BatchSigner"/> instance.</summary>
        public BatchSigner Build()
        {
            if (EnableLtv && TsaUrl is null && ArchivalTsaUrl is null)
            {
                throw new SigningException("LTV requires a timestamp. Call WithTimestamp() before enabling LTV, or use WithArchivalTimestamp().");
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
