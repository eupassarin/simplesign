using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;

namespace SimpleSign.PAdES.Signing;

/// <summary>Signs multiple PDFs with one immutable PAdES configuration.</summary>
public sealed class BatchSigner : IAsyncDisposable
{
    private readonly X509Certificate2 _certificate;
    private readonly IReadOnlyList<X509Certificate2> _chain;
    private readonly IExternalSigner? _externalSigner;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly bool _hashAlgorithmExplicitlySet;
    private readonly string? _signatureAlgorithmOid;
    private readonly AdesBaselineProfile _profile;
    private readonly IHttpClientProvider _httpClientProvider;
    private readonly ILogger _logger;
    private readonly SignatureFieldOptions? _fieldOptions;
    private readonly string? _operationId;
    private readonly int _maxConcurrency;
    private int _successCount;
    private int _failureCount;
    private long _totalElapsedMs;

    private BatchSigner(BatchSignerBuilder builder)
    {
        _certificate = builder.Certificate;
        _chain = builder.Chain;
        _externalSigner = builder.ExternalSigner;
        _hashAlgorithm = builder.HashAlgorithm;
        _hashAlgorithmExplicitlySet = builder.HashAlgorithmExplicitlySet;
        _signatureAlgorithmOid = builder.SignatureAlgorithmOid;
        _profile = builder.Profile;
        _httpClientProvider = builder.HttpClientProvider;
        _logger = builder.Logger;
        _fieldOptions = builder.FieldOptions?.Snapshot();
        _operationId = builder.OperationId;
        _maxConcurrency = builder.MaxConcurrency;
    }

    /// <summary>Creates a batch configuration for <paramref name="certificate"/>.</summary>
    public static BatchSignerBuilder Create(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new BatchSignerBuilder(certificate);
    }

    /// <summary>Number of successfully signed documents.</summary>
    public int SuccessCount => _successCount;

    /// <summary>Number of signing failures.</summary>
    public int FailureCount => _failureCount;

    /// <summary>Average terminal-operation time in milliseconds.</summary>
    public double AverageElapsedMs
    {
        get
        {
            int total = Volatile.Read(ref _successCount) + Volatile.Read(ref _failureCount);
            long elapsed = Interlocked.Read(ref _totalElapsedMs);
            return total == 0 ? 0 : (double)elapsed / total;
        }
    }

    /// <summary>Signs one PDF into a caller-owned destination stream.</summary>
    public async Task SignAsync(Stream pdfStream, Stream outputStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        ArgumentNullException.ThrowIfNull(outputStream);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await Configure(PadesSigner.Document(pdfStream)).SignAsync(outputStream, cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _successCount);
        }
        catch
        {
            Interlocked.Increment(ref _failureCount);
            throw;
        }
        finally
        {
            stopwatch.Stop();
            Interlocked.Add(ref _totalElapsedMs, stopwatch.ElapsedMilliseconds);
        }
    }

    /// <summary>Signs one PDF and returns the result.</summary>
    public async Task<byte[]> SignAsync(byte[] pdfBytes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            byte[] signed = await Configure(PadesSigner.Document(pdfBytes)).SignAsync(cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _successCount);
            return signed;
        }
        catch
        {
            Interlocked.Increment(ref _failureCount);
            throw;
        }
        finally
        {
            stopwatch.Stop();
            Interlocked.Add(ref _totalElapsedMs, stopwatch.ElapsedMilliseconds);
        }
    }

    /// <summary>Signs inputs with bounded concurrency and yields results as operations complete.</summary>
    /// <remarks>
    /// Results are completion-ordered rather than input-ordered. Disposing the asynchronous
    /// enumeration cancels pending work and the source enumeration through its cancellation token.
    /// </remarks>
    public async IAsyncEnumerable<BatchSignResult> SignAllAsync(
        IAsyncEnumerable<(string Id, byte[] PdfBytes)> inputs,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var channel = Channel.CreateBounded<BatchSignResult>(new BoundedChannelOptions(_maxConcurrency)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
        Task producer = ProduceResultsAsync(inputs, channel.Writer, linkedCancellation.Token);

        try
        {
            await foreach (BatchSignResult result in channel.Reader.ReadAllAsync(linkedCancellation.Token).ConfigureAwait(false))
            {
                yield return result;
            }
        }
        finally
        {
            linkedCancellation.Cancel();
            try
            {
                await producer.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (linkedCancellation.IsCancellationRequested)
            {
                // Enumeration was cancelled or disposed before all inputs were consumed.
            }
        }
    }

    /// <summary>Resets the batch metrics.</summary>
    public void ResetMetrics()
    {
        Interlocked.Exchange(ref _successCount, 0);
        Interlocked.Exchange(ref _failureCount, 0);
        Interlocked.Exchange(ref _totalElapsedMs, 0);
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private PadesSignerBuilder Configure(PadesSignerBuilder builder)
    {
        builder = _externalSigner is null
            ? builder.WithCertificate(_certificate, _chain)
            : builder.WithExternalSigner(_certificate, _externalSigner, _chain);
        if (_hashAlgorithmExplicitlySet)
        {
            builder = builder.WithHashAlgorithm(_hashAlgorithm);
        }

        builder = builder.WithLevel(_profile).WithHttpClientProvider(_httpClientProvider).WithLogger(_logger);
        if (_signatureAlgorithmOid is not null)
        {
            builder = builder.WithSignatureAlgorithm(_signatureAlgorithmOid);
        }
        if (_fieldOptions is not null)
        {
            builder = builder.WithFieldOptions(_fieldOptions);
        }
        if (_operationId is not null)
        {
            builder = builder.WithOperationId(_operationId);
        }
        return builder;
    }

    private async Task ProduceResultsAsync(
        IAsyncEnumerable<(string Id, byte[] PdfBytes)> inputs,
        ChannelWriter<BatchSignResult> writer,
        CancellationToken cancellationToken)
    {
        try
        {
            await Parallel.ForEachAsync(
                inputs,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = _maxConcurrency,
                    CancellationToken = cancellationToken
                },
                async (input, token) =>
                {
                    BatchSignResult result;
                    try
                    {
                        result = new BatchSignResult(
                            input.Id,
                            await SignAsync(input.PdfBytes, token).ConfigureAwait(false),
                            null);
                    }
                    catch (OperationCanceledException) when (token.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception exception)
                    {
                        _logger.LogWarning(exception, "Batch sign failed for {Id}", input.Id);
                        result = new BatchSignResult(input.Id, null, exception);
                    }

                    await writer.WriteAsync(result, token).ConfigureAwait(false);
                }).ConfigureAwait(false);
            writer.TryComplete();
        }
        catch (Exception exception)
        {
            writer.TryComplete(exception);
        }
    }

    /// <summary>Immutable builder for <see cref="BatchSigner"/>.</summary>
    public sealed class BatchSignerBuilder
    {
        internal BatchSignerBuilder(X509Certificate2 certificate)
        {
            Certificate = certificate;
            Chain = [];
            HashAlgorithm = HashAlgorithmName.SHA256;
            HashAlgorithmExplicitlySet = false;
            Profile = AdesBaselineProfile.Basic();
            HttpClientProvider = DefaultHttpClientProvider.Instance;
            Logger = NullLogger.Instance;
            MaxConcurrency = 4;
        }

        private BatchSignerBuilder(BatchSignerBuilder source, IReadOnlyList<X509Certificate2>? chain = null,
            IExternalSigner? externalSigner = null, bool replaceExternalSigner = false,
            HashAlgorithmName? hashAlgorithm = null, bool? hashAlgorithmExplicitlySet = null,
            string? signatureAlgorithmOid = null,
            bool replaceSignatureAlgorithm = false, AdesBaselineProfile? profile = null,
            IHttpClientProvider? httpClientProvider = null, ILogger? logger = null,
            SignatureFieldOptions? fieldOptions = null, bool replaceFieldOptions = false,
            string? operationId = null, bool replaceOperationId = false, int? maxConcurrency = null)
        {
            Certificate = source.Certificate;
            Chain = chain ?? source.Chain;
            ExternalSigner = replaceExternalSigner ? externalSigner : source.ExternalSigner;
            HashAlgorithm = hashAlgorithm ?? source.HashAlgorithm;
            HashAlgorithmExplicitlySet = hashAlgorithmExplicitlySet ?? source.HashAlgorithmExplicitlySet;
            SignatureAlgorithmOid = replaceSignatureAlgorithm ? signatureAlgorithmOid : source.SignatureAlgorithmOid;
            Profile = profile ?? source.Profile;
            HttpClientProvider = httpClientProvider ?? source.HttpClientProvider;
            Logger = logger ?? source.Logger;
            FieldOptions = replaceFieldOptions ? fieldOptions?.Snapshot() : source.FieldOptions;
            OperationId = replaceOperationId ? operationId : source.OperationId;
            MaxConcurrency = maxConcurrency ?? source.MaxConcurrency;
        }

        internal X509Certificate2 Certificate { get; }
        internal IReadOnlyList<X509Certificate2> Chain { get; }
        internal IExternalSigner? ExternalSigner { get; }
        internal HashAlgorithmName HashAlgorithm { get; }
        internal bool HashAlgorithmExplicitlySet { get; }
        internal string? SignatureAlgorithmOid { get; }
        internal AdesBaselineProfile Profile { get; }
        internal IHttpClientProvider HttpClientProvider { get; }
        internal ILogger Logger { get; }
        internal SignatureFieldOptions? FieldOptions { get; }
        internal string? OperationId { get; }
        internal int MaxConcurrency { get; }

        /// <summary>Sets the certificate chain included with every signature.</summary>
        public BatchSignerBuilder WithChain(IReadOnlyList<X509Certificate2> chain)
        {
            ArgumentNullException.ThrowIfNull(chain);
            return new BatchSignerBuilder(this, chain: [.. chain]);
        }

        /// <summary>Uses an external signer for each document.</summary>
        public BatchSignerBuilder WithExternalSigner(IExternalSigner signer)
        {
            ArgumentNullException.ThrowIfNull(signer);
            return new BatchSignerBuilder(this, externalSigner: signer, replaceExternalSigner: true);
        }

        /// <summary>Sets the signing hash algorithm.</summary>
        public BatchSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
            new(this, hashAlgorithm: algorithm, hashAlgorithmExplicitlySet: true);

        /// <summary>Sets the signature algorithm OID.</summary>
        public BatchSignerBuilder WithSignatureAlgorithm(string signatureAlgorithmOid)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
            return new BatchSignerBuilder(this, signatureAlgorithmOid: signatureAlgorithmOid, replaceSignatureAlgorithm: true);
        }

        /// <summary>Sets the complete ADeS baseline profile.</summary>
        public BatchSignerBuilder WithLevel(AdesBaselineProfile profile)
        {
            ArgumentNullException.ThrowIfNull(profile);
            return new BatchSignerBuilder(this, profile: profile);
        }

        /// <summary>Sets the HTTP provider used during enrichment.</summary>
        public BatchSignerBuilder WithHttpClientProvider(IHttpClientProvider provider)
        {
            ArgumentNullException.ThrowIfNull(provider);
            return new BatchSignerBuilder(this, httpClientProvider: provider);
        }

        /// <summary>Sets the complete PDF signature field configuration.</summary>
        public BatchSignerBuilder WithFieldOptions(SignatureFieldOptions fieldOptions)
        {
            ArgumentNullException.ThrowIfNull(fieldOptions);
            return new BatchSignerBuilder(this, fieldOptions: fieldOptions, replaceFieldOptions: true);
        }

        /// <summary>Sets the operation identifier passed to external signers.</summary>
        public BatchSignerBuilder WithOperationId(string operationId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
            return new BatchSignerBuilder(this, operationId: operationId, replaceOperationId: true);
        }

        /// <summary>Sets the logger.</summary>
        public BatchSignerBuilder WithLogger(ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(logger);
            return new BatchSignerBuilder(this, logger: logger);
        }

        /// <summary>Sets the maximum concurrent terminal operations.</summary>
        public BatchSignerBuilder WithMaxConcurrency(int maxConcurrency)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(maxConcurrency, 1);
            return new BatchSignerBuilder(this, maxConcurrency: maxConcurrency);
        }

        /// <summary>Builds the configured batch signer.</summary>
        public BatchSigner Build() => new(this);
    }
}

/// <summary>Result of one batch item.</summary>
public sealed record BatchSignResult(string Id, byte[]? SignedPdf, Exception? Error)
{
    /// <summary>Whether the item was signed successfully.</summary>
    public bool IsSuccess => Error is null;
}
