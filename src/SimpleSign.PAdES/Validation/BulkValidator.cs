using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace SimpleSign.PAdES.Validation;

/// <summary>
/// High-performance streaming bulk validator for mass PDF validation.
/// Unlike <see cref="PdfSignatureValidator.ValidateBatchAsync"/> which buffers all results,
/// this class yields results as they complete via <see cref="IAsyncEnumerable{T}"/>,
/// keeping memory usage constant regardless of batch size.
/// </summary>
public sealed class BulkValidator
{
    private readonly PdfSignatureValidator _validator;
    private readonly ILogger _logger;
    private readonly int _maxConcurrency;

    private int _successCount;
    private int _failureCount;
    private long _totalElapsedMs;

    /// <summary>Creates a new bulk validator.</summary>
    /// <param name="validator">The underlying PDF signature validator.</param>
    /// <param name="maxConcurrency">Maximum concurrent validations. Default: 4.</param>
    /// <param name="logger">Optional logger.</param>
    public BulkValidator(PdfSignatureValidator validator, int maxConcurrency = 4, ILogger? logger = null)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        if (maxConcurrency < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrency), "Must be at least 1.");
        }

        _maxConcurrency = maxConcurrency;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>Number of PDFs successfully validated.</summary>
    public int SuccessCount => Volatile.Read(ref _successCount);

    /// <summary>Number of PDFs that failed to validate (unreadable, corrupt, etc.).</summary>
    public int FailureCount => Volatile.Read(ref _failureCount);

    /// <summary>Total PDFs processed.</summary>
    public int TotalProcessed => SuccessCount + FailureCount;

    /// <summary>Average validation time per document in milliseconds.</summary>
    public double AverageElapsedMs
    {
        get
        {
            var total = TotalProcessed;
            return total > 0 ? (double)Volatile.Read(ref _totalElapsedMs) / total : 0;
        }
    }

    /// <summary>
    /// Validates a single PDF and returns the validation results.
    /// </summary>
    /// <param name="pdfStream">Seekable PDF stream.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Validation results for all signatures in the PDF.</returns>
    public async Task<IReadOnlyList<SignatureValidationResult>> ValidateAsync(
        Stream pdfStream,
        CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var results = await _validator.ValidateAsync(pdfStream, cancellationToken: cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _successCount);
            return results;
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
    /// Validates all PDFs from an async enumerable, yielding results as they complete.
    /// Memory usage stays constant regardless of batch size.
    /// </summary>
    /// <param name="inputs">Async enumerable of (identifier, PDF bytes) pairs.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Async enumerable of bulk validation results.</returns>
    public async IAsyncEnumerable<BulkValidationResult> ValidateAllAsync(
        IAsyncEnumerable<(string Id, byte[] PdfBytes)> inputs,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var semaphore = new SemaphoreSlim(_maxConcurrency, _maxConcurrency);
        var tasks = new List<Task<BulkValidationResult>>();

        try
        {
            await foreach (var (id, pdfBytes) in inputs.WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

                tasks.Add(Task.Run(async () =>
                {
                    var sw = Stopwatch.StartNew();
                    try
                    {
                        using var stream = new MemoryStream(pdfBytes);
                        var results = await _validator.ValidateAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
                        sw.Stop();
                        Interlocked.Increment(ref _successCount);
                        Interlocked.Add(ref _totalElapsedMs, sw.ElapsedMilliseconds);

                        return new BulkValidationResult(id, results, null, sw.Elapsed);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        sw.Stop();
                        Interlocked.Increment(ref _failureCount);
                        Interlocked.Add(ref _totalElapsedMs, sw.ElapsedMilliseconds);
                        _logger.LogWarning(ex, "Bulk validation failed for {Id}", id);

                        return new BulkValidationResult(id, null, ex, sw.Elapsed);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, cancellationToken));

                // Yield completed tasks
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
        finally
        {
            // Ensure all tasks complete before semaphore is disposed
            try
            {
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch
            {
                // Exceptions are already handled individually in each task
            }
        }
    }

    /// <summary>
    /// Validates all PDFs from a synchronous enumerable of file paths.
    /// Reads files on demand to minimize memory usage.
    /// </summary>
    /// <param name="filePaths">File paths to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Async enumerable of bulk validation results.</returns>
    public IAsyncEnumerable<BulkValidationResult> ValidateFilesAsync(
        IEnumerable<string> filePaths,
        CancellationToken cancellationToken = default)
    {
        return ValidateAllAsync(ReadFilesAsync(filePaths, cancellationToken), cancellationToken);
    }

    /// <summary>Resets success/failure counters and average elapsed time.</summary>
    public void ResetMetrics()
    {
        Volatile.Write(ref _successCount, 0);
        Volatile.Write(ref _failureCount, 0);
        Volatile.Write(ref _totalElapsedMs, 0);
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> ReadFilesAsync(
        IEnumerable<string> filePaths,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var path in filePaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            yield return (Path.GetFileName(path), bytes);
        }
    }
}

/// <summary>Result of a single bulk validation operation.</summary>
/// <param name="Id">Identifier of the input PDF.</param>
/// <param name="Results">Validation results per signature, or null if processing failed.</param>
/// <param name="Error">Exception if processing failed, or null on success.</param>
/// <param name="Duration">Time spent validating this PDF.</param>
public sealed record BulkValidationResult(
    string Id,
    IReadOnlyList<SignatureValidationResult>? Results,
    Exception? Error,
    TimeSpan Duration)
{
    /// <summary>Whether the PDF was successfully processed (not necessarily valid signatures).</summary>
    public bool IsProcessed => Error is null;

    /// <summary>Number of valid signatures found. Zero if processing failed.</summary>
    public int ValidSignatureCount => Results?.Count(r => r.IsValid) ?? 0;

    /// <summary>Total signatures found. Zero if processing failed.</summary>
    public int TotalSignatureCount => Results?.Count ?? 0;
}
