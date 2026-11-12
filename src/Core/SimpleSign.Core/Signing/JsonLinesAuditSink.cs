using System.Text;
using System.Text.Json;

namespace SimpleSign.Core.Signing;

/// <summary>
/// An <see cref="ISignatureAuditSink"/> that appends each record to a file, one JSON object per line. Each line carries
/// the SHA-256 of the previous line's hash and of its own content (<c>prev</c>, <c>hash</c>), so a line changed,
/// removed or inserted later breaks the chain: <see cref="Verify"/> finds it. The chain shows tampering; it does not
/// prevent it: keep the file where the application cannot rewrite it, or ship each line elsewhere as well. The content
/// and hashes are those of <see cref="AuditChain"/>: a sink writing to another store can produce the same chain.
/// </summary>
public sealed class JsonLinesAuditSink : ISignatureAuditSink, IDisposable
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _last;

    /// <summary>Creates a sink appending to <paramref name="path"/>; an existing file's chain is continued.</summary>
    /// <param name="path">The audit file.</param>
    public JsonLinesAuditSink(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        _path = Path.GetFullPath(path);
    }

    /// <inheritdoc />
    public async ValueTask RecordAsync(SignatureAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _last ??= ReadLastHash(_path);
            var record = AuditChain.Append(_last, auditEvent);
            string line = record.Content[..^1] + $",\"prev\":\"{record.PreviousHash}\",\"hash\":\"{record.Hash}\"}}" + "\n";
            await File.AppendAllTextAsync(_path, line, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            _last = record.Hash;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Checks the hash chain of an audit file written by this sink.
    /// </summary>
    /// <param name="path">The audit file.</param>
    /// <returns>The 1-based number of the first line that breaks the chain, or 0 when the whole file is intact.</returns>
    public static int Verify(string path)
    {
        string previous = AuditChain.Genesis;
        int number = 0;
        foreach (string line in File.ReadLines(path))
        {
            number++;
            if (line.Length == 0)
            {
                continue;
            }

            int marker = line.LastIndexOf(",\"prev\":\"", StringComparison.Ordinal);
            if (marker < 0)
            {
                return number;
            }

            string content = line[..marker] + "}";
            string prev, hash;
            try
            {
                using var document = JsonDocument.Parse(line);
                prev = document.RootElement.GetProperty("prev").GetString() ?? "";
                hash = document.RootElement.GetProperty("hash").GetString() ?? "";
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            {
                return number;
            }

            if (!AuditChain.Follows(previous, new AuditChainRecord(content, prev, hash)))
            {
                return number;
            }

            previous = hash;
        }

        return 0;
    }

    /// <inheritdoc />
    public void Dispose() => _gate.Dispose();

    private static string ReadLastHash(string path)
    {
        if (!File.Exists(path))
        {
            return AuditChain.Genesis;
        }

        string? last = File.ReadLines(path).LastOrDefault(l => l.Length > 0);
        if (last is null)
        {
            return AuditChain.Genesis;
        }

        using var document = JsonDocument.Parse(last);
        return document.RootElement.GetProperty("hash").GetString() ?? AuditChain.Genesis;
    }
}
