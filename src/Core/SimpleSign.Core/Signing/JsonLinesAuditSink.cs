using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SimpleSign.Core.Signing;

/// <summary>
/// An <see cref="ISignatureAuditSink"/> that appends each record to a file, one JSON object per line. Each line carries
/// the SHA-256 of the previous line's hash and of its own content (<c>prev</c>, <c>hash</c>), so a line changed,
/// removed or inserted later breaks the chain: <see cref="Verify"/> finds it. The chain shows tampering; it does not
/// prevent it: keep the file where the application cannot rewrite it, or ship each line elsewhere as well.
/// </summary>
public sealed class JsonLinesAuditSink : ISignatureAuditSink, IDisposable
{
    private const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

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
            string content = Content(auditEvent);
            string hash = Hash(_last, content);
            string line = content[..^1] + $",\"prev\":\"{_last}\",\"hash\":\"{hash}\"}}" + "\n";
            await File.AppendAllTextAsync(_path, line, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            _last = hash;
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
        string previous = Genesis;
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

            if (prev != previous || hash != Hash(prev, content))
            {
                return number;
            }

            previous = hash;
        }

        return 0;
    }

    /// <inheritdoc />
    public void Dispose() => _gate.Dispose();

    private static string Hash(string previous, string content) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(previous + "\n" + content)));

    private static string ReadLastHash(string path)
    {
        if (!File.Exists(path))
        {
            return Genesis;
        }

        string? last = File.ReadLines(path).LastOrDefault(l => l.Length > 0);
        if (last is null)
        {
            return Genesis;
        }

        using var document = JsonDocument.Parse(last);
        return document.RootElement.GetProperty("hash").GetString() ?? Genesis;
    }

    /// <summary>The event as a compact JSON object, without the chain fields.</summary>
    private static string Content(SignatureAuditEvent e)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("time", e.Time.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            writer.WriteString("format", e.Format);
            WriteOptional(writer, "operationId", e.OperationId);
            writer.WriteString("requestedLevel", e.RequestedLevel.ToString());
            WriteOptional(writer, "achievedLevel", e.AchievedLevel?.ToString());
            writer.WriteBoolean("signed", e.Signed);
            WriteOptional(writer, "reason", e.Reason?.ToString());
            WriteOptional(writer, "message", e.Message);
            WriteOptional(writer, "certificateSubject", e.CertificateSubject);
            WriteOptional(writer, "certificateIssuer", e.CertificateIssuer);
            WriteOptional(writer, "certificateSerialNumber", e.CertificateSerialNumber);
            WriteOptional(writer, "certificateSha256", e.CertificateSha256);
            WriteOptional(writer, "policyName", e.PolicyName);
            WriteOptional(writer, "policyDigest", e.PolicyDigest);
            WriteOptional(writer, "inputSha256", e.InputSha256);
            WriteOptional(writer, "outputSha256", e.OutputSha256);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static void WriteOptional(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is not null)
        {
            writer.WriteString(name, value);
        }
    }
}
