using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using SimpleSign.Core.Signing;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>One verification by an <see cref="IofeVerificationAgent"/>, as recorded by an <see cref="IVerificationAuditSink"/>.</summary>
public sealed record IofeVerificationAuditEvent
{
    /// <summary>When the document was verified.</summary>
    public required DateTimeOffset Time { get; init; }

    /// <summary>The format of the document.</summary>
    public required IofeDocumentFormat Format { get; init; }

    /// <summary>The SHA-256 of the document received, upper-case hex.</summary>
    public required string DocumentSha256 { get; init; }

    /// <summary>Who sent the document.</summary>
    public required string SenderId { get; init; }

    /// <summary>The reference of the reception in the system that received it, when given.</summary>
    public string? Reference { get; init; }

    /// <summary>Whether the document was accepted: every signature valid.</summary>
    public required bool Accepted { get; init; }

    /// <summary>The indication of each signature, in order (<c>Valid</c>, <c>Invalid</c>, <c>Indeterminate</c>).</summary>
    public IReadOnlyList<string> Indications { get; init; } = [];

    /// <summary>Why the document was rejected; empty when it was accepted.</summary>
    public IReadOnlyList<string> Reasons { get; init; } = [];

    /// <summary>Whether the notice of a rejected document was handed to the notifier; null when there was none to send.</summary>
    public bool? NoticeDelivered { get; init; }

    /// <summary>The validation policy applied.</summary>
    public string? PolicyName { get; init; }

    /// <summary>The digest of the validation policy applied.</summary>
    public string? PolicyDigest { get; init; }

    /// <summary>The procedure of the contingency the verification was made under; null when there was none.</summary>
    public string? Contingency { get; init; }
}

/// <summary>
/// Receives a record of every document an <see cref="IofeVerificationAgent"/> verifies, accepted or rejected (guide
/// Req. 24). The record is written before the agent returns; a failing sink fails the verification.
/// </summary>
public interface IVerificationAuditSink
{
    /// <summary>Keeps the record.</summary>
    /// <param name="auditEvent">The verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the record is kept.</returns>
    ValueTask RecordAsync(IofeVerificationAuditEvent auditEvent, CancellationToken cancellationToken);
}

/// <summary>
/// An <see cref="IVerificationAuditSink"/> that appends each record to a file, one JSON object per line, chained like
/// <see cref="JsonLinesAuditSink"/> does: each line carries the hash of the previous one (<c>prev</c>) and its own
/// (<c>hash</c>), so a line changed, removed or inserted later is found by <see cref="Verify"/> (and by
/// <c>simplesign audit verify</c>, which reads the same layout). The chain shows tampering; it does not prevent it:
/// keep the file where the application cannot rewrite it.
/// </summary>
public sealed class JsonLinesVerificationAuditSink : IVerificationAuditSink, IDisposable
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _last;

    /// <summary>Creates a sink appending to <paramref name="path"/>; an existing file's chain is continued.</summary>
    /// <param name="path">The audit file.</param>
    public JsonLinesVerificationAuditSink(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        _path = Path.GetFullPath(path);
    }

    /// <inheritdoc />
    public async ValueTask RecordAsync(IofeVerificationAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _last ??= ReadLastHash(_path);
            string content = Canonicalize(auditEvent);
            string hash = AuditChain.Link(_last, content);
            string line = content[..^1] + $",\"prev\":\"{_last}\",\"hash\":\"{hash}\"}}" + "\n";
            await File.AppendAllTextAsync(_path, line, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            _last = hash;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Checks the hash chain of an audit file written by this sink.</summary>
    /// <param name="path">The audit file.</param>
    /// <returns>The 1-based number of the first line that breaks the chain, or 0 when the whole file is intact.</returns>
    public static int Verify(string path) => JsonLinesAuditSink.Verify(path);

    /// <inheritdoc />
    public void Dispose() => _gate.Dispose();

    /// <summary>The content of a record: a JSON object with the properties in a fixed order, nulls left out.</summary>
    internal static string Canonicalize(IofeVerificationAuditEvent auditEvent)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("time", auditEvent.Time.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            writer.WriteString("kind", "verification");
            writer.WriteString("format", auditEvent.Format.ToString());
            writer.WriteString("documentSha256", auditEvent.DocumentSha256);
            writer.WriteString("sender", auditEvent.SenderId);
            WriteOptional(writer, "reference", auditEvent.Reference);
            writer.WriteBoolean("accepted", auditEvent.Accepted);
            WriteArray(writer, "indications", auditEvent.Indications);
            WriteArray(writer, "reasons", auditEvent.Reasons);
            if (auditEvent.NoticeDelivered is { } delivered)
            {
                writer.WriteBoolean("noticeDelivered", delivered);
            }

            WriteOptional(writer, "policy", auditEvent.PolicyName);
            WriteOptional(writer, "policyDigest", auditEvent.PolicyDigest);
            WriteOptional(writer, "contingency", auditEvent.Contingency);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WriteOptional(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is not null)
        {
            writer.WriteString(name, value);
        }
    }

    private static void WriteArray(Utf8JsonWriter writer, string name, IReadOnlyList<string> values)
    {
        writer.WriteStartArray(name);
        foreach (string value in values)
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
    }

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
