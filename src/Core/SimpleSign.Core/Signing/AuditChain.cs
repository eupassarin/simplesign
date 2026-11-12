using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SimpleSign.Core.Signing;

/// <summary>One record of an audit hash chain: the canonical content of an event and its chaining hashes.</summary>
/// <param name="Content">The canonical content (<see cref="AuditChain.Canonicalize"/>).</param>
/// <param name="PreviousHash">The hash of the record before it, or <see cref="AuditChain.Genesis"/> for the first one.</param>
/// <param name="Hash">The record's hash (<see cref="AuditChain.Link"/> of <paramref name="PreviousHash"/> and <paramref name="Content"/>).</param>
public sealed record AuditChainRecord(string Content, string PreviousHash, string Hash);

/// <summary>
/// The hash chain of audit records written by <see cref="JsonLinesAuditSink"/>, for any other store: a database-backed
/// <see cref="ISignatureAuditSink"/> keeps <see cref="Canonicalize"/>'s content and <see cref="Link"/>'s hash of each
/// event and produces exactly the chain the file sink does, and <see cref="Verify"/> checks it the same way.
/// </summary>
/// <remarks>
/// Each record's hash is the SHA-256 (upper-case hex) of the UTF-8 bytes of the previous hash, a line feed and the
/// content; the first record's previous hash is <see cref="Genesis"/>. A record changed, removed or inserted later
/// breaks the chain from that record on. The chain shows tampering; it does not prevent it.
/// </remarks>
public static class AuditChain
{
    /// <summary>The previous hash of the first record: 64 zeros.</summary>
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>
    /// The event as a compact JSON object, without the chain fields: the content that is hashed. Absent optional fields
    /// are left out; the order of the members is fixed.
    /// </summary>
    /// <param name="auditEvent">The event.</param>
    /// <returns>The canonical content.</returns>
    public static string Canonicalize(SignatureAuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("time", auditEvent.Time.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            writer.WriteString("format", auditEvent.Format);
            WriteOptional(writer, "operationId", auditEvent.OperationId);
            writer.WriteString("requestedLevel", auditEvent.RequestedLevel.ToString());
            WriteOptional(writer, "achievedLevel", auditEvent.AchievedLevel?.ToString());
            writer.WriteBoolean("signed", auditEvent.Signed);
            WriteOptional(writer, "reason", auditEvent.Reason?.ToString());
            WriteOptional(writer, "message", auditEvent.Message);
            WriteOptional(writer, "certificateSubject", auditEvent.CertificateSubject);
            WriteOptional(writer, "certificateIssuer", auditEvent.CertificateIssuer);
            WriteOptional(writer, "certificateSerialNumber", auditEvent.CertificateSerialNumber);
            WriteOptional(writer, "certificateSha256", auditEvent.CertificateSha256);
            WriteOptional(writer, "policyName", auditEvent.PolicyName);
            WriteOptional(writer, "policyDigest", auditEvent.PolicyDigest);
            WriteOptional(writer, "inputSha256", auditEvent.InputSha256);
            WriteOptional(writer, "outputSha256", auditEvent.OutputSha256);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>The hash of a record whose content is <paramref name="content"/> and which follows <paramref name="previousHash"/>.</summary>
    /// <param name="previousHash">The previous record's hash, or <see cref="Genesis"/>.</param>
    /// <param name="content">The record's canonical content.</param>
    /// <returns>The SHA-256 of the record, upper-case hex.</returns>
    public static string Link(string previousHash, string content)
    {
        ArgumentNullException.ThrowIfNull(previousHash);
        ArgumentNullException.ThrowIfNull(content);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(previousHash + "\n" + content)));
    }

    /// <summary>The record that follows <paramref name="previousHash"/> for <paramref name="auditEvent"/>.</summary>
    /// <param name="previousHash">The last record's hash, or <see cref="Genesis"/>.</param>
    /// <param name="auditEvent">The event.</param>
    /// <returns>The record to store.</returns>
    public static AuditChainRecord Append(string previousHash, SignatureAuditEvent auditEvent)
    {
        string content = Canonicalize(auditEvent);
        return new AuditChainRecord(content, previousHash, Link(previousHash, content));
    }

    /// <summary>Checks a chain of records, in the order they were written.</summary>
    /// <param name="records">The records, first one first.</param>
    /// <returns>The 1-based position of the first record that breaks the chain, or 0 when the whole chain holds.</returns>
    public static int Verify(IEnumerable<AuditChainRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        string previous = Genesis;
        int position = 0;
        foreach (var record in records)
        {
            position++;
            if (!Follows(previous, record))
            {
                return position;
            }

            previous = record.Hash;
        }

        return 0;
    }

    /// <summary>Whether <paramref name="record"/> follows a record whose hash is <paramref name="previousHash"/> and has its own hash right.</summary>
    /// <param name="previousHash">The previous record's hash, or <see cref="Genesis"/>.</param>
    /// <param name="record">The record.</param>
    /// <returns>True when the record is linked and intact.</returns>
    public static bool Follows(string previousHash, AuditChainRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return record.PreviousHash == previousHash && record.Hash == Link(record.PreviousHash, record.Content);
    }

    private static void WriteOptional(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is not null)
        {
            writer.WriteString(name, value);
        }
    }
}
