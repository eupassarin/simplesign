using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Policies;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Receives an audit record of every signing operation: each signature made and each one refused (by the signing
/// policy or a failure). Register one on a signer builder (<c>WithAuditSink</c>) to keep a trail of the signatures
/// the application generates. Records are written before the signer returns: an exception from the sink fails the
/// operation, so a signature is never returned without its record.
/// </summary>
public interface ISignatureAuditSink
{
    /// <summary>Records one signing operation.</summary>
    /// <param name="auditEvent">What was signed, with which certificate and policy, and the outcome.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the record is kept.</returns>
    ValueTask RecordAsync(SignatureAuditEvent auditEvent, CancellationToken cancellationToken);
}

/// <summary>One signing operation, as recorded by an <see cref="ISignatureAuditSink"/>.</summary>
public sealed record SignatureAuditEvent
{
    /// <summary>When the operation ended (UTC).</summary>
    public required DateTimeOffset Time { get; init; }

    /// <summary>The signature format: <c>PAdES</c>, <c>CAdES</c> or <c>XAdES</c>.</summary>
    public required string Format { get; init; }

    /// <summary>The operation id given to the builder, or null.</summary>
    public string? OperationId { get; init; }

    /// <summary>The baseline level requested.</summary>
    public required AdesBaselineLevel RequestedLevel { get; init; }

    /// <summary>The baseline level achieved; null when the signature was refused.</summary>
    public AdesBaselineLevel? AchievedLevel { get; init; }

    /// <summary>Whether a signature was produced.</summary>
    public required bool Signed { get; init; }

    /// <summary>Why the signature was refused; null when it was produced or the failure has no reason.</summary>
    public SigningErrorReason? Reason { get; init; }

    /// <summary>The message of the refusal; null when the signature was produced.</summary>
    public string? Message { get; init; }

    /// <summary>The subject of the signing certificate, or null when none was given.</summary>
    public string? CertificateSubject { get; init; }

    /// <summary>The issuer of the signing certificate, or null.</summary>
    public string? CertificateIssuer { get; init; }

    /// <summary>The serial number of the signing certificate (hex), or null.</summary>
    public string? CertificateSerialNumber { get; init; }

    /// <summary>The SHA-256 fingerprint of the signing certificate (hex), or null.</summary>
    public string? CertificateSha256 { get; init; }

    /// <summary>The name of the signing policy applied.</summary>
    public string? PolicyName { get; init; }

    /// <summary>The digest of the signing policy applied (<see cref="SigningPolicy.Digest"/>).</summary>
    public string? PolicyDigest { get; init; }

    /// <summary>The SHA-256 of the document or data given to sign (hex), when it was held in memory; otherwise null.</summary>
    public string? InputSha256 { get; init; }

    /// <summary>The SHA-256 of the signed artifact (hex); null when the signature was refused.</summary>
    public string? OutputSha256 { get; init; }

    /// <summary>The event for an operation of <paramref name="format"/> by <paramref name="certificate"/> under <paramref name="policy"/>.</summary>
    internal static SignatureAuditEvent Start(
        string format, string? operationId, AdesBaselineLevel requested, X509Certificate2? certificate, SigningPolicy policy, ReadOnlySpan<byte> input) =>
        new()
        {
            Time = DateTimeOffset.UtcNow,
            Format = format,
            OperationId = operationId,
            RequestedLevel = requested,
            Signed = false,
            CertificateSubject = certificate?.Subject,
            CertificateIssuer = certificate?.Issuer,
            CertificateSerialNumber = certificate?.SerialNumber,
            CertificateSha256 = certificate is null ? null : Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
            PolicyName = policy.Name,
            PolicyDigest = policy.Digest,
            InputSha256 = input.IsEmpty ? null : Convert.ToHexString(SHA256.HashData(input)),
        };
}

/// <summary>Records signing operations around a signer's work.</summary>
internal static class SignatureAudit
{
    /// <summary>
    /// Runs <paramref name="sign"/> and records its outcome with <paramref name="sink"/>: the signed artifact's hash and
    /// achieved level, or the refusal. Without a sink, only runs it. The operation is also measured
    /// (<see cref="Diagnostics.SimpleSignTelemetry"/>) when something listens.
    /// </summary>
    internal static async Task<T> RunAsync<T>(
        ISignatureAuditSink? sink,
        Func<SignatureAuditEvent> start,
        Func<Task<T>> sign,
        Func<T, (byte[] Artifact, AdesBaselineLevel Achieved)> outcome,
        CancellationToken cancellationToken)
    {
        var telemetry = Diagnostics.Telemetry.Signing.Start();
        if (sink is null && !telemetry.IsActive)
        {
            return await sign().ConfigureAwait(false);
        }

        T result;
        try
        {
            result = await sign().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var refused = start() with
            {
                Time = DateTimeOffset.UtcNow,
                Reason = (ex as SigningException)?.Reason,
                Message = ex.Message,
            };
            Measure(telemetry, refused, ex is SigningException ? Diagnostics.SimpleSignTelemetry.Outcomes.Refused : Diagnostics.SimpleSignTelemetry.Outcomes.Error);
            if (sink is not null)
            {
                await sink.RecordAsync(refused, cancellationToken).ConfigureAwait(false);
            }

            throw;
        }
        catch (OperationCanceledException)
        {
            telemetry.Complete(Diagnostics.SimpleSignTelemetry.Outcomes.Error);
            throw;
        }

        var (artifact, achieved) = outcome(result);
        if (telemetry.IsActive)
        {
            Measure(telemetry, start() with { Signed = true, AchievedLevel = achieved }, Diagnostics.SimpleSignTelemetry.Outcomes.Success);
        }

        if (sink is not null)
        {
            await sink.RecordAsync(start() with
            {
                Time = DateTimeOffset.UtcNow,
                Signed = true,
                AchievedLevel = achieved,
                OutputSha256 = Convert.ToHexString(SHA256.HashData(artifact)),
            }, cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    /// <summary>Records a signing operation's format, levels, outcome and reason — nothing about the certificate or the data.</summary>
    private static void Measure(Diagnostics.Telemetry.Scope telemetry, SignatureAuditEvent e, string outcome) =>
        telemetry.Complete(outcome,
            [
                new(Diagnostics.SimpleSignTelemetry.Tags.Format, e.Format),
                new(Diagnostics.SimpleSignTelemetry.Tags.RequestedLevel, e.RequestedLevel.ToString()),
                new(Diagnostics.SimpleSignTelemetry.Tags.AchievedLevel, e.AchievedLevel?.ToString()),
                new(Diagnostics.SimpleSignTelemetry.Tags.Reason, e.Reason?.ToString()),
            ]);
}
