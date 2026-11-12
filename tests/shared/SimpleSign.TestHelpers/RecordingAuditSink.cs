using SimpleSign.Core.Signing;

namespace SimpleSign.TestHelpers;

/// <summary>An audit sink that keeps every event it receives, in order.</summary>
public sealed class RecordingAuditSink : ISignatureAuditSink
{
    /// <summary>The events recorded so far.</summary>
    public List<SignatureAuditEvent> Events { get; } = [];

    /// <inheritdoc />
    public ValueTask RecordAsync(SignatureAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        Events.Add(auditEvent);
        return ValueTask.CompletedTask;
    }
}
