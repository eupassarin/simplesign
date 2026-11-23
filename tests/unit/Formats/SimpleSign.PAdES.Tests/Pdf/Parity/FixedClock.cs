namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>A clock that always says the same time, so what a writer writes can be snapshotted.</summary>
/// <param name="now">The time.</param>
internal sealed class FixedClock(DateTimeOffset now) : TimeProvider
{
    /// <inheritdoc/>
    public override DateTimeOffset GetUtcNow() => now;
}
