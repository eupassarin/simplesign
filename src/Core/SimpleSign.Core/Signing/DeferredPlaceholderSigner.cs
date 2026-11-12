namespace SimpleSign.Core.Signing;

/// <summary>
/// Stands for the key of a two-phase (deferred) signature while it is prepared: the key is held
/// elsewhere and signs between the two phases, so this signer is never asked to sign.
/// </summary>
internal sealed class DeferredPlaceholderSigner : IExternalSigner
{
    /// <summary>The only instance.</summary>
    internal static DeferredPlaceholderSigner Instance { get; } = new();

    private DeferredPlaceholderSigner()
    {
    }

    /// <inheritdoc />
    public ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(
            "A deferred signature is signed between its two phases: prepare it, sign the data to sign, then complete the session.");
}
