namespace SimpleSign.Core.Signing;

/// <summary>
/// Adapts a <c>Func&lt;byte[], Task&lt;byte[]&gt;&gt;</c> signing delegate to the
/// <see cref="IExternalSigner"/> contract. The delegate receives the raw payload
/// bytes (CMS signed attributes or canonicalized XML <c>SignedInfo</c>) and must
/// return raw signature bytes.
/// </summary>
public sealed class FuncExternalSigner : IExternalSigner
{
    private readonly Func<byte[], Task<byte[]>> _signer;

    /// <summary>Creates an adapter around a delegate-based external signer.</summary>
    /// <param name="signer">The delegate that signs the payload bytes. Must not be null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="signer"/> is null.</exception>
    public FuncExternalSigner(Func<byte[], Task<byte[]>> signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        _signer = signer;
    }

    /// <inheritdoc/>
    public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
        ExternalSigningRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[] signature = await _signer(request.DataToSign.ToArray()).ConfigureAwait(false);
        return signature;
    }
}
