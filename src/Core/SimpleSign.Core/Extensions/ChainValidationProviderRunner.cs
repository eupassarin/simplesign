namespace SimpleSign.Core.Extensions;

/// <summary>
/// Runs the chain validation of a trust framework (<see cref="IChainValidationProvider"/>) for a signer: the first
/// provider that can validate the certificate decides, and its errors and failures are reported. Shared by the PAdES,
/// CAdES and XAdES validators.
/// </summary>
internal static class ChainValidationProviderRunner
{
    /// <summary>
    /// The result of the first provider whose <see cref="IChainValidationProvider.CanValidate"/> takes the signer, or
    /// null when none does. A result that is not trusted adds its errors, prefixed with its region, to
    /// <paramref name="errors"/>; a trusted one with errors adds them to <paramref name="warnings"/>. A provider that
    /// throws is reported in <paramref name="warnings"/> (and to <paramref name="onFailure"/>), and the next one is tried.
    /// </summary>
    /// <param name="providers">The providers, in order.</param>
    /// <param name="context">The signer and what the signature carries.</param>
    /// <param name="errors">Where the errors of an untrusted chain go (a caller that only wants the data passes its warnings).</param>
    /// <param name="warnings">Where the warnings go.</param>
    /// <param name="onFailure">Told of a provider that threw, with its type name (for the caller's log).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    internal static async Task<ChainValidationResult?> RunAsync(
        IReadOnlyList<IChainValidationProvider> providers,
        ChainValidationContext context,
        ICollection<string> errors,
        ICollection<string> warnings,
        Action<Exception, string>? onFailure,
        CancellationToken cancellationToken)
    {
        foreach (var provider in providers)
        {
            if (!provider.CanValidate(context.Certificate))
            {
                continue;
            }

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = await provider.ValidateAsync(context, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                var target = result.IsTrusted ? warnings : errors;
                foreach (var error in result.Errors ?? [])
                {
                    target.Add($"[{result.RegionCode}] {error}");
                }

                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                onFailure?.Invoke(ex, provider.GetType().Name);
                warnings.Add($"Chain validation provider '{provider.GetType().Name}' failed: {ex.Message}");
            }
        }

        return null;
    }
}
