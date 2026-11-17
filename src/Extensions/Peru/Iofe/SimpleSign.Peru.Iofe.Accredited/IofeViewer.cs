using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.Peru.Iofe.Accredited.Internal;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>
/// The viewer the guide asks signature software to give the signer and the recipient (Req. 18, 28): for each
/// signature of a document, whether the document is intact, when it was signed, the public key and the data of the
/// certificate, as a page in Spanish. It validates under the IOFE policy, revocation included.
/// </summary>
public sealed class IofeViewer : IAsyncDisposable
{
    private readonly TrustProfile _profile;
    private readonly IHttpClientProvider? _http;
    private readonly IAsyncDisposable? _owned;

    internal IofeViewer(TrustProfile profile, IHttpClientProvider? http, IAsyncDisposable? owned = null)
    {
        _profile = profile;
        _http = http;
        _owned = owned;
    }

    /// <summary>Creates a viewer for a relying party that neither signs nor runs a verification agent.</summary>
    /// <param name="trust">Whom to trust; null for INDECOPI's trusted list.</param>
    /// <param name="httpClientProvider">The HTTP client of the revocation checks; null for the default.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The viewer.</returns>
    public static async Task<IofeViewer> CreateAsync(
        IofeTrust? trust = null, IHttpClientProvider? httpClientProvider = null, CancellationToken cancellationToken = default)
    {
        var (profile, owned) = await (trust ?? IofeTrust.IndecopiList())
            .ResolveAsync(IofePolicies.AgentSigning, IofePolicies.AgentValidation, cancellationToken).ConfigureAwait(false);
        return new IofeViewer(profile, httpClientProvider, owned);
    }

    /// <summary>Stops reading the trusted list again, when this viewer loaded it.</summary>
    /// <returns>A task that completes when the list is released.</returns>
    public ValueTask DisposeAsync() => _owned?.DisposeAsync() ?? ValueTask.CompletedTask;

    /// <summary>The page that shows the signatures of <paramref name="document"/>.</summary>
    /// <param name="document">The signed document (PDF, CMS or XML).</param>
    /// <param name="detachedContent">The signed content of a detached signature.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A self-contained HTML page in Spanish.</returns>
    public async Task<string> RenderAsync(byte[] document, byte[]? detachedContent = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        var outcome = await IofeValidation
            .ValidateAsync(document, detachedContent, _profile, _http, checkRevocation: true, operationId: null, cancellationToken)
            .ConfigureAwait(false);
        return ValidationReports.ToHtml(outcome.Signatures, "es");
    }
}
