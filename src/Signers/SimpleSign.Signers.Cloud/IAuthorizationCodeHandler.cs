namespace SimpleSign.Signers.Cloud;

/// <summary>
/// Runs the interactive part of an OAuth 2.0 authorization code flow: shows
/// the authorization page to the user (browser, web view, redirect of a web app)
/// and returns the URI the service redirected back to, with its <c>code</c> and <c>state</c>.
/// </summary>
/// <remarks>
/// Desktop and CLI apps can use <see cref="LoopbackAuthorizationHandler"/>. Web apps usually
/// redirect the user themselves and call the client's code-exchange method from their callback.
/// </remarks>
public interface IAuthorizationCodeHandler
{
    /// <summary>Shows the authorization page and waits for the redirect back.</summary>
    /// <param name="authorizationUri">The service's authorization URL, with all query parameters.</param>
    /// <param name="redirectUri">The redirect URI registered with the service.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>The full redirect URI received (including its query string).</returns>
    ValueTask<Uri> AuthorizeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken);
}
