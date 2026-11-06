using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace SimpleSign.Signers.Cloud.Csc;

/// <summary>Connection settings for a Cloud Signature Consortium (CSC) API v2 service.</summary>
public sealed record CscClientOptions
{
    /// <summary>The service base URL, e.g. <c>https://qtsp.example/csc/v2/</c>.</summary>
    public required Uri BaseUri { get; init; }

    /// <summary>
    /// A service access token obtained elsewhere (scope <c>service</c>). Alternatively call
    /// <see cref="CscClient.AuthorizeServiceAsync"/> or <see cref="CscClient.AuthorizeServiceWithClientCredentialsAsync"/>.
    /// </summary>
    public string? AccessToken { get; init; }

    /// <summary>The OAuth client ID, for the OAuth flows.</summary>
    public string? ClientId { get; init; }

    /// <summary>The OAuth client secret. Keep it out of source control.</summary>
    public string? ClientSecret { get; init; }

    /// <summary>The redirect URI registered with the service. Default <c>http://127.0.0.1:43821/callback</c>.</summary>
    public Uri RedirectUri { get; init; } = new("http://127.0.0.1:43821/callback");

    /// <summary>The OAuth 2.0 base URL. Default: <see cref="BaseUri"/> + <c>oauth2/</c>.</summary>
    public Uri? OAuthBaseUri { get; init; }

    /// <summary>Receives diagnostics of the signer. Secrets are never logged. Default: no logging.</summary>
    public ILogger? Logger { get; init; }
}

/// <summary>Service information returned by <c>info</c>.</summary>
/// <param name="Name">The service name.</param>
/// <param name="Specs">The CSC specification version implemented.</param>
/// <param name="AuthTypes">The supported service authorization types (e.g. <c>oauth2code</c>, <c>oauth2client</c>).</param>
/// <param name="Methods">The API methods implemented.</param>
public sealed record CscInfo(string? Name, string? Specs, IReadOnlyList<string> AuthTypes, IReadOnlyList<string> Methods);

/// <summary>A signing credential (key + certificate) held by a CSC service.</summary>
/// <param name="Id">The credential ID.</param>
/// <param name="Certificate">The signer certificate. Disposed with the <see cref="CscSigner"/> that owns it.</param>
/// <param name="Chain">The other certificates returned (usually the issuing chain).</param>
/// <param name="KeyAlgorithms">The signature algorithm OIDs the key accepts (<c>key/algo</c>).</param>
/// <param name="KeyLength">The key length in bits, when reported.</param>
/// <param name="AuthMode">How signing is authorized: <c>explicit</c> (PIN/OTP), <c>oauth2code</c> or <c>implicit</c>.</param>
/// <param name="Scal">The Sole Control Assurance Level: <c>1</c> or <c>2</c> (2 binds each authorization to the hashes).</param>
/// <param name="MultiSign">How many signatures one authorization allows.</param>
/// <param name="IsKeyEnabled">Whether the key is enabled.</param>
public sealed record CscCredential(
    string Id,
    X509Certificate2 Certificate,
    IReadOnlyList<X509Certificate2> Chain,
    IReadOnlyList<string> KeyAlgorithms,
    int? KeyLength,
    string AuthMode,
    string Scal,
    int MultiSign,
    bool IsKeyEnabled);

/// <summary>What a credential authorization must cover.</summary>
/// <param name="Credential">The credential to authorize.</param>
/// <param name="Hashes">The hashes about to be signed (needed for SCAL 2 and OAuth authorization).</param>
/// <param name="HashAlgorithmOid">The OID of the hash algorithm.</param>
/// <param name="NumSignatures">How many signatures the authorization should allow.</param>
public sealed record CscAuthorizationRequest(
    CscCredential Credential,
    IReadOnlyList<byte[]> Hashes,
    string HashAlgorithmOid,
    int NumSignatures);

/// <summary>An authorization to use a credential: a SAD, or a credential-scoped OAuth token.</summary>
/// <param name="Sad">The Signature Activation Data from <c>credentials/authorize</c>, or <see langword="null"/>.</param>
/// <param name="CredentialToken">The OAuth token with scope <c>credential</c>, or <see langword="null"/>.</param>
/// <param name="ExpiresAt">When the authorization expires, when known.</param>
/// <param name="RemainingSignatures">How many signatures it still allows.</param>
/// <param name="IsHashBound">Whether it only covers the hashes it was requested for.</param>
public sealed record CscCredentialAuthorization(
    string? Sad,
    OAuthToken? CredentialToken,
    DateTimeOffset? ExpiresAt,
    int RemainingSignatures,
    bool IsHashBound)
{
    /// <summary>Hides the SAD and token so they never end up in logs.</summary>
    public override string ToString() =>
        $"CscCredentialAuthorization {{ Sad = {(Sad is null ? "-" : "***")}, CredentialToken = {(CredentialToken is null ? "-" : "***")}, RemainingSignatures = {RemainingSignatures}, IsHashBound = {IsHashBound} }}";
}

/// <summary>Obtains the authorization to sign with a CSC credential (PIN/OTP, OAuth, ...).</summary>
public interface ICscCredentialAuthorizer
{
    /// <summary>Authorizes the credential for the request.</summary>
    /// <param name="client">The CSC client.</param>
    /// <param name="request">The credential, hashes and number of signatures.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    ValueTask<CscCredentialAuthorization> AuthorizeAsync(CscClient client, CscAuthorizationRequest request, CancellationToken cancellationToken);
}
