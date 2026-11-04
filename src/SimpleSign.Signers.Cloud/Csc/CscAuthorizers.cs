namespace SimpleSign.Signers.Cloud.Csc;

/// <summary>
/// Authorizes a credential with a PIN and/or OTP (<c>credentials/authorize</c>, auth mode
/// <c>explicit</c>). For SCAL 1 credentials one SAD may cover several signatures.
/// </summary>
/// <remarks>The PIN and OTP are sent only to the CSC service and are never logged.</remarks>
public sealed class ExplicitCscAuthorizer : ICscCredentialAuthorizer
{
    private readonly string? _pin;
    private readonly string? _otp;
    private readonly int _signaturesPerAuthorization;

    /// <summary>Creates an authorizer.</summary>
    /// <param name="pin">The credential PIN, or <see langword="null"/>.</param>
    /// <param name="otp">A one-time password, or <see langword="null"/>. OTPs usually allow one authorization.</param>
    /// <param name="signaturesPerAuthorization">
    /// For SCAL 1 credentials: how many signatures to request per SAD (capped by the credential's
    /// <c>multisign</c>). Default 1.
    /// </param>
    public ExplicitCscAuthorizer(string? pin, string? otp = null, int signaturesPerAuthorization = 1)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(signaturesPerAuthorization, 1);
        _pin = pin;
        _otp = otp;
        _signaturesPerAuthorization = signaturesPerAuthorization;
    }

    /// <inheritdoc />
    public async ValueTask<CscCredentialAuthorization> AuthorizeAsync(
        CscClient client, CscAuthorizationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(request);
        bool hashBound = request.Credential.Scal == "2";
        int count = hashBound
            ? request.Hashes.Count
            : Math.Max(request.NumSignatures, Math.Min(_signaturesPerAuthorization, request.Credential.MultiSign));
        return await client.AuthorizeCredentialAsync(
            request.Credential.Id,
            count,
            hashBound ? request.Hashes : null,
            hashBound ? request.HashAlgorithmOid : null,
            _pin,
            _otp,
            cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Authorizes a credential through OAuth 2.0 (scope <c>credential</c>, auth mode
/// <c>oauth2code</c>): the user approves the exact hashes on the provider's page.
/// </summary>
public sealed class OAuthCscAuthorizer : ICscCredentialAuthorizer
{
    private readonly IAuthorizationCodeHandler _handler;

    /// <summary>Creates an authorizer.</summary>
    /// <param name="handler">Shows the authorization page (e.g. <see cref="LoopbackAuthorizationHandler"/>).</param>
    public OAuthCscAuthorizer(IAuthorizationCodeHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _handler = handler;
    }

    /// <inheritdoc />
    public async ValueTask<CscCredentialAuthorization> AuthorizeAsync(
        CscClient client, CscAuthorizationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(request);
        var pkce = OAuthPkce.Create();
        var uri = client.BuildCredentialAuthorizationUri(pkce, request.Credential.Id, request.Hashes, request.HashAlgorithmOid);
        var redirect = await _handler.AuthorizeAsync(uri, client.Options.RedirectUri, cancellationToken).ConfigureAwait(false);
        var token = await client.ExchangeCodeAsync(redirect, pkce, cancellationToken).ConfigureAwait(false);
        return new CscCredentialAuthorization(null, token, token.ExpiresAt, request.Hashes.Count, IsHashBound: true);
    }
}
