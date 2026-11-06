namespace SimpleSign.Signers.Cloud;

/// <summary>An OAuth 2.0 access token issued by a cloud signing service.</summary>
/// <param name="AccessToken">The bearer token. Treat it as a secret: never log it.</param>
/// <param name="ExpiresAt">When the token expires, or <see langword="null"/> when the service did not say.</param>
/// <param name="Scope">The granted scope, when the service returned it.</param>
public sealed record OAuthToken(string AccessToken, DateTimeOffset? ExpiresAt, string? Scope)
{
    /// <summary>
    /// The identification of the authorized holder (CPF/CNPJ) returned by ICP-Brasil PSCs
    /// (<c>authorized_identification</c>), or <see langword="null"/>.
    /// </summary>
    public string? AuthorizedIdentification { get; init; }

    /// <summary>Whether the token has expired (with a 30-second safety margin).</summary>
    /// <param name="timeProvider">Clock to use; defaults to the system clock.</param>
    public bool IsExpired(TimeProvider? timeProvider = null) =>
        ExpiresAt is { } expiresAt && (timeProvider ?? TimeProvider.System).GetUtcNow() >= expiresAt.AddSeconds(-30);

    /// <summary>Hides <see cref="AccessToken"/> so the token never ends up in logs.</summary>
    public override string ToString() =>
        $"OAuthToken {{ AccessToken = ***, ExpiresAt = {ExpiresAt?.ToString("O", System.Globalization.CultureInfo.InvariantCulture) ?? "-"}, Scope = {Scope ?? "-"} }}";
}
