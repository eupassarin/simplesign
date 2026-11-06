using System.Security.Cryptography;
using System.Text;

namespace SimpleSign.Signers.Cloud;

/// <summary>
/// A PKCE pair (RFC 7636) with the S256 method, plus a random <c>state</c> value for one
/// OAuth 2.0 authorization request. Create a new instance for every authorization.
/// </summary>
public sealed class OAuthPkce
{
    private OAuthPkce(string verifier, string state)
    {
        Verifier = verifier;
        Challenge = ComputeChallenge(verifier);
        State = state;
    }

    /// <summary>The code verifier (43 characters, base64url of 32 random bytes). Keep it secret.</summary>
    public string Verifier { get; }

    /// <summary>The code challenge: base64url(SHA-256(<see cref="Verifier"/>)).</summary>
    public string Challenge { get; }

    /// <summary>The challenge method, always <c>S256</c>.</summary>
    public const string Method = "S256";

    /// <summary>A random value that the redirect must echo back, to prevent CSRF.</summary>
    public string State { get; }

    /// <summary>Creates a new random PKCE pair and state.</summary>
    public static OAuthPkce Create() =>
        new(Base64Url(RandomNumberGenerator.GetBytes(32)), Base64Url(RandomNumberGenerator.GetBytes(16)));

    internal static string ComputeChallenge(string verifier) =>
        Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    internal static string Base64Url(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
