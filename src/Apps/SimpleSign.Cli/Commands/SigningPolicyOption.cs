using SimpleSign.Core.Signing;

namespace SimpleSign.Cli.Commands;

/// <summary>The <c>--signing-policy</c> option of the sign commands.</summary>
internal static class SigningPolicyOption
{
    /// <summary>The option's description.</summary>
    internal const string Description =
        "Checks before signing: default (chain validity, key usage, RSA >= 2048, SHA-2/SHA-3), " +
        "strict (default plus the revocation of the whole chain; needs the chain up to the root) " +
        "or minimal (only the signing certificate's dates)";

    /// <summary>The policy named by the option.</summary>
    internal static SigningPolicy Parse(string? name) => name?.ToLowerInvariant() switch
    {
        null or "" or "default" => SigningPolicy.Default,
        "strict" => SigningPolicy.Strict,
        "minimal" => SigningPolicy.Minimal,
        _ => throw new ArgumentException($"Unknown signing policy '{name}': use default, strict or minimal."),
    };

    /// <summary>Whether the name is a known policy.</summary>
    internal static bool IsValid(string? name) =>
        name is null || name.ToLowerInvariant() is "default" or "strict" or "minimal";
}
