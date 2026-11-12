using SimpleSign.Core.Policies;
using SimpleSign.Peru.Iofe;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The policies the CLI knows by name: <c>--signing-policy</c>, <c>--policy</c> and <c>policy export --preset</c>
/// accept a name where they accept a file.
/// </summary>
internal static class PolicyPresets
{
    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);

    /// <summary>The signing policies by name.</summary>
    internal static IReadOnlyDictionary<string, Func<SigningPolicy>> Signing { get; } =
        new Dictionary<string, Func<SigningPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["default"] = () => SigningPolicy.Default,
            ["strict"] = () => SigningPolicy.Default
                .WithName("SimpleSign default + revocation")
                .With("SigningCertificate/NotRevoked", Fail).With("SigningCertificate/RevocationDataAvailable", Fail)
                .With("CACertificate/NotRevoked", Fail).With("CACertificate/RevocationDataAvailable", Fail),
            ["minimal"] = () => SigningPolicy.Default
                .WithName("Signing certificate dates only")
                .With("SigningCertificate/KeyUsage", new PolicyConstraint(ConstraintLevel.Ignore))
                .With("CACertificate/NotExpired", new PolicyConstraint(ConstraintLevel.Ignore))
                .With("Cryptographic", new PolicyConstraint(ConstraintLevel.Ignore)),
            ["iofe"] = () => IofePolicies.Signing,
        };

    /// <summary>The validation policies by name.</summary>
    internal static IReadOnlyDictionary<string, Func<ValidationPolicy>> Validation { get; } =
        new Dictionary<string, Func<ValidationPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["default"] = () => ValidationPolicy.Default,
            ["strict"] = () => ValidationPolicy.Default
                .WithName("SimpleSign default, strict")
                .With("Timestamp/Coherence", Fail).With("SignatureConstraints/PolicyAvailable", Fail),
            ["iofe"] = () => IofePolicies.Validation,
            ["iofe-nonrepudiation"] = () => IofePolicies.ValidationNonRepudiation,
        };

    /// <summary>The names, for messages.</summary>
    internal static string Names<T>(IReadOnlyDictionary<string, T> presets) => string.Join(", ", presets.Keys);

    /// <summary>Whether <paramref name="value"/> is a preset name rather than a file (a file of that name wins).</summary>
    internal static bool IsPreset<T>(IReadOnlyDictionary<string, T> presets, string value) =>
        presets.ContainsKey(value) && !File.Exists(value);
}
