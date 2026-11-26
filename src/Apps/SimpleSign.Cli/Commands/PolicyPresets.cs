using SimpleSign.Cli.Extensibility;
using SimpleSign.Cli.Extensions;
using SimpleSign.Core.Policies;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The policies the CLI knows by name: <c>--signing-policy</c>, <c>--policy</c> and <c>policy export --preset</c>
/// accept a name where they accept a file. The CLI's own, plus those of the installed extensions
/// (<see cref="ICliExtension.SigningPolicies"/>, <see cref="ICliExtension.ValidationPolicies"/>).
/// </summary>
internal static class PolicyPresets
{
    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);

    /// <summary>The signing policies by name.</summary>
    private static readonly Dictionary<string, Func<SigningPolicy>> s_builtInSigning =
        new(StringComparer.OrdinalIgnoreCase)
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
                .With("Cryptographic", new PolicyConstraint(ConstraintLevel.Ignore))
                .With("Timestamp/NotExpired", new PolicyConstraint(ConstraintLevel.Ignore))
                .With("Timestamp/NotRevoked", new PolicyConstraint(ConstraintLevel.Ignore))
                .With("Timestamp/RevocationDataAvailable", new PolicyConstraint(ConstraintLevel.Ignore)),
        };

    /// <summary>The validation policies by name.</summary>
    private static readonly Dictionary<string, Func<ValidationPolicy>> s_builtInValidation =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["default"] = () => ValidationPolicy.Default,
            ["strict"] = () => ValidationPolicy.Default
                .WithName("SimpleSign default, strict")
                .With("Timestamp/Coherence", Fail).With("SignatureConstraints/PolicyAvailable", Fail),
        };

    /// <summary>The signing policies, by name.</summary>
    internal static IReadOnlyDictionary<string, Func<SigningPolicy>> Signing { get; private set; } = s_builtInSigning;

    /// <summary>The validation policies, by name.</summary>
    internal static IReadOnlyDictionary<string, Func<ValidationPolicy>> Validation { get; private set; } = s_builtInValidation;

    /// <summary>Sets the policies to the CLI's own plus those of <paramref name="extensions"/>; a name the CLI already has is not replaced.</summary>
    internal static void Use(IReadOnlyList<ICliExtension> extensions)
    {
        Signing = With(s_builtInSigning, extensions.SelectMany(e => e.SigningPolicies));
        Validation = With(s_builtInValidation, extensions.SelectMany(e => e.ValidationPolicies));
    }

    private static Dictionary<string, T> With<T>(Dictionary<string, T> builtIn, IEnumerable<KeyValuePair<string, T>> added)
    {
        var all = new Dictionary<string, T>(builtIn, StringComparer.OrdinalIgnoreCase);
        foreach (var (name, policy) in added)
        {
            all.TryAdd(name, policy);
        }

        return all;
    }

    /// <summary>
    /// What to tell the user who gave <paramref name="name"/> where a policy name or file was expected and it is
    /// neither: the command that installs the extension the policy comes with, when it is a known one; null otherwise.
    /// </summary>
    internal static string? InstallHint(string? name) =>
        name is not null && KnownExtensions.PackageOfPolicy(name) is { } package
            ? $"The policy '{name}' comes with an extension: 'simplesign extension install {package}'."
            : null;

    /// <summary>The names, for messages.</summary>
    internal static string Names<T>(IReadOnlyDictionary<string, T> presets) => string.Join(", ", presets.Keys);

    /// <summary>Whether <paramref name="value"/> is a preset name rather than a file (a file of that name wins).</summary>
    internal static bool IsPreset<T>(IReadOnlyDictionary<string, T> presets, string value) =>
        presets.ContainsKey(value) && !File.Exists(value);
}
