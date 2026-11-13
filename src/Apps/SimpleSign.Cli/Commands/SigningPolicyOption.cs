using SimpleSign.Core.Policies;

namespace SimpleSign.Cli.Commands;

/// <summary>The <c>--signing-policy</c> option of the sign commands.</summary>
internal static class SigningPolicyOption
{
    /// <summary>The option's description.</summary>
    internal const string Description =
        "Signing policy: a JSON file (root SigningConstraints) or a built-in name (default, strict, minimal, iofe, icp-brasil): the checks made before " +
        "signing. Default: chain validity, key usage, RSA >= 2048, SHA-2/SHA-3. Write one with 'simplesign policy export signing [--preset NAME]'";

    /// <summary>The policy in the file or of the built-in name, or the default policy when none is given.</summary>
    internal static SigningPolicy Parse(string? path) =>
        string.IsNullOrWhiteSpace(path) ? SigningPolicy.Default
        : PolicyPresets.IsPreset(PolicyPresets.Signing, path) ? PolicyPresets.Signing[path]()
        : SigningPolicy.Load(path);

    /// <summary>Whether the option names an existing file or a built-in policy (or is absent).</summary>
    internal static bool IsValid(string? path) => path is null || File.Exists(path) || PolicyPresets.Signing.ContainsKey(path);

    /// <summary>The error when <see cref="IsValid"/> is false.</summary>
    internal static string Error(string? path) =>
        $"--signing-policy '{path}' is neither a file nor a built-in policy ({PolicyPresets.Names(PolicyPresets.Signing)}): " +
        "give a JSON signing policy (write one with 'simplesign policy export signing').";
}
