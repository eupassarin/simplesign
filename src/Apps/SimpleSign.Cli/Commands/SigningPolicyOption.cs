using SimpleSign.Core.Policies;

namespace SimpleSign.Cli.Commands;

/// <summary>The <c>--signing-policy</c> option of the sign commands.</summary>
internal static class SigningPolicyOption
{
    /// <summary>The option's description.</summary>
    internal const string Description =
        "Signing policy (JSON, root SigningConstraints): the checks made before signing. Default: chain validity, " +
        "key usage, RSA >= 2048, SHA-2/SHA-3. Write the default with 'simplesign policy export signing'";

    /// <summary>The policy in the file, or the default policy when no file is given.</summary>
    internal static SigningPolicy Parse(string? path) =>
        string.IsNullOrWhiteSpace(path) ? SigningPolicy.Default : SigningPolicy.Load(path);

    /// <summary>Whether the option names an existing file (or is absent).</summary>
    internal static bool IsValid(string? path) => path is null || File.Exists(path);

    /// <summary>The error when <see cref="IsValid"/> is false.</summary>
    internal static string Error(string? path) =>
        $"--signing-policy '{path}' is not a file: give a JSON signing policy (write the default one with 'simplesign policy export signing').";
}
