namespace SimpleSign.Cli.Extensions;

/// <summary>
/// The extensions published with SimpleSign, by what each adds: a name the CLI does not have then gets the command
/// that installs it, instead of a plain "unknown".
/// </summary>
internal static class KnownExtensions
{
    private const string Brazil = "SimpleSign.Brazil.Cli";
    private const string Eidas = "SimpleSign.Europe.Eidas.Cli";
    private const string Iofe = "SimpleSign.Peru.Iofe.Cli";

    /// <summary>The package that adds the profile <paramref name="name"/> (<c>--profile</c>); null when none is known.</summary>
    internal static string? PackageOfProfile(string name) => name.ToLowerInvariant() switch
    {
        "icp-brasil" or "gov-br" => Brazil,
        "eidas" => Eidas,
        "iofe" => Iofe,
        _ => null,
    };

    /// <summary>
    /// The command of an extension that takes the option <paramref name="option"/> (without its dashes), which a
    /// standard command does not: what to run instead, and the package it comes with; null when none is known.
    /// </summary>
    internal static (string Command, string Package)? CommandOfOption(string option) => option.ToLowerInvariant() switch
    {
        "icp-policy" or "brasil" or "aea" or "cpf" or "institution-cnpj" or "health-document" or "registration" => ("simplesign brasil sign", Brazil),
        "icp" => ("simplesign brasil timestamp verify", Brazil),
        _ => null,
    };

    /// <summary>
    /// The error for an option the command does not have, which Spectre.Console.Cli would otherwise drop in silence:
    /// a signature without the policy the user asked for, a time-stamp "valid" without the check asked for. Null when
    /// every option on the line is the command's.
    /// </summary>
    internal static string? UnknownOptionError(Spectre.Console.Cli.CommandContext context, string command)
    {
        string? option = context.Remaining.Parsed.Select(o => o.Key).FirstOrDefault();
        if (option is null)
        {
            return null;
        }

        // The option as it was typed, with or without its dashes (Spectre.Console.Cli keeps them).
        string bare = option.TrimStart('-');
        string name = (bare.Length == 1 ? "-" : "--") + bare;
        return CommandOfOption(bare) is { } known
            ? $"{name} is an option of '{known.Command}', which comes with an extension: 'simplesign extension install {known.Package}'."
            : $"Unknown option {name}: see 'simplesign {command} --help'.";
    }

    /// <summary>The package that adds the policy <paramref name="name"/> (<c>--policy</c>, <c>--signing-policy</c>, <c>--preset</c>); null when none is known.</summary>
    internal static string? PackageOfPolicy(string name) => name.ToLowerInvariant() switch
    {
        "icp-brasil" or "govbr" => Brazil,
        "eidas" => Eidas,
        "iofe" or "iofe-agent" => Iofe,
        _ => null,
    };
}
