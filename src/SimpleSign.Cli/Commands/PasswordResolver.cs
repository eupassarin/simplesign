using Spectre.Console;

namespace SimpleSign.Cli.Commands;

internal static class PasswordResolver
{
    /// <summary>
    /// Resolves the certificate password from the following sources in order:
    /// 1. --password (command-line value)
    /// 2. Interactive prompt (when running in an interactive terminal)
    /// </summary>
    public static Task<string?> ResolveAsync(string? password, bool isInteractive = true)
    {
        if (password is not null)
        {
            return Task.FromResult<string?>(password);
        }

        if (isInteractive && AnsiConsole.Profile.Capabilities.Interactive)
        {
            return Task.FromResult<string?>(AnsiConsole.Prompt(
                new TextPrompt<string>("Certificate [blue]password[/] (leave blank if none):")
                    .AllowEmpty()
                    .Secret()));
        }

        return Task.FromResult<string?>(null);
    }
}
