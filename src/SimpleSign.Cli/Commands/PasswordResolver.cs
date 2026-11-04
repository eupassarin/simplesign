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

    /// <summary>
    /// Resolves a token PIN: the <c>--pin</c> value, else an interactive prompt. A blank answer
    /// (or a non-interactive terminal) returns <see langword="null"/>, which lets readers with a
    /// PIN pad ask for the PIN on the device.
    /// </summary>
    public static Task<string?> ResolvePinAsync(string? pin, bool isInteractive = true)
    {
        if (pin is not null)
        {
            return Task.FromResult<string?>(pin);
        }

        if (isInteractive && AnsiConsole.Profile.Capabilities.Interactive)
        {
            string answer = AnsiConsole.Prompt(
                new TextPrompt<string>("Token [blue]PIN[/] (leave blank to use the reader's PIN pad):")
                    .AllowEmpty()
                    .Secret());
            return Task.FromResult<string?>(answer.Length == 0 ? null : answer);
        }

        return Task.FromResult<string?>(null);
    }
}
