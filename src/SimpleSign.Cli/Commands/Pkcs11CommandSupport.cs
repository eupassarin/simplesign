using SimpleSign.Signers.Pkcs11;
using Spectre.Console;

namespace SimpleSign.Cli.Commands;

/// <summary>Shared handling of the <c>--pkcs11-*</c> options of the signing commands.</summary>
internal static class Pkcs11CommandSupport
{
    /// <summary>Validates that the PKCS#11 options are consistent with the other credential options.</summary>
    /// <returns>An error message, or <see langword="null"/> when the options are valid.</returns>
    internal static string? Validate(string? library, string? token, string? key, string? pin, bool hasOtherCredential)
    {
        bool hasLibrary = !string.IsNullOrWhiteSpace(library);
        if (hasLibrary && hasOtherCredential)
        {
            return "--pkcs11-lib cannot be combined with --cert or --thumbprint.";
        }

        if (!hasLibrary && (token is not null || key is not null || pin is not null))
        {
            return "--pkcs11-token, --pkcs11-key and --pin require --pkcs11-lib.";
        }

        return null;
    }

    /// <summary>Opens the token selected by the options, prompting for the PIN when it is not given.</summary>
    internal static async Task<Pkcs11Signer> OpenAsync(string library, string? token, string? key, string? pin)
    {
        string? resolvedPin = await PasswordResolver.ResolvePinAsync(pin);
        var signer = Pkcs11Signer.Open(new Pkcs11SignerOptions
        {
            LibraryPath = library,
            TokenLabel = token,
            KeyLabel = key,
            Pin = resolvedPin,
        });
        AnsiConsole.MarkupLine(
            $"[dim]Token:[/] {signer.TokenLabel.EscapeMarkup()} [dim]·[/] {signer.Certificate.Subject.EscapeMarkup()}");
        return signer;
    }
}
