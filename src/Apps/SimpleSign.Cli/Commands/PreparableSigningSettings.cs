using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Validation;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The options that turn <c>sign</c>, <c>cades sign</c> and <c>xades sign</c> into the first phase of a
/// two-phase signature: with <c>--prepare</c> the command takes every option it takes when signing, but
/// writes the session and the data to sign instead of a signature. <c>deferred complete</c> finishes it.
/// </summary>
internal abstract class PreparableSigningSettings : ExternalCredentialSettings
{
    /// <summary>Prepare a two-phase signature instead of signing.</summary>
    [CommandOption("--prepare")]
    [Description("Two-phase signing: do not sign; write the session and the data to sign for a key that is elsewhere. --cert is then the signer's certificate (DER or PEM, no private key; more certificates in the file are its chain). Finish with 'simplesign deferred complete'.")]
    public bool Prepare { get; init; }

    /// <summary>HMAC key of the session. Requires --prepare.</summary>
    [CommandOption("--session-key <KEY>")]
    [Description(DeferredSessionKey.Description + ". Requires --prepare.")]
    public string? SessionKey { get; init; }

    /// <summary>Where the session goes (default: input.session). Requires --prepare.</summary>
    [CommandOption("--session <PATH>")]
    [Description("Where the session goes (default: <input>.session). Requires --prepare.")]
    public string? SessionPath { get; init; }

    /// <summary>Where the data to sign goes (default: input.tbs). Requires --prepare.</summary>
    [CommandOption("--to-sign <PATH>")]
    [Description("Where the data to sign goes (default: <input>.tbs): the signer hashes it and signs it. Requires --prepare.")]
    public string? ToSignPath { get; init; }

    /// <summary>The error of the two-phase options against the credential ones, or null.</summary>
    /// <param name="certPath">The value of --cert.</param>
    /// <param name="otherCredential">Whether a store certificate, a token or a cloud credential was asked for.</param>
    /// <param name="password">The value of --password.</param>
    /// <param name="outputPath">The value of --output.</param>
    internal string? ValidatePrepare(string? certPath, bool otherCredential, string? password, string? outputPath)
    {
        if (!Prepare)
        {
            return (SessionKey ?? SessionPath ?? ToSignPath) is null ? null : "--session-key, --session and --to-sign require --prepare.";
        }

        if (string.IsNullOrWhiteSpace(certPath))
        {
            return "--prepare requires --cert: the signer's certificate (DER or PEM, no private key).";
        }

        if (otherCredential || ExternalCredentialSupport.IsRequested(this))
        {
            return "--prepare signs nothing: it cannot be combined with --thumbprint, --pkcs11-lib, --psc-url or --csc-url.";
        }

        if (password is not null)
        {
            return "--password is not used with --prepare: --cert is a certificate without its private key.";
        }

        return outputPath is not null
            ? "--output is written by 'deferred complete'; --prepare writes --session and --to-sign."
            : DeferredSessionKey.Validate(SessionKey);
    }
}

/// <summary>What the commands that prepare a two-phase signature share: reading the signer's certificate and writing the result.</summary>
internal static class DeferredPrepareSupport
{
    /// <summary>The signer's certificate and its chain, from a DER or PEM file (the first certificate is the signer's).</summary>
    internal static (X509Certificate2 Certificate, List<X509Certificate2> Chain) LoadCertificates(
        ICertificateChainService service, string certPath, string? chainPath = null)
    {
        List<X509Certificate2> certificates = [.. service.LoadCertsFromBytes(File.ReadAllBytes(certPath))];
        if (certificates.Count == 0)
        {
            throw new InvalidDataException($"No certificate in {certPath}. With --prepare, --cert is the signer's certificate in DER or PEM.");
        }

        if (chainPath is not null)
        {
            certificates.AddRange(service.LoadCertsFromBytes(File.ReadAllBytes(chainPath)));
        }

        return (certificates[0], certificates[1..]);
    }

    /// <summary>Writes the session and the data to sign beside the input (or where the options say) and reports them.</summary>
    internal static async Task<int> WriteAsync(
        PreparableSigningSettings settings, string inputPath, string format, byte[] sessionData, byte[] dataToSign,
        string digestAlgorithm, string signatureAlgorithmOid, bool json, CancellationToken cancellationToken)
    {
        string sessionPath = settings.SessionPath ?? inputPath + ".session";
        string toSignPath = settings.ToSignPath ?? inputPath + ".tbs";
        await File.WriteAllBytesAsync(sessionPath, sessionData, cancellationToken);
        await File.WriteAllBytesAsync(toSignPath, dataToSign, cancellationToken);
        Report(inputPath, format, sessionPath, toSignPath, dataToSign.Length, digestAlgorithm, signatureAlgorithmOid, json);
        return 0;
    }

    /// <summary>Prints what was prepared, as text or as one JSON object.</summary>
    internal static void Report(
        string inputPath, string format, string sessionPath, string toSignPath, int toSignLength,
        string digestAlgorithm, string signatureAlgorithmOid, bool json)
    {
        if (json)
        {
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                writer.WriteBoolean("success", true);
                writer.WriteString("format", format);
                writer.WriteString("session", sessionPath);
                writer.WriteString("toSign", toSignPath);
                writer.WriteString("digestAlgorithm", digestAlgorithm);
                writer.WriteString("signatureAlgorithm", signatureAlgorithmOid);
                writer.WriteEndObject();
            }

            Console.Out.WriteLine(System.Text.Encoding.UTF8.GetString(buffer.ToArray()));
            return;
        }

        AnsiConsole.MarkupLine($"[green]✓ Prepared:[/] {inputPath.EscapeMarkup()}");
        AnsiConsole.MarkupLine($"  Session:   {sessionPath.EscapeMarkup()}");
        AnsiConsole.MarkupLine($"  To sign:   {toSignPath.EscapeMarkup()} ({toSignLength} bytes)");
        AnsiConsole.MarkupLine($"  Sign it with {digestAlgorithm.EscapeMarkup()} and {signatureAlgorithmOid.EscapeMarkup()} (the signer hashes the data), then run 'simplesign deferred complete'.");
    }
}
