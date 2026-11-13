using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Signs every PDF of a directory with one certificate (BatchSigner), several at a time.</summary>
[Description("Sign every PDF of a directory with one certificate, several at a time")]
internal sealed class SignDirCommand(ICertificateChainService certChainService) : AsyncCommand<SignDirCommand.Settings>
{
    /// <summary>Settings of <c>sign-dir</c>.</summary>
    internal sealed class Settings : ExternalCredentialSettings
    {
        /// <summary>Checks run before signing.</summary>
        [CommandOption("--signing-policy <PATH>")]
        [Description(SigningPolicyOption.Description)]
        public string? SigningPolicy { get; init; }

        /// <summary>Directory of PDFs to sign.</summary>
        [CommandArgument(0, "<directory>")]
        [Description("Directory of PDFs to sign")]
        public string Directory { get; init; } = null!;

        /// <summary>Where the signed PDFs go (default: directory/signed).</summary>
        [CommandOption("--output-dir|-o <DIR>")]
        [Description("Where the signed PDFs go, with the same names (default: <directory>/signed)")]
        public string? OutputDirectory { get; init; }

        /// <summary>Include subdirectories.</summary>
        [CommandOption("--recursive|-r")]
        [Description("Include subdirectories (their structure is kept in the output)")]
        public bool Recursive { get; init; }

        /// <summary>How many documents are signed at the same time.</summary>
        [CommandOption("--max-concurrency <N>")]
        [Description("How many documents are signed at the same time (default: the processor count)")]
        public int? MaxConcurrency { get; init; }

        /// <summary>PKCS#12 certificate file.</summary>
        [CommandOption("--cert|-c <PATH>")]
        [Description("PKCS#12 certificate file (.pfx/.p12)")]
        public string? CertPath { get; init; }

        /// <summary>Certificate password.</summary>
        [CommandOption("--password|-p <PASSWORD>")]
        [Description("Certificate password (omit for interactive prompt)")]
        public string? Password { get; init; }

        /// <summary>TSA URL.</summary>
        [CommandOption("--tsa|-t <URL>")]
        [Description("TSA URL for the signature timestamps (B-T or higher)")]
        public string? TsaUrl { get; init; }

        /// <summary>B-LT.</summary>
        [CommandOption("--ltv")]
        [Description("PAdES B-LT: embed the revocation data (requires --tsa)")]
        public bool Ltv { get; init; }

        /// <summary>B-LTA.</summary>
        [CommandOption("--archival")]
        [Description("PAdES B-LTA: B-LT plus a document timestamp (requires --tsa)")]
        public bool Archival { get; init; }

        /// <summary>A separate archive TSA.</summary>
        [CommandOption("--archive-tsa <URL>")]
        [Description("A separate TSA for the archive timestamps. Requires --archival.")]
        public string? ArchiveTsaUrl { get; init; }

        /// <summary>Return the highest level reached instead of failing.</summary>
        [CommandOption("--return-lower-level")]
        [Description("Return the highest level reached instead of failing when a timestamp or revocation data is missing")]
        public bool ReturnLowerLevel { get; init; }

        /// <summary>Revocation source tried first.</summary>
        [CommandOption("--revocation-preference <SOURCE>")]
        [Description("Revocation source tried first for B-LT and B-LTA: ocsp (default) or crl")]
        public string? RevocationPreference { get; init; }

        /// <summary>Hash algorithm.</summary>
        [CommandOption("--hash <ALGORITHM>")]
        [Description("Hash algorithm: SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-384 or SHA3-512")]
        public string? Hash { get; init; }

        /// <summary>RSA scheme.</summary>
        [CommandOption("--signature-algorithm <ALGO>")]
        [Description("RSA signature scheme: rsa-pkcs1 (default) or rsassa-pss")]
        public string? SignatureAlgorithm { get; init; }

        /// <summary>Signature field name.</summary>
        [CommandOption("--field-name <NAME>")]
        [Description("Name of the new signature field in every document (default Signature1)")]
        public string? FieldName { get; init; }

        /// <summary>Declared signer name.</summary>
        [CommandOption("--signer-name <NAME>")]
        [Description("Signer name in the signature dictionary")]
        public string? SignerName { get; init; }

        /// <summary>Reason.</summary>
        [CommandOption("--reason <TEXT>")]
        [Description("Reason for signing")]
        public string? Reason { get; init; }

        /// <summary>Location.</summary>
        [CommandOption("--location <TEXT>")]
        [Description("Signing location")]
        public string? Location { get; init; }

        /// <summary>Contact information.</summary>
        [CommandOption("--contact <TEXT>")]
        [Description("Signer contact information")]
        public string? Contact { get; init; }

        /// <summary>Bytes reserved for the CMS.</summary>
        [CommandOption("--contents-size <BYTES>")]
        [Description("Bytes reserved for the signature in /Contents (default 16384)")]
        public int? ContentsSize { get; init; }

        /// <summary>Correlation id for the logs.</summary>
        [CommandOption("--operation-id <ID>")]
        [Description("Correlation id written in the logs of every document")]
        public string? OperationId { get; init; }

        internal PadesProfileOptions.Level LevelOptions => new(TsaUrl, Ltv, Archival, ArchiveTsaUrl, ReturnLowerLevel, RevocationPreference);

        public override ValidationResult Validate()
        {
            if (!System.IO.Directory.Exists(Directory))
            {
                return ValidationResult.Error($"Directory not found: {Directory}");
            }

            if (ExternalCredentialSupport.Validate(this, CertPath is not null) is { } externalError)
            {
                return ValidationResult.Error(externalError);
            }

            if (CertPath is null && !ExternalCredentialSupport.IsRequested(this))
            {
                return ValidationResult.Error("Either --cert, --pkcs11-lib, --psc-url or --csc-url is required.");
            }

            if (CertPath is not null && !File.Exists(CertPath))
            {
                return ValidationResult.Error($"Certificate not found: {CertPath}");
            }

            if (MaxConcurrency is < 1 or > 256)
            {
                return ValidationResult.Error("--max-concurrency must be between 1 and 256.");
            }

            string? error = PadesProfileOptions.Validate(LevelOptions)
                ?? PadesProfileOptions.ValidateCrypto(Hash, SignatureAlgorithm, ContentsSize)
                ?? ValidateTsaCredentials(TsaUrl)
                ?? (SigningPolicyOption.IsValid(SigningPolicy) ? null : SigningPolicyOption.Error(SigningPolicy));
            return error is null ? ValidationResult.Success() : ValidationResult.Error(error);
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        string root = Path.GetFullPath(settings.Directory);
        string output = Path.GetFullPath(settings.OutputDirectory ?? Path.Combine(root, "signed"));
        var files = System.IO.Directory.EnumerateFiles(root, "*.pdf", settings.Recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Where(f => !Path.GetFullPath(f).StartsWith(output + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToList();
        if (files.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No PDF in {root.EscapeMarkup()}.[/]");
            return 0;
        }

        using ExternalCredential? token = await ExternalCredentialSupport.OpenAsync(settings, cancellationToken);
        X509Certificate2Collection? pfx = token is null
            ? certChainService.LoadPkcs12CollectionFromFile(settings.CertPath!, await PasswordResolver.ResolveAsync(settings.Password))
            : null;
        try
        {
            var signer = token?.Certificate ?? pfx!.OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey)
                ?? throw new InvalidOperationException("No certificate with a private key was found in the PFX file.");
            IReadOnlyList<X509Certificate2> chain = token?.Chain
                ?? [.. pfx!.OfType<X509Certificate2>().Where(c => c.Thumbprint != signer.Thumbprint)];
            var builder = BatchSigner.Create(signer)
                .WithChain(chain)
                .WithHashAlgorithm(SignCommandOptions.ParseHash(settings.Hash ?? "SHA256"))
                .WithFieldOptions(PadesProfileOptions.Field(
                    settings.FieldName, settings.SignerName, settings.Reason, settings.Location, settings.Contact, settings.ContentsSize))
                .WithLevel(PadesProfileOptions.Build(settings.LevelOptions, settings));
            if (token is not null)
            {
                builder = builder.WithExternalSigner(token.Signer);
            }

            if (settings.SignatureAlgorithm is not null && SignCommandOptions.ParseSignatureAlgorithm(settings.SignatureAlgorithm) is { } oid)
            {
                builder = builder.WithSignatureAlgorithm(oid);
            }

            if (settings.MaxConcurrency is { } concurrency)
            {
                builder = builder.WithMaxConcurrency(concurrency);
            }

            if (settings.OperationId is not null)
            {
                builder = builder.WithOperationId(settings.OperationId);
            }

            builder = builder.WithSigningPolicy(await settings.SigningPolicyAsync(settings.SigningPolicy, cancellationToken)).WithTrustAnchors(await settings.SigningTrustAnchorsAsync(cancellationToken));
            if (settings.AuditSink() is { } audit)
            {
                builder = builder.WithAuditSink(audit);
            }
            if (CliNetwork.IsConfigured)
            {
                builder = builder.WithHttpClientProvider(CliNetwork.Provider);
            }

            await using var batch = builder.Build();
            int failures = 0;
            await foreach (var result in batch.SignAllAsync(ReadAsync(files, cancellationToken), cancellationToken))
            {
                string relative = Path.GetRelativePath(root, result.Id);
                if (result.IsSuccess)
                {
                    string target = Path.Combine(output, relative);
                    System.IO.Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    await File.WriteAllBytesAsync(target, result.SignedPdf!, cancellationToken);
                    AnsiConsole.MarkupLine($"[green]✓[/] {relative.EscapeMarkup()}");
                }
                else
                {
                    failures++;
                    AnsiConsole.MarkupLine($"[red]✗[/] {relative.EscapeMarkup()}: {result.Error!.Message.EscapeMarkup()}");
                }
            }

            AnsiConsole.MarkupLine($"Signed {files.Count - failures} of {files.Count} into {output.EscapeMarkup()}.");
            return failures == 0 ? 0 : 1;
        }
        finally
        {
            if (pfx is not null)
            {
                foreach (var certificate in pfx)
                {
                    certificate.Dispose();
                }
            }
        }
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> ReadAsync(
        IEnumerable<string> files, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (string file in files)
        {
            yield return (file, await File.ReadAllBytesAsync(file, cancellationToken));
        }
    }
}
