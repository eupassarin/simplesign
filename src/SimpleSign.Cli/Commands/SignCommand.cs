using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

[Description("Sign a PDF document")]
internal sealed class SignCommand : AsyncCommand<SignCommand.Settings>
{
    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<input>")]
        [Description("Input PDF file to sign")]
        public string InputPath { get; init; } = null!;

        [CommandOption("--cert|-c <PATH>")]
        [Description("PKCS#12 certificate file (.pfx/.p12)")]
        public string? CertPath { get; init; }

        [CommandOption("--password|-p <PASSWORD>")]
        [Description("Certificate password")]
        public string? Password { get; init; }

        [CommandOption("--output|-o <PATH>")]
        [Description("Output file (default: input_signed.pdf)")]
        public string? OutputPath { get; init; }

        [CommandOption("--tsa|-t <URL>")]
        [Description("TSA URL for RFC 3161 timestamping")]
        public string? TsaUrl { get; init; }

        [CommandOption("--reason <TEXT>")]
        [Description("Signing reason")]
        public string? Reason { get; init; }

        [CommandOption("--location <TEXT>")]
        [Description("Signing location")]
        public string? Location { get; init; }

        [CommandOption("--contact <TEXT>")]
        [Description("Contact information")]
        public string? Contact { get; init; }

        [CommandOption("--signer-name <NAME>")]
        [Description("Override signer name (default: certificate CN)")]
        public string? SignerName { get; init; }

        [CommandOption("--ltv")]
        [Description("Enable LTV — embed revocation data (requires --tsa)")]
        public bool Ltv { get; init; }

        [CommandOption("--archival")]
        [Description("Enable archival timestamp / B-LTA (implies --ltv)")]
        public bool Archival { get; init; }

        [CommandOption("--hash <ALGORITHM>")]
        [Description("Hash algorithm: SHA256 (default), SHA384, SHA512")]
        public string? Hash { get; init; }

        [CommandOption("--field-name <NAME>")]
        [Description("Custom signature field name (default: Signature1)")]
        public string? FieldName { get; init; }

        [CommandOption("--existing-field <NAME>")]
        [Description("Sign a pre-existing empty signature field")]
        public string? ExistingField { get; init; }

        [CommandOption("--certify <LEVEL>")]
        [Description("Create certification (DocMDP) signature: no-changes, form-filling (default), annotations")]
        public string? Certify { get; init; }

        [CommandOption("--legacy-cms")]
        [Description("Use adbe.pkcs7.detached without PAdES attributes (legacy compatibility)")]
        public bool LegacyCms { get; init; }

        [CommandOption("--pdfa")]
        [Description("Preserve PDF/A conformance")]
        public bool PdfA { get; init; }

        [CommandOption("--visible")]
        [Description("Add visible signature stamp (auto-positioned)")]
        public bool Visible { get; init; }

        [CommandOption("--page <NUMBER>")]
        [Description("Page for visible signature (default: 1)")]
        public int? Page { get; init; }

        [CommandOption("--pos-x <POINTS>")]
        [Description("X coordinate for visible signature in points")]
        public float? X { get; init; }

        [CommandOption("--pos-y <POINTS>")]
        [Description("Y coordinate for visible signature in points")]
        public float? Y { get; init; }

        [CommandOption("--background-image <PATH>")]
        [Description("Background image for visible signature (JPEG or PNG)")]
        public string? BackgroundImage { get; init; }

        [CommandOption("--qr-url <URL>")]
        [Description("Verification URL — renders QR code in visible signature")]
        public string? QrUrl { get; init; }

        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(CertPath))
            {
                return ValidationResult.Error("--cert is required.");
            }

            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (!string.IsNullOrWhiteSpace(CertPath) && !File.Exists(CertPath))
            {
                return ValidationResult.Error($"Certificate not found: {CertPath}");
            }

            if (Ltv && string.IsNullOrWhiteSpace(TsaUrl))
            {
                return ValidationResult.Error("--ltv requires --tsa. LTV without a timestamp is not valid for long-term archival.");
            }

            if (Hash is not null && !Hash.Equals("SHA256", StringComparison.OrdinalIgnoreCase)
                && !Hash.Equals("SHA384", StringComparison.OrdinalIgnoreCase)
                && !Hash.Equals("SHA512", StringComparison.OrdinalIgnoreCase))
            {
                return ValidationResult.Error("--hash must be SHA256, SHA384, or SHA512.");
            }

            if (Certify is not null
                && !Certify.Equals("no-changes", StringComparison.OrdinalIgnoreCase)
                && !Certify.Equals("form-filling", StringComparison.OrdinalIgnoreCase)
                && !Certify.Equals("annotations", StringComparison.OrdinalIgnoreCase))
            {
                return ValidationResult.Error("--certify must be no-changes, form-filling, or annotations.");
            }

            if (BackgroundImage is not null && !File.Exists(BackgroundImage))
            {
                return ValidationResult.Error($"Background image not found: {BackgroundImage}");
            }

            if ((Page.HasValue || X.HasValue || Y.HasValue) && !Visible)
            {
                return ValidationResult.Error("--page, --pos-x, --pos-y require --visible.");
            }

            return ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var loggerFactory = settings.CreateLoggerFactory();

        var outputPath = settings.OutputPath ?? Path.Combine(
            Path.GetDirectoryName(settings.InputPath) ?? ".",
            Path.GetFileNameWithoutExtension(settings.InputPath) + "_signed.pdf");

        return await ExecuteCertSigningAsync(settings, outputPath, loggerFactory, cancellationToken);
    }

    private static async Task<int> ExecuteCertSigningAsync(
        Settings settings, string outputPath, ILoggerFactory? loggerFactory, CancellationToken cancellation)
    {
        var password = await PasswordResolver.ResolveAsync(settings.Password);

        // Load all certs from the PFX so that intermediate CAs are available for LTV chain building
        var collection = CertificateLoader.LoadPkcs12CollectionFromFile(settings.CertPath!, password);
        var cert = collection.OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey)
            ?? throw new InvalidOperationException("No certificate with a private key was found in the PFX file.");
        var chainCerts = collection.OfType<X509Certificate2>()
            .Where(c => c.Thumbprint != cert.Thumbprint)
            .ToList();

        try
        {
            byte[] signed = null!;
            bool dssEmbedded = false;
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .SpinnerStyle(Style.Parse("blue"))
                .StartAsync("Signing...", async _ =>
                {
                    var pdfBytes = await File.ReadAllBytesAsync(settings.InputPath);
                    ILogger? logger = loggerFactory?.CreateLogger("SimpleSign.Signing");
                    var builder = chainCerts.Count > 0
                        ? SimpleSigner.Document(pdfBytes, logger).WithCertificate(cert, chainCerts)
                        : SimpleSigner.Document(pdfBytes, logger).WithCertificate(cert);

                    if (settings.TsaUrl is not null)
                    {
                        builder = builder.WithTimestamp(settings.TsaUrl);
                    }

                    if (settings.Hash is not null)
                    {
                        builder = builder.WithHashAlgorithm(ParseHash(settings.Hash));
                    }

                    if (settings.FieldName is not null)
                    {
                        builder = builder.WithFieldName(settings.FieldName);
                    }

                    if (settings.ExistingField is not null)
                    {
                        builder = builder.WithExistingField(settings.ExistingField);
                    }

                    if (settings.Certify is not null)
                    {
                        builder = builder.AsCertification(ParseCertificationLevel(settings.Certify));
                    }

                    // Metadata: reason, location, contact, signer name
                    if (settings.Reason is not null || settings.Location is not null
                        || settings.Contact is not null || settings.SignerName is not null)
                    {
                        builder = builder.WithMetadata(
                            signerName: settings.SignerName,
                            reason: settings.Reason,
                            location: settings.Location,
                            contactInfo: settings.Contact);
                    }

                    // Visual appearance
                    if (settings.Visible)
                    {
                        var appearance = BuildAppearance(settings);
                        builder = builder.WithAppearance(appearance);
                    }

                    if (settings.LegacyCms)
                    {
                        builder = builder.WithLegacyCms();
                    }

                    if (settings.PdfA)
                    {
                        builder = builder.WithPdfAPreservation();
                    }

                    if (settings.Ltv)
                    {
                        builder = builder.WithLtv();
                    }

                    if (settings.Archival)
                    {
                        builder = builder.WithArchivalTimestamp();
                    }

                    var result = await builder.SignWithDetailsAsync();
                    signed = result.Pdf;
                    dssEmbedded = result.DssEmbedded;
                });

            await File.WriteAllBytesAsync(outputPath, signed, cancellation);

            AnsiConsole.MarkupLine($"[green]✓ Signed:[/] {outputPath.EscapeMarkup()}");
            AnsiConsole.MarkupLine($"  Certificate: [bold]{cert.Subject.EscapeMarkup()}[/]");
            if (settings.TsaUrl is not null)
            {
                AnsiConsole.MarkupLine($"  Timestamp:   {settings.TsaUrl.EscapeMarkup()}");
            }

            if (settings.Ltv)
            {
                AnsiConsole.MarkupLine(dssEmbedded
                    ? "  LTV:         [green]enabled[/]"
                    : "  LTV:         [yellow]⚠ requested but DSS not embedded[/] — revocation data unavailable (check network / certificate CRL/OCSP endpoint)");
            }

            if (settings.Archival)
            {
                AnsiConsole.MarkupLine(dssEmbedded
                    ? "  Archival TS: [green]enabled[/]"
                    : "  Archival TS: [yellow]⚠ requested but DSS not embedded[/]");
            }

            return 0;
        }
        finally
        {
            cert.Dispose();
            foreach (var c in chainCerts)
            {
                c.Dispose();
            }
        }
    }

    private static HashAlgorithmName ParseHash(string hash) => hash.ToUpperInvariant() switch
    {
        "SHA256" => HashAlgorithmName.SHA256,
        "SHA384" => HashAlgorithmName.SHA384,
        "SHA512" => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256
    };

    private static CertificationLevel ParseCertificationLevel(string level) => level.ToLowerInvariant() switch
    {
        "no-changes" => CertificationLevel.NoChanges,
        "form-filling" => CertificationLevel.FormFilling,
        "annotations" => CertificationLevel.FormFillingAndAnnotations,
        _ => CertificationLevel.FormFilling
    };

    private static SignatureAppearance BuildAppearance(Settings settings)
    {
        bool hasCoords = settings.Page.HasValue || settings.X.HasValue || settings.Y.HasValue;

        var appearance = new SignatureAppearance
        {
            AutoPosition = !hasCoords,
            Page = settings.Page ?? 1,
            X = settings.X ?? 20f,
            Y = settings.Y ?? 20f,
            ShowReason = settings.Reason is not null,
            ShowLocation = settings.Location is not null,
            VerificationUrl = settings.QrUrl,
        };

        if (settings.BackgroundImage is not null)
        {
            var imageBytes = File.ReadAllBytes(settings.BackgroundImage);
            var ext = Path.GetExtension(settings.BackgroundImage).ToLowerInvariant();
            appearance = ext is ".png"
                ? new SignatureAppearance
                {
                    AutoPosition = appearance.AutoPosition,
                    Page = appearance.Page,
                    X = appearance.X,
                    Y = appearance.Y,
                    ShowReason = appearance.ShowReason,
                    ShowLocation = appearance.ShowLocation,
                    VerificationUrl = appearance.VerificationUrl,
                    BackgroundImagePng = imageBytes,
                }
                : new SignatureAppearance
                {
                    AutoPosition = appearance.AutoPosition,
                    Page = appearance.Page,
                    X = appearance.X,
                    Y = appearance.Y,
                    ShowReason = appearance.ShowReason,
                    ShowLocation = appearance.ShowLocation,
                    VerificationUrl = appearance.VerificationUrl,
                    BackgroundImageJpeg = imageBytes,
                };
        }

        return appearance;
    }
}
