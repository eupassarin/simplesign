using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Brasil.Signing;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Sign a PDF document.</summary>
[Description("Sign a PDF document")]
internal sealed class SignCommand : AsyncCommand<SignCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;

    public SignCommand(ICertificateChainService certChainService)
    {
        _certChainService = certChainService;
    }

    /// <summary>Sign command settings.</summary>
    internal sealed class Settings : CommonSettings
    {
        /// <summary>Input PDF file to sign.</summary>
        [CommandArgument(0, "<input>")]
        [Description("Input PDF file to sign")]
        public string InputPath { get; init; } = null!;

        /// <summary>PKCS#12 certificate file (.pfx/.p12).</summary>
        [CommandOption("--cert|-c <PATH>")]
        [Description("PKCS#12 certificate file (.pfx/.p12)")]
        public string? CertPath { get; init; }

        /// <summary>Certificate password.</summary>
        [CommandOption("--password|-p <PASSWORD>")]
        [Description("Certificate password")]
        public string? Password { get; init; }

        /// <summary>OS certificate store name: My (default), Root, CA, TrustedPublisher. Requires --thumbprint.</summary>
        [CommandOption("--store <NAME>")]
        [Description("OS certificate store name: My (default), Root, CA, TrustedPublisher. Requires --thumbprint.")]
        public string? StoreName { get; init; }

        /// <summary>OS store location: CurrentUser (default) or LocalMachine. Requires --thumbprint.</summary>
        [CommandOption("--store-location <LOC>")]
        [Description("OS store location: CurrentUser (default) or LocalMachine. Requires --thumbprint.")]
        public string? StoreLocation { get; init; }

        /// <summary>Certificate thumbprint in OS certificate store (alternative to --cert).</summary>
        [CommandOption("--thumbprint <HEX>")]
        [Description("Certificate thumbprint in OS certificate store (alternative to --cert)")]
        public string? Thumbprint { get; init; }

        /// <summary>Output file (default: input_signed.pdf).</summary>
        [CommandOption("--output|-o <PATH>")]
        [Description("Output file (default: input_signed.pdf)")]
        public string? OutputPath { get; init; }

        /// <summary>TSA URL for RFC 3161 timestamping.</summary>
        [CommandOption("--tsa|-t <URL>")]
        [Description("TSA URL for RFC 3161 timestamping")]
        public string? TsaUrl { get; init; }

        /// <summary>Signing reason.</summary>
        [CommandOption("--reason <TEXT>")]
        [Description("Signing reason")]
        public string? Reason { get; init; }

        /// <summary>Signing location.</summary>
        [CommandOption("--location <TEXT>")]
        [Description("Signing location")]
        public string? Location { get; init; }

        /// <summary>Contact information.</summary>
        [CommandOption("--contact <TEXT>")]
        [Description("Contact information")]
        public string? Contact { get; init; }

        /// <summary>Override signer name (default: certificate CN).</summary>
        [CommandOption("--signer-name <NAME>")]
        [Description("Override signer name (default: certificate CN)")]
        public string? SignerName { get; init; }

        /// <summary>Enable LTV — embed revocation data (requires --tsa).</summary>
        [CommandOption("--ltv")]
        [Description("Enable LTV — embed revocation data (requires --tsa)")]
        public bool Ltv { get; init; }

        /// <summary>Enable archival timestamp / B-LTA (implies --ltv).</summary>
        [CommandOption("--archival")]
        [Description("Enable archival timestamp / B-LTA (implies --ltv)")]
        public bool Archival { get; init; }

        /// <summary>Hash algorithm: SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512.</summary>
        [CommandOption("--hash <ALGORITHM>")]
        [Description("Hash algorithm: SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512")]
        public string? Hash { get; init; }

        /// <summary>Custom signature field name (default: Signature1).</summary>
        [CommandOption("--field-name <NAME>")]
        [Description("Custom signature field name (default: Signature1)")]
        public string? FieldName { get; init; }

        /// <summary>Sign a pre-existing empty signature field.</summary>
        [CommandOption("--existing-field <NAME>")]
        [Description("Sign a pre-existing empty signature field")]
        public string? ExistingField { get; init; }

        /// <summary>Create certification (DocMDP) signature: no-changes, form-filling (default), annotations.</summary>
        [CommandOption("--certify <LEVEL>")]
        [Description("Create certification (DocMDP) signature: no-changes, form-filling (default), annotations")]
        public string? Certify { get; init; }

        /// <summary>Signature sub-filter: etsi-cades-detached (default) or adbe-pkcs7-detached.</summary>
        [CommandOption("--sub-filter <VALUE>")]
        [Description("Signature sub-filter: etsi-cades-detached (default) or adbe-pkcs7-detached")]
        public string? SubFilter { get; init; }

        /// <summary>Signature algorithm: rsa-pkcs1 (default) or rsassa-pss.</summary>
        [CommandOption("--signature-algorithm <ALGO>")]
        [Description("Signature algorithm: rsa-pkcs1 (default) or rsassa-pss")]
        public string? SignatureAlgorithm { get; init; }

        /// <summary>Use adbe.pkcs7.detached without PAdES attributes (legacy compatibility).</summary>
        [CommandOption("--legacy-cms")]
        [Description("Use adbe.pkcs7.detached without PAdES attributes (legacy compatibility)")]
        public bool LegacyCms { get; init; }

        /// <summary>Preserve PDF/A conformance.</summary>
        [CommandOption("--pdfa")]
        [Description("Preserve PDF/A conformance")]
        public bool PdfA { get; init; }

        /// <summary>Add visible signature stamp (auto-positioned).</summary>
        [CommandOption("--visible")]
        [Description("Add visible signature stamp (auto-positioned)")]
        public bool Visible { get; init; }

        /// <summary>Page for visible signature (default: 1).</summary>
        [CommandOption("--page <NUMBER>")]
        [Description("Page for visible signature (default: 1)")]
        public int? Page { get; init; }

        /// <summary>X coordinate for visible signature in points.</summary>
        [CommandOption("--pos-x <POINTS>")]
        [Description("X coordinate for visible signature in points")]
        public float? X { get; init; }

        /// <summary>Y coordinate for visible signature in points.</summary>
        [CommandOption("--pos-y <POINTS>")]
        [Description("Y coordinate for visible signature in points")]
        public float? Y { get; init; }

        /// <summary>Background image for visible signature (JPEG or PNG).</summary>
        [CommandOption("--background-image <PATH>")]
        [Description("Background image for visible signature (JPEG or PNG)")]
        public string? BackgroundImage { get; init; }

        /// <summary>Verification URL — renders QR code in visible signature.</summary>
        [CommandOption("--qr-url <URL>")]
        [Description("Verification URL — renders QR code in visible signature")]
        public string? QrUrl { get; init; }

        /// <summary>Font size for signer name in points (default: 7).</summary>
        [CommandOption("--font-size <PT>")]
        [Description("Font size for signer name in points (default: 7)")]
        public float? FontSize { get; init; }

        /// <summary>Font size for labels in points (default: 6).</summary>
        [CommandOption("--label-font-size <PT>")]
        [Description("Font size for labels in points (default: 6)")]
        public float? LabelFontSize { get; init; }

        /// <summary>Text color as RGB values 0-1, e.g. 0.5,0.5,0.5.</summary>
        [CommandOption("--text-color <R,G,B>")]
        [Description("Text color as RGB values 0-1, e.g. 0.5,0.5,0.5")]
        public string? TextColor { get; init; }

        /// <summary>Base14 font: Helvetica (default), Times-Roman, Courier, Helvetica-Bold.</summary>
        [CommandOption("--font <NAME>")]
        [Description("Base14 font: Helvetica (default), Times-Roman, Courier, Helvetica-Bold")]
        public string? Font { get; init; }

        /// <summary>Border color as RGB values 0-1, e.g. 0.2,0.2,0.2.</summary>
        [CommandOption("--border-color <R,G,B>")]
        [Description("Border color as RGB values 0-1, e.g. 0.2,0.2,0.2")]
        public string? BorderColor { get; init; }

        /// <summary>Border width in points (default: 0.5, requires --border-color).</summary>
        [CommandOption("--border-width <PT>")]
        [Description("Border width in points (default: 0.5, requires --border-color)")]
        public float? BorderWidth { get; init; }

        /// <summary>Hide signing date in visible signature.</summary>
        [CommandOption("--no-date")]
        [Description("Hide signing date in visible signature")]
        public bool NoDate { get; init; }

        /// <summary>Advanced Electronic Signature (AEA) per Lei 14.063/2020. Requires --cpf and --signer-name.</summary>
        [CommandOption("--brasil")]
        [Description("Advanced Electronic Signature (AEA) per Lei 14.063/2020. Requires --cpf and --signer-name.")]
        public bool Brasil { get; init; }

        /// <summary>CPF (11 digits, no punctuation) for AEA.</summary>
        [CommandOption("--cpf <CPF>")]
        [Description("CPF (11 digits, no punctuation) for AEA")]
        public string? Cpf { get; init; }

        /// <summary>Authentication method for AEA: digital-certificate (default), gov-br, institutional-login, facial-biometrics, token-otp, username-password.</summary>
        [CommandOption("--auth-method <METHOD>")]
        [Description("Authentication method for AEA: digital-certificate (default), gov-br, institutional-login, facial-biometrics, token-otp, username-password")]
        public string? AuthMethod { get; init; }

        /// <summary>Signer email for AEA.</summary>
        [CommandOption("--signer-email <EMAIL>")]
        [Description("Signer email for AEA")]
        public string? SignerEmail { get; init; }

        /// <summary>Institution name for AEA.</summary>
        [CommandOption("--institution <NAME>")]
        [Description("Institution name for AEA")]
        public string? Institution { get; init; }

        /// <summary>Institution CNPJ (14 digits) for AEA.</summary>
        [CommandOption("--institution-cnpj <CNPJ>")]
        [Description("Institution CNPJ (14 digits) for AEA")]
        public string? InstitutionCnpj { get; init; }

        /// <summary>Commitment type for AEA: approval (default) or origin.</summary>
        [CommandOption("--commitment <TYPE>")]
        [Description("Commitment type for AEA: approval (default) or origin")]
        public string? Commitment { get; init; }

        /// <summary>Signature policy OID for AEA.</summary>
        [CommandOption("--policy-oid <OID>")]
        [Description("Signature policy OID for AEA")]
        public string? PolicyOid { get; init; }

        /// <summary>Signature policy URI for AEA.</summary>
        [CommandOption("--policy-uri <URI>")]
        [Description("Signature policy URI for AEA")]
        public string? PolicyUri { get; init; }

        public override ValidationResult Validate()
        {
            bool hasCertPath = !string.IsNullOrWhiteSpace(CertPath);
            bool hasThumbprint = !string.IsNullOrWhiteSpace(Thumbprint);

            if (!hasCertPath && !hasThumbprint)
            {
                return ValidationResult.Error("Either --cert or --thumbprint is required.");
            }

            if (hasCertPath && hasThumbprint)
            {
                return ValidationResult.Error("--cert and --thumbprint are mutually exclusive.");
            }

            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (hasCertPath && !File.Exists(CertPath))
            {
                return ValidationResult.Error($"Certificate not found: {CertPath}");
            }

            if (hasThumbprint)
            {
                if (StoreName is not null && !ParseStoreName(StoreName).HasValue)
                {
                    return ValidationResult.Error("--store must be My, Root, CA, or TrustedPublisher.");
                }

                if (StoreLocation is not null && !ParseStoreLocation(StoreLocation).HasValue)
                {
                    return ValidationResult.Error("--store-location must be CurrentUser or LocalMachine.");
                }
            }

            if (Ltv && string.IsNullOrWhiteSpace(TsaUrl))
            {
                return ValidationResult.Error("--ltv requires --tsa. LTV without a timestamp is not valid for long-term archival.");
            }

            if (Hash is not null && !Hash.Equals("SHA256", StringComparison.OrdinalIgnoreCase)
                && !Hash.Equals("SHA384", StringComparison.OrdinalIgnoreCase)
                && !Hash.Equals("SHA512", StringComparison.OrdinalIgnoreCase)
                && !Hash.Equals("SHA3-256", StringComparison.OrdinalIgnoreCase)
                && !Hash.Equals("SHA3-384", StringComparison.OrdinalIgnoreCase)
                && !Hash.Equals("SHA3-512", StringComparison.OrdinalIgnoreCase))
            {
                return ValidationResult.Error("--hash must be SHA256, SHA384, SHA512, SHA3-256, SHA3-384, or SHA3-512.");
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

            if (SubFilter is not null && SignCommandOptions.ParseSubFilter(SubFilter) is null)
            {
                return ValidationResult.Error("--sub-filter must be etsi-cades-detached or adbe-pkcs7-detached.");
            }

            if (SignatureAlgorithm is not null && SignCommandOptions.ParseSignatureAlgorithm(SignatureAlgorithm) is null)
            {
                return ValidationResult.Error("--signature-algorithm must be rsa-pkcs1 or rsassa-pss.");
            }

            if (FontSize.HasValue && (FontSize < 1 || FontSize > 72))
            {
                return ValidationResult.Error("--font-size must be between 1 and 72.");
            }

            if (LabelFontSize.HasValue && (LabelFontSize < 1 || LabelFontSize > 72))
            {
                return ValidationResult.Error("--label-font-size must be between 1 and 72.");
            }

            if (TextColor is not null && AppearanceBuilder.ParseColor(TextColor) is null)
            {
                return ValidationResult.Error("--text-color must be in format R,G,B with values between 0 and 1.");
            }

            if (BorderColor is not null && AppearanceBuilder.ParseColor(BorderColor) is null)
            {
                return ValidationResult.Error("--border-color must be in format R,G,B with values between 0 and 1.");
            }

            if (FontSize.HasValue || LabelFontSize.HasValue || TextColor is not null
                || Font is not null || BorderColor is not null || BorderWidth.HasValue || NoDate)
            {
                if (!Visible)
                {
                    return ValidationResult.Error("Appearance options (--font-size, --text-color, etc.) require --visible.");
                }
            }

#pragma warning disable IDE0046 // Convert to conditional expression — readability
            if (Brasil)
            {
                if (string.IsNullOrWhiteSpace(Cpf))
                {
                    return ValidationResult.Error("--brasil requires --cpf.");
                }

                if (string.IsNullOrWhiteSpace(SignerName))
                {
                    return ValidationResult.Error("--brasil requires --signer-name.");
                }

                if (AuthMethod is not null && !IsValidAuthMethod(AuthMethod))
                {
                    return ValidationResult.Error("--auth-method must be digital-certificate, gov-br, institutional-login, facial-biometrics, token-otp, or username-password.");
                }

                if (Commitment is not null
                    && !Commitment.Equals("approval", StringComparison.OrdinalIgnoreCase)
                    && !Commitment.Equals("origin", StringComparison.OrdinalIgnoreCase))
                {
                    return ValidationResult.Error("--commitment must be approval or origin.");
                }
            }
#pragma warning restore IDE0046

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

    private async Task<(X509Certificate2 Cert, List<X509Certificate2> Chain)> LoadSigningCertificateAsync(
        Settings settings, CancellationToken cancellation)
    {
        if (!string.IsNullOrWhiteSpace(settings.Thumbprint))
        {
            var storeName = ParseStoreName(settings.StoreName) ?? StoreName.My;
            var storeLocation = ParseStoreLocation(settings.StoreLocation) ?? StoreLocation.CurrentUser;
            using var sysStore = new SystemCertificateStore(storeName, storeLocation);
            var cert = sysStore.FindByThumbprint(settings.Thumbprint)
                ?? throw new InvalidOperationException($"Certificate with thumbprint '{settings.Thumbprint}' not found in {storeName}/{storeLocation}.");
            return (cert, []);
        }

        var password = await PasswordResolver.ResolveAsync(settings.Password);
        var collection = _certChainService.LoadPkcs12CollectionFromFile(settings.CertPath!, password);
        var signerCert = collection.OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey)
            ?? throw new InvalidOperationException("No certificate with a private key was found in the PFX file.");
        var chainCerts = collection.OfType<X509Certificate2>()
            .Where(c => c.Thumbprint != signerCert.Thumbprint)
            .ToList();
        return (signerCert, chainCerts);
    }

    internal static StoreName? ParseStoreName(string? value) => value?.ToLowerInvariant() switch
    {
        "my" => StoreName.My,
        "root" => StoreName.Root,
        "ca" => StoreName.CertificateAuthority,
        "trustedpublisher" => StoreName.TrustedPublisher,
        _ => null
    };

    private static bool IsValidAuthMethod(string value)
    {
        var lower = value.ToLowerInvariant();
        return lower is "digital-certificate" or "digital_certificate"
            or "gov-br" or "gov_br" or "govbr"
            or "institutional-login" or "institutional_login"
            or "facial-biometrics" or "facial_biometrics"
            or "token-otp" or "token_otp"
            or "username-password" or "username_password";
    }

    internal static StoreLocation? ParseStoreLocation(string? value) => value?.ToLowerInvariant() switch
    {
        "currentuser" => StoreLocation.CurrentUser,
        "localmachine" => StoreLocation.LocalMachine,
        _ => null
    };

    private async Task<int> ExecuteCertSigningAsync(
        Settings settings, string outputPath, ILoggerFactory? loggerFactory, CancellationToken cancellation)
    {
        var (cert, chainCerts) = await LoadSigningCertificateAsync(settings, cancellation);

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
                        builder = builder.WithHashAlgorithm(SignCommandOptions.ParseHash(settings.Hash));
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
                        builder = builder.AsCertification(SignCommandOptions.ParseCertificationLevel(settings.Certify));
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

                    // Brasil AEA — after explicit metadata so it adds extra CMS attributes
                    if (settings.Brasil)
                    {
                        var info = BrasilSignOptions.Build(
                            signerName: settings.SignerName ?? "",
                            cpf: settings.Cpf!,
                            authMethod: settings.AuthMethod,
                            email: settings.SignerEmail,
                            institution: settings.Institution,
                            institutionCnpj: settings.InstitutionCnpj,
                            commitmentType: settings.Commitment,
                            policyOid: settings.PolicyOid,
                            policyUri: settings.PolicyUri);
                        builder = builder.WithAdvancedSignature(info);
                    }

                    // Visual appearance
                    if (settings.Visible)
                    {
                        var appearance = AppearanceBuilder.Build(
                            visible: true,
                            backgroundImage: settings.BackgroundImage,
                            qrUrl: settings.QrUrl,
                            page: settings.Page,
                            x: settings.X,
                            y: settings.Y,
                            hasReason: settings.Reason is not null || settings.Brasil,
                            hasLocation: settings.Location is not null,
                            fontSize: settings.FontSize,
                            labelFontSize: settings.LabelFontSize,
                            textColor: settings.TextColor,
                            font: settings.Font,
                            borderColor: settings.BorderColor,
                            borderWidth: settings.BorderWidth,
                            noDate: settings.NoDate);

                        if (settings.Brasil)
                        {
                            appearance = AppearanceBuilder.AddAeaExtraLines(
                                appearance, settings.SignerName!, settings.Cpf!);
                        }

                        builder = builder.WithAppearance(appearance);
                    }

                    if (settings.LegacyCms)
                    {
                        builder = builder.WithLegacyCms();
                    }

                    if (settings.SubFilter is not null)
                    {
                        var parsed = SignCommandOptions.ParseSubFilter(settings.SubFilter);
                        if (parsed.HasValue)
                        {
                            builder = builder.WithSubFilter(parsed.Value);
                        }
                    }

                    if (settings.SignatureAlgorithm is not null)
                    {
                        var oid = SignCommandOptions.ParseSignatureAlgorithm(settings.SignatureAlgorithm);
                        if (oid is not null)
                        {
                            builder = builder.WithSignatureAlgorithm(oid);
                        }
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

}
