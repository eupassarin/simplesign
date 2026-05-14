using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
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

        [CommandOption("--agent")]
        [Description("Sign using A3 hardware token via SimpleSign Agent (Windows certificate store)")]
        public bool Agent { get; init; }

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
            if (!Agent && string.IsNullOrWhiteSpace(CertPath))
            {
                return ValidationResult.Error("--cert or --agent is required.");
            }

            if (Agent && !string.IsNullOrWhiteSpace(CertPath))
            {
                return ValidationResult.Error("--cert and --agent are mutually exclusive.");
            }

            // For agent mode, allow glob patterns (e.g., *.pdf)
            if (Agent && ContainsWildcard(InputPath))
            {
                var files = ExpandGlob(InputPath);
                if (files.Length == 0)
                {
                    return ValidationResult.Error($"No files match pattern: {InputPath}");
                }
            }
            else if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (!Agent && !string.IsNullOrWhiteSpace(CertPath) && !File.Exists(CertPath))
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
                return ValidationResult.Error("--page, --x, --y require --visible.");
            }

            return ValidationResult.Success();
        }

        internal static bool ContainsWildcard(string path) => path.Contains('*') || path.Contains('?');

        internal static string[] ExpandGlob(string pattern)
        {
            var dir = Path.GetDirectoryName(pattern);
            if (string.IsNullOrEmpty(dir))
            {
                dir = ".";
            }

            var filePattern = Path.GetFileName(pattern);
            return Directory.Exists(dir)
                ? Directory.GetFiles(dir, filePattern)
                : [];
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellation)
    {
        using var loggerFactory = settings.CreateLoggerFactory();

        if (settings.Agent)
        {
            // Expand glob patterns for agent mode (supports multiple files)
            var inputFiles = Settings.ContainsWildcard(settings.InputPath)
                ? Settings.ExpandGlob(settings.InputPath)
                : [settings.InputPath];

            return await ExecuteAgentSigningAsync(settings, inputFiles, loggerFactory, cancellation);
        }

        var outputPath = settings.OutputPath ?? Path.Combine(
            Path.GetDirectoryName(settings.InputPath) ?? ".",
            Path.GetFileNameWithoutExtension(settings.InputPath) + "_signed.pdf");

        return await ExecuteCertSigningAsync(settings, outputPath, loggerFactory, cancellation);
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

    private static async Task<int> ExecuteAgentSigningAsync(
        Settings settings, string[] inputFiles, ILoggerFactory? loggerFactory, CancellationToken cancellation)
    {
        if (!OperatingSystem.IsWindows())
        {
            AnsiConsole.MarkupLine("[red]✗[/] --agent is only supported on Windows.");
            return 1;
        }

        ILogger? logger = loggerFactory?.CreateLogger("SimpleSign.AgentSigning");
        var hashAlg = settings.Hash is not null ? ParseHash(settings.Hash) : HashAlgorithmName.SHA256;
        using var httpClient = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:21599") };

        if (inputFiles.Length > 1)
        {
            AnsiConsole.MarkupLine($"[blue]→[/] Signing {inputFiles.Length} documents via SimpleSign Agent...");
        }
        else
        {
            AnsiConsole.MarkupLine("[blue]→[/] Opening SimpleSign Agent...");
        }

        // 1. Try to open Agent
        try
        {
            Process.Start(new ProcessStartInfo("simplesign://") { UseShellExecute = true });
        }
        catch
        {
            AnsiConsole.MarkupLine("[yellow]  Could not launch Agent automatically. Please open it manually.[/]");
        }

        // 2. Wait for Agent to be ready (health check)
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync("Waiting for Agent to start...", async _ =>
            {
                var sw = Stopwatch.StartNew();
                while (sw.Elapsed < TimeSpan.FromSeconds(30))
                {
                    try
                    {
                        var resp = await httpClient.GetAsync("/api/health", cancellation);
                        if (resp.IsSuccessStatusCode)
                        {
                            break;
                        }
                    }
                    catch
                    {
                        // Agent not ready yet
                    }
                    await Task.Delay(500, cancellation);
                }
            });

        // Verify agent is actually running
        try
        {
            var health = await httpClient.GetAsync("/api/health", cancellation);
            if (!health.IsSuccessStatusCode)
            {
                AnsiConsole.MarkupLine("[red]✗[/] Agent is not responding. Please start SimpleSign Agent.");
                return 1;
            }
        }
        catch
        {
            AnsiConsole.MarkupLine("[red]✗[/] Cannot connect to Agent at http://127.0.0.1:21599. Is it running?");
            return 1;
        }

        // 3. Create first session for cert selection
        var firstFileName = Path.GetFileName(inputFiles[0]);
        var createRequest = new AgentHttpSignRequest
        {
            FileName = inputFiles.Length > 1 ? $"{firstFileName} (+{inputFiles.Length - 1})" : firstFileName,
            HashAlgorithm = hashAlg.Name ?? "SHA256",
            DataBase64 = "",
        };
        var createJson = JsonSerializer.Serialize(createRequest, AgentJsonContext.Default.AgentHttpSignRequest);
        using var createContent = new StringContent(createJson, System.Text.Encoding.UTF8, "application/json");
        var createResponse = await httpClient.PostAsync("/api/sign", createContent, cancellation);

        if (!createResponse.IsSuccessStatusCode)
        {
            AnsiConsole.MarkupLine("[red]✗[/] Failed to create signing session.");
            return 1;
        }

        var createResult = await createResponse.Content.ReadAsStringAsync(cancellation);
        var sessionId = JsonSerializer.Deserialize(createResult, AgentJsonContext.Default.AgentHttpCreateResponse)?.SessionId
            ?? throw new InvalidOperationException("No sessionId in response.");

        // 4. Wait for certificate selection
        string? certBase64 = null;
        string? thumbprint = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync("Select a certificate in SimpleSign Agent...", async _ =>
            {
                var sw = Stopwatch.StartNew();
                while (sw.Elapsed < TimeSpan.FromMinutes(5))
                {
                    try
                    {
                        var pollResp = await httpClient.GetAsync($"/api/sign/{sessionId}", cancellation);
                        if (pollResp.IsSuccessStatusCode)
                        {
                            var pollJson = await pollResp.Content.ReadAsStringAsync(cancellation);
                            var poll = JsonSerializer.Deserialize(pollJson, AgentJsonContext.Default.AgentHttpPollResponse);
                            if (poll?.Status == "cert_selected")
                            {
                                certBase64 = poll.CertificateBase64;
                                thumbprint = poll.Thumbprint;
                                break;
                            }
                            if (poll?.Status is "cancelled" or "error")
                            {
                                break;
                            }
                        }
                    }
                    catch
                    {
                        // ignore transient errors
                    }
                    await Task.Delay(500, cancellation);
                }
            });

        if (certBase64 is null || thumbprint is null)
        {
            AnsiConsole.MarkupLine("[red]✗[/] Certificate selection timed out or was cancelled.");
            return 1;
        }

        var publicCertBytes = Convert.FromBase64String(certBase64);
#if NET9_0_OR_GREATER
        using var publicCert = X509CertificateLoader.LoadCertificate(publicCertBytes);
#else
        using var publicCert = new X509Certificate2(publicCertBytes);
#endif
        AnsiConsole.MarkupLine($"  Certificate: [bold]{publicCert.Subject.EscapeMarkup()}[/]");
        AnsiConsole.WriteLine();

        // 5. Sign each file using the selected certificate
        int signed = 0;
        int failed = 0;
        var prepareOptions = new DeferredSigningOptions { HashAlgorithm = hashAlg };
        var completeOptions = new DeferredSigningCompleteOptions { TsaUrl = settings.TsaUrl };

        for (int i = 0; i < inputFiles.Length; i++)
        {
            var inputPath = inputFiles[i];
            var outputPath = settings.OutputPath ?? Path.Combine(
                Path.GetDirectoryName(inputPath) ?? ".",
                Path.GetFileNameWithoutExtension(inputPath) + "_signed.pdf");
            var fileName = Path.GetFileName(inputPath);

            if (inputFiles.Length > 1)
            {
                AnsiConsole.MarkupLine($"[blue]({i + 1}/{inputFiles.Length})[/] {fileName.EscapeMarkup()}");
            }

            try
            {
                int result;
                if (i == 0)
                {
                    // First file: PUT data to the existing cert-selection session
                    result = await SignFirstFileWithAgentAsync(
                        httpClient, inputPath, outputPath, fileName, sessionId, publicCert,
                        hashAlg, prepareOptions, completeOptions, logger, cancellation);
                }
                else
                {
                    // Subsequent files: create new auto-sign session (thumbprint+data → data_ready)
                    result = await SignSingleFileWithAgentAsync(
                        httpClient, inputPath, outputPath, fileName, thumbprint, publicCert,
                        hashAlg, prepareOptions, completeOptions, logger, cancellation);
                }

                if (result == 0)
                {
                    signed++;
                    AnsiConsole.MarkupLine($"  [green]✓ Signed:[/] {outputPath.EscapeMarkup()}");
                    // Give Agent time to reset before next session
                    if (i < inputFiles.Length - 1)
                    {
                        await Task.Delay(1800, cancellation);
                    }
                }
                else
                {
                    failed++;
                }
            }
            catch (Exception ex)
            {
                failed++;
                AnsiConsole.MarkupLine($"  [red]✗ Failed:[/] {ex.Message.EscapeMarkup()}");
            }
        }

        AnsiConsole.WriteLine();
        if (inputFiles.Length > 1)
        {
            AnsiConsole.MarkupLine($"[green]✓[/] {signed}/{inputFiles.Length} documents signed" +
                (failed > 0 ? $", [red]{failed} failed[/]" : ""));
        }

        if (settings.TsaUrl is not null)
        {
            AnsiConsole.MarkupLine($"  Timestamp:   {settings.TsaUrl.EscapeMarkup()}");
        }

        return failed > 0 ? 1 : 0;
    }

    /// Signs the first file by PUTting data into the existing cert-selection session.
    /// The Agent's handleSign() is already waiting for this session to become data_ready.
    private static async Task<int> SignFirstFileWithAgentAsync(
        HttpClient httpClient, string inputPath, string outputPath, string fileName,
        string sessionId, X509Certificate2 publicCert, HashAlgorithmName hashAlg,
        DeferredSigningOptions prepareOptions, DeferredSigningCompleteOptions completeOptions,
        ILogger? logger, CancellationToken cancellation)
    {
        // Prepare deferred signing
        var pdfBytes = await File.ReadAllBytesAsync(inputPath, cancellation);
        DeferredSigningPrepareResult prepareResult = null!;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync($"Preparing {fileName}...", async _ =>
            {
                prepareResult = await DeferredSigner.PrepareAsync(pdfBytes, publicCert, prepareOptions, logger, cancellation);
            });

        // PUT data into the existing session → triggers Agent to sign
        var updateBody = new AgentHttpUpdateRequest
        {
            DataBase64 = Convert.ToBase64String(prepareResult.HashToSign),
            HashAlgorithm = prepareResult.DigestAlgorithm,
        };
        var updateJson = JsonSerializer.Serialize(updateBody, AgentJsonContext.Default.AgentHttpUpdateRequest);
        using var updateContent = new StringContent(updateJson, System.Text.Encoding.UTF8, "application/json");
        var updateResp = await httpClient.PutAsync($"/api/sign/{sessionId}", updateContent, cancellation);

        if (!updateResp.IsSuccessStatusCode)
        {
            var errBody = await updateResp.Content.ReadAsStringAsync(cancellation);
            AnsiConsole.MarkupLine($"  [red]✗[/] Failed to send data to Agent: {errBody.EscapeMarkup()}");
            return 1;
        }

        // Wait for Agent to sign (Agent handleSign() will call sign_session once data_ready)
        string? signatureBase64 = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync($"Signing {fileName}...", async _ =>
            {
                var sw = Stopwatch.StartNew();
                while (sw.Elapsed < TimeSpan.FromMinutes(5))
                {
                    try
                    {
                        var pollResp = await httpClient.GetAsync($"/api/sign/{sessionId}", cancellation);
                        if (pollResp.IsSuccessStatusCode)
                        {
                            var pollJson = await pollResp.Content.ReadAsStringAsync(cancellation);
                            var poll = JsonSerializer.Deserialize(pollJson, AgentJsonContext.Default.AgentHttpPollResponse);
                            if (poll?.Status == "signed")
                            {
                                signatureBase64 = poll.SignatureBase64;
                                break;
                            }
                            if (poll?.Status == "error")
                            {
                                throw new InvalidOperationException(poll.Error ?? "Unknown Agent error");
                            }
                            if (poll?.Status == "cancelled")
                            {
                                throw new OperationCanceledException("Signing cancelled by user");
                            }
                        }
                    }
                    catch (HttpRequestException)
                    {
                        // ignore transient errors
                    }
                    await Task.Delay(500, cancellation);
                }
            });

        if (signatureBase64 is null)
        {
            AnsiConsole.MarkupLine($"  [red]✗[/] Signing timed out for {fileName.EscapeMarkup()}");
            return 1;
        }

        var signatureBytes = Convert.FromBase64String(signatureBase64);

        byte[] signedPdf = null!;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync($"Completing {fileName}...", async _ =>
            {
                signedPdf = await DeferredSigner.CompleteAsync(
                    prepareResult.SessionData, signatureBytes, completeOptions, logger, cancellation);
                await File.WriteAllBytesAsync(outputPath, signedPdf, cancellation);
            });

        return 0;
    }

    /// Signs subsequent files by creating a new session with thumbprint+data (auto-signed by Agent).
    private static async Task<int> SignSingleFileWithAgentAsync(
        HttpClient httpClient, string inputPath, string outputPath, string fileName,
        string thumbprint, X509Certificate2 publicCert, HashAlgorithmName hashAlg,
        DeferredSigningOptions prepareOptions, DeferredSigningCompleteOptions completeOptions,
        ILogger? logger, CancellationToken cancellation)
    {
        // Prepare deferred signing
        var pdfBytes = await File.ReadAllBytesAsync(inputPath, cancellation);
        DeferredSigningPrepareResult prepareResult = null!;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync($"Preparing {fileName}...", async _ =>
            {
                prepareResult = await DeferredSigner.PrepareAsync(pdfBytes, publicCert, prepareOptions, logger, cancellation);
            });

        // Create signing session with data and thumbprint (auto-sign in Agent)
        var signRequest = new AgentHttpSignRequest
        {
            FileName = fileName,
            HashAlgorithm = prepareResult.DigestAlgorithm,
            DataBase64 = Convert.ToBase64String(prepareResult.HashToSign),
            Thumbprint = thumbprint,
        };
        var signJson = JsonSerializer.Serialize(signRequest, AgentJsonContext.Default.AgentHttpSignRequest);
        using var signContent = new StringContent(signJson, System.Text.Encoding.UTF8, "application/json");
        var signResponse = await httpClient.PostAsync("/api/sign", signContent, cancellation);

        if (!signResponse.IsSuccessStatusCode)
        {
            AnsiConsole.MarkupLine($"  [red]✗[/] Failed to create signing session for {fileName.EscapeMarkup()}");
            return 1;
        }

        var signResult = await signResponse.Content.ReadAsStringAsync(cancellation);
        var signSessionId = JsonSerializer.Deserialize(signResult, AgentJsonContext.Default.AgentHttpCreateResponse)?.SessionId
            ?? throw new InvalidOperationException("No sessionId in response.");

        // Wait for Agent to sign (auto-signs with thumbprint + data sessions)
        string? signatureBase64 = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync($"Signing {fileName}...", async _ =>
            {
                var sw = Stopwatch.StartNew();
                while (sw.Elapsed < TimeSpan.FromMinutes(5))
                {
                    try
                    {
                        var pollResp = await httpClient.GetAsync($"/api/sign/{signSessionId}", cancellation);
                        if (pollResp.IsSuccessStatusCode)
                        {
                            var pollJson = await pollResp.Content.ReadAsStringAsync(cancellation);
                            var poll = JsonSerializer.Deserialize(pollJson, AgentJsonContext.Default.AgentHttpPollResponse);
                            if (poll?.Status == "signed")
                            {
                                signatureBase64 = poll.SignatureBase64;
                                break;
                            }
                            if (poll?.Status == "error")
                            {
                                throw new InvalidOperationException(poll.Error ?? "Unknown Agent error");
                            }
                            if (poll?.Status == "cancelled")
                            {
                                throw new OperationCanceledException("Signing cancelled by user");
                            }
                        }
                    }
                    catch (HttpRequestException)
                    {
                        // ignore transient errors
                    }
                    await Task.Delay(500, cancellation);
                }
            });

        if (signatureBase64 is null)
        {
            AnsiConsole.MarkupLine($"  [red]✗[/] Signing timed out for {fileName.EscapeMarkup()}");
            return 1;
        }

        var signatureBytes = Convert.FromBase64String(signatureBase64);

        // Complete signing
        byte[] signedPdf = null!;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync($"Completing {fileName}...", async _ =>
            {
                signedPdf = await DeferredSigner.CompleteAsync(
                    prepareResult.SessionData, signatureBytes, completeOptions, logger, cancellation);
                await File.WriteAllBytesAsync(outputPath, signedPdf, cancellation);
            });

        return 0;
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
                    VerificationUrl = appearance.VerificationUrl,
                    BackgroundImagePng = imageBytes,
                }
                : new SignatureAppearance
                {
                    AutoPosition = appearance.AutoPosition,
                    Page = appearance.Page,
                    X = appearance.X,
                    Y = appearance.Y,
                    VerificationUrl = appearance.VerificationUrl,
                    BackgroundImageJpeg = imageBytes,
                };
        }

        return appearance;
    }

    internal sealed class AgentHttpSignRequest
    {
        public string FileName { get; set; } = "";
        public string HashAlgorithm { get; set; } = "SHA256";
        public string DataBase64 { get; set; } = "";
        public string? Thumbprint { get; set; }
    }

    internal sealed class AgentHttpCreateResponse
    {
        public string SessionId { get; set; } = "";
    }

    internal sealed class AgentHttpUpdateRequest
    {
        public string DataBase64 { get; set; } = "";
        public string HashAlgorithm { get; set; } = "SHA256";
    }

    internal sealed class AgentHttpPollResponse
    {
        public string Status { get; set; } = "";
        public string? Thumbprint { get; set; }
        public string? SignatureBase64 { get; set; }
        public string? CertificateBase64 { get; set; }
        public string? Error { get; set; }
    }
}

[System.Text.Json.Serialization.JsonSourceGenerationOptions(PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase)]
[System.Text.Json.Serialization.JsonSerializable(typeof(SignCommand.AgentHttpSignRequest))]
[System.Text.Json.Serialization.JsonSerializable(typeof(SignCommand.AgentHttpCreateResponse))]
[System.Text.Json.Serialization.JsonSerializable(typeof(SignCommand.AgentHttpUpdateRequest))]
[System.Text.Json.Serialization.JsonSerializable(typeof(SignCommand.AgentHttpPollResponse))]
internal sealed partial class AgentJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
