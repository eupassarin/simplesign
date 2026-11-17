using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.Peru.Iofe.Accredited;
using SimpleSign.Signers.Cloud.Csc;
using SimpleSign.Signers.Pkcs11;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Peru.Iofe.Cli;

/// <summary>
/// Whom the <c>iofe</c> commands trust: INDECOPI's trusted list (the default), another list read the same way, or
/// root certificates given as files.
/// </summary>
internal abstract class IofeTrustSettings : CommandSettings
{
    /// <summary>Root certificates the operator installed, instead of the trusted list.</summary>
    [CommandOption("--trust-root <FILE>")]
    [Description("A root certificate to trust instead of the trusted list (PEM or DER); repeat for more")]
    public string[] TrustRoots { get; init; } = [];

    /// <summary>A trusted list other than INDECOPI's, read the same way.</summary>
    [CommandOption("--tsl <URL|FILE>")]
    [Description("A trusted list read as INDECOPI's, instead of https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml")]
    public string? TrustedList { get; init; }

    /// <summary>The certificate that list is signed with.</summary>
    [CommandOption("--tsl-signer <FILE>")]
    [Description("The certificate --tsl is signed with (default: INDECOPI's, bundled)")]
    public string? TrustedListSigner { get; init; }

    /// <summary>The trust these options ask for.</summary>
    internal async Task<IofeTrust> TrustAsync(CancellationToken cancellationToken)
    {
        if (TrustRoots.Length > 0)
        {
            return IofeTrust.InstalledRoots(TrustRoots.Select(LoadCertificate));
        }

        IReadOnlyList<X509Certificate2> signers = TrustedListSigner is null ? [] : [LoadCertificate(TrustedListSigner)];
        if (TrustedList is null)
        {
            return IofeTrust.IndecopiList(new IofeExtensionOptions { TrustedListSigners = signers, HttpClientProvider = IofeCliExtension.Context.HttpClientProvider });
        }

        if (Uri.TryCreate(TrustedList, UriKind.Absolute, out var url) && url.Scheme is "http" or "https")
        {
            return IofeTrust.IndecopiList(new IofeExtensionOptions
            {
                TrustedListUrl = url,
                TrustedListSigners = signers,
                HttpClientProvider = IofeCliExtension.Context.HttpClientProvider,
            });
        }

        byte[] list = await File.ReadAllBytesAsync(TrustedList, cancellationToken);
        return IofeTrust.List(IofeExtension.Load(list, signers.Count > 0 ? signers : IofeExtension.IndecopiSigners));
    }

    /// <summary>The contingency of <c>--contingency</c>, in force from now, or null.</summary>
    internal static IofeContingency? Contingency(string? reference, string? until) =>
        reference is null
            ? null
            : new IofeContingency(
                reference,
                DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.Parse(until!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal));

    /// <summary>Checks the pair <c>--contingency</c> / <c>--contingency-until</c>.</summary>
    internal static ValidationResult ValidateContingency(string? reference, string? until)
    {
        if ((reference is null) != (until is null))
        {
            return ValidationResult.Error("--contingency and --contingency-until go together.");
        }

        return until is null || DateTimeOffset.TryParse(until, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _)
            ? ValidationResult.Success()
            : ValidationResult.Error($"--contingency-until is not a date and time: {until}");
    }

    internal static X509Certificate2 LoadCertificate(string path) =>
        new CertificateChainService().LoadCertsFromBytes(File.ReadAllBytes(path)).FirstOrDefault()
        ?? throw new InvalidDataException($"No certificate in {path}.");

    internal static int Refused(IofeAccreditationException ex)
    {
        AnsiConsole.MarkupLine($"[red]Refused ({ex.Refusal}):[/] {ex.Message.EscapeMarkup()}");
        return 1;
    }
}

/// <summary>Signs as the automated agent of INDECOPI's guide, section 4.2 (<see cref="IofeSigningAgent"/>).</summary>
[Description("Sign as an automated agent under INDECOPI's accreditation guide (section 4.2): key in a PKCS#11 module or in a remote signing service, fixed policy, audit")]
internal sealed class IofeSignCommand : AsyncCommand<IofeSignCommand.Settings>
{
    /// <summary>The settings of <c>iofe sign</c>.</summary>
    internal sealed class Settings : IofeTrustSettings
    {
        /// <summary>The document to sign.</summary>
        [CommandArgument(0, "<input>")]
        [Description("The document to sign (PDF, XML, or any file for a CMS signature)")]
        public string Input { get; init; } = "";

        /// <summary>Where the signed document is written.</summary>
        [CommandOption("-o|--output <FILE>")]
        [Description("Where the signed document is written")]
        public string? Output { get; init; }

        /// <summary>The format of the signature.</summary>
        [CommandOption("--format <FORMAT>")]
        [Description("pdf, xml or cms (default: by the extension of the input; cms for anything else)")]
        public string? Format { get; init; }

        /// <summary>Whether a CMS signature leaves the content out.</summary>
        [CommandOption("--detached")]
        [Description("For cms: leave the content out of the signature")]
        public bool Detached { get; init; }

        /// <summary>The PKCS#11 driver of the module.</summary>
        [CommandOption("--pkcs11-lib <PATH>")]
        [Description("PKCS#11 library of the cryptographic module (HSM or token). See 'simplesign pkcs11 list'. The key is here or in a remote service (--csc-url), one of the two")]
        public string? Pkcs11Library { get; init; }

        /// <summary>The token label.</summary>
        [CommandOption("--pkcs11-token <LABEL>")]
        [Description("Token label, when the module has more than one")]
        public string? Pkcs11Token { get; init; }

        /// <summary>The key label.</summary>
        [CommandOption("--pkcs11-key <LABEL>")]
        [Description("Key or certificate label, when the token has more than one key")]
        public string? Pkcs11Key { get; init; }

        /// <summary>The PIN.</summary>
        [CommandOption("--pin <PIN>")]
        [Description("PIN of the module (omit for a prompt or a PIN pad), or of the remote credential (omit when it has none). Accepts env:NAME")]
        public string? Pin { get; init; }

        /// <summary>The declared manufacturer of the module.</summary>
        [CommandOption("--module-manufacturer <NAME>")]
        [Description("The module's manufacturer as its driver reports it ('simplesign pkcs11 list')")]
        public string? ModuleManufacturer { get; init; }

        /// <summary>The declared model of the module.</summary>
        [CommandOption("--module-model <NAME>")]
        [Description("The module's model as its driver reports it")]
        public string? ModuleModel { get; init; }

        /// <summary>The declared certification of the module.</summary>
        [CommandOption("--module-certification <TEXT>")]
        [Description("The module's certification, e.g. \"FIPS 140-2 Level 3\"")]
        public string? ModuleCertification { get; init; }

        /// <summary>The number of the module's certificate.</summary>
        [CommandOption("--module-certificate <NUMBER>")]
        [Description("The number of the certificate of that certification")]
        public string? ModuleCertificate { get; init; }

        /// <summary>The remote signing service.</summary>
        [CommandOption("--csc-url <URL>")]
        [Description("Remote signing service that keeps the key (Cloud Signature Consortium API v2), e.g. https://provider/csc/v2/, instead of --pkcs11-lib")]
        public string? CscUrl { get; init; }

        /// <summary>The credential in the remote service.</summary>
        [CommandOption("--csc-credential <ID>")]
        [Description("The credential (key and certificate) in the remote service. See 'simplesign csc list'")]
        public string? CscCredential { get; init; }

        /// <summary>The service access token.</summary>
        [CommandOption("--csc-token <TOKEN>")]
        [Description("Service access token of the remote service, or use --csc-client-id and --csc-client-secret. Accepts env:NAME")]
        public string? CscToken { get; init; }

        /// <summary>The OAuth client of the agent in the remote service.</summary>
        [CommandOption("--csc-client-id <ID>")]
        [Description("OAuth client of this agent in the remote service (client credentials)")]
        public string? CscClientId { get; init; }

        /// <summary>The secret of that client.</summary>
        [CommandOption("--csc-client-secret <SECRET>")]
        [Description("The secret of that client. Accepts env:NAME")]
        public string? CscClientSecret { get; init; }

        /// <summary>The declared provider of the remote service.</summary>
        [CommandOption("--service-provider <NAME>")]
        [Description("Who provides the remote signing service")]
        public string? ServiceProvider { get; init; }

        /// <summary>The declared name of the remote service.</summary>
        [CommandOption("--service-name <NAME>")]
        [Description("The name the remote service reports about itself; another service is refused")]
        public string? ServiceName { get; init; }

        /// <summary>The declared accreditation of the remote service.</summary>
        [CommandOption("--service-accreditation <TEXT>")]
        [Description("Its accreditation or the certification of its signing device, e.g. \"PSVA de firma remota acreditado\"")]
        public string? ServiceAccreditation { get; init; }

        /// <summary>The reference of that accreditation.</summary>
        [CommandOption("--service-reference <NUMBER>")]
        [Description("The number of the resolution or of the certificate of that accreditation")]
        public string? ServiceReference { get; init; }

        /// <summary>The transaction signed for.</summary>
        [CommandOption("--transaction <TYPE/ID>")]
        [Description("The transaction the signature is for, as type/id (e.g. factura/F001-123)")]
        public string? Transaction { get; init; }

        /// <summary>The kinds of transaction the agent signs for.</summary>
        [CommandOption("--allow <TYPE>")]
        [Description("A kind of transaction this agent signs for; repeat for more")]
        public string[] Allowed { get; init; } = [];

        /// <summary>The audit trail.</summary>
        [CommandOption("--audit-log <FILE>")]
        [Description("The audit trail of the signatures made and refused (check it with 'simplesign audit verify')")]
        public string? AuditLog { get; init; }

        /// <summary>The time-stamp authority.</summary>
        [CommandOption("--tsa <URL>")]
        [Description("The time-stamp authority (section 4.4); with it the signature is made at B-LT")]
        public string? Tsa { get; init; }

        /// <summary>The certificate of the time-stamp authority.</summary>
        [CommandOption("--tsa-cert <FILE>")]
        [Description("The certificate the time-stamp authority signs with; a token of any other is refused")]
        public string? TsaCertificate { get; init; }

        /// <summary>The procedure of a declared contingency.</summary>
        [CommandOption("--contingency <REFERENCE>")]
        [Description("Sign under a contingency: the procedure INDECOPI approved (goes to the audit trail)")]
        public string? ContingencyReference { get; init; }

        /// <summary>When the contingency ends.</summary>
        [CommandOption("--contingency-until <DATETIME>")]
        [Description("When the contingency ends (ISO 8601, UTC when no offset is given)")]
        public string? ContingencyUntil { get; init; }

        /// <inheritdoc />
        public override ValidationResult Validate()
        {
            if (!File.Exists(Input))
            {
                return ValidationResult.Error($"File not found: {Input}");
            }

            // The key is in a module or in a remote service: one of the two, each with its declaration.
            bool remote = CscUrl is not null;
            if (remote == (Pkcs11Library is not null))
            {
                return ValidationResult.Error("Give the key one way: --pkcs11-lib (a cryptographic module) or --csc-url (a remote signing service).");
            }

            (string Option, string? Value)[] required = remote
                ?
                [
                    ("--output", Output), ("--csc-credential", CscCredential), ("--service-provider", ServiceProvider),
                    ("--service-name", ServiceName), ("--service-accreditation", ServiceAccreditation),
                    ("--service-reference", ServiceReference), ("--transaction", Transaction), ("--audit-log", AuditLog),
                ]
                :
                [
                    ("--output", Output), ("--module-manufacturer", ModuleManufacturer),
                    ("--module-model", ModuleModel), ("--module-certification", ModuleCertification),
                    ("--module-certificate", ModuleCertificate), ("--transaction", Transaction), ("--audit-log", AuditLog),
                ];
            if (required.FirstOrDefault(r => string.IsNullOrWhiteSpace(r.Value)) is { Option: not null } missing)
            {
                return ValidationResult.Error($"{missing.Option} is required.");
            }

            if (remote && !Uri.TryCreate(CscUrl, UriKind.Absolute, out _))
            {
                return ValidationResult.Error("--csc-url is the address of the service, e.g. https://provider/csc/v2/.");
            }

            if (remote && CscToken is null && (CscClientId is null || CscClientSecret is null))
            {
                return ValidationResult.Error("--csc-url needs --csc-token, or --csc-client-id and --csc-client-secret.");
            }

            (string Option, string? Value)[] ofTheOther = remote
                ? [("--pkcs11-token", Pkcs11Token), ("--pkcs11-key", Pkcs11Key), ("--module-manufacturer", ModuleManufacturer),
                    ("--module-model", ModuleModel), ("--module-certification", ModuleCertification), ("--module-certificate", ModuleCertificate)]
                : [("--csc-credential", CscCredential), ("--csc-token", CscToken), ("--csc-client-id", CscClientId),
                    ("--csc-client-secret", CscClientSecret), ("--service-provider", ServiceProvider), ("--service-name", ServiceName),
                    ("--service-accreditation", ServiceAccreditation), ("--service-reference", ServiceReference)];
            if (ofTheOther.FirstOrDefault(o => o.Value is not null) is { Option: not null } stray)
            {
                return ValidationResult.Error($"{stray.Option} goes with {(remote ? "--pkcs11-lib" : "--csc-url")}.");
            }

            if (Transaction!.Split('/', 2) is not [{ Length: > 0 }, { Length: > 0 }])
            {
                return ValidationResult.Error("--transaction is type/id, e.g. factura/F001-123.");
            }

            if (Allowed.Length == 0)
            {
                return ValidationResult.Error("--allow is required: the kinds of transaction this agent signs for.");
            }

            if ((Tsa is null) != (TsaCertificate is null))
            {
                return ValidationResult.Error("--tsa and --tsa-cert go together.");
            }

            if (Format is not (null or "pdf" or "xml" or "cms"))
            {
                return ValidationResult.Error("--format is pdf, xml or cms.");
            }

            return ValidateContingency(ContingencyReference, ContingencyUntil);
        }
    }

    /// <inheritdoc />
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        string format = settings.Format ?? Path.GetExtension(settings.Input).ToUpperInvariant() switch
        {
            ".PDF" => "pdf",
            ".XML" => "xml",
            _ => "cms",
        };
        string[] transaction = settings.Transaction!.Split('/', 2);
        byte[] input = await File.ReadAllBytesAsync(settings.Input, cancellationToken);
        using var audit = new JsonLinesAuditSink(settings.AuditLog!);
        using X509Certificate2? tsaCertificate = settings.TsaCertificate is null ? null : IofeTrustSettings.LoadCertificate(settings.TsaCertificate);
        try
        {
            await using var agent = await IofeSigningAgent.OpenAsync(
                new IofeSigningAgentOptions
                {
                    Module = settings.CscUrl is not null ? null : new Pkcs11SignerOptions
                    {
                        LibraryPath = settings.Pkcs11Library!,
                        TokenLabel = settings.Pkcs11Token,
                        KeyLabel = settings.Pkcs11Key,
                        Pin = await IofeCliExtension.Context.ResolvePinAsync(settings.Pin).ConfigureAwait(false),
                    },
                    ModuleDeclaration = settings.CscUrl is not null ? null : new IofeModuleDeclaration(
                        settings.ModuleManufacturer!, settings.ModuleModel!, settings.ModuleCertification!, settings.ModuleCertificate!),
                    RemoteService = settings.CscUrl is null ? null : new IofeRemoteService
                    {
                        Service = new CscClientOptions
                        {
                            BaseUri = new Uri(settings.CscUrl.TrimEnd('/') + "/"),
                            AccessToken = IofeCliExtension.Context.ResolveSecret(settings.CscToken),
                            ClientId = settings.CscClientId,
                            ClientSecret = IofeCliExtension.Context.ResolveSecret(settings.CscClientSecret),
                        },
                        CredentialId = settings.CscCredential!,
                        Pin = IofeCliExtension.Context.ResolveSecret(settings.Pin),
                    },
                    RemoteServiceDeclaration = settings.CscUrl is null ? null : new IofeRemoteServiceDeclaration(
                        settings.ServiceProvider!, settings.ServiceName!, settings.ServiceAccreditation!, settings.ServiceReference!),
                    Audit = audit,
                    Transactions = settings.Allowed,
                    Trust = await settings.TrustAsync(cancellationToken),
                    Timestamp = tsaCertificate is null ? null : new IofeTimestampAuthority(new Uri(settings.Tsa!), tsaCertificate),
                    Contingency = IofeTrustSettings.Contingency(settings.ContingencyReference, settings.ContingencyUntil),
                    HttpClientProvider = IofeCliExtension.Context.HttpClientProvider,
                },
                cancellationToken);

            var operation = new IofeTransaction(transaction[0], transaction[1]);
            var signed = format switch
            {
                "pdf" => await agent.SignPdfAsync(input, operation, cancellationToken),
                "xml" => await agent.SignXmlAsync(input, operation, cancellationToken),
                _ => await agent.SignCmsAsync(input, operation, settings.Detached, cancellationToken),
            };
            await File.WriteAllBytesAsync(settings.Output!, signed.Document, cancellationToken);

            AnsiConsole.MarkupLine($"[green]✓ Signed:[/] {settings.Output!.EscapeMarkup()}");
            AnsiConsole.MarkupLine($"  Signer       {signed.SignerSubject.EscapeMarkup()}");
            AnsiConsole.MarkupLine($"  Level        {signed.Level}{(signed.Timestamped ? " (time-stamped)" : "")}");
            AnsiConsole.MarkupLine($"  Transaction  {signed.OperationId.EscapeMarkup()}");
            AnsiConsole.MarkupLine($"  Policy       {signed.PolicyName.EscapeMarkup()}");
            if (agent.Module is { } module)
            {
                AnsiConsole.MarkupLine($"  Module       {module.Manufacturer.EscapeMarkup()} / {module.Model.EscapeMarkup()} (serial {module.SerialNumber.EscapeMarkup()}), "
                    + $"{module.Declaration.Certification.EscapeMarkup()} #{module.Declaration.CertificateNumber.EscapeMarkup()}");
                AnsiConsole.MarkupLine($"  Key          sensitive: {module.KeyProtection.Sensitive}, extractable: {module.KeyProtection.Extractable}, "
                    + $"generated on the module: {module.KeyProtection.GeneratedOnToken}, hardware slot: {module.KeyProtection.HardwareSlot}");
            }
            else if (agent.RemoteService is { } service)
            {
                AnsiConsole.MarkupLine($"  Service      {service.Name.EscapeMarkup()} ({service.BaseUri.AbsoluteUri.EscapeMarkup()}), {service.Declaration.Provider.EscapeMarkup()}: "
                    + $"{service.Declaration.Accreditation.EscapeMarkup()} #{service.Declaration.AccreditationReference.EscapeMarkup()}");
                AnsiConsole.MarkupLine($"  Key          in the remote service: credential {service.CredentialId.EscapeMarkup()}, authorization {service.AuthMode.EscapeMarkup()}, SCAL {service.Scal.EscapeMarkup()}");
            }

            AnsiConsole.MarkupLine($"  Audit        {settings.AuditLog!.EscapeMarkup()}");
            return 0;
        }
        catch (IofeAccreditationException ex)
        {
            return IofeTrustSettings.Refused(ex);
        }
    }
}

/// <summary>Verifies as the automated agent of INDECOPI's guide, section 4.3 (<see cref="IofeVerificationAgent"/>).</summary>
[Description("Verify a received document as an automated agent under INDECOPI's accreditation guide (section 4.3)")]
internal sealed class IofeVerifyCommand : AsyncCommand<IofeVerifyCommand.Settings>
{
    /// <summary>The settings of <c>iofe verify</c>.</summary>
    internal sealed class Settings : IofeTrustSettings
    {
        /// <summary>The document received.</summary>
        [CommandArgument(0, "<input>")]
        [Description("The signed document received (PDF, XML or CMS)")]
        public string Input { get; init; } = "";

        /// <summary>Who sent it.</summary>
        [CommandOption("--sender <ID>")]
        [Description("Who sent the document (e.g. a RUC)")]
        public string? Sender { get; init; }

        /// <summary>Where a notice reaches the sender.</summary>
        [CommandOption("--contact <ADDRESS>")]
        [Description("Where a notice reaches the sender")]
        public string? Contact { get; init; }

        /// <summary>The reference of the reception.</summary>
        [CommandOption("--reference <TEXT>")]
        [Description("The reference of this reception; goes to the audit trail and the notice")]
        public string? Reference { get; init; }

        /// <summary>The signed content of a detached signature.</summary>
        [CommandOption("--detached <FILE>")]
        [Description("The signed content of a detached CMS or XML signature")]
        public string? Detached { get; init; }

        /// <summary>The audit trail.</summary>
        [CommandOption("--audit-log <FILE>")]
        [Description("The audit trail of the verifications (check it with 'simplesign audit verify')")]
        public string? AuditLog { get; init; }

        /// <summary>Where the notice of a rejected document is written.</summary>
        [CommandOption("--notice <FILE>")]
        [Description("Where the notice to the sender is written when the document is rejected")]
        public string? Notice { get; init; }

        /// <summary>Where the report page is written.</summary>
        [CommandOption("--html-report <FILE>")]
        [Description("Write the validation report as a page in Spanish")]
        public string? HtmlReport { get; init; }

        /// <summary>Where the ETSI report is written.</summary>
        [CommandOption("--etsi-report <FILE>")]
        [Description("Write the ETSI TS 119 102-2 validation report (XML)")]
        public string? EtsiReport { get; init; }

        /// <summary>The procedure of a declared contingency.</summary>
        [CommandOption("--contingency <REFERENCE>")]
        [Description("Verify under a contingency: the procedure INDECOPI approved (goes to the audit trail)")]
        public string? ContingencyReference { get; init; }

        /// <summary>When the contingency ends.</summary>
        [CommandOption("--contingency-until <DATETIME>")]
        [Description("When the contingency ends (ISO 8601, UTC when no offset is given)")]
        public string? ContingencyUntil { get; init; }

        /// <inheritdoc />
        public override ValidationResult Validate()
        {
            if (!File.Exists(Input))
            {
                return ValidationResult.Error($"File not found: {Input}");
            }

            (string Option, string? Value)[] required = [("--sender", Sender), ("--audit-log", AuditLog), ("--notice", Notice)];
            if (required.FirstOrDefault(r => string.IsNullOrWhiteSpace(r.Value)) is { Option: not null } missing)
            {
                return ValidationResult.Error($"{missing.Option} is required.");
            }

            return Detached is not null && !File.Exists(Detached)
                ? ValidationResult.Error($"File not found: {Detached}")
                : ValidateContingency(ContingencyReference, ContingencyUntil);
        }
    }

    /// <inheritdoc />
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] input = await File.ReadAllBytesAsync(settings.Input, cancellationToken);
        byte[]? detached = settings.Detached is null ? null : await File.ReadAllBytesAsync(settings.Detached, cancellationToken);
        using var audit = new JsonLinesVerificationAuditSink(settings.AuditLog!);
        try
        {
            await using var agent = await IofeVerificationAgent.CreateAsync(
                new IofeVerificationAgentOptions
                {
                    Audit = audit,
                    Notifier = new FileNotifier(settings.Notice!),
                    Trust = await settings.TrustAsync(cancellationToken),
                    Contingency = IofeTrustSettings.Contingency(settings.ContingencyReference, settings.ContingencyUntil),
                    HttpClientProvider = IofeCliExtension.Context.HttpClientProvider,
                },
                cancellationToken);

            var result = await agent.VerifyAsync(
                input,
                new IofeSender(settings.Sender!, settings.Contact),
                new IofeVerificationRequest { DetachedContent = detached, Reference = settings.Reference },
                cancellationToken);

            if (settings.HtmlReport is not null)
            {
                await File.WriteAllTextAsync(settings.HtmlReport, result.ReportHtml, cancellationToken);
            }

            if (settings.EtsiReport is not null && result.EtsiReportXml.Length > 0)
            {
                await File.WriteAllTextAsync(settings.EtsiReport, result.EtsiReportXml, cancellationToken);
            }

            AnsiConsole.MarkupLine(result.Accepted
                ? $"[green]✓ Accepted:[/] {result.Signatures.Count} signature(s), all valid."
                : $"[red]✗ Rejected:[/] the notice to {settings.Sender!.EscapeMarkup()} was written to {settings.Notice!.EscapeMarkup()}");
            AnsiConsole.MarkupLine($"  Document     SHA-256 {result.DocumentSha256}");
            for (int i = 0; i < result.Signatures.Count; i++)
            {
                var signature = result.Signatures[i];
                AnsiConsole.MarkupLine(
                    $"  Signature {i + 1}  {signature.Indication}{(signature.SubIndication is { } sub ? $" ({sub})" : "")} — "
                    + (signature.SignerCertificate?.Subject ?? "unknown signer").EscapeMarkup());
            }

            foreach (string reason in result.Reasons)
            {
                AnsiConsole.MarkupLine($"  [red]•[/] {reason.EscapeMarkup()}");
            }

            AnsiConsole.MarkupLine($"  Audit        {settings.AuditLog!.EscapeMarkup()}");
            return result.Accepted ? 0 : 1;
        }
        catch (IofeAccreditationException ex)
        {
            return IofeTrustSettings.Refused(ex);
        }
    }

    /// <summary>The notifier of the command line: the notice goes to a file, for whatever sends it on.</summary>
    private sealed class FileNotifier(string path) : IIofeSenderNotifier
    {
        public async ValueTask NotifyAsync(IofeRejectionNotice notice, CancellationToken cancellationToken) =>
            await File.WriteAllTextAsync(path, notice.Text, cancellationToken);
    }
}

/// <summary>Writes the viewer page of a signed document (<see cref="IofeViewer"/>).</summary>
[Description("Write the viewer page of a signed document: integrity, signing time, public key and certificate data, in Spanish")]
internal sealed class IofeViewCommand : AsyncCommand<IofeViewCommand.Settings>
{
    /// <summary>The settings of <c>iofe view</c>.</summary>
    internal sealed class Settings : IofeTrustSettings
    {
        /// <summary>The signed document.</summary>
        [CommandArgument(0, "<input>")]
        [Description("The signed document (PDF, XML or CMS)")]
        public string Input { get; init; } = "";

        /// <summary>Where the page is written.</summary>
        [CommandOption("-o|--output <FILE>")]
        [Description("Where the page is written (HTML)")]
        public string? Output { get; init; }

        /// <summary>The signed content of a detached signature.</summary>
        [CommandOption("--detached <FILE>")]
        [Description("The signed content of a detached CMS or XML signature")]
        public string? Detached { get; init; }

        /// <inheritdoc />
        public override ValidationResult Validate() =>
            !File.Exists(Input) ? ValidationResult.Error($"File not found: {Input}")
            : string.IsNullOrWhiteSpace(Output) ? ValidationResult.Error("--output is required.")
            : Detached is not null && !File.Exists(Detached) ? ValidationResult.Error($"File not found: {Detached}")
            : ValidationResult.Success();
    }

    /// <inheritdoc />
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] input = await File.ReadAllBytesAsync(settings.Input, cancellationToken);
        byte[]? detached = settings.Detached is null ? null : await File.ReadAllBytesAsync(settings.Detached, cancellationToken);
        await using var viewer = await IofeViewer.CreateAsync(await settings.TrustAsync(cancellationToken), IofeCliExtension.Context.HttpClientProvider, cancellationToken);
        await File.WriteAllTextAsync(settings.Output!, await viewer.RenderAsync(input, detached, cancellationToken), cancellationToken);
        AnsiConsole.MarkupLine($"[green]✓ Written:[/] {settings.Output!.EscapeMarkup()}");
        return 0;
    }
}
