using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Brazil.Signing;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
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
    internal sealed class Settings : ExternalCredentialSettings
    {
        /// <summary>Checks run before signing.</summary>
        [CommandOption("--signing-policy <PATH>")]
        [Description(SigningPolicyOption.Description)]
        public string? SigningPolicy { get; init; }

        /// <summary>Print the result (or the refusal) as one JSON object instead of text.</summary>
        [CommandOption("--json")]
        [Description("Print the result, or the refusal with its reason, as JSON")]
        public bool Json { get; init; }

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

        /// <summary>Revocation source tried first with --ltv/--archival: ocsp (default) or crl.</summary>
        [CommandOption("--revocation-preference <SOURCE>")]
        [Description("Revocation source tried first with --ltv/--archival: ocsp (default) or crl")]
        public string? RevocationPreference { get; init; }

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

        /// <summary>Label above the signer name (default: "Signed by"; empty string hides the line).</summary>
        [CommandOption("--signed-by-label <TEXT>")]
        [Description("Label above the signer name (default: \"Signed by\"; \"\" hides the line)")]
        public string? SignedByLabel { get; init; }

        /// <summary>Prefix of the reason line (default: "Reason: ").</summary>
        [CommandOption("--reason-label <TEXT>")]
        [Description("Prefix of the reason line (default: \"Reason: \")")]
        public string? ReasonLabel { get; init; }

        /// <summary>Prefix of the location line (default: "Location: ").</summary>
        [CommandOption("--location-label <TEXT>")]
        [Description("Prefix of the location line (default: \"Location: \")")]
        public string? LocationLabel { get; init; }

        /// <summary>Prefix of the date line (default: none).</summary>
        [CommandOption("--date-label <TEXT>")]
        [Description("Prefix of the date line (default: none)")]
        public string? DateLabel { get; init; }

        /// <summary>.NET date format for the signing time, e.g. "dd/MM/yyyy HH:mm:ss zzz".</summary>
        [CommandOption("--date-format <FORMAT>")]
        [Description("Date format for the signing time, e.g. \"dd/MM/yyyy HH:mm:ss zzz\"")]
        public string? DateFormat { get; init; }

        /// <summary>Time zone for the signing time: an ID such as America/Sao_Paulo, or an offset such as -03:00.</summary>
        [CommandOption("--time-zone <ZONE>")]
        [Description("Time zone for the date: ID (America/Sao_Paulo) or offset (-03:00). Default: UTC")]
        public string? TimeZone { get; init; }

        /// <summary>Stamp fill color as RGB values 0-1, e.g. 1,1,1.</summary>
        [CommandOption("--background-color <R,G,B>")]
        [Description("Stamp fill color as RGB values 0-1, e.g. 1,1,1")]
        public string? BackgroundColor { get; init; }

        /// <summary>How the background image is scaled: stretch (default), contain or cover.</summary>
        [CommandOption("--image-fit <MODE>")]
        [Description("How the background image is scaled: stretch (default), contain, cover")]
        public string? ImageFit { get; init; }

        /// <summary>Fixed stamp width in points (text shrinks to fit).</summary>
        [CommandOption("--stamp-width <PT>")]
        [Description("Fixed stamp width in points (text shrinks to fit)")]
        public float? StampWidth { get; init; }

        /// <summary>Fixed stamp height in points (text shrinks to fit).</summary>
        [CommandOption("--stamp-height <PT>")]
        [Description("Fixed stamp height in points (text shrinks to fit)")]
        public float? StampHeight { get; init; }

        /// <summary>Text alignment in the stamp: left (default), center or right.</summary>
        [CommandOption("--text-align <ALIGN>")]
        [Description("Text alignment in the stamp: left (default), center, right")]
        public string? TextAlign { get; init; }

        /// <summary>Vertical alignment of the text in the stamp.</summary>
        [CommandOption("--vertical-align <ALIGN>")]
        [Description("Vertical alignment of the text in the stamp: top (default), middle, bottom")]
        public string? VerticalAlign { get; init; }

        /// <summary>Clip the text instead of shrinking it to the stamp.</summary>
        [CommandOption("--no-shrink-to-fit")]
        [Description("Clip the text instead of shrinking it to fit a fixed stamp size")]
        public bool NoShrinkToFit { get; init; }

        /// <summary>Longer stamp texts are cut.</summary>
        [CommandOption("--max-text-length <N>")]
        [Description("Stamp texts longer than this are cut (default 40)")]
        public int? MaxTextLength { get; init; }

        /// <summary>Culture of the date on the stamp.</summary>
        [CommandOption("--date-culture <CULTURE>")]
        [Description("Culture of the date on the stamp, e.g. pt-BR")]
        public string? DateCulture { get; init; }

        /// <summary>Name on the stamp instead of the certificate's common name.</summary>
        [CommandOption("--signer-display-name <NAME>")]
        [Description("Name on the stamp instead of the certificate's common name")]
        public string? SignerDisplayName { get; init; }

        /// <summary>More lines of text on the stamp.</summary>
        [CommandOption("--extra-line <TEXT>")]
        [Description("One more line of text on the stamp (may be specified multiple times)")]
        public string[]? ExtraLines { get; init; }

        /// <summary>Keep the reason off the stamp.</summary>
        [CommandOption("--hide-reason")]
        [Description("Keep the reason off the stamp (it stays in the signature)")]
        public bool HideReason { get; init; }

        /// <summary>Keep the location off the stamp.</summary>
        [CommandOption("--hide-location")]
        [Description("Keep the location off the stamp (it stays in the signature)")]
        public bool HideLocation { get; init; }

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

        /// <summary>ICP-Brasil PAdES signature policy: ad-rb, ad-rt, ad-rc or ad-ra.</summary>
        [CommandOption("--icp-policy <POLICY>")]
        [Description("ICP-Brasil PAdES policy: ad-rb, ad-rt, ad-rc or ad-ra; the version follows the signer's root, and the policy sets the level and the PBAD.PAdES sub-filter (all but ad-rb require --tsa; ad-ra downloads the PA and LPA from the ITI)")]
        public string? IcpPolicy { get; init; }

        /// <summary>VALIDAR health document type.</summary>
        [CommandOption("--health-document <TYPE>")]
        [Description("Health document for VALIDAR: prescricao, atestado, exame or relatorio (requires --registration)")]
        public string? HealthDocument { get; init; }

        /// <summary>Professional registrations, COUNCIL:NUMBER/UF.</summary>
        [CommandOption("--registration <COUNCIL:NUMBER/UF>")]
        [Description("Professional registration for --health-document, e.g. crm:123456/SP (repeatable)")]
        public string[]? Registrations { get; init; }

        /// <summary>The claimed signing time (ISO 8601) instead of now.</summary>
        [CommandOption("--signing-time <TIME>")]
        [Description("Claimed signing time, ISO 8601 (e.g. 2026-11-09T10:00:00-03:00), instead of now")]
        public string? SigningTime { get; init; }

        /// <summary>Document information entries, KEY=VALUE.</summary>
        [CommandOption("--doc-info <KEY=VALUE>")]
        [Description("Entry of the PDF document information dictionary, e.g. Title=Contract (repeatable)")]
        public string[]? DocumentInfo { get; init; }

        /// <summary>Bytes reserved for the CMS in /Contents.</summary>
        [CommandOption("--contents-size <BYTES>")]
        [Description("Bytes reserved for the signature in /Contents (default 16384); raise it for long chains or many revocation values")]
        public int? ContentsSize { get; init; }

        /// <summary>A separate TSA for the archive (document) timestamp. Requires --archival.</summary>
        [CommandOption("--archive-tsa <URL>")]
        [Description("A separate TSA for the archive (document) timestamp; the TSA credentials apply to it too. Requires --archival.")]
        public string? ArchiveTsaUrl { get; init; }

        /// <summary>Return the highest level reached instead of failing.</summary>
        [CommandOption("--return-lower-level")]
        [Description("When a timestamp or the revocation data cannot be obtained, return the highest level reached instead of failing")]
        public bool ReturnLowerLevel { get; init; }

        /// <summary>Hash of the signature policy document (hex). Requires --policy-oid.</summary>
        [CommandOption("--policy-hash <HEX>")]
        [Description("Hash of the signature policy document, hex: signs with an explicit policy (signature-policy-identifier). Requires --policy-oid.")]
        public string? PolicyHash { get; init; }

        /// <summary>Hash algorithm of --policy-hash: SHA256 (default), SHA384, SHA512.</summary>
        [CommandOption("--policy-hash-algorithm <ALGO>")]
        [Description("Hash algorithm of --policy-hash: SHA256 (default), SHA384 or SHA512")]
        public string? PolicyHashAlgorithm { get; init; }

        /// <summary>Signer identifier (metadata), e.g. a document number.</summary>
        [CommandOption("--signer-id <ID>")]
        [Description("Signer identifier for the signature metadata, e.g. a document number")]
        public string? SignerId { get; init; }

        /// <summary>Kind of --signer-id, e.g. CPF, passport.</summary>
        [CommandOption("--signer-id-type <TYPE>")]
        [Description("Kind of --signer-id, e.g. CPF or passport")]
        public string? SignerIdType { get; init; }

        /// <summary>IP address the signer signed from (metadata).</summary>
        [CommandOption("--ip-address <IP>")]
        [Description("IP address the signer signed from, for the signature metadata")]
        public string? IpAddress { get; init; }

        /// <summary>Institution identifier (metadata).</summary>
        [CommandOption("--institution-id <ID>")]
        [Description("Institution identifier for the signature metadata")]
        public string? InstitutionId { get; init; }

        /// <summary>Kind of --institution-id.</summary>
        [CommandOption("--institution-id-type <TYPE>")]
        [Description("Kind of --institution-id, e.g. CNPJ")]
        public string? InstitutionIdType { get; init; }

        /// <summary>Correlation id for the logs.</summary>
        [CommandOption("--operation-id <ID>")]
        [Description("Correlation id written in the logs of this signature")]
        public string? OperationId { get; init; }

        /// <summary>Legal basis of the signature (metadata).</summary>
        [CommandOption("--legal-basis <TEXT>")]
        [Description("Legal basis of the signature, for the signature metadata")]
        public string? LegalBasis { get; init; }

        /// <summary>The level options, as <see cref="PadesProfileOptions"/> takes them.</summary>
        internal PadesProfileOptions.Level LevelOptions => new(TsaUrl, Ltv, Archival, ArchiveTsaUrl, ReturnLowerLevel, RevocationPreference);

        /// <summary>Whether a structured-metadata option was given without --brasil.</summary>
        internal bool HasMetadata => !Brasil && (SignerId ?? SignerIdType ?? IpAddress ?? InstitutionId ?? InstitutionIdType
            ?? LegalBasis ?? SignerEmail ?? Institution ?? AuthMethod ?? Commitment
            ?? (PolicyHash is null ? PolicyOid : null)) is not null;

        public override ValidationResult Validate()
        {
            if (!SigningPolicyOption.IsValid(SigningPolicy))
            {
                return ValidationResult.Error(SigningPolicyOption.Error(SigningPolicy));
            }

            bool hasCertPath = !string.IsNullOrWhiteSpace(CertPath);
            bool hasThumbprint = !string.IsNullOrWhiteSpace(Thumbprint);
            if (ExternalCredentialSupport.Validate(this, hasCertPath || hasThumbprint) is { } externalError)
            {
                return ValidationResult.Error(externalError);
            }

            if (AdesOptionSupport.ValidateRevocationPreference(RevocationPreference) is { } revocationError)
            {
                return ValidationResult.Error(revocationError);
            }

            if (!hasCertPath && !hasThumbprint && !ExternalCredentialSupport.IsRequested(this))
            {
                return ValidationResult.Error("Either --cert, --thumbprint, --pkcs11-lib, --psc-url or --csc-url is required.");
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

            if (Archival && string.IsNullOrWhiteSpace(TsaUrl))
            {
                return ValidationResult.Error("--archival requires --tsa: the signature and archive timestamps come from it.");
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

            if (IcpPolicy is not null)
            {
                var policy = IcpBrasilCliOptions.ParsePolicy(IcpPolicy);
                if (policy is null)
                {
                    return ValidationResult.Error("--icp-policy must be ad-rb, ad-rt, ad-rc or ad-ra.");
                }

                if (policy != IcpBrasilPolicy.AdRb && string.IsNullOrWhiteSpace(TsaUrl))
                {
                    return ValidationResult.Error($"--icp-policy {IcpPolicy.ToLowerInvariant()} requires --tsa (an ICP-Brasil ACT).");
                }

                if (SubFilter is not null)
                {
                    return ValidationResult.Error("--icp-policy sets the PBAD.PAdES sub-filter the ICP-Brasil PAs mandate; remove --sub-filter.");
                }

                if (Ltv || Archival)
                {
                    return ValidationResult.Error("--icp-policy sets the level: use ad-rc or ad-ra for the DSS and document timestamp instead of --ltv/--archival.");
                }

                if (PolicyOid is not null)
                {
                    return ValidationResult.Error("--icp-policy and --policy-oid are mutually exclusive.");
                }
            }

            if (HealthDocument is not null)
            {
                if (IcpBrasilCliOptions.ParseHealthDocument(HealthDocument) is null)
                {
                    return ValidationResult.Error("--health-document must be prescricao, atestado, exame or relatorio.");
                }

                if (Registrations is not { Length: > 0 })
                {
                    return ValidationResult.Error("--health-document requires at least one --registration (e.g. crm:123456/SP).");
                }

                if (ExistingField is not null)
                {
                    return ValidationResult.Error("--health-document cannot be used with --existing-field.");
                }
            }

            foreach (var registration in Registrations ?? [])
            {
                if (IcpBrasilCliOptions.ParseRegistration(registration) is null)
                {
                    return ValidationResult.Error($"--registration '{registration}' must be COUNCIL:NUMBER/UF, e.g. crm:123456/SP.");
                }
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

            if (BackgroundColor is not null && AppearanceBuilder.ParseColor(BackgroundColor) is null)
            {
                return ValidationResult.Error("--background-color must be in format R,G,B with values between 0 and 1.");
            }

            if (TimeZone is not null && AppearanceBuilder.ParseTimeZone(TimeZone) is null)
            {
                return ValidationResult.Error("--time-zone must be a time zone ID (e.g. America/Sao_Paulo) or an offset (e.g. -03:00).");
            }

            if (ImageFit is not null && AppearanceBuilder.ParseImageFit(ImageFit) is null)
            {
                return ValidationResult.Error("--image-fit must be stretch, contain or cover.");
            }

            if (StampWidth is <= 0 || StampHeight is <= 0)
            {
                return ValidationResult.Error("--stamp-width and --stamp-height must be greater than 0.");
            }

            if (TextAlign is not null && AppearanceBuilder.ParseTextAlignment(TextAlign) is null)
            {
                return ValidationResult.Error("--text-align must be left, center or right.");
            }

            if (VerticalAlign is not null && AppearanceBuilder.ParseVerticalAlignment(VerticalAlign) is null)
            {
                return ValidationResult.Error("--vertical-align must be top, middle or bottom.");
            }

            if (MaxTextLength is <= 0)
            {
                return ValidationResult.Error("--max-text-length must be greater than 0.");
            }

            if (DateCulture is not null && !AppearanceBuilder.IsValidCulture(DateCulture))
            {
                return ValidationResult.Error($"Unknown --date-culture '{DateCulture}'.");
            }

            if (DateFormat is not null && !AppearanceBuilder.IsValidDateFormat(DateFormat))
            {
                return ValidationResult.Error("--date-format is not a valid date format.");
            }

            if (FontSize.HasValue || LabelFontSize.HasValue || TextColor is not null
                || Font is not null || BorderColor is not null || BorderWidth.HasValue || NoDate
                || SignedByLabel is not null || ReasonLabel is not null || LocationLabel is not null
                || DateLabel is not null || DateFormat is not null || TimeZone is not null
                || BackgroundColor is not null || ImageFit is not null
                || StampWidth.HasValue || StampHeight.HasValue || TextAlign is not null)
            {
                if (!Visible)
                {
                    return ValidationResult.Error("Appearance options (--font-size, --text-color, etc.) require --visible.");
                }
            }

            if (ValidateExtras() is { } extrasError)
            {
                return ValidationResult.Error(extrasError);
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

        /// <summary>The error for the signing time, document info, policy hash, metadata and TSA options, or null.</summary>
        private string? ValidateExtras()
        {
            if (ValidateTsaCredentials(TsaUrl) is { } tsaError)
            {
                return tsaError;
            }

            if (SigningTime is not null && SignCommandOptions.ParseSigningTime(SigningTime) is null)
            {
                return "--signing-time must be an ISO 8601 date and time, e.g. 2026-11-09T10:00:00-03:00.";
            }

            if ((DocumentInfo ?? []).FirstOrDefault(e => SignCommandOptions.SplitDocumentInfo(e) is null) is { } badEntry)
            {
                return $"--doc-info '{badEntry}' must be KEY=VALUE, e.g. Title=Contract.";
            }

            if (ContentsSize is < 1024 or > 1_048_576)
            {
                return "--contents-size must be between 1024 and 1048576 bytes.";
            }

            if (ArchiveTsaUrl is not null && !Archival)
            {
                return "--archive-tsa requires --archival.";
            }

            if (ReturnLowerLevel && string.IsNullOrWhiteSpace(TsaUrl))
            {
                return "--return-lower-level requires --tsa: only the timestamp and the revocation data can fall short.";
            }

            if (PolicyHashAlgorithm is not null && PolicyHash is null)
            {
                return "--policy-hash-algorithm requires --policy-hash.";
            }

            if (PolicyHash is not null)
            {
                if (PolicyOid is null)
                {
                    return "--policy-hash requires --policy-oid.";
                }

                if (Brasil || IcpPolicy is not null)
                {
                    return "--policy-hash is for an explicit policy; --brasil and --icp-policy set their own.";
                }

                if (SignCommandOptions.ParseHex(PolicyHash) is null)
                {
                    return "--policy-hash must be hexadecimal.";
                }

                if (PolicyHashAlgorithm is not null && SignCommandOptions.PolicyHashOid(PolicyHashAlgorithm) is null)
                {
                    return "--policy-hash-algorithm must be SHA256, SHA384 or SHA512.";
                }
            }

            return HasMetadata && Commitment is not null && SignCommandOptions.ParseCommitment(Commitment) is null
                ? "--commitment must be origin, receipt, delivery, sender, approval or creation."
                : null;
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var loggerFactory = settings.CreateLoggerFactory();
        SignJson.Enabled = settings.Json;

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

    private static AdesBaselineProfile BuildBaselineProfile(Settings settings) =>
        PadesProfileOptions.Build(settings.LevelOptions, settings);

    private async Task<int> ExecuteCertSigningAsync(
        Settings settings, string outputPath, ILoggerFactory? loggerFactory, CancellationToken cancellation)
    {
        ExternalCredential? token = await ExternalCredentialSupport.OpenAsync(settings, cancellation);
        var (cert, chainCerts) = token is null
            ? await LoadSigningCertificateAsync(settings, cancellation)
            : (token.Certificate, [.. token.Chain]);

        try
        {
            byte[] signed = null!;
            bool dssEmbedded = false;
            ISigningResult? details = null;
            async Task SignAsync()
            {
                var pdfBytes = await File.ReadAllBytesAsync(settings.InputPath, cancellation);
                ILogger? logger = loggerFactory?.CreateLogger("SimpleSign.Signing");
                PadesSignerBuilder builder;
                if (token is not null)
                {
                    builder = PadesSigner.Document(pdfBytes).WithExternalSigner(token.Certificate, token.Signer, token.Chain);
                }
                else if (chainCerts.Count > 0)
                {
                    builder = PadesSigner.Document(pdfBytes).WithCertificate(cert, chainCerts);
                }
                else
                {
                    builder = PadesSigner.Document(pdfBytes).WithCertificate(cert);
                }

                if (logger is not null)
                {
                    builder = builder.WithLogger(logger);
                }

                if (settings.TsaUrl is not null)
                {
                    var profile = BuildBaselineProfile(settings);
                    builder = builder.WithLevel(profile);
                }

                if (settings.Hash is not null)
                {
                    builder = builder.WithHashAlgorithm(SignCommandOptions.ParseHash(settings.Hash));
                }

                // Metadata is applied before partial field configuration so the latter can
                // retain it through their immutable updates.
                if (settings.Reason is not null || settings.Location is not null
                    || settings.Contact is not null || settings.SignerName is not null || settings.ContentsSize is not null)
                {
                    builder = builder.WithFieldOptions(new SignatureFieldOptions
                    {
                        SignerName = settings.SignerName,
                        Reason = settings.Reason,
                        Location = settings.Location,
                        ContactInfo = settings.Contact,
                        ContentsReservedBytes = settings.ContentsSize ?? PdfSignatureWriter.DefaultContentsReservedBytes,
                    });
                }

                if (settings.HasMetadata)
                {
                    builder = builder.WithMetadata(new SignatureMetadata
                    {
                        SignerName = settings.SignerName ?? cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                        SignerId = settings.SignerId,
                        SignerIdType = settings.SignerIdType,
                        Email = settings.SignerEmail,
                        IpAddress = settings.IpAddress,
                        AuthenticationMethod = settings.AuthMethod,
                        InstitutionName = settings.Institution,
                        InstitutionId = settings.InstitutionId,
                        InstitutionIdType = settings.InstitutionIdType,
                        CommitmentType = SignCommandOptions.ParseCommitment(settings.Commitment) ?? CommitmentType.ProofOfApproval,
                        LegalBasis = settings.LegalBasis,
                        PolicyOid = settings.PolicyHash is null ? settings.PolicyOid : null,
                        PolicyUri = settings.PolicyHash is null ? settings.PolicyUri : null,
                        Reason = settings.Reason,
                        Location = settings.Location,
                        ContactInfo = settings.Contact,
                    });
                }

                if (settings.PolicyHash is not null)
                {
                    builder = builder.WithSignaturePolicy(new SignaturePolicyReference(
                        settings.PolicyOid!,
                        SignCommandOptions.PolicyHashOid(settings.PolicyHashAlgorithm ?? "SHA256")!,
                        SignCommandOptions.ParseHex(settings.PolicyHash)!,
                        settings.PolicyUri));
                }

                if (SignCommandOptions.ParseSigningTime(settings.SigningTime) is { } signingTime)
                {
                    builder = builder.WithSigningTime(signingTime);
                }

                foreach (var entry in settings.DocumentInfo ?? [])
                {
                    var (key, value) = SignCommandOptions.SplitDocumentInfo(entry)!.Value;
                    builder = builder.WithDocumentInfo(key, value);
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
                        noDate: settings.NoDate,
                        text: new AppearanceTextOptions(
                            settings.SignedByLabel, settings.ReasonLabel, settings.LocationLabel,
                            settings.DateLabel, settings.DateFormat, settings.TimeZone),
                        backgroundColor: settings.BackgroundColor,
                        imageFit: settings.ImageFit,
                        layout: new AppearanceLayoutOptions(settings.StampWidth, settings.StampHeight, settings.TextAlign),
                        extra: new AppearanceExtraOptions(settings.VerticalAlign, settings.NoShrinkToFit, settings.MaxTextLength, settings.DateCulture,
                            settings.SignerDisplayName, settings.ExtraLines, settings.HideReason, settings.HideLocation));

                    if (settings.Brasil)
                    {
                        appearance = AppearanceBuilder.AddAeaExtraLines(
                            appearance, settings.SignerName!, settings.Cpf!);
                    }

                    builder = builder.WithAppearance(appearance);
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

                // ICP-Brasil policy: version by the signer's root, PBAD.PAdES, and the level the policy needs.
                if (IcpBrasilCliOptions.ParsePolicy(settings.IcpPolicy) is { } icpPolicy)
                {
                    IcpBrasilPolicyArtifacts? artifacts = null;
                    if (icpPolicy == IcpBrasilPolicy.AdRa)
                    {
                        using var http = new HttpClient();
                        artifacts = await IcpBrasilPolicyArtifacts.DownloadAsync(
                            http, builder.ResolveIcpBrasilPolicy(icpPolicy), cancellation);
                    }

                    builder = builder.WithIcpBrasilPolicy(icpPolicy, new IcpBrasilPadesOptions
                    {
                        Timestamp = settings.TsaUrl is null ? null : settings.Timestamp(settings.TsaUrl),
                        Artifacts = artifacts,
                    });
                }

                if (IcpBrasilCliOptions.ParseHealthDocument(settings.HealthDocument) is { } healthDocument)
                {
                    builder = builder.WithHealthDocument(
                        healthDocument,
                        [.. (settings.Registrations ?? []).Select(r => IcpBrasilCliOptions.ParseRegistration(r)!)]);
                }

                if (settings.OperationId is not null)
                {
                    builder = builder.WithOperationId(settings.OperationId);
                }

                builder = builder.WithSigningPolicy(SigningPolicyOption.Parse(settings.SigningPolicy));
                if (CliNetwork.IsConfigured)
                {
                    builder = builder.WithHttpClientProvider(CliNetwork.Provider);
                }

                var result = await builder.SignWithDetailsAsync(cancellation);
                signed = result.SignedArtifact;
                dssEmbedded = result.HasLongTermValidationMaterial;
                details = result;
            }

            if (settings.Json)
            {
                await SignAsync();
            }
            else
            {
                await AnsiConsole.Status()
                    .Spinner(Spinner.Known.Dots)
                    .SpinnerStyle(Style.Parse("blue"))
                    .StartAsync("Signing...", async _ => await SignAsync());
            }

            await File.WriteAllBytesAsync(outputPath, signed, cancellation);
            if (settings.Json)
            {
                SignJson.WriteSuccess("pades", outputPath, cert.Subject, details!);
                return 0;
            }

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
            if (token is not null)
            {
                token.Dispose();
            }
            else
            {
                cert.Dispose();
                foreach (var c in chainCerts)
                {
                    c.Dispose();
                }
            }
        }
    }

}
