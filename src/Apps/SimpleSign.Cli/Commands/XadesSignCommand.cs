using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES;
using SimpleSign.XAdES.Constants;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Sign an XML document with XAdES (B-B, B-T, B-LT, B-LTA).</summary>
[Description("Sign an XML document with XAdES (B-B, B-T, B-LT, B-LTA)")]
internal sealed class XadesSignCommand : AsyncCommand<XadesSignCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;

    public XadesSignCommand(ICertificateChainService certChainService)
    {
        _certChainService = certChainService;
    }

    /// <summary>XAdES sign command settings.</summary>
    internal sealed class Settings : TimestampedSigningSettings
    {
        /// <summary>Checks run before signing.</summary>
        [CommandOption("--signing-policy <PATH>")]
        [Description(SigningPolicyOption.Description)]
        public string? SigningPolicy { get; init; }

        /// <summary>Print the result (or the refusal) as one JSON object instead of text.</summary>
        [CommandOption("--json")]
        [Description("Print the result, or the refusal with its reason, as JSON")]
        public bool Json { get; init; }

        /// <summary>XML file to sign.</summary>
        [CommandArgument(0, "<input>")]
        [Description("XML file to sign")]
        public string InputPath { get; init; } = null!;

        /// <summary>PKCS#12 certificate file (.pfx/.p12).</summary>
        [CommandOption("--cert|-c <PATH>")]
        [Description("PKCS#12 certificate file (.pfx/.p12)")]
        public string? CertPath { get; init; }

        /// <summary>Certificate password (omit for interactive prompt).</summary>
        [CommandOption("--password|-p <PASSWORD>")]
        [Description("Certificate password (omit for interactive prompt)")]
        public string? Password { get; init; }

        /// <summary>Output signed XML file (default: input.signed.xml).</summary>
        [CommandOption("--output|-o <PATH>")]
        [Description("Output signed XML file (default: <input>.signed.xml)")]
        public string? OutputPath { get; init; }

        /// <summary>TSA URL for timestamp (B-T or higher).</summary>
        [CommandOption("--tsa <URL>")]
        [Description("TSA URL for timestamp (B-T or higher)")]
        public string? TsaUrl { get; init; }

        /// <summary>XAdES level: basic, timestamped, longterm, archive (default: basic).</summary>
        [CommandOption("--level <LEVEL>")]
        [Description("XAdES level: basic, timestamped, longterm, archive (default: basic)")]
        public string? Level { get; init; }

        /// <summary>Hash algorithm: SHA256, SHA384, SHA512 (default: SHA256).</summary>
        [CommandOption("--hash|-H <ALGO>")]
        [Description("Hash algorithm: SHA256, SHA384, SHA512 (default: SHA256)")]
        public string? HashAlgorithm { get; init; }

        /// <summary>Commitment type: ProofOfOrigin, ProofOfReceipt, ProofOfDelivery, ProofOfSender, ProofOfApproval, ProofOfCreation.</summary>
        [CommandOption("--commitment <TYPE>")]
        [Description("Commitment type: ProofOfOrigin, ProofOfReceipt, ProofOfDelivery, ProofOfSender, ProofOfApproval, ProofOfCreation")]
        public string? Commitment { get; init; }

        /// <summary>Signature policy OID.</summary>
        [CommandOption("--policy-oid <OID>")]
        [Description("Signature policy OID")]
        public string? PolicyOid { get; init; }

        /// <summary>Signature policy URI.</summary>
        [CommandOption("--policy-uri <URI>")]
        [Description("Signature policy URI")]
        public string? PolicyUri { get; init; }

        /// <summary>Claimed signer role (may be specified multiple times).</summary>
        [CommandOption("--signer-role <ROLE>")]
        [Description("Claimed signer role (may be specified multiple times)")]
        public string[]? SignerRoles { get; init; }

        /// <summary>PEM/DER file with intermediate CA certificates.</summary>
        [CommandOption("--chain <PATH>")]
        [Description("PEM/DER file with intermediate CA certificates")]
        public string? ChainPath { get; init; }

        /// <summary>XAdES form: enveloped, detached, enveloping (default: enveloped).</summary>
        [CommandOption("--form <FORM>")]
        [Description("XAdES form: enveloped, detached, enveloping (default: enveloped)")]
        public string? Form { get; init; }

        /// <summary>Data URI for Detached form (e.g., 'document.xml'). Required when --form detached.</summary>
        [CommandOption("--data-uri <URI>")]
        [Description("Data URI for Detached form (e.g., 'document.xml'). Required when --form detached.")]
        public string? DataUri { get; init; }

        /// <summary>Production place: city.</summary>
        [CommandOption("--place-city <TEXT>")]
        [Description("Where the signature was produced: city")]
        public string? PlaceCity { get; init; }

        /// <summary>Production place: street address.</summary>
        [CommandOption("--place-street <TEXT>")]
        [Description("Where the signature was produced: street address")]
        public string? PlaceStreet { get; init; }

        /// <summary>Production place: state or province.</summary>
        [CommandOption("--place-state <TEXT>")]
        [Description("Where the signature was produced: state or province")]
        public string? PlaceState { get; init; }

        /// <summary>Production place: postal code.</summary>
        [CommandOption("--place-postal-code <TEXT>")]
        [Description("Where the signature was produced: postal code")]
        public string? PlacePostalCode { get; init; }

        /// <summary>Production place: country.</summary>
        [CommandOption("--place-country <TEXT>")]
        [Description("Where the signature was produced: country")]
        public string? PlaceCountry { get; init; }

        /// <summary>Canonicalization: exclusive (default) or inclusive.</summary>
        [CommandOption("--canonicalization <ALGO>")]
        [Description("Canonicalization: exclusive (default) or inclusive (Canonical XML 1.0)")]
        public string? Canonicalization { get; init; }

        /// <summary>Revocation source tried first at longterm/archive: ocsp (default) or crl.</summary>
        [CommandOption("--revocation-preference <SOURCE>")]
        [Description("Revocation source tried first at longterm/archive: ocsp (default) or crl")]
        public string? RevocationPreference { get; init; }

        /// <summary>Policy document: hashed into the policy identifier and embedded in the SignaturePolicyStore.</summary>
        [CommandOption("--policy-document <PATH>")]
        [Description("Policy document: its SHA-256 goes in the policy identifier and the file is embedded in the signature (SignaturePolicyStore)")]
        public string? PolicyDocumentPath { get; init; }

        /// <summary>OID or URI of the specification that defines the policy document's syntax.</summary>
        [CommandOption("--policy-specification <OID|URI>")]
        [Description("OID or URI of the specification that defines the policy document's syntax (with --policy-document)")]
        public string? PolicySpecification { get; init; }

        /// <summary>Timestamp the signed data before signing (AllDataObjectsTimeStamp, requires --tsa).</summary>
        [CommandOption("--data-objects-timestamp")]
        [Description("Timestamp the signed data before signing (AllDataObjectsTimeStamp, requires --tsa)")]
        public bool DataObjectsTimestamp { get; init; }

        /// <summary>X.509 attribute certificate file (DER), a certified signer role.</summary>
        [CommandOption("--attribute-certificate <PATH>")]
        [Description("X.509 attribute certificate (DER) certifying a signer role (may be specified multiple times)")]
        public string[]? AttributeCertificates { get; init; }

        /// <summary>Signed assertion file (XML, e.g. SAML) about the signer.</summary>
        [CommandOption("--signed-assertion <PATH>")]
        [Description("Signed assertion about the signer, an XML file such as a SAML assertion (may be specified multiple times)")]
        public string[]? SignedAssertions { get; init; }

        /// <summary>File signed together with the document and embedded in the signature.</summary>
        [CommandOption("--embed-object <PATH[,MIME]>")]
        [Description("File signed together with the document and embedded in the signature (may be specified multiple times)")]
        public string[]? EmbeddedObjects { get; init; }

        /// <summary>File signed together with the document and referenced by URI.</summary>
        [CommandOption("--external-object <URI=PATH[,MIME]>")]
        [Description("File signed together with the document and referenced by its URI (may be specified multiple times)")]
        public string[]? ExternalObjects { get; init; }

        /// <summary>Countersign a signature of the signed XML given as input.</summary>
        [CommandOption("--countersign")]
        [Description("Countersign a signature of <input>, an already signed XML (levels basic and timestamped)")]
        public bool CounterSign { get; init; }

        /// <summary>Id of the signature to countersign.</summary>
        [CommandOption("--countersign-id <ID>")]
        [Description("Id of the ds:Signature to countersign (with --countersign; optional when there is a single signature)")]
        public string? CounterSignatureId { get; init; }

        public override ValidationResult Validate()
        {
            if (!SigningPolicyOption.IsValid(SigningPolicy))
            {
                return ValidationResult.Error(SigningPolicyOption.Error(SigningPolicy));
            }

            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (ValidateExtras() is { } extrasError)
            {
                return ValidationResult.Error(extrasError);
            }

            if (CertPath is not null && !File.Exists(CertPath))
            {
                return ValidationResult.Error($"Certificate file not found: {CertPath}");
            }

            if (Level is not null && ParseLevel(Level) is null)
            {
                return ValidationResult.Error($"Invalid level: {Level}. Valid: basic, timestamped, longterm, archive");
            }

            if (HashAlgorithm is not null && ParseHashAlgorithm(HashAlgorithm) is null)
            {
                return ValidationResult.Error($"Invalid hash algorithm: {HashAlgorithm}. Valid: SHA256, SHA384, SHA512");
            }

            if (Form is not null && ParseForm(Form) is null)
            {
                return ValidationResult.Error($"Invalid form: {Form}. Valid: enveloped, detached, enveloping");
            }

            var parsedForm = ParseForm(Form) ?? XadesForm.Enveloped;
            if (parsedForm == XadesForm.Detached && string.IsNullOrWhiteSpace(DataUri))
            {
                return ValidationResult.Error("--data-uri is required when using --form detached");
            }

            return ValidationResult.Success();
        }

        private string? ValidateExtras()
        {
            if (Canonicalization is not null && ParseCanonicalization(Canonicalization) is null)
            {
                return $"Invalid canonicalization: {Canonicalization}. Valid: exclusive, inclusive";
            }

            if (DataObjectsTimestamp && TsaUrl is null)
            {
                return "--data-objects-timestamp requires --tsa";
            }

            if (ValidateTsaCredentials(TsaUrl) is { } tsaError)
            {
                return tsaError;
            }

            if (CounterSignatureId is not null && !CounterSign)
            {
                return "--countersign-id is used with --countersign";
            }

            if (ExternalObjects?.FirstOrDefault(o => AdesOptionSupport.SplitUriAndPath(o) is null) is { } malformed)
            {
                return $"Invalid --external-object: {malformed}. Expected URI=PATH[,MIME]";
            }

            return AdesOptionSupport.ValidateRevocationPreference(RevocationPreference)
                ?? AdesOptionSupport.ValidatePolicyDocument(PolicyOid, PolicyDocumentPath, PolicySpecification)
                ?? AdesOptionSupport.ValidateFiles("--attribute-certificate", AttributeCertificates)
                ?? AdesOptionSupport.ValidateFiles("--signed-assertion", SignedAssertions)
                ?? AdesOptionSupport.ValidateFiles("--embed-object", EmbeddedObjects?.Select(o => AdesOptionSupport.SplitPathAndMimeType(o).Path))
                ?? AdesOptionSupport.ValidateFiles("--external-object", ExternalObjects?.Select(o => AdesOptionSupport.SplitUriAndPath(o)!.Value.Path));
        }
    }

    public override async Task<int> ExecuteAsync(
        CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        SignJson.Enabled = settings.Json;
        byte[] xmlData = await CommonSettings.ReadInputBytesAsync(settings.InputPath, cancellationToken);

        using X509Certificate2 cert = await LoadCertificateAsync(settings, cancellationToken);

        var level = ParseLevel(settings.Level) ?? AdesBaselineLevel.Basic;
        var hashAlg = ParseHashAlgorithm(settings.HashAlgorithm) ?? HashAlgorithmName.SHA256;
        var form = ParseForm(settings.Form) ?? XadesForm.Enveloped;
        var commitment = settings.Commitment is not null ? ParseCommitment(settings.Commitment) : null;

        var logger = settings.CreateLogger<XadesSignCommand>();
        var builder = settings.CounterSign
            ? XadesSigner.CounterSign(xmlData, settings.CounterSignatureId).WithCertificate(cert).WithHashAlgorithm(hashAlg)
            : XadesSigner.Document(xmlData).WithCertificate(cert).WithHashAlgorithm(hashAlg).WithForm(form);

        if (logger is not null)
        {
            builder = builder.WithLogger(logger);
        }

        if (settings.TsaUrl is not null && level >= AdesBaselineLevel.Timestamped)
        {
            builder = builder.WithLevel(BuildBaselineProfile(settings.Timestamp(settings.TsaUrl), level, settings.RevocationPreference));
        }
        if (settings.DataUri is not null)
        {
            builder = builder.WithDataUri(settings.DataUri);
        }
        if (commitment.HasValue)
        {
            builder = builder.WithCommitmentType(commitment.Value);
        }
        if (settings.PolicyOid is not null && settings.PolicyDocumentPath is not null)
        {
            var (policy, store) = await AdesOptionSupport.LoadPolicyAsync(
                settings.PolicyOid, settings.PolicyUri, settings.PolicyDocumentPath, settings.PolicySpecification!, cancellationToken);
            builder = builder.WithSignaturePolicy(policy).WithSignaturePolicyStore(store);
        }
        else if (settings.PolicyOid is not null)
        {
            builder = builder.WithSignaturePolicy(settings.PolicyOid, settings.PolicyUri);
        }
        if (settings.SignerRoles is { Length: > 0 })
        {
            builder = builder.WithSignerRoles(settings.SignerRoles);
        }

        builder = await ApplyExtrasAsync(builder, settings, cancellationToken);

        if (settings.ChainPath is not null)
        {
            builder = builder.WithCertificate(cert, LoadChainCertificates(settings.ChainPath));
        }

        builder = builder.WithSigningPolicy(SigningPolicyOption.Parse(settings.SigningPolicy));
        if (CliNetwork.IsConfigured)
        {
            builder = builder.WithHttpClientProvider(CliNetwork.Provider);
        }

        var result = await builder.SignWithDetailsAsync(cancellationToken);
        byte[] signed = result.SignedArtifact;

        string outputPath = settings.OutputPath ?? settings.InputPath + ".signed.xml";
        await File.WriteAllBytesAsync(outputPath, signed, cancellationToken);
        if (settings.Json)
        {
            SignJson.WriteSuccess("xades", outputPath, cert.Subject, result);
            return 0;
        }

        AnsiConsole.MarkupLine($"[green]XAdES signature saved to:[/] {outputPath}");

        return 0;
    }

    /// <summary>The options beyond the baseline: place, canonicalization, data timestamp, certified roles, more data objects.</summary>
    private static async Task<XadesSignerBuilder> ApplyExtrasAsync(
        XadesSignerBuilder builder, Settings settings, CancellationToken cancellationToken)
    {
        if (settings.PlaceCity is not null || settings.PlaceStreet is not null || settings.PlaceState is not null
            || settings.PlacePostalCode is not null || settings.PlaceCountry is not null)
        {
            builder = builder.WithSignatureProductionPlace(new SignatureProductionPlace
            {
                City = settings.PlaceCity,
                StreetAddress = settings.PlaceStreet,
                StateOrProvince = settings.PlaceState,
                PostalCode = settings.PlacePostalCode,
                CountryName = settings.PlaceCountry,
            });
        }

        if (ParseCanonicalization(settings.Canonicalization) is { } canonicalization)
        {
            builder = builder.WithCanonicalization(canonicalization);
        }

        if (settings.DataObjectsTimestamp)
        {
            builder = builder.WithDataObjectsTimestamp(settings.Timestamp(settings.TsaUrl!));
        }

        if (settings.AttributeCertificates is { Length: > 0 })
        {
            builder = builder.WithAttributeCertificates(await AdesOptionSupport.ReadFilesAsync(settings.AttributeCertificates, cancellationToken));
        }

        if (settings.SignedAssertions is { Length: > 0 })
        {
            var assertions = new List<string>();
            foreach (string path in settings.SignedAssertions)
            {
                assertions.Add(await File.ReadAllTextAsync(path, cancellationToken));
            }

            builder = builder.WithSignedAssertions(assertions);
        }

        foreach (string value in settings.EmbeddedObjects ?? [])
        {
            var (path, mimeType) = AdesOptionSupport.SplitPathAndMimeType(value);
            builder = builder.WithAdditionalDataObject(XadesDataObject.Embedded(await File.ReadAllBytesAsync(path, cancellationToken), mimeType));
        }

        foreach (string value in settings.ExternalObjects ?? [])
        {
            var (uri, path, mimeType) = AdesOptionSupport.SplitUriAndPath(value)!.Value;
            builder = builder.WithAdditionalDataObject(XadesDataObject.External(uri, await File.ReadAllBytesAsync(path, cancellationToken), mimeType));
        }

        return builder;
    }

    private async Task<X509Certificate2> LoadCertificateAsync(Settings settings, CancellationToken ct)
    {
        if (settings.CertPath is not null)
        {
            string? password = settings.Password;
            password ??= await PasswordResolver.ResolveAsync(password, isInteractive: true);

            return _certChainService.LoadPkcs12FromFile(settings.CertPath, password);
        }

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var certs = store.Certificates
            .Find(X509FindType.FindByTimeValid, DateTimeOffset.UtcNow, validOnly: true)
            .Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DigitalSignature, validOnly: false);

        return certs.Count > 0
            ? certs[0]
            : throw new InvalidOperationException("No certificate found. Use --cert to specify a PFX file.");
    }

    private IReadOnlyList<X509Certificate2> LoadChainCertificates(string chainPath)
    {
        byte[] raw = File.ReadAllBytes(chainPath);
        var certs = _certChainService.LoadCertsFromBytes(raw);
        return certs.ToList().AsReadOnly();
    }

    private static AdesBaselineProfile BuildBaselineProfile(TimestampOptions timestampOptions, AdesBaselineLevel level, string? revocationPreference)
    {
        return level switch
        {
            AdesBaselineLevel.Timestamped => AdesBaselineProfile.Timestamped(timestampOptions),
            AdesBaselineLevel.LongTerm => AdesBaselineProfile.LongTerm(timestampOptions, AdesOptionSupport.LongTermOptions(revocationPreference)),
            _ => AdesBaselineProfile.Archive(timestampOptions, AdesOptionSupport.LongTermOptions(revocationPreference))
        };
    }

    private static XadesCanonicalization? ParseCanonicalization(string? value) => value?.ToLowerInvariant() switch
    {
        "exclusive" or "exc-c14n" => XadesCanonicalization.Exclusive,
        "inclusive" or "c14n" => XadesCanonicalization.Inclusive,
        _ => null
    };

    private static AdesBaselineLevel? ParseLevel(string? level) => level?.ToLowerInvariant() switch
    {
        "basic" or "b-b" => AdesBaselineLevel.Basic,
        "timestamped" or "b-t" => AdesBaselineLevel.Timestamped,
        "longterm" or "b-lt" => AdesBaselineLevel.LongTerm,
        "archive" or "b-lta" => AdesBaselineLevel.Archive,
        _ => null
    };

    private static HashAlgorithmName? ParseHashAlgorithm(string? algo) =>
        HashAlgorithmHelper.TryParse(algo);

    private static CommitmentType? ParseCommitment(string? type) => type?.ToLowerInvariant() switch
    {
        "proofoforigin" or "origin" => CommitmentType.ProofOfOrigin,
        "proofofreceipt" or "receipt" => CommitmentType.ProofOfReceipt,
        "proofofdelivery" or "delivery" => CommitmentType.ProofOfDelivery,
        "proofofsender" or "sender" => CommitmentType.ProofOfSender,
        "proofofapproval" or "approval" => CommitmentType.ProofOfApproval,
        "proofofcreation" or "creation" => CommitmentType.ProofOfCreation,
        _ => null
    };

    private static XadesForm? ParseForm(string? form) => form?.ToLowerInvariant() switch
    {
        "enveloped" => XadesForm.Enveloped,
        "detached" => XadesForm.Detached,
        "enveloping" => XadesForm.Enveloping,
        _ => null
    };
}
