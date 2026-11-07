using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.CAdES;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Sign data with CAdES (CMS/PKCS#7 signature).</summary>
[Description("Sign data with CAdES (CMS/PKCS#7 signature)")]
internal sealed class CadesSignCommand : AsyncCommand<CadesSignCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;

    public CadesSignCommand(ICertificateChainService certChainService)
    {
        _certChainService = certChainService;
    }

    /// <summary>CAdES sign command settings.</summary>
    internal sealed class Settings : ExternalCredentialSettings
    {
        /// <summary>Checks run before signing.</summary>
        [CommandOption("--signing-policy <POLICY>")]
        [Description(SigningPolicyOption.Description)]
        public string? SigningPolicy { get; init; }

        /// <summary>Print the result (or the refusal) as one JSON object instead of text.</summary>
        [CommandOption("--json")]
        [Description("Print the result, or the refusal with its reason, as JSON")]
        public bool Json { get; init; }

        /// <summary>Input data file to sign.</summary>
        [CommandArgument(0, "<input>")]
        [Description("Input data file to sign")]
        public string InputPath { get; init; } = null!;

        /// <summary>PKCS#12 certificate file (.pfx/.p12).</summary>
        [CommandOption("--cert|-c <PATH>")]
        [Description("PKCS#12 certificate file (.pfx/.p12)")]
        public string? CertPath { get; init; }

        /// <summary>Certificate password (omit for interactive prompt).</summary>
        [CommandOption("--password|-p <PASSWORD>")]
        [Description("Certificate password (omit for interactive prompt)")]
        public string? Password { get; init; }

        /// <summary>Output signature file (default: input.p7s).</summary>
        [CommandOption("--output|-o <PATH>")]
        [Description("Output signature file (default: <input>.p7s)")]
        public string? OutputPath { get; init; }

        /// <summary>TSA URL for timestamp (CAdES-B-T or higher).</summary>
        [CommandOption("--tsa <URL>")]
        [Description("TSA URL for timestamp (CAdES-B-T or higher)")]
        public string? TsaUrl { get; init; }

        /// <summary>CAdES conformance level: basic, timestamped, longterm, archive (default: basic).</summary>
        [CommandOption("--level <LEVEL>")]
        [Description("CAdES conformance level: basic, timestamped, longterm, archive (default: basic)")]
        public string? Level { get; init; }

        /// <summary>Hash algorithm: SHA256, SHA384, SHA512 (default: SHA256).</summary>
        [CommandOption("--hash|-H <ALGO>")]
        [Description("Hash algorithm: SHA256, SHA384, SHA512 (default: SHA256)")]
        public string? HashAlgorithm { get; init; }

        /// <summary>Commitment type: ProofOfOrigin, ProofOfApproval.</summary>
        [CommandOption("--commitment <TYPE>")]
        [Description("Commitment type: ProofOfOrigin, ProofOfApproval")]
        public string? Commitment { get; init; }

        /// <summary>Signature policy OID.</summary>
        [CommandOption("--policy-oid <OID>")]
        [Description("Signature policy OID")]
        public string? PolicyOid { get; init; }

        /// <summary>Signature policy URI.</summary>
        [CommandOption("--policy-uri <URI>")]
        [Description("Signature policy URI")]
        public string? PolicyUri { get; init; }

        /// <summary>PEM/DER file with intermediate CA certificates.</summary>
        [CommandOption("--chain <PATH>")]
        [Description("PEM/DER file with intermediate CA certificates")]
        public string? ChainPath { get; init; }

        /// <summary>Content type: detached (.p7s, default) or enveloped (.p7m).</summary>
        [CommandOption("--content-type <TYPE>")]
        [Description("Content type: detached (.p7s, default) or enveloped (.p7m)")]
        public string? ContentType { get; init; }

        /// <summary>Signer location: country.</summary>
        [CommandOption("--signer-country <TEXT>")]
        [Description("Where the signer was (signer-location): country, such as BR")]
        public string? SignerCountry { get; init; }

        /// <summary>Signer location: locality.</summary>
        [CommandOption("--signer-locality <TEXT>")]
        [Description("Where the signer was (signer-location): locality, such as a city")]
        public string? SignerLocality { get; init; }

        /// <summary>Signer location: one line of the postal address.</summary>
        [CommandOption("--signer-postal-address <LINE>")]
        [Description("Where the signer was (signer-location): one line of the postal address (up to six)")]
        public string[]? SignerPostalAddress { get; init; }

        /// <summary>Claimed signer role (may be specified multiple times).</summary>
        [CommandOption("--signer-role <ROLE>")]
        [Description("Claimed signer role (may be specified multiple times)")]
        public string[]? SignerRoles { get; init; }

        /// <summary>X.509 attribute certificate file (DER), a certified signer role.</summary>
        [CommandOption("--attribute-certificate <PATH>")]
        [Description("X.509 attribute certificate (DER) certifying a signer role (may be specified multiple times)")]
        public string[]? AttributeCertificates { get; init; }

        /// <summary>Signed SAML assertion file about the signer.</summary>
        [CommandOption("--signed-assertion <PATH>")]
        [Description("Signed SAML assertion about the signer (may be specified multiple times)")]
        public string[]? SignedAssertions { get; init; }

        /// <summary>MIME type of the signed content.</summary>
        [CommandOption("--mime-type <TYPE>")]
        [Description("MIME type of the signed content (mime-type attribute)")]
        public string? MimeType { get; init; }

        /// <summary>Description of the signed content.</summary>
        [CommandOption("--content-description <TEXT>")]
        [Description("Description of the signed content (content-hints attribute)")]
        public string? ContentDescription { get; init; }

        /// <summary>Timestamp the content before signing (requires --tsa).</summary>
        [CommandOption("--content-timestamp")]
        [Description("Timestamp the content before signing (content-time-stamp, requires --tsa)")]
        public bool ContentTimestamp { get; init; }

        /// <summary>Revocation source tried first at longterm/archive: ocsp (default) or crl.</summary>
        [CommandOption("--revocation-preference <SOURCE>")]
        [Description("Revocation source tried first at longterm/archive: ocsp (default) or crl")]
        public string? RevocationPreference { get; init; }

        /// <summary>Policy document: hashed into the policy identifier and embedded in the signature-policy-store.</summary>
        [CommandOption("--policy-document <PATH>")]
        [Description("Policy document: its SHA-256 goes in the policy identifier and the file is embedded in the signature (signature-policy-store)")]
        public string? PolicyDocumentPath { get; init; }

        /// <summary>OID or URI of the specification that defines the policy document's syntax.</summary>
        [CommandOption("--policy-specification <OID|URI>")]
        [Description("OID or URI of the specification that defines the policy document's syntax (with --policy-document)")]
        public string? PolicySpecification { get; init; }

        public override ValidationResult Validate()
        {
            if (!SigningPolicyOption.IsValid(SigningPolicy))
            {
                return ValidationResult.Error($"Unknown --signing-policy '{SigningPolicy}': use default, strict or minimal.");
            }

            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (ContentTimestamp && TsaUrl is null)
            {
                return ValidationResult.Error("--content-timestamp requires --tsa");
            }

            string? extrasError = AdesOptionSupport.ValidateRevocationPreference(RevocationPreference)
                ?? AdesOptionSupport.ValidatePolicyDocument(PolicyOid, PolicyDocumentPath, PolicySpecification)
                ?? AdesOptionSupport.ValidateFiles("--attribute-certificate", AttributeCertificates)
                ?? AdesOptionSupport.ValidateFiles("--signed-assertion", SignedAssertions);
            if (extrasError is not null)
            {
                return ValidationResult.Error(extrasError);
            }

            if (ExternalCredentialSupport.Validate(this, CertPath is not null) is { } externalError)
            {
                return ValidationResult.Error(externalError);
            }

            if (CertPath is not null && !File.Exists(CertPath))
            {
                return ValidationResult.Error($"Certificate file not found: {CertPath}");
            }

            if (Level is not null && !ParseLevel(Level).HasValue)
            {
                return ValidationResult.Error($"Invalid level: {Level}. Valid: basic, timestamped, longterm, archive");
            }

            if (HashAlgorithm is not null && !ParseHashAlgorithm(HashAlgorithm).HasValue)
            {
                return ValidationResult.Error($"Invalid hash algorithm: {HashAlgorithm}. Valid: SHA256, SHA384, SHA512");
            }

            if (ContentType is not null && !ParseContentType(ContentType).HasValue)
            {
                return ValidationResult.Error($"Invalid content type: {ContentType}. Valid: detached, enveloped");
            }

            return ValidationResult.Success();
        }
    }

    public override async Task<int> ExecuteAsync(
        CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        SignJson.Enabled = settings.Json;
        byte[] data = await CommonSettings.ReadInputBytesAsync(settings.InputPath, cancellationToken);

        using ExternalCredential? token = await ExternalCredentialSupport.OpenAsync(settings, cancellationToken);
        using X509Certificate2? ownCert = token is null ? await LoadCertificateAsync(settings, cancellationToken) : null;
        X509Certificate2 cert = token?.Certificate ?? ownCert!;

        var level = ParseLevel(settings.Level) ?? AdesBaselineLevel.Basic;
        var hashAlg = ParseHashAlgorithm(settings.HashAlgorithm) ?? HashAlgorithmName.SHA256;
        var commitment = settings.Commitment is not null ? ParseCommitment(settings.Commitment) : null;
        var contentType = ParseContentType(settings.ContentType) ?? CadesContentType.Detached;

        var logger = settings.CreateLogger<CadesSignCommand>();
        var builder = (token is null
                ? CadesSigner.Document(data).WithCertificate(cert)
                : CadesSigner.Document(data).WithExternalSigner(token.Certificate, token.Signer, token.Chain))
            .WithHashAlgorithm(hashAlg)
            .WithContentType(contentType);

        if (logger is not null)
        {
            builder = builder.WithLogger(logger);
        }

        if (settings.TsaUrl is not null && level >= AdesBaselineLevel.Timestamped)
        {
            var profile = BuildBaselineProfile(settings.TsaUrl, level, settings.RevocationPreference);
            builder = builder.WithLevel(profile);
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

        builder = await ApplyExtrasAsync(builder, settings, cancellationToken);
        if (settings.ChainPath is not null)
        {
            builder = token is null
                ? builder.WithCertificate(cert, LoadChainCertificates(settings.ChainPath))
                : builder.WithExternalSigner(token.Certificate, token.Signer, [.. token.Chain, .. LoadChainCertificates(settings.ChainPath)]);
        }

        builder = builder.WithSigningPolicy(SigningPolicyOption.Parse(settings.SigningPolicy));
        if (CliNetwork.IsConfigured)
        {
            builder = builder.WithHttpClientProvider(CliNetwork.Provider);
        }

        var result = await builder.SignWithDetailsAsync(cancellationToken);
        byte[] cms = result.SignedArtifact;

        string outputPath = settings.OutputPath
            ?? settings.InputPath + (contentType == CadesContentType.Enveloped ? ".p7m" : ".p7s");
        await File.WriteAllBytesAsync(outputPath, cms, cancellationToken);
        if (settings.Json)
        {
            SignJson.WriteSuccess("cades", outputPath, cert.Subject, result);
            return 0;
        }

        AnsiConsole.MarkupLine($"[green]CAdES signature saved to:[/] {outputPath}");

        return 0;
    }

    /// <summary>The signed attributes beyond the baseline: location, roles, content description and timestamp.</summary>
    private static async Task<CadesSignerBuilder> ApplyExtrasAsync(
        CadesSignerBuilder builder, Settings settings, CancellationToken cancellationToken)
    {
        if (settings.SignerCountry is not null || settings.SignerLocality is not null || settings.SignerPostalAddress is { Length: > 0 })
        {
            builder = builder.WithSignerLocation(new CadesSignerLocation
            {
                CountryName = settings.SignerCountry,
                LocalityName = settings.SignerLocality,
                PostalAddress = settings.SignerPostalAddress ?? [],
            });
        }

        if (settings.SignerRoles is { Length: > 0 })
        {
            builder = builder.WithSignerRoles(settings.SignerRoles);
        }

        if (settings.AttributeCertificates is { Length: > 0 })
        {
            builder = builder.WithAttributeCertificates(await AdesOptionSupport.ReadFilesAsync(settings.AttributeCertificates, cancellationToken));
        }

        if (settings.SignedAssertions is { Length: > 0 })
        {
            var files = await AdesOptionSupport.ReadFilesAsync(settings.SignedAssertions, cancellationToken);
            builder = builder.WithSignedAssertions([.. files.Select(file => CadesSignedAssertion.Saml(file.Span))]);
        }

        if (settings.MimeType is not null)
        {
            builder = builder.WithMimeType(settings.MimeType);
        }

        if (settings.ContentDescription is not null)
        {
            builder = builder.WithContentHints(new CadesContentHints { Description = settings.ContentDescription });
        }

        if (settings.ContentTimestamp)
        {
            builder = builder.WithContentTimestamp(new TimestampOptions(new Uri(settings.TsaUrl!), CliNetwork.Provider));
        }

        return builder;
    }

    private static async Task<X509Certificate2> LoadCertificateAsync(Settings settings, CancellationToken ct)
    {
        if (settings.CertPath is not null)
        {
            string? password = settings.Password;
            password ??= await PasswordResolver.ResolveAsync(password, isInteractive: true);

            return new X509Certificate2(settings.CertPath, password, X509KeyStorageFlags.Exportable);
        }

        // Fallback: try current user store
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

    private static AdesBaselineProfile BuildBaselineProfile(string tsaUrl, AdesBaselineLevel level, string? revocationPreference)
    {
        var timestampOptions = new TimestampOptions(new Uri(tsaUrl), CliNetwork.Provider);
        return level switch
        {
            AdesBaselineLevel.Basic => AdesBaselineProfile.Basic(),
            AdesBaselineLevel.Timestamped => AdesBaselineProfile.Timestamped(timestampOptions),
            AdesBaselineLevel.LongTerm => AdesBaselineProfile.LongTerm(timestampOptions, AdesOptionSupport.LongTermOptions(revocationPreference)),
            _ => AdesBaselineProfile.Archive(timestampOptions, AdesOptionSupport.LongTermOptions(revocationPreference))
        };
    }

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
        "proofofapproval" or "approval" => CommitmentType.ProofOfApproval,
        _ => null
    };

    private static CadesContentType? ParseContentType(string? type) => type?.ToLowerInvariant() switch
    {
        "detached" => CadesContentType.Detached,
        "enveloped" => CadesContentType.Enveloped,
        _ => null
    };
}
