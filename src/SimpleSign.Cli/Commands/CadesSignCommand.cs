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
    internal sealed class Settings : CommonSettings
    {
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

        public override ValidationResult Validate()
        {
            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
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

    protected override async Task<int> ExecuteAsync(
        CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] data = await CommonSettings.ReadInputBytesAsync(settings.InputPath, cancellationToken);

        using X509Certificate2 cert = await LoadCertificateAsync(settings, cancellationToken);

        var level = ParseLevel(settings.Level) ?? CadesLevel.Basic;
        var hashAlg = ParseHashAlgorithm(settings.HashAlgorithm) ?? HashAlgorithmName.SHA256;
        var commitment = settings.Commitment is not null ? ParseCommitment(settings.Commitment) : null;
        var contentType = ParseContentType(settings.ContentType) ?? CadesContentType.Detached;

        var logger = settings.CreateLogger<CadesSignCommand>();
        var builder = CadesSigner.Document(data, logger)
            .WithCertificate(cert)
            .WithHashAlgorithm(hashAlg)
            .WithLevel(level)
            .WithContentType(contentType);

        if (settings.TsaUrl is not null)
        {
            builder = builder.WithTimestamp(settings.TsaUrl);
        }
        if (commitment.HasValue)
        {
            builder = builder.WithCommitmentType(commitment.Value);
        }
        if (settings.PolicyOid is not null)
        {
            builder = builder.WithSignaturePolicy(settings.PolicyOid, settings.PolicyUri);
        }
        if (settings.ChainPath is not null)
        {
            builder = builder.WithCertificate(cert, LoadChainCertificates(settings.ChainPath));
        }

        byte[] cms = await builder.SignAsync(cancellationToken);

        string outputPath = settings.OutputPath
            ?? settings.InputPath + (contentType == CadesContentType.Enveloped ? ".p7m" : ".p7s");
        await File.WriteAllBytesAsync(outputPath, cms, cancellationToken);

        AnsiConsole.MarkupLine($"[green]CAdES signature saved to:[/] {outputPath}");

        return 0;
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

    private static CadesLevel? ParseLevel(string? level) => level?.ToLowerInvariant() switch
    {
        "basic" or "b-b" => CadesLevel.Basic,
        "timestamped" or "b-t" => CadesLevel.Timestamped,
        "longterm" or "b-lt" => CadesLevel.LongTerm,
        "archive" or "b-lta" => CadesLevel.Archive,
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
