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

[Description("Sign an XML document with XAdES (B-B, B-T, B-LT, B-LTA)")]
internal sealed class XadesSignCommand : AsyncCommand<XadesSignCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;

    public XadesSignCommand(ICertificateChainService certChainService)
    {
        _certChainService = certChainService;
    }

    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<input>")]
        [Description("XML file to sign")]
        public string InputPath { get; init; } = null!;

        [CommandOption("--cert|-c <PATH>")]
        [Description("PKCS#12 certificate file (.pfx/.p12)")]
        public string? CertPath { get; init; }

        [CommandOption("--password|-p <PASSWORD>")]
        [Description("Certificate password (omit for interactive prompt)")]
        public string? Password { get; init; }

        [CommandOption("--output|-o <PATH>")]
        [Description("Output signed XML file (default: <input>.signed.xml)")]
        public string? OutputPath { get; init; }

        [CommandOption("--tsa <URL>")]
        [Description("TSA URL for timestamp (B-T or higher)")]
        public string? TsaUrl { get; init; }

        [CommandOption("--level <LEVEL>")]
        [Description("XAdES level: basic, timestamped, longterm, archive (default: basic)")]
        public string? Level { get; init; }

        [CommandOption("--hash|-H <ALGO>")]
        [Description("Hash algorithm: SHA256, SHA384, SHA512 (default: SHA256)")]
        public string? HashAlgorithm { get; init; }

        [CommandOption("--commitment <TYPE>")]
        [Description("Commitment type: ProofOfOrigin, ProofOfReceipt, ProofOfDelivery, ProofOfSender, ProofOfApproval, ProofOfCreation")]
        public string? Commitment { get; init; }

        [CommandOption("--policy-oid <OID>")]
        [Description("Signature policy OID")]
        public string? PolicyOid { get; init; }

        [CommandOption("--policy-uri <URI>")]
        [Description("Signature policy URI")]
        public string? PolicyUri { get; init; }

        [CommandOption("--signer-role <ROLE>")]
        [Description("Claimed signer role (may be specified multiple times)")]
        public string[]? SignerRoles { get; init; }

        [CommandOption("--chain <PATH>")]
        [Description("PEM/DER file with intermediate CA certificates")]
        public string? ChainPath { get; init; }

        [CommandOption("--form <FORM>")]
        [Description("XAdES form: enveloped, detached, enveloping (default: enveloped)")]
        public string? Form { get; init; }

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

            return ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(
        CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] xmlData = await File.ReadAllBytesAsync(settings.InputPath, cancellationToken);

        using X509Certificate2 cert = await LoadCertificateAsync(settings, cancellationToken);

        var level = ParseLevel(settings.Level) ?? XadesLevel.Basic;
        var hashAlg = ParseHashAlgorithm(settings.HashAlgorithm) ?? HashAlgorithmName.SHA256;
        var form = ParseForm(settings.Form) ?? XadesForm.Enveloped;
        var commitment = settings.Commitment is not null ? ParseCommitment(settings.Commitment) : null;

        var logger = settings.CreateLogger<XadesSignCommand>();
        var builder = XadesSigner.Document(xmlData, logger)
            .WithCertificate(cert)
            .WithHashAlgorithm(hashAlg)
            .WithLevel(level)
            .WithForm(form);

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
        if (settings.SignerRoles is { Length: > 0 })
        {
            builder = builder.WithSignerRoles(settings.SignerRoles);
        }

        if (settings.ChainPath is not null)
        {
            builder = builder.WithCertificate(cert, LoadChainCertificates(settings.ChainPath));
        }

        byte[] signed = await builder.SignAsync(cancellationToken);

        string outputPath = settings.OutputPath ?? settings.InputPath + ".signed.xml";
        await File.WriteAllBytesAsync(outputPath, signed, cancellationToken);

        AnsiConsole.MarkupLine($"[green]XAdES signature saved to:[/] {outputPath}");

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

    private static XadesLevel? ParseLevel(string? level) => level?.ToLowerInvariant() switch
    {
        "basic" or "b-b" => XadesLevel.Basic,
        "timestamped" or "b-t" => XadesLevel.Timestamped,
        "longterm" or "b-lt" => XadesLevel.LongTerm,
        "archive" or "b-lta" => XadesLevel.Archive,
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
