using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Validation.Policy;
using SimpleSign.XAdES.TrustedLists;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>The validation options shared by the validate commands: policy, trust store, trusted list, language.</summary>
internal class TrustedValidationSettings : CommonSettings
{
    /// <summary>Validation policy (JSON).</summary>
    [CommandOption("--policy <PATH>")]
    [Description("Validation policy (JSON): accepted algorithms, key sizes, key usage")]
    public string? PolicyPath { get; init; }

    /// <summary>Certificate the policy must be signed with (detached CMS next to it, .p7s).</summary>
    [CommandOption("--policy-signer <PATH>")]
    [Description("Certificate the policy must be signed with; its detached signature is <policy>.p7s")]
    public string? PolicySignerPath { get; init; }

    /// <summary>Folder of trust anchor certificates.</summary>
    [CommandOption("--trust-dir <DIR>")]
    [Description("Folder of trust anchor certificates (.cer, .crt, .der, .pem)")]
    public string? TrustDirectory { get; init; }

    /// <summary>Certificate the trust folder's manifest must be signed with.</summary>
    [CommandOption("--trust-dir-signer <PATH>")]
    [Description("Certificate the trust folder's manifest.json must be signed with")]
    public string? TrustDirectorySignerPath { get; init; }

    /// <summary>Trusted list (URL or file).</summary>
    [CommandOption("--tsl <URL|PATH>")]
    [Description("Trusted list (ETSI TS 119 612 / TS 102 231), URL or file; its CA and TSA services become trust anchors")]
    public string? TrustedList { get; init; }

    /// <summary>Certificate the trusted list must be signed with.</summary>
    [CommandOption("--tsl-signer <PATH>")]
    [Description("Certificate the trusted list must be signed with (the scheme operator's)")]
    public string? TrustedListSignerPath { get; init; }

    /// <summary>Language of the verification report.</summary>
    [CommandOption("--lang <LANG>")]
    [Description("Language of the verification report: en (default) or es")]
    public string Language { get; init; } = "en";

    /// <summary>Whether the report is written in Spanish.</summary>
    public bool Spanish => Language.StartsWith("es", StringComparison.OrdinalIgnoreCase);

    /// <summary>Checks the files the options name.</summary>
    protected Spectre.Console.ValidationResult ValidateTrustOptions()
    {
        foreach (var (path, what) in new[]
        {
            (PolicyPath, "Policy"), (PolicySignerPath, "Policy signer"), (TrustDirectorySignerPath, "Trust folder signer"),
            (TrustedListSignerPath, "Trusted list signer"),
        })
        {
            if (path is not null && !File.Exists(path))
            {
                return Spectre.Console.ValidationResult.Error($"{what} file not found: {path}");
            }
        }

        if (TrustDirectory is not null && !Directory.Exists(TrustDirectory))
        {
            return Spectre.Console.ValidationResult.Error($"Trust folder not found: {TrustDirectory}");
        }

        if (TrustedList is not null && TrustedListSignerPath is null)
        {
            return Spectre.Console.ValidationResult.Error("--tsl needs --tsl-signer: the certificate the list must be signed with.");
        }

        return Language is "en" or "es" or "es-PE"
            ? Spectre.Console.ValidationResult.Success()
            : Spectre.Console.ValidationResult.Error($"Unknown language '{Language}': use en or es.");
    }

    /// <summary>The policy, and the trust anchors of the trust folder and the trusted list.</summary>
    internal async Task<(ValidationPolicy Policy, List<X509Certificate2> Anchors)> LoadTrustAsync(CancellationToken cancellationToken)
    {
        ValidationPolicy policy = PolicyPath is null ? ValidationPolicy.Default
            : PolicySignerPath is null ? ValidationPolicy.Load(PolicyPath)
            : ValidationPolicy.LoadSigned(PolicyPath, PolicyPath + ".p7s", LoadCertificate(PolicySignerPath));

        var anchors = new List<X509Certificate2>();
        if (TrustDirectory is not null)
        {
            var provider = new DirectoryTrustAnchorProvider(
                TrustDirectory, TrustDirectorySignerPath is null ? null : LoadCertificate(TrustDirectorySignerPath));
            anchors.AddRange(provider.GetTrustAnchors());
            anchors.AddRange(provider.GetIntermediateCertificates());
        }

        if (TrustedList is not null)
        {
            var options = new TrustedListOptions { SignerCertificates = [LoadCertificate(TrustedListSignerPath!)] };
            var list = Uri.TryCreate(TrustedList, UriKind.Absolute, out var url) && url.Scheme is "http" or "https"
                ? await SimpleSign.XAdES.TrustedLists.TrustedList.DownloadAsync(url, options, cancellationToken: cancellationToken)
                : SimpleSign.XAdES.TrustedLists.TrustedList.Load(await File.ReadAllBytesAsync(TrustedList, cancellationToken), options);
            anchors.AddRange(list.GetTrustAnchors());
        }

        return (policy, anchors);
    }

    /// <summary>A chain revocation checker that downloads through the CLI's HTTP provider (proxy, outbound policy).</summary>
    internal static SimpleSign.Core.Revocation.IChainRevocationChecker RevocationCheckerFor(SimpleSign.Core.Http.IHttpClientProvider http) =>
        new SimpleSign.Core.Revocation.ChainRevocationChecker(http.GetClient(), outboundPolicy: http.OutboundPolicy);

    private static X509Certificate2 LoadCertificate(string path) =>
        new SimpleSign.Core.Validation.CertificateChainService().LoadCertsFromBytes(File.ReadAllBytes(path)).FirstOrDefault()
        ?? throw new InvalidDataException($"No certificate in {path}.");
}
