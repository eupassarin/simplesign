using System.ComponentModel;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Core.Signing;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// How the sign commands reach a TSA that asks for credentials: HTTP Basic, a bearer token or a TLS
/// client certificate. Shared by <c>sign</c>, <c>cades sign</c> and <c>xades sign</c>. Secret values
/// accept <c>env:NAME</c> to read them from an environment variable.
/// </summary>
internal abstract class TimestampedSigningSettings : CommonSettings
{
    /// <summary>User name for a TSA with HTTP Basic authentication. Requires --tsa-password.</summary>
    [CommandOption("--tsa-user <USER>")]
    [Description("User name for a TSA with HTTP Basic authentication. Requires --tsa-password.")]
    public string? TsaUser { get; init; }

    /// <summary>Password for --tsa-user. Accepts env:NAME.</summary>
    [CommandOption("--tsa-password <PASSWORD>")]
    [Description("Password for --tsa-user. Accepts env:NAME.")]
    public string? TsaPassword { get; init; }

    /// <summary>Bearer token for the TSA. Accepts env:NAME.</summary>
    [CommandOption("--tsa-token <TOKEN>")]
    [Description("Bearer token for the TSA (instead of --tsa-user). Accepts env:NAME.")]
    public string? TsaToken { get; init; }

    /// <summary>TLS client certificate (PKCS#12) the TSA asks for.</summary>
    [CommandOption("--tsa-cert <PATH>")]
    [Description("TLS client certificate (.pfx/.p12) the TSA asks for")]
    public string? TsaCertificate { get; init; }

    /// <summary>Password of --tsa-cert. Accepts env:NAME.</summary>
    [CommandOption("--tsa-cert-password <PASSWORD>")]
    [Description("Password of --tsa-cert. Accepts env:NAME.")]
    public string? TsaCertificatePassword { get; init; }

    /// <summary>Trust anchor certificate files for the checks made before signing.</summary>
    [CommandOption("--trust <PATH>")]
    [Description("Trust anchor certificate (.cer/.crt/.pem), repeatable: the signing certificate and each TSA must chain to an anchor when the signing policy asks (ProspectiveCertificateChain)")]
    public string[] SigningTrust { get; init; } = [];

    /// <summary>Folder of trust anchor certificates for the checks made before signing.</summary>
    [CommandOption("--trust-dir <DIR>")]
    [Description("Folder of trust anchor certificates (.cer, .crt, .der, .pem) for the checks made before signing")]
    public string? SigningTrustDirectory { get; init; }

    /// <summary>Certificate the trust folder's manifest must be signed with.</summary>
    [CommandOption("--trust-dir-signer <PATH>")]
    [Description("Certificate the trust folder's manifest.json must be signed with")]
    public string? SigningTrustDirectorySigner { get; init; }

    /// <summary>Trusted list (URL or file) whose services are trust anchors before signing.</summary>
    [CommandOption("--tsl <URL|PATH>")]
    [Description("Trusted list (ETSI TS 119 612 / TS 102 231), URL or file: its CA and TSA services are the trust anchors before signing. Requires --tsl-signer")]
    public string? SigningTrustedList { get; init; }

    /// <summary>Certificate the trusted list must be signed with.</summary>
    [CommandOption("--tsl-signer <PATH>")]
    [Description("Certificate the trusted list must be signed with (the scheme operator's)")]
    public string? SigningTrustedListSigner { get; init; }

    /// <summary>The certificate the TSA must sign with.</summary>
    [CommandOption("--expected-tsa <PATH>")]
    [Description("Certificate the TSA must sign its timestamps with (.cer/.pem): a timestamp from any other is refused")]
    public string? ExpectedTsa { get; init; }

    /// <summary>Audit trail file.</summary>
    [CommandOption("--audit-log <PATH>")]
    [Description("Append a record of each signature made or refused to this file (JSON lines, hash-chained; check it with 'simplesign audit verify')")]
    public string? AuditLog { get; init; }

    /// <summary>Whether any TSA credential was given.</summary>
    internal bool HasTsaCredentials =>
        TsaUser is not null || TsaPassword is not null || TsaToken is not null || TsaCertificate is not null;

    /// <summary>The error for inconsistent TSA credentials, or null.</summary>
    /// <param name="tsaUrl">The <c>--tsa</c> value.</param>
    internal string? ValidateTsaCredentials(string? tsaUrl)
    {
        if (ValidateSigningTrust() is { } trustError)
        {
            return trustError;
        }

        if (!HasTsaCredentials && TsaCertificatePassword is null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(tsaUrl))
        {
            return "--tsa-user, --tsa-token and --tsa-cert require --tsa.";
        }

        if ((TsaUser is null) != (TsaPassword is null))
        {
            return "--tsa-user and --tsa-password go together.";
        }

        if (TsaUser is not null && TsaToken is not null)
        {
            return "--tsa-user and --tsa-token are mutually exclusive.";
        }

        if (TsaCertificatePassword is not null && TsaCertificate is null)
        {
            return "--tsa-cert-password requires --tsa-cert.";
        }

        return TsaCertificate is not null && !File.Exists(TsaCertificate)
            ? $"TSA client certificate not found: {TsaCertificate}"
            : null;
    }

    /// <summary>The options for the TSA at <paramref name="url"/>, with the credentials given.</summary>
    internal TimestampOptions Timestamp(string url) => new(new Uri(url), CliNetwork.Provider)
    {
        Authorization = TsaAuthorization(),
        ClientCertificate = TsaClientCertificate(),
        ExpectedTsaCertificate = ExpectedTsa is null ? null : LoadCertificate(ExpectedTsa),
    };

    /// <summary>The options for a separate archive TSA at <paramref name="url"/>, with the same credentials.</summary>
    internal ArchiveTimestampOptions ArchiveTimestamp(string url) => new(new Uri(url), CliNetwork.Provider)
    {
        Authorization = TsaAuthorization(),
        ClientCertificate = TsaClientCertificate(),
        ExpectedTsaCertificate = ExpectedTsa is null ? null : LoadCertificate(ExpectedTsa),
    };

    /// <summary>The error of the trust, expected TSA and audit options, or null.</summary>
    internal string? ValidateSigningTrust()
    {
        foreach (var (path, what) in SigningTrust.Select(p => ((string?)p, "Trust anchor"))
            .Append((SigningTrustDirectorySigner, "Trust folder signer"))
            .Append((SigningTrustedListSigner, "Trusted list signer"))
            .Append((ExpectedTsa, "Expected TSA certificate")))
        {
            if (path is not null && !File.Exists(path))
            {
                return $"{what} file not found: {path}";
            }
        }

        if (SigningTrustDirectory is not null && !Directory.Exists(SigningTrustDirectory))
        {
            return $"Trust folder not found: {SigningTrustDirectory}";
        }

        return SigningTrustedList is not null && SigningTrustedListSigner is null
            ? "--tsl requires --tsl-signer: the certificate the trusted list must be signed with."
            : null;
    }

    /// <summary>The trust anchors of <c>--trust</c>, <c>--trust-dir</c> and <c>--tsl</c>, for the checks made before signing.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    internal async Task<SimpleSign.Core.Extensions.ITrustAnchorProvider[]> SigningTrustAnchorsAsync(CancellationToken cancellationToken)
    {
        var providers = new List<SimpleSign.Core.Extensions.ITrustAnchorProvider>();
        if (SigningTrust.Length > 0)
        {
            providers.Add(new CertificateTrustAnchors([.. SigningTrust.Select(LoadCertificate)]));
        }

        if (SigningTrustDirectory is not null)
        {
            providers.Add(new SimpleSign.Core.Extensions.DirectoryTrustAnchorProvider(
                SigningTrustDirectory, SigningTrustDirectorySigner is null ? null : LoadCertificate(SigningTrustDirectorySigner)));
        }

        if (SigningTrustedList is not null)
        {
            var options = new SimpleSign.XAdES.TrustedLists.TrustedListOptions { SignerCertificates = [LoadCertificate(SigningTrustedListSigner!)] };
            providers.Add(Uri.TryCreate(SigningTrustedList, UriKind.Absolute, out var url) && url.Scheme is "http" or "https"
                ? await SimpleSign.XAdES.TrustedLists.TrustedList.DownloadAsync(url, options, CliNetwork.Provider, cancellationToken: cancellationToken)
                : SimpleSign.XAdES.TrustedLists.TrustedList.Load(await File.ReadAllBytesAsync(SigningTrustedList, cancellationToken), options));
        }

        return [.. providers];
    }

    /// <summary>The audit sink of <c>--audit-log</c>, or null.</summary>
    internal ISignatureAuditSink? AuditSink() => AuditLog is null ? null : new JsonLinesAuditSink(AuditLog);

    private static X509Certificate2 LoadCertificate(string path) =>
        new SimpleSign.Core.Validation.CertificateChainService().LoadCertsFromBytes(File.ReadAllBytes(path)).FirstOrDefault()
        ?? throw new InvalidDataException($"No certificate in {path}.");

    /// <summary>Trust anchors given as certificate files.</summary>
    private sealed class CertificateTrustAnchors(IReadOnlyList<X509Certificate2> certificates) : SimpleSign.Core.Extensions.ITrustAnchorProvider
    {
        public string RegionCode => "CLI";

        public string DisplayName => "--trust";

        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => [.. certificates.Where(c => c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData))];

        public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => [.. certificates.Where(c => !c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData))];
    }

    private AuthenticationHeaderValue? TsaAuthorization()
    {
        if (TsaToken is not null)
        {
            return new AuthenticationHeaderValue("Bearer", ExternalCredentialSupport.Secret(TsaToken));
        }

        return TsaUser is null
            ? null
            : new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TsaUser}:{ExternalCredentialSupport.Secret(TsaPassword)}")));
    }

    private X509Certificate2? TsaClientCertificate() =>
        TsaCertificate is null
            ? null
            : X509CertificateLoader.LoadPkcs12FromFile(TsaCertificate, ExternalCredentialSupport.Secret(TsaCertificatePassword));
}
