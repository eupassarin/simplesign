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

    /// <summary>Whether any TSA credential was given.</summary>
    internal bool HasTsaCredentials =>
        TsaUser is not null || TsaPassword is not null || TsaToken is not null || TsaCertificate is not null;

    /// <summary>The error for inconsistent TSA credentials, or null.</summary>
    /// <param name="tsaUrl">The <c>--tsa</c> value.</param>
    internal string? ValidateTsaCredentials(string? tsaUrl)
    {
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
    };

    /// <summary>The options for a separate archive TSA at <paramref name="url"/>, with the same credentials.</summary>
    internal ArchiveTimestampOptions ArchiveTimestamp(string url) => new(new Uri(url), CliNetwork.Provider)
    {
        Authorization = TsaAuthorization(),
        ClientCertificate = TsaClientCertificate(),
    };

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
