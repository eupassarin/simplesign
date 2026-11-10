using System.ComponentModel;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// Options for signing without a local private key: a PKCS#11 token, an ICP-Brasil cloud
/// certificate (PSC) or a CSC v2 remote signing service. Shared by <c>sign</c> and <c>cades sign</c>.
/// Secret values accept <c>env:NAME</c> to read them from an environment variable.
/// </summary>
internal abstract class ExternalCredentialSettings : TimestampedSigningSettings
{
    /// <summary>PKCS#11 library of an A3 token, smartcard or HSM (alternative to --cert).</summary>
    [CommandOption("--pkcs11-lib <PATH>")]
    [Description("PKCS#11 library of an A3 token, smartcard or HSM (alternative to --cert), or 'auto' to find the installed driver. See 'simplesign pkcs11 list'.")]
    public string? Pkcs11Library { get; init; }

    /// <summary>Token label, when more than one token is connected. Requires --pkcs11-lib.</summary>
    [CommandOption("--pkcs11-token <LABEL>")]
    [Description("Token label, when more than one token is connected. Requires --pkcs11-lib.")]
    public string? Pkcs11Token { get; init; }

    /// <summary>Key or certificate label, when the token has more than one key. Requires --pkcs11-lib.</summary>
    [CommandOption("--pkcs11-key <LABEL>")]
    [Description("Key or certificate label, when the token has more than one key. Requires --pkcs11-lib.")]
    public string? Pkcs11Key { get; init; }

    /// <summary>PIN of the PKCS#11 token or CSC credential (omit for a prompt / PIN pad). Accepts env:NAME.</summary>
    [CommandOption("--pin <PIN>")]
    [Description("PIN of the PKCS#11 token or CSC credential (omit for a prompt or a PIN pad). Accepts env:NAME.")]
    public string? Pin { get; init; }

    /// <summary>ICP-Brasil cloud certificate provider (PSC) API base, e.g. https://provider/v0/.</summary>
    [CommandOption("--psc-url <URL>")]
    [Description("ICP-Brasil cloud certificate provider (PSC) API base, e.g. https://provider/v0/ (alternative to --cert)")]
    public string? PscUrl { get; init; }

    /// <summary>PSC client ID. Requires --psc-url.</summary>
    [CommandOption("--psc-client-id <ID>")]
    [Description("PSC client ID registered with the provider. Requires --psc-url.")]
    public string? PscClientId { get; init; }

    /// <summary>PSC client secret. Accepts env:NAME. Requires --psc-url.</summary>
    [CommandOption("--psc-client-secret <SECRET>")]
    [Description("PSC client secret. Accepts env:NAME. Requires --psc-url.")]
    public string? PscClientSecret { get; init; }

    /// <summary>Holder CPF/CNPJ (login hint; required with --psc-otp). Requires --psc-url.</summary>
    [CommandOption("--psc-cpf <CPF>")]
    [Description("Holder CPF/CNPJ (login hint; required with --psc-otp). Requires --psc-url.")]
    public string? PscCpf { get; init; }

    /// <summary>One-time password from the provider's app, instead of the browser login. Accepts env:NAME.</summary>
    [CommandOption("--psc-otp <OTP>")]
    [Description("One-time password from the provider's app, instead of the browser login. Accepts env:NAME.")]
    public string? PscOtp { get; init; }

    /// <summary>PSC certificate alias, when the account has more than one certificate.</summary>
    [CommandOption("--psc-alias <ALIAS>")]
    [Description("PSC certificate alias, when the account has more than one certificate. Requires --psc-url.")]
    public string? PscAlias { get; init; }

    /// <summary>Cloud Signature Consortium API v2 base URL, e.g. https://qtsp/csc/v2/.</summary>
    [CommandOption("--csc-url <URL>")]
    [Description("Cloud Signature Consortium API v2 base URL, e.g. https://qtsp/csc/v2/ (alternative to --cert)")]
    public string? CscUrl { get; init; }

    /// <summary>CSC service access token. Accepts env:NAME. Requires --csc-url.</summary>
    [CommandOption("--csc-token <TOKEN>")]
    [Description("CSC service access token. Accepts env:NAME. Requires --csc-url.")]
    public string? CscToken { get; init; }

    /// <summary>CSC credential ID (see 'simplesign csc list'). Requires --csc-url.</summary>
    [CommandOption("--csc-credential <ID>")]
    [Description("CSC credential ID (see 'simplesign csc list'). Requires --csc-url.")]
    public string? CscCredential { get; init; }

    /// <summary>One-time password for the CSC credential. Accepts env:NAME. Requires --csc-url.</summary>
    [CommandOption("--otp <OTP>")]
    [Description("One-time password for the CSC credential. Accepts env:NAME. Requires --csc-url.")]
    public string? Otp { get; init; }
}
