using SimpleSign.Signers.Cloud.Csc;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>Where the signing key of an <see cref="IofeSigningAgent"/> is kept.</summary>
public enum IofeKeySourceKind
{
    /// <summary>The organization's cryptographic module, through PKCS#11.</summary>
    Module = 0,

    /// <summary>A remote signing service, which keeps the key in its own module and signs the hash it is sent.</summary>
    RemoteService = 1,
}

/// <summary>
/// A remote signing service (Cloud Signature Consortium API v2, the protocol of ETSI TS 119 432) and the credential of
/// the organization in it. The private key stays in the service's cryptographic module: the agent sends the hash of
/// what it signs and receives the signature (guide Req. 15: no key operation in the application, no copy of the key).
/// An agent signs unattended, so the credential is authorized with the service's own means — a service token or
/// client credentials, and the credential's PIN — never with a one-time password or a login a person completes.
/// </summary>
public sealed record IofeRemoteService
{
    /// <summary>
    /// The service: its address (https) and how the agent authenticates to it, either a service access token
    /// (<see cref="CscClientOptions.AccessToken"/>) or client credentials (<see cref="CscClientOptions.ClientId"/> and
    /// <see cref="CscClientOptions.ClientSecret"/>), which the agent renews when the token they give expires.
    /// </summary>
    public required CscClientOptions Service { get; init; }

    /// <summary>The credential (key and certificate) of the organization in the service.</summary>
    public required string CredentialId { get; init; }

    /// <summary>The PIN of the credential; null when the service asks for none.</summary>
    public string? Pin { get; init; }

    /// <summary>The service and the credential, without the PIN, the token or the client secret.</summary>
    /// <returns>A text safe to log.</returns>
    public override string ToString() =>
        $"IofeRemoteService {{ Service = {Service?.BaseUri}, CredentialId = {CredentialId}, Pin = {(Pin is null ? "-" : "***")} }}";
}

/// <summary>
/// The remote signing service the operator declares: who provides it, the name the service reports about itself
/// (<c>info</c>; <c>simplesign csc list</c> shows it), and what entitles it to keep the key — its accreditation by
/// INDECOPI as a remote signature service (Resolución 175-2024/DGI-INDECOPI) or the certification of its signing
/// device (EN 419 241-2, EN 419 221-5). The service in use must be that one; the accreditation itself is a statement
/// of the operator, which software cannot check: it is what the audit confirms against the reference given here.
/// </summary>
/// <param name="Provider">Who provides the service.</param>
/// <param name="ServiceName">The name the service reports about itself.</param>
/// <param name="Accreditation">Its accreditation or the certification of its signing device.</param>
/// <param name="AccreditationReference">The number of the resolution or of the certificate.</param>
public sealed record IofeRemoteServiceDeclaration(string Provider, string ServiceName, string Accreditation, string AccreditationReference)
{
    /// <summary>Whether <paramref name="service"/> is the declared service.</summary>
    /// <param name="service">What the service in use reports about itself.</param>
    /// <returns>True when it reports the declared name.</returns>
    public bool Matches(CscInfo service)
    {
        ArgumentNullException.ThrowIfNull(service);
        return Matches(service.Name);
    }

    /// <summary>Whether a service reporting this name is the declared one.</summary>
    internal bool Matches(string? reportedName) =>
        !string.IsNullOrWhiteSpace(reportedName)
        && string.Equals(ServiceName.Trim(), reportedName.Trim(), StringComparison.OrdinalIgnoreCase);
}

/// <summary>The remote signing service a signing agent uses.</summary>
/// <param name="BaseUri">The address of the service.</param>
/// <param name="Name">The name the service reports about itself.</param>
/// <param name="Specs">The version of the protocol it reports.</param>
/// <param name="CredentialId">The credential in use.</param>
/// <param name="AuthMode">How the service authorizes a signature with the credential (<c>explicit</c>, <c>implicit</c>).</param>
/// <param name="Scal">The sole control assurance level of the credential (<c>1</c> or <c>2</c>).</param>
/// <param name="Declaration">What the operator declared about the service.</param>
public sealed record IofeRemoteServiceInfo(
    Uri BaseUri,
    string Name,
    string? Specs,
    string CredentialId,
    string AuthMode,
    string Scal,
    IofeRemoteServiceDeclaration Declaration);
